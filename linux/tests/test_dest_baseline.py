#!/usr/bin/env python3
"""Agent Access Audit — Phase 3: approved-destination baseline (egress authorization).

An AI-lineage process reaching an EXTERNAL destination it has not used before — and that is not a
catalogued LLM provider — raises ai-dest-unapproved. Covered here: the destination gatherer's filtering
(private / provider / non-lineage excluded) and domain-vs-IP keying; the learn-only baseline (first pass
is silent, a repeat stays silent); a genuinely new destination firing medium; escalation to high when a
new agent identity appears in the same window; and keying on the DNS-resolved domain rather than the IP.

Pure stdlib. Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


class GatherDestinations(unittest.TestCase):
    def setUp(self):
        self.c = agent.AISurfaceCollector(enabled=False, baseline_file=None)
        self.procs = {
            100: {"pid": 100, "ppid": 1, "exe": "/opt/claude", "cmdline": "claude", "user": "me"},
            101: {"pid": 101, "ppid": 100, "exe": "/bin/curl", "cmdline": "curl", "user": "me"},
            200: {"pid": 200, "ppid": 1, "exe": "/bin/zsh", "cmdline": "zsh", "user": "me"},
        }

    def test_filters_private_provider_and_non_lineage(self):
        net = {
            100: [{"raddr": "1.2.3.4", "rport": "443"},     # external, keeps
                  {"raddr": "10.0.0.5", "rport": "443"},    # private, drop
                  {"raddr": "20.20.20.20", "rport": "443"}],  # llm provider, drop
            101: [{"raddr": "5.6.7.8", "rport": "443"}],    # curl under claude lineage, keeps
            200: [{"raddr": "9.9.9.9", "rport": "443"}],    # not AI lineage, drop
        }
        d = self.c._gather_destinations(self.procs, net, ai_pids={100}, ai_bases={"claude"},
                                        llm_ipmap={"20.20.20.20": "openai"}, dns_ipmap={})
        got = {(x["agent"], x["dest"]) for x in d}
        self.assertEqual(got, {("claude", "1.2.3.4"), ("claude", "5.6.7.8")})

    def test_keys_on_domain_when_dns_resolves_the_ip(self):
        net = {100: [{"raddr": "1.2.3.4", "rport": "443"}]}
        d = self.c._gather_destinations(self.procs, net, ai_pids={100}, ai_bases={"claude"},
                                        llm_ipmap={}, dns_ipmap={"1.2.3.4": "api.example.com"})
        self.assertEqual(d[0]["dest"], "api.example.com")
        self.assertEqual(d[0]["kind"], "domain")


class DnsIpDomainMap(unittest.TestCase):
    def test_only_rows_with_answer_ip_contribute(self):
        d = tempfile.mkdtemp()
        h = agent.HistoryDB(path=os.path.join(d, "h.db"))
        now = int(time.time())
        h.record_dns([(agent._hkey("dns", "api.example.com", "A", "claude"),
                       "api.example.com", "A", "claude", "", 0, "dnsmasq", "1.2.3.4", now, now)])
        h.record_dns([(agent._hkey("dns", "noip.example.com", "A", "claude"),
                       "noip.example.com", "A", "claude", "", 0, "dnsmasq", None, now, now)])
        c = agent.AISurfaceCollector(enabled=False, baseline_file=None, history=h)
        m = c._dns_ip_domain_map()
        self.assertEqual(m.get("1.2.3.4"), "api.example.com")
        self.assertNotIn(None, m)                      # the answerless row contributes nothing

    def test_no_history_is_empty(self):
        c = agent.AISurfaceCollector(enabled=False, baseline_file=None, history=None)
        self.assertEqual(c._dns_ip_domain_map(), {})


class CollectorDestFinding(unittest.TestCase):
    def _collector(self, home, net):
        c = agent.AISurfaceCollector(enabled=False, baseline_file=os.path.join(home, "b.json"))
        c._gather_agents = lambda procs: []
        c._gather_runtimes = lambda procs, net: []
        c._gather_offensive = lambda procs, net: []
        c._gather_context = lambda: []
        c._gather_egress = lambda *a, **k: []
        c._gather_mcp = lambda: []
        c._gather_access = lambda *a, **k: []
        c._gather_nhi = lambda mcp: list(self._nhi)        # drives the escalation window
        c._annotate_scopes = lambda nhi: nhi
        c._endpoint_ip_map = lambda: {}
        c._dns_ip_domain_map = lambda *a, **k: {}
        procs = {100: {"pid": 100, "ppid": 1, "exe": "/opt/claude", "cmdline": "claude", "user": "me"}}
        c._gather_destinations = lambda *a, **k: agent.AISurfaceCollector._gather_destinations(
            c, procs, net, {100}, {"claude"}, {}, {})
        return c

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self._nhi = []                                     # no new identity by default
        self._orig = (agent._ai_home, agent.collect_processes, agent.collect_network)
        agent._ai_home = lambda: self.home
        agent.collect_processes = lambda: {}
        agent.collect_network = lambda: {}

    def tearDown(self):
        agent._ai_home, agent.collect_processes, agent.collect_network = self._orig

    def _dest_findings(self, c):
        return [n for n in c.snapshot() if n["detail"].get("finding") == "dest-unapproved"]

    def test_learnonly_suppresses_then_new_dest_fires_medium(self):
        net = {100: [{"raddr": "1.2.3.4", "rport": "443"}]}
        c = self._collector(self.home, net)
        c._collect()                                       # learn-only
        self.assertFalse(self._dest_findings(c), "first (learn-only) pass must not alarm")
        self.assertTrue(c.inv["dest"], "the destination is still inventoried on the first pass")
        c._collect()                                       # same dest -> baselined -> quiet
        self.assertFalse(self._dest_findings(c), "a baselined (agent, dest) stays quiet")
        # a genuinely new destination now appears
        c._gather_destinations = lambda *a, **k: agent.AISurfaceCollector._gather_destinations(
            c, {100: {"pid": 100, "ppid": 1, "exe": "/opt/claude", "cmdline": "claude", "user": "me"}},
            {100: [{"raddr": "5.6.7.8", "rport": "443"}]}, {100}, {"claude"}, {}, {})
        c._collect()
        fs = self._dest_findings(c)
        self.assertTrue(any(f["detail"]["dest"] == "5.6.7.8" for f in fs), "new dest must fire")
        self.assertEqual(fs[0]["severity"], "medium")
        self.assertFalse(fs[0]["detail"]["correlated_new_identity"])

    def test_new_identity_in_window_escalates_to_high(self):
        net = {100: [{"raddr": "1.2.3.4", "rport": "443"}]}
        c = self._collector(self.home, net)
        c._collect()                                       # learn the first dest
        # a NEW destination AND a NEW identity in the same window
        self._nhi = [{"provider": "aws", "kind": "cloud-credentials", "source": "/home/me/.aws/credentials",
                      "new_since_baseline": True}]
        c._gather_destinations = lambda *a, **k: agent.AISurfaceCollector._gather_destinations(
            c, {100: {"pid": 100, "ppid": 1, "exe": "/opt/claude", "cmdline": "claude", "user": "me"}},
            {100: [{"raddr": "5.6.7.8", "rport": "443"}]}, {100}, {"claude"}, {}, {})
        c._collect()
        fs = self._dest_findings(c)
        self.assertTrue(fs, "new dest + new identity must fire")
        self.assertEqual(fs[0]["severity"], "high")
        self.assertTrue(fs[0]["detail"]["correlated_new_identity"])

    def test_finding_carries_no_port_path_or_query(self):
        net = {100: [{"raddr": "1.2.3.4", "rport": "443"}]}
        c = self._collector(self.home, net)
        c._collect()
        c._gather_destinations = lambda *a, **k: agent.AISurfaceCollector._gather_destinations(
            c, {100: {"pid": 100, "ppid": 1, "exe": "/opt/claude", "cmdline": "claude", "user": "me"}},
            {100: [{"raddr": "5.6.7.8", "rport": "443"}]}, {100}, {"claude"}, {}, {})
        c._collect()
        det = self._dest_findings(c)[0]["detail"]
        self.assertEqual(det["dest"], "5.6.7.8")      # host granularity, not a URL
        self.assertNotIn("url", det)
        self.assertNotIn("path", det)
        self.assertNotIn("query", det)


class AccessSummaryRelay(unittest.TestCase):
    """P5: the counts-only + scored-findings surface the Mesh fans. It must carry the per-category
    counts and the scored ai-access findings (with the actionable path/dest), but NOT the full identity
    inventory and NEVER a credential value."""

    def _collector(self):
        c = agent.AISurfaceCollector(enabled=False, baseline_file=None)
        c.inv = {"generated": "now",
                 "counts": {"nhi": 4, "exposed_identities": 1, "new_identities": 0,
                            "excessive_scopes": 2, "access": 1, "new_access": 1,
                            "dest": 3, "new_dest": 1},
                 # full inventory lists that must NOT appear in the relay
                 "nhi": [{"provider": "aws", "source": "/root/.aws/credentials"}],
                 "dest": [{"agent": "claude", "dest": "api.x.example"}]}
        c.items = {
            "ai:nhi-exposed:x": {"id": "ai:nhi-exposed:x", "label": "Agent-usable credential exposed: aws",
                                 "severity": "high", "reasons": [{"mitre": "T1552.001"}],
                                 "detail": {"category": "ai-access", "finding": "nhi-exposed",
                                            "provider": "aws", "path": "/root/.aws/credentials"}},
            "ai:dest:y": {"id": "ai:dest:y", "label": "new dest", "severity": "medium",
                          "reasons": [{"mitre": "T1071"}],
                          "detail": {"category": "ai-access", "finding": "dest-unapproved",
                                     "agent": "claude", "dest": "api.x.example"}},
            "ai:egress:z": {"id": "ai:egress:z", "label": "egress", "severity": "high",
                            "reasons": [{"mitre": "T1071.001"}],
                            "detail": {"category": "ai-egress", "finding": "llm-egress-anomaly"}},
        }
        return c

    def test_counts_and_only_ai_access_findings(self):
        s = self._collector().access_summary()
        self.assertEqual(s["counts"]["exposed_identities"], 1)
        self.assertEqual(s["counts"]["excessive_scopes"], 2)
        self.assertEqual(s["counts"]["new_dest"], 1)
        findings = {f["finding"] for f in s["findings"]}
        self.assertEqual(findings, {"nhi-exposed", "dest-unapproved"})  # ai-egress excluded
        self.assertNotIn("nhi", s)                    # raw identity inventory stays on-host
        self.assertNotIn("dest", s)

    def test_scored_finding_carries_actionable_target_not_values(self):
        s = self._collector().access_summary()
        exp = next(f for f in s["findings"] if f["finding"] == "nhi-exposed")
        self.assertEqual(exp["path"], "/root/.aws/credentials")   # the exposure operators must fix
        self.assertEqual(exp["mitre"], "T1552.001")
        blob = repr(s)
        self.assertNotIn("aws_access_key_id", blob)   # never a secret value
        self.assertNotIn("AKIA", blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)
