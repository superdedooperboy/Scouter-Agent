#!/usr/bin/env python3
"""Agent Access Audit — Phase 6: operator policy & reversible response.

A policy turns "new vs. learned baseline" into a first-class approved / denied verdict: an approved
destination never fires (even when new), a denied one always fires (even when baselined), an approved
identity suppresses ai-identity-new, and a scope the operator declared within max_scope suppresses
ai-scope-excessive (while a scope that EXCEEDS it fires as a policy breach). With no policy file the audit
behaves exactly as P1–P5. The reversible response reuses the shipped channel: a denied/unapproved
destination offers block_ip, an over-scoped identity wired into an MCP server offers quarantine_mcp.

Pure stdlib. Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


POLICY = {
    "default": {"approved_destinations": [".anthropic.com", "api.github.com"],
                "denied_destinations": ["paste.ee"],
                "approved_identities": ["GitHub:token"],
                "max_scope": ["repo"]},
    "agents": {"claude": {"approved_destinations": ["api.example.com"]}},
}


class PolicyHelpers(unittest.TestCase):
    def test_destination_verdicts(self):
        self.assertEqual(agent.policy_dest_verdict(POLICY, "x", "api.anthropic.com"), "approved")
        self.assertEqual(agent.policy_dest_verdict(POLICY, "x", "anthropic.com"), "approved")  # suffix
        self.assertEqual(agent.policy_dest_verdict(POLICY, "claude", "api.example.com"), "approved")
        self.assertEqual(agent.policy_dest_verdict(POLICY, "x", "api.example.com"), "unknown")  # other agent
        self.assertEqual(agent.policy_dest_verdict(POLICY, "x", "paste.ee"), "denied")
        self.assertEqual(agent.policy_dest_verdict(POLICY, "x", "evil.net"), "unknown")
        self.assertEqual(agent.policy_dest_verdict({}, "x", "evil.net"), "unknown")  # no policy

    def test_denied_beats_approved(self):
        pol = {"default": {"approved_destinations": ["*"], "denied_destinations": ["paste.ee"]}}
        self.assertEqual(agent.policy_dest_verdict(pol, "x", "paste.ee"), "denied")
        self.assertEqual(agent.policy_dest_verdict(pol, "x", "other.com"), "approved")

    def test_identity_and_scope(self):
        self.assertIs(agent.policy_identity_approved(POLICY, "x", "GitHub", "token"), True)
        self.assertIs(agent.policy_identity_approved(POLICY, "x", "AWS", "cloud-credentials"), False)
        self.assertIsNone(agent.policy_identity_approved({}, "x", "AWS", "x"))
        self.assertIs(agent.policy_scope_within_max(POLICY, "x", ["repo"]), True)
        self.assertIs(agent.policy_scope_within_max(POLICY, "x", ["repo", "admin:org"]), False)
        self.assertIsNone(agent.policy_scope_within_max({"default": {}}, "x", ["repo"]))

    def test_malformed_policy_file_is_empty(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "pol.json")
        with open(p, "w") as f:
            f.write("{ not valid json")
        self.assertEqual(agent.load_access_policy(p), {})
        self.assertEqual(agent.load_access_policy(os.path.join(d, "nope.json")), {})


class CollectorPolicy(unittest.TestCase):
    def _collector(self, policy, dest=None, nhi=None):
        c = agent.AISurfaceCollector(enabled=False, baseline_file=os.path.join(self.home, "b.json"),
                                     policy_file=None)
        c.policy = policy
        c._gather_agents = lambda procs: []
        c._gather_runtimes = lambda procs, net: []
        c._gather_offensive = lambda procs, net: []
        c._gather_context = lambda: []
        c._gather_egress = lambda *a, **k: []
        c._gather_mcp = lambda: []
        c._gather_access = lambda *a, **k: []
        c._gather_nhi = lambda mcp: list(nhi or [])
        c._annotate_scopes = lambda x: x
        c._endpoint_ip_map = lambda: {}
        c._dns_ip_domain_map = lambda *a, **k: {}
        c._gather_destinations = lambda *a, **k: list(dest or [])
        return c

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self._orig = (agent.collect_processes, agent.collect_network)
        agent.collect_processes = lambda: {}
        agent.collect_network = lambda: {}

    def tearDown(self):
        agent.collect_processes, agent.collect_network = self._orig

    def _finds(self, c, finding):
        return [n for n in c.snapshot() if n["detail"].get("finding") == finding]

    def test_approved_destination_never_fires_even_when_new(self):
        dest = [{"agent": "claude", "dest": "api.example.com", "kind": "domain",
                 "raddr": "1.2.3.4", "rport": "443"}]
        c = self._collector(POLICY, dest=dest)
        c._collect()                 # learn
        c._collect()                 # policy-approved → never a dest finding
        self.assertFalse(self._finds(c, "dest-unapproved"))

    def test_denied_destination_fires_even_when_baselined(self):
        dest = [{"agent": "claude", "dest": "paste.ee", "kind": "domain",
                 "raddr": "5.6.7.8", "rport": "443"}]
        c = self._collector(POLICY, dest=dest)
        c._collect()                 # learn — but denied fires regardless of baseline
        fs = self._finds(c, "dest-unapproved")
        self.assertTrue(fs)
        self.assertEqual(fs[0]["severity"], "high")
        self.assertEqual(fs[0]["detail"]["policy"], "denied")

    def test_approved_identity_suppresses_new_identity(self):
        nhi = [{"provider": "GitHub", "kind": "token", "source": "env:GITHUB_TOKEN",
                "used_by": ["claude/github"], "mcp_refs": []}]
        c = self._collector(POLICY, nhi=nhi)
        c._collect()                 # learn
        nhi[0]["source"] = "env:GITHUB_TOKEN2"   # a "new" one, but GitHub:token is approved
        c._collect()
        self.assertFalse(self._finds(c, "nhi-new"))

    def test_scope_within_max_suppresses_but_breach_fires(self):
        ok = [{"provider": "GitHub", "kind": "token", "source": "env:GH", "scope_broad": True,
               "scope_broad_grants": ["repo"], "used_by": ["claude/github"], "mcp_refs": []}]
        c = self._collector(POLICY, nhi=ok)
        c._collect()
        self.assertFalse(self._finds(c, "scope-excessive"), "scope within max_scope is suppressed")

        bad = [{"provider": "GitHub", "kind": "token", "source": "env:GH", "scope_broad": True,
                "scope_broad_grants": ["repo", "admin:org"], "used_by": ["claude/github"],
                "mcp_refs": [{"path": "/x/mcp.json", "server": "github", "client": "claude"}]}]
        c2 = self._collector(POLICY, nhi=bad)
        c2._collect()
        fs = self._finds(c2, "scope-excessive")
        self.assertTrue(fs)
        self.assertEqual(fs[0]["detail"]["policy"], "exceeds-max-scope")
        self.assertEqual(fs[0]["detail"]["mcp_server"], "github")   # carries the quarantine target


class ResponseWiring(unittest.TestCase):
    def test_dest_unapproved_offers_reversible_block_ip(self):
        node = {"type": "ai-access", "severity": "high",
                "detail": {"category": "ai-access", "finding": "dest-unapproved",
                           "raddr": "1.2.3.4", "rport": "443"}}
        rec = agent.recommend_response(node)
        self.assertEqual(rec["action"], "block_ip")
        self.assertEqual(rec["target"], {"ip": "1.2.3.4"})
        self.assertTrue(rec["reversible"])
        self.assertEqual(agent.derive_action_target("block_ip", node, {"block_ip": {"applies": ["ai-access"]}}),
                         {"ip": "1.2.3.4"})

    def test_overscoped_identity_offers_quarantine_mcp(self):
        node = {"type": "ai-access", "severity": "high",
                "detail": {"category": "ai-access", "finding": "scope-excessive",
                           "mcp_path": "/x/mcp.json", "mcp_server": "github", "mcp_client": "claude"}}
        rec = agent.recommend_response(node)
        self.assertEqual(rec["action"], "quarantine_mcp")
        self.assertEqual(rec["target"]["server"], "github")
        self.assertTrue(rec["reversible"])

    def test_no_actionable_target_offers_nothing(self):
        # an exposed FILE credential with no MCP wiring: no reversible auto-action (the fix is chmod)
        node = {"type": "ai-access", "severity": "high",
                "detail": {"category": "ai-access", "finding": "nhi-exposed", "path": "/root/.aws/credentials"}}
        self.assertIsNone(agent.recommend_response(node))

    def test_block_ip_and_quarantine_mcp_apply_to_ai_access(self):
        reg = agent.Responder(locked=True).registry if hasattr(agent, "Responder") else None
        if reg is None:
            self.skipTest("no registry")
        self.assertIn("ai-access", reg["block_ip"]["applies"])
        self.assertIn("ai-access", reg["quarantine_mcp"]["applies"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
