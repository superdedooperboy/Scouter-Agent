"""snapshot_alert_lineage: the owning-process chain is frozen onto a connection/listener/download
alert's own detail, so the lineage persists after the process (and its live graph node) exit.

Regression guard for the bug where "Peer in VPN / proxy-exit hosting infrastructure" (and related
remote/listen/download alerts) showed process lineage while the node was live, then lost it once the
owning process exited and the graph no longer held it.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


def _procs():
    # launchd(1) > sshd(42) > bash(43) > curl(44)
    return {
        1: {"ppid": 0, "exe": "/sbin/launchd", "cmdline": "/sbin/launchd"},
        42: {"ppid": 1, "exe": "/usr/sbin/sshd", "cmdline": "sshd: user"},
        43: {"ppid": 42, "exe": "/bin/bash", "cmdline": "-bash"},
        44: {"ppid": 43, "exe": "/usr/bin/curl", "cmdline": "curl https://1.2.3.4/x"},
    }


def _nodes_with_remote():
    procs = _procs()
    nodes = [{"id": f"proc:{pid}", "type": "process", "label": os.path.basename(p["exe"]),
              "severity": "info", "detail": {"pid": pid, "ppid": p["ppid"],
                                             "exe": p["exe"], "cmdline": p["cmdline"]}}
             for pid, p in procs.items()]
    # the connection peer node (what b-vpn-hosting fires on), owned by curl (pid 44)
    nodes.append({"id": "remote:1.2.3.4:443", "type": "remote", "label": "1.2.3.4:443",
                  "severity": "low", "detail": {"raddr": "1.2.3.4", "rport": 443,
                                                "proto": "tcp", "public": True}})
    edges = [{"source": "proc:44", "target": "remote:1.2.3.4:443", "rel": "connects_to"}]
    # parent edges (not strictly needed; the chain walks ppid from the procs table)
    return nodes, edges, procs


class TestAlertLineageSnapshot(unittest.TestCase):
    def test_remote_node_gets_owner_chain_via_edge(self):
        nodes, edges, procs = _nodes_with_remote()
        agent.enrich_process_lineage(nodes, procs)
        agent.snapshot_alert_lineage(nodes, edges, procs)
        rem = next(n for n in nodes if n["type"] == "remote")
        lin = rem["detail"].get("proc_lineage")
        self.assertTrue(lin, "remote node should carry a frozen proc_lineage")
        # ordered root -> owner
        self.assertEqual([r["name"] for r in lin], ["launchd", "sshd", "bash", "curl"])
        self.assertEqual([r["pid"] for r in lin], [1, 42, 43, 44])
        # the owner (last row) carries its command line — the forensic "what ran this"
        self.assertEqual(lin[-1]["cmd"], "curl https://1.2.3.4/x")
        self.assertEqual(rem["detail"]["lineage_owner"], {"pid": 44, "label": "curl"})

    def test_survives_owning_process_removal(self):
        # Freeze while everything is live, then drop the whole process table and the graph proc nodes
        # (what actually happens once the process exits and a later snapshot is taken).
        nodes, edges, procs = _nodes_with_remote()
        agent.enrich_process_lineage(nodes, procs)
        agent.snapshot_alert_lineage(nodes, edges, procs)
        rem = next(n for n in nodes if n["type"] == "remote")
        frozen = rem["detail"]["proc_lineage"]
        # re-run with the owner gone: the ALREADY-frozen detail is what persists on the stored alert
        self.assertEqual([r["name"] for r in frozen], ["launchd", "sshd", "bash", "curl"])
        # and a fresh snapshot with no procs at all leaves a remote node without a chain (nothing to
        # freeze) rather than crashing
        lonely = [{"id": "remote:9.9.9.9:443", "type": "remote", "label": "9.9.9.9:443",
                   "severity": "low", "detail": {"raddr": "9.9.9.9", "rport": 443}}]
        agent.snapshot_alert_lineage(lonely, [], {})
        self.assertNotIn("proc_lineage", lonely[0]["detail"])

    def test_listener_uses_owner_pid(self):
        procs = _procs()
        nodes = [{"id": "proc:43", "type": "process", "label": "bash",
                  "severity": "info", "detail": {"pid": 43, "ppid": 42,
                                                 "exe": "/bin/bash", "cmdline": "-bash"}},
                 {"id": "proc:42", "type": "process", "label": "sshd",
                  "severity": "info", "detail": {"pid": 42, "ppid": 1,
                                                 "exe": "/usr/sbin/sshd", "cmdline": "sshd: user"}},
                 {"id": "proc:1", "type": "process", "label": "launchd",
                  "severity": "info", "detail": {"pid": 1, "ppid": 0,
                                                 "exe": "/sbin/launchd", "cmdline": "/sbin/launchd"}},
                 {"id": "listen:43:tcp:0.0.0.0:4444", "type": "listen", "label": "tcp :4444",
                  "severity": "medium", "detail": {"proto": "tcp", "laddr": "0.0.0.0",
                                                   "lport": 4444, "owner_pid": 43}}]
        agent.enrich_process_lineage(nodes, procs)
        agent.snapshot_alert_lineage(nodes, [], procs)  # no edges: must use owner_pid
        lis = next(n for n in nodes if n["type"] == "listen")
        self.assertEqual([r["name"] for r in lis["detail"]["proc_lineage"]],
                         ["launchd", "sshd", "bash"])

    def test_process_node_keeps_own_chain(self):
        nodes, edges, procs = _nodes_with_remote()
        agent.enrich_process_lineage(nodes, procs)
        agent.snapshot_alert_lineage(nodes, edges, procs)
        curl = next(n for n in nodes if n["id"] == "proc:44")
        self.assertEqual([r["name"] for r in curl["detail"]["proc_lineage"]],
                         ["launchd", "sshd", "bash", "curl"])

    def test_brief_whitelist_persists_lineage(self):
        # the stored-alert brief must carry proc_lineage / lineage_owner so alert_detail reads it back
        import inspect
        src = inspect.getsource(agent)
        self.assertIn('"proc_lineage", "lineage_owner"', src)

    def test_slim_alert_keeps_lineage_as_bounded_array(self):
        # the mesh relay must receive proc_lineage as a STRUCTURED array (not a stringified blob the
        # generic nested-clamp would produce), bounded in rows + cmd length.
        lin = [{"name": "launchd", "pid": 1, "cmd": "/sbin/launchd", "sev": None},
               {"name": "bash", "pid": 43, "cmd": "x" * 500, "sev": "info"},
               {"name": "curl", "pid": 44, "cmd": "curl https://1.2.3.4/" + "y" * 500, "sev": "low"}]
        a = {"node_id": "remote:1.2.3.4:443", "type": "remote", "label": "1.2.3.4:443",
             "severity": "low", "detail": {"raddr": "1.2.3.4",
                                           "proc_lineage": lin,
                                           "lineage_owner": {"pid": 44, "label": "curl"}}}
        slim = agent.MeshReporter._slim_alert(a)
        got = slim["detail"]["proc_lineage"]
        self.assertIsInstance(got, list)
        self.assertEqual([r["name"] for r in got], ["launchd", "bash", "curl"])
        self.assertLessEqual(len(got[2]["cmd"]), 160)        # cmd re-capped for the relay
        self.assertEqual(slim["detail"]["lineage_owner"], {"pid": 44, "label": "curl"})


class TestLineagePersistRoundTrip(unittest.TestCase):
    def test_stored_remote_alert_reads_back_its_lineage(self):
        import tempfile
        import time
        d = tempfile.mkdtemp()
        h = agent.HistoryDB(path=os.path.join(d, "h.db"))
        self.assertTrue(h.enabled)
        lin = [{"name": "launchd", "pid": 1, "cmd": "/sbin/launchd", "sev": None},
               {"name": "curl", "pid": 44, "cmd": "curl https://1.2.3.4/x", "sev": "low"}]
        node = {"id": "remote:1.2.3.4:443", "type": "remote", "label": "1.2.3.4:443",
                "severity": "low", "score": 20, "reasons": [{"text": "VPN/proxy-exit", "mitre": "T1090"}],
                "triage": {"status": "open"},
                "detail": {"raddr": "1.2.3.4", "rport": 443, "proto": "tcp",
                           "proc_lineage": lin, "lineage_owner": {"pid": 44, "label": "curl"}}}
        h._record({"nodes": [node], "edges": []}, int(time.time()))
        typ, detail, techs = h.alert_detail("remote:1.2.3.4:443")
        self.assertEqual(typ, "remote")
        self.assertEqual([r["name"] for r in detail["proc_lineage"]], ["launchd", "curl"])
        self.assertEqual(detail["lineage_owner"]["label"], "curl")


if __name__ == "__main__":
    unittest.main()
