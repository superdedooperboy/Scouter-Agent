#!/usr/bin/env python3
"""Compromise Assessment — the on-demand local sweep mirrored from the Scouter Mesh pack.

Covers pack integrity, the single-host VQL localizer (unwrapping the fleet `foreach(clients())`),
the keep/drop/probe filter (identical semantics to the Mesh, including the fail-open probe-miss),
and the CompromiseAssessment runner against a stub Velociraptor — so no VR binary is needed. The
honesty invariant is asserted directly: a query error is reported as 'could not run', never as a
clean result.

Pure stdlib. Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


class FakeVR:
    """Stand-in VelociraptorManager: a binary is 'present', and query_local returns canned rows
    chosen by the VQL text so the runner can be exercised without Velociraptor installed."""

    def __init__(self, have_binary=True):
        self._have = have_binary

    def find_binary(self):
        return "/usr/bin/velociraptor" if self._have else None

    def query_local(self, vql, timeout=120):
        def ok(rows, cols):
            return {"ok": True, "rows": rows, "columns": cols, "count": len(rows)}
        if "netstat()" in vql:
            rows = [
                {"laddr": "0.0.0.0", "lport": "22", "raddr": "", "rport": "", "Status": "LISTEN", "Pid": 1},
                {"laddr": "127.0.0.1", "lport": "5000", "raddr": "", "rport": "", "Status": "LISTEN", "Pid": 2},
                {"laddr": "192.168.1.5", "lport": "52000", "raddr": "93.184.216.34", "rport": "443", "Status": "ESTABLISHED", "Pid": 3},
                {"laddr": "192.168.1.5", "lport": "52001", "raddr": "10.0.0.5", "rport": "443", "Status": "ESTABLISHED", "Pid": 4},
            ]
            return ok(rows, ["laddr", "lport", "raddr", "rport", "Status", "Pid"])
        if "pslist()" in vql:
            rows = [
                {"Name": "cloudflared", "Exe": "/usr/local/bin/cloudflared", "CommandLine": "cloudflared tunnel run"},
                {"Name": "bash", "Exe": "/bin/bash", "CommandLine": "bash"},
                {"Name": "x", "Exe": "/tmp/.hidden/x", "CommandLine": "/tmp/.hidden/x"},
            ]
            return ok(rows, ["Name", "Exe", "CommandLine"])
        if "info()" in vql:
            return ok([{"Hostname": "host-01", "OS": "darwin", "Platform": "macOS",
                        "Release": "26.0", "Architecture": "arm64"}],
                      ["Hostname", "OS", "Platform", "Release", "Architecture"])
        if "TCC.db" in vql or "sqlite(" in vql:
            return {"ok": False, "error": "could not open TCC.db (needs Full Disk Access)"}
        if "authorized_keys" in vql:
            return ok([{"OSPath": "/Users/x/.ssh/authorized_keys", "Mtime": "2026-01-01",
                        "Data": "ssh-ed25519 AAAA... attacker@evil"}],
                      ["OSPath", "Mtime", "Data"])
        return ok([], ["OSPath", "Mtime"])   # every other glob check comes back clean


class PackIntegrity(unittest.TestCase):
    def test_required_fields_and_unique_ids(self):
        ids = set()
        for c in agent.COMPROMISE_ASSESSMENT:
            for k in ("id", "cat", "os", "severity", "title", "why", "vql"):
                self.assertIn(k, c, "%s missing %s" % (c.get("id"), k))
            self.assertNotIn(c["id"], ids, "duplicate id %s" % c["id"])
            ids.add(c["id"])
            self.assertIn(c["severity"], ("critical", "high", "medium", "low", "info"))

    def test_assessment_for_filters_by_os(self):
        mac = agent.assessment_for("darwin")
        self.assertTrue(all(c["os"] in ("darwin", "any") for c in mac))
        self.assertFalse(any(c["os"] == "linux" for c in mac))
        self.assertTrue(any(c["id"] == "net-listening" for c in mac))   # 'any' checks included


class Localizer(unittest.TestCase):
    def test_no_fleet_constructs_survive(self):
        for c in agent.COMPROMISE_ASSESSMENT:
            local = agent._assess_localize(c["vql"])
            self.assertNotIn("clients()", local, c["id"])
            self.assertNotIn("foreach(", local, c["id"])
            self.assertNotIn("os_info.hostname", local, c["id"])
            self.assertTrue(local.lstrip().upper().startswith("SELECT"), c["id"])

    def test_netstat_pslist_reduce_to_bare_select(self):
        by = {c["id"]: c for c in agent.COMPROMISE_ASSESSMENT}
        self.assertEqual(agent._assess_localize(by["net-listening"]["vql"]), "SELECT * FROM netstat()")
        self.assertEqual(agent._assess_localize(by["net-tunnel-rmm"]["vql"]), "SELECT * FROM pslist()")

    def test_scope_check_becomes_info(self):
        by = {c["id"]: c for c in agent.COMPROMISE_ASSESSMENT}
        self.assertIn("info()", agent._assess_localize(by["any-enrolled"]["vql"]))


class Filter(unittest.TestCase):
    def test_keep_drop_listening(self):
        q = next(c for c in agent.COMPROMISE_ASSESSMENT if c["id"] == "net-listening")
        rows = FakeVR().query_local("SELECT * FROM netstat()")["rows"]
        kept, note = agent.assess_filter(rows, q)
        self.assertEqual(note, "")
        laddrs = {r["laddr"] for r in kept}
        self.assertIn("0.0.0.0", laddrs)        # listening beyond loopback kept
        self.assertNotIn("127.0.0.1", laddrs)   # loopback dropped

    def test_keep_drop_established_public_only(self):
        q = next(c for c in agent.COMPROMISE_ASSESSMENT if c["id"] == "net-established")
        rows = FakeVR().query_local("SELECT * FROM netstat()")["rows"]
        kept, _ = agent.assess_filter(rows, q)
        raddrs = {r["raddr"] for r in kept}
        self.assertEqual(raddrs, {"93.184.216.34"})   # public kept, 10.0.0.5 (private) dropped

    def test_probe_miss_fails_open_with_note(self):
        # Rows whose field NAMES contain none of the probe hints => schema mismatch => show all + note.
        q = next(c for c in agent.COMPROMISE_ASSESSMENT if c["id"] == "net-listening")  # probe ['status','state']
        rows = [{"foo": "LISTEN 0.0.0.0"}, {"foo": "bar"}]
        kept, note = agent.assess_filter(rows, q)
        self.assertEqual(len(kept), 2)
        self.assertTrue(note)


class Runner(unittest.TestCase):
    def _run(self, vr):
        ca = agent.CompromiseAssessment(vr, responder=None)
        checks = agent.assessment_for("darwin")
        ca._started = time.time()
        ca._progress = {"done": 0, "total": len(checks), "current": ""}
        ca._run(checks)
        return ca._result, {f["id"]: f for f in ca._result["findings"]}

    def test_unavailable_without_binary(self):
        ca = agent.CompromiseAssessment(FakeVR(have_binary=False))
        self.assertFalse(ca.available())
        self.assertFalse(ca.start().get("ok"))

    def test_full_run_statuses_and_honesty(self):
        res, by = self._run(FakeVR())
        # a network hit is surfaced
        self.assertEqual(by["net-listening"]["status"], "hits")
        self.assertEqual(by["net-tunnel-rmm"]["status"], "hits")
        self.assertTrue(any("cloudflared" in str(r) for r in by["net-tunnel-rmm"]["rows"]))
        self.assertEqual(by["net-proc-oddpath"]["status"], "hits")   # /tmp/.hidden/x
        # a file check with a planted key is a hit
        self.assertEqual(by["mac-authorized-keys"]["status"], "hits")
        # a failed query is 'could not run', never silently clean
        self.assertEqual(by["mac-tcc-grants"]["status"], "skipped")
        self.assertIn("note", by["mac-tcc-grants"])
        # an empty query is genuinely clean
        self.assertEqual(by["mac-sysext-kext"]["status"], "clean")
        # summary adds up
        s = res["summary"]
        self.assertEqual(s["checks"], len(agent.assessment_for("darwin")))
        self.assertEqual(s["checks"], s["with_hits"] + s["clean"] + s["could_not_run"])
        self.assertGreaterEqual(s["with_hits"], 4)

    def test_run_never_reads_a_secret_value_into_summary(self):
        # Honesty + privacy sibling: the summary carries counts, not row contents.
        res, _ = self._run(FakeVR())
        self.assertNotIn("attacker@evil", agent.json.dumps(res["summary"]))


if __name__ == "__main__":
    unittest.main()
