#!/usr/bin/env python3
"""b-audit-tamper: flushing audit rules or disabling auditing (anti-forensics, T1562.001).

The Linux analog of the macOS FSEvents-wipe gap: `auditctl -D` flushes every rule and `auditctl -e 0`
disables auditing while leaving auditd running (so it still looks healthy). Must fire on those and on
deletion of /var/log/audit/, and stay quiet on ordinary auditctl use.

Pure stdlib. Run from the linux/ dir:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402

RULE = next(r for r in agent.BUILTIN_RULES if r["id"] == "b-audit-tamper")


def proc(cmdline):
    return {"type": "process", "label": "x", "detail": {"cmdline": cmdline}}


class TestAuditTamper(unittest.TestCase):
    def test_flags_audit_tampering(self):
        for cmd in (
            "auditctl -D",
            "auditctl -e 0",
            "/sbin/auditctl -e 0",
            "rm -f /var/log/audit/audit.log",
            "shred -u /var/log/audit/audit.log.1",
            "auditctl -R /dev/null",
        ):
            self.assertTrue(agent.rule_node_matches(RULE, proc(cmd)), "should flag: " + cmd)

    def test_quiet_on_normal_auditctl(self):
        for cmd in (
            "auditctl -l",                 # list rules
            "auditctl -e 1",               # enable auditing
            "auditctl -s",                 # status
            "auditctl -w /etc/passwd -p wa -k identity",
        ):
            self.assertFalse(agent.rule_node_matches(RULE, proc(cmd)), "should NOT flag: " + cmd)

    def test_rated_high_confidence(self):
        self.assertEqual(agent.rule_confidence(RULE), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
