#!/usr/bin/env python3
"""b-forensic-wipe: deletion/clearing of a macOS forensic store (anti-forensics, T1070.004).

The FSEvents gap — nothing flagged wiping /.fseventsd (the filesystem-change log) or the unified-log
store — plus the Phase-2 provenance DBs (QuarantineEventsV2, TCC.db). Must fire on a deliberate wipe
of those stores and stay quiet on ordinary file deletion and the supported `tccutil reset`.

Pure stdlib. Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402

RULE = next(r for r in agent.BUILTIN_RULES if r["id"] == "b-forensic-wipe")


def proc(cmdline):
    return {"type": "process", "label": "x", "detail": {"cmdline": cmdline}}


class TestForensicWipe(unittest.TestCase):
    def test_flags_forensic_store_wipes(self):
        for cmd in (
            "rm -rf /.fseventsd",
            "srm -rf /System/Volumes/Data/.fseventsd",
            "rm -rf /var/db/diagnostics",
            "shred -u /var/db/uuidtext/ABCD",
            "rm /Users/lonnie/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
            "rm '/Library/Application Support/com.apple.TCC/TCC.db'",
            "truncate -s 0 /.fseventsd/0000000000a1b2c3",
        ):
            self.assertTrue(agent.rule_node_matches(RULE, proc(cmd)), "should flag: " + cmd)

    def test_quiet_on_benign_deletion_and_supported_reset(self):
        for cmd in (
            "rm -rf /tmp/build",
            "rm /Users/lonnie/Downloads/notes.txt",
            "tccutil reset All com.example.app",     # the SUPPORTED way to reset privacy perms
            "rm -rf node_modules",
        ):
            self.assertFalse(agent.rule_node_matches(RULE, proc(cmd)), "should NOT flag: " + cmd)

    def test_rated_high_confidence(self):
        self.assertEqual(agent.rule_confidence(RULE), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
