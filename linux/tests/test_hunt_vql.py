#!/usr/bin/env python3
"""VQL (Velociraptor) parity for the auto-hunts and advisory hunts.

The SQL hunts ask Scouter's recorded history "where has this indicator been seen"; the VQL twins ask
the live system (via Velociraptor plugins) "is it here / running now". Every advisory hunt and every
IOC-driven auto-hunt kind must carry a VQL alongside its SQL, and the VQL string-escaping must be
injection-safe (IOC values come from attacker-influenced telemetry).

Note: Velociraptor isn't available in CI, so these assert the GENERATED VQL (shape + escaping), not a
live run. Pure stdlib. Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


class TestAdvisoryHuntsHaveVql(unittest.TestCase):
    def test_every_advisory_hunt_has_sql_and_vql(self):
        self.assertTrue(agent.ADVISORY_HUNTS)
        for adv in agent.ADVISORY_HUNTS:
            for hn in adv["hunts"]:
                self.assertTrue(hn.get("sql"), "%s/%s missing sql" % (adv["id"], hn["name"]))
                self.assertTrue(hn.get("vql"), "%s/%s missing vql" % (adv["id"], hn["name"]))
                # the VQL should use a Velociraptor plugin, not look like SQL against the history DB
                self.assertRegex(hn["vql"], r"(pslist\(\)|netstat\(\)|glob\(|foreach\()")
                self.assertNotIn("FROM processes", hn["vql"])


class TestAutohuntVql(unittest.TestCase):
    def test_every_sql_kind_has_a_vql_twin(self):
        # whatever kinds autohunt_sql handles, autohunt_vql must handle too (and vice versa)
        for kind in ("sha256", "md5", "ip", "domain", "url", "cmdline", "path"):
            self.assertIsNotNone(agent.autohunt_sql(kind, "x" * 64 if kind in ("sha256", "md5") else "v"),
                                 "autohunt_sql missing " + kind)
            self.assertIsNotNone(agent.autohunt_vql(kind, "x" * 64 if kind in ("sha256", "md5") else "v"),
                                 "autohunt_vql missing " + kind)
        self.assertIsNone(agent.autohunt_vql("nonsense", "v"))

    def test_hash_kind_uses_glob_and_hash(self):
        q = agent.autohunt_vql("sha256", "a" * 64)
        self.assertIn("hash(path=OSPath).SHA256", q)
        self.assertIn("glob(globs=", q)

    def test_ip_kind_uses_netstat(self):
        self.assertIn("netstat()", agent.autohunt_vql("ip", "8.8.8.8"))

    def test_cmdline_kind_uses_pslist(self):
        self.assertIn("pslist()", agent.autohunt_vql("cmdline", "curl | sh"))


class TestVqlEscaping(unittest.TestCase):
    def test_vqlstr_escapes_quotes_and_backslashes(self):
        self.assertEqual(agent._vqlstr("a'b"), "'a\\'b'")
        self.assertEqual(agent._vqlstr("a\\b"), "'a\\\\b'")

    def test_vqlrx_is_case_insensitive_and_escapes_metachars(self):
        rx = agent._vqlrx("a.b")
        self.assertTrue(rx.startswith("'(?i)"))
        self.assertIn("\\\\.", rx)                      # the regex dot is escaped (literal)

    def test_malicious_value_cannot_break_out_of_the_literal(self):
        # a value trying to close the string + inject must stay inside the quotes
        q = agent.autohunt_vql("cmdline", "x' OR 1=1 --")
        # exactly two UNescaped single quotes (the delimiters); the injected one is escaped as \'
        body = q.split("WHERE CommandLine =~ ", 1)[1]
        literal = body.split("\n", 1)[0].strip()
        self.assertTrue(literal.startswith("'") and literal.endswith("'"))
        self.assertIn("\\'", literal)                   # the attacker quote was escaped


if __name__ == "__main__":
    unittest.main(verbosity=2)
