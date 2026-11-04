#!/usr/bin/env python3
"""b-chrome-safestorage — critical Keychain Safe-Storage-key read.

Reading a browser's Safe Storage key from the login Keychain via the `security` CLI is the step that
turns copied cookie/password DBs into plaintext — the highest-signal action in the current macOS
stealer playbook. The rule must catch BOTH command forms:
  - the service-string form:  security find-generic-password -s "Chrome Safe Storage"
  - the account form an AMOS/Odyssey sample was seen using on macOS 26.4+:
        security find-generic-password -ga "Chrome"
    (pberba.github.io/security/2026/10/20/amos-keychain). The account form used to fall through to
    the medium b-keychain-find rule; this pins it at critical.

Pure stdlib. Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402

RULE = next(r for r in agent.BUILTIN_RULES if r["id"] == "b-chrome-safestorage")


def proc(cmdline):
    return {"type": "process", "label": "security", "detail": {"cmdline": cmdline, "label": "security"}}


class TestSafeStorageRule(unittest.TestCase):
    def test_rule_is_critical(self):
        self.assertEqual(RULE["severity"], "critical")
        self.assertEqual(RULE["mitre"], "T1555.001")

    def test_account_form_amos(self):
        # the exact command documented in the article, plus unquoted + other browsers
        for cmd in ('security find-generic-password -ga "Chrome"',
                    "security find-generic-password -ga Chrome",
                    'security find-generic-password -a "Brave" -g',
                    'security find-generic-password -gwa "Microsoft Edge"',
                    'security find-generic-password -ga "Google Chrome"',
                    'security find-generic-password -ga "Arc"'):
            self.assertTrue(agent.rule_node_matches(RULE, proc(cmd)),
                            "should be CRITICAL: %s" % cmd)

    def test_service_string_form_still_caught(self):
        for cmd in ('security find-generic-password -s "Chrome Safe Storage" -w',
                    'security find-generic-password -s "Microsoft Edge Safe Storage"'):
            self.assertTrue(agent.rule_node_matches(RULE, proc(cmd)))

    def test_non_browser_account_not_critical(self):
        # a keychain read for a non-browser account must NOT hit the critical rule
        # (b-keychain-find still covers it at medium)
        for cmd in ('security find-generic-password -ga "GitHub"',
                    'security find-generic-password -s "AWS"',
                    'security find-generic-password -a "slack" -w'):
            self.assertFalse(agent.rule_node_matches(RULE, proc(cmd)),
                             "should NOT be critical: %s" % cmd)

    def test_unrelated_commands_not_matched(self):
        for cmd in ('security unlock-keychain -p hunter2 build.keychain',
                    'chrome --password-store=basic',
                    'ls -la ~/Library/Keychains'):
            self.assertFalse(agent.rule_node_matches(RULE, proc(cmd)))

    def test_medium_fallback_still_exists(self):
        # the broadening must not have removed the medium generic rule
        self.assertTrue(any(r["id"] == "b-keychain-find" for r in agent.BUILTIN_RULES))


if __name__ == "__main__":
    unittest.main(verbosity=2)
