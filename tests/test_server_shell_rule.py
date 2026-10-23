#!/usr/bin/env python3
"""b-lin-server-shell ancestry coverage.

A shell spawned by an internet-facing service is one of the highest-fidelity RCE/webshell signals
there is. The ancestry set must include the Node runtime family (node/deno/bun) so a Node app RCE
that spawns a shell — Node2Shell (CVE-2026-111497) or any other — is caught the same way a PHP2Shell
shell is. Pinned here because the two agents' ancestry lists drifted (Linux was missing node).

Pure stdlib. Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402

RULE = next(r for r in agent.BUILTIN_RULES if r["id"] == "b-lin-server-shell")


def proc(ancestry, label):
    return {"type": "process", "label": label, "detail": {"ancestry": ancestry, "label": label}}


class TestServerShellAncestry(unittest.TestCase):
    def test_node_runtime_family_spawning_a_shell_is_caught(self):
        for runtime in ("node", "deno", "bun"):
            self.assertTrue(agent.rule_node_matches(RULE, proc("systemd > %s" % runtime, "sh")),
                            "%s > sh should match b-lin-server-shell" % runtime)

    def test_php_worker_still_caught(self):
        self.assertTrue(agent.rule_node_matches(RULE, proc("systemd > php-fpm", "bash")))

    def test_node_without_a_shell_child_is_not_a_match(self):
        # 'ls' is not in the interpreter/shell label set — a node tree doing benign work must not fire.
        self.assertFalse(agent.rule_node_matches(RULE, proc("systemd > node", "ls")))

    def test_shell_without_a_server_ancestor_is_not_a_match(self):
        self.assertFalse(agent.rule_node_matches(RULE, proc("login > zsh", "sh")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
