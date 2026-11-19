#!/usr/bin/env python3
"""Agent Access Audit — Phase 4: agent file-reach / credential-access audit.

Covers the sensitive-path matcher, the AI-lineage map (a process descending from an AI agent is
attributed to it), the cross-platform cmdline reach, and the collector's ai-access-sensitive finding
with its learn-only baseline. A benign non-AI process touching the same path must stay silent, and an
emitted event carries a path but never file contents.

Pure stdlib. Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


class SensitivePathMatcher(unittest.TestCase):
    def test_known_stores_match(self):
        cases = {
            "/Users/x/.aws/credentials": "cloud-credentials",
            "/home/u/.ssh/id_ed25519": "ssh-key",
            "/home/u/.config/gh/hosts.yml": "vcs-token",
            "/home/u/.kube/config": "kubeconfig",
            "/u/Library/Application Support/Google/Chrome/Default/Login Data": "browser-passwords",
            "/home/u/.mozilla/firefox/ab.default/logins.json": "browser-passwords",
            "/home/u/.mozilla/firefox/ab.default/cookies.sqlite": "browser-cookies",
        }
        for path, cat in cases.items():
            m = agent.match_sensitive_path(path)
            self.assertIsNotNone(m, "should match: " + path)
            self.assertEqual(m[0], cat, path)

    def test_ordinary_paths_do_not_match(self):
        for path in ("/usr/bin/python3", "/home/u/project/src/main.py", "/tmp/notes.txt", ""):
            self.assertIsNone(agent.match_sensitive_path(path), "should NOT match: " + path)


class LineageMap(unittest.TestCase):
    def test_descendants_of_an_ai_agent_are_attributed(self):
        procs = {
            100: {"pid": 100, "ppid": 1, "exe": "/opt/claude", "cmdline": "claude"},
            101: {"pid": 101, "ppid": 100, "exe": "/bin/bash", "cmdline": "bash -c x"},
            102: {"pid": 102, "ppid": 101, "exe": "/usr/bin/curl", "cmdline": "curl"},
            200: {"pid": 200, "ppid": 1, "exe": "/bin/zsh", "cmdline": "zsh"},
        }
        lm = agent.ai_lineage_map(procs, ai_pids={100}, ai_bases={"claude"})
        self.assertEqual(lm.get(101), "claude")
        self.assertEqual(lm.get(102), "claude")   # grandchild
        self.assertNotIn(200, lm)                  # unrelated process

    def test_cycle_is_safe(self):
        procs = {1: {"pid": 1, "ppid": 2, "exe": "a", "cmdline": "a"},
                 2: {"pid": 2, "ppid": 1, "exe": "b", "cmdline": "b"}}
        self.assertEqual(agent.ai_lineage_map(procs, set(), set()), {})


class GatherAccessCmdline(unittest.TestCase):
    def test_cmdline_reference_under_ai_lineage(self):
        c = agent.AISurfaceCollector(enabled=False, baseline_file=None)
        procs = {
            100: {"pid": 100, "ppid": 1, "exe": "/opt/claude", "cmdline": "claude"},
            101: {"pid": 101, "ppid": 100, "exe": "/bin/cat",
                  "cmdline": "cat /Users/x/.aws/credentials"},
        }
        acc = c._gather_access(procs, ai_pids={100}, ai_bases={"claude"})
        hit = next(a for a in acc if a["category"] == "cloud-credentials")
        self.assertEqual(hit["agent"], "claude")
        self.assertEqual(hit["source"], "cmdline")

    def test_non_ai_process_is_silent(self):
        c = agent.AISurfaceCollector(enabled=False, baseline_file=None)
        procs = {
            300: {"pid": 300, "ppid": 1, "exe": "/bin/zsh", "cmdline": "zsh"},
            301: {"pid": 301, "ppid": 300, "exe": "/bin/cat",
                  "cmdline": "cat /Users/x/.aws/credentials"},
        }
        acc = c._gather_access(procs, ai_pids=set(), ai_bases={"claude"})
        self.assertEqual(acc, [], "a non-AI-lineage process must raise no access event")


class CollectorAccessFinding(unittest.TestCase):
    def _collector(self, home):
        c = agent.AISurfaceCollector(enabled=False, baseline_file=os.path.join(home, "b.json"))
        c._gather_agents = lambda procs: []
        c._gather_runtimes = lambda procs, net: []
        c._gather_offensive = lambda procs, net: []
        c._gather_context = lambda: []
        c._gather_egress = lambda *a, **k: []
        c._gather_mcp = lambda: []
        # a fixed AI-lineage access: claude -> cat ~/.aws/credentials
        c._procs = {100: {"pid": 100, "ppid": 1, "exe": "/opt/claude", "cmdline": "claude"},
                    101: {"pid": 101, "ppid": 100, "exe": "/bin/cat",
                          "cmdline": "cat /root/.aws/credentials"}}
        c._gather_access = lambda procs, ai_pids, ai_bases: agent.AISurfaceCollector._gather_access(
            c, c._procs, {100}, {"claude"})
        return c

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self._orig = (agent._ai_home, agent.collect_processes, agent.collect_network)
        agent._ai_home = lambda: self.home
        agent.collect_processes = lambda: {}
        agent.collect_network = lambda: {}

    def tearDown(self):
        agent._ai_home, agent.collect_processes, agent.collect_network = self._orig

    def _access_findings(self, c):
        return [n for n in c.snapshot() if n["detail"].get("finding") == "access-sensitive"]

    def test_learnonly_suppresses_then_fires(self):
        c = self._collector(self.home)
        c._collect()                                  # learn-only: record, no alarm
        self.assertFalse(self._access_findings(c), "first (learn-only) pass must not alarm")
        self.assertTrue(c.inv["access"], "the access event is still inventoried on the first pass")
        # same access again -> baselined -> still quiet
        c._collect()
        self.assertFalse(self._access_findings(c), "a baselined (agent, path) pair stays quiet")

    def test_new_pair_after_baseline_fires_high(self):
        c = self._collector(self.home)
        c._collect()                                  # learn
        # a NEW access: claude reaches an SSH key it never touched before
        c._procs = {100: {"pid": 100, "ppid": 1, "exe": "/opt/claude", "cmdline": "claude"},
                    102: {"pid": 102, "ppid": 100, "exe": "/bin/cat",
                          "cmdline": "cat /root/.ssh/id_rsa"}}
        c._collect()
        fs = self._access_findings(c)
        self.assertTrue(any("id_rsa" in f["detail"]["path"] for f in fs), "new (agent,path) must fire")
        self.assertEqual(fs[0]["severity"], "high")

    def test_event_has_no_file_contents(self):
        c = self._collector(self.home)
        c._collect()
        blob = repr(c.inv["access"])
        self.assertNotIn("aws_access_key_id", blob)   # we never read the file body
        ev = c.inv["access"][0]
        self.assertEqual(set(ev) >= {"agent", "path", "category", "source", "ts"}, True)
        self.assertNotIn("content", ev)


if __name__ == "__main__":
    unittest.main(verbosity=2)
