#!/usr/bin/env python3
"""Agent Access Audit — Phase 2: scope reading.

Covers the locally-readable scope sources (gcloud ADC), the broad-scope classifier, the OPT-IN
`gh auth status` probe (off by default, never shells out unless the env gate is set), the
scope_status honesty contract (read / unknown / none — unknown is never guessed and never silently
becomes none), and the collector emitting ai-scope-excessive (high when the identity is wired into an
agent, medium when dormant) only where the scope was actually read.

Pure stdlib. Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402

GH_STATUS = "github.com\n  ✓ Logged in to github.com\n  - Token scopes: 'gist', 'read:org', 'repo'\n"


def full_mcp(name, env_keys, client="Claude Code", source="/tmp/.mcp.json"):
    return {"client": client, "name": name, "scope": "user", "source": source,
            "env_keys": list(env_keys), "writable": False, "transport": "stdio",
            "command": "node", "package": "", "url_host": "", "fetched": False,
            "offensive": False, "offensive_tokens": []}


class GcpAdcScopes(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def _adc(self, obj):
        p = os.path.join(self.d, "adc.json")
        with open(p, "w") as f:
            json.dump(obj, f)
        return p

    def test_authorized_user_scopes_are_read(self):
        p = self._adc({"type": "authorized_user",
                       "scopes": ["https://www.googleapis.com/auth/cloud-platform", "openid"]})
        self.assertEqual(agent.read_gcp_adc_scopes(p)[0],
                         "https://www.googleapis.com/auth/cloud-platform")

    def test_service_account_without_scopes_is_none(self):
        p = self._adc({"type": "service_account", "client_email": "x@p.iam.gserviceaccount.com"})
        self.assertIsNone(agent.read_gcp_adc_scopes(p))

    def test_garbage_is_none(self):
        p = os.path.join(self.d, "x.json")
        with open(p, "w") as f:
            f.write("not json{{")
        self.assertIsNone(agent.read_gcp_adc_scopes(p))


class BroadScopeClassifier(unittest.TestCase):
    def test_gcp_cloud_platform_is_broad(self):
        broad, grants = agent.classify_scope_breadth(
            "Google Cloud", ["https://www.googleapis.com/auth/cloud-platform"])
        self.assertTrue(broad)
        self.assertEqual(len(grants), 1)

    def test_github_admin_scopes_broad_readonly_not(self):
        self.assertTrue(agent.classify_scope_breadth("GitHub", ["repo", "gist"])[0])
        self.assertTrue(agent.classify_scope_breadth("GitHub", ["admin:org"])[0])
        self.assertFalse(agent.classify_scope_breadth("GitHub", ["read:org", "gist"])[0])

    def test_empty_is_not_broad(self):
        self.assertEqual(agent.classify_scope_breadth("GitHub", None), (False, []))


class GithubProbe(unittest.TestCase):
    def setUp(self):
        self._run, self._which = agent.run, agent.shutil.which
        os.environ.pop("SCOUTER_AGENT_SCOPE_PROBE", None)

    def tearDown(self):
        agent.run, agent.shutil.which = self._run, self._which
        os.environ.pop("SCOUTER_AGENT_SCOPE_PROBE", None)

    def test_disabled_by_default_and_does_not_shell_out(self):
        called = []
        agent.run = lambda *a, **k: called.append(a) or (0, GH_STATUS, "")
        self.assertIsNone(agent.probe_github_scopes())
        self.assertEqual(called, [], "gh must not be invoked when the probe is disabled")

    def test_enabled_parses_scopes_without_token(self):
        agent.shutil.which = lambda n: "/usr/bin/gh" if n == "gh" else None
        agent.run = lambda cmd, timeout=15, env=None: (0, GH_STATUS, "")
        self.assertEqual(agent.probe_github_scopes(env_value="1"), ["gist", "read:org", "repo"])

    def test_enabled_but_gh_absent_is_none(self):
        agent.shutil.which = lambda n: None
        self.assertIsNone(agent.probe_github_scopes(env_value="1"))


class AnnotateScopesHonesty(unittest.TestCase):
    def test_status_read_unknown_none_are_distinct(self):
        c = agent.AISurfaceCollector(enabled=False, baseline_file=None)
        d = tempfile.mkdtemp()
        adc = os.path.join(d, "adc.json")
        with open(adc, "w") as f:
            json.dump({"type": "authorized_user",
                       "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}, f)
        os.environ.pop("SCOUTER_AGENT_SCOPE_PROBE", None)   # gh probe OFF
        nhi = [
            {"provider": "Google Cloud", "kind": "adc", "path": adc, "source": adc, "used_by": []},
            {"provider": "SSH", "kind": "private-key", "path": "/h/.ssh/id_rsa",
             "source": "/h/.ssh/id_rsa", "used_by": []},
            {"provider": "GitHub", "kind": "token", "path": "", "source": "env:GITHUB_TOKEN",
             "used_by": ["Claude Code/gh"]},
            {"provider": "AWS", "kind": "access-key", "path": "/h/.aws/credentials",
             "source": "/h/.aws/credentials", "used_by": []},
        ]
        c._annotate_scopes(nhi)
        by = {r["provider"]: r for r in nhi}
        self.assertEqual(by["Google Cloud"]["scope_status"], "read")
        self.assertTrue(by["Google Cloud"]["scope_broad"])
        self.assertEqual(by["SSH"]["scope_status"], "none")        # no scope concept
        self.assertEqual(by["GitHub"]["scope_status"], "unknown")  # probe off -> unknown, not none
        self.assertFalse(by["GitHub"]["scope_broad"])
        self.assertEqual(by["AWS"]["scope_status"], "unknown")     # IAM-defined, not local


class CollectorScopeFinding(unittest.TestCase):
    def _collector(self, home, mcp):
        c = agent.AISurfaceCollector(enabled=False, baseline_file=os.path.join(home, "b.json"))
        c._gather_agents = lambda procs: []
        c._gather_runtimes = lambda procs, net: []
        c._gather_offensive = lambda procs, net: []
        c._gather_context = lambda: []
        c._gather_egress = lambda *a, **k: []
        c._gather_mcp = lambda: mcp
        return c

    def setUp(self):
        self.home = tempfile.mkdtemp()
        gc = os.path.join(self.home, ".config", "gcloud")
        os.makedirs(gc)
        # a dormant, broadly-scoped ADC file on disk (not wired to any agent)
        with open(os.path.join(gc, "application_default_credentials.json"), "w") as f:
            json.dump({"type": "authorized_user",
                       "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}, f)
        self._orig = (agent._ai_home, agent.collect_processes, agent.collect_network,
                      agent.run, agent.shutil.which)
        agent._ai_home = lambda: self.home
        agent.collect_processes = lambda: {}
        agent.collect_network = lambda: {}

    def tearDown(self):
        (agent._ai_home, agent.collect_processes, agent.collect_network,
         agent.run, agent.shutil.which) = self._orig
        os.environ.pop("SCOUTER_AGENT_SCOPE_PROBE", None)

    def _scope_findings(self, c):
        return [n for n in c.snapshot() if n["detail"].get("finding") == "scope-excessive"]

    def test_dormant_broad_scope_is_medium(self):
        os.environ.pop("SCOUTER_AGENT_SCOPE_PROBE", None)
        c = self._collector(self.home, mcp=[])
        c._collect()
        fs = self._scope_findings(c)
        gcp = [f for f in fs if f["detail"]["provider"] == "Google Cloud"]
        self.assertTrue(gcp, "dormant cloud-platform ADC must raise scope-excessive")
        self.assertEqual(gcp[0]["severity"], "medium")   # dormant -> 45
        self.assertFalse(gcp[0]["detail"]["active"])

    def test_active_broad_scope_is_high(self):
        agent.shutil.which = lambda n: "/usr/bin/gh" if n == "gh" else None
        agent.run = lambda cmd, timeout=15, env=None: (0, GH_STATUS, "")
        os.environ["SCOUTER_AGENT_SCOPE_PROBE"] = "1"
        c = self._collector(self.home, mcp=[full_mcp("gh", ["GITHUB_TOKEN"])])
        c._collect()
        gh = [f for f in self._scope_findings(c) if f["detail"]["provider"] == "GitHub"]
        self.assertTrue(gh, "an agent-wired GitHub token with repo scope must raise scope-excessive")
        self.assertEqual(gh[0]["severity"], "high")       # active -> 70
        self.assertTrue(gh[0]["detail"]["active"])

    def test_unknown_scope_raises_nothing(self):
        # probe OFF: the GitHub token's scope is unknown -> no scope-excessive finding for it
        os.environ.pop("SCOUTER_AGENT_SCOPE_PROBE", None)
        c = self._collector(self.home, mcp=[full_mcp("gh", ["GITHUB_TOKEN"])])
        c._collect()
        self.assertFalse([f for f in self._scope_findings(c)
                          if f["detail"]["provider"] == "GitHub"],
                         "unknown scope must never raise a finding")


if __name__ == "__main__":
    unittest.main(verbosity=2)
