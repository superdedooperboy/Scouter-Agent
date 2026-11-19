#!/usr/bin/env python3
"""Agent Access Audit — Phase 1: non-human-identity (NHI) inventory.

Covers the env-var credential classifier, the on-disk credential-store scanner (presence / mode /
provider / NON-SECRET labels, never a value), and the AISurfaceCollector wiring that turns those into
the two scored findings — ai-identity-exposed (A1) and ai-identity-new (A2) — with a learn-only first
pass. The hard privacy invariant (no credential VALUE ever reaches a record or a finding) is asserted
directly.

Pure stdlib. Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402

# a credential value that must NEVER appear in any emitted record or finding.
SECRET_SENTINELS = ("AKIAZZEXAMPLEKEY", "ghp_SUPERSECRETTOKENVALUE", "hunter2password")


def full_mcp(name, env_keys, client="Claude Code", source="/tmp/.mcp.json"):
    """A complete MCP server record, as _gather_mcp would emit it, so the collector's F1–F4 code
    (which reads source/writable/transport/…) runs cleanly in these NHI-focused tests."""
    return {"client": client, "name": name, "scope": "user", "source": source,
            "env_keys": list(env_keys), "writable": False, "transport": "stdio",
            "command": "node", "package": "", "url_host": "", "fetched": False,
            "offensive": False, "offensive_tokens": []}


class EnvClassifier(unittest.TestCase):
    def test_provider_and_kind_mapping(self):
        cases = {
            "GITHUB_TOKEN": ("GitHub", "token"),
            "GH_TOKEN": ("GitHub", "token"),
            "AWS_ACCESS_KEY_ID": ("AWS", "access-key"),
            "AWS_SECRET_ACCESS_KEY": ("AWS", "secret"),
            "OPENAI_API_KEY": ("OpenAI", "api-key"),
            "ANTHROPIC_API_KEY": ("Anthropic", "api-key"),
            "GOOGLE_APPLICATION_CREDENTIALS": ("Google Cloud", "service-account"),
            "SLACK_BOT_TOKEN": ("Slack", "token"),
            "DB_PASSWORD": ("Other", "password"),
            "AWS_PROFILE": ("AWS", "profile"),
            "KUBECONFIG": ("Kubernetes", "kubeconfig"),
        }
        for k, exp in cases.items():
            self.assertEqual(agent.classify_cred_env(k), exp, "mismatch for " + k)

    def test_non_credential_env_is_ignored(self):
        for k in ("PATH", "HOME", "NODE_ENV", "MCP_SERVER_NAME", "LANG", "PWD_DIR", ""):
            self.assertIsNone(agent.classify_cred_env(k), "should NOT classify: " + repr(k))


class StoreScanner(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.home, ".aws"))
        os.makedirs(os.path.join(self.home, ".ssh"))
        os.makedirs(os.path.join(self.home, ".config", "gh"))

    def _write(self, rel, content, mode):
        p = os.path.join(self.home, rel)
        with open(p, "w") as f:
            f.write(content)
        os.chmod(p, mode)
        return p

    def test_world_readable_secret_is_flagged_and_labeled(self):
        self._write(".aws/credentials",
                    "[default]\naws_access_key_id=%s\n[prod]\nx=1\n" % SECRET_SENTINELS[0], 0o644)
        recs = agent.scan_credential_stores(home=self.home, platform="linux")
        aws = next(r for r in recs if r["provider"] == "AWS" and r["kind"] == "access-key")
        self.assertTrue(aws["secret_bearing"])
        self.assertTrue(aws["world_readable"])        # 0o644 -> readable by others
        self.assertIn("default", aws["labels"])
        self.assertIn("prod", aws["labels"])

    def test_owner_only_secret_is_not_world_readable(self):
        self._write(".config/gh/hosts.yml",
                    "github.com:\n  user: alice\n  oauth_token: %s\n" % SECRET_SENTINELS[1], 0o600)
        recs = agent.scan_credential_stores(home=self.home, platform="linux")
        gh = next(r for r in recs if r["provider"] == "GitHub")
        self.assertFalse(gh["world_readable"])
        self.assertIn("github.com", gh["labels"])
        self.assertIn("user alice", gh["labels"])

    def test_ssh_private_key_in_but_pub_excluded(self):
        self._write(".ssh/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\n", 0o600)
        self._write(".ssh/id_rsa.pub", "ssh-rsa AAAAB3Nz\n", 0o644)
        recs = agent.scan_credential_stores(home=self.home, platform="linux")
        self.assertTrue(any(r["provider"] == "SSH" and r["kind"] == "private-key" for r in recs))
        self.assertFalse(any(r["source"].endswith(".pub") for r in recs))

    def test_no_secret_value_ever_in_records(self):
        self._write(".aws/credentials", "[default]\naws_secret_access_key=%s\n" % SECRET_SENTINELS[0], 0o644)
        self._write(".netrc", "machine api.example.com login bob password %s\n" % SECRET_SENTINELS[2], 0o644)
        recs = agent.scan_credential_stores(home=self.home, platform="linux")
        blob = repr(recs)
        for s in SECRET_SENTINELS:
            self.assertNotIn(s, blob, "SECRET VALUE LEAKED into NHI records")
        # the netrc machine (non-secret) is still captured
        netrc = next(r for r in recs if r["provider"] == "netrc")
        self.assertIn("api.example.com", netrc["labels"])


class GatherNhi(unittest.TestCase):
    def test_env_identities_attributed_to_mcp_server(self):
        c = agent.AISurfaceCollector(enabled=False, baseline_file=None)
        mcp = [{"client": "Claude Code", "name": "github", "env_keys": ["GITHUB_TOKEN", "PATH"]},
               {"client": "Cursor", "name": "aws", "env_keys": ["AWS_ACCESS_KEY_ID"]}]
        nhi = c._gather_nhi(mcp)
        gh = next(r for r in nhi if r["source"] == "env:GITHUB_TOKEN")
        self.assertEqual(gh["used_by"], ["Claude Code/github"])
        self.assertFalse(any(r["source"] == "env:PATH" for r in nhi), "PATH must not be an identity")


class CollectorFindings(unittest.TestCase):
    """End-to-end through _collect with controlled inputs: learn-only suppresses A2 but not A1, and a
    newly-wired identity fires A2 on the second pass."""

    def _collector(self, home, mcp):
        bl = os.path.join(home, "baseline.json")
        c = agent.AISurfaceCollector(enabled=False, baseline_file=bl)
        # neutralize every other gatherer so the run is deterministic
        c._gather_agents = lambda procs: []
        c._gather_runtimes = lambda procs, net: []
        c._gather_offensive = lambda procs, net: []
        c._gather_context = lambda: []
        c._gather_egress = lambda *a, **k: []
        c._gather_mcp = lambda: mcp
        return c

    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.home, ".aws"))
        with open(os.path.join(self.home, ".aws", "credentials"), "w") as f:
            f.write("[default]\naws_access_key_id=%s\n" % SECRET_SENTINELS[0])
        os.chmod(os.path.join(self.home, ".aws", "credentials"), 0o644)   # world-readable -> A1
        self._orig_home = agent._ai_home
        self._orig_procs = agent.collect_processes
        self._orig_net = agent.collect_network
        agent._ai_home = lambda: self.home
        agent.collect_processes = lambda: {}
        agent.collect_network = lambda: {}

    def tearDown(self):
        agent._ai_home = self._orig_home
        agent.collect_processes = self._orig_procs
        agent.collect_network = self._orig_net

    def _exposed(self, c):
        return [n for n in c.snapshot() if n["detail"].get("finding") == "nhi-exposed"]

    def _new(self, c):
        return [n for n in c.snapshot() if n["detail"].get("finding") == "nhi-new"]

    def test_learnonly_fires_exposed_but_not_new(self):
        c = self._collector(self.home, mcp=[full_mcp("gh", ["GITHUB_TOKEN"])])
        self.assertTrue(c.learn_only)
        c._collect()
        self.assertTrue(self._exposed(c), "world-readable AWS creds must fire A1 even on first pass")
        self.assertFalse(self._new(c), "no A2 on the learn-only first pass")
        self.assertFalse(c.learn_only, "baseline learned after first pass")

    def test_new_identity_fires_on_second_pass(self):
        c = self._collector(self.home, mcp=[full_mcp("gh", ["GITHUB_TOKEN"])])
        c._collect()                                  # learn
        self.assertFalse(self._new(c))
        # a new identity is wired in and we collect again
        c._gather_mcp = lambda: [full_mcp("gh", ["GITHUB_TOKEN"]),
                                 full_mcp("stripe", ["STRIPE_API_KEY"], client="Cursor")]
        c._collect()
        news = self._new(c)
        self.assertTrue(any(n["detail"]["provider"] == "Stripe" for n in news),
                        "the newly-wired Stripe identity must fire A2")

    def test_findings_carry_no_secret_value(self):
        c = self._collector(self.home, mcp=[full_mcp("gh", ["GITHUB_TOKEN"])])
        c._collect()
        blob = repr(c.snapshot()) + repr(c.inv)
        for s in SECRET_SENTINELS:
            self.assertNotIn(s, blob, "SECRET VALUE LEAKED into a finding/inventory")

    def test_exposed_finding_is_high_severity_credential_access(self):
        c = self._collector(self.home, mcp=[])
        c._collect()
        f = self._exposed(c)[0]
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["reasons"][0]["mitre"], "T1552.001")


if __name__ == "__main__":
    unittest.main(verbosity=2)
