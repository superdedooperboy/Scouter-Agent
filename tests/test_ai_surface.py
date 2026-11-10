#!/usr/bin/env python3
"""AI Surface Inventory (Phase 1 of AI-agent-abuse detection) — the inventory is read-only,
the four scored exposures fire on exactly the right conditions, and the two privacy walls hold.

The collector catalogues every AI agent / local runtime / MCP server / instruction file on the host
and emits a scored node ONLY for a genuine exposure: F1 remote-url MCP (T1567), F2 npx/uvx-fetched MCP
(T1195), F3 a local LLM runtime reachable off-loopback (T1133), F4 an MCP config or instruction file an
attacker could rewrite (T1574). Privacy walls: MCP env is captured as KEY NAMES only (never values) and
remote MCP urls keep the HOST only (never a querystring token); instruction files are captured as
path + sha256 + mtime only (never content).

Pure stdlib. Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


def _write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _dump(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)


def _findings_by_mitre(nodes):
    out = {}
    for n in nodes:
        out.setdefault(n["reasons"][0]["mitre"], []).append(n)
    return out


class McpParsing(unittest.TestCase):
    def test_remote_npx_and_env_keyname_only(self):
        tmp = tempfile.mkdtemp()
        cfg = os.path.join(tmp, "mcp.json")
        _dump(cfg, {"mcpServers": {
            "weather-remote": {"url": "https://mcp.example.com/sse?token=SECRET_TOKEN_123", "type": "sse"},
            "fetchpkg": {"command": "npx", "args": ["-y", "@evil/mcp-fetch"],
                         "env": {"API_KEY": "s3cr3t-value", "DEBUG": "1"}},
            "localstdio": {"command": "/usr/local/bin/mymcp", "args": [], "env": {"TOKEN": "abc"}},
        }})

        orig = agent._mcp_config_paths
        agent._mcp_config_paths = lambda: [(cfg, "Cursor", "project")]
        try:
            c = agent.AISurfaceCollector(enabled=True, endpoints=None)
            mcp = c._gather_mcp()
        finally:
            agent._mcp_config_paths = orig

        by_name = {s["name"]: s for s in mcp}
        self.assertEqual(set(by_name), {"weather-remote", "fetchpkg", "localstdio"})

        # remote: host captured, token NOT captured anywhere
        rem = by_name["weather-remote"]
        self.assertEqual(rem["transport"], "remote")
        self.assertEqual(rem["url_host"], "mcp.example.com")
        self.assertNotIn("SECRET_TOKEN_123", json.dumps(rem))

        # npx-fetched: flagged, package captured
        fetched = by_name["fetchpkg"]
        self.assertTrue(fetched["fetched"])
        self.assertEqual(fetched["package"], "@evil/mcp-fetch")
        # env KEY NAMES only, never values
        self.assertEqual(fetched["env_keys"], ["API_KEY", "DEBUG"])
        self.assertNotIn("s3cr3t-value", json.dumps(fetched))

        # plain stdio local server: no exposure flags
        loc = by_name["localstdio"]
        self.assertEqual(loc["transport"], "stdio")
        self.assertFalse(loc["fetched"])
        self.assertEqual(loc["env_keys"], ["TOKEN"])


class Findings(unittest.TestCase):
    def test_four_findings_fire_on_the_right_conditions(self):
        tmp = tempfile.mkdtemp()
        cfg = os.path.join(tmp, "mcp.json")
        _dump(cfg, {"mcpServers": {
            "remote1": {"url": "https://api.example.com/mcp", "type": "http"},
            "npxfetch": {"command": "uvx", "args": ["some-mcp-pkg"]},
            "normal": {"command": "/opt/mcp/bin/server"},
        }})
        os.chmod(cfg, 0o666)                         # world-writable -> F4(config)

        ctx = os.path.join(tmp, "CLAUDE.md")
        _write(ctx, "# rules\n")
        os.chmod(ctx, 0o666)                         # world-writable -> F4(context)

        orig_paths = agent._mcp_config_paths
        orig_roots = agent._ai_project_roots
        orig_home = agent._ai_home
        agent._mcp_config_paths = lambda: [(cfg, "Cursor", "project")]
        agent._ai_project_roots = lambda limit=60: []
        agent._ai_home = lambda: "/nonexistent-home-xyz"
        try:
            c = agent.AISurfaceCollector(enabled=True, endpoints=None, context_roots=[tmp])
            c._collect()
            nodes = c.snapshot()
        finally:
            agent._mcp_config_paths = orig_paths
            agent._ai_project_roots = orig_roots
            agent._ai_home = orig_home

        by_mitre = _findings_by_mitre(nodes)
        # F1 remote MCP (T1567), F2 npx-fetched (T1195.x), F4 writable config+context (T1574 x2)
        self.assertEqual(len(by_mitre.get("T1567", [])), 1, "F1 remote MCP")
        self.assertTrue(any(m.startswith("T1195") for m in by_mitre), "F2 npx-fetched MCP")
        t1574 = by_mitre.get("T1574", [])
        self.assertEqual(len(t1574), 2, "F4 world-writable config + context")
        for n in nodes:
            self.assertEqual(n["severity"], agent.severity_for(n["score"]))
            self.assertTrue(n["type"].startswith("ai-"))

    def test_world_writable_mcp_file_flags_once_not_per_server(self):
        # a config file with three servers, world-writable, yields ONE F4(config), not three
        tmp = tempfile.mkdtemp()
        cfg = os.path.join(tmp, "mcp.json")
        _dump(cfg, {"mcpServers": {"a": {"command": "x"}, "b": {"command": "y"},
                                   "c": {"command": "z"}}})
        os.chmod(cfg, 0o666)
        orig = agent._mcp_config_paths
        agent._mcp_config_paths = lambda: [(cfg, "Cursor", "project")]
        try:
            c = agent.AISurfaceCollector(enabled=True, endpoints=None)
            c._collect()
            writable = [n for n in c.snapshot()
                        if n["detail"].get("finding") == "world-writable-config"]
        finally:
            agent._mcp_config_paths = orig
        self.assertEqual(len(writable), 1)

    def test_runtime_exposed_only_when_off_loopback(self):
        c = agent.AISurfaceCollector(enabled=True, endpoints=None)
        # loopback-bound Ollama -> catalogued, NO finding
        procs = {}
        net_loop = {111: [{"state": "LISTEN", "laddr": "127.0.0.1", "lport": "11434",
                           "raddr": "", "rport": "", "proto": "TCP"}]}
        rts = c._gather_runtimes(procs, net_loop)
        self.assertEqual(len(rts), 1)
        self.assertEqual(rts[0]["name"], "Ollama")
        self.assertFalse(rts[0]["public"])
        # 0.0.0.0-bound -> public -> F3
        net_pub = {111: [{"state": "LISTEN", "laddr": "*", "lport": "11434",
                          "raddr": "", "rport": "", "proto": "TCP"}]}
        rts2 = c._gather_runtimes(procs, net_pub)
        self.assertTrue(rts2[0]["public"])

    def test_no_false_positive_on_common_system_ports(self):
        # 5000 (macOS AirPlay) / 8000 (dev servers) must NOT be read as runtimes
        c = agent.AISurfaceCollector(enabled=True, endpoints=None)
        net = {222: [{"state": "LISTEN", "laddr": "*", "lport": "5000", "raddr": "", "rport": "", "proto": "TCP"}],
               333: [{"state": "LISTEN", "laddr": "*", "lport": "8000", "raddr": "", "rport": "", "proto": "TCP"}]}
        self.assertEqual(c._gather_runtimes({}, net), [])


class ContextPrivacy(unittest.TestCase):
    def test_instruction_file_hash_and_mtime_only_never_content(self):
        tmp = tempfile.mkdtemp()
        secret = "SECRET-PROMPT-INJECTION-STRING"
        p = os.path.join(tmp, "AGENTS.md")
        _write(p, "# agents\n" + secret + "\n")

        orig_home = agent._ai_home
        orig_roots = agent._ai_project_roots
        agent._ai_home = lambda: "/nonexistent-home-xyz"
        agent._ai_project_roots = lambda limit=60: []
        try:
            c = agent.AISurfaceCollector(enabled=True, endpoints=None, context_roots=[tmp])
            ctx = c._gather_context()
        finally:
            agent._ai_home = orig_home
            agent._ai_project_roots = orig_roots

        self.assertEqual(len(ctx), 1)
        rec = ctx[0]
        self.assertEqual(len(rec["sha256"]), 64)
        self.assertIn("mtime", rec)
        self.assertNotIn(secret, json.dumps(rec))   # content never captured


class LlmEndpointFeed(unittest.TestCase):
    def test_static_set_and_suffix_matching(self):
        feed = agent.LLMEndpointFeed(enabled=True, feed_url=None, cache_file=None)
        self.assertEqual(feed.provider_for_host("api.openai.com"), "OpenAI")
        self.assertEqual(feed.provider_for_host("api.anthropic.com"), "Anthropic")
        # azure suffix
        self.assertEqual(feed.provider_for_host("my-resource.openai.azure.com"), "Azure OpenAI")
        # bedrock narrowed to bedrock-runtime.*
        self.assertEqual(feed.provider_for_host("bedrock-runtime.us-east-1.amazonaws.com"), "AWS Bedrock")
        self.assertIsNone(feed.provider_for_host("s3.us-east-1.amazonaws.com"))
        self.assertIsNone(feed.provider_for_host("example.com"))
        self.assertGreaterEqual(feed.status()["static"], 15)


class CollectorContract(unittest.TestCase):
    def test_summary_and_detail_shape(self):
        # the live collector must produce a meta summary and a /api/ai-surface detail without raising
        c = agent.AISurfaceCollector(enabled=True, endpoints=None)
        c._collect()
        s = c.summary()
        for k in ("enabled", "agents", "runtimes", "mcp", "context", "egress", "flagged"):
            self.assertIn(k, s)
        d = c.detail()
        for k in ("enabled", "agents", "runtimes", "mcp", "context", "counts"):
            self.assertIn(k, d)
        self.assertEqual(d["enabled"], True)


if __name__ == "__main__":
    unittest.main()
