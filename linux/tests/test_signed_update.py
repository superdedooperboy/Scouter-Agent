"""Signed-release update path + staged rollback (code-review finding #3).

A fleet-pushed update used to be a bare `git pull --ff-only` + re-exec. Now the agent (1) refuses to
apply a pulled commit that isn't signed by a PINNED release key, and (2) applies it as a staged change
that rolls back automatically if the new version can't come up cleanly. These pin that logic without a
real git repo by stubbing the `run()` helper where the crypto / reset happens.
"""
import json
import os
import tempfile
import unittest

import agent


class _Run:
    """Swap in for agent.run; returns a scripted (rc, out, err) per git subcommand."""
    def __init__(self, verify_rc=0, reset_rc=0):
        self.verify_rc, self.reset_rc = verify_rc, reset_rc
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        if "verify-commit" in cmd:
            return (self.verify_rc, "", "ok" if self.verify_rc == 0 else "bad")
        if "reset" in cmd:
            return (self.reset_rc, "", "")
        return (0, "", "")


class ReleaseVerifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._orig_run = agent.run

    def tearDown(self):
        agent.run = self._orig_run

    def test_no_signer_file_fails_closed(self):
        agent.run = _Run(verify_rc=0)
        ok, detail = agent.release_verify_head(self.tmp, allow_unverified=False)
        self.assertFalse(ok)                                 # unverifiable → refuse by default
        self.assertIn("pinned release signer", detail)

    def test_no_signer_file_allowed_with_optin(self):
        agent.run = _Run(verify_rc=0)
        ok, _ = agent.release_verify_head(self.tmp, allow_unverified=True)
        self.assertTrue(ok)                                  # explicit escape hatch

    def test_signed_commit_passes(self):
        with open(os.path.join(self.tmp, agent.RELEASE_SIGNERS_FILE), "w") as _f:
            _f.write("signer ssh-ed25519 AAAA...\n")
        agent.run = _Run(verify_rc=0)
        ok, detail = agent.release_verify_head(self.tmp)
        self.assertTrue(ok)
        self.assertIn("verified", detail)

    def test_unsigned_commit_rejected(self):
        with open(os.path.join(self.tmp, agent.RELEASE_SIGNERS_FILE), "w") as _f:
            _f.write("signer ssh-ed25519 AAAA...\n")
        agent.run = _Run(verify_rc=1)                        # git verify-commit non-zero
        ok, detail = agent.release_verify_head(self.tmp)
        self.assertFalse(ok)
        self.assertIn("not signed by a pinned release key", detail)


class StagedRollbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._orig_run = agent.run

    def tearDown(self):
        agent.run = self._orig_run

    def _marker(self):
        with open(agent._update_stage_path(self.tmp)) as f:
            return json.load(f)

    def test_begin_writes_marker(self):
        agent.staged_update_begin(self.tmp, "PREV", "NEW", "9.9.9")
        m = self._marker()
        self.assertEqual((m["prev_sha"], m["new_sha"], m["boots"]), ("PREV", "NEW", 0))

    def test_mark_healthy_commits(self):
        agent.staged_update_begin(self.tmp, "PREV", "NEW", None)
        agent.staged_update_mark_healthy(self.tmp)
        self.assertFalse(os.path.exists(agent._update_stage_path(self.tmp)))
        self.assertIsNone(agent.staged_update_confirm_or_rollback(self.tmp))  # nothing pending

    def test_boots_accumulate_then_rollback(self):
        agent.run = _Run(reset_rc=0)
        agent.staged_update_begin(self.tmp, "PREVSHA", "NEWSHA", None)
        # Each boot without confirming increments the counter; it stays "watching" until the cap.
        for _ in range(agent.UPDATE_MAX_BOOTS):
            r = agent.staged_update_confirm_or_rollback(self.tmp)
            self.assertEqual(r["action"], "watching")
        # The next boot exceeds the cap → roll back to prev_sha and clear the marker.
        r = agent.staged_update_confirm_or_rollback(self.tmp)
        self.assertEqual(r["action"], "rolled_back")
        self.assertTrue(r["ok"])
        self.assertEqual(r["prev_sha"], "PREVSHA")
        self.assertFalse(os.path.exists(agent._update_stage_path(self.tmp)))
        self.assertTrue(any("reset" in c and "PREVSHA" in c for c in agent.run.calls))

    def test_healthy_before_cap_prevents_rollback(self):
        agent.staged_update_begin(self.tmp, "PREV", "NEW", None)
        agent.staged_update_confirm_or_rollback(self.tmp)   # boot 1, watching
        agent.staged_update_mark_healthy(self.tmp)           # came up clean → commit
        self.assertIsNone(agent.staged_update_confirm_or_rollback(self.tmp))  # no pending update now


if __name__ == "__main__":
    unittest.main()
