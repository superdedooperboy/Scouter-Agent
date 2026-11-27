"""Agent side of per-device credential binding (code-review finding #1).

The mesh issues a per-device credential on first contact and derives our identity from it thereafter.
This pins the agent's half: it adopts an issued key, presents it on every mesh request alongside the
site token, and forgets it on unenroll.
"""
import os
import tempfile
import unittest

import agent


class FakeSecrets:
    def __init__(self):
        self.d = {}

    def get(self, k):
        return self.d.get(k)

    def set(self, k, v):
        self.d[k] = v
        return "memory"


class MeshDeviceKey(unittest.TestCase):
    def _reporter(self):
        return agent.MeshReporter(cache=object(), secrets=FakeSecrets(),
                                  settings_file=os.path.join(tempfile.mkdtemp(), "mesh.json"))

    def test_starts_without_a_device_key(self):
        mr = self._reporter()
        self.assertEqual(mr.device_key, "")
        self.assertNotIn("X-Scouter-Device", mr._mesh_headers())   # nothing to present yet

    def test_adopts_and_persists_issued_key(self):
        mr = self._reporter()
        mr._maybe_device_key({"device_key": "issued-key-xyz"})
        self.assertEqual(mr.device_key, "issued-key-xyz")
        self.assertEqual(mr.secrets.get(mr.DEVICE_SECRET_ID), "issued-key-xyz")  # saved to Keychain
        self.assertEqual(mr.counts.get("device_key"), 1)

    def test_key_reload_from_secret_store(self):
        secrets = FakeSecrets()
        secrets.set("mesh-device-key", "persisted-key")
        mr = agent.MeshReporter(cache=object(), secrets=secrets,
                                settings_file=os.path.join(tempfile.mkdtemp(), "mesh.json"))
        self.assertEqual(mr.device_key, "persisted-key")

    def test_headers_carry_token_and_device_key(self):
        mr = self._reporter()
        mr.token = "site-token"
        mr.set_device_key("dev-123")
        h = mr._mesh_headers()
        self.assertEqual(h["X-Scouter-Mesh-Token"], "site-token")
        self.assertEqual(h["X-Scouter-Device"], "dev-123")
        self.assertEqual(h["Content-Type"], "application/json")
        self.assertNotIn("Content-Type", mr._mesh_headers(content_type=False))

    def test_reissue_supersedes(self):
        mr = self._reporter()
        mr._maybe_device_key({"device_key": "first"})
        mr._maybe_device_key({"device_key": "second"})     # re-enroll → fresh key
        self.assertEqual(mr.device_key, "second")
        self.assertEqual(mr.counts.get("device_key"), 2)
        mr._maybe_device_key({"device_key": "second"})     # unchanged → no churn
        self.assertEqual(mr.counts.get("device_key"), 2)

    def test_unenroll_forgets_device_key(self):
        mr = self._reporter()
        mr.set_device_key("dev-123")
        mr.unenroll()
        self.assertEqual(mr.device_key, "")
        self.assertEqual(mr.secrets.get(mr.DEVICE_SECRET_ID), "")


if __name__ == "__main__":
    unittest.main()
