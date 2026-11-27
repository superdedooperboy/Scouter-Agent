"""Agent side of sensor coverage (code-review finding #5).

The agent normalizes its per-subsystem meta into a compact sensor roster — ok / off / blind — that
rides every mesh check-in, so the fleet sees coverage gaps independently of connectivity.
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


class SensorHealth(unittest.TestCase):
    def _reporter(self):
        return agent.MeshReporter(cache=object(), secrets=FakeSecrets(),
                                  settings_file=os.path.join(tempfile.mkdtemp(), "mesh.json"))

    def test_classifies_ok_off_blind(self):
        mr = self._reporter()
        meta = {"epoch": 1000, "privilege": "user",
                "persist": {"enabled": True, "needs_root": ["/Library/LaunchDaemons"]},  # blind
                "dns": {"enabled": True},                                                # ok
                "tcc": {"enabled": False}}                                               # off
        sh = mr._sensor_health(meta)
        self.assertEqual((sh["ok"], sh["off"], sh["blind"]), (1, 1, 1))
        self.assertTrue(sh["degraded"])
        self.assertEqual(sh["privilege"], "user")
        by = {i["name"]: i for i in sh["items"]}
        self.assertEqual(by["Persistence"]["state"], "blind")
        self.assertIn("LaunchDaemons", by["Persistence"]["detail"])
        self.assertEqual(by["Persistence"]["last"], 1000)
        self.assertEqual(by["DNS"]["state"], "ok")
        self.assertEqual(by["TCC"]["state"], "off")

    def test_not_degraded_when_all_collecting(self):
        mr = self._reporter()
        meta = {"epoch": 1, "privilege": "full",
                "persist": {"enabled": True}, "dns": {"enabled": True}}
        sh = mr._sensor_health(meta)
        self.assertFalse(sh["degraded"])
        self.assertEqual(sh["blind"], 0)

    def test_skips_absent_or_malformed_subsystems(self):
        mr = self._reporter()
        sh = mr._sensor_health({"epoch": 1, "persist": "not-a-dict"})
        self.assertEqual(sh["items"], [])


if __name__ == "__main__":
    unittest.main()
