#!/usr/bin/env python3
"""build_auth_map — the flat, auditable events[] list behind the Authentications table.

The Authentications tab used to surface records only via per-map-point drill-in, and device (local)
logins only became map points when external-IP resolution was on — so a workstation with console/sudo
logins and the (default-off) external-IP lookup showed an empty map and NO auditable data. The payload
now carries a flat events[] of every auth row in the window — remote + device, mapped or not — each
tagged with the point key `pk` (empty = unmapped) so a selected point filters the table.

Pure stdlib. Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


class FakeHist:
    def __init__(self, rows):
        self._rows = rows

    def recent_auths(self, days):
        return self._rows


class FakeExtIP:
    def __init__(self, status):
        self._s = status

    def status(self):
        return self._s


class FakeGeo:
    enabled = True

    def lookup(self, ip):
        return ({"country": "US", "lat": 37.4, "lng": -122.1, "summary": "Mountain View, US"}
                if ip == "8.8.8.8" else None)


ROWS = [  # newest-first, as recent_auths returns
    {"ts": 1700, "user": "lonnie", "source": "console", "method": "login", "success": True},
    {"ts": 1699, "user": "lonnie", "source": "sudo", "method": "sudo", "success": True},
    {"ts": 1698, "user": "root", "source": "45.9.148.7", "method": "ssh", "success": False},  # global, no geo
    {"ts": 1697, "user": "admin", "source": "8.8.8.8", "method": "ssh", "success": True},      # global, geo
]


class AuthMapEvents(unittest.TestCase):
    def _build(self, ext_enabled):
        ext = {"enabled": True, "resolved": True, "lat": 1.0, "lng": 2.0,
               "country": "GB", "place": "London, GB"} if ext_enabled else {"enabled": False}
        return agent.build_auth_map(FakeHist(ROWS), FakeGeo(), FakeExtIP(ext), days=30)

    def test_every_row_is_itemized_even_with_extip_off(self):
        out = self._build(ext_enabled=False)
        self.assertEqual(len(out["events"]), 4)
        cats = sorted(e["cat"] for e in out["events"])
        self.assertEqual(cats, ["device", "device", "remote", "remote"])

    def test_device_events_present_and_unmapped_when_extip_off(self):
        out = self._build(ext_enabled=False)
        dev = [e for e in out["events"] if e["cat"] == "device"]
        self.assertEqual(len(dev), 2)                       # the whole point: still auditable
        self.assertTrue(all(e["pk"] == "" for e in dev))    # not placed on the map
        self.assertEqual(out["unmapped"]["device"], 2)

    def test_geolocated_remote_event_links_to_a_point(self):
        out = self._build(ext_enabled=False)
        ev = next(e for e in out["events"] if e["source"] == "8.8.8.8")
        pks = {p["pk"] for p in out["points"]}
        self.assertIn(ev["pk"], pks)                        # selecting that point filters to this row
        self.assertEqual(ev["loc"], "Mountain View, US")

    def test_non_geolocated_remote_event_still_itemized(self):
        out = self._build(ext_enabled=False)
        ev = next(e for e in out["events"] if e["source"] == "45.9.148.7")
        self.assertEqual(ev["pk"], "")                      # unmapped, but present in the table
        self.assertEqual(out["unmapped"]["remote"], 1)

    def test_device_events_map_when_extip_resolved(self):
        out = self._build(ext_enabled=True)
        dev = [e for e in out["events"] if e["cat"] == "device"]
        pks = {p["pk"] for p in out["points"]}
        self.assertTrue(all(e["pk"] in pks for e in dev))   # now placed at the host's own location
        self.assertEqual(out["unmapped"]["device"], 0)

    def test_point_pk_matches_event_pk_shape(self):
        out = self._build(ext_enabled=True)
        for p in out["points"]:
            self.assertIn("pk", p)
            self.assertIsInstance(p["pk"], str)

    def test_empty_history(self):
        out = agent.build_auth_map(FakeHist([]), FakeGeo(), FakeExtIP({"enabled": False}), days=30)
        self.assertEqual(out["events"], [])
        self.assertFalse(out["events_trunc"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
