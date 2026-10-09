#!/usr/bin/env python3
"""In-agent vulnerability scanning (CTEM-Lite, macOS-first).

Three local pieces: OS-update currency (parsed from `softwareupdate -l`), a software inventory
(.app bundles + Homebrew), and a GeoIP-style advisory feed matched against installed versions
locally. These tests pin the version comparator, the softwareupdate/brew parsers, the feed index +
match, and the scanner's finding assembly — all without touching the live system.

Run from the repo root:  python3 -m unittest discover -s tests
"""
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


class TestVersionCompare(unittest.TestCase):
    def test_ver_key(self):
        self.assertEqual(agent._ver_key("131.0.6778.69"), (131, 0, 6778, 69))
        self.assertEqual(agent._ver_key("3.4.0"), (3, 4, 0))
        self.assertEqual(agent._ver_key(""), ())
        self.assertEqual(agent._ver_key(None), ())

    def test_vcmp(self):
        k = agent._ver_key
        self.assertEqual(agent._vcmp_key(k("1.2.0"), k("1.2")), 0)      # zero-padded tail
        self.assertEqual(agent._vcmp_key(k("1.10"), k("1.9")), 1)       # numeric, not lexical
        self.assertEqual(agent._vcmp_key(k("1.2.3"), k("1.2.4")), -1)

    def test_affected_ranges(self):
        A = agent._version_affected
        self.assertTrue(A("130.0", [{"lt": "131.0.6778.69"}]))         # below fixed -> affected
        self.assertFalse(A("131.0.6778.69", [{"lt": "131.0.6778.69"}]))  # at fixed -> safe
        self.assertFalse(A("132.0", [{"lt": "131.0.6778.69"}]))        # above fixed -> safe
        self.assertTrue(A("3.3.0", [{"ge": "3.0.0", "lt": "3.4.0"}]))  # inside a bounded range
        self.assertFalse(A("2.9.0", [{"ge": "3.0.0", "lt": "3.4.0"}]))  # below the lower bound
        self.assertFalse(A("", [{"lt": "9.9"}]))                       # unparseable -> never flagged
        self.assertFalse(A("1.0", []))                                 # no constraints -> no match


class TestSoftwareUpdateParse(unittest.TestCase):
    MODERN = """Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: macOS Sequoia 15.1-24B83
\tTitle: macOS Sequoia 15.1, Version: 15.1, Size: 787079KiB, Recommended: YES, Action: restart,
* Label: Command Line Tools for Xcode-16.1
\tTitle: Command Line Tools for Xcode, Version: 16.1, Size: 745661KiB, Recommended: YES,
"""
    LEGACY = """Software Update Tool

   * Security Update 2024-001-10.15.7
      Security Update 2024-001 (10.15.7), 1234567K [recommended] [restart]
"""

    def test_modern(self):
        ups = agent._parse_softwareupdate(self.MODERN)
        self.assertEqual(len(ups), 2)
        self.assertEqual(ups[0]["title"], "macOS Sequoia 15.1")
        self.assertTrue(ups[0]["recommended"])
        self.assertTrue(ups[0]["restart"])
        self.assertFalse(ups[1]["restart"])

    def test_legacy_security_flag(self):
        ups = agent._parse_softwareupdate(self.LEGACY)
        self.assertEqual(len(ups), 1)
        self.assertTrue(ups[0]["recommended"])
        self.assertTrue(ups[0]["restart"])
        self.assertTrue(ups[0]["security"])            # "Security Update" in the label

    def test_none_available(self):
        self.assertEqual(agent._parse_softwareupdate("No new software available."), [])

    def test_os_findings_severity(self):
        state = {"product_version": "15.0", "pending": agent._parse_softwareupdate(self.LEGACY)}
        f = agent.OSCurrency.findings(state)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "high")     # security/recommended -> high
        self.assertTrue(f[0]["restart"])
        self.assertEqual(agent.OSCurrency.findings({"pending": []}), [])


class TestBrewParse(unittest.TestCase):
    def test_versions(self):
        recs = agent._parse_brew_versions("openssl@3 3.3.0 3.4.0\nwget 1.24.5\nbadline\n")
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[0]["name"], "openssl@3")
        self.assertEqual(recs[0]["version"], "3.4.0")  # highest installed version kept
        self.assertEqual(recs[1]["version"], "1.24.5")


class TestVulnFeed(unittest.TestCase):
    def _feed(self, **kw):
        # seed-only, no disk cache, no refresh thread (url=None)
        return agent.VulnFeed(enabled=True, url=None,
                              cache_file="/nonexistent/vuln-feed.json", **kw)

    def test_seed_indexed(self):
        feed = self._feed()
        self.assertEqual(feed.status()["advisories"], len(agent.VULN_SEED_ADVISORIES))

    def test_match_bundle_id(self):
        feed = self._feed()
        hits = feed.match(bundle_id="com.google.Chrome", version="130.0.0.0")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["id"], "SCOUTER-EXAMPLE-CHROME")
        self.assertEqual(feed.match(bundle_id="com.google.Chrome", version="999.0"), [])

    def test_match_homebrew_eco(self):
        feed = self._feed()
        hits = feed.match(name="openssl@3", version="3.3.0",
                          ecosystem="Homebrew", package="openssl@3")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["id"], "SCOUTER-EXAMPLE-OPENSSL")

    def test_custom_seed_and_ingest(self):
        adv = {"id": "X", "severity": "critical", "match": {"name": "Foo"},
               "affected": [{"lt": "2.0"}]}
        feed = agent.VulnFeed(enabled=True, url=None, cache_file="/nonexistent/x.json", seed=[adv])
        self.assertEqual(feed.match(name="foo", version="1.0")[0]["id"], "X")   # case-insensitive
        feed._ingest({"advisories": [{"id": "R", "match": {"name": "Bar"},
                                      "affected": [{"lt": "5"}]}]}, source="remote")
        self.assertEqual(feed.status()["advisories"], 2)       # seed + remote
        self.assertEqual(feed.match(name="bar", version="4")[0]["id"], "R")


class TestScanner(unittest.TestCase):
    def test_build_findings_sorted_and_flagged(self):
        vs = agent.VulnScanner(enabled=False, feed_url=None)   # no threads
        osc = {"product_version": "15.0",
               "pending": [{"title": "Security Update", "recommended": True,
                            "restart": True, "security": True}]}
        inv = {"apps": [{"name": "Google Chrome", "bundle_id": "com.google.Chrome",
                         "version": "130.0.0.0"}],
               "brew": [{"name": "openssl@3", "version": "3.3.0"}],
               "counts": {"apps": 1, "brew": 1}}
        findings = vs._build_findings(osc, inv)
        # one OS finding + one app match + one brew match
        self.assertEqual(len(findings), 3)
        # sorted by severity: the two 'high' (OS + Chrome) precede the 'medium' (openssl)
        self.assertEqual(findings[-1]["severity"], "medium")
        self.assertTrue(all(f.get("example") for f in findings if f["source"] == "feed"))
        summ = vs._summary(findings)
        self.assertEqual(summ["total"], 3)
        self.assertEqual(summ["by_severity"]["high"], 2)

    def test_status_shape(self):
        vs = agent.VulnScanner(enabled=False, feed_url=None)
        st = vs.status()
        for key in ("findings", "os", "feed", "osv", "enabled", "summary"):
            self.assertIn(key, st)
        self.assertFalse(st["enabled"])

    def test_live_ranking(self):
        vs = agent.VulnScanner(enabled=False, feed_url=None)
        inv = {"apps": [{"name": "Google Chrome", "bundle_id": "com.google.Chrome",
                         "version": "130.0.0.0", "path": "/Applications/Google Chrome.app"}],
               "brew": [], "packages": []}
        live = {"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}   # a running exe in the bundle
        findings = vs._build_findings({"pending": []}, inv, live_exes=live)
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["live"])            # exe under the bundle path -> live
        # not running -> not live
        self.assertFalse(vs._build_findings({"pending": []}, inv, live_exes=set())[0]["live"])
        self.assertEqual(vs._summary(findings)["live"], 1)


class TestLangInventoryParse(unittest.TestCase):
    def test_pip_json(self):
        # the format pip --format=json emits
        import subprocess
        orig = agent._run_as_user
        agent._run_as_user = staticmethod(
            lambda cmd, timeout=60: (0, json.dumps([{"name": "requests", "version": "2.19.0"},
                                                     {"name": "urllib3", "version": "1.25.0"}]), ""))
        try:
            # force python3 present
            if not (agent.shutil.which("python3") or agent.shutil.which("python")):
                self.skipTest("no python on PATH")
            pkgs = agent._pip_packages()
        finally:
            agent._run_as_user = orig
        self.assertEqual(pkgs[0], {"ecosystem": "PyPI", "name": "requests", "version": "2.19.0"})


class TestOSV(unittest.TestCase):
    REC = {
        "id": "GHSA-xxxx", "summary": "requests vuln", "aliases": ["CVE-2023-0001"],
        "database_specific": {"severity": "HIGH"},
        "references": [{"url": "https://example/adv"}],
        "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}],
    }

    def test_osv_affected(self):
        affs = self.REC["affected"]
        self.assertEqual(agent._osv_affected("2.19.0", affs), "2.20.0")   # below fixed
        self.assertIsNone(agent._osv_affected("2.20.0", affs))            # at fixed -> safe
        self.assertIsNone(agent._osv_affected("2.31.0", affs))            # above fixed
        # exact-version list
        v = [{"package": {"ecosystem": "npm", "name": "left-pad"}, "versions": ["1.0.0"]}]
        self.assertEqual(agent._osv_affected("1.0.0", v), "")             # listed, no fixed known
        self.assertIsNone(agent._osv_affected("1.0.1", v))

    def test_osv_helpers(self):
        self.assertEqual(agent._osv_cve(self.REC), "CVE-2023-0001")
        self.assertEqual(agent._osv_severity(self.REC), "high")
        self.assertEqual(agent._osv_severity({"severity": [{"type": "CVSS_V3", "score": 9.8}]}), "critical")

    def test_osv_index_and_match(self):
        # build a tiny all.zip, point OSVFeeds at it, and match an installed package offline
        d = tempfile.mkdtemp()
        zp = os.path.join(d, "osv-pypi.zip")
        with zipfile.ZipFile(zp, "w") as z:
            z.writestr("GHSA-xxxx.json", json.dumps(self.REC))
            z.writestr("GHSA-other.json", json.dumps(
                {"id": "GHSA-other", "affected": [{"package": {"ecosystem": "PyPI", "name": "flask"},
                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0"}]}]}]}))
        osv = agent.OSVFeeds(enabled=True, ecosystems="pypi", cache_dir=d)
        # pretend requests is installed; _ensure sees the cached zip is fresh and indexes it
        osv.prepare([{"ecosystem": "PyPI", "name": "requests", "version": "2.19.0"}])
        hits = osv.match("PyPI", "requests", "2.19.0")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["cve"], "CVE-2023-0001")
        self.assertEqual(hits[0]["fixed"], "2.20.0")
        self.assertEqual(hits[0]["severity"], "high")
        # flask not in the wanted set -> not indexed -> no match even though it's in the zip
        self.assertEqual(osv.match("PyPI", "flask", "2.0"), [])
        # a safe version of a wanted package -> no hit
        self.assertEqual(osv.match("PyPI", "requests", "2.31.0"), [])

    def test_osv_off(self):
        osv = agent.OSVFeeds(enabled=True, ecosystems="off", cache_dir=tempfile.mkdtemp())
        osv.prepare([{"ecosystem": "PyPI", "name": "requests", "version": "1.0"}])
        self.assertEqual(osv.match("PyPI", "requests", "1.0"), [])


if __name__ == "__main__":
    unittest.main()
