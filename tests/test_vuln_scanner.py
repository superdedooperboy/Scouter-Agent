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


class TestRemediation(unittest.TestCase):
    def _scanner(self):
        vs = agent.VulnScanner(enabled=False, feed_url=None, osv="off")
        vs.remediation = agent.VulnRemediationStore(
            path=os.path.join(tempfile.mkdtemp(), "vuln-remediation.json"))
        return vs

    def test_sig_stable_across_version(self):
        a = {"kind": "app", "component": "Google Chrome", "cve": "CVE-1", "installed_version": "118"}
        b = dict(a, installed_version="120")                 # version changed, sig must not
        self.assertEqual(agent._finding_sig(a), agent._finding_sig(b))

    def test_mitigate_suppresses_from_active_counts(self):
        vs = self._scanner()
        inv = {"apps": [{"name": "Google Chrome", "bundle_id": "com.google.Chrome",
                         "version": "130.0.0.0", "path": "/Applications/Google Chrome.app"}],
               "brew": [], "packages": []}
        findings = vs._build_findings({"pending": []}, inv)
        vs._apply_remediation(findings, scanned_ts=1000)
        self.assertEqual(len(findings), 1)
        sig = findings[0]["sig"]
        self.assertEqual(vs._summary(findings)["total"], 1)   # active before remediation
        # mitigate it -> drops out of active counts, stays in the list as resolved
        vs.remediation.set(sig, "mitigated", note="WAF rule blocks the exploit path")
        vs._apply_remediation(findings, scanned_ts=1000)
        s = vs._summary(findings)
        self.assertEqual(s["total"], 0)
        self.assertEqual(s["resolved"], 1)
        self.assertFalse(agent.VulnScanner._active(findings[0]))
        self.assertEqual(findings[0]["remediation"]["status"], "mitigated")
        self.assertEqual(findings[0]["remediation"]["note"], "WAF rule blocks the exploit path")

    def test_patched_pending_then_conflict(self):
        vs = self._scanner()
        inv = {"apps": [{"name": "Google Chrome", "bundle_id": "com.google.Chrome",
                         "version": "130.0.0.0", "path": "/Applications/Google Chrome.app"}],
               "brew": [], "packages": []}
        findings = vs._build_findings({"pending": []}, inv)
        sig = agent._finding_sig(findings[0])
        vs.remediation.set(sig, "patched")
        pts = vs.remediation.get(sig)["ts"]
        # a scan that ran BEFORE the patch mark -> pending verification, suppressed, no conflict
        vs._apply_remediation(findings, scanned_ts=pts - 10)
        self.assertFalse(agent.VulnScanner._active(findings[0]))
        self.assertFalse(findings[0]["remediation"]["conflict"])
        self.assertEqual(vs._summary(findings)["total"], 0)
        # a fresh scan AFTER the mark that STILL detects it -> conflict -> re-opens as active
        findings2 = vs._build_findings({"pending": []}, inv)
        vs._apply_remediation(findings2, scanned_ts=pts + 10)
        self.assertTrue(findings2[0]["remediation"]["conflict"])
        self.assertTrue(agent.VulnScanner._active(findings2[0]))
        self.assertEqual(vs._summary(findings2)["total"], 1)

    def test_patched_gone_is_pruned(self):
        vs = self._scanner()
        vs.remediation.set("app|google chrome|cve-1", "patched")
        self.assertIsNotNone(vs.remediation.get("app|google chrome|cve-1"))
        # next scan no longer detects it (version now fixed) -> empty findings -> decision pruned
        vs._apply_remediation([], scanned_ts=9999)
        self.assertIsNone(vs.remediation.get("app|google chrome|cve-1"))

    def test_set_remediation_updates_result_live(self):
        vs = self._scanner()
        inv = {"apps": [{"name": "Google Chrome", "bundle_id": "com.google.Chrome",
                         "version": "130.0.0.0", "path": "/Applications/Google Chrome.app"}],
               "brew": [], "packages": []}
        findings = vs._build_findings({"pending": []}, inv)
        vs._apply_remediation(findings, 1000)
        vs._result = {"findings": findings, "scanned": 1000, "summary": vs._summary(findings)}
        sig = findings[0]["sig"]
        r = vs.set_remediation(sig, "accepted", note="low exposure", by="lonnie")
        self.assertTrue(r["ok"])
        self.assertEqual(vs._result["summary"]["total"], 0)     # recomputed without a rescan
        self.assertEqual(vs._result["findings"][0]["remediation"]["by"], "lonnie")


class TestEdrAlerts(unittest.TestCase):
    def _scanner(self, sev="critical"):
        d = tempfile.mkdtemp()
        self.fired = []
        vs = agent.VulnScanner(enabled=False, feed_url=None, osv="off",
                               alert_severity=sev, on_alert=lambda f: self.fired.append(f))
        vs._alerted_path = os.path.join(d, "vuln-alerted.json")
        vs._alerted, vs._alert_baselined = set(), False
        vs.remediation = agent.VulnRemediationStore(path=os.path.join(d, "rem.json"))
        return vs

    def _finding(self, sev, live=False, cve="CVE-X", comp="pkg"):
        return {"severity": sev, "component": comp, "cve": cve, "kind": "app",
                "sig": "app|%s|%s" % (comp, cve.lower()), "live": live, "remediation": None}

    def test_baseline_then_new_alert(self):
        vs = self._scanner("critical")
        existing = [self._finding("critical", cve="CVE-1")]
        vs._raise_alerts(existing)                      # first pass = silent baseline
        self.assertEqual(self.fired, [])
        # a NEW critical finding on the next scan fires
        vs._raise_alerts(existing + [self._finding("critical", cve="CVE-2")])
        self.assertEqual(len(self.fired), 1)
        self.assertEqual(self.fired[0]["cve"], "CVE-2")
        # re-scan with the same set -> no duplicate alert
        vs._raise_alerts(existing + [self._finding("critical", cve="CVE-2")])
        self.assertEqual(len(self.fired), 1)

    def test_threshold_and_live_high(self):
        vs = self._scanner("critical"); vs._alert_baselined = True
        vs._raise_alerts([self._finding("high", cve="H1")])          # high, not live -> no alert
        self.assertEqual(self.fired, [])
        vs._raise_alerts([self._finding("high", live=True, cve="H2")])  # high AND live -> alert
        self.assertEqual([f["cve"] for f in self.fired], ["H2"])

    def test_remediated_not_alerted(self):
        vs = self._scanner("critical"); vs._alert_baselined = True
        f = self._finding("critical", cve="CVE-9"); f["remediation"] = {"status": "mitigated"}
        vs._raise_alerts([f])                            # resolved -> not active -> no alert
        self.assertEqual(self.fired, [])

    def test_off_disables(self):
        vs = self._scanner("off"); vs._alert_baselined = True
        vs._raise_alerts([self._finding("critical")])
        self.assertEqual(self.fired, [])

    def test_recurrence_realerts_after_gone(self):
        vs = self._scanner("critical"); vs._alert_baselined = True
        vs._raise_alerts([self._finding("critical", cve="CVE-5")]); self.assertEqual(len(self.fired), 1)
        vs._raise_alerts([])                             # finding gone -> forgotten
        vs._raise_alerts([self._finding("critical", cve="CVE-5")]); self.assertEqual(len(self.fired), 2)


class TestEnrichment(unittest.TestCase):
    def test_osv_record_enriched(self):
        rec = {"id": "GHSA-x", "summary": "short", "details": "a long description of the flaw",
               "aliases": ["CVE-2023-9"], "published": "2023-01-02T00:00:00Z",
               "references": [{"type": "WEB", "url": "https://example/adv"},
                              {"type": "FIX", "url": "https://example/fix"}],
               "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
               "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}]}
        d = tempfile.mkdtemp()
        with zipfile.ZipFile(os.path.join(d, "osv-pypi.zip"), "w") as z:
            z.writestr("x.json", json.dumps(rec))
        osv = agent.OSVFeeds(enabled=True, ecosystems="pypi", cache_dir=d)
        osv.prepare([{"ecosystem": "PyPI", "name": "requests", "version": "1.0"}])
        hit = osv.match("PyPI", "requests", "1.0")[0]
        self.assertEqual(hit["description"], "a long description of the flaw")
        self.assertIn("https://example/adv", hit["references"])
        self.assertTrue(hit["cvss"].startswith("CVSSV3"))
        self.assertEqual(hit["aliases"], ["CVE-2023-9"])
        self.assertEqual(hit["published"], "2023-01-02T00:00:00Z")

    def test_os_currency_finding_has_description(self):
        f = agent.OSCurrency.findings({"product_version": "15.0", "pending": [
            {"title": "Security Update", "security": True, "recommended": True, "restart": True}]})[0]
        self.assertIn("description", f)
        self.assertTrue(f["references"])


class TestKevHuntKeyword(unittest.TestCase):
    """KEV threat-hunt keyword extraction: prefer a specific product/model token over generic infra
    or vulnerability-description words (regression for the 1.8.1 fix)."""

    def kw(self, product, vendor, name=""):
        return agent.KevFeed.hunt_keyword(product, vendor, name)

    def test_prefers_model_over_generic_product_word(self):
        self.assertEqual(self.kw("SMA1000 Appliances", "SonicWall",
                                 "SonicWall SMA1000 Appliances server-side request forgery"), "sma1000")

    def test_drops_generic_product_words(self):
        # "Secure Email Gateway" / "Remote Support" are all generic -> no good keyword or the vendor
        self.assertIsNone(self.kw("Secure Email Gateway", "Cisco",
                                  "Cisco Secure Email Gateway relative path traversal vulnerability"))
        self.assertEqual(self.kw("Remote Support", "BeyondTrust",
                                 "BeyondTrust Remote Support authentication bypass by spoofing"), "beyondtrust")

    def test_name_fallback_ignores_vuln_description_words(self):
        # product/vendor generic; the name must not yield "elevation"/"privilege"/etc.
        self.assertIsNone(self.kw("Windows", "Microsoft",
                                  "Microsoft Windows kernel elevation of privilege vulnerability"))
        self.assertEqual(self.kw("Multiple Products", "Atlassian",
                                 "Atlassian Confluence Data Center deserialization"), "confluence")

    def test_good_cases_unchanged(self):
        self.assertEqual(self.kw("Chrome", "Google"), "chrome")
        self.assertEqual(self.kw("Log4j2", "Apache"), "log4j2")       # digit-bearing model wins
        self.assertEqual(self.kw("NetScaler", "Citrix"), "netscaler")
        self.assertEqual(self.kw("Apache Tomcat", "Apache"), "tomcat")
        self.assertEqual(self.kw("Connect Secure", "Ivanti",
                                 "Ivanti Connect Secure authentication bypass"), "ivanti")



class TestThreatCoverage(unittest.TestCase):
    """PHP2Shell + litellm supply-chain: vuln coverage and the clearable advisory hunts (1.9.0)."""

    def test_litellm_and_php_advisories(self):
        f = agent.VulnFeed(enabled=False)                       # seed only, no remote fetch
        ids = lambda ms: {m["id"] for m in ms}
        self.assertIn("SCOUTER-LITELLM-1.107.0", ids(f.match(name="litellm", version="1.107.0")))
        self.assertEqual(ids(f.match(name="litellm", version="1.106.0")), set())
        self.assertTrue(any(i.startswith("SCOUTER-PHP2SHELL")
                            for i in ids(f.match(name="php", version="8.5.11",
                                                 ecosystem="Homebrew", package="php"))))
        self.assertFalse(any(i.startswith("SCOUTER-PHP2SHELL")     # 8.5.12 is patched
                             for i in ids(f.match(name="php", version="8.5.12",
                                                  ecosystem="Homebrew", package="php"))))

    def test_advisory_hunts_store_and_sql(self):
        import sqlite3
        import tempfile
        store = agent.AdvisoryHunts(path=os.path.join(tempfile.mkdtemp(), "dismissed.json"))
        st = store.status()
        self.assertEqual(st["total"], len(agent.ADVISORY_HUNTS))
        aid = st["advisories"][0]["id"]
        store.dismiss(aid)
        self.assertNotIn(aid, [a["id"] for a in store.status()["advisories"]])
        self.assertEqual(store.status()["dismissed_count"], 1)
        self.assertEqual(agent.AdvisoryHunts(path=store.path).status()["dismissed_count"], 1)  # persists
        store.restore(aid)
        self.assertEqual(store.status()["dismissed_count"], 0)
        con = sqlite3.connect(":memory:")
        con.executescript(agent.HISTORY_SCHEMA)
        for adv in agent.ADVISORY_HUNTS:                          # every hunt query must parse vs the schema
            for h in adv["hunts"]:
                con.execute("EXPLAIN " + h["sql"])



if __name__ == "__main__":
    unittest.main()
