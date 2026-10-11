#!/usr/bin/env python3
"""In-agent vulnerability scanning (CTEM-Lite), Linux.

APT update currency (parsed from `apt-get -s upgrade`), a dpkg + pip/npm inventory, and offline
advisory/OSV matching. These tests exercise the pure parsers and the scanner's finding assembly with
synthetic fixtures — no live apt/dpkg/OSV required, so they run on any platform while porting.

    python3 -m unittest discover -s tests
"""
import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


class TestVersionCompare(unittest.TestCase):
    def test_affected(self):
        A = agent._version_affected
        self.assertTrue(A("1.0", [{"lt": "2.0"}]))
        self.assertFalse(A("2.0", [{"lt": "2.0"}]))
        self.assertTrue(A("3.3.0", [{"ge": "3.0.0", "lt": "3.4.0"}]))
        self.assertFalse(A("", [{"lt": "9"}]))              # unparseable never flagged
        # dpkg-style version with epoch/revision still yields a numeric key
        self.assertEqual(agent._ver_key("1:2.3-4ubuntu0.1"), (1, 2, 3, 4, 0, 1))


class TestAptUpgrade(unittest.TestCase):
    SAMPLE = """Reading package lists...
Building dependency tree...
The following packages will be upgraded:
  libc6 openssl tzdata
Inst libc6 [2.35-0ubuntu3.1] (2.35-0ubuntu3.8 Ubuntu:22.04/jammy-updates [amd64])
Inst openssl [3.0.2-0ubuntu1.12] (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-security [amd64])
Inst tzdata [2024a] (2024b Ubuntu:22.04/jammy-updates [all])
Conf libc6 (2.35-0ubuntu3.8 Ubuntu:22.04/jammy-updates [amd64])
"""

    def test_parse_and_security_flag(self):
        ups = agent._parse_apt_upgrade(self.SAMPLE)
        self.assertEqual([u["name"] for u in ups], ["libc6", "openssl", "tzdata"])
        sec = {u["name"]: u["security"] for u in ups}
        self.assertTrue(sec["openssl"])        # jammy-security pocket
        self.assertFalse(sec["libc6"])         # jammy-updates, not security
        self.assertFalse(sec["tzdata"])

    def test_findings_severity(self):
        state = {"pretty": "Ubuntu 22.04.4 LTS", "version": "22.04", "reboot_required": True,
                 "pending": agent._parse_apt_upgrade(self.SAMPLE)}
        f = agent.LinuxOSCurrency.findings(state)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "high")     # a security update is pending
        self.assertTrue(f[0]["restart"])
        self.assertEqual(agent.LinuxOSCurrency.findings({"pending": []}), [])

    def test_no_updates(self):
        self.assertEqual(agent._parse_apt_upgrade("Calculating upgrade...\n0 upgraded, 0 newly installed"), [])


class TestDpkgStatus(unittest.TestCase):
    STATUS = (
        "Package: openssl\nStatus: install ok installed\nVersion: 3.0.2-0ubuntu1.12\n"
        "Description: toolkit\n\n"
        "Package: removed-pkg\nStatus: deinstall ok config-files\nVersion: 1.0\n\n"
        "Package: libssl3\nStatus: install ok installed\nVersion: 3.0.2-0ubuntu1.12\n"
    )

    def test_parse(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "status")
        with open(p, "w") as f:
            f.write(self.STATUS)
        recs = agent._parse_dpkg_status(p)
        names = {r["name"]: r["version"] for r in recs}
        self.assertIn("openssl", names)                 # fully installed -> kept
        self.assertIn("libssl3", names)
        self.assertNotIn("removed-pkg", names)           # config-files only -> dropped
        self.assertEqual(names["openssl"], "3.0.2-0ubuntu1.12")


class _FakeDpkg:
    """Stands in for DpkgIndex.package_for for liveness tests."""
    def __init__(self, mapping):
        self.mapping = mapping

    def package_for(self, path):
        return self.mapping.get(path)


class TestScanner(unittest.TestCase):
    def test_build_findings_dpkg_and_live(self):
        # seed advisory matches an old openssl; liveness resolves a running exe to the package
        vs = agent.VulnScanner(enabled=False, feed_url=None, osv="off",
                               dpkg_index=_FakeDpkg({"/usr/bin/openssl": "openssl"}))
        inv = {"dpkg": [{"name": "openssl", "version": "1.1.1"}], "packages": []}
        live = {"openssl"}
        findings = vs._build_findings({"pending": []}, inv, live_pkgs=live)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["component"], "openssl")
        self.assertTrue(findings[0]["live"])
        self.assertTrue(findings[0]["example"])
        # a current openssl is not flagged
        self.assertEqual(vs._build_findings(
            {"pending": []}, {"dpkg": [{"name": "openssl", "version": "3.0.11"}], "packages": []}, set()), [])

    def test_live_packages_from_dpkg_index(self):
        vs = agent.VulnScanner(enabled=False, osv="off",
                               dpkg_index=_FakeDpkg({"/usr/bin/sshd": "openssh-server"}))
        # inject a fake process list
        orig = agent.collect_processes
        agent.collect_processes = lambda: {1: {"exe": "/usr/bin/sshd"}, 2: {"exe": "/unowned/bin/x"}}
        try:
            self.assertEqual(vs._live_packages(), {"openssh-server"})
        finally:
            agent.collect_processes = orig

    def test_status_and_fleet_summary_shape(self):
        vs = agent.VulnScanner(enabled=False, feed_url=None, osv="off")
        st = vs.status()
        for k in ("findings", "os", "feed", "osv", "enabled", "summary"):
            self.assertIn(k, st)
        self.assertIsNone(vs.fleet_summary())            # no scan yet


class TestOSV(unittest.TestCase):
    def test_index_and_match(self):
        d = tempfile.mkdtemp()
        with zipfile.ZipFile(os.path.join(d, "osv-pypi.zip"), "w") as z:
            z.writestr("x.json", json.dumps(
                {"id": "GHSA-x", "aliases": ["CVE-2023-1"], "database_specific": {"severity": "HIGH"},
                 "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                               "ranges": [{"type": "ECOSYSTEM",
                                           "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}]}))
        osv = agent.OSVFeeds(enabled=True, ecosystems="pypi", cache_dir=d)
        osv.prepare([{"ecosystem": "PyPI", "name": "requests", "version": "2.19.0"}])
        hits = osv.match("PyPI", "requests", "2.19.0")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["cve"], "CVE-2023-1")
        self.assertEqual(hits[0]["fixed"], "2.20.0")


class TestRemediation(unittest.TestCase):
    def _scanner(self):
        vs = agent.VulnScanner(enabled=False, feed_url=None, osv="off")
        vs.remediation = agent.VulnRemediationStore(
            path=os.path.join(tempfile.mkdtemp(), "vuln-remediation.json"))
        return vs

    def test_sig_stable_across_version(self):
        a = {"kind": "dpkg", "component": "openssl", "cve": "CVE-1", "installed_version": "1.1.1"}
        b = dict(a, installed_version="3.0.2")
        self.assertEqual(agent._finding_sig(a), agent._finding_sig(b))

    def test_mitigate_and_patched_conflict(self):
        vs = self._scanner()
        inv = {"dpkg": [{"name": "openssl", "version": "1.1.1"}], "packages": []}
        findings = vs._build_findings({"pending": []}, inv)
        vs._apply_remediation(findings, 1000)
        self.assertEqual(len(findings), 1)
        sig = findings[0]["sig"]
        # mitigate -> suppressed from active counts
        vs.remediation.set(sig, "mitigated", note="not network-reachable")
        vs._apply_remediation(findings, 1000)
        s = vs._summary(findings)
        self.assertEqual(s["total"], 0)
        self.assertEqual(s["resolved"], 1)
        # patched then a later scan still detects it -> conflict re-opens
        vs.remediation.set(sig, "patched")
        pts = vs.remediation.get(sig)["ts"]
        vs._apply_remediation(findings, pts + 10)
        self.assertTrue(findings[0]["remediation"]["conflict"])
        self.assertEqual(vs._summary(findings)["total"], 1)

    def test_set_remediation_live(self):
        vs = self._scanner()
        inv = {"dpkg": [{"name": "openssl", "version": "1.1.1"}], "packages": []}
        findings = vs._build_findings({"pending": []}, inv)
        vs._apply_remediation(findings, 1000)
        vs._result = {"findings": findings, "scanned": 1000, "summary": vs._summary(findings)}
        r = vs.set_remediation(findings[0]["sig"], "accepted", note="eol box", by="ops")
        self.assertTrue(r["ok"])
        self.assertEqual(vs._result["summary"]["total"], 0)


class TestDistroFamilies(unittest.TestCase):
    def test_family_detection(self):
        self.assertEqual(agent._distro_family({"ID": "ubuntu", "ID_LIKE": "debian"}), "debian")
        self.assertEqual(agent._distro_family({"ID": "debian"}), "debian")
        self.assertEqual(agent._distro_family({"ID": "rocky", "ID_LIKE": "rhel centos fedora"}), "rhel")
        self.assertEqual(agent._distro_family({"ID": "fedora"}), "rhel")
        self.assertEqual(agent._distro_family({"ID": "alpine"}), "alpine")
        self.assertIsNone(agent._distro_family({"ID": "arch"}))

    def test_dnf_checkupdate_and_security(self):
        sec = agent._parse_dnf_security(
            "RHSA-2024:1234 Important/Sec. bash-5.1.8-9.el9.x86_64\n"
            "FEDORA-2024-aa Moderate/Sec. python3-libs-3.9.18-1.el9.x86_64\n"
            "RHBA-2024:9  bugfix        tzdata-2024a-1.el9.noarch")
        self.assertEqual(sec, {"bash", "python3-libs"})
        ups = agent._parse_dnf_checkupdate(
            "\nbash.x86_64        5.1.8-9.el9     baseos\n"
            "python3-libs.x86_64 3.9.18-1.el9    appstream\n"
            "tzdata.noarch      2024a-1.el9     baseos\n"
            "Obsoleting Packages\n", security_names=sec)
        bysec = {u["name"]: u["security"] for u in ups}
        self.assertEqual(set(bysec), {"bash", "python3-libs", "tzdata"})
        self.assertTrue(bysec["bash"]); self.assertFalse(bysec["tzdata"])

    def test_apk_parsers(self):
        up = agent._parse_apk_upgradable("busybox-1.36.1-r5 < 1.36.1-r7\nssl_client-1.36.1-r5 < 1.36.1-r7")
        self.assertEqual([u["name"] for u in up], ["busybox", "ssl_client"])
        inv = agent._parse_apk_info("busybox-1.36.1-r5\nmusl-1.2.4-r2\npy3-pip-23.1.2-r0")
        d = {x["name"]: x["version"] for x in inv}
        self.assertEqual(d["busybox"], "1.36.1-r5")
        self.assertEqual(d["py3-pip"], "23.1.2-r0")

    def test_rpm_parser_and_nevra(self):
        inv = agent._parse_rpm_qa("bash 5.1.8-9.el9\npython3-libs 3.9.18-1.el9")
        self.assertEqual({x["name"]: x["version"] for x in inv}["python3-libs"], "3.9.18-1.el9")
        self.assertEqual(agent._nevra_name("bash-5.1.8-9.el9"), "bash")
        self.assertEqual(agent._nevra_name("python3-libs-3.9.18-1.el9"), "python3-libs")

    def test_os_currency_findings_per_family(self):
        f = agent.LinuxOSCurrency.findings({"family": "rhel", "version": "9", "pending": [
            {"name": "bash", "security": True}]})[0]
        self.assertIn("dnf", f["description"])
        self.assertTrue(any("redhat" in r or "rockylinux" in r for r in f["references"]))
        f2 = agent.LinuxOSCurrency.findings({"family": "alpine", "version": "3.19", "pending": [
            {"name": "busybox", "security": False}]})[0]
        self.assertIn("apk", f2["description"])


class TestEdrAlerts(unittest.TestCase):
    def _scanner(self, sev="critical"):
        d = tempfile.mkdtemp(); self.fired = []
        vs = agent.VulnScanner(enabled=False, feed_url=None, osv="off",
                               alert_severity=sev, on_alert=lambda f: self.fired.append(f))
        vs._alerted_path = os.path.join(d, "a.json"); vs._alerted, vs._alert_baselined = set(), False
        vs.remediation = agent.VulnRemediationStore(path=os.path.join(d, "r.json"))
        return vs

    def _f(self, sev, live=False, cve="CVE-X"):
        return {"severity": sev, "component": "openssl", "cve": cve, "kind": "dpkg",
                "sig": "dpkg|openssl|%s" % cve.lower(), "live": live, "remediation": None}

    def test_baseline_new_threshold_live(self):
        vs = self._scanner("critical")
        vs._raise_alerts([self._f("critical", cve="C1")])          # baseline, silent
        self.assertEqual(self.fired, [])
        vs._raise_alerts([self._f("critical", cve="C1"), self._f("critical", cve="C2")])
        self.assertEqual([f["cve"] for f in self.fired], ["C2"])   # only the new one
        vs._alerted = set(); vs._alert_baselined = True            # reset for threshold check
        vs._raise_alerts([self._f("high", cve="H1")]); self.assertEqual([f["cve"] for f in self.fired], ["C2"])  # high not live -> none new
        vs._raise_alerts([self._f("high", live=True, cve="H2")])   # high AND live -> alerts
        self.assertEqual(self.fired[-1]["cve"], "H2")

    def test_off_and_remediated(self):
        vs = self._scanner("off"); vs._alert_baselined = True
        vs._raise_alerts([self._f("critical")]); self.assertEqual(self.fired, [])
        vs2 = self._scanner("critical"); vs2._alert_baselined = True
        g = self._f("critical"); g["remediation"] = {"status": "accepted"}
        vs2._raise_alerts([g]); self.assertEqual(self.fired, [])


class TestEnrichment(unittest.TestCase):
    def test_osv_enriched_and_os_currency_description(self):
        rec = {"id": "GHSA-x", "summary": "s", "details": "the flaw", "aliases": ["CVE-9"],
               "references": [{"url": "https://ex/adv"}],
               "severity": [{"type": "CVSS_V3", "score": "9.8"}],
               "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}]}
        d = tempfile.mkdtemp()
        with zipfile.ZipFile(os.path.join(d, "osv-pypi.zip"), "w") as z:
            z.writestr("x.json", json.dumps(rec))
        osv = agent.OSVFeeds(enabled=True, ecosystems="pypi", cache_dir=d)
        osv.prepare([{"ecosystem": "PyPI", "name": "requests", "version": "1.0"}])
        hit = osv.match("PyPI", "requests", "1.0")[0]
        self.assertEqual(hit["description"], "the flaw")
        self.assertIn("https://ex/adv", hit["references"])
        f = agent.LinuxOSCurrency.findings({"version": "22.04", "pending": [
            {"name": "openssl", "security": True}]})[0]
        self.assertIn("description", f)
        self.assertTrue(f["references"])


if __name__ == "__main__":
    unittest.main()
