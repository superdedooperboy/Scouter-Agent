#!/usr/bin/env python3
"""ProvenanceCollector — install receipts (T1195) and volume mounts (USB/DMG/network, T1052/T1091/T1021).

Two FOR518 surfaces the cron/launchd/FIM walks miss. The calibration is the point: benign noise
(Apple OS-update receipts, internal volumes) stays silent `info`; a third-party install, a removable
or image-backed or network mount, or anything entering from a user/temp location surfaces once. Pure
stdlib; command output is stubbed so no real pkgutil/mount/diskutil is invoked.

Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import sqlite3
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


def make_quarantine_db(path, rows):
    """rows: (id, mac_ts, agent_bundle, agent_name, data_url, origin_url, sender)."""
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT PRIMARY KEY, "
                "LSQuarantineTimeStamp REAL, LSQuarantineAgentBundleIdentifier TEXT, "
                "LSQuarantineAgentName TEXT, LSQuarantineDataURLString TEXT, "
                "LSQuarantineOriginURLString TEXT, LSQuarantineSenderName TEXT)")
    con.executemany("INSERT INTO LSQuarantineEvent VALUES (?,?,?,?,?,?,?)", rows)
    con.commit()
    con.close()

PKG_INFO = """<?xml version="1.0"?><!DOCTYPE plist><plist version="1.0"><dict>
<key>pkg-version</key><string>3.1.4</string>
<key>install-time</key><integer>1792700000</integer>
<key>install-location</key><string>%s</string>
<key>volume</key><string>/</string></dict></plist>"""

MOUNT_OUT = """/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse)
/dev/disk6s1 on /Volumes/KINGSTON (msdos, local, nodev, nosuid, noowners)
/dev/disk7s1 on /Volumes/Installer (hfs, local, nodev, read-only, noowners, mounted by lonnie)
//guest@nas.local/share on /Volumes/share (smbfs, nodev, nosuid, mounted by lonnie)"""

HDIUTIL_OUT = """<?xml version="1.0"?><plist version="1.0"><dict><key>images</key><array><dict>
<key>image-path</key><string>/Users/lonnie/Downloads/Installer.dmg</string>
<key>system-entities</key><array><dict>
<key>dev-entry</key><string>/dev/disk7</string>
<key>mount-point</key><string>/Volumes/Installer</string></dict></array></dict></array></dict></plist>"""

DISKUTIL_USB = """<?xml version="1.0"?><plist version="1.0"><dict>
<key>BusProtocol</key><string>USB</string><key>Internal</key><false/>
<key>RemovableMedia</key><true/><key>VolumeName</key><string>KINGSTON</string>
<key>VolumeUUID</key><string>ABCD-1234</string><key>DeviceNode</key><string>/dev/disk6s1</string></dict></plist>"""


class _StubRun:
    """Patch agent.run with canned output dispatched on the command."""
    def __init__(self, pkgs=(), pkg_location="", with_mounts=True):
        self.pkgs = list(pkgs)
        self.pkg_location = pkg_location
        self.with_mounts = with_mounts

    def __enter__(self):
        self._orig = agent.run
        agent.run = self._run
        return self

    def __exit__(self, *a):
        agent.run = self._orig

    def _run(self, cmd, timeout=15, env=None):
        if cmd[:2] == ["pkgutil", "--pkgs"]:
            return 0, "\n".join(self.pkgs), ""
        if cmd[:2] == ["pkgutil", "--pkg-info-plist"]:
            return 0, PKG_INFO % self.pkg_location, ""
        if cmd[:1] == ["mount"]:
            return 0, (MOUNT_OUT if self.with_mounts else
                       "/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)"), ""
        if cmd[:3] == ["hdiutil", "info", "-plist"]:
            return 0, HDIUTIL_OUT, ""
        if cmd[:3] == ["diskutil", "info", "-plist"]:
            return 0, DISKUTIL_USB, ""      # only disk6 reaches here; disk7 is a DMG, network is smbfs
        return 1, "", "unstubbed"


def collector():
    d = tempfile.mkdtemp(prefix="scouter-prov-")
    return agent.ProvenanceCollector(enabled=True, baseline_file=os.path.join(d, "b.json"))


class TestParsers(unittest.TestCase):
    def test_parse_mount(self):
        rows = agent.parse_mount(MOUNT_OUT)
        by_mp = {r["mountpoint"]: r for r in rows}
        self.assertEqual(by_mp["/Volumes/KINGSTON"]["fstype"], "msdos")
        self.assertEqual(by_mp["//guest@nas.local/share" if False else "/Volumes/share"]["fstype"], "smbfs")
        self.assertEqual(by_mp["/Volumes/share"]["dev"], "//guest@nas.local/share")

    def test_parse_pkg_info(self):
        info = agent.parse_pkg_info(PKG_INFO % "")
        self.assertEqual(info["version"], "3.1.4")
        self.assertEqual(info["install_time"], 1792700000)

    def test_parse_hdiutil_images(self):
        m = agent.parse_hdiutil_images(HDIUTIL_OUT)
        self.assertEqual(m["/dev/disk7"]["image_path"], "/Users/lonnie/Downloads/Installer.dmg")

    def test_parse_diskutil_info(self):
        info = agent.parse_diskutil_info(DISKUTIL_USB)
        self.assertTrue(info["removable"])
        self.assertEqual(info["bus"], "USB")
        self.assertEqual(info["uuid"], "ABCD-1234")

    def test_parsers_never_raise_on_garbage(self):
        self.assertEqual(agent.parse_mount("not a mount line"), [])
        self.assertEqual(agent.parse_pkg_info("not a plist"), {})
        self.assertEqual(agent.parse_hdiutil_images(b"\x00\x01"), {})
        self.assertEqual(agent.parse_diskutil_info("<plist></plist>"), {})


class TestInstallScoring(unittest.TestCase):
    def test_apple_receipt_is_silent(self):
        pc = collector()
        with _StubRun():
            n = pc._install_node("install|com.apple.pkg.Foo", "com.apple.pkg.Foo", [])
        self.assertEqual(n["severity"], "info")        # OS-update noise stays silent

    def test_third_party_receipt_surfaces(self):
        pc = collector()
        with _StubRun():
            n = pc._install_node("install|com.acme.tool", "com.acme.tool", [])
        self.assertEqual(n["severity"], "low")

    def test_install_from_user_temp_location_elevates(self):
        pc = collector()
        with _StubRun(pkg_location="tmp/payload"):
            n = pc._install_node("install|com.acme.tool", "com.acme.tool", [])
        self.assertEqual(n["severity"], "medium")
        self.assertTrue(any("user/temporary location" in r["text"] for r in n["reasons"]))


class TestMountScoring(unittest.TestCase):
    def _nodes(self):
        pc = collector()
        with _StubRun():
            found, counts, _ = pc._discover()
        return {found[k]["detail"]["kind"]: found[k] for k in found if k.startswith("mount|")}, counts

    def test_usb_dmg_network_classified_and_scored(self):
        nodes, counts = self._nodes()
        self.assertEqual(counts["mount"], 3)                    # KINGSTON(USB), Installer(DMG), share(net)
        self.assertEqual(nodes["USB / removable volume"]["severity"], "low")
        self.assertEqual(nodes["Network share"]["severity"], "low")
        # DMG mounted from ~/Downloads is the lure → elevated
        self.assertEqual(nodes["Disk image (DMG)"]["severity"], "medium")
        self.assertEqual(nodes["Disk image (DMG)"]["detail"]["image_path"],
                         "/Users/lonnie/Downloads/Installer.dmg")

    def test_internal_and_system_volumes_are_ignored(self):
        nodes, _ = self._nodes()
        mps = {n["detail"]["mountpoint"] for n in nodes.values()}
        self.assertNotIn("/", mps)
        self.assertNotIn("/System/Volumes/Data", mps)


class TestBaselineDiff(unittest.TestCase):
    def test_first_run_is_silent_then_new_items_flag_once(self):
        pc = collector()
        with _StubRun(pkgs=["com.acme.tool"], with_mounts=False):
            pc._collect()                                       # learn_only: baseline everything, flag nothing
            self.assertEqual(pc.snapshot(), [])
        # now three volumes mount — new since baseline
        with _StubRun(pkgs=["com.acme.tool"], with_mounts=True):
            pc._collect()
        flagged = pc.snapshot()
        kinds = sorted({n["detail"]["category"] for n in flagged})
        self.assertIn("mount", kinds)                           # mounts were new this pass
        # re-running the identical state adds nothing new
        before = len(flagged)
        with _StubRun(pkgs=["com.acme.tool"], with_mounts=True):
            pc._collect()
        self.assertEqual(len(pc.snapshot()), before)


class TestQuarantineDownloads(unittest.TestCase):
    """Download provenance from QuarantineEventsV2: a non-browser download (malware staging) or an
    executable from a raw-code/paste/IP source surfaces; ordinary browser downloads stay silent."""

    def test_read_quarantine_events(self):
        d = tempfile.mkdtemp(prefix="scouter-q-")
        p = os.path.join(d, "q.sqlite")
        make_quarantine_db(p, [("A", 0.0, "com.google.chrome", "Chrome", "https://x/y.pdf", "https://x", "")])
        evs = agent.read_quarantine_events(p)
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["agent_bundle"], "com.google.chrome")
        self.assertEqual(evs[0]["data_url"], "https://x/y.pdf")

    def test_read_absent_or_bad_db_is_empty(self):
        self.assertEqual(agent.read_quarantine_events("/no/such/path.sqlite"), [])
        d = tempfile.mkdtemp(prefix="scouter-q-")
        bad = os.path.join(d, "bad.sqlite")
        open(bad, "w").write("not a database")
        self.assertEqual(agent.read_quarantine_events(bad), [])

    def _dl(self, **ev):
        base = {"id": "i", "ts": 0, "agent_bundle": "", "agent_name": "", "data_url": "",
                "origin_url": "", "sender": ""}
        base.update(ev)
        return collector()._download_node(base, "u")

    def test_non_browser_download_is_medium(self):
        n = self._dl(agent_name="osascript", data_url="http://1.2.3.4/stage.sh")
        self.assertEqual(n["severity"], "medium")
        self.assertTrue(any("non-browser" in r["text"] for r in n["reasons"]))

    def test_browser_document_download_is_silent(self):
        n = self._dl(agent_bundle="com.apple.safari", agent_name="Safari",
                     data_url="https://site.example/report.pdf", origin_url="https://site.example")
        self.assertEqual(n["severity"], "info")

    def test_executable_from_raw_source_surfaces(self):
        n = self._dl(agent_bundle="com.google.chrome", agent_name="Chrome",
                     data_url="https://raw.githubusercontent.com/x/y/main/run.sh")
        self.assertEqual(n["severity"], "low")       # suspicious source + executable → 30


class TestAutologinPosture(unittest.TestCase):
    def test_enabled_when_autologin_user_set(self):
        orig = agent.run
        agent.run = lambda cmd, timeout=6, env=None: (
            (0, "alice\n", "") if cmd[:2] == ["defaults", "read"] else orig(cmd, timeout, env))
        try:
            al = agent.get_autologin()
        finally:
            agent.run = orig
        self.assertTrue(al["enabled"])
        self.assertEqual(al["user"], "alice")

    def test_disabled_when_nothing_set(self):
        orig = agent.run
        agent.run = lambda cmd, timeout=6, env=None: (
            (1, "", "") if cmd[:2] == ["defaults", "read"] else orig(cmd, timeout, env))
        try:
            al = agent.get_autologin()
        finally:
            agent.run = orig
        # enabled only if /etc/kcpassword exists; on a normal host it does not
        self.assertEqual(al["enabled"], os.path.exists("/etc/kcpassword"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
