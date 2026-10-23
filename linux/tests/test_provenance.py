#!/usr/bin/env python3
"""ProvenanceCollector (Linux) — install history (T1195) and volume mounts (USB/image/network,
T1052/T1091/T1021).

Parity with the macOS collector, Linux-native sources: installed packages via dpkg/rpm/apk (keyed on
NAME so `apt upgrade` version bumps stay silent), and mounts via /proc/mounts + lsblk + losetup. Snap
squashfs loop mounts and internal fixed disks are ignored; removable/USB, loop-backed disk images
(especially from a user/temp path), and network shares surface once. Pure stdlib; all command output
and the package inventory are stubbed, so no real /proc, lsblk or dpkg is touched.

Run from the linux/ dir:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402

PROC_MOUNTS = """sysfs /sys sysfs rw,nosuid,nodev,noexec 0 0
proc /proc proc rw,nosuid,nodev,noexec 0 0
/dev/sda2 / ext4 rw,relatime 0 0
/dev/loop0 /snap/core22/1 squashfs ro,nodev 0 0
/dev/loop8 /mnt/iso iso9660 ro,relatime 0 0
/dev/sdb1 /media/user/KINGSTON vfat rw,nosuid,nodev,relatime 0 0
//nas.local/share /mnt/share cifs rw,relatime 0 0"""

LSBLK_JSON = """{"blockdevices":[
  {"name":"sda","tran":"sata","rm":false,"hotplug":false,"type":"disk","children":[
     {"name":"sda2","mountpoints":["/"],"fstype":"ext4","uuid":"AAAA","label":"root"}]},
  {"name":"sdb","tran":"usb","rm":true,"hotplug":true,"type":"disk","children":[
     {"name":"sdb1","mountpoints":["/media/user/KINGSTON"],"fstype":"vfat","uuid":"1234-ABCD","label":"KINGSTON"}]}
]}"""

LOSETUP = "/dev/loop0 /var/lib/snapd/snaps/core22.snap\n/dev/loop8 /home/user/Downloads/ubuntu.iso\n"

DPKG_LOG = """2026-10-22 14:03:11 status installed libc6:amd64 2.39
2026-10-22 14:03:12 install curl:amd64 <none> 8.5.0
2026-10-22 14:03:13 configure curl:amd64 8.5.0 <none>"""


def collector():
    d = tempfile.mkdtemp(prefix="scouter-prov-lin-")
    return agent.ProvenanceCollector(enabled=True, baseline_file=os.path.join(d, "b.json"))


def mnt(dev, mp, fstype):
    return {"dev": dev, "mountpoint": mp, "fstype": fstype, "opts": []}


class TestParsers(unittest.TestCase):
    def test_parse_proc_mounts(self):
        rows = {r["mountpoint"]: r for r in agent.parse_proc_mounts(PROC_MOUNTS)}
        self.assertEqual(rows["/media/user/KINGSTON"]["fstype"], "vfat")
        self.assertEqual(rows["/mnt/share"]["dev"], "//nas.local/share")

    def test_parse_proc_mounts_unescapes_spaces(self):
        rows = agent.parse_proc_mounts("/dev/sdc1 /media/My\\040Disk ext4 rw 0 0")
        self.assertEqual(rows[0]["mountpoint"], "/media/My Disk")

    def test_parse_lsblk_json_inherits_parent_flags(self):
        m = agent.parse_lsblk_json(LSBLK_JSON)
        self.assertTrue(m["/media/user/KINGSTON"]["rm"])          # partition inherits disk's rm
        self.assertEqual(m["/media/user/KINGSTON"]["tran"], "usb")
        self.assertFalse(m["/"]["rm"])

    def test_parse_losetup(self):
        self.assertEqual(agent.parse_losetup(LOSETUP)["/dev/loop8"], "/home/user/Downloads/ubuntu.iso")

    def test_parse_dpkg_log(self):
        hits = agent.parse_dpkg_log(DPKG_LOG)
        self.assertTrue(any("install curl" in h for h in hits))
        self.assertFalse(any("configure" in h for h in hits))

    def test_parsers_never_raise_on_garbage(self):
        self.assertEqual(agent.parse_proc_mounts("x"), [])
        self.assertEqual(agent.parse_lsblk_json("not json"), {})
        self.assertEqual(agent.parse_losetup(""), {})


class TestMountScoring(unittest.TestCase):
    def setUp(self):
        self.lsblk = agent.parse_lsblk_json(LSBLK_JSON)
        self.loops = agent.parse_losetup(LOSETUP)
        self.pc = collector()

    def _node(self, dev, mp, fs):
        return self.pc._mount_node(mnt(dev, mp, fs), self.lsblk, self.loops)

    def test_usb_removable_is_low(self):
        key, n = self._node("/dev/sdb1", "/media/user/KINGSTON", "vfat")
        self.assertIsNotNone(key)
        self.assertEqual(n["detail"]["kind"], "USB / removable volume")
        self.assertEqual(n["severity"], "low")

    def test_network_share_is_low(self):
        key, n = self._node("//nas.local/share", "/mnt/share", "cifs")
        self.assertEqual(n["detail"]["kind"], "Network share")
        self.assertEqual(n["severity"], "low")

    def test_disk_image_from_downloads_is_elevated(self):
        key, n = self._node("/dev/loop8", "/mnt/iso", "iso9660")
        self.assertEqual(n["detail"]["kind"], "Disk image")
        self.assertEqual(n["severity"], "medium")
        self.assertEqual(n["detail"]["image_path"], "/home/user/Downloads/ubuntu.iso")

    def test_snap_loop_is_ignored(self):
        self.assertEqual(self._node("/dev/loop0", "/snap/core22/1", "squashfs"), (None, None))

    def test_internal_disk_and_pseudo_fs_ignored(self):
        self.assertEqual(self._node("/dev/sda2", "/", "ext4"), (None, None))
        self.assertEqual(self._node("proc", "/proc", "proc"), (None, None))


class TestInstallScoring(unittest.TestCase):
    def test_new_package_surfaces_low(self):
        pc = collector()
        n = pc._install_node("install|curl", {"name": "curl", "version": "8.5.0"}, "dpkg",
                             ["2026-10-22 14:03:12 install curl:amd64 <none> 8.5.0"])
        self.assertEqual(n["severity"], "low")
        self.assertEqual(n["detail"]["manager"], "dpkg")
        self.assertTrue(n["detail"]["log_evidence"])              # dpkg.log evidence attached


class TestBaselineDiff(unittest.TestCase):
    """_collect's baseline logic, with _discover stubbed so no /proc or dpkg is touched."""

    def test_first_run_silent_then_new_flags_once(self):
        pc = collector()
        node = pc._node("install|newpkg", "pkg: newpkg", 20,
                        [agent.reason("New dpkg package installed: newpkg", "T1195", 20)],
                        {"category": "install", "pkgid": "newpkg"})
        state = {"found": {"install|base": None}}
        pc._discover = lambda: (dict(state["found"]), {"install": len(state["found"]), "mount": 0}, [])
        pc._collect()                                             # learn: baseline {install|base}
        self.assertEqual(pc.snapshot(), [])
        state["found"] = {"install|base": None, "install|newpkg": node}   # newpkg appears
        pc._collect()
        self.assertEqual(len(pc.snapshot()), 1)
        pc._collect()                                             # same state → nothing new
        self.assertEqual(len(pc.snapshot()), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
