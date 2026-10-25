#!/usr/bin/env python3
"""WebshellScanner — file-content detection of webshells (T1505.003).

Two zones, two bars (see the module comment in agent.py):
  DROP   (session dirs, /tmp …): loose bar. A sess_* holding script code = php2shell drop → CRITICAL;
         code + a sink in a non-script file = disguised shell → HIGH; a real .php there is judged only
         by the strict bar.
  WEBROOT (docroots): strict bar + named-shell markers only — a framework's ordinary system()/eval()
         must NOT fire; only attacker-input-into-a-sink patterns + known-shell banners do.

Languages: PHP, JSP, ASP/ASPX, Perl/CGI, Python-CGI. Pure stdlib. Run from the repo root:
  python3 -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402

SHELL = '<?php echo "PWNED::"; system($_GET["c"]); ?>'                 # php2shell / direct input->sink
BENIGN_SESS = 'user|s:5:"lonni";role|s:5:"admin";count|i:3;'
DISGUISED_HIGH = 'access log\n<?php $p = $_REQUEST["cmd"]; echo "<pre>"; passthru($p); ?>'  # loose only
DISGUISED_STRICT = 'image data\n<?php eval(base64_decode($_POST["x"])); ?>'                 # strict (obfuscated eval)
REAL_PHP = '<?php require "config.php"; echo render($user); ?>'
WP_BENIGN = '<?php function run_it(){ return system("ls -la"); } $id = (int) $_GET["id"]; ?>'  # plain sink + superglobal, NOT wired together
CHINA_CHOPPER = '<?php @eval($_POST["pass"]); ?>'
JSP_SHELL = '<%@ page import="java.util.*" %><% Runtime.getRuntime().exec(request.getParameter("c")); %>'
ASPX_SHELL = '<%@ Page Language="C#" %><% eval(Request("cmd")) %>'
PERL_SHELL = '#!/usr/bin/perl\nuse CGI;\nmy $q = CGI->new;\nsystem(param("c"));\n'
PY_SHELL = 'import cgi, os\nform = cgi.FieldStorage()\nos.system(cgi.FieldStorage()["c"].value)\n'
NAMED = '<?php /* r57shell  -- uname: */ phpinfo(); ?>'


def write(d, name, content):
    p = os.path.join(d, name)
    os.makedirs(os.path.dirname(p), exist_ok=True) if os.path.dirname(name) else None
    with open(p, "w") as f:
        f.write(content)


class TestWebshellParser(unittest.TestCase):
    """The stable PHP loose helper (scan_data_for_webshell) — the DROP-zone php2shell bar."""

    def test_session_webshell_matches_with_sinks(self):
        m, sinks = agent.scan_data_for_webshell(SHELL.encode())
        self.assertTrue(m)
        self.assertIn("system(", sinks)
        self.assertIn("$_GET[", sinks)

    def test_benign_session_data_does_not_match(self):
        self.assertFalse(agent.scan_data_for_webshell(BENIGN_SESS.encode())[0])

    def test_php_without_a_sink_does_not_match(self):
        self.assertFalse(agent.scan_data_for_webshell(b"<?php echo 1 + 1; ?>")[0])

    def test_empty_or_non_php_does_not_match(self):
        self.assertFalse(agent.scan_data_for_webshell(b"")[0])
        self.assertFalse(agent.scan_data_for_webshell(b"just some text system( here")[0])


class TestClassifier(unittest.TestCase):
    """classify_webshell — zone- and language-aware, pure."""

    def c(self, name, data, in_webroot):
        return agent.classify_webshell(name, data.encode() if isinstance(data, str) else data,
                                       in_webroot=in_webroot)

    # --- DROP zone ---
    def test_drop_session_drop_is_critical(self):
        r = self.c("sess_abc", SHELL, False)
        self.assertEqual(r["severity"], "critical")
        self.assertTrue(r["is_session"])

    def test_drop_disguised_loose_is_high(self):
        r = self.c("notes.txt", DISGUISED_HIGH, False)
        self.assertEqual(r["severity"], "high")
        self.assertFalse(r["strict"])

    def test_drop_disguised_strict_is_critical(self):
        r = self.c("photo.jpg", DISGUISED_STRICT, False)
        self.assertEqual(r["severity"], "critical")
        self.assertTrue(r["strict"])

    def test_drop_real_php_benign_loose_skipped(self):
        # a real .php accidentally in /tmp is not a shell on the loose bar alone
        self.assertIsNone(self.c("index.php", REAL_PHP, False))

    def test_drop_real_php_strict_still_fires(self):
        r = self.c("x.php", SHELL, False)
        self.assertEqual(r["severity"], "critical")
        self.assertTrue(r["strict"])

    # --- WEBROOT zone (strict only) ---
    def test_webroot_benign_framework_not_flagged(self):
        # plain system("ls") + a sanitized $_GET elsewhere must NOT fire in a webroot
        self.assertIsNone(self.c("functions.php", WP_BENIGN, True))

    def test_webroot_benign_app_not_flagged(self):
        self.assertIsNone(self.c("index.php", REAL_PHP, True))

    def test_webroot_loose_only_not_flagged(self):
        # a loose-only payload in a webroot is below the strict bar — no FP
        self.assertIsNone(self.c("page.php", DISGUISED_HIGH, True))

    def test_webroot_china_chopper_critical(self):
        r = self.c("avatar.php", CHINA_CHOPPER, True)
        self.assertEqual(r["severity"], "critical")
        self.assertEqual(r["lang"], "php")

    def test_webroot_jsp_shell_critical(self):
        r = self.c("cmd.jsp", JSP_SHELL, True)
        self.assertEqual((r["severity"], r["lang"]), ("critical", "jsp"))

    def test_webroot_aspx_shell_critical(self):
        r = self.c("cmd.aspx", ASPX_SHELL, True)
        self.assertEqual((r["severity"], r["lang"]), ("critical", "asp"))

    def test_webroot_perl_shell_critical(self):
        r = self.c("cmd.cgi", PERL_SHELL, True)
        self.assertEqual((r["severity"], r["lang"]), ("critical", "perl"))

    def test_webroot_python_shell_critical(self):
        r = self.c("cmd.py", PY_SHELL, True)
        self.assertEqual((r["severity"], r["lang"]), ("critical", "python"))

    def test_named_marker_always_flags(self):
        r = self.c("legit.php", NAMED, True)
        self.assertEqual(r["severity"], "critical")
        self.assertTrue(r["markers"])

    def test_empty_is_none(self):
        self.assertIsNone(self.c("sess_x", "", False))


class TestWebshellScanner(unittest.TestCase):
    def _scan_drop(self, files):
        d = tempfile.mkdtemp(prefix="scouter-ws-drop-")
        for name, content in files.items():
            write(d, name, content)
        ws = agent.WebshellScanner(enabled=True, interval=60, dirs=(d,), webroots=())
        ws._collect()
        return d, ws, {n["detail"]["path"].split("/")[-1]: n for n in ws.snapshot()}

    def _scan_webroot(self, files):
        d = tempfile.mkdtemp(prefix="scouter-ws-root-")
        for name, content in files.items():
            write(d, name, content)
        ws = agent.WebshellScanner(enabled=True, interval=60, dirs=(), webroots=(d,))
        ws._collect()
        return d, ws, {n["detail"]["path"].split("/")[-1]: n for n in ws.snapshot()}

    def test_session_drop_is_critical(self):
        _, _, by = self._scan_drop({"sess_abc": SHELL})
        self.assertIn("sess_abc", by)
        self.assertEqual(by["sess_abc"]["severity"], "critical")
        self.assertEqual(by["sess_abc"]["detail"]["location"], "session")

    def test_disguised_webshell_is_high(self):
        _, _, by = self._scan_drop({"notes.txt": DISGUISED_HIGH})
        self.assertEqual(by["notes.txt"]["severity"], "high")
        self.assertEqual(by["notes.txt"]["detail"]["location"], "drop")

    def test_benign_session_and_real_php_not_flagged(self):
        _, _, by = self._scan_drop({"sess_ok": BENIGN_SESS, "index.php": REAL_PHP})
        self.assertEqual(by, {})

    def test_webroot_shell_caught_in_subdir(self):
        _, _, by = self._scan_webroot({"uploads/deep/avatar.php": CHINA_CHOPPER, "index.php": REAL_PHP})
        self.assertIn("avatar.php", by)
        self.assertEqual(by["avatar.php"]["severity"], "critical")
        self.assertEqual(by["avatar.php"]["detail"]["location"], "webroot")
        self.assertNotIn("index.php", by)              # benign app file not flagged

    def test_webroot_multilang(self):
        _, _, by = self._scan_webroot({"a.jsp": JSP_SHELL, "b.aspx": ASPX_SHELL, "c.cgi": PERL_SHELL})
        self.assertEqual({k: by[k]["severity"] for k in ("a.jsp", "b.aspx", "c.cgi")},
                         {"a.jsp": "critical", "b.aspx": "critical", "c.cgi": "critical"})

    def test_empty_file_not_flagged(self):
        _, _, by = self._scan_drop({"sess_empty": ""})
        self.assertEqual(by, {})

    def test_flag_persists_after_file_is_deleted(self):
        d, ws, by = self._scan_drop({"sess_x": SHELL})
        self.assertIn("sess_x", by)
        os.remove(os.path.join(d, "sess_x"))           # attacker cleans up
        ws._collect()                                  # next pass: file gone
        self.assertEqual(len(ws.snapshot()), 1)        # but the finding is kept for triage (TTL)


if __name__ == "__main__":
    unittest.main(verbosity=2)
