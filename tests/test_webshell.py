#!/usr/bin/env python3
"""WebshellScanner — file-content detection of PHP webshells (T1505.003).

Closes the php2shell gap: a PHP session file (sess_*) that contains `<?php … system($_GET)` is the
PHP_SESSION_UPLOAD_PROGRESS drop (a session file must never hold executable PHP) — flagged CRITICAL.
PHP + a dangerous sink hiding in a non-.php file is a disguised webshell — flagged HIGH. A real .php
application file and benign serialized session data are NOT flagged (near-zero FP).

Pure stdlib. Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402

SHELL = '<?php echo "PWNED::"; system($_GET["c"]); ?>'
BENIGN_SESS = 'user|s:5:"lonni";role|s:5:"admin";count|i:3;'
DISGUISED = 'image data\n<?php eval(base64_decode($_POST["x"])); ?>'
REAL_PHP = '<?php require "config.php"; echo render($user); ?>'


def write(d, name, content):
    with open(os.path.join(d, name), "w") as f:
        f.write(content)


class TestWebshellParser(unittest.TestCase):
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


class TestWebshellScanner(unittest.TestCase):
    def _scan(self, files):
        d = tempfile.mkdtemp(prefix="scouter-ws-")
        for name, content in files.items():
            write(d, name, content)
        ws = agent.WebshellScanner(enabled=True, interval=60, dirs=(d,))
        ws._collect()
        return d, ws, {n["detail"]["path"].split("/")[-1]: n for n in ws.snapshot()}

    def test_session_drop_is_critical(self):
        _, _, by = self._scan({"sess_abc": SHELL})
        self.assertIn("sess_abc", by)
        self.assertEqual(by["sess_abc"]["severity"], "critical")
        self.assertTrue(by["sess_abc"]["detail"]["session_file"])

    def test_disguised_webshell_is_high(self):
        _, _, by = self._scan({"notes.txt": DISGUISED})
        self.assertEqual(by["notes.txt"]["severity"], "high")

    def test_benign_session_and_real_php_not_flagged(self):
        _, _, by = self._scan({"sess_ok": BENIGN_SESS, "index.php": REAL_PHP})
        self.assertEqual(by, {})

    def test_empty_file_not_flagged(self):
        _, _, by = self._scan({"sess_empty": ""})
        self.assertEqual(by, {})

    def test_flag_persists_after_file_is_deleted(self):
        d, ws, by = self._scan({"sess_x": SHELL})
        self.assertIn("sess_x", by)
        os.remove(os.path.join(d, "sess_x"))        # attacker cleans up
        ws._collect()                               # next pass: file gone
        self.assertEqual(len(ws.snapshot()), 1)     # but the finding is kept for triage (TTL)


if __name__ == "__main__":
    unittest.main(verbosity=2)
