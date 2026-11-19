#!/usr/bin/env python3
"""Agent Access Audit — Phase 3a: DNS-query collection.

DNS is default-on, best-effort telemetry: the collector reads whatever DNS source the host exposes
(a local resolver query log on Linux, the unified log on macOS) and HONESTLY reports when there is
none, so an empty table is never mistaken for a quiet host. These tests cover the resolver-log
parsers, the tunnelling/DGA anomaly scorer, the dedup upsert into dns_events (storage tracks distinct
lookups, not query volume), and the honesty invariant on status().

A DNS event carries qname/qtype/source only — never a response payload. The line reader is pluggable,
so the whole parse → dedup → anomaly pipeline is exercised without a live resolver.

Pure stdlib. Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402


def _hist():
    """An isolated on-disk history (NEVER the real one — path= is the 5th positional)."""
    d = tempfile.mkdtemp()
    return agent.HistoryDB(path=os.path.join(d, "h.db"))


class Parsers(unittest.TestCase):
    def test_dnsmasq(self):
        rec = agent.parse_dnsmasq_query(
            "Nov 18 10:00:00 dnsmasq[1]: query[A] Example.com from 192.168.1.5")
        self.assertEqual(rec, {"qname": "example.com", "qtype": "A",
                               "client": "192.168.1.5", "resolved_ip": None})

    def test_unbound(self):
        rec = agent.parse_unbound_query(
            "[1700000000] unbound[1:0] info: 10.0.0.2 example.org. AAAA IN")
        self.assertEqual(rec["qname"], "example.org")
        self.assertEqual(rec["qtype"], "AAAA")
        self.assertEqual(rec["client"], "10.0.0.2")

    def test_mdns_name_first_and_private(self):
        rec = agent.parse_macos_mdns_query("2026-11-18 mDNSResponder: Question example.com. A")
        self.assertEqual(rec["qname"], "example.com")
        self.assertEqual(rec["qtype"], "A")
        priv = agent.parse_macos_mdns_query("2026-11-18 mDNSResponder: Question <private> A")
        self.assertEqual(priv["qname"], "<private>")
        self.assertEqual(priv["qtype"], "")      # counted, never guessed

    def test_mdns_does_not_pull_qtype_from_mid_label(self):
        # 'networkexteNSion' must NOT parse as name='com.apple.networkexte' + qtype='NS'.
        bad = agent.parse_macos_mdns_query("2026-11-18 mDNSResponder: com.apple.networkextension start")
        self.assertIsNone(bad)

    def test_unknown_qtype_and_junk_are_rejected(self):
        self.assertIsNone(agent.parse_dnsmasq_query("query[WIDGET] x.com from 1.1.1.1"))
        self.assertIsNone(agent.parse_dnsmasq_query("this is not a dns line"))
        self.assertIsNone(agent.parse_unbound_query("random text"))


class FileSourceDetection(unittest.TestCase):
    def test_first_readable_source_wins(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "dnsmasq.log")
        open(log, "w").close()
        cands = (("/no/such/pihole.log", "pihole", agent.parse_dnsmasq_query),
                 (log, "dnsmasq", agent.parse_dnsmasq_query))
        src = agent.detect_dns_file_source(cands)
        self.assertEqual(src["kind"], "file")
        self.assertEqual(src["name"], "dnsmasq")
        self.assertEqual(src["path"], log)

    def test_no_readable_source_is_none(self):
        cands = (("/no/such/a.log", "x", agent.parse_dnsmasq_query),
                 ("/no/such/b.log", "y", agent.parse_unbound_query))
        self.assertIsNone(agent.detect_dns_file_source(cands))


class Entropy(unittest.TestCase):
    def test_random_label_is_high_entropy(self):
        self.assertGreater(agent._shannon_entropy("kq3x9vmz1p7wab2c8f"), 3.5)

    def test_repetitive_label_is_low_entropy(self):
        self.assertLess(agent._shannon_entropy("aaaaaaaaaaaa"), 1.0)
        self.assertEqual(agent._shannon_entropy(""), 0.0)


class AnomalyScorer(unittest.TestCase):
    def test_data_bearing_record_types(self):
        for qt in ("TXT", "NULL"):
            an = agent.dns_anomaly("beacon.evil.example", qt)
            self.assertIsNotNone(an)
            self.assertEqual(an[2], "T1071.004")

    def test_high_entropy_label_is_flagged(self):
        an = agent.dns_anomaly("kq3x9vmz1p7wab2c8fgh.example.com", "A")
        self.assertIsNotNone(an)
        self.assertEqual(an[2], "T1568.002")

    def test_overlong_and_deeply_nested(self):
        long = ("a" * 60) + ".example.com"
        self.assertIsNotNone(agent.dns_anomaly(long, "A"))
        nested = "a.b.c.d.e.f.g.h.example.com"
        self.assertIsNotNone(agent.dns_anomaly(nested, "A"))

    def test_benign_and_private_are_silent(self):
        self.assertIsNone(agent.dns_anomaly("www.google.com", "A"))
        self.assertIsNone(agent.dns_anomaly("mail.apple.com", "A"))
        self.assertIsNone(agent.dns_anomaly("<private>", ""))
        self.assertIsNone(agent.dns_anomaly("", "A"))


class CollectorPipeline(unittest.TestCase):
    def _collector(self, hist, lines, name="dnsmasq", parser=None):
        c = agent.DNSCollector(history=hist, enabled=True, interval=60, platform="linux")
        c.source = {"kind": "file", "path": "/x", "name": name,
                    "parser": parser or agent.parse_dnsmasq_query}
        c.source_name = name
        c._read_lines = lambda: iter(lines)
        return c

    def test_records_dedup_and_flags_anomalies(self):
        h = _hist()
        lines = ["q query[A] www.google.com from 127.0.0.1",
                 "q query[NULL] data.tunnel.example.com from 127.0.0.1",
                 "q query[A] kq3x9vmz1p7wab2c8fgh.example.com from 127.0.0.1"]
        c = self._collector(h, lines)
        c._collect()
        c._collect()                                   # same lines again → dedup, not new rows
        rows = h.recent_dns(3650)
        self.assertEqual(len(rows), 3, "three distinct queries, deduped across two passes")
        self.assertTrue(all(r["times_seen"] == 2 for r in rows), "repeat bumps times_seen")
        sev = {n["id"]: n["severity"] for n in c.snapshot()}
        self.assertIn("dns:data.tunnel.example.com:NULL", sev)
        self.assertIn("dns:kq3x9vmz1p7wab2c8fgh.example.com:A", sev)
        self.assertNotIn("dns:www.google.com:A", sev, "a benign lookup raises no anomaly node")

    def test_event_carries_no_payload(self):
        h = _hist()
        c = self._collector(h, ["q query[A] example.com from 127.0.0.1"])
        c._collect()
        row = h.recent_dns(3650)[0]
        self.assertEqual(set(row) >= {"qname", "qtype", "source", "times_seen"}, True)
        self.assertNotIn("answer", row)
        self.assertNotIn("payload", row)
        self.assertNotIn("content", row)


class HonestyInvariant(unittest.TestCase):
    def test_no_source_reports_none_not_silence(self):
        c = agent.DNSCollector(history=_hist(), enabled=True, interval=60,
                               platform="linux", candidates=())
        c.start()                                      # no file source, linux → no unified log either
        st = c.status()
        self.assertEqual(st["source"], "none")
        self.assertEqual(st["source_kind"], "none")
        self.assertIn("no readable DNS source", st["note"])

    def test_disabled_collector_does_nothing(self):
        c = agent.DNSCollector(history=_hist(), enabled=False)
        c.start()
        self.assertFalse(c.started, "a disabled collector never starts its loop")
        self.assertEqual(c.status()["enabled"], False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
