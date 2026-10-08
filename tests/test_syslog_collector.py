#!/usr/bin/env python3
"""The edge syslog collector (XDR Phase 2).

Network gear (firewall / AP / router) speaks syslog in a handful of shapes. The collector parses the
RFC3164/5424 envelope, routes each line to a device profile, normalizes it to the mesh's common event
schema, and keeps only the security-relevant events. These tests pin the normalization and the edge
filter against representative lines from the first device profiles.

Device-log formats vary by firmware; these are starting profiles to tune against real output. The
point here is the contract: a known line yields the right normalized fields, and routine chatter is
dropped before it ever leaves the LAN.

Run from the repo root:  python3 -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent  # noqa: E402

N = agent.normalize_syslog


class TestEnvelope(unittest.TestCase):
    def test_rfc3164(self):
        env = agent._parse_syslog("<30>Oct  7 14:03:22 router dnsmasq-dhcp[1]: hello world")
        self.assertEqual(env["host"], "router")
        self.assertEqual(env["tag"], "dnsmasq-dhcp")
        self.assertEqual(env["msg"], "hello world")
        self.assertEqual(env["severity"], 30 & 7)

    def test_rfc5424(self):
        env = agent._parse_syslog("<134>1 2026-10-07T14:03:22Z fw1 filterlog - - - the message")
        self.assertEqual(env["host"], "fw1")
        self.assertEqual(env["tag"], "filterlog")
        self.assertEqual(env["msg"], "the message")
        self.assertEqual(env["ts"], 1791381802)        # 2026-10-07T14:03:22Z

    def test_accepts_bytes(self):
        self.assertIsNotNone(N(b"<190>Oct  7 14:03:22 ap1 hostapd: wlan0: AP-STA-CONNECTED a4:83:e7:11:22:33"))


class TestProfiles(unittest.TestCase):
    def test_pfsense_block(self):
        line = ("<134>Oct  7 14:03:22 fw1 filterlog[9]: 5,,,100,em0,match,block,in,4,0x0,,64,1,0,DF,6,"
                "tcp,60,203.0.113.5,10.0.0.12,54321,443,0,S")
        ev = N(line)
        self.assertEqual(ev["type"], "firewall_deny")
        self.assertEqual(ev["action"], "deny")
        self.assertEqual((ev["src_ip"], ev["dst_ip"]), ("203.0.113.5", "10.0.0.12"))
        self.assertEqual((ev["src_port"], ev["dst_port"]), (54321, 443))

    def test_fortigate_deny(self):
        line = ('<189>date=2026-10-07 time=14:03:22 devname=FGT type=traffic action=deny '
                'srcip=203.0.113.9 dstip=10.0.0.5 srcport=4444 dstport=22 user="bob" policyid=7')
        ev = N(line)
        self.assertEqual(ev["type"], "firewall_deny")
        self.assertEqual((ev["src_ip"], ev["dst_ip"]), ("203.0.113.9", "10.0.0.5"))
        self.assertEqual((ev["src_port"], ev["dst_port"]), (4444, 22))
        self.assertEqual(ev["user"], "bob")
        self.assertEqual(ev["rule"], "7")

    def test_dnsmasq_dhcp_lease(self):
        line = "<30>Oct  7 14:03:22 router dnsmasq-dhcp[1]: DHCPACK(eth0) 10.0.0.12 a4:83:e7:11:22:33 johns-mbp"
        ev = N(line)
        self.assertEqual(ev["type"], "dhcp_lease")
        self.assertEqual(ev["src_ip"], "10.0.0.12")
        self.assertEqual(ev["mac"], "a4:83:e7:11:22:33")
        self.assertEqual(ev["host"], "johns-mbp")

    def test_hostapd_wifi_assoc(self):
        line = "<190>Oct  7 14:03:22 ap1 hostapd: wlan0: AP-STA-CONNECTED A4:83:E7:11:22:33"
        ev = N(line)
        self.assertEqual(ev["type"], "wifi_assoc")
        self.assertEqual(ev["action"], "assoc")
        self.assertEqual(ev["mac"], "a4:83:e7:11:22:33")     # lower-cased

    def test_sonicwall_drop(self):
        line = ('<134>id=firewall sn=ABC fw=10.0.0.1 pri=1 m=36 msg="Connection Dropped" '
                'src=203.0.113.9:4444:X1 dst=10.0.0.5:22:X0')
        ev = N(line)
        self.assertEqual(ev["type"], "firewall_deny")
        self.assertEqual((ev["src_ip"], ev["dst_ip"]), ("203.0.113.9", "10.0.0.5"))
        self.assertEqual((ev["src_port"], ev["dst_port"]), (4444, 22))

    def test_generic_fallback(self):
        line = "<134>Oct  7 14:03:22 myfw kernel: [UFW BLOCK] SRC=203.0.113.9 DST=10.0.0.5 PROTO=TCP"
        ev = N(line)
        self.assertEqual(ev["type"], "firewall_deny")
        self.assertEqual(ev["src_ip"], "203.0.113.9")
        self.assertEqual(ev["dst_ip"], "10.0.0.5")


class TestEdgeFilter(unittest.TestCase):
    INTERNAL_ALLOW = ('<189>date=2026-10-07 time=14:03:22 devname=FGT type=traffic action=accept '
                      'srcip=10.0.0.5 dstip=10.0.0.6 srcport=5000 dstport=445')
    PUBLIC_ALLOW = ('<189>date=2026-10-07 time=14:03:22 devname=FGT type=traffic action=accept '
                    'srcip=10.0.0.5 dstip=1.1.1.1 srcport=5000 dstport=443')

    def test_internal_allow_dropped_by_default(self):
        self.assertIsNone(N(self.INTERNAL_ALLOW))       # LAN->LAN can't match an external IOC

    def test_public_allow_kept_by_default(self):
        ev = N(self.PUBLIC_ALLOW)                        # crosses the trust boundary -> kept
        self.assertEqual(ev["type"], "firewall_allow")
        self.assertEqual(ev["dst_ip"], "1.1.1.1")

    def test_keep_allows_keeps_internal(self):
        self.assertEqual(N(self.INTERNAL_ALLOW, keep_allows=True)["type"], "firewall_allow")

    def test_unparseable_dropped(self):
        self.assertIsNone(N("<13>Oct  7 14:03:22 host sshd: random informational chatter"))

    def test_custom_keep_set(self):
        # keep only DHCP leases -> a deny is now dropped
        deny = ("<134>Oct  7 14:03:22 fw1 filterlog[9]: 5,,,100,em0,match,block,in,4,0x0,,64,1,0,DF,6,"
                "tcp,60,203.0.113.5,10.0.0.12,54321,443,0,S")
        self.assertIsNone(N(deny, keep={"dhcp_lease"}))


class _FakeReporter:
    """Stands in for MeshReporter: configured and capturing, never touches the network or keychain."""
    enabled = True

    def __init__(self):
        self.batches = []

    def configured(self):
        return True

    def send_logs(self, events):
        self.batches.append(list(events))
        return {"accepted": len(events)}


class TestListener(unittest.TestCase):
    def test_udp_receive_to_forward(self):
        import socket
        import time
        rep = _FakeReporter()
        col = agent.SyslogCollector(rep, enabled=True, port=15140)   # binds an unprivileged test port
        if not col.enabled:
            self.skipTest("syslog test port unavailable")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(b'<189>date=2026-10-07 time=14:03:22 devname=FGT type=traffic action=deny '
                     b'srcip=203.0.113.9 dstip=10.0.0.5 srcport=4444 dstport=22', ("127.0.0.1", 15140))
            s.close()
            for _ in range(50):          # give the listener thread a moment
                if col.counts["kept"]:
                    break
                time.sleep(0.02)
            col.flush()
        finally:
            try:
                col._udp.close()
            except OSError:
                pass
        self.assertEqual(len(rep.batches), 1)
        self.assertEqual(rep.batches[0][0]["type"], "firewall_deny")
        self.assertEqual(rep.batches[0][0]["src_ip"], "203.0.113.9")



if __name__ == "__main__":
    unittest.main()
