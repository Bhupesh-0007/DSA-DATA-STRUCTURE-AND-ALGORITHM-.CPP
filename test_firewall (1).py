import struct
import socket
import unittest

from personal_firewall import (Packet, Rule, RuleSet, parse_ethernet,
                               build_iptables)


def make_ipv4_tcp(src, dst, sport, dport, flags=0x02):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 8192, 0, 0)
    total = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return b"\xff" * 6 + b"\x00" * 6 + b"\x08\x00" + ip + tcp


class T(unittest.TestCase):
    def setUp(self):
        self.rs = RuleSet.load("rules.json")

    def test_parser(self):
        p = parse_ethernet(make_ipv4_tcp("1.2.3.4", "5.6.7.8", 4444, 22), "in")
        self.assertEqual((p.proto, p.src, p.dst, p.sport, p.dport, p.flags),
                         ("tcp", "1.2.3.4", "5.6.7.8", 4444, 22, "SYN"))

    def test_garbage_is_ignored(self):
        self.assertIsNone(parse_ethernet(b"\x00" * 5, "in"))
        self.assertIsNone(parse_ethernet(b"\x00" * 12 + b"\x08\x00" + b"\x00" * 4, "in"))

    def test_ssh_lan_allowed_wan_dropped(self):
        lan = Packet("in", "tcp", "192.168.1.9", "192.168.1.5", 5000, 22)
        wan = Packet("in", "tcp", "8.8.8.8", "192.168.1.5", 5000, 22)
        self.assertEqual(self.rs.evaluate(lan)[0], "ALLOW")
        self.assertEqual(self.rs.evaluate(wan)[0], "DROP")

    def test_blocklist_beats_later_allow(self):
        p = Packet("in", "icmp", "203.0.113.7", "192.168.1.5")
        self.assertEqual(self.rs.evaluate(p)[0], "DROP")

    def test_outbound_rules_and_default(self):
        self.assertEqual(self.rs.evaluate(Packet("out", "tcp", "10.0.0.2", "9.9.9.9", 1, 23))[0], "DROP")
        self.assertEqual(self.rs.evaluate(Packet("out", "udp", "10.0.0.2", "9.9.9.9", 1, 6885))[0], "DROP")
        self.assertEqual(self.rs.evaluate(Packet("out", "tcp", "10.0.0.2", "9.9.9.9", 1, 443))[0], "ALLOW")

    def test_bad_rules_rejected(self):
        for bad in ({"action": "MAYBE"}, {"action": "DROP", "proto": "icmp", "dport": "1"},
                    {"action": "DROP", "proto": "tcp", "dport": "70000"},
                    {"action": "DROP", "src": "not-an-ip"}):
            with self.assertRaises(ValueError):
                Rule.from_dict(bad)

    def test_iptables_generation(self):
        cmds = [" ".join(c) for c in build_iptables(self.rs)]
        self.assertIn("iptables -A PF_IN -p tcp -s 192.168.0.0/16 --dport 22:22 -j ACCEPT", cmds)
        self.assertIn("iptables -A PF_OUT -p udp --dport 6881:6889 -j DROP", cmds)
        self.assertEqual(cmds[-2:], ["iptables -I INPUT 1 -j PF_IN", "iptables -I OUTPUT 1 -j PF_OUT"])


if __name__ == "__main__":
    unittest.main()
