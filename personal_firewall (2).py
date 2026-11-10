#!/usr/bin/env python3
"""
Personal Firewall (educational) - stdlib only.

Modes
  monitor : sniff traffic (AF_PACKET, Linux, root), evaluate each packet against
            the rule file and log the verdict. Passive: nothing is blocked.
  enforce : translate the rule file into iptables rules (custom chains PF_IN /
            PF_OUT) so the kernel actually filters traffic.
  clear   : remove everything `enforce` installed.
  check   : evaluate one hand-described packet against the rules (no root).

Examples
  sudo python3 personal_firewall.py monitor -r rules.json
  sudo python3 personal_firewall.py enforce -r rules.json --dry-run
  sudo python3 personal_firewall.py enforce -r rules.json
  sudo python3 personal_firewall.py clear
  python3 personal_firewall.py check -r rules.json --dir in --proto tcp \
          --src 8.8.8.8 --dst 192.168.1.5 --dport 22
"""
import argparse
import ipaddress
import json
import logging
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

log = logging.getLogger("pfw")

# --------------------------------------------------------------------------
# Packet parsing (protocol analysis)
# --------------------------------------------------------------------------
PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp"}
TCP_FLAGS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
             (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]


@dataclass
class Packet:
    direction: str            # "in" or "out"
    proto: str                # tcp / udp / icmp / other
    src: str
    dst: str
    sport: Optional[int] = None
    dport: Optional[int] = None
    flags: str = ""
    length: int = 0

    def summary(self) -> str:
        s = f"{self.src}:{self.sport}" if self.sport is not None else self.src
        d = f"{self.dst}:{self.dport}" if self.dport is not None else self.dst
        extra = f" [{self.flags}]" if self.flags else ""
        return f"{self.direction.upper():3} {self.proto.upper():5} {s} -> {d}{extra} len={self.length}"


def parse_ipv4(data: bytes, direction: str) -> Optional[Packet]:
    """Parse a raw IPv4 packet (no Ethernet header)."""
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total_len = struct.unpack("!H", data[2:4])[0]
    proto_num = data[9]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    pkt = Packet(direction, PROTO_NAMES.get(proto_num, "other"), src, dst, length=total_len)
    payload = data[ihl:]
    if pkt.proto in ("tcp", "udp") and len(payload) >= 4:
        pkt.sport, pkt.dport = struct.unpack("!HH", payload[:4])
        if pkt.proto == "tcp" and len(payload) >= 14:
            f = payload[13]
            pkt.flags = ",".join(n for bit, n in TCP_FLAGS if f & bit)
    return pkt


def parse_ethernet(frame: bytes, direction: str) -> Optional[Packet]:
    if len(frame) < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype == 0x0800:           # IPv4 only (IPv6 left as an exercise)
        return parse_ipv4(frame[14:], direction)
    return None


# --------------------------------------------------------------------------
# Rule engine
# --------------------------------------------------------------------------
def parse_ports(spec) -> Optional[Tuple[int, int]]:
    if spec in (None, "", "any"):
        return None
    s = str(spec)
    lo, _, hi = s.partition("-")
    lo_i, hi_i = int(lo), int(hi or lo)
    if not (0 <= lo_i <= hi_i <= 65535):
        raise ValueError(f"bad port spec: {spec!r}")
    return lo_i, hi_i


@dataclass
class Rule:
    action: str                       # ALLOW / DROP
    direction: str = "any"            # in / out / any
    proto: str = "any"                # tcp / udp / icmp / any
    src: Optional[ipaddress.IPv4Network] = None
    dst: Optional[ipaddress.IPv4Network] = None
    sport: Optional[Tuple[int, int]] = None
    dport: Optional[Tuple[int, int]] = None
    comment: str = ""
    raw_ports: Tuple[str, str] = ("", "")

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        action = d.get("action", "").upper()
        if action not in ("ALLOW", "DROP"):
            raise ValueError(f"rule action must be ALLOW or DROP: {d}")
        direction = d.get("direction", "any").lower()
        proto = d.get("proto", "any").lower()
        if direction not in ("in", "out", "any"):
            raise ValueError(f"bad direction: {d}")
        if proto not in ("tcp", "udp", "icmp", "any"):
            raise ValueError(f"bad proto: {d}")
        net = lambda v: ipaddress.ip_network(v, strict=False) if v not in (None, "", "any") else None
        r = cls(action, direction, proto, net(d.get("src")), net(d.get("dst")),
                parse_ports(d.get("sport")), parse_ports(d.get("dport")),
                d.get("comment", ""),
                (str(d.get("sport", "")), str(d.get("dport", ""))))
        if (r.sport or r.dport) and proto not in ("tcp", "udp"):
            raise ValueError(f"ports need proto tcp/udp: {d}")
        return r

    def matches(self, p: Packet) -> bool:
        if self.direction != "any" and self.direction != p.direction:
            return False
        if self.proto != "any" and self.proto != p.proto:
            return False
        if self.src and ipaddress.ip_address(p.src) not in self.src:
            return False
        if self.dst and ipaddress.ip_address(p.dst) not in self.dst:
            return False
        if self.sport and (p.sport is None or not self.sport[0] <= p.sport <= self.sport[1]):
            return False
        if self.dport and (p.dport is None or not self.dport[0] <= p.dport <= self.dport[1]):
            return False
        return True


class RuleSet:
    def __init__(self, rules: List[Rule], default_in="DROP", default_out="ALLOW",
                 log_drops=True):
        self.rules, self.default_in, self.default_out = rules, default_in, default_out
        self.log_drops = log_drops

    @classmethod
    def load(cls, path: str) -> "RuleSet":
        with open(path) as f:
            cfg = json.load(f)
        pol = cfg.get("default_policy", {})
        din, dout = pol.get("in", "DROP").upper(), pol.get("out", "ALLOW").upper()
        for v in (din, dout):
            if v not in ("ALLOW", "DROP"):
                raise ValueError("default policy must be ALLOW or DROP")
        return cls([Rule.from_dict(r) for r in cfg.get("rules", [])], din, dout,
                   cfg.get("log_drops", True))

    def evaluate(self, p: Packet) -> Tuple[str, str]:
        """First match wins. Returns (action, reason)."""
        for i, r in enumerate(self.rules, 1):
            if r.matches(p):
                return r.action, f"rule #{i} {r.comment}".strip()
        return (self.default_in if p.direction == "in" else self.default_out), "default policy"


# --------------------------------------------------------------------------
# Monitor mode (live sniffing)
# --------------------------------------------------------------------------
PACKET_OUTGOING = 4


def run_monitor(rs: RuleSet, iface: Optional[str], count: int):
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except (AttributeError, PermissionError, OSError) as e:
        sys.exit(f"Cannot open raw socket ({e}). Needs Linux and root.")
    if iface:
        s.bind((iface, 0))
    stats = {"ALLOW": 0, "DROP": 0}
    seen = 0
    log.info("Monitoring (passive - nothing is blocked). Ctrl+C to stop.")
    try:
        while count == 0 or seen < count:
            frame, addr = s.recvfrom(65535)
            direction = "out" if addr[2] == PACKET_OUTGOING else "in"
            pkt = parse_ethernet(frame, direction)
            if not pkt:
                continue
            seen += 1
            action, why = rs.evaluate(pkt)
            stats[action] += 1
            lvl = logging.WARNING if action == "DROP" else logging.INFO
            log.log(lvl, "%-5s %s  (%s)", action, pkt.summary(), why)
    except KeyboardInterrupt:
        pass
    log.info("Summary: %d would-be allowed, %d would-be dropped", stats["ALLOW"], stats["DROP"])


# --------------------------------------------------------------------------
# Enforce mode (iptables backend)
# --------------------------------------------------------------------------
IPT_TARGET = {"ALLOW": "ACCEPT", "DROP": "DROP"}


def build_iptables(rs: RuleSet) -> List[List[str]]:
    """Return iptables argument lists. Never uses a shell."""
    cmds: List[List[str]] = []
    ipt = lambda *a: cmds.append(["iptables", *a])

    for chain in ("PF_IN", "PF_OUT"):
        ipt("-N", chain)
    ipt("-A", "PF_IN", "-i", "lo", "-j", "ACCEPT")
    ipt("-A", "PF_OUT", "-o", "lo", "-j", "ACCEPT")
    ipt("-A", "PF_IN", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")

    for r in rs.rules:
        chains = {"in": ["PF_IN"], "out": ["PF_OUT"], "any": ["PF_IN", "PF_OUT"]}[r.direction]
        for chain in chains:
            a = ["-A", chain]
            if r.proto != "any":
                a += ["-p", r.proto]
            if r.src:
                a += ["-s", str(r.src)]
            if r.dst:
                a += ["-d", str(r.dst)]
            if r.sport:
                a += ["--sport", f"{r.sport[0]}:{r.sport[1]}"]
            if r.dport:
                a += ["--dport", f"{r.dport[0]}:{r.dport[1]}"]
            if r.action == "DROP" and rs.log_drops:
                ipt(*a, "-m", "limit", "--limit", "5/min", "-j", "LOG", "--log-prefix", "PFW-DROP: ")
            ipt(*a, "-j", IPT_TARGET[r.action])

    for chain, pol in (("PF_IN", rs.default_in), ("PF_OUT", rs.default_out)):
        if pol == "DROP" and rs.log_drops:
            ipt("-A", chain, "-m", "limit", "--limit", "5/min", "-j", "LOG", "--log-prefix", "PFW-DROP: ")
        ipt("-A", chain, "-j", IPT_TARGET[pol])

    ipt("-I", "INPUT", "1", "-j", "PF_IN")
    ipt("-I", "OUTPUT", "1", "-j", "PF_OUT")
    return cmds


def clear_iptables(dry_run=False):
    cmds = [["iptables", "-D", "INPUT", "-j", "PF_IN"],
            ["iptables", "-D", "OUTPUT", "-j", "PF_OUT"]]
    for c in ("PF_IN", "PF_OUT"):
        cmds += [["iptables", "-F", c], ["iptables", "-X", c]]
    for c in cmds:
        run_cmd(c, dry_run, check=False)


def run_cmd(cmd: List[str], dry_run: bool, check=True):
    print(("[dry-run] " if dry_run else "") + " ".join(cmd))
    if dry_run:
        return
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode and check:
        raise RuntimeError(f"{' '.join(cmd)} failed: {res.stderr.strip()}")


def run_enforce(rs: RuleSet, dry_run: bool):
    if not dry_run:
        clear_iptables(dry_run=False)      # idempotent re-apply
    try:
        for c in build_iptables(rs):
            run_cmd(c, dry_run)
    except Exception as e:
        print(f"Error: {e}\nRolling back...", file=sys.stderr)
        clear_iptables(dry_run)
        sys.exit(1)
    if not dry_run:
        print("\nFirewall active. Remove with: sudo python3 personal_firewall.py clear")


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Personal firewall")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("monitor", "enforce", "check"):
        p = sub.add_parser(name)
        p.add_argument("-r", "--rules", default="rules.json")
    sub.add_parser("clear").add_argument("--dry-run", action="store_true")
    sub.choices["monitor"].add_argument("-i", "--iface")
    sub.choices["monitor"].add_argument("-n", "--count", type=int, default=0)
    sub.choices["enforce"].add_argument("--dry-run", action="store_true")
    c = sub.choices["check"]
    c.add_argument("--dir", choices=["in", "out"], required=True)
    c.add_argument("--proto", choices=["tcp", "udp", "icmp"], required=True)
    c.add_argument("--src", required=True)
    c.add_argument("--dst", required=True)
    c.add_argument("--sport", type=int)
    c.add_argument("--dport", type=int)
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")

    if args.cmd == "clear":
        clear_iptables(args.dry_run)
        return
    rs = RuleSet.load(args.rules)
    if args.cmd == "monitor":
        run_monitor(rs, args.iface, args.count)
    elif args.cmd == "enforce":
        run_enforce(rs, args.dry_run)
    else:
        pkt = Packet(args.dir, args.proto, args.src, args.dst, args.sport, args.dport)
        action, why = rs.evaluate(pkt)
        print(f"{action}  ({why})")


if __name__ == "__main__":
    main()
