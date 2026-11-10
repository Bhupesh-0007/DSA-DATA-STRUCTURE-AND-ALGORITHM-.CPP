# Personal Firewall (Python)

A small educational firewall: a rule engine, a raw-socket packet analyzer, and an iptables backend. Standard library only.

## Files
- `personal_firewall.py` - the firewall
- `rules.json` - example rule set
- `test_firewall.py` - unit tests (`python3 -m unittest -v test_firewall`)

## Modes
| Command | Needs root | What it does |
|---|---|---|
| `check` | no | Evaluate one described packet against the rules |
| `monitor` | yes (Linux) | Sniff live traffic, log what the rules *would* allow/drop (passive) |
| `enforce` | yes (Linux) | Install the rules into iptables (chains `PF_IN`, `PF_OUT`) |
| `clear` | yes (Linux) | Remove everything `enforce` installed |

```bash
python3 personal_firewall.py check --dir in --proto tcp --src 8.8.8.8 --dst 192.168.1.5 --dport 22
sudo python3 personal_firewall.py monitor -r rules.json -i eth0
sudo python3 personal_firewall.py enforce -r rules.json --dry-run   # preview commands
sudo python3 personal_firewall.py enforce -r rules.json
sudo python3 personal_firewall.py clear
```

## Rule format (`rules.json`)
Rules are evaluated top to bottom; the first match wins, otherwise the default policy applies.

```json
{ "action": "ALLOW|DROP", "direction": "in|out|any", "proto": "tcp|udp|icmp|any",
  "src": "CIDR", "dst": "CIDR", "sport": "80 or 1000-2000", "dport": "22", "comment": "..." }
```

`enforce` also adds loopback and ESTABLISHED/RELATED accept rules, so replies to your own outbound connections still work with a default-drop inbound policy.

## How it works
1. **Protocol analysis** - `parse_ethernet` / `parse_ipv4` decode Ethernet, IPv4, TCP/UDP ports, and TCP flags with `struct`.
2. **Packet filtering** - `RuleSet.evaluate` does first-match-wins over CIDR, protocol, port-range and direction.
3. **Kernel enforcement** - `build_iptables` turns the same rules into iptables commands (no shell, so no injection), with rate-limited LOG rules for drops and rollback if any command fails.

## Safety
- Run `enforce --dry-run` first. A default-drop inbound policy can lock you out of a remote SSH session; keep an allow rule for your own address.
- Test on a VM or machine you own. `clear` restores the previous state.

## Limitations / next steps
- IPv4 only (add ip6tables and an IPv6 parser).
- `monitor` is passive. For true userspace blocking, use NFQUEUE (`python-netfilterqueue`) with `-j NFQUEUE`.
- Windows: port the backend using the Windows Filtering Platform (WFP) API, or `netsh advfirewall` for a quick version.
- C++ variant: same parser with `AF_PACKET`/`libpcap`, rules via `libnetfilter_queue`.
