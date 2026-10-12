# Avulse

Divert, modify and re-inject network packets on Linux, Windows and macOS. Avulse covers every
WinDivert feature, adds an Ethernet layer, and uses a Wireshark-compatible filter language.

> *Avulsion*: a river suddenly abandoning its channel for a new one.

**Status: pre-alpha.** No packet capture yet. What works today:

- `avulse-proto`: zero-copy, `no_std` parsing of Ethernet, VLAN/QinQ, ARP, IPv4, IPv6 (extension
  headers, fragments), TCP, UDP, ICMP and ICMPv6, plus checksum recalculation.
- `avulse-filter`: the filter language (parser, type checker, IR, evaluator), `no_std` with `alloc`.
- `avulse filter check|fmt|explain|eval|fields`.

See [docs/roadmap.md](docs/roadmap.md) for the plan.

## Filters

Filters are Wireshark display filters, restricted to fields that one packet determines, plus a
few extensions:

```text
let lan = {10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16}
let web = tcp.port in {80, 443, 8000..8100}

outbound and ip.dst not in $lan and $web
```

- Wireshark semantics, including multi-value fields: `ip.addr == x` matches either address, and
  `ip.addr != x` means neither is `x`. `!==` (or `~=`) means "some differs". A comparison with an
  absent field is false.
- Sets, ranges and CIDR: `tcp.dstport in {80, 443, 8000..8100}`, `ip.src == 10.0.0.0/8`.
- Slices and payloads: `eth.src[0:3] == 00:11:22`, `tcp.payload contains "GET"`, `len(udp.payload) > 512`.
- Symbolic constants: `tcp.flags & syn`, `icmp.type == echo-request`, `eth.type == arp`.
- Extensions: `inbound`, `outbound`, `loopback`, `iface`, `layer`, `event`, `process.pid`,
  `local.addr`, `remote.port`, `let` macros used as `$name`.
- Fields that need stream state or application dissectors (`tcp.seq`, `tcp.stream`, `http.*`,
  `dns.*`) are rejected with a hint.

```console
$ avulse filter check 'tcp.prot == 80'
error: unknown field `tcp.prot`
  |
1 | tcp.prot == 80
  | ^^^^^^^^
  = help: did you mean `tcp.port`?

$ avulse filter explain 'tcp.flags & syn and not tcp.flags & ack'
(and (true (& tcp.flags 2)) (not (true (& tcp.flags 16))))

$ avulse filter fields     # every supported field
```

## License

Dual-licensed under LGPL-3.0-or-later or GPL-2.0-or-later, at your option. See [LICENSE](LICENSE).
