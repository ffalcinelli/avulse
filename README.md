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

- Wireshark 4.6+ semantics, including multi-value fields: `ip.addr == x` matches either address,
  and `ip.addr != x` means neither is `x`. `!==` means "some differs". `ip.dst not in {…}` needs an
  IPv4 header, like any comparison: one with an absent field is false.
- Quantifiers: `all tcp.port > 1024`, `any ip.addr !== 10.0.0.1`, `all ip.addr in {10.0.0.0/8}`.
- Arithmetic and functions: `tcp.srcport + 1 == tcp.dstport`, `{len(tcp) - 20} * 2 > 8`,
  `max(tcp.srcport, tcp.dstport) < 1024`, `abs(tcp.srcport - tcp.dstport) == 1`. Results are signed.
  As in Wireshark, `-` and `/` need spaces (`tcp.srcport-1` is a field name), and `{ }` groups
  arithmetic while `( )` groups tests.
- Layers: `vlan.id#2 == 20` (the second 802.1Q tag), `vlan.id#[-1]` (the last one), `ip#1`. Each
  VLAN tag is a layer; every other protocol is layer 1, since Avulse reads only the outer headers.
  A `#` followed by a digit or `[` is the layer operator, even after a space; any other `#` starts
  a comment.
- Sets, ranges and CIDR: `tcp.dstport in {80, 443, 8000..8100}`, `ip.src == 10.0.0.0/8`.
- Slices and payloads: `eth.src[0:3] == 00:11:22`, `tcp.payload contains "GET"`, `len(udp.payload) > 512`.
- Multi-range slices concatenate: `eth.src[0:3,5] == 00:11:22:55`. Ranges that do not fit are
  skipped, as in Wireshark.
- `&` on bytes and addresses: `udp.payload[2:2] & 80:00`, `eth.dst[0] & 1`,
  `ip.src & 255.255.0.0 == 192.168.0.0`. The result is as long as the shorter side; bare, it tests
  for a set bit. `upper()` and `lower()` fold the string fields (`upper(iface) == "ETH0"`).
  An integer compared with bytes is one byte, as in Wireshark 4.6: `tcp[13] == 18` is 0x12, and
  `tcp[13] == 18:` is 0x18.
- Wireshark's value labels, quoted or not and in any case: `ip.proto == "TCP"`,
  `icmp.type == "Echo (ping) request"`, `ip.flags.df == "Set"`. A label shared by several values
  (`"Unassigned"`) is an error: write the number.
- Regular expressions: `tcp.payload matches "^(GET|POST) "`, or `~`. As in Wireshark they are
  case-insensitive unless the pattern says `(?-i)`, and they run over bytes (`"\\x81"` matches that
  byte). They need the `regex` feature (the CLI has it) and run in user space only.
- Symbolic constants: `tcp.flags & syn`, `icmp.type == echo-request`, `eth.type == arp`.
- Extensions: `inbound`, `outbound`, `loopback`, `iface`, `layer`, `event`, `process.pid`,
  `local.addr`, `remote.port`, `let` macros used as `$name`.
- Fields that need stream state or application dissectors (`tcp.seq`, `tcp.stream`, `http.*`,
  `dns.*`) are rejected with a hint.

### Differences from Wireshark

A test compares Avulse with `tshark` 4.6+ on every supported field and on a table of filters
(`AVULSE_TSHARK=1 cargo test -p avulse-filter tshark`). A filter that Wireshark accepts and Avulse
compiles selects the same packets, except:

- **Outermost headers only.** Wireshark also dissects the datagram that an ICMP error quotes, so
  there `udp.port == 53` matches a "port unreachable" about DNS traffic. Avulse, like WinDivert,
  reads only the outer headers.
- **No partial headers.** Wireshark keeps the fields of a header that is cut short as far as the
  bytes go. Avulse drops the incomplete header, so its fields are absent.
- **No reassembly.** As in Wireshark with reassembly off, `tcp.len` is absent on IP fragments.
- **Stricter types.** A literal that cannot fit the field is an error (`ip.flags == 8`), where
  Wireshark accepts the filter and never matches.
- **Computed byte strings are capped at 32 bytes.** A multi-range slice or a `&` on two byte
  strings that comes out longer gives no value (or a compile error when the length is known). A
  single-range slice has no limit.
- **Rust regular expressions, not PCRE2.** Look-around and backreferences are rejected, and `$`
  matches only at the very end, where PCRE2 also matches before a final newline (write `\n?$`).
- **Signed arithmetic throughout.** `tcp.srcport + -1` subtracts one; Wireshark converts the `-1` to
  the field's unsigned type. Avulse also accepts literals beyond the field's range in arithmetic
  (`tcp.srcport + 1 == 65536`), which Wireshark rejects.

Avulse also accepts some syntax that Wireshark rejects, and that never changes the meaning of a
Wireshark filter: `#`, `//` and `/* */` comments, `let` macros, `~=` (Wireshark 3.6's spelling of
`!==`), space-separated sets (`{80 443}`), the metadata fields above, and symbolic constants
Wireshark does not know (`syn`, `echo-request`, `ip.proto == tcp`, where Wireshark reads `tcp` as
the protocol field).

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
