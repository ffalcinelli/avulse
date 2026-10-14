# WinDivert filters

Avulse also accepts [WinDivert](https://reqrypt.org/windivert.html)'s own filter language, so
that existing programs keep their filters. A WinDivert filter compiles to the same IR as a native
one: it runs in the same evaluator and the same kernel bytecode, and `avulse filter convert`
prints its native equivalent.

```console
$ avulse filter convert 'outbound and !loopback and (tcp.DstPort == 80 or udp.DstPort == 53)'
outbound and not loopback and (tcp.dstport == 80 or udp.dstport == 53)
$ avulse filter convert --layer socket 'event == CONNECT and processId == 4'
event == 4 and process.pid == 4
```

In Rust, use `Filter::compile_windivert(src, layer)`. The layer matters: WinDivert accepts each
field and macro at some layers only, such as `processId` at FLOW, SOCKET and REFLECT, or `CONNECT`
at SOCKET.

```windivert
inbound and tcp.Syn and !tcp.Ack

(tcp? tcp.PayloadLength > 0: udp.DstPort == 53)

packet[0] == 0x45 and packet16[-2b] != 0x0d0a and ip.DstAddr >= 10.0.0.0 and ip.DstAddr <= 10.255.255.255

ipv6.SrcAddr == ::1 or localAddr == ::ffff:127.0.0.1
```

## Same results as WinDivert

The front-end follows WinDivert 2.2's compiler and evaluator, and passes WinDivert's own test
vectors: 241 filters over 10 packets, through the evaluator, the bytecode and the converted
native filter (the vectors that use `random*` only check that they compile, since their result
depends on the packet hash). WinDivert's rules differ from Wireshark's in several ways:

- **Names are case-sensitive**: `tcp.DstPort` and `TCP`, not `tcp.dstport` or `tcp`.
- **`not` negates one comparison.** `not tcp.DstPort == 80` is `tcp.DstPort != 80`, which, like
  every test on a header the packet lacks, is false on a UDP packet. `not` cannot apply to a
  parenthesized filter.
- **A bare field is `field != 0`**: `tcp.Syn`, `ip`, `outbound`.
- **Values are 128-bit numbers with a sign.** An IPv4 address is `::ffff:a.b.c.d`, so
  `ip.DstAddr == ::ffff:8.8.4.4` holds for 8.8.4.4, `ipv6.DstAddr >= 1000` is valid, and even
  `tcp.Syn == ::1` is (a field narrower than 64 bits compares only the low 32 bits of the
  value).
- **Decided comparisons become protocol tests.** When a field's range decides a comparison,
  WinDivert replaces it with a test on the field's protocol. `ip.TOS < 0` becomes `not ip`, true
  on an IPv6 packet; `tcp.Syn <= 1` becomes `tcp`.
- **`(a? b: c)`** is a conditional, and needs its parentheses. `and` binds tighter than `or`.
- **`packet[i]`, `packet16[i]`, `packet32[i]`** read a big-endian word at word `i`, at byte `i`
  with a `b` suffix, and from the end with a negative index; `tcp.Payload*` and `udp.Payload*`
  read the payload the same way.
- **`localPort` and `remotePort`** on an ICMP packet are the ICMP type on the sending side and 0
  on the other.

## How fields convert

| WinDivert | Native |
| --- | --- |
| `ip.HdrLength`, `tcp.HdrLength` (32-bit words) | `ip.hdr_len`, `tcp.hdr_len` (bytes), four times the value |
| `ip.TOS`, `ip.Length`, `ip.Id`, `ip.FragOff`, `ip.TTL`, `ip.Protocol` | `ip.dsfield`, `ip.len`, `ip.id`, `ip.frag_offset`, `ip.ttl`, `ip.proto` |
| `ip.DF`, `ip.MF`, `tcp.Syn`, … | `ip.flags.df == true`, `tcp.flags.syn == true`, … |
| `ipv6.TrafficClass`, `ipv6.FlowLabel`, `ipv6.Length`, `ipv6.NextHdr`, `ipv6.HopLimit` | `ipv6.tclass`, `ipv6.flow`, `ipv6.plen`, `ipv6.nxt`, `ipv6.hlim` |
| `tcp.SeqNum`, `tcp.AckNum`, `tcp.Window`, `tcp.UrgPtr` | `tcp.seq_raw`, `tcp.ack_raw`, `tcp.window_size_value`, `tcp.urgent_pointer` |
| `icmp.Body`, `icmpv6.Body` | `icmp[4:4]`, `icmpv6[4:4]` |
| `tcp.PayloadLength`, `udp.PayloadLength` | `len(tcp.payload)`, `len(udp.payload)` (0 when absent) |
| `packet16[2]`, `tcp.Payload32[-1]` | `frame[4:2]`, `tcp.payload[-4:4]` |
| `length` | `frame.len` |
| `localAddr`, `remoteAddr`, `localPort`, `remotePort`, `processId`, `endpointId`, `ifIdx`, … | `local.addr`, `remote.addr`, `local.port`, `remote.port`, `process.pid`, `endpoint.id`, `ifidx`, … |
| `timestamp`, `priority`, `random8`, `random16`, `random32` | the same names ([metadata](metadata.md)) |

Native filters have no conditional, so `convert` writes `(a? b: c)` as `a and b or not a and c`.
Conditionals nested in conditions double in size at every level; `convert` refuses output of
more than 10,000 tests. The compiled filter itself has a conditional node, so it does not grow.

## Limits and differences

- WinDivert's limits apply: at most 256 tests, tokens of at most 40 characters, indexes up to
  65,535 bytes. Parentheses nest at most 341 levels deep, as WinDivert's parser allows.
- Compiled filter objects (strings starting with `@`) are not accepted; pass the filter string.
- On some malformed packets, WinDivert's own parser reads the headers differently from Avulse's:
  the UDP payload ends at the UDP length rather than at the IP length, IPv6 mobility headers
  (135) are not skipped, ICMP is recognized after IPv6, and a TCP header whose options are cut
  short is dropped rather than shortened.
- `random8`, `random16` and `random32` read the packet hash the backend provides; a
  WinDivert-compatible backend computes it as WinDivert does.
