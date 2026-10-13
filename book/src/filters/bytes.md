# Bytes, slices and layers

## Protocols as bytes

A protocol name is also its bytes:

| Name | Bytes |
| --- | --- |
| `frame` | the whole packet |
| `eth` | the Ethernet header (14 bytes) |
| `ip` | the IPv4 header, options included |
| `ipv6` | the IPv6 header, extension headers included |
| `tcp`, `udp` | the TCP or UDP header (options included), not the payload |
| `arp`, `icmp`, `icmpv6` | the whole message |
| `tcp.payload`, `udp.payload` | what follows the header (absent when empty) |

`contains` looks for a byte string, and `len()` gives the length:

```filter
tcp.payload contains "Host:" and len(tcp.payload) < 1400

udp.payload contains 00:01:00:00
```

## Slices

`value[…]` takes some bytes of a byte value. Offsets start at 0; negative offsets count from the
end.

| Slice | Bytes |
| --- | --- |
| `[i]` | byte `i` |
| `[i:n]` | `n` bytes from `i` |
| `[i-j]` | from `i` to `j`, inclusive |
| `[i:]` | from `i` to the end |
| `[:n]` | the first `n` |

```filter
tcp.payload[0:4] == "GET "

frame[12:2] == 08:00

tcp.payload[-2:] == 0d:0a

eth.src[0:3] == 00:11:22
```

A slice that does not fit is absent, so the comparison is false. Several ranges concatenate:

```filter
eth.src[0:3,5] == 00:11:22:55
```

Ranges that do not fit are skipped, as in Wireshark. A multi-range slice is limited to
[32 bytes](limits.md).

## Bitwise and

`&` is the bitwise and of integers or byte strings. On byte strings, the result is as long as the
shorter side. Used as a test, it checks that some bit is set:

```filter
tcp.flags & 0x12 == 0x12

eth.dst[0] & 1

ip.src & 255.255.0.0 == 192.168.0.0

udp.payload[2:2] & 80:00
```

## Raw bytes

`@field` is the bytes that a field covers on the wire. A field that is a few bits covers the bytes
it sits in:

```filter
@tcp.flags == 50:02

@ip.src == c0:a8:01:02
```

## Layers

`field#n` selects the occurrences of a field in protocol layer `n` (from 1; negative counts from
the last), and `field#[ranges]` in several layers. Each VLAN tag is a layer; every other protocol
is layer 1, since Avulse reads only the outermost headers.

```filter
vlan.id#1 == 100 and vlan.id#2 == 200

vlan.id#[-1] == 20

ip#1
```

A `#` followed by a digit or `[` is the layer operator, even after a space; any other `#` starts a
comment.
