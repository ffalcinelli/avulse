# Fields and comparisons

## Fields with several values

Some fields have more than one value, or *occurrence*, in a packet:

- `ip.addr`, `ipv6.addr`, `eth.addr`: the source and the destination;
- `tcp.port`, `udp.port`: the source and the destination port;
- `vlan.id` and the other `vlan.*` fields: one per 802.1Q tag.

A comparison between two values looks at every *pair* of occurrences, and its operator says how
many pairs must satisfy it. This is Wireshark's behaviour since version 3.6, and the operators read
naturally:

| Filter | Matches when |
| --- | --- |
| `ip.addr == 10.0.0.1` | the source **or** the destination is 10.0.0.1 |
| `ip.addr != 10.0.0.1` | **neither** is 10.0.0.1 |
| `ip.addr === 10.0.0.1` | **both** are 10.0.0.1 |
| `ip.addr !== 10.0.0.1` | **at least one** is not 10.0.0.1 |
| `tcp.port > 1024` | **some** port is above 1024 |

So `ip.addr != 10.0.0.1` is the negation of `ip.addr == 10.0.0.1` on an IPv4 packet. `!==` is
the "some differs" operator; Avulse also accepts `~=`, its spelling in Wireshark 3.6.

## Quantifiers

`any` and `all` before a relation override the operator's default:

```filter
all tcp.port > 1024

any ip.addr !== 10.0.0.1

all ip.addr in {10.0.0.0/8}
```

The first matches TCP packets where both ports are above 1024; the last matches IPv4 packets whose
source and destination are both in 10.0.0.0/8.

## Absent fields

**A comparison with an absent field is false**, whatever the operator. `tcp.port != 80` does not
match a UDP packet, and `ip.dst != 10.0.0.1` does not match an IPv6 packet. To include packets
without the field, say so:

```filter
not tcp or tcp.port != 80
```

`not in` follows the same rule: `ip.dst not in {10.0.0.0/8}` means "has an IPv4 destination, and
it is not in 10.0.0.0/8". `not ip.dst in {10.0.0.0/8}` also matches packets without an IPv4
header.

```filter
ip.dst not in {10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16}
```

## Presence

A field or protocol name on its own tests that it is present:

```filter
ipv6.fraghdr.offset or vlan
```

For a boolean field, this is a trap inherited from Wireshark: `tcp.flags.syn` is true for every
TCP packet, because the field is present even when the bit is 0. Avulse compiles it, as Wireshark
does, but warns. Compare the value instead:

```filter
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

The Avulse flags (`outbound`, `loopback` and the others in [metadata](metadata.md)) are the
exception: bare, they test that the value is true.

```filter
outbound and not loopback
```

## Types

Every field has a type, listed in the [field reference](../reference/fields.md): boolean, unsigned
integer of a given width, IPv4 or IPv6 address, MAC address, bytes, string, or protocol. Both
sides of a comparison must have compatible types, and a literal must fit the field:

```filter,error
ip.ttl > 300
```

```filter,error
ip.src == ::1
```

Both are compile errors. Wireshark accepts the first one and never matches it.

An integer compared with bytes is one byte, as in Wireshark 4.6: `tcp[13] == 18` compares the
byte with 18 (0x12). Because older Wireshark versions read `18` as the hex byte 0x18, Avulse
warns about one- and two-digit integers there. Write `0x12`, or `18:` for the hex byte.

```filter
tcp[13] == 0x12 or tcp[13] == 18:
```
