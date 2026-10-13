# Values, sets and labels

## Addresses and networks

IPv4 and IPv6 addresses compare as addresses, so ordering works. A network in CIDR notation
matches every address in it, with `==` as well as with `in`:

```filter
ip.src == 10.0.0.0/8 or ipv6.src == fe80::/10
```

MAC addresses accept `:`, `-` and `.` separators:

```filter
eth.dst == ff:ff:ff:ff:ff:ff or eth.src == 0011.2233.4455
```

## Sets and ranges

`in` tests membership in a set. A set holds values, inclusive ranges `a..b`, and networks.
Items are separated by commas or, as an Avulse extension, by spaces:

```filter
tcp.port in {80, 443, 8000..8100}

ip.dst in {10.0.0.0/8 192.168.1.1 172.16.0.1..172.16.0.9}

iface in {"eth0", "wlan0"}
```

A set can be named with `let` and reused:

```filter
let lan = {10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16}

ip.src in $lan and ip.dst not in $lan
```

## Wireshark's value labels

Wireshark shows many integer fields with a label, such as "TCP" for `ip.proto == 6` or
"Echo (ping) request" for `icmp.type == 8`, and accepts the label in filters. So does Avulse,
quoted or not and in any case:

```filter
ip.proto == "TCP"

icmp.type == "Echo (ping) request"

ip.flags.df == "Set"
```

The tables come from Wireshark itself (`tshark -G values`), merged across Wireshark 4.6 and 4.7.
A label that names several values, such as `"Unassigned"`, is an error: write the number, or a
set.

```filter,error
ip.proto == "Unassigned"
```

## Symbolic names

Avulse adds short names for common values that Wireshark does not have. They are listed for each
field in the [field reference](../reference/fields.md):

| Fields | Names |
| --- | --- |
| `eth.type`, `vlan.etype` | `ipv4`, `ip`, `arp`, `vlan`, `ipv6`, `qinq`, `lldp`, … |
| `ip.proto`, `ipv6.nxt`, `protocol` | `tcp`, `udp`, `icmp`, `icmpv6`, `gre`, `esp`, … |
| `tcp.flags` | `fin`, `syn`, `rst`, `psh`, `ack`, `urg`, `ece`, `cwr`, `ae` |
| `icmp.type`, `icmpv6.type` | `echo-request`, `echo-reply`, `neighbor-solicitation`, … |
| `arp.opcode` | `request`, `reply`, … |
| `layer`, `event` | see [metadata](metadata.md) |

```filter
eth.type == arp and arp.opcode == request

tcp.flags & syn and not tcp.flags & ack

icmpv6.type == neighbor-solicitation
```

Wireshark reads `ip.proto == tcp` differently: there `tcp` is the protocol field, so the filter
is not the same. A filter meant for both should use the number or the quoted label.
