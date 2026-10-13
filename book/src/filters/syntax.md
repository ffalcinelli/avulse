# Syntax

## Tests and logical operators

A filter is a test. Tests combine with the logical operators, in decreasing order of precedence:

| Operator | Also written | Meaning |
| --- | --- | --- |
| `not a` | `!a` | negation |
| `a and b` | `a && b` | both |
| `a xor b` | `a ^^ b` | exactly one |
| `a or b` | `a \|\| b` | at least one |

Keywords are case-insensitive (`AND` works). Parentheses group tests. As in Wireshark, `and`
binds tighter than `or`, so these two filters are the same:

```filter
ip.src == 10.0.0.1 or ip.dst == 10.0.0.1 and tcp

ip.src == 10.0.0.1 or (ip.dst == 10.0.0.1 and tcp)
```

The simplest tests are `true`, `false`, and a bare protocol or field name, which tests that it is
present:

```filter
tcp

not (arp or ipv6)
```

## Relations

A relation compares a value with another value or a set:

| Operator | Also written | Meaning |
| --- | --- | --- |
| `==` | `eq`, `any_eq` | some pair of values is equal |
| `!=` | `ne`, `all_ne` | no pair is equal |
| `===` | `all_eq` | every pair is equal |
| `!==` | `~=`, `any_ne` | some pair differs |
| `<` `<=` `>` `>=` | `lt` `le` `gt` `ge` | ordering (integers, addresses, strings, bytes) |
| `contains` | | byte substring |
| `matches` | `~` | [regular expression](regex.md) |
| `in` | | set membership |
| `not in` | | present, and no value in the set |

"Pair" matters for fields that have [several values](comparisons.md), such as `ip.addr` (the
source and the destination). There is no single `=`: write `==`.

```filter
tcp.port == 80 && ip.src eq 10.0.0.1

tcp.dstport in {80, 443} and not ip.dst in {10.0.0.0/8}
```

## Values

Values are fields, literals, slices, function calls and arithmetic. The literal forms are:

| Kind | Examples |
| --- | --- |
| Integer | `80`, `0x50`, `0120` (octal) |
| IPv4 address or network | `10.0.0.1`, `10.0.0.0/8` |
| IPv6 address or network | `2001:db8::1`, `fe80::/10` |
| MAC address | `00:11:22:33:44:55`, `00-11-22-33-44-55`, `0011.2233.4455` |
| Bytes | `47:45:54`, `0d-0a`, `18:` (one byte) |
| String | `"GET "`, `"a\"b"`, `"\x00\x01"`, `r"\d+"` (raw) |
| Character | `'G'`, `'\n'` |
| Label or symbolic name | `"TCP"`, `syn`, `echo-request` (see [values](values.md)) |

A word is read according to what it is compared with, as in Wireshark: `00:11:22:33:44:55` is a
MAC address in `eth.src == 00:11:22:33:44:55` and six bytes in
`tcp.payload[0:6] == 00:11:22:33:44:55`.

As in Wireshark, `-` and `/` are part of a word unless spaces surround them: `tcp.srcport-1` is a
field name, and `tcp.srcport - 1` is arithmetic.

## Comments

Avulse accepts three kinds of comments, which Wireshark does not:

```filter
# a line comment
tcp.port == 80 // another one
/* a block comment */ or udp.port == 53
```

A `#` followed by a digit or `[` is the [layer operator](bytes.md#layers) instead (`vlan.id#2`).

## Macros

`let name = …` defines a macro, and `$name` (or `${name}`) uses it. The `let` lines come first.
A macro holds a test, a value or a set:

```filter
let lan = {10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16}
let web = tcp.port in {80, 443}
let gw = 192.168.1.1

$web and ip.dst not in $lan and ip.dst != ${gw}
```

Macros expand where they are used; they do not change the meaning of what they contain.
Wireshark has display filter macros too, but defines them in its preferences instead.

## Canonical form

`avulse filter fmt` prints a filter in canonical form: `and`/`or`/`not`, `==`/`!=`, sets with
commas, and single spaces. It is a good way to see how a filter was parsed.

```console
$ avulse filter fmt 'TCP.port==80&&!udp||ip.src in {10.0.0.0/8 192.168.0.0/16}'
TCP.port == 80 and not udp or ip.src in {10.0.0.0/8, 192.168.0.0/16}
```

Field names are case-sensitive: `TCP.port` parses, but it is an unknown field.
