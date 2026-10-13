# Arithmetic and functions

## Arithmetic

Integer values support `+`, `-`, `*`, `/`, `%` and unary `-`. Curly braces group arithmetic, while
parentheses group tests:

```filter
tcp.srcport + 1 == tcp.dstport

{len(tcp) - 20} * 2 > 8

{tcp.srcport + tcp.dstport} % 2 == 0
```

As in Wireshark, `-` and `/` need spaces around them: `tcp.srcport-1` is read as a field name.

```filter,error
tcp.srcport-1 == 80
```

Arithmetic is signed and 64-bit. On fields with several occurrences, it combines every pair, as
comparisons do. Overflow and division by zero give no value, so a comparison with them is false.

Avulse differs from Wireshark in two small ways, both listed in the
[differences](wireshark.md): `tcp.srcport + -1` subtracts one (Wireshark converts the `-1` to the
field's unsigned type), and literals beyond the field's range are accepted in arithmetic
(`tcp.srcport + 1 == 65536`).

## Functions

| Function | Result |
| --- | --- |
| `len(v)` | the length in bytes of each occurrence of a byte value or protocol |
| `count(v)` | the number of occurrences |
| `max(a, b, …)`, `min(a, b, …)` | the largest or smallest of all occurrences of the arguments |
| `abs(v)` | the absolute value |
| `upper(s)`, `lower(s)` | a string field with ASCII letters folded |

```filter
len(udp.payload) > 512

count(vlan) == 2

max(tcp.srcport, tcp.dstport) < 1024

abs(tcp.srcport - tcp.dstport) == 1

upper(iface) == "ETH0"
```

Wireshark's `string()`, `dec()`, `hex()`, `float()` and `vals()` are not supported: they format
values as text, which needs allocation. `${field}` references to the packet selected in the
Wireshark window have no meaning outside the GUI.
