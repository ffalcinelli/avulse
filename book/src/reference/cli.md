# Command line

```text
avulse <COMMAND>

Commands:
  filter  Work with filters
```

Today the CLI only works with filters. Capture and injection commands will come with the
backends.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success; for `eval`, the packet matched |
| 1 | `eval` only: the packet did not match |
| 2 | an error: the filter does not compile, or a bad argument |

Errors and warnings go to standard error, in color when it is a terminal.

## Giving a filter

Every `filter` subcommand except `fields` takes the filter in one of three ways:

- as an argument: `avulse filter check 'tcp.port == 80'`;
- from a file, with `-f`/`--file`: `avulse filter check -f web.filter`;
- from standard input, with `-`: `echo 'tcp' | avulse filter check -`.

Quote filters in the shell: they contain spaces, `!`, `&`, `|`, `<`, `>` and braces.

## `avulse filter check`

Compiles the filter and prints its warnings. No output means the filter is clean.

```console
$ avulse filter check 'tcp.flags.syn'
warning: `tcp.flags.syn` is true whenever the field is present, even when it is 0
  |
1 | tcp.flags.syn
  | ^^^^^^^^^^^^^
  = help: to test the flag, write `tcp.flags.syn == 1`
```

## `avulse filter fmt`

Parses the filter and prints it in canonical form. It does not resolve fields, so it works on
filters that would not compile. Comments are dropped.

```console
$ avulse filter fmt 'tcp.port==80&&!udp'
tcp.port == 80 and not udp
```

## `avulse filter explain`

Compiles the filter and prints the typed intermediate representation as an S-expression, after
macro expansion and simplification. It notes when the filter needs user space.

```console
$ avulse filter explain 'tcp.flags & syn and not tcp.flags & ack'
(and (true (& tcp.flags 2)) (not (true (& tcp.flags 16))))
```

With `--bytecode`, it also prints the program that the kernel backends verify and run (see
[Design and roadmap](../project/design.md#compiled-programs)):

```console
$ avulse filter explain --bytecode 'tcp.dstport in {80 443} and not ip.src == 10.0.0.0/8'
(and (in tcp.dstport 80 443) (not (any_eq ip.src 10.0.0.0/8)))

bytecode, 7 instructions, 101 bytes:
0  field    r0, tcp.dstport
1  member   any_in r0, {80 443}
2  jf       7
3  field    r0, ip.src
4  lit      r1, 10.0.0.0/8
5  cmp      any_eq r0, r1
6  not
```

## `avulse filter convert`

Compiles a [WinDivert filter](../filters/windivert.md) and prints a native filter that selects the
same packets. `--layer <network|network-forward|flow|socket|reflect>` (default `network`) is the
WinDivert layer the filter is for: it decides which fields and macros are valid.

```console
$ avulse filter convert 'inbound and (tcp.Syn or udp.DstPort == 53) and !loopback'
inbound and (tcp.flags.syn == true or udp.dstport == 53) and not loopback
$ avulse filter convert 'packet16[1] > 0x40 and ip.HdrLength == 5'
frame[2:2] > 00:40 and ip.hdr_len == 20
```

## `avulse filter eval`

Evaluates the filter against one packet given in hex, and prints `match` or `no match`.

| Option | Meaning |
| --- | --- |
| `--hex <HEX>` | the packet bytes; spaces, colons, dashes and newlines are ignored |
| `--link <ethernet\|ip>` | what the bytes start with (default `ethernet`) |
| `--outbound` | treat the packet as outbound (the default is inbound) |
| `--iface <NAME>` | the interface name, for `iface` |

```console
$ avulse filter eval 'arp' --hex 'ffffffffffff 020000000001 0806
    0001 0800 06 04 0001 020000000001 0a000001 000000000000 0a000002'
match
```

## `avulse filter fields`

Lists every field: name, type, description and symbolic names. Extensions are marked with `+`.
`--format markdown` prints the [field reference](fields.md) of this guide.
