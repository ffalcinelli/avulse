# Your first filter

This walkthrough writes a filter for outbound web traffic that leaves the local network, then
checks, formats, explains and tests it.

## Check it

`avulse filter check` compiles a filter and reports errors and warnings. Typos get a suggestion:

```console
$ avulse filter check 'tcp.prot == 80'
error: unknown field `tcp.prot`
  |
1 | tcp.prot == 80
  | ^^^^^^^^
  = help: did you mean `tcp.port`?
```

Types are checked too. Comparing an IPv4 field with an IPv6 address is an error, not a filter
that silently never matches:

```console
$ avulse filter check 'ip.src == ::1'
error: `::1` is an IPv6 address
  |
1 | ip.src == ::1
  |           ^^^
  = help: IPv6 fields are `ipv6.src`, `ipv6.dst`, `ipv6.addr`
```

Some filters compile but probably do not mean what they say. A bare boolean field tests that the
field is *present*, as in Wireshark, so `avulse` warns:

```console
$ avulse filter check 'tcp.flags.syn'
warning: `tcp.flags.syn` is true whenever the field is present, even when it is 0
  |
1 | tcp.flags.syn
  | ^^^^^^^^^^^^^
  = help: to test the flag, write `tcp.flags.syn == 1`
```

## Write it

Put the filter in a file, say `web.filter`. `let` names a set or a test, and `$name` uses it:

```filter
# Private networks (RFC 1918).
let lan = {10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16}
let web = tcp.dstport in {80, 443, 8000..8100}

outbound and ip.dst not in $lan and $web
```

```console
$ avulse filter check -f web.filter
```

No output means no errors and no warnings. The exit code is 0.

## Format it

`avulse filter fmt` prints the canonical form: one spelling per operator, normalized spacing and
sets. It parses the filter but does not check it, so it also works on filters with unknown fields.
Comments are not kept.

```console
$ avulse filter fmt 'tcp.port==80&&!udp||ip.src in {10.0.0.0/8 192.168.0.0/16}'
tcp.port == 80 and not udp or ip.src in {10.0.0.0/8, 192.168.0.0/16}
```

## Explain it

`avulse filter explain` prints the compiled filter: the typed intermediate representation that
backends run, after macros are expanded and constants folded. It shows how each operator was
read. Here, `!=` became "all occurrences differ", because `ip.addr` has two occurrences in every
IPv4 packet (the source and the destination):

```console
$ avulse filter explain 'ip.addr != 10.0.0.1'
(all_ne ip.addr 10.0.0.1)

$ avulse filter explain 'tcp.port in {80, 443} and not tcp.flags & ack'
(and (in tcp.port 80 443) (not (true (& tcp.flags 16))))
```

## Test it

`avulse filter eval` runs a filter over one packet given in hex. `--link ip` says the bytes start
with an IP header (the NETWORK layer); the default is an Ethernet frame. The packet below is a
TCP SYN from 192.168.1.2:40000 to 93.184.215.14:443:

```console
$ avulse filter eval -f web.filter --outbound --link ip \
    --hex '4500 0028 0001 4000 4006 0000 c0a80102 5db8d70e
           9c40 01bb 00000001 00000000 5002 ffff 0000 0000'
match
$ echo $?
0
```

Without `--outbound` the packet counts as inbound, and the filter does not match (exit code 1).
Exit code 2 means the filter has an error.

## Next steps

- The [overview](../filters/overview.md) of the filter language.
- The [field reference](../reference/fields.md).
- The [command-line reference](../reference/cli.md).
