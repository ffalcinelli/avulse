# The filter language

An Avulse filter is a [Wireshark display filter](https://www.wireshark.org/docs/man-pages/wireshark-filter.html),
restricted to the fields that one packet determines, plus a few extensions for what a packet
diverter knows besides the bytes: direction, interface, process.

```filter
let lan = {10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16}
let web = tcp.port in {80, 443, 8000..8100}

outbound and ip.dst not in $lan and $web
```

## The compatibility rule

**A filter that compiles means what it means in Wireshark.** Avulse may reject more than
Wireshark, always with an error and a hint, but it never gives a different answer silently. The
[differences](wireshark.md) are few and listed. A test runs every supported field, and about 300
filters, through both `tshark` and Avulse over the same captures, and checks that they select the
same packets.

This makes filters easy to write and easy to test: you can try them on a capture in Wireshark
first. Existing WinDivert filters are accepted too, through a front-end for
[WinDivert's syntax](windivert.md) that gives WinDivert's results, and `avulse filter convert`
translates them.

## What a filter can see

A filter sees one packet, and only its outermost headers:

- Ethernet, up to two VLAN tags (802.1Q and 802.1ad), ARP;
- IPv4 and IPv6, with the IPv6 extension headers and the fragment headers;
- TCP (with the MSS, window scale, SACK permitted and timestamps options), UDP, ICMP and
  ICMPv6, and the payload after them;
- the [metadata](metadata.md) the backend provides: direction, loopback, interface, layer, event,
  process and flow endpoints.

It cannot see anything that needs state across packets (TCP stream analysis, reassembly, relative
sequence numbers) or an application-protocol dissector (`http`, `dns`, `tls`). Those fields are
rejected with a hint: match ports or payload bytes instead.

```filter,error
http.request.method == "GET"
```

```filter
tcp.flags.syn and tcp.options.mss_val < 1200 and not tcp.options.sack_perm
```

```filter
tcp.dstport == 80 and tcp.payload[0:4] == "GET "
```

## Where filters run

Filters compile to a typed intermediate representation. Today it runs in an interpreter that
never allocates (except for regular expressions), so that it can run inside a kernel. The planned
backends will run the same filter:

- on Linux, as eBPF generated at runtime, in the kernel;
- on Windows and macOS, as verified bytecode, in the driver and the system extension.

Regular expressions (`matches`) run in user space only: kernel backends pass the packets that
need them up to user space, and `avulse filter explain` says so.

## In this part

- [Syntax](syntax.md): operators, precedence, literals, comments and macros.
- [Fields and comparisons](comparisons.md): fields with several values, absent fields, quantifiers.
- [Values, sets and labels](values.md): addresses, ranges, CIDR, symbolic names.
- [Bytes, slices and layers](bytes.md): payload matching, `@field`, `&`, the layer operator.
- [Arithmetic and functions](arithmetic.md).
- [Regular expressions](regex.md).
- [Metadata fields](metadata.md): `outbound`, `iface`, `process.pid` and the others.
- [Differences from Wireshark](wireshark.md) and [evaluator limits](limits.md).
