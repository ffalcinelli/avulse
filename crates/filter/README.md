# avulse-filter

The [Avulse](https://ffalcinelli.github.io/avulse/) filter language: Wireshark display filters,
restricted to fields that one packet determines, plus a few extensions (`inbound`, `outbound`,
`iface`, process and flow fields, `let` macros).

```rust
use avulse_filter::{Filter, Meta};
use avulse_proto::{Link, Packet};

let filter = Filter::compile("outbound and tcp.dstport in {80, 443}").unwrap();

// IPv4 + TCP SYN from 192.168.1.2:40000 to 93.184.215.14:443.
let bytes = [
    0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0, 192, 168, 1, 2, 93, 184, 215, 14, //
    0x9c, 0x40, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
];
let packet = Packet::parse(&bytes, Link::Ip);
assert!(filter.matches(&packet, &Meta { outbound: true, ..Meta::default() }));
```

- **Wireshark semantics.** A filter that Wireshark 4.6+ accepts and Avulse compiles selects the
  same packets. A test compares the two with `tshark` on every supported field; the
  [guide](https://ffalcinelli.github.io/avulse/guide/) lists the few intentional differences.
- **Helpful errors.** Diagnostics carry a source span and a "did you mean" hint.
- **Kernel-ready.** `no_std` with `alloc`, no `unsafe`. Evaluation does not allocate and never
  panics, so the same engine runs in user space and in kernel drivers.

## Features

- `regex`: the `matches` (`~`) operator, through `regex-automata`. It stays `no_std`, but only
  user space runs it.

## License

Dual-licensed under LGPL-3.0-or-later or GPL-2.0-or-later, at your option.
