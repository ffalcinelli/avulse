# avulse-proto

Zero-copy packet parsing and checksums for [Avulse](https://ffalcinelli.github.io/avulse/):
Ethernet, up to two VLAN tags (QinQ), ARP, IPv4, IPv6 (extension headers and fragments), TCP,
UDP, ICMP and ICMPv6.

```rust
use avulse_proto::{Link, Packet};

// IPv4 + UDP from 10.0.0.1:5353 to 10.0.0.2:53, with a 2-byte payload.
let bytes = [
    0x45, 0, 0, 30, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, //
    0x14, 0xe9, 0, 53, 0, 10, 0, 0, //
    0xab, 0xcd,
];
let packet = Packet::parse(&bytes, Link::Ip);
assert_eq!(packet.udp().unwrap().dst_port(), 53);
assert_eq!(packet.payload(), [0xab, 0xcd]);
```

- **Parsing never fails, allocates or panics.** It stops at the first truncated or unknown
  header, and the rest of the buffer becomes the payload.
- **`no_std`, no `alloc`, no `unsafe`**, so the same code runs in kernel drivers.
- `checksum::recalculate` fixes the IPv4, TCP, UDP, ICMP and ICMPv6 checksums after an edit.

## License

Dual-licensed under LGPL-3.0-or-later or GPL-2.0-or-later, at your option.
