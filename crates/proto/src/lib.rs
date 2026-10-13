//! Zero-copy packet parsing and checksums for [Avulse].
//!
//! [`Packet::parse`] reads Ethernet (with up to two VLAN tags), ARP, IPv4, IPv6 (walking extension
//! headers), TCP, UDP, ICMP and ICMPv6, and gives typed views of each header:
//!
//! ```
//! use avulse_proto::{Link, Packet, Tcp};
//!
//! // Ethernet + IPv4 + TCP SYN from 10.0.0.1:40000 to 192.0.2.7:443.
//! let frame = [
//!     0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x08, 0x00, // Ethernet
//!     0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 192, 0, 2, 7, // IPv4
//!     0x9c, 0x40, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0, // TCP
//! ];
//! let pkt = Packet::parse(&frame, Link::Ethernet);
//! assert_eq!(pkt.ethertype(), Some(avulse_proto::ethertype::IPV4));
//! let tcp = pkt.tcp().unwrap();
//! assert_eq!(tcp.dst_port(), 443);
//! assert!(tcp.has(Tcp::SYN) && !tcp.has(Tcp::ACK));
//! assert!(pkt.payload().is_empty());
//! ```
//!
//! # Guarantees
//!
//! - **Parsing never fails, allocates or panics**, whatever the input. It stops at the first
//!   header that is truncated, malformed or of an unknown type: that header is absent and the rest
//!   of the buffer becomes the [`payload`](Packet::payload).
//! - **Zero-copy.** Header views borrow the buffer; [`Packet`] stores offsets into it.
//! - **`no_std`, no `alloc`, no `unsafe`.** The same code runs in user space, in the Windows driver
//!   and in the macOS system extension.
//!
//! Only the outermost headers are read: the datagram quoted by an ICMP error is payload, and IP
//! fragments are not reassembled.
//!
//! [`checksum::recalculate`] fixes the IPv4, TCP, UDP, ICMP and ICMPv6 checksums after a packet
//! is modified.
//!
//! [Avulse]: https://ffalcinelli.github.io/avulse/
#![no_std]
#![forbid(unsafe_code)]
#![doc(html_logo_url = "https://ffalcinelli.github.io/avulse/favicon.svg")]
#![doc(html_favicon_url = "https://ffalcinelli.github.io/avulse/favicon.svg")]

pub mod checksum;
mod headers;
mod packet;

pub use headers::*;
pub use packet::*;

#[cfg(test)]
mod tests;
