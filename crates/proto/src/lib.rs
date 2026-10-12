//! Zero-copy packet parsing and checksums for Avulse.
//!
//! [`Packet::parse`] reads Ethernet (with up to two VLAN tags), ARP, IPv4, IPv6 (walking extension
//! headers), TCP, UDP, ICMP and ICMPv6. It never allocates, never panics on any input, and stops
//! at the first header it cannot read. The crate is `no_std` so that the same code runs in the
//! Windows driver and the macOS system extension.

#![no_std]
#![forbid(unsafe_code)]

pub mod checksum;
mod headers;
mod packet;

pub use headers::*;
pub use packet::*;

#[cfg(test)]
mod tests;
