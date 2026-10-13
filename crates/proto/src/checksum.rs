//! Internet checksums (RFC 1071).
//!
//! After changing a packet, call [`recalculate`] to fix every checksum it carries:
//!
//! ```
//! use avulse_proto::checksum::{self, Updated};
//! use avulse_proto::{Link, Packet};
//!
//! // IPv4 + UDP from 10.0.0.1:5353 to 10.0.0.2:53, both checksums zero.
//! let mut bytes = [
//!     0x45, 0, 0, 30, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, //
//!     0x14, 0xe9, 0, 53, 0, 10, 0, 0, //
//!     0xab, 0xcd,
//! ];
//! let updated = checksum::recalculate(&mut bytes, Link::Ip);
//! assert_eq!(updated, Updated { ipv4: true, udp: true, ..Updated::default() });
//!
//! let pkt = Packet::parse(&bytes, Link::Ip);
//! let ip = pkt.ipv4().unwrap();
//! assert_eq!(checksum::ipv4_header(ip.bytes()), ip.checksum());
//! ```

use crate::headers::ip_proto;
use crate::packet::{Link, Network, Packet, Transport};

/// Adds `data` to a running one's-complement sum.
///
/// Start with `acc = 0`, chain calls for the pieces, then [`finish`]. An odd-length `data` is
/// padded with a zero byte, so only the last piece may have an odd length.
pub fn sum(data: &[u8], mut acc: u64) -> u64 {
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        acc += u16::from_be_bytes(*w) as u64;
    }
    if let [last] = rest {
        acc += (*last as u64) << 8;
    }
    acc
}

/// Folds a running sum into the final 16-bit checksum.
pub fn finish(mut acc: u64) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// Checksum of an IPv4 header, ignoring the value in its checksum field.
///
/// # Panics
///
/// If `header` is shorter than 20 bytes. [`Ipv4::bytes`](crate::Ipv4::bytes) never is.
pub fn ipv4_header(header: &[u8]) -> u16 {
    finish(sum(&header[12..], sum(&header[..10], 0)))
}

/// Which checksums [`recalculate`] updated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Updated {
    /// The IPv4 header checksum.
    pub ipv4: bool,
    /// The TCP checksum.
    pub tcp: bool,
    /// The UDP checksum.
    pub udp: bool,
    /// The ICMP checksum.
    pub icmp: bool,
    /// The ICMPv6 checksum.
    pub icmpv6: bool,
}

#[derive(Clone, Copy)]
enum Pseudo {
    V4([u8; 4], [u8; 4]),
    V6([u8; 16], [u8; 16]),
}

impl Pseudo {
    fn sum(&self, proto: u8, len: usize) -> u64 {
        let acc = proto as u64 + len as u64;
        match self {
            Pseudo::V4(s, d) => sum(d, sum(s, acc)),
            Pseudo::V6(s, d) => sum(d, sum(s, acc)),
        }
    }
}

/// Recomputes every checksum of the packet in `buf`: the IPv4 header, and the TCP, UDP, ICMP or
/// ICMPv6 checksum of unfragmented packets.
///
/// IPv6 routing headers are not followed: the pseudo-header uses the destination in the fixed
/// header.
pub fn recalculate(buf: &mut [u8], link: Link) -> Updated {
    let mut updated = Updated::default();
    let (ipv4, l4) = {
        let p = Packet::parse(buf, link);
        let (ipv4, pseudo) = match p.network() {
            Network::Ipv4(ip) => (
                Some((p.l3_offset().unwrap_or(0), ip.header_len())),
                Pseudo::V4(ip.src().octets(), ip.dst().octets()),
            ),
            Network::Ipv6(ip) => (None, Pseudo::V6(ip.src().octets(), ip.dst().octets())),
            _ => return updated,
        };
        // (protocol, offset of the checksum field)
        let kind = match p.transport() {
            Transport::Tcp(_) => Some((ip_proto::TCP, 16)),
            Transport::Udp(_) => Some((ip_proto::UDP, 6)),
            Transport::Icmp(_) => Some((ip_proto::ICMP, 2)),
            Transport::Icmpv6(_) => Some((ip_proto::ICMPV6, 2)),
            Transport::None => None,
        };
        let l4 = match (kind, p.l4_offset()) {
            (Some(kind), Some(off)) if p.fragment().is_none() => {
                Some((kind, off, p.payload_range().end, pseudo))
            }
            _ => None,
        };
        (ipv4, l4)
    };
    if let Some((off, hl)) = ipv4 {
        let hdr = &mut buf[off..off + hl];
        let c = ipv4_header(hdr);
        hdr[10..12].copy_from_slice(&c.to_be_bytes());
        updated.ipv4 = true;
    }
    if let Some(((proto, field), off, end, pseudo)) = l4 {
        let seg = &mut buf[off..end];
        if seg.len() < field + 2 {
            return updated;
        }
        seg[field..field + 2].fill(0);
        let acc = if proto == ip_proto::ICMP {
            0
        } else {
            pseudo.sum(proto, seg.len())
        };
        let mut c = finish(sum(seg, acc));
        if proto == ip_proto::UDP && c == 0 {
            c = 0xffff;
        }
        seg[field..field + 2].copy_from_slice(&c.to_be_bytes());
        match proto {
            ip_proto::TCP => updated.tcp = true,
            ip_proto::UDP => updated.udp = true,
            ip_proto::ICMP => updated.icmp = true,
            _ => updated.icmpv6 = true,
        }
    }
    updated
}
