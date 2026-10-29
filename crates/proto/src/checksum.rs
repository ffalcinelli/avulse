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

/// Which checksums [`recalculate`] updated, or [`verify`] found correct.
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

/// Where a packet's checksums are.
struct Located {
    /// Offset and length of the IPv4 header.
    ipv4: Option<(usize, usize)>,
    /// The transport checksum: protocol, offset of the checksum field in the segment, the
    /// segment's range, and the pseudo-header.
    l4: Option<(u8, usize, core::ops::Range<usize>, Pseudo)>,
}

fn locate(buf: &[u8], link: Link) -> Located {
    let p = Packet::parse(buf, link);
    let (ipv4, pseudo) = match p.network() {
        Network::Ipv4(ip) => (
            Some((p.l3_offset().unwrap_or(0), ip.header_len())),
            Pseudo::V4(ip.src().octets(), ip.dst().octets()),
        ),
        Network::Ipv6(ip) => (None, Pseudo::V6(ip.src().octets(), ip.dst().octets())),
        _ => {
            return Located {
                ipv4: None,
                l4: None,
            };
        }
    };
    let kind = match p.transport() {
        Transport::Tcp(_) => Some((ip_proto::TCP, 16)),
        Transport::Udp(_) => Some((ip_proto::UDP, 6)),
        Transport::Icmp(_) => Some((ip_proto::ICMP, 2)),
        Transport::Icmpv6(_) => Some((ip_proto::ICMPV6, 2)),
        Transport::None => None,
    };
    let l4 = match (kind, p.l4_offset()) {
        (Some((proto, field)), Some(off)) if p.fragment().is_none() => {
            let end = p.payload_range().end;
            (end - off >= field + 2).then_some((proto, field, off..end, pseudo))
        }
        _ => None,
    };
    Located { ipv4, l4 }
}

/// The running sum of a transport segment with its pseudo-header (none for ICMP).
fn segment_sum(proto: u8, seg: &[u8], pseudo: &Pseudo) -> u64 {
    let acc = if proto == ip_proto::ICMP {
        0
    } else {
        pseudo.sum(proto, seg.len())
    };
    sum(seg, acc)
}

impl Updated {
    /// Every checksum.
    pub const ALL: Updated = Updated {
        ipv4: true,
        tcp: true,
        udp: true,
        icmp: true,
        icmpv6: true,
    };

    fn set(&mut self, proto: u8) {
        match proto {
            ip_proto::TCP => self.tcp = true,
            ip_proto::UDP => self.udp = true,
            ip_proto::ICMP => self.icmp = true,
            _ => self.icmpv6 = true,
        }
    }
}

/// Recomputes every checksum of the packet in `buf`: the IPv4 header, and the TCP, UDP, ICMP or
/// ICMPv6 checksum of unfragmented packets.
///
/// IPv6 routing headers are not followed: the pseudo-header uses the destination in the fixed
/// header.
pub fn recalculate(buf: &mut [u8], link: Link) -> Updated {
    recalculate_only(buf, link, Updated::ALL)
}

/// [`recalculate`], for the checksums set in `which` only; the others are left as they are.
///
/// ```
/// use avulse_proto::checksum::{self, Updated};
/// use avulse_proto::Link;
///
/// let mut bytes = [
///     0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, //
///     8, 0, 0, 0, 0, 1, 0, 1, // ICMP echo request
/// ];
/// let ip = Updated { ipv4: true, ..Updated::default() };
/// assert_eq!(checksum::recalculate_only(&mut bytes, Link::Ip, ip), ip);
/// let valid = checksum::verify(&bytes, Link::Ip);
/// assert!(valid.ipv4 && !valid.icmp);
/// ```
pub fn recalculate_only(buf: &mut [u8], link: Link, which: Updated) -> Updated {
    let mut updated = Updated::default();
    let Located { ipv4, l4 } = locate(buf, link);
    if let Some((off, hl)) = ipv4.filter(|_| which.ipv4) {
        let hdr = &mut buf[off..off + hl];
        let c = ipv4_header(hdr);
        hdr[10..12].copy_from_slice(&c.to_be_bytes());
        updated.ipv4 = true;
    }
    let mut wanted = Updated::default();
    if let Some((proto, ..)) = &l4 {
        wanted.set(*proto);
    }
    let l4 = l4.filter(|_| {
        (wanted.tcp && which.tcp)
            || (wanted.udp && which.udp)
            || (wanted.icmp && which.icmp)
            || (wanted.icmpv6 && which.icmpv6)
    });
    if let Some((proto, field, range, pseudo)) = l4 {
        let seg = &mut buf[range];
        seg[field..field + 2].fill(0);
        let mut c = finish(segment_sum(proto, seg, &pseudo));
        if proto == ip_proto::UDP && c == 0 {
            c = 0xffff;
        }
        seg[field..field + 2].copy_from_slice(&c.to_be_bytes());
        updated.set(proto);
    }
    updated
}

/// Writes the TCP checksum a large send (LSO, TSO) carries for the network card: the folded,
/// uncomplemented sum of the pseudo-header without its length. The card adds each segment's
/// length and bytes, and completes the checksum. Returns the TCP header's offset in `buf`, or
/// `None` (and changes nothing) for anything but an unfragmented TCP segment.
///
/// ```
/// use avulse_proto::checksum;
/// use avulse_proto::Link;
///
/// let mut bytes = [0u8; 40];
/// bytes[..20].copy_from_slice(&[0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]);
/// bytes[32] = 0x50; // data offset: 5 words
/// assert_eq!(checksum::tcp_large_send(&mut bytes, Link::Ip), Some(20));
/// // 10.0.0.1 + 10.0.0.2 + protocol 6
/// assert_eq!(bytes[36..38], [0x14, 0x09]);
/// ```
pub fn tcp_large_send(buf: &mut [u8], link: Link) -> Option<usize> {
    let Located { l4, .. } = locate(buf, link);
    let (proto, field, range, pseudo) = l4?;
    if proto != ip_proto::TCP {
        return None;
    }
    let mut acc = pseudo.sum(proto, 0);
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    let at = range.start;
    buf[at + field..at + field + 2].copy_from_slice(&(acc as u16).to_be_bytes());
    Some(at)
}

/// Which checksums of the packet in `buf` are present and correct, among those [`recalculate`]
/// computes. A UDP datagram over IPv4 with a zero checksum (none) counts as correct.
///
/// Packets captured on their way out often carry a partial checksum that the network card
/// completes (checksum offload); those are reported as incorrect.
///
/// ```
/// use avulse_proto::checksum;
/// use avulse_proto::Link;
///
/// let mut bytes = [
///     0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, //
///     8, 0, 0, 0, 0, 1, 0, 1, // ICMP echo request
/// ];
/// assert!(!checksum::verify(&bytes, Link::Ip).icmp);
/// checksum::recalculate(&mut bytes, Link::Ip);
/// let valid = checksum::verify(&bytes, Link::Ip);
/// assert!(valid.ipv4 && valid.icmp && !valid.tcp);
/// ```
pub fn verify(buf: &[u8], link: Link) -> Updated {
    let mut valid = Updated::default();
    let Located { ipv4, l4 } = locate(buf, link);
    if let Some((off, hl)) = ipv4 {
        valid.ipv4 = finish(sum(&buf[off..off + hl], 0)) == 0;
    }
    if let Some((proto, field, range, pseudo)) = l4 {
        let seg = &buf[range];
        let none = proto == ip_proto::UDP && ipv4.is_some() && seg[field..field + 2] == [0, 0];
        if none || finish(segment_sum(proto, seg, &pseudo)) == 0 {
            valid.set(proto);
        }
    }
    valid
}
