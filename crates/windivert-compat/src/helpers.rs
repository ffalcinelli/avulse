//! WinDivert's helper functions (`WinDivertHelper*`), with WinDivert's results: the packet hash,
//! checksum recalculation, and filters evaluated, checked and formatted in WinDivert's syntax.

use avulse::{Address, Layer};
use avulse_filter::{Diagnostic, Filter};
use avulse_proto::checksum;
use avulse_proto::{Link, Packet};

use crate::packet::{self, Transport, View};

/// `WINDIVERT_HELPER_NO_IP_CHECKSUM` and the others: what [`calc_checksums`] leaves alone.
pub mod no {
    /// The IPv4 header checksum.
    pub const IP: u64 = 1;
    /// The ICMP checksum.
    pub const ICMP: u64 = 2;
    /// The ICMPv6 checksum.
    pub const ICMPV6: u64 = 4;
    /// The TCP checksum.
    pub const TCP: u64 = 8;
    /// The UDP checksum.
    pub const UDP: u64 = 16;
}

/// Why a helper failed: WinDivert's `ERROR_INVALID_PARAMETER`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invalid {
    /// The filter does not compile.
    Filter(Diagnostic),
    /// The packet or the address is not what the call needs.
    Argument(&'static str),
}

const PRIME1: u64 = 11400714785074694791;
const PRIME2: u64 = 14029467366897019727;
const PRIME3: u64 = 1609587929392839161;
const PRIME4: u64 = 9650029242287828579;

/// The first 64 bits of SHA-2's initial values, which WinDivert pads with.
const PADDING: [u64; 9] = [
    0x428A2F9871374491,
    0xB5C0FBCFE9B5DBA5,
    0x3956C25B59F111F1,
    0x923F82A4AB1C5ED5,
    0xD807AA9812835B01,
    0x243185BE550C7DC3,
    0x72BE5D7480DEB1FE,
    0x9BDC06A7C19BF174,
    0xE49B69C1EFBE4786,
];

fn round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(PRIME2))
        .rotate_left(31)
        .wrapping_mul(PRIME1)
}

fn merge(acc: u64, val: u64) -> u64 {
    (acc ^ round(0, val))
        .wrapping_mul(PRIME1)
        .wrapping_add(PRIME4)
}

/// A little-endian word of `p` at `at`, as WinDivert reads headers on x86 and ARM64.
fn le64(p: &[u8], at: usize) -> u64 {
    let mut w = [0; 8];
    w.copy_from_slice(&p[at..at + 8]);
    u64::from_le_bytes(w)
}

fn le32(p: &[u8], at: usize) -> u64 {
    u64::from(u32::from_le_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]]))
}

/// WinDivert's hash (`WinDivertHashPacket`): xxHash64's rounds over the IP header and the first
/// bytes of the transport header, seeded with `seed`.
fn hash_view(p: &[u8], view: &View, seed: u64) -> u64 {
    let mut v = [0u64; 4];
    let v1 = seed ^ PADDING[0];
    let (mut v2, v3, v4, mut i);
    if view.ipv6 {
        v2 = le64(p, 0) ^ PADDING[1];
        v3 = le64(p, 8) ^ PADDING[2];
        v4 = le64(p, 16) ^ PADDING[3];
        v[0] = le64(p, 24) ^ PADDING[4];
        v[1] = le64(p, 32) ^ PADDING[5];
        i = 2;
    } else {
        v2 = le64(p, 0) ^ PADDING[1];
        v3 = le64(p, 8) ^ PADDING[2];
        v4 = le32(p, 16) ^ PADDING[3];
        i = 0;
    }
    match view.transport {
        Some((Transport::Tcp(_), at)) => {
            v[i] = le64(p, at) ^ PADDING[i + 4];
            i += 1;
            v[i] = le64(p, at + 8) ^ PADDING[i + 4];
            i += 1;
            if i <= 3 {
                v[i] = le32(p, at + 16) ^ PADDING[i + 4];
                i += 1;
            } else {
                v2 ^= le32(p, at + 16) << 32;
            }
        }
        Some((_, at)) => {
            v[i] = le64(p, at) ^ PADDING[i + 4];
            i += 1;
        }
        None => {}
    }
    while i <= 3 {
        v[i] = seed ^ PADDING[i + 4];
        i += 1;
    }
    let v1 = round(v[0], v1);
    let v2 = round(v[1], v2);
    let v3 = round(v[2], v3);
    let v4 = round(v[3], v4);
    let mut h = v1
        .rotate_left(1)
        .wrapping_add(v2.rotate_left(7))
        .wrapping_add(v3.rotate_left(12))
        .wrapping_add(v4.rotate_left(18));
    for x in [v1, v2, v3, v4] {
        h = merge(h, x);
    }
    h = h.wrapping_add(32);
    h ^= h >> 33;
    h = h.wrapping_mul(PRIME2);
    h ^= h >> 29;
    h = h.wrapping_mul(PRIME3);
    h ^ (h >> 32)
}

/// `WinDivertHelperHashPacket`: 0 for a packet WinDivert cannot parse or that is truncated.
pub fn hash_packet(packet: &[u8], seed: u64) -> u64 {
    match packet::parse(packet) {
        Some(view) if !view.truncated => hash_view(packet, &view, seed),
        _ => 0,
    }
}

/// The sum of an IPv4 or IPv6 pseudo-header for `protocol` and `len` bytes.
fn pseudo(p: &[u8], ipv6: bool, protocol: u8, len: usize) -> u64 {
    let acc = if ipv6 {
        checksum::sum(&(len as u32).to_be_bytes(), checksum::sum(&p[8..40], 0))
    } else {
        checksum::sum(&(len as u16).to_be_bytes(), checksum::sum(&p[12..20], 0))
    };
    checksum::sum(&[0, protocol], acc)
}

fn put16(p: &mut [u8], at: usize, v: u16) {
    p[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

/// The checksums [`calc_checksums`] computed, whose address bits WinDivert sets (`IPChecksum`,
/// `TCPChecksum`, `UDPChecksum`; ICMP has none).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Computed {
    /// The IPv4 header checksum.
    pub ip: bool,
    /// The TCP checksum.
    pub tcp: bool,
    /// The UDP checksum.
    pub udp: bool,
}

/// `WinDivertHelperCalcChecksums`: recomputes the checksums of `packet` in place, except those
/// `flags` ([`no`]) excludes. Returns whether WinDivert succeeds, and which checksums it computed.
/// It fails on a packet it cannot parse, or a transport checksum it cannot compute because the
/// packet is truncated or a fragment; the IPv4 checksum is computed anyway.
pub fn calc_checksums(packet: &mut [u8], flags: u64) -> (bool, Computed) {
    let mut set = Computed::default();
    let Some(view) = packet::parse(packet) else {
        return (false, set);
    };
    if !view.ipv6 && flags & no::IP == 0 {
        let header_len = usize::from(packet[0] & 0xf) * 4;
        put16(packet, 10, 0);
        let sum = checksum::finish(checksum::sum(&packet[..header_len], 0));
        put16(packet, 10, sum);
        set.ip = true;
    }
    let truncated = view.truncated || view.mf || view.frag_off != 0;
    let ok = match view.transport {
        Some((t, at)) => {
            let (skip, field, protocol, len) = match t {
                Transport::Icmp => (no::ICMP, 2, None, view.payload_len + 8),
                Transport::Icmpv6 => (no::ICMPV6, 2, Some(58), view.payload_len + 8),
                Transport::Tcp(h) => (no::TCP, 16, Some(6), view.payload_len + h),
                Transport::Udp => (no::UDP, 6, Some(17), view.payload_len + 8),
            };
            if flags & skip != 0 {
                true
            } else if truncated {
                false
            } else {
                put16(packet, at + field, 0);
                let acc = protocol.map_or(0, |pr| pseudo(packet, view.ipv6, pr, len));
                let mut sum = checksum::finish(checksum::sum(&packet[at..at + len], acc));
                if t == Transport::Udp && sum == 0 {
                    sum = 0xffff;
                }
                put16(packet, at + field, sum);
                set.tcp = matches!(t, Transport::Tcp(_));
                set.udp = t == Transport::Udp;
                true
            }
        }
        None => true,
    };
    (ok, set)
}

/// `WinDivertHelperCompileFilter`, as a check: the filter compiles at `layer`.
pub fn check_filter(src: &str, layer: Layer) -> Result<(), Diagnostic> {
    Filter::compile_windivert(src, layer).map(|_| ())
}

/// `WinDivertHelperFormatFilter`: the filter in canonical WinDivert syntax
/// ([`Filter::format_windivert`]).
pub fn format_filter(src: &str, layer: Layer) -> Result<String, Diagnostic> {
    Filter::format_windivert(src, layer)
}

/// `WinDivertHelperEvalFilter`: whether `packet`, received with `addr`, matches the WinDivert
/// filter `src`, compiled at the address's layer.
///
/// As in WinDivert, at the NETWORK layers the packet must parse as IP of the family the address
/// says (`ipv6`), and the `random*` fields read WinDivert's hash of the packet seeded with the
/// timestamp. At FLOW and SOCKET there is no packet: one with bytes is refused.
pub fn eval_filter(src: &str, packet: &[u8], addr: &Address) -> Result<bool, Invalid> {
    let mut meta = addr.meta();
    match addr.layer {
        Layer::Network | Layer::NetworkForward => {
            let view = packet::parse(packet).ok_or(Invalid::Argument("not an IP packet"))?;
            if view.ipv6 != addr.ipv6 {
                return Err(Invalid::Argument("the address's IPv6 flag does not match"));
            }
            meta.hash = hash_view(packet, &view, addr.timestamp as u64);
        }
        Layer::Flow | Layer::Socket if !packet.is_empty() => {
            return Err(Invalid::Argument("FLOW and SOCKET events have no packet"));
        }
        Layer::Flow | Layer::Socket | Layer::Reflect => {}
        Layer::Ethernet => return Err(Invalid::Argument("WinDivert has no ETHERNET layer")),
    }
    // WinDivert makes the hash non-zero.
    meta.hash |= 0xff00_0000_0000_0000;
    let filter = Filter::compile_windivert(src, addr.layer).map_err(Invalid::Filter)?;
    Ok(filter.matches(&Packet::parse(packet, Link::Ip), &meta))
}
