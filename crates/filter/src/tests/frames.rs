//! Frame builders shared by the unit tests and the tshark comparison.

use alloc::vec;
use alloc::vec::Vec;

use avulse_proto::{Tcp, ethertype, ip_proto};

pub(super) const MAC_A: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
pub(super) const MAC_B: [u8; 6] = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

/// An Ethernet frame. With two tags, the outer one is an 802.1ad tag (TPID 0x88a8).
pub(super) fn eth(et: u16, tags: &[u16], payload: &[u8]) -> Vec<u8> {
    let tagged: Vec<(u16, u16)> = tags
        .iter()
        .enumerate()
        .map(|(i, &tci)| {
            let tpid = if i == 0 && tags.len() > 1 {
                ethertype::QINQ
            } else {
                ethertype::VLAN
            };
            (tpid, tci)
        })
        .collect();
    eth_tpids(et, &tagged, payload)
}

/// An Ethernet frame with explicit `(TPID, TCI)` tags.
pub(super) fn eth_tpids(et: u16, tags: &[(u16, u16)], payload: &[u8]) -> Vec<u8> {
    let mut v = [MAC_B, MAC_A].concat();
    for (tpid, tci) in tags {
        v.extend_from_slice(&tpid.to_be_bytes());
        v.extend_from_slice(&tci.to_be_bytes());
    }
    v.extend_from_slice(&et.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// IPv4 header fields the builders vary.
#[derive(Clone, Copy)]
pub(super) struct V4<'a> {
    pub tos: u8,
    /// Flags and fragment offset, as on the wire.
    pub frag: u16,
    pub options: &'a [u8],
}

impl Default for V4<'_> {
    fn default() -> Self {
        V4 {
            tos: 0,
            frag: 0x4000,
            options: &[],
        }
    }
}

/// 10.0.0.1 -> 192.168.1.2
pub(super) fn ipv4(proto: u8, payload: &[u8]) -> Vec<u8> {
    ipv4_with(V4::default(), proto, payload)
}

pub(super) fn ipv4_with(h: V4<'_>, proto: u8, payload: &[u8]) -> Vec<u8> {
    let hl = 20 + h.options.len();
    let mut v = vec![0x40 | (hl / 4) as u8, h.tos];
    v.extend_from_slice(&((hl + payload.len()) as u16).to_be_bytes());
    v.extend_from_slice(&[0x12, 0x34]);
    v.extend_from_slice(&h.frag.to_be_bytes());
    v.extend_from_slice(&[64, proto, 0, 0, 10, 0, 0, 1, 192, 168, 1, 2]);
    v.extend_from_slice(h.options);
    v.extend_from_slice(payload);
    v
}

/// fe80::1 -> 2001:db8::2
pub(super) fn ipv6(next: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x60, 0, 0, 0];
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(&[
        next, 64, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);
    v.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    v.extend_from_slice(payload);
    v
}

/// An IPv6 Fragment extension header followed by `payload`.
pub(super) fn ipv6_frag(next: u8, offset: u16, more: bool, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![next, 0];
    v.extend_from_slice(&((offset << 3) | more as u16).to_be_bytes());
    v.extend_from_slice(&0xcafe_f00du32.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// A Hop-by-Hop options header (PadN only) followed by `payload`.
pub(super) fn ipv6_hbh(next: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![next, 0, 1, 4, 0, 0, 0, 0];
    v.extend_from_slice(payload);
    v
}

pub(super) fn tcp(sport: u16, dport: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
    tcp_with(sport, dport, flags, &[], payload)
}

pub(super) fn tcp_with(
    sport: u16,
    dport: u16,
    flags: u16,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let words = (5 + options.len() / 4) as u16;
    let mut v = Vec::new();
    v.extend_from_slice(&sport.to_be_bytes());
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2]);
    v.extend_from_slice(&((words << 12) | flags).to_be_bytes());
    v.extend_from_slice(&[0x10, 0x00, 0, 0, 0, 0]);
    v.extend_from_slice(options);
    v.extend_from_slice(payload);
    v
}

pub(super) fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&sport.to_be_bytes());
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(payload);
    v
}

/// An ICMP or ICMPv6 message: type, code, a zero checksum, the 4-byte rest of header, the body.
pub(super) fn icmp(ty: u8, code: u8, rest: [u8; 4], body: &[u8]) -> Vec<u8> {
    let mut v = vec![ty, code, 0, 0];
    v.extend_from_slice(&rest);
    v.extend_from_slice(body);
    v
}

pub(super) fn https_syn() -> Vec<u8> {
    eth(
        ethertype::IPV4,
        &[],
        &ipv4(ip_proto::TCP, &tcp(51000, 443, Tcp::SYN, b"")),
    )
}

pub(super) fn http_get() -> Vec<u8> {
    eth(
        ethertype::IPV4,
        &[100],
        &ipv4(
            ip_proto::TCP,
            &tcp(51000, 80, Tcp::PSH | Tcp::ACK, b"GET / HTTP/1.1\r\n"),
        ),
    )
}

pub(super) fn dns_query() -> Vec<u8> {
    eth(
        ethertype::IPV4,
        &[],
        &ipv4(ip_proto::UDP, &udp(5353, 53, b"\x12\x34\x01\x00")),
    )
}

pub(super) fn arp_request() -> Vec<u8> {
    let mut a = vec![0, 1, 8, 0, 6, 4, 0, 1];
    a.extend_from_slice(&MAC_A);
    a.extend_from_slice(&[10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 2]);
    eth(ethertype::ARP, &[], &a)
}

pub(super) fn v6_udp() -> Vec<u8> {
    eth(
        ethertype::IPV6,
        &[7, 0x1fff],
        &ipv6(ip_proto::UDP, &udp(546, 547, b"x")),
    )
}
