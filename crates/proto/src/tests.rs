extern crate std;

use std::vec;
use std::vec::Vec;

use crate::checksum::{self, Updated, finish, sum};
use crate::*;

const MAC_A: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const MAC_B: [u8; 6] = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

fn eth(et: u16, tags: &[(u16, u16)], payload: &[u8]) -> Vec<u8> {
    // dst, src, (TPID, TCI)*, EtherType, payload; outermost tag first.
    let mut v = [MAC_B, MAC_A].concat();
    for (tpid, tci) in tags {
        v.extend_from_slice(&tpid.to_be_bytes());
        v.extend_from_slice(&tci.to_be_bytes());
    }
    v.extend_from_slice(&et.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn ipv4(proto: u8, frag: u16, payload: &[u8]) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    let mut v = vec![0x45, 0x00];
    v.extend_from_slice(&total.to_be_bytes());
    v.extend_from_slice(&[0x12, 0x34]);
    v.extend_from_slice(&frag.to_be_bytes());
    v.extend_from_slice(&[64, proto, 0, 0, 10, 0, 0, 1, 192, 168, 1, 2]);
    v.extend_from_slice(payload);
    v
}

fn ipv6(next: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x60, 0x00, 0x00, 0x00];
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(&[next, 64]);
    v.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    v.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    v.extend_from_slice(payload);
    v
}

fn tcp(sport: u16, dport: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&sport.to_be_bytes());
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&1000u32.to_be_bytes());
    v.extend_from_slice(&2000u32.to_be_bytes());
    v.extend_from_slice(&((5u16 << 12) | flags).to_be_bytes());
    v.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
    v.extend_from_slice(payload);
    v
}

fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&sport.to_be_bytes());
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(payload);
    v
}

/// The one's-complement sum over a segment and its pseudo-header is 0 when the checksum is right.
fn l4_valid(p: &Packet<'_>) -> bool {
    let seg = &p.data()[p.l4_offset().unwrap()..p.payload_range().end];
    let (proto, src, dst): (u8, &[u8], &[u8]) = match p.network() {
        Network::Ipv4(ip) => (ip.protocol(), &ip.bytes()[12..16], &ip.bytes()[16..20]),
        Network::Ipv6(ip) => (
            p.ip_protocol().unwrap(),
            &ip.bytes()[8..24],
            &ip.bytes()[24..40],
        ),
        _ => unreachable!(),
    };
    let acc = if proto == ip_proto::ICMP {
        0
    } else {
        sum(dst, sum(src, proto as u64 + seg.len() as u64))
    };
    finish(sum(seg, acc)) == 0
}

#[test]
fn ipv4_header_checksum_known_vector() {
    // Example from RFC 1071 discussions / Wikipedia.
    let h = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00,
        0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];
    assert_eq!(checksum::ipv4_header(&h), 0xb861);
}

#[test]
fn ethernet_vlan_ipv4_tcp() {
    let frame = eth(
        ethertype::IPV4,
        &[(ethertype::VLAN, 0xa064)],
        &ipv4(
            ip_proto::TCP,
            0x4000,
            &tcp(51000, 443, Tcp::SYN | Tcp::ACK, b"hello"),
        ),
    );
    let p = Packet::parse(&frame, Link::Ethernet);
    let e = p.eth().unwrap();
    assert_eq!(e.dst(), MacAddr(MAC_B));
    assert_eq!(e.src(), MacAddr(MAC_A));
    assert_eq!(e.ethertype(), ethertype::VLAN);
    assert_eq!(p.vlans().len(), 1);
    let tag = p.vlans()[0];
    assert_eq!(
        (tag.priority(), tag.dei(), tag.id(), tag.ethertype),
        (5, false, 100, ethertype::IPV4)
    );
    assert_eq!(p.ethertype(), Some(ethertype::IPV4));
    let ip = p.ipv4().unwrap();
    assert_eq!(ip.src(), core::net::Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(ip.dst(), core::net::Ipv4Addr::new(192, 168, 1, 2));
    assert!(ip.dont_fragment() && !ip.is_fragment());
    assert_eq!(ip.flags(), 0b010);
    assert_eq!(p.l3_offset(), Some(18));
    let t = p.tcp().unwrap();
    assert_eq!(
        (t.src_port(), t.dst_port(), t.seq(), t.ack()),
        (51000, 443, 1000, 2000)
    );
    assert!(t.has(Tcp::SYN) && t.has(Tcp::ACK) && !t.has(Tcp::FIN));
    assert_eq!(t.flags(), 0x012);
    assert_eq!(p.l4_offset(), Some(38));
    assert_eq!(p.payload(), b"hello");
}

#[test]
fn qinq_two_tags() {
    let frame = eth(
        ethertype::IPV6,
        &[(ethertype::QINQ, 0x0007), (ethertype::VLAN, 0x1fff)],
        &ipv6(ip_proto::UDP, &udp(1, 2, b"x")),
    );
    let p = Packet::parse(&frame, Link::Ethernet);
    let ids: Vec<u16> = p.vlans().iter().map(|t| t.id()).collect();
    assert_eq!(ids, [7, 0xfff]);
    assert!(p.vlans()[1].dei());
    assert_eq!(p.vlans()[0].tpid, ethertype::QINQ);
    assert_eq!(p.udp().unwrap().dst_port(), 2);
    assert_eq!(p.payload(), b"x");
}

#[test]
fn arp_request() {
    let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 1];
    arp.extend_from_slice(&MAC_A);
    arp.extend_from_slice(&[10, 0, 0, 1]);
    arp.extend_from_slice(&[0; 6]);
    arp.extend_from_slice(&[10, 0, 0, 2]);
    let mut frame = eth(ethertype::ARP, &[], &arp);
    frame.resize(60, 0); // Ethernet padding
    let p = Packet::parse(&frame, Link::Ethernet);
    let a = p.arp().unwrap();
    assert_eq!(
        (a.hw_type(), a.proto_type(), a.opcode()),
        (1, ethertype::IPV4, 1)
    );
    assert_eq!(a.sender_mac(), Some(MacAddr(MAC_A)));
    assert_eq!(a.sender_ipv4(), Some(core::net::Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(a.target_ipv4(), Some(core::net::Ipv4Addr::new(10, 0, 0, 2)));
    assert!(p.payload().is_empty());
    assert!(p.ipv4().is_none() && p.tcp().is_none());
}

#[test]
fn ethernet_padding_is_not_payload() {
    let mut frame = eth(
        ethertype::IPV4,
        &[],
        &ipv4(ip_proto::UDP, 0, &udp(53, 5353, b"ab")),
    );
    frame.resize(64, 0xee);
    let p = Packet::parse(&frame, Link::Ethernet);
    assert_eq!(p.payload(), b"ab");
}

#[test]
fn ipv4_fragments() {
    let first = ipv4(ip_proto::UDP, 0x2000, &udp(1, 2, &[0; 16]));
    let p = Packet::parse(&first, Link::Ip);
    assert_eq!(
        p.fragment(),
        Some(Fragment {
            offset: 0,
            more: true,
            id: 0x1234
        })
    );
    assert!(
        p.udp().is_some(),
        "the first fragment carries the UDP header"
    );

    let later = ipv4(ip_proto::UDP, 0x0003, &[1, 2, 3, 4, 5, 6, 7, 8]);
    let p = Packet::parse(&later, Link::Ip);
    assert_eq!(
        p.fragment(),
        Some(Fragment {
            offset: 3,
            more: false,
            id: 0x1234
        })
    );
    assert!(
        p.udp().is_none(),
        "later fragments have no transport header"
    );
    assert_eq!(p.ip_protocol(), Some(ip_proto::UDP));
    assert_eq!(p.payload(), &[1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn ipv6_extension_headers_and_fragment() {
    // Hop-by-hop (8 bytes) -> fragment (offset 0, more) -> TCP.
    let mut ext = vec![ip_proto::IPV6_FRAG, 0, 1, 4, 0, 0, 0, 0];
    ext.extend_from_slice(&[ip_proto::TCP, 0, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef]);
    ext.extend_from_slice(&tcp(1, 80, Tcp::SYN, b""));
    let pkt = ipv6(ip_proto::HOPOPT, &ext);
    let p = Packet::parse(&pkt, Link::Ip);
    assert_eq!(p.ip_protocol(), Some(ip_proto::TCP));
    assert_eq!(
        p.fragment(),
        Some(Fragment {
            offset: 0,
            more: true,
            id: 0xdeadbeef
        })
    );
    assert_eq!(p.tcp().unwrap().dst_port(), 80);
    assert_eq!(p.l4_offset(), Some(56));

    // Same chain with a non-zero offset: no transport.
    let mut ext = vec![ip_proto::UDP, 0, 0x00, 0x10, 0, 0, 0, 1];
    ext.extend_from_slice(&[9; 8]);
    let pkt = ipv6(ip_proto::IPV6_FRAG, &ext);
    let p = Packet::parse(&pkt, Link::Ip);
    assert_eq!(p.fragment().map(|f| (f.offset, f.more)), Some((2, false)));
    assert!(p.udp().is_none());
    assert_eq!(p.payload(), &[9; 8]);
}

#[test]
fn icmp_echo() {
    let msg = [8, 0, 0, 0, 0x12, 0x34, 0x00, 0x07, b'p', b'i', b'n', b'g'];
    let pkt = ipv4(ip_proto::ICMP, 0, &msg);
    let p = Packet::parse(&pkt, Link::Ip);
    let i = p.icmp().unwrap();
    assert_eq!(
        (i.icmp_type(), i.code(), i.ident(), i.seq()),
        (8, 0, Some(0x1234), Some(7))
    );
    assert_eq!(p.payload(), b"ping");

    let unreachable = [3, 1, 0, 0, 0, 0, 0, 0];
    let pkt = ipv4(ip_proto::ICMP, 0, &unreachable);
    assert_eq!(Packet::parse(&pkt, Link::Ip).icmp().unwrap().ident(), None);
}

#[test]
fn recalculate_fixes_every_checksum() {
    let mut frame = eth(
        ethertype::IPV4,
        &[],
        &ipv4(
            ip_proto::TCP,
            0,
            &tcp(1234, 80, Tcp::PSH | Tcp::ACK, b"GET /"),
        ),
    );
    let u = checksum::recalculate(&mut frame, Link::Ethernet);
    assert!(u.ipv4 && u.tcp);
    let p = Packet::parse(&frame, Link::Ethernet);
    assert_eq!(finish(sum(p.ipv4().unwrap().bytes(), 0)), 0);
    assert!(l4_valid(&p));

    let mut pkt = ipv6(ip_proto::UDP, &udp(5353, 5353, b"odd"));
    assert!(checksum::recalculate(&mut pkt, Link::Ip).udp);
    assert!(l4_valid(&Packet::parse(&pkt, Link::Ip)));

    let mut pkt = ipv6(ip_proto::ICMPV6, &[128, 0, 0, 0, 0, 1, 0, 2]);
    assert!(checksum::recalculate(&mut pkt, Link::Ip).icmpv6);
    assert!(l4_valid(&Packet::parse(&pkt, Link::Ip)));

    let mut pkt = ipv4(ip_proto::ICMP, 0, &[8, 0, 0, 0, 0, 1, 0, 1, 1, 2, 3]);
    assert!(checksum::recalculate(&mut pkt, Link::Ip).icmp);
    assert!(l4_valid(&Packet::parse(&pkt, Link::Ip)));
}

#[test]
fn verify_finds_correct_checksums() {
    let mut frame = eth(
        ethertype::IPV4,
        &[],
        &ipv4(ip_proto::TCP, 0, &tcp(1234, 80, Tcp::ACK, b"GET /")),
    );
    assert_eq!(checksum::verify(&frame, Link::Ethernet), Updated::default());
    let updated = checksum::recalculate(&mut frame, Link::Ethernet);
    assert_eq!(checksum::verify(&frame, Link::Ethernet), updated);
    let last = frame.len() - 1;
    frame[last] ^= 1;
    let v = checksum::verify(&frame, Link::Ethernet);
    assert!(v.ipv4 && !v.tcp);

    // A zero UDP checksum means none over IPv4, and is wrong over IPv6.
    let pkt = ipv4(ip_proto::UDP, 0, &udp(53, 53, b"x"));
    assert!(checksum::verify(&pkt, Link::Ip).udp);
    let pkt = ipv6(ip_proto::UDP, &udp(53, 53, b"x"));
    assert!(!checksum::verify(&pkt, Link::Ip).udp);
    for mut pkt in [
        ipv6(ip_proto::ICMPV6, &[128, 0, 0, 0, 0, 1, 0, 2]),
        ipv4(ip_proto::ICMP, 0, &[8, 0, 0, 0, 0, 1, 0, 1, 1, 2, 3]),
        ipv6(ip_proto::UDP, &udp(5353, 5353, b"odd")),
    ] {
        let updated = checksum::recalculate(&mut pkt, Link::Ip);
        assert_eq!(checksum::verify(&pkt, Link::Ip), updated);
    }
}

#[test]
fn tcp_large_send_checksums() {
    let seg = tcp(1234, 80, Tcp::ACK, &[7; 3000]);
    let mut frame = eth(ethertype::IPV4, &[], &ipv4(ip_proto::TCP, 0, &seg));
    assert_eq!(
        checksum::tcp_large_send(&mut frame, Link::Ethernet),
        Some(34)
    );
    // The full checksum is the complement of the partial one plus the length and the segment.
    let partial = u16::from_be_bytes([frame[50], frame[51]]);
    let mut full = frame.clone();
    checksum::recalculate(&mut full, Link::Ethernet);
    let mut s = partial as u64 + (frame.len() - 34) as u64;
    s = sum(&frame[34..50], s);
    s = sum(&frame[52..], s);
    assert_eq!(finish(s).to_be_bytes(), [full[50], full[51]]);

    let mut v6 = ipv6(ip_proto::TCP, &seg);
    assert_eq!(checksum::tcp_large_send(&mut v6, Link::Ip), Some(40));
    let mut not_tcp = ipv4(ip_proto::UDP, 0, &udp(53, 53, b"x"));
    let before = not_tcp.clone();
    assert_eq!(checksum::tcp_large_send(&mut not_tcp, Link::Ip), None);
    assert_eq!(not_tcp, before);
}

#[test]
fn recalculate_only_what_is_asked() {
    let tcp_pkt = ipv4(ip_proto::TCP, 0, &tcp(1234, 80, Tcp::ACK, b"GET /"));
    let mut pkt = tcp_pkt.clone();
    let none = checksum::recalculate_only(&mut pkt, Link::Ip, Updated::default());
    assert_eq!((none, &pkt), (Updated::default(), &tcp_pkt));
    let tcp_only = Updated {
        tcp: true,
        ..Updated::default()
    };
    assert_eq!(
        checksum::recalculate_only(&mut pkt, Link::Ip, tcp_only),
        tcp_only
    );
    assert_eq!(checksum::verify(&pkt, Link::Ip), tcp_only);
    // Asking for another protocol's checksum changes nothing.
    let mut pkt = tcp_pkt.clone();
    let udp_only = Updated {
        udp: true,
        ..Updated::default()
    };
    assert_eq!(
        checksum::recalculate_only(&mut pkt, Link::Ip, udp_only),
        Updated::default()
    );
    assert_eq!(pkt, tcp_pkt);
}

#[test]
fn recalculate_skips_fragments() {
    let mut pkt = ipv4(ip_proto::UDP, 0x2000, &udp(1, 2, &[0; 8]));
    let u = checksum::recalculate(&mut pkt, Link::Ip);
    assert!(u.ipv4 && !u.udp);

    // An IPv6 atomic fragment (offset 0, M=0) still carries the complete L4 segment.
    let seg = udp(5353, 5353, b"atomic");
    let mut frag = vec![ip_proto::UDP, 0, 0, 0, 0, 0, 0, 1];
    frag.extend_from_slice(&seg);
    let mut v6 = ipv6(ip_proto::IPV6_FRAG, &frag);
    let u = checksum::recalculate(&mut v6, Link::Ip);
    assert!(u.udp);
    assert!(checksum::verify(&v6, Link::Ip).udp);

    // Short or oversized slices passed to `ipv4_header` never panic and cap at IHL.
    assert_eq!(checksum::ipv4_header(&[]), 0xffff);
    assert_eq!(
        checksum::ipv4_header(&pkt[..20]),
        checksum::ipv4_header(&pkt)
    );
}

#[test]
fn every_truncation_parses() {
    let frames = [
        eth(
            ethertype::IPV4,
            &[(ethertype::VLAN, 1)],
            &ipv4(ip_proto::TCP, 0, &tcp(1, 2, Tcp::SYN, b"data")),
        ),
        eth(
            ethertype::IPV6,
            &[],
            &ipv6(
                ip_proto::HOPOPT,
                &[ip_proto::UDP, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 8, 0, 0],
            ),
        ),
    ];
    for frame in &frames {
        for n in 0..=frame.len() {
            let mut b = frame[..n].to_vec();
            let p = Packet::parse(&b, Link::Ethernet);
            let _ = (p.payload(), p.tcp(), p.udp(), p.vlans());
            checksum::recalculate(&mut b, Link::Ethernet);
            let p = Packet::parse(&frame[n.min(frame.len())..], Link::Ip);
            let _ = p.payload();
        }
    }
}

#[test]
fn random_bytes_never_panic() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..20_000 {
        let len = (next() % 128) as usize;
        let mut b: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        // Bias towards plausible headers.
        if len > 14 && next() % 2 == 0 {
            b[12..14].copy_from_slice(&[0x08, 0x00]);
            b[14] = 0x45;
        }
        for link in [Link::Ethernet, Link::Ip] {
            let p = Packet::parse(&b, link);
            let _ = (p.payload(), p.ip_protocol(), p.fragment());
            checksum::recalculate(&mut b, link);
        }
    }
}

/// The option walk agrees with Wireshark on the cases `tests/tshark.rs` in avulse-filter checks:
/// wrong lengths, overflow, EOL, unknown kinds.
#[test]
fn tcp_options() {
    use crate::tcp_option as k;
    let hdr = |opts: &[u8]| {
        let mut h = vec![0; 20];
        h.extend_from_slice(opts);
        h.resize(h.len().next_multiple_of(4), 0);
        h[12] = (h.len() as u8 / 4) << 4;
        h
    };
    let kinds = |opts: &[u8]| {
        let h = hdr(opts);
        Tcp::new(&h)
            .unwrap()
            .option_iter()
            .map(|o| o.kind())
            .collect::<Vec<_>>()
    };
    let full = hdr(&[
        2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 1, 3, 3, 7,
    ]);
    let t = Tcp::new(&full).unwrap();
    assert_eq!(
        kinds(&[
            2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 1, 3, 3, 7
        ]),
        [2, 4, 8, 1, 3]
    );
    assert_eq!(t.option(k::MSS).unwrap().mss(), Some(1460));
    assert_eq!(t.option(k::MSS).unwrap().offset(), 20);
    assert_eq!(t.option(k::SACK_PERM).unwrap().bytes(), [4, 2]);
    assert_eq!(t.option(k::TIMESTAMP).unwrap().timestamps(), Some((1, 2)));
    assert_eq!(t.option(k::WSCALE).unwrap().wscale_shift(), Some(7));
    // A wrong length: the option is there, its value is not.
    let h = hdr(&[2, 3, 5, 1]);
    let mss = Tcp::new(&h).unwrap().option(k::MSS).unwrap();
    assert_eq!((mss.bytes().len(), mss.mss()), (3, None));
    assert_eq!(kinds(&[2, 3, 5, 1]), [2, 1]);
    // Past the end, or a length below 2: the walk stops.
    assert_eq!(kinds(&[1, 3, 10, 7]), [1]);
    assert_eq!(kinds(&[9, 1, 2, 4, 5, 0xb4]), [0u8; 0]);
    // Nothing after EOL; unknown kinds are skipped by their length.
    assert_eq!(kinds(&[1, 0, 2, 4, 5, 0xb4]), [1, 0]);
    assert_eq!(kinds(&[99, 4, 1, 2, 2, 4, 5, 0xb4]), [99, 2]);
    assert_eq!(kinds(&[]), [0u8; 0]);
}
