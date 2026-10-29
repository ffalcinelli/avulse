//! The address's layout, which the C ABI and the driver's IOCTLs depend on, and its accessors.

extern crate std;

use std::format;
use std::mem::{align_of, offset_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::vec;
use std::vec::Vec;

use avulse_filter::{Event, Layer};

use crate::*;

#[test]
fn address_layout() {
    assert_eq!(size_of::<Address>(), 216);
    assert_eq!(align_of::<Address>(), 8);
    assert_eq!(offset_of!(Address, timestamp), 0);
    assert_eq!(offset_of!(Address, version), 8);
    assert_eq!(offset_of!(Address, layer), 10);
    assert_eq!(offset_of!(Address, event), 11);
    assert_eq!(offset_of!(Address, outbound), 12);
    assert_eq!(offset_of!(Address, udp_checksum), 19);
    assert_eq!(offset_of!(Address, if_idx), 20);
    assert_eq!(offset_of!(Address, sub_if_idx), 24);
    assert_eq!(offset_of!(Address, vlan_tci), 28);
    assert_eq!(offset_of!(Address, vlan), 30);
    assert_eq!(offset_of!(Address, flow), 32);
    assert_eq!(offset_of!(Address, reflect), 128);
    assert_eq!(offset_of!(Address, context), 152);
    assert_eq!(size_of::<Flow>(), 96);
    assert_eq!(offset_of!(Flow, process_name), 64);
    assert_eq!(offset_of!(Flow, local_addr), 24);
    assert_eq!(offset_of!(Flow, protocol), 56);
    assert_eq!(size_of::<Reflect>(), 24);
    assert_eq!(offset_of!(Reflect, syntax), 23);
    assert_eq!(size_of::<Context>(), CONTEXT_LEN);
    assert_eq!(size_of::<Flags>(), 8);
}

#[test]
fn new_addresses() {
    let a = Address::new(Layer::Ethernet);
    assert_eq!(a.version(), ADDRESS_VERSION);
    assert_eq!(a.layer, Layer::Ethernet);
    assert_eq!(a.event, Event::Packet);
    assert!(!a.outbound && !a.ip_checksum && a.context.is_empty());
    assert_eq!(Address::default(), Address::new(Layer::Network));
    assert_eq!(format!("{:?}", a.context), "Context(empty)");
    let mut bytes = [0; CONTEXT_LEN];
    bytes[0] = 0xab;
    let c = Context::from_bytes(bytes);
    assert!(!c.is_empty());
    assert_eq!(c.as_bytes()[0], 0xab);
    assert!(format!("{c:?}").starts_with("Context(ab00"));
}

#[test]
fn flow_addresses() {
    let mut f = Flow::default();
    f.set_local_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    f.set_remote_addr(IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(
        f.local_addr,
        Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped().octets()
    );
    assert_eq!(f.local_addr(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(f.remote_addr(), IpAddr::V6(Ipv6Addr::LOCALHOST));

    // The process name: none, then one, then one cut at a character boundary.
    assert_eq!(f.process_name(), None);
    f.set_process_name("curl");
    assert_eq!(f.process_name(), Some("curl"));
    let long = format!("{}é", "x".repeat(31));
    f.set_process_name(&long);
    assert_eq!(f.process_name(), Some("x".repeat(31).as_str()));
    f.set_process_name(&"y".repeat(40));
    assert_eq!(f.process_name(), Some("y".repeat(32).as_str()));
}

/// An address with every field set.
fn full_address() -> Address {
    let mut a = Address::new(Layer::Socket);
    a.timestamp = -123_456_789;
    a.event = Event::SocketConnect;
    a.outbound = true;
    a.impostor = true;
    a.ipv6 = true;
    a.tcp_checksum = true;
    a.if_idx = 7;
    a.sub_if_idx = 0xdead_beef;
    a.vlan = true;
    a.vlan_tci = 0x2005;
    let f = &mut a.flow;
    f.endpoint_id = 0x1122_3344_5566_7788;
    f.parent_endpoint_id = 9;
    f.process_id = 4242;
    f.local_port = 40000;
    f.remote_port = 443;
    f.set_local_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    f.set_remote_addr(IpAddr::V6(Ipv6Addr::LOCALHOST));
    f.protocol = 6;
    f.set_process_name("curl");
    let r = &mut a.reflect;
    r.timestamp = 5;
    r.flags = Flags::SNIFF | Flags::RECV_ONLY;
    r.process_id = 1;
    r.priority = -30_000;
    r.layer = Layer::Flow;
    r.syntax = Syntax::WinDivert;
    a.context = Context::from_bytes([0x5a; CONTEXT_LEN]);
    a
}

#[test]
fn addresses_cross_the_driver_boundary() {
    use crate::ioctl::{ADDRESS_LEN, Malformed, decode_address, encode_address};
    assert_eq!(ADDRESS_LEN, size_of::<Address>());
    let a = full_address();
    let b = encode_address(&a);
    assert_eq!(decode_address(&b), Ok(a));
    // The fields are at their `repr(C)` offsets.
    assert_eq!(&b[offset_of!(Address, if_idx)..][..4], &7u32.to_le_bytes());
    assert_eq!(
        b[offset_of!(Address, reflect) + offset_of!(Reflect, syntax)],
        1
    );
    assert_eq!(&b[offset_of!(Address, context)..], &[0x5a; CONTEXT_LEN]);

    let bad = |at: usize, v: u8| {
        let mut b = b;
        b[at] = v;
        decode_address(&b)
    };
    assert_eq!(bad(8, 2), Err(Malformed::Version));
    assert_eq!(bad(10, 9), Err(Malformed::Value), "layer");
    assert_eq!(bad(11, 10), Err(Malformed::Value), "event");
    assert_eq!(bad(12, 2), Err(Malformed::Value), "bool");
    assert_eq!(bad(151, 7), Err(Malformed::Value), "syntax");
    assert_eq!(bad(143, 1), Err(Malformed::Value), "reflect flags");
    assert_eq!(decode_address(&b[..200]), Err(Malformed::Truncated));
}

#[test]
fn open_requests() {
    use crate::ioctl::{Malformed, OpenRequest};
    let req = OpenRequest {
        layer: Layer::Network,
        priority: -7,
        flags: Flags::SNIFF,
        program: &[1, 2, 3, 4, 5],
        interfaces: vec![3, 9],
        filter: "tcp.DstPort == 80",
        syntax: Syntax::WinDivert,
    };
    let b = req.encode();
    assert_eq!(b.len(), 32 + 8 + 5 + 17);
    assert_eq!(OpenRequest::decode(&b), Ok(req.clone()));
    assert_eq!(
        OpenRequest::decode(&b[..b.len() - 1]),
        Err(Malformed::Truncated)
    );
    let mut longer = b.clone();
    longer.push(0);
    assert_eq!(OpenRequest::decode(&longer), Err(Malformed::Value));
    let mut v2 = b.clone();
    v2[0] = 2;
    assert_eq!(OpenRequest::decode(&v2), Err(Malformed::Version));
    let mut flags = b;
    flags[8] = 0x40;
    assert_eq!(OpenRequest::decode(&flags), Err(Malformed::Value));
}

#[test]
fn records_and_small_requests() {
    use crate::ioctl::*;
    let (a, mut b) = (full_address(), Address::new(Layer::Network));
    b.outbound = true;
    let mut out = Vec::new();
    for (addr, data) in [(a, &b"hello"[..]), (b, &[][..]), (a, &[7; 8][..])] {
        Record { addr, data }.encode_into(&mut out);
    }
    assert_eq!(
        out.len(),
        Record::encoded_len(5) + Record::encoded_len(0) + Record::encoded_len(8)
    );
    let got: Vec<_> = Record::decode_all(&out).collect::<Result<_, _>>().unwrap();
    assert_eq!(got.len(), 3);
    assert_eq!((got[0].addr, got[0].data), (a, &b"hello"[..]));
    assert_eq!((got[1].addr, got[1].data), (b, &[][..]));
    assert_eq!(got[2].data, &[7; 8]);
    // A cut record is an error, and ends the iteration.
    let cut: Vec<_> = Record::decode_all(&out[..out.len() - 3]).collect();
    assert_eq!(cut.len(), 3);
    assert_eq!(cut[2], Err(Malformed::Truncated));

    let p = encode_set_param(Param::QueueTime, 4000);
    assert_eq!(decode_param(&p), Ok((Param::QueueTime, Some(4000))));
    assert_eq!(decode_param(&p[..4]), Ok((Param::QueueTime, None)));
    assert_eq!(decode_param(&[9, 0, 0, 0]), Err(Malformed::Value));

    let s = Stats {
        diverted: 3,
        queue_drops: 9,
        ..Stats::default()
    };
    assert_eq!(decode_stats(&encode_stats(&s)), Ok(s));
    assert_eq!(decode_stats(&[0; 63]), Err(Malformed::Truncated));
    // The codes are WinDivert-style CTL_CODEs: device FILE_DEVICE_NETWORK, read and write access.
    assert_eq!(OPEN >> 16, 0x12);
    assert_eq!((OPEN >> 14) & 3, 3);
    assert_eq!(RECV & 3, 2);
}

#[test]
fn ethernet_contexts() {
    use crate::ioctl::EthernetContext;
    let c = EthernetContext {
        if_idx: 7,
        flags: EthernetContext::VLAN_OFFLOADED | EthernetContext::LSO_V2,
        lso_mss: 1460,
    };
    let bytes = c.encode();
    assert_eq!(
        bytes.as_bytes()[..12],
        [0xe7, 5, 0, 0, 7, 0, 0, 0, 0xb4, 5, 0, 0]
    );
    assert_eq!(EthernetContext::decode(&bytes), Some(c));
    assert!(c.lso());
    assert_eq!(EthernetContext::decode(&Context::EMPTY), None);
    let mut other = *bytes.as_bytes();
    other[1] = 8;
    assert_eq!(EthernetContext::decode(&Context::from_bytes(other)), None);
    let mut other = *bytes.as_bytes();
    other[40] = 1;
    assert_eq!(EthernetContext::decode(&Context::from_bytes(other)), None);
}
