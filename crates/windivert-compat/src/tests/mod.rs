//! The address layout and conversions, and the helpers against WinDivert's own results
//! (`vectors.rs`, from `scripts/gen_compat_vectors.py`) and WinDivert's filter vectors.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use avulse::{Address, CONTEXT_LEN, Context, Event, Flags, Layer};

use crate::helpers::{self, Invalid};
use crate::{CONTEXT_KEPT, WdAddress};

#[rustfmt::skip]
mod vectors;

/// WinDivert's filter vectors, as the filter crate's tests have them.
#[path = "../../../filter/src/tests/windivert_vectors.rs"]
#[rustfmt::skip]
#[allow(dead_code)]
mod windivert_vectors;

fn word(a: &WdAddress, at: usize) -> u32 {
    u32::from_ne_bytes(a.data[at..at + 4].try_into().unwrap())
}

/// The bitfields and the union are where WinDivert's `WINDIVERT_ADDRESS` has them.
#[test]
fn layout() {
    assert_eq!(size_of::<WdAddress>(), 80);
    assert_eq!(std::mem::offset_of!(WdAddress, bits), 8);
    assert_eq!(std::mem::offset_of!(WdAddress, data), 16);

    let mut a = Address::new(Layer::NetworkForward);
    a.timestamp = -7;
    a.outbound = true;
    a.ipv6 = true;
    a.udp_checksum = true;
    a.if_idx = 3;
    a.sub_if_idx = 9;
    let w = WdAddress::from_avulse(&a);
    assert_eq!(w.timestamp, -7);
    assert_eq!(w.bits, 1 | 1 << 17 | 1 << 20 | 1 << 23);
    assert_eq!((word(&w, 0), word(&w, 4)), (3, 9));

    let mut a = Address::new(Layer::Socket);
    a.event = Event::SocketConnect;
    a.sniffed = true;
    let f = &mut a.flow;
    f.endpoint_id = 0x1122_3344_5566_7788;
    f.parent_endpoint_id = 5;
    f.process_id = 4242;
    f.set_local_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    f.set_remote_addr(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)));
    f.local_port = 40000;
    f.remote_port = 443;
    f.protocol = 6;
    let w = WdAddress::from_avulse(&a);
    assert_eq!(w.bits, 3 | 4 << 8 | 1 << 16);
    assert_eq!(&w.data[..8], &0x1122_3344_5566_7788u64.to_ne_bytes());
    assert_eq!(word(&w, 16), 4242);
    // Host-order words, least significant first: ::ffff:10.0.0.1.
    assert_eq!(
        [word(&w, 20), word(&w, 24), word(&w, 28), word(&w, 32)],
        [0x0a00_0001, 0xffff, 0, 0]
    );
    assert_eq!(
        [word(&w, 36), word(&w, 40), word(&w, 44), word(&w, 48)],
        [2, 0, 0, 0x2001_0db8]
    );
    assert_eq!(&w.data[52..57], &[0x40, 0x9c, 0xbb, 0x01, 6]);

    let mut a = Address::new(Layer::Reflect);
    a.event = Event::ReflectOpen;
    let r = &mut a.reflect;
    r.timestamp = 99;
    r.process_id = 7;
    r.layer = Layer::Flow;
    r.flags = Flags::SNIFF | Flags::RECV_ONLY;
    r.priority = -3;
    let w = WdAddress::from_avulse(&a);
    assert_eq!(&w.data[..8], &99i64.to_ne_bytes());
    assert_eq!((word(&w, 8), word(&w, 12)), (7, 2));
    assert_eq!(&w.data[16..24], &5u64.to_ne_bytes());
    assert_eq!(&w.data[24..26], &(-3i16).to_ne_bytes());
}

/// Every layer goes to WinDivert's address and back unchanged, the reinjection context included,
/// and an address from C keeps its union at the NETWORK layers.
#[test]
fn round_trips() {
    let mut ctx = [0u8; CONTEXT_LEN];
    for (i, b) in ctx[..CONTEXT_KEPT].iter_mut().enumerate() {
        *b = i as u8 + 1;
    }
    let mut net = Address::new(Layer::Network);
    net.timestamp = 123;
    net.loopback = true;
    net.impostor = true;
    net.ip_checksum = true;
    net.tcp_checksum = true;
    net.if_idx = 1;
    net.context = Context::from_bytes(ctx);
    let mut flow = Address::new(Layer::Flow);
    flow.event = Event::FlowDeleted;
    flow.flow.endpoint_id = 77;
    flow.flow.set_remote_addr(IpAddr::V6(Ipv6Addr::LOCALHOST));
    flow.flow.remote_port = 8080;
    flow.flow.protocol = 17;
    let mut reflect = Address::new(Layer::Reflect);
    reflect.event = Event::ReflectClose;
    reflect.reflect.layer = Layer::Socket;
    reflect.reflect.flags = Flags::RECV_ONLY;
    reflect.reflect.priority = 30000;
    for a in [net, flow, reflect] {
        assert_eq!(WdAddress::from_avulse(&a).to_avulse().unwrap(), a);
    }

    let mut w = WdAddress::default();
    for (i, b) in w.data.iter_mut().enumerate() {
        *b = !(i as u8);
    }
    assert_eq!(WdAddress::from_avulse(&w.to_avulse().unwrap()), w);
}

#[test]
fn bad_addresses() {
    let bad = |bits: u32| WdAddress {
        bits,
        ..WdAddress::default()
    };
    assert!(bad(5).to_avulse().is_err(), "ETHERNET");
    assert!(bad(9).to_avulse().is_err(), "an unknown layer");
    assert!(bad(10 << 8).to_avulse().is_err(), "an unknown event");
    let mut w = bad(4);
    w.data[12] = 9;
    assert!(w.to_avulse().is_err(), "an unknown reflected layer");
    let mut w = bad(4);
    w.data[16] = 0x80;
    assert!(w.to_avulse().is_err(), "unknown flags");
}

#[test]
fn hash_vectors() {
    for &(i, seed, want) in vectors::HASHES {
        let got = helpers::hash_packet(vectors::PACKETS[i], seed);
        assert_eq!(got, want, "packet {i}, seed {seed:#x}");
    }
}

#[test]
fn checksum_vectors() {
    for &(i, flags, ret, bits, diff) in vectors::CHECKSUMS {
        let mut p = vectors::PACKETS[i].to_vec();
        let (ok, set) = helpers::calc_checksums(&mut p, flags);
        let mut w = WdAddress::default();
        w.set_checksums(set.ip, set.tcp, set.udp);
        assert_eq!((ok, w.bits), (ret == 0, bits), "packet {i}, flags {flags}");
        let mut want = vectors::PACKETS[i].to_vec();
        for &(at, b) in diff {
            want[at] = b;
        }
        assert_eq!(p, want, "packet {i}, flags {flags}");
    }
}

/// The address `scripts/gen_compat_vectors.py` passes WinDivert: outbound, with this
/// timestamp, layer and IPv6 flag.
fn eval_address(timestamp: i64, layer: u8, ipv6: bool) -> WdAddress {
    WdAddress {
        timestamp,
        bits: u32::from(layer) | 1 << 17 | u32::from(ipv6) << 20,
        ..WdAddress::default()
    }
}

/// 1, 0 or `-EINVAL`, as `ebpfdivert_helper_eval_filter` returns.
fn eval(src: &str, packet: &[u8], addr: &WdAddress) -> i32 {
    let addr = addr.to_avulse().unwrap();
    match helpers::eval_filter(src, packet, &addr) {
        Ok(m) => i32::from(m),
        Err(Invalid::Filter(_) | Invalid::Argument(_)) => -22,
    }
}

/// The `random*` fields, and which packets and addresses WinDivert refuses.
#[test]
fn eval_vectors() {
    for &(src, i, ts, layer, ipv6, want) in vectors::EVALS {
        let packet = i.map_or(&[][..], |i| vectors::PACKETS[i]);
        let got = eval(src, packet, &eval_address(ts, layer, ipv6));
        assert_eq!(
            got, want,
            "{src} on packet {i:?} at {ts}, layer {layer}, ipv6 {ipv6}"
        );
    }
}

/// WinDivert's filter vectors (without `random*`) through `eval_filter`, at the NETWORK layer
/// and outbound, as WinDivert's tests run them.
#[test]
fn windivert_filter_vectors() {
    let mut ran = 0;
    for &(src, packet, want) in windivert_vectors::VECTORS {
        if src.contains("random") {
            continue;
        }
        let bytes = windivert_vectors::PACKETS[packet].1;
        let addr = eval_address(0, 0, bytes[0] >> 4 == 6);
        assert_eq!(eval(src, bytes, &addr), i32::from(want), "{src}");
        ran += 1;
    }
    assert!(ran > 200, "{ran}");
}

/// WinDivert's serialized filter objects (REFLECT's data), from WinDivert's own compiler.
#[test]
fn filter_objects() {
    for &(layer, src, want) in vectors::OBJECTS {
        let layer = Layer::try_from(layer).unwrap();
        let got = avulse_filter::Filter::windivert_object(src, layer).unwrap();
        assert_eq!(got, want, "{src} at {layer:?}");
    }
}

#[test]
fn filters_check_and_format() {
    assert!(helpers::check_filter("tcp.DstPort == 80", Layer::Network).is_ok());
    let e = helpers::check_filter("tcp.DstPort == ", Layer::Network).unwrap_err();
    assert_eq!(e.span.start, 15);
    assert!(helpers::check_filter("processId == 1", Layer::Network).is_err());
    assert_eq!(
        helpers::format_filter("tcp.DstPort==80||udp", Layer::Network).unwrap(),
        "tcp.DstPort == 80 or udp"
    );
}

#[cfg(target_os = "linux")]
mod exports;
