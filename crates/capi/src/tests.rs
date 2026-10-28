//! The C ABI without privileges: layouts, conversions, errors and the filter helpers.

use std::ffi::CStr;
use std::mem::offset_of;
use std::net::{IpAddr, Ipv4Addr};

use super::*;

fn last_error() -> String {
    // SAFETY: a valid C string, until the next call on this thread.
    unsafe { CStr::from_ptr(avulse_last_error()) }
        .to_string_lossy()
        .into_owned()
}

#[test]
fn layouts_match_the_header_and_the_rust_types() {
    // The numbers of the asserts in `include/avulse.h`.
    assert_eq!(size_of::<avulse_address>(), 216);
    assert_eq!(size_of::<avulse_address>(), size_of::<Address>());
    assert_eq!(offset_of!(avulse_address, version), 8);
    assert_eq!(offset_of!(avulse_address, outbound), 12);
    assert_eq!(offset_of!(avulse_address, if_idx), 20);
    assert_eq!(offset_of!(avulse_address, vlan), 30);
    assert_eq!(offset_of!(avulse_address, flow), 32);
    assert_eq!(offset_of!(avulse_address, reflect), 128);
    assert_eq!(offset_of!(avulse_address, context), 152);
    assert_eq!(size_of::<avulse_flow>(), 96);
    assert_eq!(offset_of!(avulse_flow, local_addr), 24);
    assert_eq!(offset_of!(avulse_flow, protocol), 56);
    assert_eq!(offset_of!(avulse_flow, process_name), 64);
    assert_eq!(size_of::<avulse_reflect>(), 24);
    assert_eq!(offset_of!(avulse_reflect, layer), 22);
    // The Rust address has the same offsets.
    assert_eq!(offset_of!(Address, flow), 32);
    assert_eq!(offset_of!(Address, reflect), 128);
    assert_eq!(offset_of!(Address, context), 152);
    assert_eq!(size_of::<avulse_open_options>(), 32);
    assert_eq!(size_of::<avulse_stats>(), 64);
    assert_eq!(offset_of!(avulse_open_options, flags), 8);
    assert_eq!(offset_of!(avulse_open_options, interfaces), 16);
}

#[test]
fn addresses_round_trip() {
    let mut a = Address::new(Layer::Socket);
    a.timestamp = 1234;
    a.event = Event::SocketConnect;
    a.outbound = true;
    a.udp_checksum = true;
    a.if_idx = 7;
    a.vlan = true;
    a.vlan_tci = 0x2005;
    a.flow.process_id = 42;
    a.flow.remote_port = 443;
    a.flow
        .set_remote_addr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    a.flow.set_process_name("curl");
    a.reflect.flags = Flags::SNIFF;
    a.reflect.layer = Layer::Flow;
    a.reflect.syntax = avulse_rs::Syntax::WinDivert;
    a.context = Context::from_bytes([9; 64]);
    let c = avulse_address::from(&a);
    assert_eq!((c.layer, c.event, c.outbound, c.version), (3, 4, 1, 3));
    assert_eq!(c.reflect.syntax, 1);
    assert_eq!(&c.flow.process_name[..5], b"curl\0");
    assert_eq!(Address::try_from(&c).unwrap(), a);

    // What C may pass that Rust has no value for.
    let mut bad = c;
    bad.layer = 6;
    assert!(Address::try_from(&bad).is_err());
    let mut bad = c;
    bad.event = 10;
    assert!(Address::try_from(&bad).is_err());
    let mut bad = c;
    bad.reflect.syntax = 2;
    assert!(Address::try_from(&bad).is_err());
    let mut bad = c;
    bad.reflect.flags = 1 << 40;
    assert!(Address::try_from(&bad).is_err());
    // Any non-zero byte is true.
    let mut odd = c;
    odd.loopback = 7;
    assert!(Address::try_from(&odd).unwrap().loopback);

    let mut init = avulse_address::from(&Address::default());
    // SAFETY: a valid address.
    unsafe { avulse_address_init(&mut init, 5) };
    assert_eq!((init.layer, init.version), (5, 3));
}

#[test]
fn filter_helpers() {
    // SAFETY: valid C strings and buffers throughout.
    unsafe {
        assert_eq!(
            avulse_filter_check(c"tcp.port == 80".as_ptr(), 0, 0),
            AVULSE_OK
        );
        assert_eq!(
            avulse_filter_check(c"tcp.port ==".as_ptr(), 0, 0),
            AVULSE_E_FILTER
        );
        assert!(last_error().contains("tcp.port =="), "{}", last_error());
        assert_eq!(
            avulse_filter_check(c"tcp.DstPort == 80".as_ptr(), 1, 0),
            AVULSE_OK
        );
        assert_eq!(avulse_filter_check(c"tcp".as_ptr(), 2, 0), AVULSE_E_INVALID);
        assert_eq!(
            avulse_filter_check(std::ptr::null(), 0, 0),
            AVULSE_E_INVALID
        );

        let mut out = [0 as c_char; 64];
        let mut needed = 0;
        let f = c"tcp.port==80 && !udp".as_ptr();
        assert_eq!(
            avulse_filter_format(f, out.as_mut_ptr(), 64, &mut needed),
            AVULSE_OK
        );
        let s = CStr::from_ptr(out.as_ptr()).to_str().unwrap();
        assert_eq!(needed, s.len() + 1);
        assert_eq!(
            s,
            avulse_filter::parse("tcp.port==80 && !udp")
                .unwrap()
                .to_string()
        );
        assert_eq!(
            avulse_filter_format(f, out.as_mut_ptr(), 3, &mut needed),
            AVULSE_E_BUFFER
        );
        let w = c"tcp.DstPort == 80".as_ptr();
        assert_eq!(
            avulse_filter_convert(w, 0, out.as_mut_ptr(), 64, &mut needed),
            AVULSE_OK
        );
        assert!(
            CStr::from_ptr(out.as_ptr())
                .to_str()
                .unwrap()
                .contains("tcp.dstport")
        );

        // An IPv4 TCP packet to port 80, outbound.
        let mut p = vec![
            0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        p.extend([
            0x9c, 0x40, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 2, 0xff, 0xff, 0, 0, 0, 0,
        ]);
        let mut a = avulse_address::from(&Address::default());
        a.outbound = 1;
        let eval = |f: &CStr, a: *const avulse_address| {
            avulse_filter_eval(f.as_ptr(), p.as_ptr(), p.len(), false, a)
        };
        assert_eq!(eval(c"tcp.dstport == 80 and outbound", &a), 1);
        assert_eq!(eval(c"tcp.dstport == 80 and outbound", std::ptr::null()), 0);
        assert_eq!(eval(c"udp", &a), 0);
        assert_eq!(eval(c"udp ==", &a), AVULSE_E_FILTER);
        a.layer = 9;
        assert_eq!(eval(c"tcp", &a), AVULSE_E_INVALID);
    }
}

#[test]
fn opening_checks_arguments() {
    let mut h: *mut avulse_handle = std::ptr::null_mut();
    // SAFETY: valid C strings and pointers.
    unsafe {
        assert_eq!(
            avulse_open(c"tcp and (".as_ptr(), 0, 0, 0, &mut h),
            AVULSE_E_FILTER
        );
        assert!(last_error().contains("tcp and ("));
        assert_eq!(
            avulse_open(c"tcp".as_ptr(), 0, 31_000, 0, &mut h),
            AVULSE_E_INVALID
        );
        assert!(last_error().contains("priority"));
        assert_eq!(
            avulse_open(c"tcp".as_ptr(), 9, 0, 0, &mut h),
            AVULSE_E_INVALID
        );
        assert_eq!(
            avulse_open(c"tcp".as_ptr(), 0, 0, 1 << 40, &mut h),
            AVULSE_E_INVALID
        );
        assert_eq!(
            avulse_open(c"tcp".as_ptr(), 0, 0, 3, &mut h),
            AVULSE_E_INVALID
        );
        assert_eq!(
            avulse_open(c"tcp".as_ptr(), 0, 0, 0, std::ptr::null_mut()),
            AVULSE_E_INVALID
        );
        let small = avulse_open_options {
            size: 8,
            priority: 0,
            syntax: 0,
            flags: 0,
            interfaces: std::ptr::null(),
            interface_count: 0,
        };
        assert_eq!(
            avulse_open_ex(c"tcp".as_ptr(), 0, &small, &mut h),
            AVULSE_E_INVALID
        );
        assert!(h.is_null());
        assert_eq!(avulse_close(std::ptr::null_mut()), AVULSE_OK);
        assert_eq!(avulse_fd(std::ptr::null()), -1);
    }
    assert!(!last_error().is_empty());
    // SAFETY: a static C string.
    let v = unsafe { CStr::from_ptr(avulse_version()) };
    assert_eq!(v.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
}
