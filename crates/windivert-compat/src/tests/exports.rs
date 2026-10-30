//! The `ebpfdivert_*` exports, called as C would, for what needs no privileges.

use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr::{null, null_mut};

use super::{eval_address, vectors};
use crate::WdAddress;
use crate::ebpfdivert::*;

const EINVAL: i32 = -libc::EINVAL;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[test]
fn compile_filter() {
    let mut msg: *const c_char = null();
    let mut pos = 99;
    let f = c("tcp.DstPort == 80");
    // SAFETY: valid arguments.
    assert_eq!(
        unsafe { ebpfdivert_helper_compile_filter(f.as_ptr(), 0, &mut msg, &mut pos) },
        0
    );
    assert!(msg.is_null());
    assert_eq!(pos, 0);
    let f = c("tcp.DstPort == 80 and");
    // SAFETY: valid arguments.
    let r = unsafe { ebpfdivert_helper_compile_filter(f.as_ptr(), 0, &mut msg, &mut pos) };
    assert_eq!(r, EINVAL);
    // SAFETY: the message the call kept.
    assert_eq!(
        unsafe { CStr::from_ptr(msg) }.to_str(),
        Ok("unexpected end of filter")
    );
    assert_eq!(pos, 21);
    // A layer WinDivert does not have, and NULL out-pointers.
    let f = c("true");
    // SAFETY: valid arguments.
    unsafe {
        assert_eq!(
            ebpfdivert_helper_compile_filter(f.as_ptr(), 5, null_mut(), null_mut()),
            EINVAL
        );
        assert_eq!(
            ebpfdivert_helper_compile_filter(f.as_ptr(), 4, null_mut(), null_mut()),
            0
        );
        assert_eq!(
            ebpfdivert_helper_compile_filter(null(), 0, null_mut(), null_mut()),
            EINVAL
        );
    }
}

#[test]
fn eval_filter() {
    let p = vectors::PACKETS[0];
    let a = eval_address(0, 0, false);
    let eval = |f: &str, p: &[u8], a: *const WdAddress| {
        let f = c(f);
        // SAFETY: valid arguments.
        unsafe { ebpfdivert_helper_eval_filter(f.as_ptr(), p.as_ptr().cast(), p.len() as u32, a) }
    };
    assert_eq!(eval("icmp", p, &a), 1);
    assert_eq!(eval("tcp", p, &a), 0);
    assert_eq!(eval("tcp.Bogus", p, &a), EINVAL);
    assert_eq!(eval("icmp", p, null()), EINVAL);
    assert_eq!(eval("icmp", &p[..10], &a), EINVAL);
    assert_eq!(eval("true", &[], &eval_address(0, 2, false)), 1);
}

#[test]
fn format_filter() {
    let f = c("tcp.DstPort==80||udp");
    let mut buf = [0 as c_char; 64];
    // SAFETY: valid arguments.
    unsafe {
        assert_eq!(
            ebpfdivert_helper_format_filter(f.as_ptr(), 0, buf.as_mut_ptr(), 64),
            0
        );
        assert_eq!(
            CStr::from_ptr(buf.as_ptr()).to_str(),
            Ok("tcp.DstPort == 80 or udp")
        );
        assert_eq!(
            ebpfdivert_helper_format_filter(f.as_ptr(), 0, buf.as_mut_ptr(), 24),
            -libc::ENOBUFS
        );
        let bad = c("tcp.DstPort ==");
        assert_eq!(
            ebpfdivert_helper_format_filter(bad.as_ptr(), 0, buf.as_mut_ptr(), 64),
            EINVAL
        );
    }
}

#[test]
fn checksums_and_hash() {
    // The first vector with flags 0, through the export, with an address and without.
    let &(i, _, ret, bits, diff) = vectors::CHECKSUMS
        .iter()
        .find(|v| v.1 == 0 && v.2 == 0 && !v.4.is_empty())
        .unwrap();
    let mut want = vectors::PACKETS[i].to_vec();
    for &(at, b) in diff {
        want[at] = b;
    }
    for with_addr in [true, false] {
        let mut p = vectors::PACKETS[i].to_vec();
        let mut a = WdAddress::default();
        let ap: *mut WdAddress = if with_addr { &mut a } else { null_mut() };
        // SAFETY: valid arguments.
        let r = unsafe {
            ebpfdivert_helper_calc_checksums(p.as_mut_ptr().cast(), p.len() as u32, ap, 0)
        };
        assert_eq!((r, &p), (ret, &want));
        assert_eq!(a.bits, if with_addr { bits } else { 0 });
    }
    // SAFETY: valid arguments.
    unsafe {
        assert_eq!(
            ebpfdivert_helper_calc_checksums(null_mut(), 0, null_mut(), 0),
            EINVAL
        );
    }
    let &(i, seed, h) = &vectors::HASHES[4];
    let p = vectors::PACKETS[i];
    // SAFETY: valid arguments.
    assert_eq!(
        unsafe { ebpfdivert_helper_hash_packet(p.as_ptr().cast(), p.len() as u32, seed) },
        h
    );
    // SAFETY: NULL is a packet that does not parse.
    assert_eq!(unsafe { ebpfdivert_helper_hash_packet(null(), 0, 1) }, 0);
}

#[test]
fn strings() {
    // SAFETY: the strings the calls return.
    unsafe {
        assert_eq!(
            CStr::from_ptr(ebpfdivert_strerror(-libc::EINVAL)).to_str(),
            Ok("Invalid argument")
        );
        assert_eq!(
            CStr::from_ptr(ebpfdivert_strerror(libc::EPERM)).to_str(),
            Ok("Operation not permitted")
        );
        assert_eq!(
            CStr::from_ptr(ebpfdivert_version()).to_str(),
            Ok(env!("CARGO_PKG_VERSION"))
        );
    }
    ebpfdivert_set_print(null::<c_void>());
}

/// What fails before any privilege is needed: bad arguments, filters and handles.
#[test]
fn handle_arguments() {
    let f = c("tcp");
    let bad = c("tcp.DstPort ==");
    let mut h = null_mut();
    // SAFETY: valid arguments, or NULL where the call checks.
    unsafe {
        assert_eq!(
            ebpfdivert_open_ex(bad.as_ptr(), 0, 0, 0, null(), &mut h),
            EINVAL
        );
        assert!(h.is_null());
        assert_eq!(
            ebpfdivert_open_ex(f.as_ptr(), 5, 0, 0, null(), &mut h),
            EINVAL
        );
        assert_eq!(
            ebpfdivert_open_ex(f.as_ptr(), 0, 30001, 0, null(), &mut h),
            EINVAL
        );
        assert_eq!(
            ebpfdivert_open_ex(f.as_ptr(), 0, 0, 0x40, null(), &mut h),
            EINVAL
        );
        assert_eq!(
            ebpfdivert_open_ex(f.as_ptr(), 0, 0, 3, null(), &mut h),
            EINVAL
        );
        assert_eq!(
            ebpfdivert_open_ex(f.as_ptr(), 2, 0, 0, null(), &mut h),
            EINVAL
        );
        assert_eq!(
            ebpfdivert_open_ex(f.as_ptr(), 0, 0, 0, null(), null_mut()),
            EINVAL
        );
        assert!(ebpfdivert_open(bad.as_ptr(), 0, 0, 0, null()).is_null());
        assert_eq!(*libc::__errno_location(), libc::EINVAL);

        let mut v = 0;
        let mut n = 0;
        let mut a = WdAddress::default();
        assert_eq!(
            ebpfdivert_recv(null_mut(), null_mut(), 0, &mut n, &mut a, 0),
            EINVAL
        );
        assert_eq!(
            ebpfdivert_send(null_mut(), [0u8].as_ptr().cast(), 1, &mut n, &a),
            EINVAL
        );
        assert_eq!(ebpfdivert_get_param(null_mut(), 0, &mut v), EINVAL);
        assert_eq!(ebpfdivert_set_param(null_mut(), 0, 64), EINVAL);
        assert_eq!(ebpfdivert_shutdown(null_mut(), 3), EINVAL);
        assert_eq!(ebpfdivert_get_event_fd(null_mut()), EINVAL);
        assert_eq!(ebpfdivert_close(null_mut()), EINVAL);
        let mut stats = [0u64; 8];
        assert_eq!(
            ebpfdivert_get_handle_stats(null_mut(), stats.as_mut_ptr(), 8),
            EINVAL
        );
    }
}
