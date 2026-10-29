//! `WinDivert.dll`'s exports against the driver, called as WinDivert's callers do, overlapped
//! requests and kernel32's waits included: what pydivert and jdivert rely on. It needs the driver
//! and Administrator rights, so it runs only with `AVULSE_DRIVER` set, in the `windows` VM
//! (drivers/windows/scripts/test.ps1):
//!
//! ```text
//! $env:AVULSE_DRIVER = "C:\build\avulse\drivers\windows\driver\target\release\avulse_package\avulse.sys"
//! cargo test -p avulse-windivert-compat --test windows -- --test-threads=1
//! ```

#![cfg(windows)]

use std::ffi::CString;
use std::net::UdpSocket;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;
use std::ptr::{null, null_mut};
use std::time::Duration;

use avulse::{Filter, Layer};
use avulse_windivert::WdAddress;
use avulse_windivert::windows::*;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED, FALSE,
    GetLastError, HANDLE, INVALID_HANDLE_VALUE, TRUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

/// `WINDIVERT_LAYER_*` and `WINDIVERT_FLAG_*`.
const NETWORK: u32 = 0;
const REFLECT: u32 = 4;
const SNIFF: u64 = 1;
const RECV_ONLY: u64 = 4;

fn enabled() -> bool {
    if std::env::var_os("AVULSE_DRIVER").is_some() {
        return true;
    }
    eprintln!("skipped: set AVULSE_DRIVER to avulse.sys and run as Administrator (in the VM)");
    false
}

fn open(filter: &str, layer: u32, priority: i16, flags: u64) -> HANDLE {
    let f = CString::new(filter).unwrap();
    // SAFETY: a NUL-terminated filter.
    let h = unsafe { WinDivertOpen(f.as_ptr(), layer, priority, flags) };
    // SAFETY: plain call.
    assert_ne!(h, INVALID_HANDLE_VALUE, "{filter}: error {}", unsafe {
        GetLastError()
    });
    h
}

fn close(h: HANDLE) {
    // SAFETY: an open handle.
    assert_eq!(unsafe { WinDivertClose(h) }, TRUE);
}

/// One synchronous receive.
fn recv(h: HANDLE) -> (Vec<u8>, WdAddress) {
    let mut buf = vec![0u8; 65_575];
    let mut a = WdAddress::default();
    let mut n = 0;
    // SAFETY: valid buffers.
    let ok = unsafe { WinDivertRecv(h, buf.as_mut_ptr().cast(), buf.len() as u32, &mut n, &mut a) };
    // SAFETY: plain call.
    assert_eq!(ok, TRUE, "WinDivertRecv: error {}", unsafe {
        GetLastError()
    });
    buf.truncate(n as usize);
    (buf, a)
}

fn send_udp(port: u16, payloads: &[&[u8]]) {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    for p in payloads {
        s.send_to(p, ("127.0.0.1", port)).unwrap();
    }
}

fn receiver(port: u16) -> UdpSocket {
    let s = UdpSocket::bind(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    s
}

/// The library exports WinDivert's API: every function pydivert and jdivert look up, and the
/// rest of `windivert.h`.
#[test]
fn exports() {
    if !enabled() {
        return;
    }
    // Tests do not build the DLL: build it, then look each name up.
    let dir = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let mut build = Command::new(env!("CARGO"));
    build.args(["build", "-p", "avulse-windivert-compat"]);
    if dir.ends_with("release") {
        build.arg("--release");
    }
    assert!(build.status().unwrap().success());
    let dll: PathBuf = dir.join("avulse_windivert.dll");
    let wide: Vec<u16> = dll.as_os_str().encode_wide().chain([0]).collect();
    // SAFETY: a NUL-terminated path.
    let module = unsafe { LoadLibraryW(wide.as_ptr()) };
    assert!(!module.is_null(), "{}", dll.display());
    for name in [
        "WinDivertOpen",
        "WinDivertRecv",
        "WinDivertRecvEx",
        "WinDivertSend",
        "WinDivertSendEx",
        "WinDivertShutdown",
        "WinDivertClose",
        "WinDivertSetParam",
        "WinDivertGetParam",
        "WinDivertHelperHashPacket",
        "WinDivertHelperParsePacket",
        "WinDivertHelperParseIPv4Address",
        "WinDivertHelperParseIPv6Address",
        "WinDivertHelperFormatIPv4Address",
        "WinDivertHelperFormatIPv6Address",
        "WinDivertHelperCalcChecksums",
        "WinDivertHelperDecrementTTL",
        "WinDivertHelperCompileFilter",
        "WinDivertHelperEvalFilter",
        "WinDivertHelperFormatFilter",
        "WinDivertHelperNtohs",
        "WinDivertHelperHtons",
        "WinDivertHelperNtohl",
        "WinDivertHelperHtonl",
        "WinDivertHelperNtohll",
        "WinDivertHelperHtonll",
        "WinDivertHelperNtohIPv6Address",
        "WinDivertHelperHtonIPv6Address",
        "WinDivertHelperNtohIpv6Address",
        "WinDivertHelperHtonIpv6Address",
    ] {
        let c = CString::new(name).unwrap();
        // SAFETY: a loaded module and a NUL-terminated name.
        assert!(
            unsafe { GetProcAddress(module, c.as_ptr().cast()) }.is_some(),
            "{name}"
        );
    }
}

/// A bad filter is ERROR_INVALID_PARAMETER, as WinDivert reports it.
#[test]
fn bad_filter() {
    if !enabled() {
        return;
    }
    let f = CString::new("tcp.DstPort ==").unwrap();
    // SAFETY: a NUL-terminated filter.
    let h = unsafe { WinDivertOpen(f.as_ptr(), NETWORK, 0, 0) };
    assert_eq!(h, INVALID_HANDLE_VALUE);
    // SAFETY: plain call.
    assert_eq!(unsafe { GetLastError() }, ERROR_INVALID_PARAMETER);
}

/// The driver is installed as the `WinDivert` service; a diverted loopback datagram comes with
/// WinDivert's address, and arrives once sent back, unchanged; the version parameters say 2.2.
#[test]
fn divert_and_send_back() {
    if !enabled() {
        return;
    }
    let rx = receiver(9510);
    let h = open("udp.DstPort == 9510", NETWORK, 0, 0);
    // Installed as WinDivert's DLL installs its driver, under WinDivert's service name.
    let sc = Command::new("sc.exe")
        .args(["query", "WinDivert"])
        .output()
        .unwrap();
    assert!(
        sc.status.success(),
        "{}",
        String::from_utf8_lossy(&sc.stdout)
    );
    let mut v = 0;
    // SAFETY: an open handle.
    unsafe {
        assert_eq!(WinDivertGetParam(h, 3, &mut v), TRUE);
        assert_eq!(v, 2);
        assert_eq!(WinDivertSetParam(h, 0, 512), TRUE);
        assert_eq!(WinDivertGetParam(h, 0, &mut v), TRUE);
        assert_eq!(v, 512);
    }
    send_udp(9510, &[b"hello"]);
    let (p, a) = recv(h);
    assert_eq!(a.layer(), 0);
    assert_eq!(p.len(), 28 + 5);
    assert_eq!(&p[28..], b"hello");
    // Outbound, loopback: bits 17 and 18.
    assert_eq!(a.bits & (3 << 17), 3 << 17, "{:#x}", a.bits);
    let mut sent = 0;
    // SAFETY: valid buffers.
    let ok = unsafe { WinDivertSend(h, p.as_ptr().cast(), p.len() as u32, &mut sent, &a) };
    assert_eq!((ok, sent as usize), (TRUE, p.len()));
    let mut got = [0; 16];
    assert_eq!(rx.recv(&mut got).unwrap(), 5);
    close(h);
}

/// An overlapped receive with nothing to receive stays pending; it is cancelled with
/// `CancelIoEx`, as pydivert's timeouts do, then one completes when a packet comes.
#[test]
fn overlapped_receive() {
    if !enabled() {
        return;
    }
    let h = open("udp.DstPort == 9511", NETWORK, 0, SNIFF);
    // SAFETY: an auto-reset event, unnamed.
    let event = unsafe { CreateEventW(null(), FALSE, FALSE, null()) };
    let mut buf = vec![0u8; 65_575];
    let mut a = WdAddress::default();
    let mut n = 0;
    // SAFETY: all zeros is a valid OVERLAPPED.
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = event;
    let start = |buf: &mut Vec<u8>, a: &mut WdAddress, n: &mut u32, ov: &mut OVERLAPPED| {
        // SAFETY: the buffers and `ov` outlive the request, which the test waits for.
        unsafe {
            WinDivertRecvEx(
                h,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                n,
                0,
                a,
                null_mut(),
                ov,
            )
        }
    };
    assert_eq!(start(&mut buf, &mut a, &mut n, &mut ov), FALSE);
    // SAFETY: plain calls on the request just started.
    unsafe {
        assert_eq!(GetLastError(), ERROR_IO_PENDING);
        assert_eq!(WaitForSingleObject(event, 200), WAIT_TIMEOUT);
        assert_eq!(CancelIoEx(h, &ov), TRUE);
        assert_eq!(GetOverlappedResult(h, &ov, &mut n, TRUE), FALSE);
        assert_eq!(GetLastError(), ERROR_OPERATION_ABORTED);
    }
    let r = start(&mut buf, &mut a, &mut n, &mut ov);
    // Read now: the socket calls below reset it.
    // SAFETY: plain call.
    let err = unsafe { GetLastError() };
    send_udp(9511, &[b"later"]);
    // SAFETY: as above.
    unsafe {
        if r == FALSE {
            assert_eq!(err, ERROR_IO_PENDING);
            assert_eq!(WaitForSingleObject(event, 3000), WAIT_OBJECT_0);
            assert_eq!(GetOverlappedResult(h, &ov, &mut n, FALSE), TRUE);
        }
        CloseHandle(event);
    }
    assert_eq!(n, 28 + 5);
    assert_eq!(&buf[28..33], b"later");
    // Sniffed: bit 16.
    assert_ne!(a.bits & (1 << 16), 0);
    close(h);
}

/// A batch receive returns the packets back to back, as many as there are addresses, and their
/// addresses' length.
#[test]
fn batch_receive() {
    if !enabled() {
        return;
    }
    let h = open("udp.DstPort == 9512", NETWORK, 0, SNIFF);
    send_udp(9512, &[b"one", b"two", b"three"]);
    std::thread::sleep(Duration::from_millis(200));
    let mut buf = vec![0u8; 65_575];
    let mut addrs = [WdAddress::default(); 4];
    let mut addr_len = (addrs.len() * 80) as u32;
    let mut n = 0;
    // SAFETY: valid buffers.
    let ok = unsafe {
        WinDivertRecvEx(
            h,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            &mut n,
            0,
            addrs.as_mut_ptr(),
            &mut addr_len,
            null_mut(),
        )
    };
    assert_eq!(ok, TRUE);
    assert_eq!(addr_len, 3 * 80);
    assert_eq!(n as usize, 3 * 28 + 3 + 3 + 5);
    let second = &buf[31..];
    assert_eq!(&second[28..31], b"two");
    assert!(addrs[..3].iter().all(|a| a.layer() == 0));
    close(h);
}

/// Closing a handle ends a receive another thread waits in.
#[test]
fn close_ends_a_waiting_receive() {
    if !enabled() {
        return;
    }
    let h = open("udp.DstPort == 9513", NETWORK, 0, SNIFF) as usize;
    let t = std::thread::spawn(move || {
        let mut buf = vec![0u8; 1500];
        let mut n = 0;
        // SAFETY: valid buffers; the handle stays open until the call returns.
        let ok = unsafe {
            WinDivertRecv(
                h as HANDLE,
                buf.as_mut_ptr().cast(),
                1500,
                &mut n,
                null_mut(),
            )
        };
        // SAFETY: plain call.
        (ok, unsafe { GetLastError() })
    });
    std::thread::sleep(Duration::from_millis(300));
    close(h as HANDLE);
    let (ok, _) = t.join().unwrap();
    assert_eq!(ok, FALSE);
}

/// REFLECT's data for a WinDivert filter is WinDivert's compiled object, as WinDivert sends it.
#[test]
fn reflect_object() {
    if !enabled() {
        return;
    }
    let other = open("tcp.DstPort == 443", NETWORK, 7, SNIFF);
    let r = open("true", REFLECT, 0, SNIFF | RECV_ONLY);
    let want = Filter::windivert_object("tcp.DstPort == 443", Layer::Network).unwrap() + "\0";
    let mut found = false;
    for _ in 0..16 {
        let (data, a) = recv(r);
        // REFLECT: the reflected handle's priority at byte 24 of the union.
        if a.layer() == 4 && i16::from_ne_bytes([a.data[24], a.data[25]]) == 7 {
            assert_eq!(data, want.as_bytes());
            found = true;
            break;
        }
    }
    assert!(found);
    close(other);
    close(r);
}

/// The helpers that do not need the driver, as WinDivert gives them.
#[test]
fn helpers() {
    let mut v4 = 0;
    let a = CString::new("10.0.0.1").unwrap();
    // SAFETY: valid strings and outputs.
    unsafe {
        assert_eq!(WinDivertHelperParseIPv4Address(a.as_ptr(), &mut v4), TRUE);
        assert_eq!(v4, 0x0a00_0001);
        let mut v6 = [0u32; 4];
        let a = CString::new("2001:db8::2").unwrap();
        assert_eq!(
            WinDivertHelperParseIPv6Address(a.as_ptr(), v6.as_mut_ptr()),
            TRUE
        );
        assert_eq!(v6, [2, 0, 0, 0x2001_0db8]);
        let mut s = [0i8; 64];
        assert_eq!(
            WinDivertHelperFormatIPv6Address(v6.as_ptr(), s.as_mut_ptr().cast(), 64),
            TRUE
        );
        let text = std::ffi::CStr::from_ptr(s.as_ptr().cast())
            .to_str()
            .unwrap();
        assert_eq!(text, "2001:db8::2");
        assert_eq!(WinDivertHelperNtohs(0x3412), 0x1234);
        let mut back = [0u32; 4];
        WinDivertHelperHtonIPv6Address(v6.as_ptr(), back.as_mut_ptr());
        let mut again = [0u32; 4];
        WinDivertHelperNtohIPv6Address(back.as_ptr(), again.as_mut_ptr());
        assert_eq!(again, v6);
    }
}
