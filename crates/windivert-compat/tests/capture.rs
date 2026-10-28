//! The `ebpfdivert_*` exports on real traffic over `lo`, called as C would: what pydivert and
//! jdivert rely on. It needs root, so it runs only with `AVULSE_BPF=1`, in the Vagrant VMs:
//!
//! ```text
//! cargo test -p avulse-windivert-compat --test capture --no-run   # prints the binary's path
//! vagrant ssh default -c "sudo AVULSE_BPF=1 /vagrant/target/debug/deps/capture-… --test-threads=1"
//! ```

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::ptr::{null, null_mut};
use std::thread;
use std::time::Duration;

use avulse_windivert::WdAddress;
use avulse_windivert::ebpfdivert::*;

const EINVAL: i32 = -libc::EINVAL;
/// `EBPFDIVERT_FLAG_*`.
const SNIFF: u64 = 1;
const RECV_ONLY: u64 = 4;
const SEND_ONLY: u64 = 8;

fn enabled() -> bool {
    if std::env::var_os("AVULSE_BPF").is_some() {
        return true;
    }
    eprintln!("skipped: set AVULSE_BPF=1 and run as root (in a VM) to capture packets");
    false
}

/// A handle, closed when dropped.
struct H(*mut ebpfdivert_handle);

// SAFETY: the library's handles are thread-safe.
unsafe impl Send for H {}
// SAFETY: as above.
unsafe impl Sync for H {}

impl H {
    /// Opens on `lo` only.
    fn open(filter: &str, layer: i32, flags: u64) -> H {
        let f = CString::new(filter).unwrap();
        let lo = CString::new("lo").unwrap();
        let names = [lo.as_ptr(), null()];
        let opts = ebpfdivert_open_opts {
            sz: size_of::<ebpfdivert_open_opts>(),
            ifnames: names.as_ptr(),
            ring_bytes: 0,
        };
        let mut h = null_mut();
        // SAFETY: valid arguments.
        let r = unsafe { ebpfdivert_open_ex(f.as_ptr(), layer, 0, flags, &opts, &mut h) };
        assert_eq!(r, 0, "opening `{filter}` at layer {layer}");
        H(h)
    }

    /// Receives with a timeout: the result, the packet and the address.
    fn recv(&self, len: u32, timeout_ms: i32) -> (i32, Vec<u8>, WdAddress) {
        let mut buf = vec![0u8; len as usize];
        let mut n = 0;
        let mut a = WdAddress::default();
        // SAFETY: valid arguments.
        let r = unsafe {
            ebpfdivert_recv(
                self.0,
                buf.as_mut_ptr().cast(),
                len,
                &mut n,
                &mut a,
                timeout_ms,
            )
        };
        buf.truncate(n as usize);
        (r, buf, a)
    }

    fn send(&self, p: &[u8], a: &WdAddress) -> i32 {
        let mut n = 0;
        // SAFETY: valid arguments.
        let r = unsafe { ebpfdivert_send(self.0, p.as_ptr().cast(), p.len() as u32, &mut n, a) };
        if r == 0 {
            assert_eq!(n as usize, p.len());
        }
        r
    }

    fn stats(&self) -> [u64; 8] {
        let mut s = [0; 8];
        // SAFETY: valid arguments.
        assert_eq!(
            unsafe { ebpfdivert_get_handle_stats(self.0, s.as_mut_ptr(), 8) },
            8
        );
        s
    }
}

impl Drop for H {
    fn drop(&mut self) {
        // SAFETY: open, and not used after this.
        assert_eq!(unsafe { ebpfdivert_close(self.0) }, 0);
    }
}

fn udp_to(port: u16, payloads: &[&[u8]]) {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    for p in payloads {
        s.send_to(p, ("127.0.0.1", port)).unwrap();
    }
}

fn receiver(port: u16) -> UdpSocket {
    let s = UdpSocket::bind(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    s
}

fn layer(a: &WdAddress) -> u32 {
    a.bits & 0xff
}

fn bit(a: &WdAddress, n: u32) -> bool {
    a.bits & (1 << n) != 0
}

/// Divert, the event descriptor, buffers too small or absent, and sending back, modified.
#[test]
fn divert_and_reinject() {
    if !enabled() {
        return;
    }
    let rx = receiver(9301);
    let h = H::open("udp.DstPort == 9301", 0, 0);
    assert_eq!(h.recv(2048, 0).0, -libc::EAGAIN);
    assert_eq!(h.recv(2048, 50).0, -libc::EAGAIN);

    udp_to(9301, &[b"hello"]);
    // SAFETY: open.
    let fd = unsafe { ebpfdivert_get_event_fd(h.0) };
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd.
    assert_eq!(unsafe { libc::poll(&mut p, 1, 2000) }, 1);
    let (r, pkt, a) = h.recv(2048, 2000);
    assert_eq!(r, 0);
    assert_eq!(pkt.len(), 33);
    assert_eq!(layer(&a), 0);
    assert!(
        bit(&a, 17) && bit(&a, 18),
        "outbound, loopback: {:#x}",
        a.bits
    );
    assert!(
        rx.recv(&mut [0; 16]).is_err(),
        "diverted: held until sent back"
    );

    // Modified: a different payload, the checksums recomputed by the helper.
    let mut m = pkt.clone();
    m[28..33].copy_from_slice(b"HELLO");
    let mut ma = a;
    // SAFETY: valid arguments.
    let r = unsafe { ebpfdivert_helper_calc_checksums(m.as_mut_ptr().cast(), 33, &mut ma, 0) };
    assert_eq!(r, 0);
    assert_eq!(h.send(&m, &ma), 0);
    let mut got = [0; 16];
    assert_eq!(rx.recv(&mut got).unwrap(), 5);
    assert_eq!(&got[..5], b"HELLO");

    // Too small: dropped, with its length. Without a buffer: the length and the address.
    udp_to(9301, &[b"12345", b"67890"]);
    let mut n = 0;
    let mut a = WdAddress::default();
    let mut small = [0u8; 10];
    // SAFETY: valid arguments.
    let r = unsafe { ebpfdivert_recv(h.0, small.as_mut_ptr().cast(), 10, &mut n, &mut a, 2000) };
    assert_eq!((r, n), (-libc::ENOBUFS, 33));
    // SAFETY: valid arguments.
    assert_eq!(
        unsafe { ebpfdivert_recv(h.0, null_mut(), 0, &mut n, &mut a, 2000) },
        0
    );
    assert_eq!((n, layer(&a)), (33, 0));
    assert!(rx.recv(&mut got).is_err());

    let s = h.stats();
    assert!(s[0] >= 3, "diverted: {s:?}");
    assert_eq!(s[1], 0, "dropped: {s:?}");
}

/// Batches: three datagrams in one receive, back to back, sent back in one call.
#[test]
fn batches() {
    if !enabled() {
        return;
    }
    let rx = receiver(9302);
    let h = H::open("udp.DstPort == 9302", 0, 0);
    udp_to(9302, &[b"a", b"bb", b"ccc"]);
    thread::sleep(Duration::from_millis(200));
    let mut buf = vec![0u8; 4096];
    let mut addrs = [WdAddress::default(); 4];
    let (mut len, mut count) = (0, 4);
    // SAFETY: valid arguments.
    let r = unsafe {
        ebpfdivert_recv_ex(
            h.0,
            buf.as_mut_ptr().cast(),
            4096,
            &mut len,
            addrs.as_mut_ptr(),
            &mut count,
            2000,
        )
    };
    assert_eq!((r, count, len), (0, 3, 29 + 30 + 31));
    let mut sent = 0;
    // SAFETY: valid arguments.
    let r = unsafe {
        ebpfdivert_send_ex(
            h.0,
            buf.as_ptr().cast(),
            len,
            &mut sent,
            addrs.as_ptr(),
            count,
        )
    };
    assert_eq!((r, sent), (0, len));
    let mut got = [0; 16];
    for want in [&b"a"[..], b"bb", b"ccc"] {
        let n = rx.recv(&mut got).unwrap();
        assert_eq!(&got[..n], want);
    }
    // SAFETY: a zero count is refused.
    let mut zero = 0;
    let r = unsafe { ebpfdivert_recv_ex(h.0, null_mut(), 0, null_mut(), null_mut(), &mut zero, 0) };
    assert_eq!(r, EINVAL);
}

/// Parameters, directions refused by the flags, shutdown, and closing while another thread
/// waits.
#[test]
fn params_flags_and_shutdown() {
    if !enabled() {
        return;
    }
    let h = H::open("udp.DstPort == 9303", 0, RECV_ONLY);
    let mut v = 0;
    // SAFETY: valid arguments.
    unsafe {
        assert_eq!(ebpfdivert_get_param(h.0, 0, &mut v), 0);
        assert_eq!(v, 4096);
        assert_eq!(ebpfdivert_set_param(h.0, 1, 4000), 0);
        assert_eq!(ebpfdivert_get_param(h.0, 1, &mut v), 0);
        assert_eq!(v, 4000);
        assert_eq!(ebpfdivert_set_param(h.0, 1, 1), EINVAL);
        assert_eq!(ebpfdivert_set_param(h.0, 9, 1), EINVAL);
        assert_eq!(ebpfdivert_get_param(h.0, 3, &mut v), 0);
        assert_eq!(v, 2);
        assert_eq!(ebpfdivert_get_param(h.0, 4, &mut v), 0);
        assert_eq!(v, 2);
    }
    assert_eq!(h.send(&[0x45; 20], &WdAddress::default()), -libc::EPERM);

    udp_to(9303, &[b"queued"]);
    thread::sleep(Duration::from_millis(100));
    // SAFETY: open.
    assert_eq!(unsafe { ebpfdivert_shutdown(h.0, 1) }, 0);
    assert_eq!(h.recv(2048, 1000).0, 0, "what is queued is still delivered");
    assert_eq!(h.recv(2048, 1000).0, -libc::ESHUTDOWN);
    // SAFETY: open.
    assert_eq!(unsafe { ebpfdivert_shutdown(h.0, 0) }, EINVAL);
    drop(h);

    let s = H::open("false", 0, SEND_ONLY);
    assert_eq!(s.recv(2048, 0).0, -libc::EPERM);
    drop(s);

    // Closing wakes a receiver blocked in another thread.
    let h = H::open("udp.DstPort == 9304", 0, 0);
    let w = std::sync::Arc::new(h);
    let w2 = w.clone();
    let t = thread::spawn(move || w2.recv(2048, -1).0);
    thread::sleep(Duration::from_millis(200));
    // SAFETY: open; the other thread's call is in progress, which close waits for.
    assert_eq!(unsafe { ebpfdivert_shutdown(w.0, 3) }, 0);
    assert_eq!(t.join().unwrap(), -libc::ESHUTDOWN);
}

/// FLOW and SOCKET addresses, through WinDivert's union.
#[test]
fn flow_and_socket() {
    if !enabled() {
        return;
    }
    let pid = std::process::id();
    let flows = H::open("udp and remotePort == 9305", 2, SNIFF | RECV_ONLY);
    let socket = H::open("event == CONNECT and remotePort == 9306", 3, RECV_ONLY);

    udp_to(9305, &[b"x"]);
    let (r, pkt, a) = flows.recv(0, 2000);
    assert_eq!((r, pkt.len(), layer(&a)), (0, 0, 2));
    assert_eq!((a.bits >> 8) & 0xff, 1, "FLOW_ESTABLISHED");
    let d = &a.data;
    assert_eq!(u32::from_ne_bytes(d[16..20].try_into().unwrap()), pid);
    assert_eq!(u16::from_ne_bytes([d[54], d[55]]), 9305);
    assert_eq!(d[56], 17);
    // 127.0.0.1 as ::ffff:127.0.0.1, in host-order words, least significant first.
    assert_eq!(
        u32::from_ne_bytes(d[36..40].try_into().unwrap()),
        0x7f00_0001
    );
    assert_eq!(u32::from_ne_bytes(d[40..44].try_into().unwrap()), 0xffff);

    let l = TcpListener::bind("127.0.0.1:9306").unwrap();
    let e = TcpStream::connect("127.0.0.1:9306").unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    drop(l);
    let (r, _, a) = socket.recv(0, 2000);
    assert_eq!(
        (r, layer(&a), (a.bits >> 8) & 0xff),
        (0, 3, 4),
        "SOCKET_CONNECT"
    );
    assert!(!bit(&a, 16), "not sniffed: refused");
    assert_eq!(u16::from_ne_bytes([a.data[54], a.data[55]]), 9306);

    // A filter on an empty event: eval_filter at the SOCKET layer, with the received address.
    let f =
        CString::new("remotePort == 9306 and processId == ".to_owned() + &pid.to_string()).unwrap();
    // SAFETY: valid arguments; no packet at this layer.
    assert_eq!(
        unsafe { ebpfdivert_helper_eval_filter(f.as_ptr(), null(), 0, &a) },
        1
    );
}

/// REFLECT reports the handles that open, with their filter as the data (in native syntax, where
/// WinDivert serializes its filter object).
#[test]
fn reflect() {
    if !enabled() {
        return;
    }
    let r = H::open("true", 4, SNIFF | RECV_ONLY);
    let h = H::open("udp.DstPort == 9307", 0, SNIFF);
    let mut found = false;
    for _ in 0..20 {
        let (rc, data, a) = r.recv(4096, 500);
        if rc != 0 {
            break;
        }
        assert_eq!(layer(&a), 4);
        if (a.bits >> 8) & 0xff == 8 && String::from_utf8_lossy(&data).contains("dstport == 9307") {
            assert_eq!(
                u32::from_ne_bytes(a.data[8..12].try_into().unwrap()),
                std::process::id()
            );
            assert_eq!(&a.data[16..24], &SNIFF.to_ne_bytes());
            found = true;
            break;
        }
    }
    assert!(found, "REFLECT_OPEN of the NETWORK handle");
    drop(h);
}

/// `ebpfdivert_open` sets errno.
#[test]
fn open_sets_errno() {
    if !enabled() {
        return;
    }
    let f = CString::new("tcp").unwrap();
    // SAFETY: valid arguments; SOCKET needs RECV_ONLY.
    let h = unsafe { ebpfdivert_open(f.as_ptr(), 3, 0, 0, null()) };
    assert!(h.is_null());
    // SAFETY: the thread's errno.
    assert_eq!(unsafe { *libc::__errno_location() }, libc::EINVAL);
}
