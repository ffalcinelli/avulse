//! The Windows backend against the driver, `avulse.sys`, in the `windows` VM. It needs
//! Administrator rights and the driver, so it runs only with `AVULSE_DRIVER` set to the path of
//! `avulse.sys`; the backend installs and starts the service from there
//! (drivers/windows/scripts/test.ps1 does all of it):
//!
//! ```text
//! $env:AVULSE_DRIVER = "C:\build\avulse\drivers\windows\driver\target\release\avulse_package\avulse.sys"
//! cargo test -p avulse --test capture_windows -- --test-threads=1
//! ```

#![cfg(target_os = "windows")]

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use avulse::{Error, Flags, Handle, Layer, MAX_PACKET_LEN, OpenOptions, Param, Shutdown};

fn enabled() -> bool {
    if std::env::var_os("AVULSE_DRIVER").is_some() {
        return true;
    }
    eprintln!("skipped: set AVULSE_DRIVER to avulse.sys and run as Administrator (in the VM)");
    false
}

fn sniff(filter: &str) -> Handle {
    Handle::open(filter, Layer::Network, 0, Flags::SNIFF)
        .unwrap_or_else(|e| panic!("opening `{filter}`: {e}"))
}

/// A receive times out, after about its timeout, also with a zero timeout.
#[test]
fn receive_times_out() {
    if !enabled() {
        return;
    }
    let h = sniff("udp.dstport == 9");
    let mut buf = vec![0; MAX_PACKET_LEN];
    let start = Instant::now();
    let r = h.recv_timeout(&mut buf, Duration::from_millis(200));
    assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
    assert!(
        start.elapsed() >= Duration::from_millis(150),
        "{:?}",
        start.elapsed()
    );
    let r = h.recv_timeout(&mut buf, Duration::ZERO);
    assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
    h.close().unwrap();
}

/// Shutting down wakes a receiver waiting in another thread, and later receives fail too.
#[test]
fn shutdown_ends_receives() {
    if !enabled() {
        return;
    }
    let h = sniff("udp.dstport == 9");
    std::thread::scope(|s| {
        let t = s.spawn(|| {
            let mut buf = vec![0; MAX_PACKET_LEN];
            h.recv(&mut buf).map(|(n, _)| n)
        });
        std::thread::sleep(Duration::from_millis(300));
        h.shutdown(Shutdown::Recv).unwrap();
        let r = t.join().unwrap();
        assert!(matches!(r, Err(Error::Shutdown)), "{r:?}");
    });
    let mut buf = vec![0; MAX_PACKET_LEN];
    let r = h.recv_timeout(&mut buf, Duration::from_secs(1));
    assert!(matches!(r, Err(Error::Shutdown)), "{r:?}");
}

/// Parameters reach the driver, counters come back, and a RECV_ONLY handle cannot send.
#[test]
fn parameters_counters_and_limits() {
    if !enabled() {
        return;
    }
    let h = OpenOptions::new()
        .flags(Flags::SNIFF)
        .open("udp.dstport == 9", Layer::Network)
        .unwrap();
    h.set_param(Param::QueueLength, 64).unwrap();
    assert_eq!(h.param(Param::QueueLength), 64);
    let s = h.stats().unwrap();
    assert_eq!((s.diverted, s.sniffed, s.queue_drops), (0, 0, 0));
    let r = Handle::open(
        "udp.dstport == 9",
        Layer::Network,
        0,
        Flags::SNIFF | Flags::RECV_ONLY,
    )
    .unwrap()
    .send(&[0x45; 20], &avulse::Address::new(Layer::Network));
    assert!(matches!(r, Err(Error::InvalidArgument(_))), "{r:?}");
    // The installed driver is used as it is.
    let h2 = Handle::open(
        "udp",
        Layer::NetworkForward,
        5,
        Flags::SNIFF | Flags::NO_INSTALL,
    );
    assert!(h2.is_ok(), "{:?}", h2.err());
}

/// A UDP socket listening on `addr`, with a short read timeout.
fn receiver(addr: &str) -> UdpSocket {
    let s = UdpSocket::bind(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    s
}

fn send_to(to: &str, payloads: &[&[u8]]) {
    let from = if to.starts_with('[') {
        "[::1]:0"
    } else {
        "127.0.0.1:0"
    };
    let s = UdpSocket::bind(from).unwrap();
    for p in payloads {
        s.send_to(p, to).unwrap();
    }
}

fn recv_one(h: &Handle) -> (Vec<u8>, avulse::Address) {
    let mut buf = vec![0; MAX_PACKET_LEN];
    let (n, a) = h
        .recv_timeout(&mut buf, Duration::from_secs(3))
        .unwrap_or_else(|e| panic!("recv: {e}"));
    buf.truncate(n);
    (buf, a)
}

/// A sniffing handle sees a loopback datagram once, outbound, and the datagram arrives.
#[test]
fn sniff_loopback() {
    if !enabled() {
        return;
    }
    for (bind, to, v6) in [
        ("127.0.0.1:9401", "127.0.0.1:9401", false),
        ("[::1]:9401", "[::1]:9401", true),
    ] {
        let rx = receiver(bind);
        let h = sniff("udp.dstport == 9401");
        send_to(to, &[b"hello"]);
        let (p, a) = recv_one(&h);
        assert_eq!(p.len(), if v6 { 48 } else { 28 } + 5, "{to}");
        assert_eq!(&p[p.len() - 5..], b"hello");
        assert!(a.outbound && a.loopback && a.sniffed, "{a:?}");
        assert_eq!(a.ipv6, v6);
        assert!(a.timestamp > 0);
        let mut got = [0; 16];
        assert_eq!(rx.recv(&mut got).unwrap(), 5, "the datagram still arrives");
        // Seen once: no inbound copy.
        let mut buf = vec![0; MAX_PACKET_LEN];
        let r = h.recv_timeout(&mut buf, Duration::from_millis(300));
        assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
        assert_eq!(h.stats().unwrap().sniffed, 1);
    }
}

/// A diverting handle takes the datagram: it never arrives (it cannot be sent back yet).
#[test]
fn divert_and_drop() {
    if !enabled() {
        return;
    }
    let rx = receiver("127.0.0.1:9402");
    let h = Handle::open("udp.dstport == 9402", Layer::Network, 0, Flags::NONE).unwrap();
    send_to("127.0.0.1:9402", &[b"held"]);
    let (p, a) = recv_one(&h);
    assert_eq!(&p[28..], b"held");
    assert!(!a.sniffed);
    let mut got = [0; 16];
    assert!(rx.recv(&mut got).is_err(), "diverted, so not delivered");
    assert_eq!(h.stats().unwrap().diverted, 1);
    drop(h);

    let d = Handle::open("udp.dstport == 9402", Layer::Network, 0, Flags::DROP).unwrap();
    send_to("127.0.0.1:9402", &[b"gone"]);
    assert!(rx.recv(&mut got).is_err(), "dropped");
    assert_eq!(d.stats().unwrap().dropped, 1);
    drop(d);
    send_to("127.0.0.1:9402", &[b"back"]);
    assert_eq!(
        rx.recv(&mut got).unwrap(),
        4,
        "delivered once the handles are closed"
    );
}

/// Filters that miss, and two sniffing handles at different priorities that both see a packet.
#[test]
fn filters_and_priorities() {
    if !enabled() {
        return;
    }
    let _rx = receiver("127.0.0.1:9403");
    let high = Handle::open("udp.dstport == 9403", Layer::Network, 100, Flags::SNIFF).unwrap();
    let low = Handle::open("udp", Layer::Network, -100, Flags::SNIFF).unwrap();
    let miss = sniff("udp.dstport == 9404 or tcp");
    send_to("127.0.0.1:9403", &[b"x"]);
    let (a, b) = (recv_one(&high), recv_one(&low));
    assert_eq!(a.0, b.0);
    let mut buf = vec![0; MAX_PACKET_LEN];
    let r = miss.recv_timeout(&mut buf, Duration::from_millis(300));
    assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
}

/// What is queued at shutdown is still received, then receives fail.
#[test]
fn shutdown_delivers_what_is_queued() {
    if !enabled() {
        return;
    }
    let _rx = receiver("127.0.0.1:9405");
    let h = sniff("udp.dstport == 9405");
    send_to("127.0.0.1:9405", &[b"one", b"two"]);
    std::thread::sleep(Duration::from_millis(300));
    h.shutdown(Shutdown::Recv).unwrap();
    let mut buf = vec![0; MAX_PACKET_LEN];
    for want in [&b"one"[..], b"two"] {
        let (n, _) = h.recv_timeout(&mut buf, Duration::from_secs(1)).unwrap();
        assert_eq!(&buf[28..n], want);
    }
    let r = h.recv_timeout(&mut buf, Duration::from_secs(1));
    assert!(matches!(r, Err(Error::Shutdown)), "{r:?}");
}

/// Interfaces by index, and an unknown name.
#[test]
fn interfaces() {
    if !enabled() {
        return;
    }
    let h = OpenOptions::new()
        .flags(Flags::SNIFF)
        .interfaces(["1"])
        .open("ip", Layer::Network);
    assert!(h.is_ok(), "{:?}", h.err());
    let r = OpenOptions::new()
        .flags(Flags::SNIFF)
        .interfaces(["no such interface"])
        .open("ip", Layer::Network);
    assert!(matches!(r, Err(Error::InvalidArgument(_))), "{r:?}");
}

/// Many handles opened and closed in turn: each close releases the driver's side.
#[test]
fn many_handles() {
    if !enabled() {
        return;
    }
    for i in 0..200 {
        let h = sniff(&format!("tcp.dstport == {i}"));
        if i % 2 == 0 {
            h.close().unwrap();
        }
    }
}

/// A diverted datagram sent back arrives, unchanged or modified, and its handle does not see it
/// again.
#[test]
fn reinject() {
    if !enabled() {
        return;
    }
    let rx = receiver("127.0.0.1:9406");
    let h = Handle::open("udp.dstport == 9406", Layer::Network, 0, Flags::NONE).unwrap();
    send_to("127.0.0.1:9406", &[b"hello", b"world"]);
    let mut got = [0; 16];
    let (p, a) = recv_one(&h);
    h.send(&p, &a).unwrap();
    assert_eq!(rx.recv(&mut got).unwrap(), 5);
    assert_eq!(&got[..5], b"hello");
    // Modified: the checksums are computed again, as the address's flags are clear.
    let (mut p, a) = recv_one(&h);
    p[28..33].copy_from_slice(b"WORLD");
    h.send(&p, &a).unwrap();
    assert_eq!(rx.recv(&mut got).unwrap(), 5);
    assert_eq!(&got[..5], b"WORLD");
    let mut buf = vec![0; MAX_PACKET_LEN];
    let r = h.recv_timeout(&mut buf, Duration::from_millis(300));
    assert!(
        matches!(r, Err(Error::Timeout)),
        "its own packets pass it by: {r:?}"
    );
}

/// A UDP datagram for 127.0.0.1:`port`, with zero checksums.
fn udp_packet(port: u16, payload: &[u8]) -> Vec<u8> {
    let len = 28 + payload.len();
    let mut p = vec![
        0x45, 0, 0, 0, 0, 1, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
    ];
    p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    p.extend_from_slice(&40000u16.to_be_bytes());
    p.extend_from_slice(&port.to_be_bytes());
    p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    p
}

/// A packet built from scratch, injected by a SEND_ONLY handle, arrives.
#[test]
fn inject_built_packet() {
    if !enabled() {
        return;
    }
    let rx = receiver("127.0.0.1:9407");
    let h = Handle::open("false", Layer::Network, 0, Flags::SEND_ONLY).unwrap();
    let mut a = avulse::Address::new(Layer::Network);
    a.outbound = true;
    a.loopback = true;
    h.send(&udp_packet(9407, b"built"), &a).unwrap();
    let mut got = [0; 16];
    assert_eq!(rx.recv(&mut got).unwrap(), 5);
    assert_eq!(&got[..5], b"built");
}

/// A high-priority handle diverts and reinjects; a lower one then sees the packet, as an
/// impostor, and the higher one does not see it again.
#[test]
fn priorities_and_impostors() {
    if !enabled() {
        return;
    }
    let rx = receiver("127.0.0.1:9409");
    let high = Handle::open("udp.dstport == 9409", Layer::Network, 100, Flags::NONE).unwrap();
    let low = Handle::open("udp.dstport == 9409", Layer::Network, -100, Flags::SNIFF).unwrap();
    send_to("127.0.0.1:9409", &[b"order"]);
    let (p, a) = recv_one(&high);
    assert!(!a.impostor);
    let mut buf = vec![0; MAX_PACKET_LEN];
    let r = low.recv_timeout(&mut buf, Duration::from_millis(300));
    assert!(
        matches!(r, Err(Error::Timeout)),
        "the higher handle took it first: {r:?}"
    );
    high.send(&p, &a).unwrap();
    let (q, b) = recv_one(&low);
    assert_eq!(q[28..], p[28..]);
    assert!(b.impostor, "{b:?}");
    let r = high.recv_timeout(&mut buf, Duration::from_millis(300));
    assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
    let mut got = [0; 16];
    assert_eq!(rx.recv(&mut got).unwrap(), 5);
}
