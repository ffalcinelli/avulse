//! The Windows backend against the driver, `avulse.sys`, in the `windows` VM. It needs
//! Administrator rights and the driver, so it runs only with `AVULSE_DRIVER` set to the path of
//! `avulse.sys`; the backend installs and starts the service from there
//! (drivers/windows/scripts/test.ps1 does all of it):
//!
//! ```text
//! $env:AVULSE_DRIVER = "C:\build\avulse\drivers\windows\driver\target\release\avulse_package\avulse.sys"
//! cargo test -p avulse --test capture_windows -- --test-threads=1
//! ```
//!
//! The ETHERNET tests need the driver installed as a lightweight filter (`netcfg`), and run with
//! `AVULSE_ETHERNET` set; without it they check that the layer is refused. They use the VM's NAT
//! adapter and its gateway, 10.0.2.2, with narrow filters (WinRM goes over the same adapter).
//! `AVULSE_TCP_PEER` (`10.0.2.2:<port>`, a byte-counting sink on the host,
//! `drivers/windows/scripts/tcp-sink.py`) adds a large TCP upload through a diverting handle.

#![cfg(target_os = "windows")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown as NetShutdown, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use avulse::{
    Address, Error, Event, Flags, Handle, Layer, MAX_PACKET_LEN, OpenOptions, Param, Shutdown,
};

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
    let low = Handle::open("udp and loopback", Layer::Network, -100, Flags::SNIFF).unwrap();
    // Not `tcp`: that matches WinRM, which drives the test VM.
    let miss = sniff("udp.dstport == 9404 or tcp.port == 9404");
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
    let mut a = a;
    a.udp_checksum = false;
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

/// Whether the ETHERNET tests run: the driver is installed as a lightweight filter.
fn ethernet() -> bool {
    enabled() && std::env::var_os("AVULSE_ETHERNET").is_some()
}

/// The VM's gateway, behind its NAT adapter.
const GATEWAY: [u8; 4] = [10, 0, 2, 2];

/// Whether `ping` got an answer from `to`.
fn ping(to: &str, count: u32) -> bool {
    let out = Command::new("ping")
        .args(["-n", &count.to_string(), "-w", "1000", to])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).contains("TTL=")
}

/// The NAT adapter, as a ping to the gateway shows it.
struct Nat {
    if_idx: u32,
    mac: [u8; 6],
    gateway_mac: [u8; 6],
    ip: [u8; 4],
}

fn nat() -> Nat {
    let h = Handle::open(
        "icmp.type == 8 and ip.dst == 10.0.2.2",
        Layer::Ethernet,
        0,
        Flags::SNIFF,
    )
    .unwrap();
    assert!(ping("10.0.2.2", 1), "the gateway answers pings");
    let (f, a) = recv_one(&h);
    assert!(a.outbound && a.if_idx != 0, "{a:?}");
    Nat {
        if_idx: a.if_idx,
        mac: f[6..12].try_into().unwrap(),
        gateway_mac: f[..6].try_into().unwrap(),
        ip: f[26..30].try_into().unwrap(),
    }
}

/// An ARP frame from `src_mac`/`src_ip` to `dst_mac`, about `target_ip` (request: `op` 1).
fn arp_frame(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    op: u8,
    src_ip: [u8; 4],
    target_ip: [u8; 4],
) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst_mac);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, op]);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&src_ip);
    f.extend_from_slice(&[0; 6]);
    f.extend_from_slice(&target_ip);
    f.resize(60, 0);
    f
}

/// Receives from `h` for up to `wait` until `want` accepts a frame.
fn recv_until(
    h: &Handle,
    wait: Duration,
    mut want: impl FnMut(&[u8], &avulse::Address) -> bool,
) -> Option<(Vec<u8>, avulse::Address)> {
    let end = Instant::now() + wait;
    let mut buf = vec![0; MAX_PACKET_LEN];
    while let Some(left) = end.checked_duration_since(Instant::now()) {
        match h.recv_timeout(&mut buf, left) {
            Ok((n, a)) if want(&buf[..n], &a) => return Some((buf[..n].to_vec(), a)),
            Ok(_) | Err(Error::Timeout) => {}
            Err(e) => panic!("recv: {e}"),
        }
    }
    None
}

/// Without the lightweight filter installed, the ETHERNET layer is refused.
#[test]
fn ethernet_needs_the_filter() {
    if !enabled() || ethernet() {
        return;
    }
    let r = Handle::open("arp", Layer::Ethernet, 0, Flags::SNIFF);
    assert!(matches!(r, Err(Error::Unsupported(_))), "{:?}", r.err());
}

/// Pings to the gateway are seen both ways, as Ethernet frames of the NAT adapter; a handle on
/// another interface sees none of them.
#[test]
fn ethernet_sniff() {
    if !ethernet() {
        return;
    }
    let filter = "icmp and ip.addr == 10.0.2.2";
    let h = Handle::open(filter, Layer::Ethernet, 0, Flags::SNIFF).unwrap();
    let other = OpenOptions::new()
        .flags(Flags::SNIFF)
        .interfaces(["1"])
        .open(filter, Layer::Ethernet)
        .unwrap();
    assert!(ping("10.0.2.2", 2));
    let (mut out, mut inb) = (0, 0);
    while let Some((f, a)) = recv_until(&h, Duration::from_millis(500), |_, _| true) {
        assert_eq!(f[12..14], [0x08, 0x00], "IPv4 in Ethernet");
        assert!(
            a.if_idx != 0 && !a.loopback && a.sniffed && !a.ipv6,
            "{a:?}"
        );
        match (a.outbound, f[34]) {
            (true, 8) => out += 1,
            (false, 0) => inb += 1,
            other => panic!("unexpected frame: {other:?}"),
        }
    }
    assert_eq!((out, inb), (2, 2));
    let r = recv_until(&other, Duration::from_millis(300), |_, _| true);
    assert!(r.is_none(), "another interface: {r:?}");
}

/// Dropped pings get no answer, and do again once the handle closes.
#[test]
fn ethernet_drop() {
    if !ethernet() {
        return;
    }
    let d = Handle::open(
        "icmp.type == 8 and ip.dst == 10.0.2.2",
        Layer::Ethernet,
        0,
        Flags::DROP,
    )
    .unwrap();
    assert!(!ping("10.0.2.2", 1));
    assert!(d.stats().unwrap().dropped >= 1);
    d.close().unwrap();
    assert!(ping("10.0.2.2", 1));
}

/// ARP diverted both ways and sent back: the gateway still resolves, and a ping goes through.
#[test]
fn arp_divert_and_reinject() {
    if !ethernet() {
        return;
    }
    let h = Handle::open("arp", Layer::Ethernet, 0, Flags::NONE).unwrap();
    // Forget the gateway's address (an error if it was not known), so that it is resolved again.
    let _ = Command::new("arp").args(["-d", "10.0.2.2"]).status();
    let stop = AtomicBool::new(false);
    let (out, inb) = (AtomicUsize::new(0), AtomicUsize::new(0));
    std::thread::scope(|s| {
        s.spawn(|| {
            let mut buf = vec![0; MAX_PACKET_LEN];
            while !stop.load(Ordering::Relaxed) {
                let Ok((n, a)) = h.recv_timeout(&mut buf, Duration::from_millis(100)) else {
                    continue;
                };
                assert_eq!(buf[12..14], [0x08, 0x06]);
                if a.outbound { &out } else { &inb }.fetch_add(1, Ordering::Relaxed);
                h.send(&buf[..n], &a).unwrap();
            }
        });
        let answered = ping("10.0.2.2", 2);
        stop.store(true, Ordering::Relaxed);
        assert!(answered, "the ping goes through");
    });
    let (out, inb) = (out.into_inner(), inb.into_inner());
    assert!(out >= 1 && inb >= 1, "{out} out, {inb} in");
}

/// A built ARP request goes out of the adapter: a lower handle sees it as an impostor, then
/// the gateway's reply.
#[test]
fn inject_outbound_frame() {
    if !ethernet() {
        return;
    }
    let nat = nat();
    let tx = Handle::open("false", Layer::Ethernet, 100, Flags::SEND_ONLY).unwrap();
    let low = Handle::open("arp", Layer::Ethernet, 0, Flags::SNIFF).unwrap();
    let req = arp_frame([0xff; 6], nat.mac, 1, nat.ip, GATEWAY);
    let mut a = avulse::Address::new(Layer::Ethernet);
    a.outbound = true;
    a.if_idx = nat.if_idx;
    tx.send(&req, &a).unwrap();
    let seen = recv_until(&low, Duration::from_secs(2), |f, b| {
        b.outbound && f == &req[..]
    });
    let (_, b) = seen.expect("the lower handle sees the request");
    assert!(b.impostor && b.if_idx == nat.if_idx, "{b:?}");
    let reply = recv_until(&low, Duration::from_secs(3), |f, b| {
        !b.outbound && f[20..22] == [0, 2] && f[28..32] == GATEWAY
    });
    let (f, b) = reply.expect("the gateway replies");
    assert!(!b.impostor);
    assert_eq!(f[6..12], nat.gateway_mac);
}

/// A built ARP request injected inbound reaches Windows, which answers it.
#[test]
fn inject_inbound_frame() {
    if !ethernet() {
        return;
    }
    let nat = nat();
    let tx = Handle::open("false", Layer::Ethernet, 100, Flags::SEND_ONLY).unwrap();
    let low = Handle::open("arp", Layer::Ethernet, 0, Flags::SNIFF).unwrap();
    let (peer_mac, peer_ip) = ([0x02, 0, 0, 0, 0, 0x77], [10, 0, 2, 77]);
    let req = arp_frame(nat.mac, peer_mac, 1, peer_ip, nat.ip);
    let mut a = avulse::Address::new(Layer::Ethernet);
    a.if_idx = nat.if_idx;
    tx.send(&req, &a).unwrap();
    let seen = recv_until(&low, Duration::from_secs(2), |f, b| {
        !b.outbound && f == &req[..]
    });
    assert!(seen.expect("the lower handle sees it").1.impostor);
    let reply = recv_until(&low, Duration::from_secs(3), |f, b| {
        b.outbound && f[20..22] == [0, 2] && f[38..42] == peer_ip
    });
    let (f, _) = reply.expect("Windows answers");
    assert_eq!(f[..6], peer_mac);
}

/// A frame with a VLAN tag in it is seen with its tag by a lower handle.
#[test]
fn vlan_tag_in_band() {
    if !ethernet() {
        return;
    }
    let nat = nat();
    let tx = Handle::open("false", Layer::Ethernet, 100, Flags::SEND_ONLY).unwrap();
    let low = Handle::open(
        "vlan.id == 5 and vlan.priority == 1",
        Layer::Ethernet,
        0,
        Flags::SNIFF,
    )
    .unwrap();
    let mut f = vec![0xff; 6];
    f.extend_from_slice(&nat.mac);
    // 802.1Q, priority 1, VLAN 5, then the local experimental ethertype.
    f.extend_from_slice(&[0x81, 0x00, 0x20, 0x05, 0x88, 0xb5]);
    f.resize(64, 0xab);
    let mut a = avulse::Address::new(Layer::Ethernet);
    a.outbound = true;
    a.if_idx = nat.if_idx;
    tx.send(&f, &a).unwrap();
    let (got, b) = recv_until(&low, Duration::from_secs(2), |_, _| true).expect("seen");
    assert_eq!(got, f);
    assert!(b.vlan && b.vlan_tci == 0x2005 && b.impostor, "{b:?}");
}

/// A 4 MiB upload whose frames a handle diverts and sends back still arrives whole; with large
/// send offload on, the frames are larger than the MTU and go back as large sends.
#[test]
fn lso_reinject() {
    let Some(peer) = std::env::var("AVULSE_TCP_PEER").ok().filter(|_| ethernet()) else {
        return;
    };
    let port: u16 = peer.rsplit(':').next().unwrap().parse().unwrap();
    let h = Handle::open(
        &format!("tcp.dstport == {port}"),
        Layer::Ethernet,
        0,
        Flags::NONE,
    )
    .unwrap();
    const LEN: usize = 4 << 20;
    let stop = AtomicBool::new(false);
    let (largest, frames) = (AtomicUsize::new(0), AtomicUsize::new(0));
    let reply = std::thread::scope(|s| {
        s.spawn(|| {
            let mut buf = vec![0; MAX_PACKET_LEN];
            while !stop.load(Ordering::Relaxed) {
                let Ok((n, a)) = h.recv_timeout(&mut buf, Duration::from_millis(100)) else {
                    continue;
                };
                largest.fetch_max(n, Ordering::Relaxed);
                frames.fetch_add(1, Ordering::Relaxed);
                h.send(&buf[..n], &a).unwrap();
            }
        });
        let mut c = TcpStream::connect(&peer).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        c.write_all(&vec![0x5a; LEN]).unwrap();
        c.shutdown(NetShutdown::Write).unwrap();
        let mut reply = String::new();
        c.read_to_string(&mut reply).unwrap();
        stop.store(true, Ordering::Relaxed);
        reply
    });
    eprintln!(
        "{} frames diverted, the largest {} bytes",
        frames.into_inner(),
        largest.into_inner()
    );
    assert_eq!(reply.trim(), LEN.to_string());
}

// The FLOW, SOCKET and REFLECT layers (Step 28).

/// What `h` receives until it is quiet for `quiet`.
fn drain_for(h: &Handle, quiet: Duration) -> Vec<(Vec<u8>, Address)> {
    let mut buf = vec![0; MAX_PACKET_LEN];
    let mut out = Vec::new();
    loop {
        match h.recv_timeout(&mut buf, quiet) {
            Ok((n, a)) => out.push((buf[..n].to_vec(), a)),
            Err(Error::Timeout) => return out,
            Err(e) => panic!("recv: {e}"),
        }
    }
}

fn drain(h: &Handle) -> Vec<(Vec<u8>, Address)> {
    drain_for(h, Duration::from_millis(500))
}

fn open_flow(filter: &str) -> Handle {
    Handle::open(filter, Layer::Flow, 0, Flags::SNIFF | Flags::RECV_ONLY)
        .unwrap_or_else(|e| panic!("opening `{filter}` at FLOW: {e}"))
}

fn open_socket(filter: &str, flags: Flags) -> Handle {
    Handle::open(filter, Layer::Socket, 0, flags | Flags::RECV_ONLY)
        .unwrap_or_else(|e| panic!("opening `{filter}` at SOCKET: {e}"))
}

fn kinds(got: &[(Vec<u8>, Address)]) -> Vec<(Event, bool)> {
    let mut k: Vec<_> = got.iter().map(|(_, a)| (a.event, a.outbound)).collect();
    k.sort_by_key(|&(e, o)| (e as u8, o));
    k
}

/// Loopback TCP flows over IPv4 and IPv6: both ends, each established and deleted once, with
/// their endpoints and this process.
#[test]
fn flow_loopback() {
    use Event::{FlowDeleted, FlowEstablished};
    if !enabled() {
        return;
    }
    for host in ["127.0.0.1", "::1"] {
        let listener = TcpListener::bind((host, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = open_flow(&format!("local.port == {port} or remote.port == {port}"));
        let s = TcpStream::connect((host, port)).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        drop((s, accepted, listener));
        let got = drain_for(&h, Duration::from_secs(2));
        assert_eq!(
            kinds(&got),
            [
                (FlowEstablished, false),
                (FlowEstablished, true),
                (FlowDeleted, false),
                (FlowDeleted, true)
            ],
            "{host}: {got:#?}"
        );
        for (p, a) in &got {
            assert!(p.is_empty() && a.sniffed && a.loopback && a.layer == Layer::Flow);
            assert_eq!(a.ipv6, host == "::1");
            assert_eq!(
                (a.flow.protocol, a.flow.process_id),
                (6, std::process::id())
            );
            assert!(a.flow.endpoint_id != 0, "{a:?}");
        }
        let out = got.iter().find(|(_, a)| a.outbound).unwrap();
        assert_eq!(out.1.flow.remote_port, port);
        let mut endpoints: Vec<_> = got.iter().map(|(_, a)| a.flow.endpoint_id).collect();
        endpoints.sort();
        endpoints.dedup();
        assert_eq!(endpoints.len(), 2, "{got:#?}");
    }
}

/// A UDP flow is established once over several datagrams, and deleted when its socket closes.
#[test]
fn flow_udp() {
    use Event::{FlowDeleted, FlowEstablished};
    if !enabled() {
        return;
    }
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = rx.local_addr().unwrap().port();
    let h = open_flow(&format!("protocol == 17 and remote.port == {port}"));
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    for _ in 0..3 {
        tx.send_to(b"ping", ("127.0.0.1", port)).unwrap();
        rx.recv_from(&mut [0; 16]).unwrap();
    }
    let got = drain(&h);
    assert_eq!(kinds(&got), [(FlowEstablished, true)], "{got:#?}");
    drop(tx);
    let ended = drain_for(&h, Duration::from_secs(2));
    assert_eq!(kinds(&ended), [(FlowDeleted, true)], "{ended:#?}");
    assert_eq!(got[0].1.flow, ended[0].1.flow);
}

fn refused(r: std::io::Result<impl Sized>) -> bool {
    matches!(r, Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied)
}

/// A SNIFF handle sees a bind, a listen, a connect, an accept and the closes of the two
/// connected sockets.
#[test]
fn socket_events() {
    use Event::*;
    if !enabled() {
        return;
    }
    let port = 9104;
    let h = open_socket(
        &format!("local.port == {port} or remote.port == {port}"),
        Flags::SNIFF,
    );
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let (accepted, peer) = listener.accept().unwrap();
    drop((client, accepted, listener));
    let got = drain_for(&h, Duration::from_secs(1));
    let events: Vec<_> = got.iter().map(|(_, a)| a.event).collect();
    for e in [SocketBind, SocketListen, SocketConnect, SocketAccept] {
        assert_eq!(
            events.iter().filter(|&&x| x == e).count(),
            1,
            "{e:?}: {got:#?}"
        );
    }
    // The client and the accepted socket: Windows reports no closure for a listening socket
    // (Linux does, so it has three).
    let closes: Vec<_> = got
        .iter()
        .filter(|(_, a)| a.event == SocketClose)
        .map(|(_, a)| (a.flow.local_port, a.flow.remote_port))
        .collect();
    assert_eq!(closes.len(), 2, "{got:#?}");
    assert!(
        closes.iter().all(|&(l, r)| l == port || r == port),
        "{closes:?}"
    );
    for (p, a) in &got {
        assert!(p.is_empty() && a.sniffed && a.loopback && a.layer == Layer::Socket);
        assert_eq!(
            (a.flow.protocol, a.flow.process_id),
            (6, std::process::id())
        );
    }
    let connect = got.iter().find(|(_, a)| a.event == SocketConnect).unwrap();
    assert!(connect.1.outbound);
    assert_eq!(connect.1.flow.remote_port, port);
    let accept = got.iter().find(|(_, a)| a.event == SocketAccept).unwrap();
    assert!(!accept.1.outbound);
    assert_eq!(
        (accept.1.flow.local_port, accept.1.flow.remote_port),
        (port, peer.port())
    );
}

/// Without SNIFF, the handle refuses the connects, binds, listens and accepts its filter
/// matches, over IPv4 and IPv6, reports them, and lets the others through; with DROP, it reports
/// nothing.
#[test]
fn socket_refuses_calls() {
    use Event::*;
    if !enabled() {
        return;
    }
    let h = open_socket(
        "(event == connect and remote.port == 9100) or (event == bind and local.port == 9101) \
         or (event == listen and local.port == 9107) or (event == accept and local.port == 9108)",
        Flags::NONE,
    );
    let listener = TcpListener::bind("127.0.0.1:9102").unwrap();
    let listener6 = TcpListener::bind("[::1]:9102").unwrap();
    for host in ["127.0.0.1", "::1"] {
        assert!(refused(TcpStream::connect((host, 9100))), "{host}");
        assert!(refused(UdpSocket::bind((host, 9101))), "{host}");
        assert!(TcpStream::connect((host, 9102)).is_ok(), "{host}");
        assert!(UdpSocket::bind((host, 9105)).is_ok(), "{host}");
        assert!(TcpListener::bind((host, 9107)).is_err(), "{host}");
        let accepting = TcpListener::bind((host, 9108)).unwrap();
        let to = accepting.local_addr().unwrap();
        assert!(
            TcpStream::connect_timeout(&to, Duration::from_secs(1)).is_err(),
            "{host}"
        );
    }
    drop((listener, listener6));
    let got = drain(&h);
    let events: Vec<_> = got.iter().map(|(_, a)| a.event).collect();
    for e in [SocketConnect, SocketBind, SocketListen] {
        assert_eq!(
            events.iter().filter(|&&x| x == e).count(),
            2,
            "{e:?}: {got:#?}"
        );
    }
    assert!(
        events.iter().filter(|&&x| x == SocketAccept).count() >= 2,
        "{got:#?}"
    );
    assert!(got.iter().all(|(_, a)| !a.sniffed), "{got:#?}");
    h.close().unwrap();
    assert!(!refused(TcpStream::connect(("127.0.0.1", 9100))));

    let d = open_socket("event == connect and remote.port == 9100", Flags::DROP);
    assert!(refused(TcpStream::connect(("127.0.0.1", 9100))));
    assert!(drain(&d).is_empty());
}

/// The driver refuses calls by process name (the image's file name, as Windows names it, cut to
/// 32 bytes), and FLOW reports it.
#[test]
fn process_names() {
    if !enabled() {
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:9106").unwrap();
    let flow = open_flow("remote.port == 9106");
    drop(TcpStream::connect(("127.0.0.1", 9106)).unwrap());
    let got = drain(&flow);
    let name = got[0].1.flow.process_name().expect("a name").to_owned();
    let exe = std::env::current_exe().unwrap();
    let exe = exe.file_name().unwrap().to_str().unwrap();
    // The address keeps the first 32 bytes of the name: this one is cut.
    let kept = &exe[..exe.len().min(avulse::PROCESS_NAME_LEN)];
    assert!(name.eq_ignore_ascii_case(kept), "{name} for {exe}");
    let other = open_socket(
        "event == connect and remote.port == 9106 and process.name == \"other.exe\"",
        Flags::NONE,
    );
    assert!(TcpStream::connect(("127.0.0.1", 9106)).is_ok());
    drop(other);
    let deny = open_socket(
        &format!("event == connect and remote.port == 9106 and process.name == \"{name}\""),
        Flags::NONE,
    );
    assert!(refused(TcpStream::connect(("127.0.0.1", 9106))));
    let got = drain(&deny);
    assert_eq!(got.len(), 1, "{got:#?}");
    assert_eq!(got[0].1.flow.process_name(), Some(name.as_str()));
    drop(listener);
}

/// Starts this test binary as a child that opens a FLOW handle (`owner`), and returns once the
/// handle is open.
fn spawn_owner() -> Child {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "owner", "--nocapture", "--test-threads=1"])
        .env("AVULSE_OWNER", "flow")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let out = BufReader::new(child.stdout.take().unwrap());
    for line in out.lines() {
        if line.unwrap().ends_with("handle open") {
            return child;
        }
    }
    let status = child.wait().unwrap();
    panic!("the owner process ended: {status}");
}

/// The child process of [`reflect_layer`]: opens a handle and waits to be killed.
#[test]
fn owner() {
    if std::env::var_os("AVULSE_OWNER").is_none() {
        return;
    }
    let _h = open_flow("true");
    println!("handle open");
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

/// REFLECT reports the handles there are (itself included), then those that open, and close
/// when their process dies; its filter sees the reflected handle's layer.
#[test]
fn reflect_layer() {
    use Event::{ReflectClose, ReflectOpen};
    if !enabled() {
        return;
    }
    let pid = std::process::id();
    let all = Handle::open("true", Layer::Reflect, 0, Flags::SNIFF | Flags::RECV_ONLY).unwrap();
    let flows = Handle::open(
        "layer == flow",
        Layer::Reflect,
        0,
        Flags::SNIFF | Flags::RECV_ONLY,
    )
    .unwrap();
    let first = drain(&all);
    let me = first
        .iter()
        .find(|(_, a)| a.reflect.process_id == pid && a.reflect.layer == Layer::Reflect)
        .unwrap_or_else(|| panic!("itself: {first:#?}"));
    assert_eq!(me.1.event, ReflectOpen);
    assert!(me.1.sniffed);
    assert_eq!(me.1.reflect.flags, Flags::SNIFF | Flags::RECV_ONLY);
    assert!(
        drain(&flows)
            .iter()
            .all(|(_, a)| a.reflect.layer == Layer::Flow)
    );

    let mut child = spawn_owner();
    let opened = drain(&all);
    let theirs: Vec<_> = opened
        .iter()
        .filter(|(_, a)| a.reflect.process_id == child.id())
        .collect();
    assert_eq!(theirs.len(), 1, "{opened:#?}");
    let (data, a) = theirs[0];
    assert_eq!(a.event, ReflectOpen);
    assert_eq!(a.reflect.layer, Layer::Flow);
    assert_eq!(a.reflect.flags, Flags::SNIFF | Flags::RECV_ONLY);
    assert_eq!(data.as_slice(), b"true");
    assert_eq!(a.reflect.syntax, avulse::Syntax::Native);
    assert!(a.reflect.timestamp <= a.timestamp);
    assert!(
        drain(&flows)
            .iter()
            .any(|(_, a)| a.reflect.process_id == child.id() && a.event == ReflectOpen)
    );

    child.kill().unwrap();
    child.wait().unwrap();
    let closed = drain(&all);
    let theirs: Vec<_> = closed
        .iter()
        .filter(|(_, a)| a.reflect.process_id == child.id())
        .map(|(_, a)| a.event)
        .collect();
    assert_eq!(theirs, [ReflectClose], "{closed:#?}");
}
