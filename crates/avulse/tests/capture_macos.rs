//! The macOS backend without the system extension (Step 31), on real traffic. It needs root and
//! the `feth0`/`feth1` pair that `.github/workflows/privileged.yml` sets up, so it runs only with
//! `AVULSE_MACOS` set:
//!
//! ```text
//! sudo ifconfig feth0 create && sudo ifconfig feth1 create && sudo ifconfig feth0 peer feth1
//! sudo ifconfig feth0 up && sudo ifconfig feth1 inet 10.77.1.1/24 up
//! sudo ifconfig feth1 inet6 fd77::1/64
//! sudo arp -s 10.77.1.2 02:00:00:00:00:99 && sudo ndp -s fd77::2 02:00:00:00:00:99
//! sudo AVULSE_MACOS=1 target/debug/deps/capture_macos-<hash> --test-threads=1
//! ```
//!
//! `feth0` and `feth1` are peers: a frame sent out of one is received by the other. `feth1` is
//! the host's side, with addresses; `feth0` plays the wire, where the tests write frames from
//! a made-up peer (10.77.1.2, `fd77::2`) and watch what the host sends.

#![cfg(target_os = "macos")]

use std::ffi::CString;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsFd, AsRawFd};
use std::time::{Duration, Instant};

use avulse::proto::{Link, Packet, checksum};
use avulse::{Address, Error, Flags, Handle, Layer, MAX_PACKET_LEN, OpenOptions, Param, Shutdown};

const WIRE: &str = "feth0";
const HOST: &str = "feth1";
const HOST_IP: [u8; 4] = [10, 77, 1, 1];
const PEER_IP: [u8; 4] = [10, 77, 1, 2];
const HOST_IP6: [u8; 16] = [0xfd, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const PEER_IP6: [u8; 16] = [0xfd, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const PEER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x99];
const SEC: Duration = Duration::from_secs(1);

fn enabled() -> bool {
    if std::env::var_os("AVULSE_MACOS").is_some() {
        return true;
    }
    eprintln!("skipped: set AVULSE_MACOS and run as root, with the feth pair (see the header)");
    false
}

fn ifindex(name: &str) -> u32 {
    let c = CString::new(name).unwrap();
    // SAFETY: a NUL-terminated name.
    unsafe { libc::if_nametoindex(c.as_ptr()) }
}

/// The MAC address of `name`, from the frames it sends: a datagram to the peer, seen on the wire.
fn host_mac() -> [u8; 6] {
    let wire = ethernet(WIRE, "eth.type == 0x0800 and udp.dstport == 47999");
    send_udp(47999);
    let (frame, _) = recv_within(&wire, SEC).expect("the host's datagram on the wire");
    frame[6..12].try_into().unwrap()
}

/// A sniffing handle at `layer` on interface `iface`.
fn sniff_on(iface: &str, filter: &str, layer: Layer) -> Handle {
    OpenOptions::new()
        .flags(Flags::SNIFF)
        .interfaces([iface])
        .open(filter, layer)
        .unwrap_or_else(|e| panic!("opening `{filter}` on {iface}: {e}"))
}

fn ethernet(iface: &str, filter: &str) -> Handle {
    sniff_on(iface, filter, Layer::Ethernet)
}

fn sender(layer: Layer) -> Handle {
    Handle::open("false", layer, 0, Flags::SEND_ONLY).unwrap()
}

fn recv_within(h: &Handle, timeout: Duration) -> Option<(Vec<u8>, Address)> {
    let mut buf = vec![0; MAX_PACKET_LEN];
    match h.recv_timeout(&mut buf, timeout) {
        Ok((n, addr)) => Some((buf[..n].to_vec(), addr)),
        Err(Error::Timeout) => None,
        Err(e) => panic!("recv: {e}"),
    }
}

/// Sends a datagram from the host to the peer's `port`, out of `feth1`.
fn send_udp(port: u16) {
    let s = UdpSocket::bind(SocketAddr::from((HOST_IP, 0))).unwrap();
    s.send_to(b"avulse", SocketAddr::from((PEER_IP, port)))
        .unwrap();
}

fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = dst.to_vec();
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = sport.to_be_bytes().to_vec();
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(payload);
    v
}

/// An IPv4 UDP datagram, checksums computed.
fn udp4(src: [u8; 4], dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
    let body = udp(47000, dport, payload);
    let mut v = vec![0x45, 0, 0, 0, 0x12, 0x34, 0, 0, 64, 17, 0, 0];
    v[2..4].copy_from_slice(&((20 + body.len()) as u16).to_be_bytes());
    v.extend_from_slice(&src);
    v.extend_from_slice(&dst);
    v.extend_from_slice(&body);
    checksum::recalculate(&mut v, Link::Ip);
    v
}

/// An IPv6 UDP datagram, checksums computed.
fn udp6(src: [u8; 16], dst: [u8; 16], dport: u16, payload: &[u8]) -> Vec<u8> {
    let body = udp(47000, dport, payload);
    let mut v = vec![0x60, 0, 0, 0];
    v.extend_from_slice(&(body.len() as u16).to_be_bytes());
    v.extend_from_slice(&[17, 64]);
    v.extend_from_slice(&src);
    v.extend_from_slice(&dst);
    v.extend_from_slice(&body);
    checksum::recalculate(&mut v, Link::Ip);
    v
}

/// Writes `ip` on the wire as a frame from the peer to the host: the host receives it on
/// `feth1`.
fn from_peer(host_mac: [u8; 6], ip: &[u8]) {
    let ethertype = if ip[0] >> 4 == 6 { 0x86dd } else { 0x0800 };
    let mut addr = Address::new(Layer::Ethernet);
    addr.outbound = true;
    addr.if_idx = ifindex(WIRE);
    sender(Layer::Ethernet)
        .send(&eth(host_mac, PEER_MAC, ethertype, ip), &addr)
        .unwrap();
}

fn udp_dst(data: &[u8], link: Link) -> Option<u16> {
    Packet::parse(data, link).udp().map(|u| u.dst_port())
}

/// A receive times out, after about its timeout, also with a zero timeout.
#[test]
fn receive_times_out() {
    if !enabled() {
        return;
    }
    let h = sniff_on(HOST, "udp.dstport == 9", Layer::Network);
    let mut buf = vec![0; MAX_PACKET_LEN];
    let start = Instant::now();
    let r = h.recv_timeout(&mut buf, Duration::from_millis(200));
    assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
    assert!(start.elapsed() >= Duration::from_millis(150));
    let r = h.recv_timeout(&mut buf, Duration::ZERO);
    assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
}

/// Shutting down wakes a receiver waiting in another thread, and later receives fail too.
#[test]
fn shutdown_ends_receives() {
    if !enabled() {
        return;
    }
    let h = sniff_on(HOST, "udp.dstport == 9", Layer::Network);
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
    let r = h.recv_timeout(&mut buf, SEC);
    assert!(matches!(r, Err(Error::Shutdown)), "{r:?}");
}

/// Packets queued before a shutdown are still delivered.
#[test]
fn shutdown_delivers_what_is_queued() {
    if !enabled() {
        return;
    }
    let h = sniff_on(HOST, "udp.dstport == 47010", Layer::Network);
    send_udp(47010);
    std::thread::sleep(Duration::from_millis(300));
    h.shutdown(Shutdown::Recv).unwrap();
    assert!(recv_within(&h, SEC).is_some());
    let mut buf = vec![0; MAX_PACKET_LEN];
    let r = h.recv_timeout(&mut buf, SEC);
    assert!(matches!(r, Err(Error::Shutdown)), "{r:?}");
}

/// Parameters apply, counters come back, and what the backend cannot do is refused.
#[test]
fn parameters_counters_and_limits() {
    if !enabled() {
        return;
    }
    let h = sniff_on(HOST, "udp.dstport == 47011", Layer::Network);
    h.set_param(Param::QueueLength, 32).unwrap();
    assert_eq!(h.param(Param::QueueLength), 32);
    for _ in 0..34 {
        send_udp(47011);
    }
    std::thread::sleep(Duration::from_millis(300));
    let mut n = 0;
    while recv_within(&h, Duration::from_millis(300)).is_some() {
        n += 1;
    }
    assert_eq!(n, 32);
    let s = h.stats().unwrap();
    assert_eq!((s.diverted, s.sniffed, s.queue_drops), (0, 34, 2), "{s:?}");

    // Diverting, dropping, and the layers that need the system extension.
    for (layer, flags) in [
        (Layer::Network, Flags::NONE),
        (Layer::Network, Flags::DROP),
        (Layer::Ethernet, Flags::NONE),
        (Layer::NetworkForward, Flags::SNIFF),
        (Layer::Flow, Flags::SNIFF | Flags::RECV_ONLY),
        (Layer::Reflect, Flags::SNIFF | Flags::RECV_ONLY),
    ] {
        let r = Handle::open("true", layer, 0, flags);
        assert!(
            matches!(r, Err(Error::Unsupported(_))),
            "{layer:?} {flags:?}"
        );
    }
    // An interface that does not exist.
    let r = OpenOptions::new()
        .flags(Flags::SNIFF)
        .interfaces(["nosuch0"])
        .open("true", Layer::Network);
    assert!(matches!(r, Err(Error::Io(_))), "{:?}", r.err());
    // lo0 has no Ethernet header.
    let r = OpenOptions::new()
        .flags(Flags::SNIFF)
        .interfaces(["lo0"])
        .open("true", Layer::Ethernet);
    assert!(matches!(r, Err(Error::Unsupported(_))), "{:?}", r.err());
}

/// An outbound datagram, at the NETWORK layer: its direction, interface and bytes.
#[test]
fn sniff_outbound() {
    if !enabled() {
        return;
    }
    let h = sniff_on(HOST, "udp.dstport == 47012", Layer::Network);
    send_udp(47012);
    let (data, addr) = recv_within(&h, SEC).expect("the outbound datagram");
    assert_eq!(udp_dst(&data, Link::Ip), Some(47012));
    assert!(addr.outbound && addr.sniffed && !addr.loopback && !addr.ipv6);
    assert_eq!(addr.if_idx, ifindex(HOST));
    assert!(
        recv_within(&h, Duration::from_millis(300)).is_none(),
        "seen twice"
    );
}

/// A frame written on the wire reaches the host inbound, and its socket.
#[test]
fn sniff_inbound() {
    if !enabled() {
        return;
    }
    let mac = host_mac();
    let rx = UdpSocket::bind(SocketAddr::from((HOST_IP, 47013))).unwrap();
    rx.set_read_timeout(Some(SEC)).unwrap();
    let h = sniff_on(HOST, "udp.dstport == 47013", Layer::Network);
    from_peer(mac, &udp4(PEER_IP, HOST_IP, 47013, b"in"));
    let (data, addr) = recv_within(&h, SEC).expect("the inbound datagram");
    assert_eq!(udp_dst(&data, Link::Ip), Some(47013));
    assert!(!addr.outbound && addr.sniffed && !addr.loopback);
    assert_eq!(addr.if_idx, ifindex(HOST));
    assert!(addr.ip_checksum && addr.udp_checksum);
    // A copy: the socket gets it too.
    assert_eq!(rx.recv(&mut [0; 16]).unwrap(), 2);
}

/// A datagram over lo0: outbound and loopback, seen once.
#[test]
fn sniff_loopback() {
    if !enabled() {
        return;
    }
    let h = sniff_on("lo0", "udp.dstport == 47014", Layer::Network);
    let rx = UdpSocket::bind("127.0.0.1:47014").unwrap();
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .send_to(b"lo", "127.0.0.1:47014")
        .unwrap();
    let (data, addr) = recv_within(&h, SEC).expect("the loopback datagram");
    assert_eq!(udp_dst(&data, Link::Ip), Some(47014));
    assert!(addr.loopback && addr.outbound);
    assert_eq!(addr.if_idx, ifindex("lo0"));
    assert!(
        recv_within(&h, Duration::from_millis(300)).is_none(),
        "seen twice"
    );
    drop(rx);
}

/// Filters on direction and interface, with every interface captured.
#[test]
fn filters_on_direction_and_interface() {
    if !enabled() {
        return;
    }
    let mac = host_mac();
    let out = Handle::open(
        r#"outbound and iface == "feth1" and udp.port == 47015"#,
        Layer::Network,
        0,
        Flags::SNIFF,
    )
    .unwrap();
    let inb = Handle::open(
        "inbound and udp.dstport == 47015",
        Layer::Network,
        0,
        Flags::SNIFF,
    )
    .unwrap();
    send_udp(47015);
    from_peer(mac, &udp4(PEER_IP, HOST_IP, 47015, b"in"));
    let (_, a) = recv_within(&out, SEC).expect("outbound");
    assert!(a.outbound);
    assert!(recv_within(&out, Duration::from_millis(300)).is_none());
    let (_, a) = recv_within(&inb, SEC).expect("inbound");
    assert!(!a.outbound);
    assert!(recv_within(&inb, Duration::from_millis(300)).is_none());
}

/// The ETHERNET layer: an ARP request and a VLAN-tagged frame from the wire, whole.
#[test]
fn ethernet_sniff() {
    if !enabled() {
        return;
    }
    let mac = host_mac();
    let h = ethernet(HOST, "arp or vlan.id == 100");
    // Who has 10.77.1.1? Tell 10.77.1.2.
    let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 1];
    arp.extend_from_slice(&PEER_MAC);
    arp.extend_from_slice(&PEER_IP);
    arp.extend_from_slice(&[0; 6]);
    arp.extend_from_slice(&HOST_IP);
    let request = eth([0xff; 6], PEER_MAC, 0x0806, &arp);
    let mut addr = Address::new(Layer::Ethernet);
    addr.outbound = true;
    addr.if_idx = ifindex(WIRE);
    let tx = sender(Layer::Ethernet);
    tx.send(&request, &addr).unwrap();
    let mut tagged = eth(mac, PEER_MAC, 0x8100, &[0, 100, 0x08, 0]);
    tagged.extend_from_slice(&udp4(PEER_IP, HOST_IP, 47016, b"vlan"));
    tx.send(&tagged, &addr).unwrap();

    let mut seen = Vec::new();
    while let Some((frame, addr)) = recv_within(&h, SEC) {
        if !addr.outbound {
            seen.push((frame, addr));
        }
    }
    let arp_in = seen.iter().find(|(f, _)| f == &request);
    assert!(arp_in.is_some(), "the ARP request");
    let (_, a) = seen
        .iter()
        .find(|(f, _)| f == &tagged)
        .expect("the tagged frame");
    assert!(a.vlan);
    assert_eq!(a.vlan_tci, 100);
    assert_eq!(a.if_idx, ifindex(HOST));
}

/// Inbound IPv4 and IPv6 packets the application built reach the host's sockets.
#[test]
fn inject_inbound() {
    if !enabled() {
        return;
    }
    let tx = sender(Layer::Network);
    let mut addr = Address::new(Layer::Network);
    addr.if_idx = ifindex(HOST);

    let rx = UdpSocket::bind(SocketAddr::from((HOST_IP, 47017))).unwrap();
    rx.set_read_timeout(Some(SEC)).unwrap();
    tx.send(&udp4(PEER_IP, HOST_IP, 47017, b"four"), &addr)
        .unwrap();
    assert_eq!(rx.recv(&mut [0; 16]).unwrap(), 4);

    let rx6 = UdpSocket::bind(SocketAddr::from((HOST_IP6, 47018))).unwrap();
    rx6.set_read_timeout(Some(SEC)).unwrap();
    tx.send(&udp6(PEER_IP6, HOST_IP6, 47018, b"six"), &addr)
        .unwrap();
    let (n, from) = rx6.recv_from(&mut [0; 16]).unwrap();
    assert_eq!(n, 3);
    assert_eq!(from, SocketAddr::from((PEER_IP6, 47000)));

    // At the ETHERNET layer, a frame carrying IPv4 goes in the same way.
    let mac = host_mac();
    let mut addr = Address::new(Layer::Ethernet);
    addr.if_idx = ifindex(HOST);
    let frame = eth(
        mac,
        PEER_MAC,
        0x0800,
        &udp4(PEER_IP, HOST_IP, 47017, b"frame"),
    );
    sender(Layer::Ethernet).send(&frame, &addr).unwrap();
    assert_eq!(rx.recv(&mut [0; 16]).unwrap(), 5);
}

/// Outbound packets, built or captured, leave through the interface: the wire sees them.
#[test]
fn inject_outbound() {
    if !enabled() {
        return;
    }
    let mac = host_mac();
    let wire = ethernet(WIRE, "udp.dstport in {47019, 47020, 47021}");

    // A frame, at the ETHERNET layer.
    let frame = eth(
        PEER_MAC,
        mac,
        0x0800,
        &udp4(HOST_IP, PEER_IP, 47019, b"frame"),
    );
    let mut addr = Address::new(Layer::Ethernet);
    addr.outbound = true;
    addr.if_idx = ifindex(HOST);
    sender(Layer::Ethernet).send(&frame, &addr).unwrap();
    let (got, _) = recv_within(&wire, SEC).expect("the frame on the wire");
    assert_eq!(got, frame);

    // An IPv4 packet, routed out of feth1.
    let ip = udp4(HOST_IP, PEER_IP, 47020, b"ip");
    let mut addr = Address::new(Layer::Network);
    addr.outbound = true;
    sender(Layer::Network).send(&ip, &addr).unwrap();
    let (got, _) = recv_within(&wire, SEC).expect("the packet on the wire");
    assert_eq!(&got[14..], &ip[..]);

    // An IPv6 datagram captured outbound, sent again behind its saved Ethernet header.
    let h = sniff_on(HOST, "ipv6 and udp.dstport == 47021", Layer::Network);
    let s = UdpSocket::bind(SocketAddr::from((HOST_IP6, 0))).unwrap();
    s.send_to(b"six", SocketAddr::from((PEER_IP6, 47021)))
        .unwrap();
    let (pkt, addr) = recv_within(&h, SEC).expect("the outbound IPv6 datagram");
    assert!(addr.ipv6 && addr.outbound);
    let (first, _) = recv_within(&wire, SEC).expect("the original");
    h.send(&pkt, &addr).unwrap();
    let (second, _) = recv_within(&wire, SEC).expect("the copy");
    assert_eq!(first, second);
}

/// A handle does not capture what it sends itself; other handles do.
#[test]
fn own_sends_are_not_captured() {
    if !enabled() {
        return;
    }
    let me = sniff_on(HOST, "udp.dstport == 47022", Layer::Network);
    let other = sniff_on(HOST, "udp.dstport == 47022", Layer::Network);
    let mut addr = Address::new(Layer::Network);
    addr.outbound = true;
    me.send(&udp4(HOST_IP, PEER_IP, 47022, b"me"), &addr)
        .unwrap();
    assert!(recv_within(&other, SEC).is_some());
    assert!(recv_within(&me, Duration::from_millis(500)).is_none());
}

/// Many handles at once, each with its devices.
#[test]
fn many_handles() {
    if !enabled() {
        return;
    }
    let handles: Vec<Handle> = (0..16)
        .map(|_| sniff_on(HOST, "udp.dstport == 47023", Layer::Network))
        .collect();
    send_udp(47023);
    for h in &handles {
        assert!(recv_within(h, SEC).is_some());
    }
    for h in handles {
        h.close().unwrap();
    }
}

/// The handle's descriptor is readable when a packet waits, and not before.
#[test]
fn descriptor_readiness() {
    if !enabled() {
        return;
    }
    let h = sniff_on(HOST, "udp.dstport == 47024", Layer::Network);
    let mut pfd = libc::pollfd {
        fd: h.as_fd().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd.
    assert_eq!(unsafe { libc::poll(&mut pfd, 1, 0) }, 0);
    send_udp(47024);
    // SAFETY: as above.
    assert_eq!(unsafe { libc::poll(&mut pfd, 1, 1000) }, 1);
    assert!(recv_within(&h, Duration::ZERO).is_some());
}
