//! The Linux backend on real traffic, the privileged suite (Step 12): a veth pair with one end in
//! a network namespace, `ping` across it, and a UDP and TCP server in the namespace (the
//! [`peer_server`] test, in a child process); VLAN devices over the pair; `lo`; and two more
//! namespaces routed through the host, for the NETWORK_FORWARD layer. It ports the packet-layer
//! scenarios of ebpfdivert's `tests/test_integration.c`, and checks that the kernel and the
//! evaluator agree on real traffic.
//!
//! It needs root and changes the network configuration, so it runs only with `AVULSE_BPF=1`, in
//! the Vagrant VMs, one test at a time:
//!
//! ```text
//! cargo test -p avulse --test capture --no-run   # on the host; prints the binary's path
//! vagrant up default
//! vagrant ssh default -c "sudo AVULSE_BPF=1 /vagrant/target/debug/deps/capture-… --test-threads=1"
//! vagrant destroy -f default
//! ```

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown as NetShutdown, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use avulse::proto::{Link, Packet};
use avulse::{Address, Error, Flags, Handle, Layer, MAX_PACKET_LEN, OpenOptions, Param, Shutdown};
use avulse_filter::Filter;

const HOST_IF: &str = "avt0";
const PEER_IF: &str = "avt1";
const NETNS: &str = "avulse-test";
const HOST: &str = "10.199.0.1";
const PEER: &str = "10.199.0.2";
/// What the tests divert or copy: pings between the two ends.
const PINGS: &str = "icmp and ip.addr == 10.199.0.2";
/// The peer server's UDP echo port and TCP sink port.
const ECHO_PORT: u16 = 9001;
const SINK_PORT: u16 = 9002;
/// The peer server's TCP source port: it sends [`BULK`] bytes of [`bulk_byte`] and closes.
const SOURCE_PORT: u16 = 9003;
/// The size of the bulk TCP transfers.
const BULK: usize = 8 << 20;

fn enabled() -> bool {
    if std::env::var_os("AVULSE_BPF").is_some() {
        return true;
    }
    eprintln!("skipped: set AVULSE_BPF=1 and run as root (in a VM) to capture packets");
    false
}

fn sh(cmd: &str) -> bool {
    Command::new("sh")
        .args(["-c", cmd])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn output(cmd: &str) -> String {
    let out = Command::new("sh").args(["-c", cmd]).output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The veth pair, removed when dropped.
struct Veth;

impl Veth {
    fn new() -> Veth {
        Veth::remove();
        for cmd in [
            format!("ip netns add {NETNS}"),
            format!("ip link add {HOST_IF} type veth peer name {PEER_IF}"),
            format!("ip link set {PEER_IF} netns {NETNS}"),
            format!("ip addr add {HOST}/24 dev {HOST_IF}"),
            format!("ip link set {HOST_IF} up"),
            format!("ip netns exec {NETNS} ip addr add {PEER}/24 dev {PEER_IF}"),
            format!("ip netns exec {NETNS} ip link set {PEER_IF} up"),
            format!("ip netns exec {NETNS} ip link set lo up"),
        ] {
            assert!(sh(&cmd), "{cmd}");
        }
        // The first ping waits for ARP; do it before any handle exists.
        assert!(ping(1), "the veth pair does not work");
        Veth
    }

    fn remove() {
        sh(&format!("ip link del {HOST_IF}"));
        sh(&format!("ip netns del {NETNS}"));
    }

    fn ifindex() -> u32 {
        ifindex(HOST_IF)
    }
}

fn ifindex(name: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

impl Drop for Veth {
    fn drop(&mut self) {
        Veth::remove();
    }
}

/// Pings the peer `count` times; whether a reply came.
fn ping(count: u32) -> bool {
    sh(&format!("ping -c {count} -i 0.2 -W 1 {PEER}"))
}

/// The TC priorities of the filters on the host end's egress hook.
fn tc_priorities() -> Vec<u32> {
    let out = output(&format!("tc filter show dev {HOST_IF} egress"));
    let mut p: Vec<u32> = out
        .lines()
        .filter(|l| l.contains("avulse_egress"))
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            words.find(|w| *w == "pref")?;
            words.next()?.parse().ok()
        })
        .collect();
    p.sort();
    p
}

fn open(filter: &str, layer: Layer, priority: i16, flags: Flags) -> Handle {
    OpenOptions::new()
        .priority(priority)
        .flags(flags)
        .interfaces([HOST_IF])
        .open(filter, layer)
        .unwrap_or_else(|e| panic!("opening `{filter}`: {e}"))
}

/// Everything the handle receives until it has been quiet for half a second.
fn drain(h: &Handle) -> Vec<(Vec<u8>, Address)> {
    let mut buf = vec![0; MAX_PACKET_LEN];
    let mut out = Vec::new();
    loop {
        match h.recv_timeout(&mut buf, Duration::from_millis(500)) {
            Ok((n, addr)) => out.push((buf[..n].to_vec(), addr)),
            Err(Error::Timeout) => return out,
            Err(e) => panic!("recv: {e}"),
        }
    }
}

/// The ICMP type of an IP packet, and its destination.
fn icmp(p: &[u8]) -> (u8, String) {
    let pkt = Packet::parse(p, Link::Ip);
    let ip = pkt.ipv4().expect("an IPv4 packet");
    (
        pkt.icmp().expect("an ICMP packet").icmp_type(),
        ip.dst().to_string(),
    )
}

/// Whether the kernel runs the filter exactly at the NETWORK layer.
fn exact(filter: &str) -> bool {
    exact_at(filter, Layer::Network)
}

/// Whether the kernel runs the filter exactly at `layer`.
fn exact_at(filter: &str, layer: Layer) -> bool {
    let env = avulse_ebpf::codegen::Env::new(layer);
    avulse_ebpf::codegen::compile_superset(Filter::compile(filter).unwrap().ir(), &env)
        .is_ok_and(|m| m.exact())
}

#[test]
fn divert_pings() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    assert!(exact(PINGS));
    let h = open(PINGS, Layer::Network, 0, Flags::NONE);
    assert_eq!(tc_priorities(), [30_001]);
    let before = now_ns();
    // Diverted: the requests never leave, and nothing sends them back.
    assert!(!ping(3));
    let got = drain(&h);
    assert_eq!(got.len(), 3, "{got:?}");
    for (p, a) in &got {
        assert_eq!(icmp(p), (8, PEER.to_owned()));
        assert_eq!(a.layer, Layer::Network);
        assert!(a.outbound && !a.loopback && !a.impostor && !a.sniffed && !a.ipv6);
        assert_eq!(a.if_idx, Veth::ifindex());
        assert!(a.ip_checksum);
        assert!(!a.context.is_empty());
        assert!(a.timestamp >= before && a.timestamp <= now_ns());
    }
    h.close().unwrap();
    assert_eq!(tc_priorities(), Vec::<u32>::new());
    assert!(ping(1));
}

#[test]
fn sniff_pings() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    let h = open(PINGS, Layer::Network, 0, Flags::SNIFF);
    assert!(ping(3));
    let got = drain(&h);
    let requests: Vec<_> = got.iter().filter(|(p, _)| icmp(p).0 == 8).collect();
    let replies: Vec<_> = got.iter().filter(|(p, _)| icmp(p).0 == 0).collect();
    assert_eq!((requests.len(), replies.len()), (3, 3), "{got:?}");
    assert!(requests.iter().all(|(_, a)| a.outbound && a.sniffed));
    assert!(replies.iter().all(|(p, a)| {
        !a.outbound && a.sniffed && a.if_idx == Veth::ifindex() && icmp(p).1 == HOST
    }));
}

/// Filters the code generator cannot compile run as a superset in the kernel, and user space
/// keeps the matching packets; it reinjects the others when the handle diverts. `timestamp` is
/// user space only, so the kernel takes every ping here (the `xor` widens to `true`), and user
/// space keeps the outbound ones.
#[test]
fn user_space_filters() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    let filter = format!("{PINGS} and (outbound xor timestamp < 0)");
    assert!(!exact(&filter));
    let h = open(&filter, Layer::Network, 0, Flags::SNIFF);
    assert!(ping(3));
    let got = drain(&h);
    assert_eq!(got.len(), 3, "{got:?}");
    assert!(got.iter().all(|(p, a)| a.outbound && icmp(p).0 == 8));
    drop(h);

    // Diverting: the replies do not match and go back at once; the requests come to the handle.
    let h = open(&filter, Layer::Network, 0, Flags::NONE);
    let (ok, got) = forwarding(&h, |_, _| {}, || ping(3));
    assert!(ok);
    assert_eq!(got.len(), 3, "{got:?}");
    assert!(got.iter().all(|(p, a)| a.outbound && icmp(p).0 == 8));
    drop(h);

    // Dropping the matching packets only: the requests go out, and the peer replies (as a handle
    // that runs before sees), but the replies are dropped.
    let h = open(
        &format!("{PINGS} and (inbound xor timestamp < 0)"),
        Layer::Network,
        0,
        Flags::DROP,
    );
    let before = open(PINGS, Layer::Network, 100, Flags::SNIFF);
    before.set_param(Param::QueueTime, 16_000).unwrap();
    assert!(!ping(2));
    assert!(drain(&h).is_empty());
    let seen = drain(&before);
    assert_eq!(seen.len(), 4, "{seen:?}");
    assert!(seen.iter().any(|(p, a)| icmp(p).0 == 0 && !a.outbound));
    drop(h);
    assert!(ping(1));
}

#[test]
fn drop_pings() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    let h = open(PINGS, Layer::Network, 0, Flags::DROP);
    assert!(!ping(2));
    assert!(drain(&h).is_empty());
    drop(h);
    assert!(ping(1));
}

#[test]
fn shutdown_delivers_what_is_queued() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    let h = open(PINGS, Layer::Network, 0, Flags::NONE);
    assert!(!ping(2));
    h.shutdown(Shutdown::Recv).unwrap();
    // Packets pass once the receive side is shut down.
    assert!(ping(1));
    let mut buf = vec![0; MAX_PACKET_LEN];
    for _ in 0..2 {
        let (n, _) = h.recv(&mut buf).unwrap();
        assert_eq!(icmp(&buf[..n]).0, 8);
    }
    assert!(matches!(h.recv(&mut buf), Err(Error::Shutdown)));
    assert!(matches!(
        h.recv_timeout(&mut buf, Duration::ZERO),
        Err(Error::Shutdown)
    ));
}

#[test]
fn recv_details() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    let h = open(PINGS, Layer::Network, 0, Flags::NONE);
    let mut pfd = libc::pollfd {
        fd: std::os::fd::AsFd::as_fd(&h).as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd.
    assert_eq!(unsafe { libc::poll(&mut pfd, 1, 0) }, 0);
    let mut buf = vec![0; MAX_PACKET_LEN];
    assert!(matches!(
        h.recv_timeout(&mut buf, Duration::ZERO),
        Err(Error::Timeout)
    ));
    let start = Instant::now();
    assert!(matches!(
        h.recv_timeout(&mut buf, Duration::from_millis(300)),
        Err(Error::Timeout)
    ));
    assert!(start.elapsed() >= Duration::from_millis(300));

    assert!(!ping(2));
    // SAFETY: as above.
    assert_eq!(unsafe { libc::poll(&mut pfd, 1, 1000) }, 1);
    assert!(matches!(
        h.recv(&mut buf[..20]),
        Err(Error::BufferTooSmall { needed: 84 })
    ));
    // The packet that did not fit is gone.
    assert_eq!(drain(&h).len(), 1);

    // A blocked recv wakes up for a packet from another thread.
    thread::scope(|s| {
        s.spawn(|| {
            thread::sleep(Duration::from_millis(300));
            ping(1);
        });
        let (n, _) = h.recv(&mut buf).unwrap();
        assert_eq!(icmp(&buf[..n]).0, 8);
    });
}

#[test]
fn ethernet_layer() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    sh(&format!("ip neigh flush dev {HOST_IF}"));
    let h = open(
        "arp or (icmp and ip.addr == 10.199.0.2)",
        Layer::Ethernet,
        0,
        Flags::SNIFF,
    );
    assert!(ping(2));
    let got = drain(&h);
    let ethertype = |p: &[u8]| u16::from_be_bytes([p[12], p[13]]);
    assert!(got.iter().any(|(p, _)| ethertype(p) == 0x0806), "{got:?}");
    let pings = got.iter().filter(|(p, _)| ethertype(p) == 0x0800).count();
    assert_eq!(pings, 4);
    assert!(got.iter().all(|(p, a)| {
        let pkt = Packet::parse(p, Link::Ethernet);
        a.layer == Layer::Ethernet && pkt.eth().is_some() && a.context.as_bytes()[1] == 0
    }));
}

#[test]
fn priorities() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    let a = open(PINGS, Layer::Network, 0, Flags::SNIFF);
    let b = open(PINGS, Layer::Network, 0, Flags::SNIFF);
    let c = open(PINGS, Layer::Network, 100, Flags::SNIFF);
    let d = open(PINGS, Layer::Network, -100, Flags::SNIFF);
    assert_eq!(tc_priorities(), [29_901, 30_001, 30_002, 30_101]);
    // Priority 0 goes after every handle open, -100 included.
    let e = open(PINGS, Layer::Network, 0, Flags::SNIFF);
    assert_eq!(tc_priorities(), [29_901, 30_001, 30_002, 30_101, 30_102]);
    // Every sniffing handle sees the pings. Draining them one after the other takes longer than
    // the default QUEUE_TIME (2 s), after which packets are dropped.
    for h in [&a, &b, &c, &d, &e] {
        h.set_param(Param::QueueTime, 16_000).unwrap();
    }
    assert!(ping(1));
    for h in [&a, &b, &c, &d, &e] {
        assert_eq!(drain(h).len(), 2);
    }
}

/// Runs `f` while a thread receives every packet of `h`, passes it to `edit`, and sends it back.
/// Returns what `f` returns, and what the thread received (before `edit`).
fn forwarding<R>(
    h: &Handle,
    edit: impl Fn(&mut Vec<u8>, &mut Address) + Sync,
    f: impl FnOnce() -> R,
) -> (R, Vec<(Vec<u8>, Address)>) {
    let stop = AtomicBool::new(false);
    thread::scope(|s| {
        let t = s.spawn(|| {
            let mut buf = vec![0; MAX_PACKET_LEN];
            let mut seen = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                match h.recv_timeout(&mut buf, Duration::from_millis(100)) {
                    Ok((n, addr)) => {
                        seen.push((buf[..n].to_vec(), addr));
                        let (mut p, mut a) = (buf[..n].to_vec(), addr);
                        edit(&mut p, &mut a);
                        h.send(&p, &a).unwrap_or_else(|e| panic!("send: {e}"));
                    }
                    Err(Error::Timeout) => {}
                    Err(e) => panic!("recv: {e}"),
                }
            }
            seen
        });
        let r = f();
        // What is still on its way.
        thread::sleep(Duration::from_millis(300));
        stop.store(true, Ordering::Relaxed);
        (r, t.join().unwrap())
    })
}

/// An IPv4 UDP datagram, its checksums left to compute.
fn udp_packet(src: &str, sport: u16, dst: &str, dport: u16, payload: &[u8]) -> Vec<u8> {
    let ip = |a: &str| a.parse::<std::net::Ipv4Addr>().unwrap().octets();
    let len = 28 + payload.len();
    let mut p = vec![0x45, 0];
    p.extend((len as u16).to_be_bytes());
    p.extend([0, 0, 0x40, 0, 64, 17, 0, 0]);
    p.extend(ip(src));
    p.extend(ip(dst));
    p.extend(sport.to_be_bytes());
    p.extend(dport.to_be_bytes());
    p.extend(((8 + payload.len()) as u16).to_be_bytes());
    p.extend([0, 0]);
    p.extend(payload);
    p
}

fn udp_socket(addr: &str) -> UdpSocket {
    let s = UdpSocket::bind(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s
}

/// Diverted and sent back unchanged, pings work, in both directions: the requests go out of the
/// interface behind their saved Ethernet header, the replies come in through `lo`'s redirect.
#[test]
fn reinject_pings() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    let h = open(PINGS, Layer::Network, 0, Flags::NONE);
    let (ok, got) = forwarding(&h, |_, _| {}, || ping(3));
    assert!(ok);
    // Each packet once: the handle does not see what it sends.
    let requests = got.iter().filter(|(p, _)| icmp(p).0 == 8).count();
    let replies: Vec<_> = got.iter().filter(|(p, _)| icmp(p).0 == 0).collect();
    assert_eq!((requests, replies.len()), (3, 3), "{got:?}");
    assert!(got.iter().all(|(_, a)| !a.impostor && !a.sniffed));
    assert!(replies.iter().all(|(_, a)| !a.outbound));
}

/// The ETHERNET layer sends frames back as they are.
#[test]
fn reinject_frames() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    let h = open(PINGS, Layer::Ethernet, 0, Flags::NONE);
    let (ok, got) = forwarding(&h, |_, _| {}, || ping(3));
    assert!(ok);
    assert_eq!(got.len(), 6, "{got:?}");
}

/// A diverted datagram is sent on to another port, with another payload: the peer answers from
/// that port, with the new payload (the checksum is computed again).
#[test]
fn modify_outbound() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    let _peer = PeerServer::start();
    let h = open(
        &format!("udp.dstport == 9000 and ip.dst == {PEER}"),
        Layer::Network,
        0,
        Flags::NONE,
    );
    let edit = |p: &mut Vec<u8>, a: &mut Address| {
        p[22..24].copy_from_slice(&ECHO_PORT.to_be_bytes());
        p[28..33].copy_from_slice(b"HELLO");
        a.udp_checksum = false;
    };
    let ((n, from, data), got) = forwarding(&h, edit, || {
        let s = udp_socket(&format!("{HOST}:0"));
        s.send_to(b"hello", format!("{PEER}:9000")).unwrap();
        let mut buf = [0; 64];
        let (n, from) = s.recv_from(&mut buf).expect("the echo");
        (n, from, buf)
    });
    assert_eq!(&data[..n], b"HELLO");
    assert_eq!(from.to_string(), format!("{PEER}:{ECHO_PORT}"));
    assert_eq!(got.len(), 1);
}

/// A SEND_ONLY handle injects a datagram the application built: inbound (through `lo`, to the
/// veth's address), and outbound (routed).
#[test]
fn inject_built_packets() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    let _peer = PeerServer::start();
    let h = open("ip", Layer::Network, 0, Flags::SEND_ONLY);
    // On lo's ingress only, for the redirect.
    let lo = output("tc filter show dev lo ingress");
    assert!(lo.contains("avulse_ingress"), "{lo}");
    assert!(tc_priorities().is_empty());

    let host = udp_socket(&format!("{HOST}:7000"));
    let mut addr = Address::new(Layer::Network);
    addr.if_idx = Veth::ifindex();
    let pkt = udp_packet(PEER, 5555, HOST, 7000, b"inbound");
    assert_eq!(h.send(&pkt, &addr).unwrap(), pkt.len());
    let mut buf = [0; 64];
    let (n, from) = host.recv_from(&mut buf).expect("the inbound datagram");
    assert_eq!(
        (&buf[..n], from.to_string()),
        (&b"inbound"[..], format!("{PEER}:5555"))
    );

    let mut addr = Address::new(Layer::Network);
    addr.outbound = true;
    let pkt = udp_packet(HOST, 7000, PEER, ECHO_PORT, b"outbound");
    h.send(&pkt, &addr).unwrap();
    let (n, from) = host.recv_from(&mut buf).expect("the echo");
    assert_eq!(
        (&buf[..n], from.to_string()),
        (&b"outbound"[..], format!("{PEER}:{ECHO_PORT}"))
    );

    // Not a packet.
    assert!(matches!(
        h.send(&[0x45; 10], &addr),
        Err(Error::InvalidArgument(_))
    ));
    drop(h);
    assert!(!output("tc filter show dev lo ingress").contains("avulse"));
}

/// Loopback packets, IPv4 and IPv6, are seen once and go back through raw sockets.
#[test]
fn loopback() {
    if !enabled() {
        return;
    }
    let h = OpenOptions::new()
        .interfaces(["lo"])
        .open("udp.dstport == 7002", Layer::Network)
        .unwrap();
    let v4 = udp_socket("127.0.0.1:7002");
    let v6 = udp_socket("[::1]:7002");
    let (_, got) = forwarding(
        &h,
        |_, _| {},
        || {
            let mut buf = [0; 64];
            for (server, to) in [(&v4, "127.0.0.1:7002"), (&v6, "[::1]:7002")] {
                let c = udp_socket(if to.starts_with('[') {
                    "[::1]:0"
                } else {
                    "127.0.0.1:0"
                });
                c.send_to(b"lo", to).unwrap();
                let (n, _) = server.recv_from(&mut buf).expect("the datagram");
                assert_eq!(&buf[..n], b"lo");
            }
        },
    );
    assert_eq!(got.len(), 2, "{got:?}");
    assert!(got.iter().all(|(_, a)| a.loopback && a.outbound));
    assert_eq!(got.iter().filter(|(_, a)| a.ipv6).count(), 1);
}

/// Bulk TCP transfers through a diverting handle, both ways, checked byte for byte. Sending, the
/// stack hands the handle packets larger than the MTU (GSO), which go back out as GSO packets.
#[test]
fn bulk_tcp() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    let _peer = PeerServer::start();
    let h = open(
        &format!("tcp.port in {{{SINK_PORT} {SOURCE_PORT}}}"),
        Layer::Network,
        0,
        Flags::NONE,
    );
    let (reply, got) = forwarding(
        &h,
        |_, _| {},
        || {
            let mut s = TcpStream::connect((PEER, SINK_PORT)).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            let data: Vec<u8> = (0..BULK).map(bulk_byte).collect();
            for chunk in data.chunks(1 << 16) {
                s.write_all(chunk).unwrap();
            }
            s.shutdown(NetShutdown::Write).unwrap();
            let mut reply = String::new();
            s.read_to_string(&mut reply).unwrap();
            reply
        },
    );
    assert_eq!(reply, format!("{BULK} {:08x}", bulk_hash(0..BULK)));
    let big = got.iter().filter(|(p, _)| p.len() > 1500).count();
    assert!(big > 0, "no GSO packet among {}", got.len());

    let (data, got) = forwarding(
        &h,
        |_, _| {},
        || {
            let mut s = TcpStream::connect((PEER, SOURCE_PORT)).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            let mut data = Vec::new();
            s.read_to_end(&mut data).unwrap();
            data
        },
    );
    assert_eq!(data.len(), BULK);
    assert!(data.iter().enumerate().all(|(i, b)| *b == bulk_byte(i)));
    assert!(got.iter().any(|(_, a)| !a.outbound));
}

/// The bytes of the bulk transfers: a pattern that does not repeat every page.
fn bulk_byte(i: usize) -> u8 {
    (i * 7 + (i >> 11)) as u8
}

/// The hash of the pattern's bytes at `range`.
fn bulk_hash(range: std::ops::Range<usize>) -> u32 {
    fnv(FNV_START, range.map(bulk_byte))
}

const FNV_START: u32 = 0x811c_9dc5;

/// FNV-1a, from `hash` on.
fn fnv(hash: u32, bytes: impl IntoIterator<Item = u8>) -> u32 {
    bytes
        .into_iter()
        .fold(hash, |h, b| (h ^ u32::from(b)).wrapping_mul(0x0100_0193))
}

/// Two diverting handles: the higher-priority one sees each packet first, and what it sends
/// back reaches the other as an impostor, once.
#[test]
fn priority_chaining() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    let first = open(PINGS, Layer::Network, 100, Flags::NONE);
    let second = open(PINGS, Layer::Network, -100, Flags::NONE);
    let last = open(PINGS, Layer::Network, -200, Flags::SNIFF);
    last.set_param(Param::QueueTime, 16_000).unwrap();
    let ((ok, a), b) = forwarding(
        &second,
        |_, _| {},
        || forwarding(&first, |_, _| {}, || ping(2)),
    );
    assert!(ok);
    assert_eq!((a.len(), b.len()), (4, 4), "{a:?} {b:?}");
    assert!(a.iter().all(|(_, a)| !a.impostor));
    assert!(b.iter().all(|(_, a)| a.impostor));
    // The last handle sees what the second sent: impostors, with one hop less.
    let c = drain(&last);
    assert_eq!(c.len(), 4, "{c:?}");
    for ((p, _), (q, a)) in b.iter().zip(&c) {
        assert!(a.impostor);
        assert_eq!(q[8], p[8] - 1);
    }
}

/// The UDP echo and TCP sink of the peer, in the network namespace, killed when dropped.
struct PeerServer(Child);

impl PeerServer {
    fn start() -> PeerServer {
        let exe = std::env::current_exe().unwrap();
        let mut child = Command::new("ip")
            .args(["netns", "exec", NETNS])
            .arg(exe)
            .args(["--exact", "peer_server", "--nocapture", "--test-threads=1"])
            .env("AVULSE_PEER", "1")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        for line in out.lines() {
            if line.unwrap().ends_with("peer ready") {
                return PeerServer(child);
            }
        }
        let status = child.wait().unwrap();
        panic!("the peer server ended: {status}");
    }
}

impl Drop for PeerServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The child process of [`PeerServer`], in the namespace: echoes UDP datagrams on
/// [`ECHO_PORT`], answers each TCP connection on [`SINK_PORT`] with the number of bytes it
/// received and their hash ([`fnv`]), and sends [`BULK`] bytes on each connection to
/// [`SOURCE_PORT`].
#[test]
fn peer_server() {
    if std::env::var_os("AVULSE_PEER").is_none() {
        return;
    }
    let udp = UdpSocket::bind(("0.0.0.0", ECHO_PORT)).unwrap();
    let tcp = TcpListener::bind(("0.0.0.0", SINK_PORT)).unwrap();
    let source = TcpListener::bind(("0.0.0.0", SOURCE_PORT)).unwrap();
    thread::spawn(move || {
        let mut buf = [0; 2048];
        loop {
            let (n, from) = udp.recv_from(&mut buf).unwrap();
            udp.send_to(&buf[..n], from).unwrap();
        }
    });
    thread::spawn(move || {
        for s in tcp.incoming() {
            let mut s = s.unwrap();
            thread::spawn(move || {
                let mut buf = vec![0; 1 << 16];
                let (mut total, mut hash) = (0, FNV_START);
                loop {
                    match s.read(&mut buf).unwrap() {
                        0 => break,
                        n => {
                            total += n;
                            hash = fnv(hash, buf[..n].iter().copied());
                        }
                    }
                }
                s.write_all(format!("{total} {hash:08x}").as_bytes())
                    .unwrap();
            });
        }
    });
    thread::spawn(move || {
        let data: Vec<u8> = (0..BULK).map(bulk_byte).collect();
        for s in source.incoming() {
            let mut s = s.unwrap();
            let data = data.clone();
            thread::spawn(move || {
                s.write_all(&data).unwrap();
            });
        }
    });
    println!("peer ready");
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

/// The owner of a diverting handle dies: its filters pass everything once the heartbeat is
/// stale, and `cleanup` removes them.
#[test]
fn dead_owners() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    let mut child = spawn_owner();
    assert_eq!(tc_priorities(), [30_001]);
    assert!(!ping(2));
    // SAFETY: plain system call.
    unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
    child.wait().unwrap();
    // The filters stay, and still divert until the heartbeat is 3 s old.
    assert_eq!(tc_priorities(), [30_001]);
    thread::sleep(Duration::from_millis(3500));
    assert!(ping(2));
    assert!(avulse::cleanup().unwrap() >= 1);
    assert_eq!(tc_priorities(), Vec::<u32>::new());
    assert_eq!(avulse::cleanup().unwrap(), 0);
}

/// Runs [`owner`] in a child process, and waits until its handle is open.
fn spawn_owner() -> Child {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "owner", "--nocapture", "--test-threads=1"])
        .env("AVULSE_OWNER", "1")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let out = BufReader::new(child.stdout.take().unwrap());
    for line in out.lines() {
        // libtest writes "test owner ... " first, on the same line.
        if line.unwrap().ends_with("handle open") {
            return child;
        }
    }
    let status = child.wait().unwrap();
    panic!("the owner process ended: {status}");
}

/// The child process of [`dead_owners`]: opens a handle and waits to be killed.
#[test]
fn owner() {
    if std::env::var_os("AVULSE_OWNER").is_none() {
        return;
    }
    let _h = open(PINGS, Layer::Network, 0, Flags::NONE);
    println!("handle open");
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

fn now_ns() -> i64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    // `time_t` and `c_long` are 32 bits on some targets.
    #[allow(clippy::unnecessary_cast)]
    let ns = ts.tv_sec as i64 * 1_000_000_000 + ts.tv_nsec as i64;
    ns
}

// The ETHERNET layer (Step 11).

/// Turns the VLAN offloads of both ends on or off: with them on, the device keeps the outer tag
/// out of the frame (`skb->vlan_tci`), and the backend must put it back.
fn vlan_offload(on: bool) {
    let v = if on { "on" } else { "off" };
    // veth may not offer the 802.1ad offloads: only the 802.1Q state is checked.
    let features =
        format!("rxvlan {v} txvlan {v} rx-vlan-stag-hw-parse {v} tx-vlan-stag-hw-insert {v}");
    for exec in [String::new(), format!("ip netns exec {NETNS} ")] {
        let dev = if exec.is_empty() { HOST_IF } else { PEER_IF };
        sh(&format!("{exec}ethtool -K {dev} {features}"));
        let k = output(&format!("{exec}ethtool -k {dev}"));
        for f in ["rx-vlan-offload", "tx-vlan-offload"] {
            assert!(k.contains(&format!("{f}: {v}")), "{dev} {f}: {k}");
        }
    }
}

/// A VLAN device `name` on `parent`, at both ends, with 10.199.`net`.1 here and .2 at the peer.
fn vlan_link(parent: (&str, &str), name: (&str, &str), kind: &str, net: u8) {
    for (ns, parent, name, host) in [("", parent.0, name.0, 1), (NETNS, parent.1, name.1, 2)] {
        let exec = if ns.is_empty() {
            String::new()
        } else {
            format!("ip netns exec {ns} ")
        };
        for cmd in [
            format!("{exec}ip link add link {parent} name {name} type vlan {kind}"),
            format!("{exec}ip addr add 10.199.{net}.{host}/24 dev {name}"),
            format!("{exec}ip link set {name} up"),
        ] {
            assert!(sh(&cmd), "{cmd}");
        }
    }
}

fn ping_to(addr: &str, count: u32) -> bool {
    sh(&format!("ping -c {count} -i 0.2 -W 1 {addr}"))
}

/// ARP requests and replies diverted and sent back: the peers still resolve each other.
#[test]
fn arp_divert_and_reinject() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    sh(&format!("ip neigh flush dev {HOST_IF}"));
    sh(&format!(
        "ip netns exec {NETNS} ip neigh flush dev {PEER_IF}"
    ));
    let h = open("arp", Layer::Ethernet, 0, Flags::NONE);
    let (ok, got) = forwarding(&h, |_, _| {}, || ping(2));
    assert!(ok);
    let op = |p: &[u8]| u16::from_be_bytes([p[20], p[21]]);
    assert!(got.iter().any(|(p, a)| op(p) == 1 && a.outbound), "{got:?}");
    assert!(
        got.iter().any(|(p, a)| op(p) == 2 && !a.outbound),
        "{got:?}"
    );
}

/// 802.1Q tags, with the offloads on and off: the filter sees them in the kernel (exactly),
/// the frames come with the tag in place, and diverted tagged frames go back out and in.
#[test]
fn vlan_tags() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    vlan_link((HOST_IF, PEER_IF), ("avt0.10", "avt1.10"), "id 10", 10);
    let peer = "10.199.10.2";
    assert!(ping_to(peer, 1));
    for offload in [true, false] {
        vlan_offload(offload);
        for filter in ["vlan.id == 10 and icmp", "eth.type == 0x8100 and icmp"] {
            assert!(exact_at(filter, Layer::Ethernet), "{filter}");
            let h = open(filter, Layer::Ethernet, 0, Flags::SNIFF);
            assert!(ping_to(peer, 2));
            let got = drain(&h);
            assert_eq!(got.len(), 4, "{filter}, offload {offload}: {got:?}");
            for (p, a) in &got {
                assert_eq!(&p[12..14], &[0x81, 0x00], "{p:02x?}");
                assert_eq!(u16::from_be_bytes([p[14], p[15]]) & 0xfff, 10);
                assert!(a.vlan && a.vlan_tci & 0xfff == 10);
            }
            assert!(got.iter().any(|(_, a)| a.outbound) && got.iter().any(|(_, a)| !a.outbound));
        }
        let h = open("vlan.id == 10 and icmp", Layer::Ethernet, 0, Flags::NONE);
        let (ok, got) = forwarding(&h, |_, _| {}, || ping_to(peer, 3));
        assert!(ok, "offload {offload}");
        assert_eq!(got.len(), 6, "offload {offload}: {got:?}");
    }
}

/// An 802.1ad tag outside an 802.1Q one (QinQ), with the offloads on and off.
#[test]
fn qinq() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    vlan_link(
        (HOST_IF, PEER_IF),
        ("avt0.20", "avt1.20"),
        "proto 802.1ad id 20",
        30,
    );
    vlan_link(("avt0.20", "avt1.20"), ("avt0.21", "avt1.21"), "id 21", 21);
    let peer = "10.199.21.2";
    assert!(ping_to(peer, 1));
    for offload in [true, false] {
        vlan_offload(offload);
        let filter = "ieee8021ad.id == 20 and vlan.id == 21 and icmp";
        assert!(exact_at(filter, Layer::Ethernet));
        let h = open(filter, Layer::Ethernet, 0, Flags::SNIFF);
        assert!(ping_to(peer, 2));
        let got = drain(&h);
        assert_eq!(got.len(), 4, "offload {offload}: {got:?}");
        for (p, _) in &got {
            assert_eq!(
                (&p[12..14], &p[16..18]),
                (&[0x88, 0xa8][..], &[0x81, 0x00][..])
            );
        }
        let h = open(filter, Layer::Ethernet, 0, Flags::NONE);
        let (ok, got) = forwarding(&h, |_, _| {}, || ping_to(peer, 2));
        assert!(ok && got.len() == 4, "offload {offload}: {got:?}");
    }
}

/// A frame changed on its way: the host's ARP replies say another MAC address, and the peer
/// believes them.
#[test]
fn modify_source_mac() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    let fake = [2, 0, 0, 0, 0, 0x99];
    let h = open(
        "arp.opcode == reply and outbound",
        Layer::Ethernet,
        0,
        Flags::NONE,
    );
    sh(&format!(
        "ip netns exec {NETNS} ip neigh flush dev {PEER_IF}"
    ));
    let edit = |p: &mut Vec<u8>, _: &mut Address| {
        p[6..12].copy_from_slice(&fake);
        p[22..28].copy_from_slice(&fake);
    };
    let (_, got) = forwarding(&h, edit, || {
        sh(&format!("ip netns exec {NETNS} ping -c 1 -W 1 {HOST}"))
    });
    assert!(!got.is_empty());
    let neigh = output(&format!("ip netns exec {NETNS} ip neigh show {HOST}"));
    assert!(neigh.contains("02:00:00:00:00:99"), "{neigh}");
}

/// Non-IP frames injected inbound: an LLDP frame reaches the interface, and an ARP request
/// gets the host's reply.
#[test]
fn inject_inbound_frames() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    // A handle sees what handles of a higher priority inject, as impostors.
    let send = open("eth", Layer::Ethernet, 100, Flags::SEND_ONLY);
    let sniff = open(
        "eth.type == 0x88cc or arp",
        Layer::Ethernet,
        0,
        Flags::SNIFF,
    );
    let mut addr = Address::new(Layer::Ethernet);
    addr.if_idx = Veth::ifindex();
    let me = [2, 0, 0, 0, 0, 0x77];
    let mut lldp = vec![0x01, 0x80, 0xc2, 0, 0, 0x0e];
    lldp.extend(me);
    lldp.extend([0x88, 0xcc]);
    // Chassis ID, port ID, TTL, end.
    lldp.extend([
        0x02, 0x07, 0x04, 2, 0, 0, 0, 0, 0x77, 0x04, 0x02, 0x07, b'1',
    ]);
    lldp.extend([0x06, 0x02, 0, 120, 0, 0]);
    lldp.resize(60, 0);
    send.send(&lldp, &addr).unwrap();
    let mac: Vec<u8> = output(&format!("cat /sys/class/net/{HOST_IF}/address"))
        .trim()
        .split(':')
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect();
    let mut arp = vec![0xff; 6];
    arp.extend(me);
    arp.extend([0x08, 0x06, 0, 1, 8, 0, 6, 4, 0, 1]);
    arp.extend(me);
    arp.extend([10, 199, 0, 77, 0, 0, 0, 0, 0, 0, 10, 199, 0, 1]);
    arp.resize(60, 0);
    send.send(&arp, &addr).unwrap();
    let got = drain(&sniff);
    assert!(
        got.iter()
            .any(|(p, a)| p == &lldp && !a.outbound && a.impostor),
        "{got:?}"
    );
    // The host answers the made-up peer.
    assert!(
        got.iter().any(|(p, a)| a.outbound
            && p[12..14] == [8, 6]
            && p[20..22] == [0, 2]
            && p[..6] == me
            && p[6..12] == mac[..]),
        "{got:?}"
    );
}

// The rest of ebpfdivert's packet-layer scenarios (Step 12).

/// A handle on `lo` only.
fn open_lo(filter: &str) -> Handle {
    OpenOptions::new()
        .interfaces(["lo"])
        .open(filter, Layer::Network)
        .unwrap_or_else(|e| panic!("opening `{filter}`: {e}"))
}

/// Whether nothing reaches `s` within 300 ms.
fn nothing(s: &UdpSocket) -> bool {
    s.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let quiet = s.recv_from(&mut [0; 64]).is_err();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    quiet
}

fn timeout(h: &Handle, ms: u64) -> bool {
    let mut buf = vec![0; MAX_PACKET_LEN];
    matches!(
        h.recv_timeout(&mut buf, Duration::from_millis(ms)),
        Err(Error::Timeout)
    )
}

/// A loopback datagram, IPv4 then IPv6, is held until the handle sends it back, and seen once
/// (on `lo`'s egress, not again on its ingress).
#[test]
fn loopback_single_sighting() {
    if !enabled() {
        return;
    }
    let h = open_lo("udp.dstport == 7003");
    let mut buf = vec![0; MAX_PACKET_LEN];
    for (to, from) in [("127.0.0.1:7003", "127.0.0.1:0"), ("[::1]:7003", "[::1]:0")] {
        let server = udp_socket(to);
        udp_socket(from).send_to(b"hello-lo", to).unwrap();
        let (n, addr) = h.recv_timeout(&mut buf, Duration::from_secs(1)).unwrap();
        assert!(addr.outbound && addr.loopback && !addr.impostor && !addr.sniffed);
        assert_eq!(addr.ipv6, to.starts_with('['));
        assert!(nothing(&server), "delivered before it was sent back");
        h.send(&buf[..n], &addr).unwrap();
        let mut data = [0; 64];
        let (m, _) = server
            .recv_from(&mut data)
            .expect("the datagram, sent back");
        assert_eq!(&data[..m], b"hello-lo");
        assert!(timeout(&h, 300), "seen twice");
    }
}

/// `tcp.port` takes both directions of a connection: the handshake, the data and the end.
#[test]
fn tcp_both_directions() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    let _peer = PeerServer::start();
    let h = open(
        &format!("tcp.port == {SINK_PORT}"),
        Layer::Network,
        0,
        Flags::NONE,
    );
    let (reply, got) = forwarding(
        &h,
        |_, _| {},
        || {
            let mut s = TcpStream::connect((PEER, SINK_PORT)).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            s.write_all(b"ping").unwrap();
            s.shutdown(NetShutdown::Write).unwrap();
            let mut reply = String::new();
            s.read_to_string(&mut reply).unwrap();
            reply
        },
    );
    assert_eq!(reply, format!("4 {:08x}", fnv(FNV_START, *b"ping")));
    // The TCP flags, and whether there is a payload (IPv4 without options, TCP's offset); the
    // FINs may carry data or not.
    let seen = |outbound: bool, flags: u8, data: Option<bool>| {
        got.iter().any(|(p, a)| {
            a.outbound == outbound
                && p[33] & flags == flags
                && data.is_none_or(|d| (p.len() > 20 + (p[32] >> 4) as usize * 4) == d)
        })
    };
    for (outbound, flags, data, what) in [
        (true, 0x02, Some(false), "SYN"),
        (false, 0x12, Some(false), "SYN-ACK"),
        (true, 0x10, Some(true), "data out"),
        (false, 0x10, Some(true), "data in"),
        (true, 0x01, None, "FIN out"),
        (false, 0x01, None, "FIN in"),
    ] {
        assert!(seen(outbound, flags, data), "no {what} among {got:?}");
    }
}

/// An inbound datagram on the veth is held until the handle sends it back (through `lo`'s
/// redirect), then delivered.
#[test]
fn inbound_udp() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    let _peer = PeerServer::start();
    let h = open(
        &format!("inbound and udp.srcport == {ECHO_PORT}"),
        Layer::Network,
        0,
        Flags::NONE,
    );
    let s = udp_socket(&format!("{HOST}:0"));
    s.send_to(b"hello-inbound", (PEER, ECHO_PORT)).unwrap();
    let mut buf = vec![0; MAX_PACKET_LEN];
    let (n, addr) = h.recv_timeout(&mut buf, Duration::from_secs(2)).unwrap();
    assert!(!addr.outbound && !addr.loopback && addr.if_idx == Veth::ifindex());
    assert!(nothing(&s), "delivered before it was sent back");
    h.send(&buf[..n], &addr).unwrap();
    let mut data = [0; 64];
    let (m, from) = s.recv_from(&mut data).expect("the echo, sent back");
    assert_eq!(
        (&data[..m], from.to_string()),
        (&b"hello-inbound"[..], format!("{PEER}:{ECHO_PORT}"))
    );
}

/// Handles of priority 0 run in the order they were opened: the second sees a packet only once
/// the first has sent it back, as an impostor, and the first does not see it again.
#[test]
fn auto_priority() {
    if !enabled() {
        return;
    }
    let first = open_lo("udp.dstport == 7004");
    let second = open_lo("udp.dstport == 7004");
    let server = udp_socket("127.0.0.1:7004");
    udp_socket("127.0.0.1:0")
        .send_to(b"auto", "127.0.0.1:7004")
        .unwrap();
    let mut buf = vec![0; MAX_PACKET_LEN];
    assert!(timeout(&second, 300), "the second handle ran first");
    let (n, a) = first
        .recv_timeout(&mut buf, Duration::from_secs(1))
        .unwrap();
    assert!(!a.impostor);
    first.send(&buf[..n], &a).unwrap();
    assert!(timeout(&first, 300), "the first handle saw its own packet");
    let (n, a) = second
        .recv_timeout(&mut buf, Duration::from_secs(1))
        .unwrap();
    assert!(a.impostor);
    second.send(&buf[..n], &a).unwrap();
    let mut data = [0; 64];
    let (m, _) = server.recv_from(&mut data).expect("the datagram");
    assert_eq!(&data[..m], b"auto");
}

/// The queue parameters: a handle keeps at most QUEUE_LENGTH packets and QUEUE_SIZE bytes, and
/// drops what waited longer than QUEUE_TIME. After `shutdown(Send)`, it cannot send.
#[test]
fn queue_limits() {
    if !enabled() {
        return;
    }
    let h = open_lo("udp.dstport == 7005");
    for p in Param::ALL {
        assert_eq!(h.param(p), p.default_value());
    }
    assert!(matches!(
        h.set_param(Param::QueueLength, 1),
        Err(Error::InvalidArgument(_))
    ));
    h.set_param(Param::QueueLength, 32).unwrap();
    assert_eq!(h.param(Param::QueueLength), 32);
    let c = udp_socket("127.0.0.1:0");
    let flood = |n: usize, len: usize| {
        for _ in 0..n {
            c.send_to(&vec![b'x'; len], "127.0.0.1:7005").unwrap();
        }
        thread::sleep(Duration::from_millis(200));
    };
    flood(100, 5);
    assert_eq!(drain(&h).len(), 32);

    // 8 packets of 8,028 bytes fit in 65,535.
    h.set_param(Param::QueueLength, 4096).unwrap();
    h.set_param(Param::QueueSize, 65_535).unwrap();
    flood(10, 8000);
    assert_eq!(drain(&h).len(), 8);

    // The timestamp is the capture's: these waited in the ring buffer.
    h.set_param(Param::QueueTime, 100).unwrap();
    flood(3, 5);
    thread::sleep(Duration::from_millis(200));
    assert!(timeout(&h, 0));

    h.shutdown(Shutdown::Send).unwrap();
    let mut addr = Address::new(Layer::Network);
    addr.outbound = true;
    let pkt = udp_packet("127.0.0.1", 5555, "127.0.0.1", 7005, b"late");
    assert!(matches!(h.send(&pkt, &addr), Err(Error::Shutdown)));
}

/// A `recv` blocked in another thread returns once the handle is shut down. (WinDivert's test
/// closes the handle under the receiver; a Rust handle cannot be closed while it is borrowed.)
#[test]
fn shutdown_wakes_blocked_recv() {
    if !enabled() {
        return;
    }
    let h = open_lo("udp.dstport == 7006");
    thread::scope(|s| {
        let t = s.spawn(|| {
            let mut buf = vec![0; MAX_PACKET_LEN];
            h.recv(&mut buf).map(|(n, _)| n)
        });
        thread::sleep(Duration::from_millis(200));
        h.shutdown(Shutdown::Both).unwrap();
        assert!(matches!(t.join().unwrap(), Err(Error::Shutdown)));
    });
    h.close().unwrap();
}

/// What the backend refuses (the handle's own checks run on a fake backend, in `src/tests.rs`,
/// and again here through the real one), and that a refused open leaves nothing behind.
#[test]
fn bad_arguments() {
    if !enabled() {
        return;
    }
    let open_on = |ifname: &str| {
        OpenOptions::new()
            .interfaces([ifname])
            .open("true", Layer::Network)
    };
    assert!(matches!(
        open_on("no-such-if0"),
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound
    ));
    sh("ip link del avtun0");
    assert!(sh("ip tuntap add dev avtun0 mode tun") && sh("ip link set avtun0 up"));
    let tun = open_on("avtun0");
    sh("ip link del avtun0");
    assert!(matches!(tun, Err(Error::Unsupported(_))));
    assert!(matches!(
        Handle::open("tcp and (", Layer::Network, 0, Flags::NONE),
        Err(Error::Filter(_))
    ));
    assert!(matches!(
        Handle::open("true", Layer::Network, 31_000, Flags::NONE),
        Err(Error::InvalidArgument(_))
    ));
    assert!(matches!(
        Handle::open("true", Layer::Network, 0, Flags::SNIFF | Flags::DROP),
        Err(Error::InvalidArgument(_))
    ));
    for dir in ["ingress", "egress"] {
        assert!(!output(&format!("tc filter show dev lo {dir}")).contains("avulse"));
    }
    assert_eq!(avulse::cleanup().unwrap(), 0);
}

const FWD_NS: [&str; 2] = ["avulse-fwd1", "avulse-fwd2"];
const FWD_IFS: [&str; 2] = ["avf1", "avf2"];

/// Two namespaces, 10.198.1.2 and 10.198.2.2, routed through this host (`ip_forward` on), removed
/// when dropped.
struct Routed(String);

impl Routed {
    fn new() -> Routed {
        Routed::remove();
        let forward = output("sysctl -n net.ipv4.ip_forward").trim().to_owned();
        for i in 0..2 {
            let (ns, dev, net) = (FWD_NS[i], FWD_IFS[i], i + 1);
            for cmd in [
                format!("ip netns add {ns}"),
                format!("ip link add {dev} type veth peer name {dev}p"),
                format!("ip link set {dev}p netns {ns}"),
                format!("ip addr add 10.198.{net}.1/24 dev {dev}"),
                format!("ip link set {dev} up"),
                format!("ip netns exec {ns} ip addr add 10.198.{net}.2/24 dev {dev}p"),
                format!("ip netns exec {ns} ip link set {dev}p up"),
                format!("ip netns exec {ns} ip route add default via 10.198.{net}.1"),
            ] {
                assert!(sh(&cmd), "{cmd}");
            }
        }
        assert!(sh("sysctl -qw net.ipv4.ip_forward=1"));
        let routed = Routed(forward);
        assert!(routed.ping(1), "the routed namespaces do not work");
        routed
    }

    /// Pings the second namespace from the first.
    fn ping(&self, count: u32) -> bool {
        sh(&format!(
            "ip netns exec {} ping -c {count} -i 0.2 -W 1 10.198.2.2",
            FWD_NS[0]
        ))
    }

    fn remove() {
        for i in 0..2 {
            sh(&format!("ip link del {}", FWD_IFS[i]));
            sh(&format!("ip netns del {}", FWD_NS[i]));
        }
    }
}

impl Drop for Routed {
    fn drop(&mut self) {
        Routed::remove();
        sh(&format!("sysctl -qw net.ipv4.ip_forward={}", self.0));
    }
}

/// Packets routed between two namespaces are at the NETWORK_FORWARD layer only, where a handle
/// diverts them and sends them on.
#[test]
fn forward_layer() {
    if !enabled() {
        return;
    }
    let routed = Routed::new();
    let local = OpenOptions::new()
        .flags(Flags::SNIFF)
        .interfaces(FWD_IFS)
        .open("icmp", Layer::Network)
        .unwrap();
    let h = OpenOptions::new()
        .interfaces(FWD_IFS)
        .open("icmp and ip.dst == 10.198.2.2", Layer::NetworkForward)
        .unwrap();
    h.set_param(Param::QueueTime, 16_000).unwrap();
    let (ok, got) = forwarding(&h, |_, _| {}, || routed.ping(3));
    assert!(ok);
    assert_eq!(got.len(), 3, "{got:?}");
    assert!(got.iter().all(|(p, a)| {
        a.layer == Layer::NetworkForward
            && a.if_idx == ifindex(FWD_IFS[1])
            && icmp(p) == (8, "10.198.2.2".to_owned())
    }));
    assert!(
        drain(&local).is_empty(),
        "the NETWORK layer saw forwarded packets"
    );
    // Diverted and not sent back, they do not arrive.
    assert!(!routed.ping(2));
    assert_eq!(drain(&h).len(), 2);
}

/// On real traffic, what runs in the kernel (exactly, or as a superset that user space narrows)
/// agrees with the evaluator: each handle receives the packets of a catch-all handle that its
/// filter matches.
#[test]
fn kernel_agrees_with_evaluator() {
    if !enabled() {
        return;
    }
    const FILTERS: &[&str] = &[
        "icmp",
        "udp",
        "tcp.flags.syn == 1",
        "outbound",
        "inbound and tcp",
        "ip.len > 100",
        "frame.len <= 60",
        "tcp.options.mss_val >= 1000",
        "tcp.len > 0",
        "tcp.payload[0:4] == 47:45:54:20",
        "icmp.type == 8 or udp.dstport == 9001",
        "tcp.srcport == 9002",
        "not (icmp or tcp.flags.ack == 1)",
        "len(tcp.payload) > 10",
        "udp.length > 100",
        "tcp.port in {9002 9003} and tcp.flags.fin == 1",
        "ip.src == 10.199.0.0/24 and not ip.dst == 10.199.0.1",
        // Inexact.
        "udp.payload contains \"hello\"",
        "(outbound xor timestamp < 0) and udp",
        "icmp.seq == 1",
    ];
    let _veth = Veth::new();
    let _peer = PeerServer::start();
    let all = open("ip.addr == 10.199.0.2", Layer::Network, 0, Flags::SNIFF);
    let handles: Vec<Handle> = FILTERS
        .iter()
        .map(|f| open(f, Layer::Network, 0, Flags::SNIFF))
        .collect();
    for h in std::iter::once(&all).chain(&handles) {
        h.set_param(Param::QueueTime, 16_000).unwrap();
    }

    assert!(ping(2));
    let s = udp_socket(&format!("{HOST}:0"));
    for payload in [&b"hello"[..], &[b'u'; 300]] {
        s.send_to(payload, (PEER, ECHO_PORT)).unwrap();
        s.recv_from(&mut [0; 512]).expect("the echo");
    }
    let mut t = TcpStream::connect((PEER, SINK_PORT)).unwrap();
    t.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    t.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    t.shutdown(NetShutdown::Write).unwrap();
    t.read_to_string(&mut String::new()).unwrap();
    drop(t);
    thread::sleep(Duration::from_millis(200));

    let seen = drain(&all);
    assert!(seen.len() > 15, "{seen:?}");
    let mut exact_ones = 0;
    for (f, h) in FILTERS.iter().zip(&handles) {
        let filter = Filter::compile(f).unwrap();
        let mut want: Vec<Vec<u8>> = seen
            .iter()
            .filter(|(p, a)| filter.matches(&Packet::parse(p, Link::Ip), &a.meta()))
            .map(|(p, _)| p.clone())
            .collect();
        // Only the peer's traffic: the host end sends IPv6 neighbour discovery too.
        let mut got: Vec<Vec<u8>> = drain(h)
            .into_iter()
            .map(|(p, _)| p)
            .filter(|p| {
                Packet::parse(p, Link::Ip)
                    .ipv4()
                    .is_some_and(|ip| [ip.src(), ip.dst()].contains(&PEER.parse().unwrap()))
            })
            .collect();
        want.sort();
        got.sort();
        assert!(
            !want.is_empty() && want.len() < seen.len(),
            "`{f}` does not split the traffic"
        );
        assert!(
            got == want,
            "`{f}`: the handle got {} packets, the evaluator matches {}",
            got.len(),
            want.len()
        );
        exact_ones += usize::from(exact(f));
    }
    eprintln!(
        "{} filters agree on {} packets, {exact_ones} of them exact in the kernel",
        FILTERS.len(),
        seen.len()
    );
}
