//! The Linux backend on real traffic: a veth pair with one end in a network namespace, and
//! `ping` across it.
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

use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Stdio};
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
        std::fs::read_to_string(format!("/sys/class/net/{HOST_IF}/ifindex"))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }
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

fn exact(filter: &str) -> bool {
    avulse_ebpf::codegen::compile(Filter::compile(filter).unwrap().ir()).is_ok()
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

/// Filters the code generator cannot compile take every packet of the layer in the kernel, and
/// user space keeps the matching ones.
#[test]
fn user_space_filters() {
    if !enabled() {
        return;
    }
    let _veth = Veth::new();
    let filter = format!("{PINGS} and outbound");
    assert!(!exact(&filter));
    assert!(matches!(
        OpenOptions::new()
            .interfaces([HOST_IF])
            .open(&filter, Layer::Network),
        Err(Error::Unsupported(_))
    ));
    let h = open(&filter, Layer::Network, 0, Flags::SNIFF);
    assert!(ping(3));
    let got = drain(&h);
    assert_eq!(got.len(), 3, "{got:?}");
    assert!(got.iter().all(|(p, a)| a.outbound && icmp(p).0 == 8));
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
