//! The TC programs in a real kernel, through `BPF_PROG_TEST_RUN`:
//!
//! - the programs compute the facts `Facts::from_packet` (and `Facts::at_network`) describes;
//! - the verifier accepts every generated matcher, and the verdicts agree with the IR evaluator,
//!   at the ETHERNET and NETWORK layers;
//! - capture: records in the ring buffer, divert, sniff and drop, marks and priorities,
//!   loopback, the NETWORK_FORWARD split, fragments, and failing open;
//! - the redirect of inbound packets injected through `lo`.
//!
//! It needs root, so it runs only with `AVULSE_BPF=1`, in the Vagrant VMs:
//!
//! ```text
//! cargo test -p avulse-ebpf --test kernel --no-run   # on the host; prints the binary's path
//! vagrant up default
//! vagrant ssh default -c "sudo AVULSE_BPF=1 /vagrant/target/debug/deps/kernel-… --nocapture --test-threads=1"
//! vagrant destroy -f default
//! ```

#![cfg(target_os = "linux")]

mod common;

use avulse_ebpf::abi::{self, Config, EventRecord, Record, stat};
use avulse_ebpf::codegen;
use avulse_ebpf::facts::{
    F_IPV4, F_IPV6, F_UDP, Facts, M_FORWARD, M_IMPOSTOR, M_LOOPBACK, M_OUTBOUND, M_SNIFFED,
};
use avulse_ebpf::loader::{self, Classifier, EventHook, Events, Hook, SkbCtx};
use avulse_filter::{Event, Filter, Layer};
use avulse_proto::{Link, Packet};

const TC_ACT_SHOT: i32 = 2;
const EVENT_FLOW_ESTABLISHED: u8 = Event::FlowEstablished as u8;
const EVENT_FLOW_DELETED: u8 = Event::FlowDeleted as u8;
const EVENT_SOCKET_BIND: u8 = Event::SocketBind as u8;
const EVENT_SOCKET_CONNECT: u8 = Event::SocketConnect as u8;
const EVENT_SOCKET_LISTEN: u8 = Event::SocketListen as u8;
const EVENT_SOCKET_ACCEPT: u8 = Event::SocketAccept as u8;
const EVENT_SOCKET_CLOSE: u8 = Event::SocketClose as u8;
const TC_ACT_STOLEN: i32 = 4;
const TC_ACT_REDIRECT: i32 = 7;
const TC_ACT_UNSPEC: i32 = -1;

/// The device `BPF_PROG_TEST_RUN` uses when the context names none: the loopback device.
const TEST_DEV: u32 = 1;

fn enabled() -> bool {
    if std::env::var_os("AVULSE_BPF").is_some() {
        return true;
    }
    eprintln!("skipped: set AVULSE_BPF=1 and run as root (in a VM) to load BPF programs");
    false
}

/// Runs on CPU 0, so that the per-CPU facts of the last run are at index 0.
fn pin_to_cpu0() {
    // SAFETY: plain system call on a zeroed, then initialised, `cpu_set_t`.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(0, &mut set);
        assert_eq!(
            libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &set),
            0
        );
    }
}

/// `CLOCK_MONOTONIC` in nanoseconds: the clock of `bpf_ktime_get_ns`.
fn monotonic_ns() -> u64 {
    // SAFETY: plain system call with a valid out-pointer.
    unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        assert_eq!(libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts), 0);
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }
}

/// `processed N insns` from the verifier's statistics.
fn processed(log: &str) -> usize {
    log.split("processed ")
        .nth(1)
        .and_then(|s| s.split(' ').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

fn config(layer: Layer, flags: u32) -> Config {
    Config {
        layer: layer as u8,
        flags,
        // The test device is the loopback device; 0 makes it an ordinary one.
        lo_ifindex: 0,
        ..Config::default()
    }
}

fn classifier(filter: &str, config: &Config) -> Classifier {
    let mut tc = Classifier::load().expect("load the TC object");
    tc.set_config(config).unwrap();
    let f = Filter::compile(filter).unwrap();
    let layer = match config.layer {
        5 => Layer::Ethernet,
        1 => Layer::NetworkForward,
        _ => Layer::Network,
    };
    tc.set_matcher(&codegen::compile(f.ir(), &common::env(layer)).unwrap())
        .unwrap_or_else(|e| panic!("{filter}: {e}"));
    tc
}

fn dns() -> Vec<u8> {
    common::eth(
        &[],
        0x0800,
        &common::ipv4(
            &common::Ip4 {
                proto: 17,
                ..Default::default()
            },
            &common::udp(40000, 53, b"\x12\x34\x01\x00"),
        ),
    )
}

fn web() -> Vec<u8> {
    common::eth(
        &[],
        0x0800,
        &common::ipv4(
            &common::Ip4::default(),
            &common::tcp(40000, 443, 0x18, 0, b"GET /"),
        ),
    )
}

#[test]
fn kernel_agrees_with_the_evaluator() {
    if !enabled() {
        return;
    }
    pin_to_cpu0();
    let mut tc = Classifier::load().expect("load the TC object");
    // `avulse_options` finds the TCP options when the configuration asks for them.
    let opts = abi::CFG_TCP_OPTIONS;
    tc.set_config(&config(Layer::Ethernet, abi::CFG_DROP | opts))
        .unwrap();
    let frames: Vec<_> = common::corpus(1, 3000, 14)
        .into_iter()
        .filter(|f| common::test_runnable(f))
        .collect();

    // Without a matcher every packet passes, and the facts are `Facts::from_packet`'s.
    let base = tc.stats().unwrap()[stat::NO_MATCHER];
    for frame in &frames {
        assert_eq!(tc.run(frame).unwrap(), TC_ACT_UNSPEC);
        let want = Facts {
            layer: Layer::Ethernet as u8,
            ifindex: TEST_DEV,
            ..Facts::from_packet(&Packet::parse(frame, Link::Ethernet))
        };
        assert_eq!(tc.facts(0).unwrap(), want, "facts of {frame:02x?}");
    }
    assert_eq!(
        tc.stats().unwrap()[stat::NO_MATCHER] - base,
        frames.len() as u64
    );
    // At the NETWORK layer, IP packets get `Facts::at_network`; the rest never reaches the
    // matcher.
    tc.set_config(&config(
        Layer::Network,
        abi::CFG_DROP | abi::CFG_FRAGMENTS | opts,
    ))
    .unwrap();
    let mut ip_frames = 0;
    for frame in &frames {
        assert_eq!(tc.run(frame).unwrap(), TC_ACT_UNSPEC);
        let eth = Facts::from_packet(&Packet::parse(frame, Link::Ethernet));
        if eth.flags & (F_IPV4 | F_IPV6) == 0 {
            continue;
        }
        let want = Facts {
            layer: Layer::Network as u8,
            ifindex: TEST_DEV,
            ..eth.at_network()
        };
        assert_eq!(tc.facts(0).unwrap(), want, "NETWORK facts of {frame:02x?}");
        ip_frames += 1;
    }
    eprintln!(
        "facts: {} frames agree, {ip_frames} of them at NETWORK too",
        frames.len()
    );

    let cases: usize = std::env::var("AVULSE_EBPF_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let mut rng = common::Rng::new(5);
    let mut filters: Vec<String> = common::SUPPORTED.iter().map(|s| s.to_string()).collect();
    filters.extend((0..cases).map(|_| common::random_filter(&mut rng, common::SUPPORTED, 4)));
    let (mut most_insns, mut most_processed, mut runs) = (0, (0, String::new()), 0);
    let verdict = |m: bool| if m { TC_ACT_SHOT } else { TC_ACT_UNSPEC };
    for (i, src) in filters.iter().enumerate() {
        let filter = Filter::compile(src).unwrap();
        let mut load = |tc: &mut Classifier, layer: Layer| {
            let m = codegen::compile(filter.ir(), &common::env(layer)).unwrap();
            let stats = tc.set_matcher(&m).unwrap_or_else(|e| panic!("{src}: {e}"));
            most_insns = most_insns.max(stats.insns);
            let p = processed(&stats.log);
            if p > most_processed.0 {
                most_processed = (p, src.clone());
            }
            if m.reads_tcp_options() { opts } else { 0 }
        };
        // Packets of `BPF_PROG_TEST_RUN` arrive on the loopback device (ingress, not marked as
        // loopback, since the configuration names no loopback device).
        let o = load(&mut tc, Layer::Ethernet);
        tc.set_config(&config(Layer::Ethernet, abi::CFG_DROP | o))
            .unwrap();
        let meta = common::meta(Layer::Ethernet, 0, TEST_DEV);
        for frame in &frames {
            let pkt = Packet::parse(frame, Link::Ethernet);
            let want = verdict(filter.matches(&pkt, &meta));
            assert_eq!(tc.run(frame).unwrap(), want, "{src} on {frame:02x?}");
            runs += 1;
        }
        // The NETWORK layer for the hand-written filters and a third of the random ones.
        if i >= common::SUPPORTED.len() && i % 3 != 0 {
            continue;
        }
        let o = load(&mut tc, Layer::Network);
        tc.set_config(&config(
            Layer::Network,
            abi::CFG_DROP | abi::CFG_FRAGMENTS | o,
        ))
        .unwrap();
        let meta = common::meta(Layer::Network, 0, TEST_DEV);
        for frame in &frames {
            let eth = Facts::from_packet(&Packet::parse(frame, Link::Ethernet));
            let want = if eth.flags & (F_IPV4 | F_IPV6) == 0 {
                TC_ACT_UNSPEC
            } else {
                let ip = Packet::parse(&frame[eth.l3 as usize..], Link::Ip);
                verdict(filter.matches(&ip, &meta))
            };
            assert_eq!(
                tc.run(frame).unwrap(),
                want,
                "{src} at NETWORK on {frame:02x?}"
            );
            runs += 1;
        }
    }
    eprintln!(
        "verdicts: {} filters, {runs} runs agree; largest matcher {most_insns} instructions; \
         most verifier work {} instructions processed, for {}",
        filters.len(),
        most_processed.0,
        most_processed.1
    );
}

#[test]
fn diverted_packets_reach_the_ring() {
    if !enabled() {
        return;
    }
    let mut tc = classifier("udp.dstport == 53", &config(Layer::Ethernet, 0));
    let before = monotonic_ns();
    let frame = dns();
    assert_eq!(
        tc.run_on(Hook::Egress, &frame, &SkbCtx::default()).unwrap(),
        TC_ACT_STOLEN
    );
    assert_eq!(tc.run(&web()).unwrap(), TC_ACT_UNSPEC);
    let records = tc.records();
    assert_eq!(records.len(), 1);
    let r = Record::parse(&records[0]).unwrap();
    assert_eq!(r.data, frame);
    assert_eq!(r.len as usize, frame.len());
    assert_eq!((r.l3, r.ifindex, r.ingress_ifindex), (14, TEST_DEV, 0));
    assert_eq!((r.meta, r.layer), (M_OUTBOUND, Layer::Ethernet as u8));
    assert_eq!(r.flags as u32 & (F_IPV4 | F_UDP), F_IPV4 | F_UDP);
    assert!(r.timestamp >= before && r.timestamp <= monotonic_ns());
    assert_eq!(tc.stats().unwrap()[stat::DIVERTED], 1);

    // Records in the 16 KiB class; the larger class needs packets BPF_PROG_TEST_RUN refuses.
    let big = common::eth(
        &[],
        0x0800,
        &common::ipv4(
            &common::Ip4 {
                proto: 17,
                ..Default::default()
            },
            &common::udp(40000, 53, &[0x5a; 3000]),
        ),
    );
    assert_eq!(tc.run(&big).unwrap(), TC_ACT_STOLEN);
    let records = tc.records();
    let r = Record::parse(&records[0]).unwrap();
    assert_eq!(r.data, big);
    assert_eq!(r.meta, 0);

    // At the NETWORK layer the record still holds the whole frame; `l3` says where IP starts.
    let mut tc = classifier("ipv6", &config(Layer::Network, 0));
    let v6 = common::eth(
        &[(0x8100, 7)],
        0x86dd,
        &common::ipv6(17, &[], 0, &common::udp(1, 2, b"x")),
    );
    assert_eq!(tc.run(&v6).unwrap(), TC_ACT_STOLEN);
    let records = tc.records();
    let r = Record::parse(&records[0]).unwrap();
    assert_eq!((r.l3, r.layer, r.data), (18, Layer::Network as u8, &v6[..]));
    assert_ne!(r.flags as u32 & F_IPV6, 0);
}

#[test]
fn sniff_and_drop() {
    if !enabled() {
        return;
    }
    let mut tc = classifier("udp", &config(Layer::Network, abi::CFG_SNIFF));
    let frame = dns();
    assert_eq!(tc.run(&frame).unwrap(), TC_ACT_UNSPEC);
    let records = tc.records();
    let r = Record::parse(&records[0]).unwrap();
    assert_eq!((r.meta, r.data), (M_SNIFFED, &frame[..]));
    assert_eq!(tc.stats().unwrap()[stat::SNIFFED], 1);

    // A sniffed copy can be cut short; `len` keeps the packet's length.
    tc.set_config(&Config {
        snaplen: 20,
        ..config(Layer::Network, abi::CFG_SNIFF)
    })
    .unwrap();
    assert_eq!(tc.run(&frame).unwrap(), TC_ACT_UNSPEC);
    let records = tc.records();
    let r = Record::parse(&records[0]).unwrap();
    assert_eq!((r.data, r.len as usize), (&frame[..20], frame.len()));

    tc.set_config(&config(Layer::Network, abi::CFG_DROP))
        .unwrap();
    assert_eq!(tc.run(&frame).unwrap(), TC_ACT_SHOT);
    assert_eq!(tc.run(&web()).unwrap(), TC_ACT_UNSPEC);
    assert!(tc.records().is_empty());
    assert_eq!(tc.stats().unwrap()[stat::DROPPED], 1);
}

#[test]
fn marks_and_priorities() {
    if !enabled() {
        return;
    }
    let mut tc = classifier(
        "udp",
        &Config {
            priority: 100,
            ..config(Layer::Network, 0)
        },
    );
    let frame = dns();
    let run = |tc: &Classifier, mark| {
        tc.run_on(
            Hook::Ingress,
            &frame,
            &SkbCtx {
                mark,
                ..SkbCtx::default()
            },
        )
        .unwrap()
    };
    // Injected by a handle of the same or a lower priority (TC priority 100 or more): skipped.
    assert_eq!(run(&tc, abi::MARK_INJECTED | 100), TC_ACT_UNSPEC);
    assert_eq!(run(&tc, abi::MARK_INJECTED | 150), TC_ACT_UNSPEC);
    // Inbound injections on their way through lo are redirected (`injected_inbound_is_redirected`).
    assert!(tc.records().is_empty());
    // Injected by a higher-priority handle: seen, as an impostor.
    assert_eq!(run(&tc, abi::MARK_INJECTED | 50), TC_ACT_STOLEN);
    let records = tc.records();
    assert_eq!(Record::parse(&records[0]).unwrap().meta, M_IMPOSTOR);
    assert_eq!(tc.stats().unwrap()[stat::IMPOSTOR], 1);
    // Other marks are not ours.
    assert_eq!(run(&tc, 0x4d49_0064), TC_ACT_STOLEN);
    let records = tc.records();
    assert_eq!(Record::parse(&records[0]).unwrap().meta, 0);
}

#[test]
fn injected_inbound_is_redirected() {
    if !enabled() {
        return;
    }
    let mut tc = classifier("udp", &config(Layer::Network, 0));
    let frame = dns();
    let sent = SkbCtx {
        mark: abi::MARK_REDIRECT | 7,
        priority: abi::PRIO_INJECTED | 120,
        ..SkbCtx::default()
    };
    // On lo's ingress: to interface 7, as a packet injected at TC priority 120.
    let (verdict, out) = tc.run_ctx(Hook::Ingress, &frame, &sent).unwrap();
    assert_eq!(verdict, TC_ACT_REDIRECT);
    assert_eq!((out.mark, out.priority), (abi::MARK_INJECTED | 120, 0));
    // A priority that is not ours: injected at TC priority 0, an impostor to every handle.
    let (verdict, out) = tc
        .run_ctx(
            Hook::Ingress,
            &frame,
            &SkbCtx {
                priority: 6,
                ..sent
            },
        )
        .unwrap();
    assert_eq!((verdict, out.mark), (TC_ACT_REDIRECT, abi::MARK_INJECTED));
    // Whatever the handle's configuration.
    tc.set_config(&config(Layer::Network, abi::CFG_SHUTDOWN))
        .unwrap();
    assert_eq!(
        tc.run_ctx(Hook::Ingress, &frame, &sent).unwrap().0,
        TC_ACT_REDIRECT
    );
    // On lo's egress, on its way there: skipped.
    tc.set_config(&config(Layer::Network, 0)).unwrap();
    assert_eq!(
        tc.run_on(Hook::Egress, &frame, &sent).unwrap(),
        TC_ACT_UNSPEC
    );
    assert!(tc.records().is_empty());
}

#[test]
fn loopback_is_seen_once() {
    if !enabled() {
        return;
    }
    let lo = Config {
        lo_ifindex: TEST_DEV,
        ..config(Layer::Network, 0)
    };
    let mut tc = classifier("udp", &lo);
    let frame = dns();
    assert_eq!(tc.run(&frame).unwrap(), TC_ACT_UNSPEC);
    let egress = |tc: &Classifier| tc.run_on(Hook::Egress, &frame, &SkbCtx::default()).unwrap();
    assert_eq!(egress(&tc), TC_ACT_STOLEN);
    let records = tc.records();
    assert_eq!(records.len(), 1);
    assert_eq!(
        Record::parse(&records[0]).unwrap().meta,
        M_OUTBOUND | M_LOOPBACK
    );
    // Attached to lo only to inject.
    tc.set_config(&Config {
        flags: abi::CFG_SKIP_LO,
        ..lo
    })
    .unwrap();
    assert_eq!(egress(&tc), TC_ACT_UNSPEC);
}

#[test]
fn network_and_forward_layers() {
    if !enabled() {
        return;
    }
    let frame = dns();
    let arp = common::eth(&[], 0x0806, &common::arp());
    let ctx = |ingress_ifindex| SkbCtx {
        ingress_ifindex,
        ..SkbCtx::default()
    };
    // BPF_PROG_TEST_RUN takes `ingress_ifindex` from the context on 6.8, but 5.15 refuses it
    // (EINVAL); there, only the unforwarded cases run.
    let forwarded = |tc: &Classifier| match tc.run_on(Hook::Egress, &frame, &ctx(2)) {
        Ok(verdict) => Some(verdict),
        Err(avulse_ebpf::loader::Error::Sys(_, e)) if e.raw_os_error() == Some(libc::EINVAL) => {
            None
        }
        Err(e) => panic!("{e}"),
    };
    let mut net = classifier("frame", &config(Layer::Network, 0));
    // Forwarded packets (egress, with an ingress device) are not the NETWORK layer's.
    let can_forward = match forwarded(&net) {
        Some(verdict) => {
            assert_eq!(verdict, TC_ACT_UNSPEC);
            true
        }
        None => {
            eprintln!("this kernel's BPF_PROG_TEST_RUN cannot set ingress_ifindex");
            false
        }
    };
    assert_eq!(
        net.run_on(Hook::Egress, &frame, &ctx(0)).unwrap(),
        TC_ACT_STOLEN
    );
    assert_eq!(net.run(&frame).unwrap(), TC_ACT_STOLEN);
    // The NETWORK layers see IP only.
    assert_eq!(net.run(&arp).unwrap(), TC_ACT_UNSPEC);
    assert_eq!(net.records().len(), 2);

    let mut fwd = classifier("frame", &config(Layer::NetworkForward, 0));
    assert_eq!(fwd.run(&frame).unwrap(), TC_ACT_UNSPEC);
    assert_eq!(
        fwd.run_on(Hook::Egress, &frame, &ctx(0)).unwrap(),
        TC_ACT_UNSPEC
    );
    if can_forward {
        assert_eq!(forwarded(&fwd), Some(TC_ACT_STOLEN));
        let records = fwd.records();
        let r = Record::parse(&records[0]).unwrap();
        assert_eq!((r.meta, r.ingress_ifindex), (M_OUTBOUND | M_FORWARD, 2));
    }

    // The ETHERNET layer sees every frame.
    let mut eth = classifier("frame", &config(Layer::Ethernet, 0));
    assert_eq!(eth.run(&arp).unwrap(), TC_ACT_STOLEN);
    assert_eq!(eth.records().len(), 1);
}

#[test]
fn fragments_need_the_flag_inbound() {
    if !enabled() {
        return;
    }
    let frag = common::eth(
        &[],
        0x0800,
        &common::ipv4(
            &common::Ip4 {
                proto: 17,
                frag: 0x2000,
                ..Default::default()
            },
            &common::udp(1, 53, b"abc"),
        ),
    );
    let mut tc = classifier("ip", &config(Layer::Network, 0));
    assert_eq!(tc.run(&frag).unwrap(), TC_ACT_UNSPEC);
    assert_eq!(
        tc.run_on(Hook::Egress, &frag, &SkbCtx::default()).unwrap(),
        TC_ACT_STOLEN
    );
    tc.set_config(&config(Layer::Network, abi::CFG_FRAGMENTS))
        .unwrap();
    assert_eq!(tc.run(&frag).unwrap(), TC_ACT_STOLEN);
    // The ETHERNET layer takes frames as they are.
    tc.set_config(&config(Layer::Ethernet, 0)).unwrap();
    assert_eq!(tc.run(&frag).unwrap(), TC_ACT_STOLEN);
}

#[test]
fn the_forwarding_check_keeps_local_traffic() {
    if !enabled() {
        return;
    }
    // To 127.0.0.1, which a FIB lookup finds local: not forwarded, so captured.
    let local = common::eth(
        &[],
        0x0800,
        &common::ipv4(
            &common::Ip4 {
                proto: 17,
                dst: [127, 0, 0, 1],
                ..Default::default()
            },
            &common::udp(1, 53, b"abc"),
        ),
    );
    let mut tc = classifier("udp", &config(Layer::Network, abi::CFG_FWD_CHECK));
    assert_eq!(tc.run(&local).unwrap(), TC_ACT_STOLEN);
    assert_eq!(tc.records().len(), 1);
}

#[test]
fn everything_fails_open() {
    if !enabled() {
        return;
    }
    let frame = dns();
    let mut tc = classifier("udp", &config(Layer::Network, 0));

    // A fresh heartbeat diverts; a stale one passes everything.
    let now = monotonic_ns();
    let beat = |ns| Config {
        heartbeat_ns: ns,
        heartbeat_timeout_ns: 3_000_000_000,
        ..config(Layer::Network, 0)
    };
    tc.set_config(&beat(now)).unwrap();
    assert_eq!(tc.run(&frame).unwrap(), TC_ACT_STOLEN);
    tc.set_config(&beat(now - 10_000_000_000)).unwrap();
    assert_eq!(tc.run(&frame).unwrap(), TC_ACT_UNSPEC);
    assert_eq!(tc.stats().unwrap()[stat::OWNER_GONE], 1);

    tc.set_config(&config(Layer::Network, abi::CFG_SHUTDOWN))
        .unwrap();
    assert_eq!(tc.run(&frame).unwrap(), TC_ACT_UNSPEC);

    tc.set_config(&config(Layer::Network, 0)).unwrap();
    tc.clear_matcher().unwrap();
    assert_eq!(tc.run(&frame).unwrap(), TC_ACT_UNSPEC);
    assert_eq!(tc.stats().unwrap()[stat::NO_MATCHER], 1);
    assert_eq!(tc.records().len(), 1);

    // A full ring: one page holds one record of the 2 KiB class.
    let mut small = Classifier::load_with_ring(4096).unwrap();
    small.set_config(&config(Layer::Network, 0)).unwrap();
    let f = Filter::compile("udp").unwrap();
    small
        .set_matcher(&codegen::compile(f.ir(), &common::env(Layer::Network)).unwrap())
        .unwrap();
    assert_eq!(small.run(&frame).unwrap(), TC_ACT_STOLEN);
    assert_eq!(small.run(&frame).unwrap(), TC_ACT_UNSPEC);
    assert_eq!(small.stats().unwrap()[stat::RING_FULL], 1);
    assert_eq!(small.records().len(), 1);
    assert_eq!(small.run(&frame).unwrap(), TC_ACT_STOLEN);
}

#[test]
fn records_carry_gso_fields() {
    if !enabled() {
        return;
    }
    let mut tc = classifier("udp", &config(Layer::Network, 0));
    let ctx = SkbCtx {
        gso_size: 1400,
        gso_segs: 3,
        ..SkbCtx::default()
    };
    assert_eq!(
        tc.run_on(Hook::Egress, &dns(), &ctx).unwrap(),
        TC_ACT_STOLEN
    );
    let records = tc.records();
    let r = Record::parse(&records[0]).unwrap();
    assert_eq!((r.gso_size, r.gso_segs), (1400, 3));
}

/// How the verifier copes with large filters: long sets, long chains, long byte strings.
#[test]
fn large_filters_load() {
    if !enabled() {
        return;
    }
    let mut tc = Classifier::load().expect("load the TC object");
    let ports = (1..=2000)
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let chain = (0..300)
        .map(|i| format!("(tcp.dstport == {i} and ip.src == 10.{}.0.0/16)", i % 256))
        .collect::<Vec<_>>()
        .join(" or ");
    let long = format!("tcp.payload[0:1000] == {}", vec!["41"; 1000].join(":"));
    let mut rng = common::Rng::new(9);
    let deep = common::random_filter(&mut rng, common::SUPPORTED, 10);
    // Each `xor` keeps its left result on the stack.
    let xors = (0..12).fold("tcp".to_string(), |acc, i| {
        format!("(ip.ttl == {i} xor {acc})")
    });
    for (name, src) in [
        ("2000-port set", format!("tcp.port in {{{ports}}}")),
        ("300-term or", chain),
        ("1000-byte compare", long),
        ("depth-10 random", deep),
        ("12 nested xor", xors),
        (
            "40-option set",
            format!(
                "tcp.options.mss_val in {{{}}}",
                (1..=40)
                    .map(|i| (i * 31).to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        ),
        (
            "header contains",
            "tcp contains 05:b4:01:01 or ip contains 0a:00:00".into(),
        ),
        (
            "arithmetic",
            "max(tcp.srcport, tcp.dstport, udp.srcport) / (tcp.hdr_len + 1) > count(ip.addr) * 3"
                .into(),
        ),
    ] {
        let filter = Filter::compile(&src).unwrap();
        match codegen::compile(filter.ir(), &common::env(Layer::Ethernet)) {
            Ok(m) => match tc.set_matcher(&m) {
                Ok(s) => eprintln!(
                    "{name}: {} instructions, {} processed",
                    s.insns,
                    processed(&s.log)
                ),
                Err(e) => panic!("{name}: {e}"),
            },
            Err(e) => eprintln!("{name}: {e}"),
        }
    }
}

/// What a packet costs: the checks and the parse alone, then with matchers of several sizes
/// (dropping what matches, so that the ring does not fill).
#[test]
fn timing() {
    if !enabled() {
        return;
    }
    let mut tc = Classifier::load().expect("load the TC object");
    tc.set_config(&config(Layer::Ethernet, abi::CFG_DROP))
        .unwrap();
    let frame = common::eth(
        &[],
        0x0800,
        &common::ipv4(
            &common::Ip4::default(),
            &common::tcp(40000, 443, 0x018, 0, b"GET / HTTP/1.1\r\n\r\n"),
        ),
    );
    let (_, ns) = tc.time(&frame, 200_000).unwrap();
    eprintln!("parse only: {ns} ns");
    let syn = common::eth(
        &[],
        0x0800,
        &common::ipv4(
            &common::Ip4::default(),
            &common::tcp_opts(
                40000,
                443,
                0x002,
                &[
                    2, 4, 5, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7,
                ],
                b"",
            ),
        ),
    );
    let mss = Filter::compile("tcp.options.mss_val < 1400").unwrap();
    tc.set_matcher(&codegen::compile(mss.ir(), &common::env(Layer::Ethernet)).unwrap())
        .unwrap();
    tc.set_config(&config(
        Layer::Ethernet,
        abi::CFG_DROP | abi::CFG_TCP_OPTIONS,
    ))
    .unwrap();
    let (verdict, ns) = tc.time(&syn, 200_000).unwrap();
    eprintln!("tcp.options.mss_val < 1400 on a SYN with 4 options: {ns} ns (verdict {verdict})");
    tc.set_config(&config(Layer::Ethernet, abi::CFG_DROP))
        .unwrap();
    let ports = (1..=2000)
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    for src in [
        "tcp.dstport == 443".to_string(),
        "ip.src == 10.0.0.0/8 and tcp.dstport in {80 443} and tcp.payload[0:4] == \"GET \"".into(),
        format!("tcp.port in {{{ports}}}"),
    ] {
        let filter = Filter::compile(&src).unwrap();
        tc.set_matcher(&codegen::compile(filter.ir(), &common::env(Layer::Ethernet)).unwrap())
            .unwrap();
        let (verdict, ns) = tc.time(&frame, 200_000).unwrap();
        let name: String = src.chars().take(60).collect();
        eprintln!("{name}: {ns} ns (verdict {verdict})");
    }
    // Diverting: the copy to the ring, drained between batches.
    tc.set_config(&config(Layer::Ethernet, 0)).unwrap();
    let filter = Filter::compile("tcp.dstport == 443").unwrap();
    tc.set_matcher(&codegen::compile(filter.ir(), &common::env(Layer::Ethernet)).unwrap())
        .unwrap();
    let (verdict, ns) = tc.time(&frame, 1_000).unwrap();
    tc.records();
    eprintln!("tcp.dstport == 443, diverted: {ns} ns (verdict {verdict})");
}

/// WinDivert's vectors, as the filter crate's tests have them.
#[path = "../../filter/src/tests/windivert_vectors.rs"]
#[rustfmt::skip]
#[allow(dead_code)]
mod windivert_vectors;

/// The filters of the tshark comparison.
#[path = "../../filter/src/tests/filters.rs"]
#[allow(dead_code)]
mod tshark_filters;

/// WinDivert's vectors through the kernel matcher, at the NETWORK layer and outbound, as
/// WinDivert's own tests run them.
#[test]
fn windivert_vectors_in_the_kernel() {
    if !enabled() {
        return;
    }
    let mut tc = Classifier::load().expect("load the TC object");
    tc.set_config(&config(Layer::Network, abi::CFG_DROP | abi::CFG_FRAGMENTS))
        .unwrap();
    let (mut exact, mut total) = (0, 0);
    for &(src, packet, want) in windivert_vectors::VECTORS {
        if src.contains("random") {
            continue;
        }
        let filter = Filter::compile_windivert(src, Layer::Network).unwrap();
        let m = codegen::compile_superset(filter.ir(), &common::env(Layer::Network)).unwrap();
        tc.set_matcher(&m).unwrap_or_else(|e| panic!("{src}: {e}"));
        let o = if m.reads_tcp_options() {
            abi::CFG_TCP_OPTIONS
        } else {
            0
        };
        tc.set_config(&config(
            Layer::Network,
            abi::CFG_DROP | abi::CFG_FRAGMENTS | o,
        ))
        .unwrap();
        let ip = windivert_vectors::PACKETS[packet].1;
        let frame = common::eth(&[], if ip[0] >> 4 == 6 { 0x86dd } else { 0x0800 }, ip);
        let got = tc.run_on(Hook::Egress, &frame, &SkbCtx::default()).unwrap() == TC_ACT_SHOT;
        if m.exact() {
            assert_eq!(got, want, "{src}");
            exact += 1;
        } else {
            assert!(got || !want, "{src}");
        }
        total += 1;
    }
    eprintln!("WinDivert vectors: {exact} of {total} exact in the kernel, the rest supersets");
}

/// Every filter of the tshark comparison loads, exactly or widened, at both layers, and the
/// verdicts on the corpus are those of the evaluator (or a superset of them).
#[test]
fn tshark_filters_in_the_kernel() {
    if !enabled() {
        return;
    }
    pin_to_cpu0();
    let mut tc = Classifier::load().expect("load the TC object");
    let frames: Vec<_> = common::corpus(12, 300, 14)
        .into_iter()
        .filter(|f| common::test_runnable(f))
        .collect();
    let all = tshark_filters::AGREE
        .iter()
        .chain(tshark_filters::OUTER)
        .chain(tshark_filters::EXTENSIONS);
    let mut n = 0;
    for src in all {
        let filter = Filter::compile(src).unwrap();
        let m = codegen::compile_superset(filter.ir(), &common::env(Layer::Ethernet)).unwrap();
        tc.set_matcher(&m).unwrap_or_else(|e| panic!("{src}: {e}"));
        let o = if m.reads_tcp_options() {
            abi::CFG_TCP_OPTIONS
        } else {
            0
        };
        tc.set_config(&config(Layer::Ethernet, abi::CFG_DROP | o))
            .unwrap();
        let meta = common::meta(Layer::Ethernet, 0, TEST_DEV);
        for frame in &frames {
            let want = filter.matches(&Packet::parse(frame, Link::Ethernet), &meta);
            let got = tc.run(frame).unwrap() == TC_ACT_SHOT;
            if m.exact() {
                assert_eq!(got, want, "{src} on {frame:02x?}");
            } else {
                assert!(got || !want, "{src} on {frame:02x?}");
            }
        }
        let m = codegen::compile_superset(filter.ir(), &common::env(Layer::Network)).unwrap();
        tc.set_matcher(&m)
            .unwrap_or_else(|e| panic!("{src} at NETWORK: {e}"));
        n += 1;
    }
    eprintln!("tshark filters: {n} load at both layers");
}

/// The event programs, with the configuration of a live handle at `layer` (no heartbeat check),
/// attached to the cgroup root.
fn events(layer: Layer) -> Events {
    let mut ev = Events::load_with_ring(1 << 20).unwrap();
    ev.set_config(&Config {
        layer: layer as u8,
        ..Config::default()
    })
    .unwrap();
    ev.attach(layer).unwrap();
    ev
}

/// The event records of this process's sockets whose ports include one of `ports`.
fn event_records(ev: &mut Events, ports: &[u16]) -> Vec<EventRecord> {
    std::thread::sleep(std::time::Duration::from_millis(200));
    ev.records()
        .iter()
        .map(|r| EventRecord::parse(r).expect("an event record"))
        .filter(|e| ports.contains(&e.local_port) || ports.contains(&e.remote_port))
        .collect()
}

/// `addr` as the programs report it: IPv4 as `::ffff:a.b.c.d`.
fn mapped(addr: std::net::IpAddr) -> [u8; 16] {
    match addr {
        std::net::IpAddr::V4(a) => a.to_ipv6_mapped().octets(),
        std::net::IpAddr::V6(a) => a.octets(),
    }
}

/// The current thread's name, which `bpf_get_current_comm` reports.
fn thread_comm() -> String {
    std::fs::read_to_string("/proc/thread-self/comm")
        .unwrap()
        .trim_end()
        .to_owned()
}

#[test]
fn event_programs_load_and_attach() {
    if !enabled() {
        return;
    }
    for layer in [Layer::Flow, Layer::Socket] {
        let ev = events(layer);
        eprintln!(
            "{layer:?}: programs attached, the task's PID and name {}",
            if ev.have_task() { "known" } else { "unknown" }
        );
    }
    assert!(loader::cgroup_root().unwrap().is_dir());
}

/// SOCKET: a TCP listener and a client over IPv4 and IPv6 (BIND, LISTEN, CONNECT, ACCEPT,
/// CLOSE), and a UDP socket that binds and connects.
#[test]
fn socket_events() {
    use std::net::{TcpListener, TcpStream, UdpSocket};
    if !enabled() {
        return;
    }
    let mut ev = events(Layer::Socket);
    let (pid, comm) = (std::process::id(), thread_comm());
    for host in ["127.0.0.1", "::1"] {
        let before = monotonic_ns();
        let listener = TcpListener::bind((host, 0)).unwrap();
        let server = listener.local_addr().unwrap();
        let client = TcpStream::connect(server).unwrap();
        let (accepted, peer) = listener.accept().unwrap();
        drop((client, accepted, listener));
        let got = event_records(&mut ev, &[server.port(), peer.port()]);
        let family = if server.is_ipv4() { 4 } else { 6 };
        let find = |event: u8, local: u16| {
            got.iter()
                .find(|e| e.event == event && e.local_port == local)
                .unwrap_or_else(|| panic!("no event {event} on port {local}: {got:#?}"))
        };
        let bind = find(EVENT_SOCKET_BIND, server.port());
        let listen = find(EVENT_SOCKET_LISTEN, server.port());
        let accept = find(EVENT_SOCKET_ACCEPT, server.port());
        let connect = got
            .iter()
            .find(|e| e.event == EVENT_SOCKET_CONNECT)
            .unwrap_or_else(|| panic!("no connect: {got:#?}"));
        for e in [bind, listen, accept, connect] {
            assert_eq!((e.protocol, e.family), (6, family), "{e:?}");
            assert!(e.timestamp >= before && e.timestamp <= monotonic_ns());
            assert_ne!(e.endpoint, 0);
            if ev.have_task() {
                assert_eq!(e.pid, pid, "{e:?}");
                assert_eq!(e.comm(), Some(comm.as_str()), "{e:?}");
            }
        }
        assert_eq!(bind.local_addr, mapped(server.ip()));
        assert_eq!(bind.endpoint, listen.endpoint);
        assert_eq!(
            (connect.remote_addr, connect.remote_port),
            (mapped(server.ip()), server.port())
        );
        assert_eq!(connect.flags & abi::EV_OUTBOUND, abi::EV_OUTBOUND);
        assert_eq!(
            (accept.remote_addr, accept.remote_port),
            (mapped(peer.ip()), peer.port())
        );
        assert_eq!(accept.flags & abi::EV_OUTBOUND, 0);
        // Each socket closes once: the listener, the client and the accepted one.
        let closes: Vec<_> = got
            .iter()
            .filter(|e| e.event == EVENT_SOCKET_CLOSE)
            .map(|e| e.endpoint)
            .collect();
        for e in [bind.endpoint, connect.endpoint, accept.endpoint] {
            assert_eq!(closes.iter().filter(|&&c| c == e).count(), 1, "{got:#?}");
        }
    }

    // UDP: bind, then connect (no handshake), then close.
    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (pa, pb) = (
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
    );
    a.connect(("127.0.0.1", pb)).unwrap();
    drop((a, b));
    let got = event_records(&mut ev, &[pa, pb]);
    let kinds: Vec<_> = got
        .iter()
        .filter(|e| e.local_port == pa)
        .map(|e| (e.event, e.protocol))
        .collect();
    assert_eq!(
        kinds,
        [
            (EVENT_SOCKET_BIND, 17),
            (EVENT_SOCKET_CONNECT, 17),
            (EVENT_SOCKET_CLOSE, 17)
        ],
        "{got:#?}"
    );
}

/// FLOW: a TCP connection is established and deleted on both ends; a UDP datagram establishes
/// a flow on each socket, and their release ends them.
#[test]
fn flow_events() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    if !enabled() {
        return;
    }
    let mut ev = events(Layer::Flow);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server = listener.local_addr().unwrap().port();
    let mut client = TcpStream::connect(("127.0.0.1", server)).unwrap();
    let (mut accepted, peer) = listener.accept().unwrap();
    client.write_all(b"ping").unwrap();
    accepted.read_exact(&mut [0; 4]).unwrap();
    drop((client, accepted, listener));
    let got = event_records(&mut ev, &[server]);
    let established: Vec<_> = got
        .iter()
        .filter(|e| e.event == EVENT_FLOW_ESTABLISHED)
        .collect();
    assert_eq!(established.len(), 2, "{got:#?}");
    let active = established
        .iter()
        .find(|e| e.flags & abi::EV_OUTBOUND != 0)
        .expect("the client's flow");
    let passive = established
        .iter()
        .find(|e| e.flags & abi::EV_OUTBOUND == 0)
        .expect("the server's flow");
    assert_eq!(
        (active.local_port, active.remote_port),
        (peer.port(), server)
    );
    assert_eq!(
        (passive.local_port, passive.remote_port),
        (server, peer.port())
    );
    assert!(established.iter().all(|e| e.protocol == 6 && e.family == 4));
    let deleted: Vec<_> = got
        .iter()
        .filter(|e| e.event == EVENT_FLOW_DELETED)
        .map(|e| e.endpoint)
        .collect();
    assert_eq!(deleted.len(), 2, "{got:#?}");
    assert!(deleted.contains(&active.endpoint) && deleted.contains(&passive.endpoint));
    if ev.have_task() {
        let pid = std::process::id();
        assert!(got.iter().all(|e| e.pid == pid), "{got:#?}");
    }

    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (pa, pb) = (
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
    );
    for _ in 0..3 {
        a.send_to(b"hello", ("127.0.0.1", pb)).unwrap();
        b.recv_from(&mut [0; 16]).unwrap();
    }
    let got = event_records(&mut ev, &[pa, pb]);
    let flows: Vec<_> = got
        .iter()
        .map(|e| (e.event, e.local_port, e.remote_port, e.flags))
        .collect();
    // Once per 5-tuple and socket: the sender's, outbound, and the receiver's.
    assert_eq!(
        flows,
        [
            (EVENT_FLOW_ESTABLISHED, pa, pb, abi::EV_OUTBOUND),
            (EVENT_FLOW_ESTABLISHED, pb, pa, 0)
        ],
        "{got:#?}"
    );
    let endpoints: Vec<_> = got.iter().map(|e| e.endpoint).collect();
    drop((a, b));
    std::thread::sleep(std::time::Duration::from_millis(200));
    let released: Vec<_> = ev
        .records()
        .iter()
        .map(|r| EventRecord::parse(r).unwrap())
        .filter(|e| endpoints.contains(&e.endpoint))
        .collect();
    assert_eq!(released.len(), 2, "{released:#?}");
    assert!(
        released
            .iter()
            .all(|e| e.event == EVENT_FLOW_DELETED && e.flags == abi::EV_RELEASED)
    );
}

/// Shut down, or with a stale heartbeat, the event programs report nothing.
#[test]
fn events_fail_open() {
    use std::net::UdpSocket;
    if !enabled() {
        return;
    }
    let mut ev = events(Layer::Socket);
    for config in [
        Config {
            layer: Layer::Socket as u8,
            flags: abi::CFG_SHUTDOWN,
            ..Config::default()
        },
        Config {
            layer: Layer::Socket as u8,
            heartbeat_ns: 1,
            heartbeat_timeout_ns: 1,
            ..Config::default()
        },
    ] {
        ev.set_config(&config).unwrap();
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = s.local_addr().unwrap().port();
        drop(s);
        assert_eq!(event_records(&mut ev, &[port]), []);
    }
    assert!(ev.stats().unwrap()[stat::OWNER_GONE] > 0);
}

/// Every SOCKET filter of the emulator's table loads as the matcher of each kind of program
/// that refuses calls.
#[test]
fn event_matchers_load() {
    if !enabled() {
        return;
    }
    let mut ev = Events::load_with_ring(1 << 20).unwrap();
    let mut most = 0;
    for src in common::EVENT_FILTERS {
        let filter = Filter::compile(src).unwrap();
        for hook in EventHook::ALL {
            let env = codegen::Env {
                event: Some(hook.event()),
                ..common::env(Layer::Socket)
            };
            let m = codegen::compile(filter.ir(), &env).unwrap();
            let stats = ev
                .set_matcher(hook, &m)
                .unwrap_or_else(|e| panic!("{src} ({hook:?}): {e}"));
            most = most.max(processed(&stats.log));
        }
    }
    eprintln!(
        "{} SOCKET filters load for 4 kinds of program; at most {most} instructions processed",
        common::EVENT_FILTERS.len()
    );
}
