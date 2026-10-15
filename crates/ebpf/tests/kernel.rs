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

use avulse_ebpf::abi::{self, Config, Record, stat};
use avulse_ebpf::codegen;
use avulse_ebpf::facts::{
    F_IPV4, F_IPV6, F_UDP, Facts, M_FORWARD, M_IMPOSTOR, M_LOOPBACK, M_OUTBOUND, M_SNIFFED,
};
use avulse_ebpf::loader::{Classifier, Hook, SkbCtx};
use avulse_filter::{Filter, Layer, Meta};
use avulse_proto::{Link, Packet};

const TC_ACT_SHOT: i32 = 2;
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
    tc.set_matcher(&codegen::compile(f.ir()).unwrap())
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
    tc.set_config(&config(Layer::Ethernet, abi::CFG_DROP))
        .unwrap();
    let frames = common::corpus(1, 3000, 14);

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
    tc.set_config(&config(Layer::Network, abi::CFG_DROP | abi::CFG_FRAGMENTS))
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
    filters.extend((0..cases).map(|_| common::random_filter(&mut rng, 4)));
    let (mut most_insns, mut most_processed, mut runs) = (0, (0, String::new()), 0);
    for (i, src) in filters.iter().enumerate() {
        let filter = Filter::compile(src).unwrap();
        let m = codegen::compile(filter.ir()).unwrap();
        let stats = tc.set_matcher(&m).unwrap_or_else(|e| panic!("{src}: {e}"));
        most_insns = most_insns.max(stats.insns);
        let p = processed(&stats.log);
        if p > most_processed.0 {
            most_processed = (p, src.clone());
        }
        let verdict = |m: bool| if m { TC_ACT_SHOT } else { TC_ACT_UNSPEC };
        tc.set_config(&config(Layer::Ethernet, abi::CFG_DROP))
            .unwrap();
        for frame in &frames {
            let pkt = Packet::parse(frame, Link::Ethernet);
            let want = verdict(filter.matches(&pkt, &Meta::default()));
            assert_eq!(tc.run(frame).unwrap(), want, "{src} on {frame:02x?}");
            runs += 1;
        }
        // The NETWORK layer for the hand-written filters and a third of the random ones.
        if i >= common::SUPPORTED.len() && i % 3 != 0 {
            continue;
        }
        tc.set_config(&config(Layer::Network, abi::CFG_DROP | abi::CFG_FRAGMENTS))
            .unwrap();
        for frame in &frames {
            let eth = Facts::from_packet(&Packet::parse(frame, Link::Ethernet));
            let want = if eth.flags & (F_IPV4 | F_IPV6) == 0 {
                TC_ACT_UNSPEC
            } else {
                let ip = Packet::parse(&frame[eth.l3 as usize..], Link::Ip);
                verdict(filter.matches(&ip, &Meta::default()))
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
        .set_matcher(&codegen::compile(f.ir()).unwrap())
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
    let deep = common::random_filter(&mut rng, 10);
    // Each `xor` compiles its right side twice.
    let xors = (0..12).fold("tcp".to_string(), |acc, i| {
        format!("(ip.ttl == {i} xor {acc})")
    });
    for (name, src) in [
        ("2000-port set", format!("tcp.port in {{{ports}}}")),
        ("300-term or", chain),
        ("1000-byte compare", long),
        ("depth-10 random", deep),
        ("12 nested xor", xors),
    ] {
        let filter = Filter::compile(&src).unwrap();
        match codegen::compile(filter.ir()) {
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
        tc.set_matcher(&codegen::compile(filter.ir()).unwrap())
            .unwrap();
        let (verdict, ns) = tc.time(&frame, 200_000).unwrap();
        let name: String = src.chars().take(60).collect();
        eprintln!("{name}: {ns} ns (verdict {verdict})");
    }
    // Diverting: the copy to the ring, drained between batches.
    tc.set_config(&config(Layer::Ethernet, 0)).unwrap();
    let filter = Filter::compile("tcp.dstport == 443").unwrap();
    tc.set_matcher(&codegen::compile(filter.ir()).unwrap())
        .unwrap();
    let (verdict, ns) = tc.time(&frame, 1_000).unwrap();
    tc.records();
    eprintln!("tcp.dstport == 443, diverted: {ns} ns (verdict {verdict})");
}
