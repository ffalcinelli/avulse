//! The spike in a real kernel, through `BPF_PROG_TEST_RUN`: the static TC program computes the
//! same facts as `Facts::from_packet`, the verifier accepts every generated matcher, and the
//! verdicts agree with the IR evaluator. It needs root, so it runs only with `AVULSE_BPF=1`, in
//! the Vagrant VMs:
//!
//! ```text
//! cargo test -p avulse-ebpf --test kernel --no-run   # on the host; prints the binary's path
//! vagrant up default
//! vagrant ssh default -c "sudo AVULSE_BPF=1 /vagrant/target/debug/deps/kernel-… --nocapture"
//! vagrant destroy -f default
//! ```

#![cfg(target_os = "linux")]

mod common;

use avulse_ebpf::codegen;
use avulse_ebpf::facts::Facts;
use avulse_ebpf::loader::Classifier;
use avulse_filter::{Filter, Meta};
use avulse_proto::{Link, Packet};

const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;
const TC_ACT_UNSPEC: i32 = -1;

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

/// `processed N insns` from the verifier's statistics.
fn processed(log: &str) -> usize {
    log.split("processed ")
        .nth(1)
        .and_then(|s| s.split(' ').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

#[test]
fn kernel_agrees_with_the_evaluator() {
    if !enabled() {
        return;
    }
    pin_to_cpu0();
    let mut tc = Classifier::load().expect("load the TC object");
    let frames = common::corpus(1, 3000, 14);

    // Without a matcher every packet passes, and the facts are `Facts::from_packet`'s.
    for frame in &frames {
        assert_eq!(tc.run(frame).unwrap(), TC_ACT_OK);
        let want = Facts::from_packet(&Packet::parse(frame, Link::Ethernet));
        assert_eq!(tc.facts(0).unwrap(), want, "facts of {frame:02x?}");
    }
    eprintln!("facts: {} frames agree", frames.len());

    let cases: usize = std::env::var("AVULSE_EBPF_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let mut rng = common::Rng::new(5);
    let mut filters: Vec<String> = common::SUPPORTED.iter().map(|s| s.to_string()).collect();
    filters.extend((0..cases).map(|_| common::random_filter(&mut rng, 4)));
    let (mut most_insns, mut most_processed, mut runs) = (0, (0, String::new()), 0);
    for src in &filters {
        let filter = Filter::compile(src).unwrap();
        let m = codegen::compile(filter.ir()).unwrap();
        let stats = tc.set_matcher(&m).unwrap_or_else(|e| panic!("{src}: {e}"));
        most_insns = most_insns.max(stats.insns);
        let p = processed(&stats.log);
        if p > most_processed.0 {
            most_processed = (p, src.clone());
        }
        for frame in &frames {
            let pkt = Packet::parse(frame, Link::Ethernet);
            let want = if filter.matches(&pkt, &Meta::default()) {
                TC_ACT_SHOT
            } else {
                TC_ACT_UNSPEC
            };
            assert_eq!(tc.run(frame).unwrap(), want, "{src} on {frame:02x?}");
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

/// What a packet costs: the parse alone, and with matchers of several sizes.
#[test]
fn timing() {
    if !enabled() {
        return;
    }
    let mut tc = Classifier::load().expect("load the TC object");
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
}
