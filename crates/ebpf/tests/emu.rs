//! The generated matchers agree with the IR evaluator, run in the emulator over the facts that
//! `Facts::from_packet` computes. The kernel test (`kernel.rs`) checks the same in the kernel,
//! and that the static TC program computes the same facts.

mod common;

use avulse_ebpf::codegen::{self, Error};
use avulse_ebpf::facts::{F_IPV4, F_IPV6, Facts};
use avulse_filter::{Filter, Meta};
use avulse_proto::{Link, Packet};
use common::emu::{self, FACTS_FD, Outcome, PROGS_FD};

fn cases() -> usize {
    std::env::var("AVULSE_EBPF_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300)
}

fn check(src: &str, frames: &[Vec<u8>]) {
    let filter = Filter::compile(src).unwrap_or_else(|e| panic!("{src}: {e:?}"));
    let m = codegen::compile(filter.ir()).unwrap_or_else(|e| panic!("{src}: {e}"));
    let insns = m.with_fds(FACTS_FD, PROGS_FD);
    emu::check_shape(&insns);
    for frame in frames {
        let pkt = Packet::parse(frame, Link::Ethernet);
        let want = filter.matches(&pkt, &Meta::default());
        let got = emu::run(&insns, &Facts::from_packet(&pkt), frame);
        assert_eq!(
            got,
            Outcome::Verdict(want),
            "{src} on {frame:02x?}\nfacts {:?}",
            Facts::from_packet(&pkt)
        );
        // At the NETWORK layers the filter sees the IP packet alone.
        let facts = Facts::from_packet(&pkt);
        if facts.flags & (F_IPV4 | F_IPV6) != 0 {
            let ip = Packet::parse(&frame[facts.l3 as usize..], Link::Ip);
            let want = filter.matches(&ip, &Meta::default());
            let got = emu::run(&insns, &facts.at_network(), frame);
            assert_eq!(
                got,
                Outcome::Verdict(want),
                "{src} at NETWORK on {frame:02x?}"
            );
        }
    }
}

/// `Facts::at_network` is what parsing the IP packet alone gives, offsets apart.
#[test]
fn network_facts_are_those_of_the_ip_packet() {
    let mut checked = 0;
    for frame in common::corpus(6, 2000, 0) {
        let eth = Facts::from_packet(&Packet::parse(&frame, Link::Ethernet));
        if eth.flags & (F_IPV4 | F_IPV6) == 0 {
            continue;
        }
        let net = eth.at_network();
        let base = net.base;
        let ip = Facts::from_packet(&Packet::parse(&frame[base as usize..], Link::Ip));
        let shift = |v: u32| if v == 0 { 0 } else { v + base };
        let want = Facts {
            len: ip.len + base,
            l3: base,
            l4: shift(ip.l4),
            pay: ip.pay + base,
            pay_end: ip.pay_end + base,
            base,
            ..ip
        };
        assert_eq!(net, want, "{frame:02x?}");
        checked += 1;
    }
    assert!(checked > 1000, "{checked}");
}

#[test]
fn supported_filters_agree_with_the_evaluator() {
    let frames = common::corpus(1, 2000, 0);
    for src in common::SUPPORTED {
        check(src, &frames);
    }
}

#[test]
fn random_filters_agree_with_the_evaluator() {
    let frames = common::corpus(2, 300, 0);
    let mut rng = common::Rng::new(3);
    for _ in 0..cases() {
        let src = common::random_filter(&mut rng, 4);
        check(&src, &frames);
    }
}

#[test]
fn unsupported_filters_are_refused() {
    for src in common::UNSUPPORTED {
        let filter = Filter::compile(src).unwrap_or_else(|e| panic!("{src}: {e:?}"));
        match codegen::compile(filter.ir()) {
            Err(Error::Unsupported(_)) => {}
            other => panic!("{src}: {other:?}"),
        }
    }
}

#[test]
fn every_supported_filter_is_small() {
    for src in common::SUPPORTED {
        let filter = Filter::compile(src).unwrap();
        let m = codegen::compile(filter.ir()).unwrap();
        assert!(
            m.insns().len() < 400,
            "{src}: {} instructions",
            m.insns().len()
        );
    }
}

#[test]
fn the_corpus_exercises_every_filter() {
    let frames = common::corpus(1, 2000, 0);
    let mut dull = Vec::new();
    // These hold on every frame or none.
    let constant = [
        "frame",
        "true",
        "false",
        "tcp.srcport < -1",
        "tcp.srcport <= -5",
        "frame[-1000:]",
    ];
    for src in common::SUPPORTED {
        if constant.contains(src) {
            continue;
        }
        let filter = Filter::compile(src).unwrap();
        let hits = frames
            .iter()
            .filter(|f| filter.matches(&Packet::parse(f, Link::Ethernet), &Meta::default()))
            .count();
        if hits == 0 || hits == frames.len() {
            dull.push(format!("{src}: {hits} of {}", frames.len()));
        }
    }
    assert!(dull.is_empty(), "{dull:#?}");
}

/// The checker puts the constant on the right; the generator also takes it on the left.
#[test]
fn a_constant_on_the_left_is_mirrored() {
    use avulse_filter::fields::Field;
    use avulse_filter::ir::{CmpOp, Lit, Quant, Test, Value};

    let frames = common::corpus(4, 300, 0);
    for (op, mirrored) in [
        (CmpOp::Lt, CmpOp::Gt),
        (CmpOp::Le, CmpOp::Ge),
        (CmpOp::Gt, CmpOp::Lt),
        (CmpOp::Ge, CmpOp::Le),
        (CmpOp::Eq, CmpOp::Eq),
        (CmpOp::Ne, CmpOp::Ne),
    ] {
        let cmp = |lhs, op, rhs| Test::Cmp {
            lhs,
            op,
            quant: Quant::Any,
            rhs,
        };
        let (port, lit) = (Value::Field(Field::TcpSrcport), Value::Lit(Lit::Uint(443)));
        let left = codegen::compile(&cmp(lit.clone(), op, port.clone())).unwrap();
        let right = codegen::compile(&cmp(port, mirrored, lit)).unwrap();
        for frame in &frames {
            let facts = Facts::from_packet(&Packet::parse(frame, Link::Ethernet));
            assert_eq!(
                emu::run(&left.with_fds(FACTS_FD, PROGS_FD), &facts, frame),
                emu::run(&right.with_fds(FACTS_FD, PROGS_FD), &facts, frame),
                "{op:?}"
            );
        }
    }
}
