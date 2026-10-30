//! The generated matchers agree with the IR evaluator, run in the emulator over the facts that
//! `Facts::from_packet` computes. The kernel test (`kernel.rs`) checks the same in the kernel,
//! and that the static TC program computes the same facts.

mod common;

/// WinDivert's vectors, as the filter crate's tests have them.
#[path = "../../filter/src/tests/windivert_vectors.rs"]
#[rustfmt::skip]
#[allow(dead_code)]
mod windivert_vectors;

/// The filters of the tshark comparison.
#[path = "../../filter/src/tests/filters.rs"]
#[allow(dead_code)]
mod tshark_filters;

use avulse_ebpf::codegen::{self, Env, Error, Matcher};
use avulse_ebpf::facts::{F_IPV4, F_IPV6, Facts, M_OUTBOUND};
use avulse_filter::{Filter, Layer, Meta};
use avulse_proto::{Link, Packet};
use common::emu::{self, FACTS_FD, Outcome, PROGS_FD};

fn cases() -> usize {
    std::env::var("AVULSE_EBPF_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300)
}

const LAYERS: [Layer; 2] = [Layer::Ethernet, Layer::Network];

/// Runs `m` (compiled for `layer`) on every frame that reaches the matcher at that layer, with
/// the metadata variants of [`common::variant`], and compares with the evaluator: equal when
/// the matcher is exact, a superset otherwise. Returns how many frames each side matched.
fn agree(src: &str, filter: &Filter, m: &Matcher, layer: Layer, frames: &[Vec<u8>]) -> usize {
    let insns = m.with_fds(FACTS_FD, PROGS_FD);
    emu::check_shape(&insns);
    let mut hits = 0;
    for (i, frame) in frames.iter().enumerate() {
        let (bits, ifindex) = common::variant(i);
        let meta = common::meta(layer, bits, ifindex);
        let pkt = Packet::parse(frame, Link::Ethernet);
        let mut facts = Facts {
            layer: layer as u8,
            meta: bits,
            ifindex,
            ..Facts::from_packet(&pkt)
        };
        let want = match layer {
            Layer::Ethernet => filter.matches(&pkt, &meta),
            _ => {
                // At the NETWORK layers the filter sees the IP packet alone.
                if facts.flags & (F_IPV4 | F_IPV6) == 0 {
                    continue;
                }
                facts = facts.at_network();
                let ip = Packet::parse(&frame[facts.l3 as usize..], Link::Ip);
                filter.matches(&ip, &meta)
            }
        };
        let got = emu::run(&insns, &facts, frame);
        let Outcome::Verdict(got) = got else {
            panic!("{src} at {layer:?}: {got:?} on {frame:02x?}");
        };
        if m.exact() {
            assert_eq!(
                got, want,
                "{src} at {layer:?} on {frame:02x?}\nfacts {facts:?}"
            );
        } else {
            assert!(
                got || !want,
                "{src}: a superset missed {frame:02x?} at {layer:?}"
            );
        }
        hits += want as usize;
    }
    hits
}

/// Compiles `src` exactly for both layers and checks it.
fn check(src: &str, frames: &[Vec<u8>]) {
    let filter = Filter::compile(src).unwrap_or_else(|e| panic!("{src}: {e:?}"));
    for layer in LAYERS {
        let m = codegen::compile(filter.ir(), &common::env(layer))
            .unwrap_or_else(|e| panic!("{src} at {layer:?}: {e}"));
        agree(src, &filter, &m, layer, frames);
    }
}

/// Compiles `filter` exactly or as a superset, for both layers, and checks it; returns whether
/// it was exact.
fn check_superset(src: &str, filter: &Filter, frames: &[Vec<u8>]) -> bool {
    let mut exact = true;
    for layer in LAYERS {
        let env = common::env(layer);
        let m = match codegen::compile_superset(filter.ir(), &env) {
            Ok(m) => m,
            Err(Error::TooLarge) => continue,
            Err(e) => panic!("{src} at {layer:?}: {e}"),
        };
        exact &= m.exact();
        agree(src, filter, &m, layer, frames);
    }
    exact
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
        let src = common::random_filter(&mut rng, common::SUPPORTED, 4);
        check(&src, &frames);
    }
}

#[test]
fn unsupported_filters_are_refused_and_widened() {
    let frames = common::corpus(7, 300, 0);
    for src in common::UNSUPPORTED {
        let filter = Filter::compile(src).unwrap_or_else(|e| panic!("{src}: {e:?}"));
        for layer in LAYERS {
            match codegen::compile(filter.ir(), &common::env(layer)) {
                Err(Error::Unsupported(_)) => {}
                other => panic!("{src}: {other:?}"),
            }
        }
        assert!(!check_superset(src, &filter, &frames), "{src}");
    }
}

/// An unsupported test widens to the presence of the protocols it reads, and not further than
/// the tests next to it require.
#[test]
fn supersets_keep_the_protocols() {
    let env = common::env(Layer::Network);
    for (src, superset) in [
        ("icmp.seq == 1", "icmp"),
        ("udp.payload contains \"hello\"", "udp"),
        (
            "tcp.dstport == 80 and tcp.payload contains \"GET\"",
            "tcp.dstport == 80",
        ),
        (
            "ip.src == 10.0.0.1 and icmp.seq == 1",
            "ip.src == 10.0.0.1 and icmp",
        ),
        (
            "tcp.payload contains \"GET\" or icmp.seq == 1",
            "tcp or icmp",
        ),
        // Under a `not`, the only subset is false; extensions have no protocol.
        ("tcp and not icmp.seq == 1", "tcp"),
        ("udp and timestamp > 0", "udp"),
        ("timestamp > 0", "true"),
    ] {
        let filter = Filter::compile(src).unwrap();
        let s = codegen::superset(filter.ir(), &env);
        assert!(!s.exact, "{src}");
        assert_eq!(s.test.native().to_string(), superset, "{src}");
    }
}

/// Random mixes of supported and unsupported tests: the superset never misses a packet.
#[test]
fn supersets_are_sound() {
    let frames = common::corpus(8, 300, 0);
    let pool: Vec<&str> = common::SUPPORTED
        .iter()
        .chain(common::UNSUPPORTED)
        .copied()
        .collect();
    let mut rng = common::Rng::new(11);
    let (mut exact, mut total) = (0, 0);
    for _ in 0..cases() {
        let src = common::random_filter(&mut rng, &pool, 4);
        let filter = Filter::compile(&src).unwrap_or_else(|e| panic!("{src}: {e:?}"));
        exact += check_superset(&src, &filter, &frames) as usize;
        total += 1;
    }
    eprintln!("{exact} of {total} random filters compile exactly");
}

/// Every filter of the tshark comparison runs in the kernel, exactly or as a superset.
#[test]
fn tshark_filters_compile_exactly_or_widened() {
    let frames = common::corpus(9, 500, 0);
    let mut widened = Vec::new();
    let all = tshark_filters::AGREE
        .iter()
        .chain(tshark_filters::OUTER)
        .chain(tshark_filters::EXTENSIONS);
    let mut n = 0;
    for src in all {
        let filter = Filter::compile(src).unwrap_or_else(|e| panic!("{src}: {e:?}"));
        check_superset(src, &filter, &frames);
        // What had to be widened (the matcher is also inexact on frames whose outer VLAN tag
        // was offloaded, when the filter reads the link layer).
        if !codegen::superset(filter.ir(), &common::env(Layer::Ethernet)).exact {
            widened.push(*src);
        }
        n += 1;
    }
    eprintln!(
        "{} of {n} tshark filters compile exactly; widened: {widened:#?}",
        n - widened.len()
    );
}

/// WinDivert's vectors through the matcher, at the NETWORK layer as WinDivert's tests run them.
#[test]
fn windivert_vectors_agree() {
    let (mut exact, mut total) = (0, 0);
    for &(src, packet, want) in windivert_vectors::VECTORS {
        if src.contains("random") {
            continue;
        }
        let filter = Filter::compile_windivert(src, Layer::Network)
            .unwrap_or_else(|e| panic!("{src}: {e:?}"));
        let m = match codegen::compile_superset(filter.ir(), &common::env(Layer::Network)) {
            Ok(m) => m,
            Err(e) => panic!("{src}: {e}"),
        };
        let ip = windivert_vectors::PACKETS[packet].1;
        let frame = common::eth(&[], if ip[0] >> 4 == 6 { 0x86dd } else { 0x0800 }, ip);
        let facts = Facts {
            layer: Layer::Network as u8,
            meta: M_OUTBOUND,
            ..Facts::from_packet(&Packet::parse(&frame, Link::Ethernet))
        }
        .at_network();
        let got = emu::run(&m.with_fds(FACTS_FD, PROGS_FD), &facts, &frame);
        let meta = Meta {
            outbound: true,
            ..Meta::default()
        };
        assert_eq!(
            filter.matches(&Packet::parse(ip, Link::Ip), &meta),
            want,
            "{src}"
        );
        if m.exact() {
            assert_eq!(got, Outcome::Verdict(want), "{src}");
            exact += 1;
        } else {
            eprintln!("widened: {src}");
            assert!(got == Outcome::Verdict(true) || !want, "{src}");
        }
        total += 1;
    }
    eprintln!("{exact} of {total} WinDivert vectors compile exactly");
    assert!(exact * 10 >= total * 9, "{exact} of {total}");
}

/// At the ETHERNET layer the device may have taken the outer VLAN tag off the frame: user
/// space puts it back (with its TPID), and the matcher must agree with the frame as user space
/// sees it, from the facts the kernel computes (`Facts::offloaded`), or take it (a superset)
/// when the filter reads link-layer bytes.
#[test]
fn offloaded_vlan_tags() {
    let frames: Vec<Vec<u8>> = common::corpus(10, 3000, 0)
        .into_iter()
        .filter(|f| f.len() >= 18 && matches!(f[12..14], [0x81, 0x00] | [0x88, 0xa8]))
        .collect();
    assert!(frames.len() > 100, "{}", frames.len());
    let env = common::env(Layer::Ethernet);
    for src in common::SUPPORTED {
        let filter = Filter::compile(src).unwrap();
        let m = codegen::compile(filter.ir(), &env).unwrap();
        let insns = m.with_fds(FACTS_FD, PROGS_FD);
        for (i, frame) in frames.iter().enumerate() {
            let stripped = [&frame[..12], &frame[16..]].concat();
            let restored = Packet::parse(frame, Link::Ethernet);
            let (bits, ifindex) = common::variant(i);
            let facts = Facts::offloaded(&restored).unwrap();
            let facts = Facts {
                layer: Layer::Ethernet as u8,
                meta: facts.meta | bits,
                ifindex,
                ..facts
            };
            let meta = common::meta(Layer::Ethernet, bits, ifindex);
            let want = filter.matches(&restored, &meta);
            let got = emu::run(&insns, &facts, &stripped);
            if m.exact() {
                assert_eq!(got, Outcome::Verdict(want), "{src} on {frame:02x?}");
            } else {
                assert_eq!(got, Outcome::Verdict(true), "{src} on {frame:02x?}");
            }
        }
    }
}

/// Handle constants are decided when the matcher is generated.
#[test]
fn handle_constants_are_folded() {
    for (src, layer, want) in [
        ("layer == ethernet", Layer::Ethernet, true),
        ("layer == network", Layer::Ethernet, false),
        ("layer in {network network-forward}", Layer::Network, true),
        ("event == packet", Layer::Network, true),
        ("priority == 0", Layer::Network, true),
        ("priority > 0", Layer::Network, false),
        ("subifidx == 0", Layer::Network, true),
        ("iface == \"nonexistent\"", Layer::Network, false),
        ("iface != \"nonexistent\"", Layer::Network, true),
    ] {
        let filter = Filter::compile(src).unwrap_or_else(|e| panic!("{src}: {e:?}"));
        let s = codegen::superset(filter.ir(), &common::env(layer));
        assert!(s.exact, "{src}");
        let m = codegen::compile(filter.ir(), &common::env(layer)).unwrap();
        let frame = common::eth(&[], 0x0800, &common::ipv4(&Default::default(), &[]));
        let facts = Facts::from_packet(&Packet::parse(&frame, Link::Ethernet));
        let got = emu::run(&m.with_fds(FACTS_FD, PROGS_FD), &facts, &frame);
        assert_eq!(got, Outcome::Verdict(want), "{src}");
    }
    let env = Env {
        priority: -5,
        ..common::env(Layer::Network)
    };
    let f = Filter::compile("priority < 0").unwrap();
    assert_eq!(codegen::superset(f.ir(), &env).test, f.ir().clone());
}

#[test]
fn every_supported_filter_is_small() {
    for src in common::SUPPORTED {
        let filter = Filter::compile(src).unwrap();
        for layer in LAYERS {
            let m = codegen::compile(filter.ir(), &common::env(layer)).unwrap();
            assert!(
                m.insns().len() < 1000,
                "{src}: {} instructions",
                m.insns().len()
            );
        }
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
            .enumerate()
            .filter(|(i, f)| {
                let (bits, ifindex) = common::variant(*i);
                let meta = common::meta(Layer::Ethernet, bits, ifindex);
                filter.matches(&Packet::parse(f, Link::Ethernet), &meta)
            })
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
    let env = common::env(Layer::Ethernet);
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
        let left = codegen::compile(&cmp(lit.clone(), op, port.clone()), &env).unwrap();
        let right = codegen::compile(&cmp(port, mirrored, lit), &env).unwrap();
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

/// At the SOCKET layer, the matchers of `connect` and `bind` agree with the evaluator on every
/// event, run on the facts the event programs write (`facts::ev::from_record`).
#[test]
fn event_matchers_agree_with_the_evaluator() {
    use avulse_ebpf::facts::ev;
    use avulse_filter::Event;
    let records = common::event_records();
    for src in common::EVENT_FILTERS {
        let filter = Filter::compile(src).unwrap_or_else(|e| panic!("{src}: {e:?}"));
        let (mut hit, mut miss) = (0, 0);
        for (event, n) in [(Event::SocketConnect, 4), (Event::SocketBind, 3)] {
            let env = Env {
                event: Some(event),
                ..common::env(Layer::Socket)
            };
            let m = codegen::compile(filter.ir(), &env)
                .unwrap_or_else(|e| panic!("{src} ({event:?}): {e}"));
            assert!(m.exact());
            let insns = m.with_fds(FACTS_FD, PROGS_FD);
            emu::check_shape(&insns);
            for r in records.iter().filter(|r| r.event == n) {
                let want = filter.matches(&Packet::parse(&[], Link::Ip), &common::event_meta(r));
                let got = emu::run_event(&insns, &ev::from_record(r));
                assert_eq!(got, Outcome::Verdict(want), "{src} on {r:?}");
                if want { hit += 1 } else { miss += 1 }
            }
        }
        assert!(hit > 0 && miss > 0, "`{src}` does not split the events");
    }
    let env = Env {
        event: Some(Event::SocketConnect),
        ..common::env(Layer::Socket)
    };
    for src in common::EVENT_UNSUPPORTED {
        let filter = Filter::compile(src).unwrap();
        assert!(
            matches!(
                codegen::compile(filter.ir(), &env),
                Err(Error::Unsupported(_))
            ),
            "{src}"
        );
    }
    // Without its event, a matcher cannot decide `event`.
    let filter = Filter::compile("event == connect").unwrap();
    assert!(codegen::compile(filter.ir(), &common::env(Layer::Socket)).is_err());
}
