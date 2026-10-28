//! The WinDivert front-end: WinDivert's own test vectors, through the IR evaluator, the bytecode
//! and the native form `avulse filter convert` prints.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use avulse_proto::{Link, Packet};

use super::windivert_vectors::{PACKETS, VECTORS};
use crate::bytecode;
use crate::{Filter, Layer, Meta};

/// What ebpfdivert's `test_filter.c` passes WinDivert's evaluator: the NETWORK layer, outbound,
/// everything else zero.
fn meta() -> Meta<'static> {
    Meta {
        layer: Layer::Network,
        outbound: true,
        ..Meta::default()
    }
}

fn wd(src: &str) -> Filter {
    Filter::compile_windivert(src, Layer::Network).unwrap_or_else(|e| panic!("{}", e.render(src)))
}

/// Every vector that does not depend on `random*`: the IR, the bytecode and the converted native
/// filter all give WinDivert's result.
#[test]
fn windivert_vectors() {
    let mut failures: Vec<String> = Vec::new();
    let mut ran = 0;
    for (i, (src, pkt, expected)) in VECTORS.iter().enumerate() {
        if src.contains("random") {
            continue;
        }
        ran += 1;
        let (name, bytes) = PACKETS[*pkt];
        let packet = Packet::parse(bytes, Link::Ip);
        let f = match Filter::compile_windivert(src, Layer::Network) {
            Ok(f) => f,
            Err(e) => {
                failures.push(format!("#{i} {src}: {}", e.render(src)));
                continue;
            }
        };
        let ir = f.matches(&packet, &meta());
        if ir != *expected {
            failures.push(format!(
                "#{i} {src} on {name}: got {ir}, expected {expected}\n  {}",
                f.ir().native()
            ));
            continue;
        }
        let bytes_ = f.program().unwrap().to_bytes();
        let bc = bytecode::verify(&bytes_).unwrap().matches(&packet, &meta());
        if bc != ir {
            failures.push(format!("#{i} {src} on {name}: bytecode {bc}"));
        }
        let native = f.ir().native().to_string();
        match Filter::compile(&native) {
            Ok(n) if n.matches(&packet, &meta()) == ir => {}
            Ok(_) => failures.push(format!("#{i} {src} on {name}: native `{native}` differs")),
            Err(e) => failures.push(format!(
                "#{i} {src}: native does not compile\n{}",
                e.render(&native)
            )),
        }
    }
    assert!(ran > 220, "only {ran} vectors ran");
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The random vectors compile, and run, even though their results depend on the hash.
#[test]
fn windivert_random_vectors_compile() {
    for (src, pkt, _) in VECTORS.iter().filter(|(s, ..)| s.contains("random")) {
        let f = wd(src);
        f.matches(&Packet::parse(PACKETS[*pkt].1, Link::Ip), &meta());
    }
}

/// `and` binds tighter than `or`, `or` groups to the right, and `?:` needs parentheses.
#[test]
fn windivert_grammar() {
    use crate::windivert::shape;
    assert_eq!(
        shape("true or true and false"),
        "(or true (and true false))"
    );
    assert_eq!(
        shape("tcp and udp or ip and ipv6"),
        "(or (and tcp udp) (and ip ipv6))"
    );
    assert_eq!(
        shape("tcp or udp and ip or ipv6"),
        "(or tcp (and udp ip) ipv6)"
    );
    assert_eq!(shape("(tcp? udp: ip)"), "(? tcp udp ip)");
    assert_eq!(shape("tcp? udp: ip"), "unexpected token");
    assert_eq!(shape("not (tcp)"), "unexpected token");
    assert_eq!(shape("!!tcp && ip"), "(and tcp ip)");
}

fn error(src: &str, layer: Layer) -> String {
    match Filter::compile_windivert(src, layer) {
        Ok(_) => panic!("{src} compiled"),
        Err(e) => e.message,
    }
}

#[test]
fn windivert_errors() {
    assert_eq!(
        error("tcp.dstport == 80", Layer::Network),
        "unknown token `tcp.dstport`"
    );
    assert_eq!(
        error("TCP.DstPort", Layer::Network),
        "unknown token `TCP.DstPort`"
    );
    assert_eq!(
        error("processId == 4", Layer::Network),
        "`processId` is not available at the NETWORK layer"
    );
    assert_eq!(
        error("event == CONNECT", Layer::Network),
        "`CONNECT` has no value at this layer"
    );
    assert_eq!(
        error("packet[65536] == 1", Layer::Network),
        "index out of bounds"
    );
    assert_eq!(
        error("packet32[-3b] == 1", Layer::Network),
        "index out of bounds"
    );
    assert_eq!(error("tcp &", Layer::Network), "unknown token `&`");
    assert_eq!(
        error("tcp.DstPort ==", Layer::Network),
        "unexpected end of filter"
    );
    assert_eq!(
        error("tcp", Layer::Ethernet),
        "WinDivert filters have no ETHERNET layer"
    );
    let long = alloc::vec!["tcp"; 257].join(" or ");
    assert_eq!(error(&long, Layer::Network), "the filter is too long");
    let deep = "(".repeat(600) + "tcp" + &")".repeat(600);
    assert_eq!(error(&deep, Layer::Network), "the filter nests too deeply");
    // Valid at their layers.
    for (src, layer) in [
        ("event == CONNECT and processId == 4 and tcp", Layer::Socket),
        ("event == ESTABLISHED and endpointId > 3", Layer::Flow),
        (
            "layer == NETWORK and priority < -100 and event == CLOSE",
            Layer::Reflect,
        ),
    ] {
        wd_at(src, layer);
    }
}

fn wd_at(src: &str, layer: Layer) -> Filter {
    Filter::compile_windivert(src, layer).unwrap_or_else(|e| panic!("{}", e.render(src)))
}

/// WinDivert's quirks: `not` negates one comparison, decided comparisons become protocol tests,
/// and narrow fields compare the low 32 bits.
#[test]
fn windivert_semantics() {
    use super::frames::*;
    let udp = ipv4(17, &udp(1000, 53, b"q"));
    let v6 = ipv6(6, &tcp(1, 2, avulse_proto::Tcp::SYN, b""));
    let run = |src: &str, frame: &[u8]| wd(src).matches(&Packet::parse(frame, Link::Ip), &meta());
    // `not` is not a logical negation: the field is still missing.
    assert!(!run("not tcp.DstPort == 80", &udp));
    assert!(run("not udp.DstPort == 80", &udp));
    // Decided comparisons test the protocol.
    assert!(run("ip.TOS < 0", &v6));
    assert!(!run("ip.TOS < 0", &udp));
    assert!(run("tcp.Syn <= 1", &v6));
    assert!(run("tcp.Syn == ::1", &v6));
    assert!(!run("tcp.Syn == ::2", &v6));
    // The low 32 bits of a value against a 32-bit field.
    assert!(run("tcp.SeqNum == 0x100000001", &v6));
    // 128-bit addresses.
    assert!(run("ipv6.DstAddr >= 1000", &v6));
    assert!(run("ip.SrcAddr == ::ffff:10.0.0.1", &udp));
    assert!(run(
        "localAddr == ::ffff:10.0.0.1 and remotePort == 53",
        &udp
    ));
    // `-0` is below 0.
    assert!(run("timestamp > -0", &udp));
    assert!(!run("timestamp == -0", &udp));
    let ts = Meta {
        timestamp: -5,
        ..meta()
    };
    assert!(
        wd("timestamp < -4 and timestamp >= -0x8000000000000000")
            .matches(&Packet::parse(&udp, Link::Ip), &ts)
    );
}

/// The native form of a few filters, as `avulse filter convert` prints them.
#[test]
fn windivert_convert() {
    for (src, native) in [
        (
            "outbound and tcp.DstPort == 80",
            "outbound and tcp.dstport == 80",
        ),
        ("inbound and tcp.Syn", "inbound and tcp.flags.syn == true"),
        ("ip.TOS < 0", "not ip"),
        ("tcp.PayloadLength > 0", "len(tcp.payload) > 0"),
        ("packet32[-4b] == 0x34353637", "frame[-4:4] == 34:35:36:37"),
        (
            "(tcp? tcp.DstPort == 80: udp)",
            "tcp and tcp.dstport == 80 or not tcp and udp",
        ),
        ("(tcp? false: true)", "not tcp"),
        ("ipv6.SrcAddr == ::1", "ipv6.src == ::1"),
        ("true", "true"),
    ] {
        assert_eq!(wd(src).ir().native().to_string(), native, "{src}");
    }
}

/// `format_windivert` gives WinDivert syntax that compiles to the same IR, on every vector, and is
/// stable when formatted again.
#[test]
fn windivert_format() {
    for (src, _, _) in VECTORS.iter() {
        let out = Filter::format_windivert(src, Layer::Network).unwrap();
        assert_eq!(wd(&out).ir(), wd(src).ir(), "{src} => {out}");
        assert_eq!(
            Filter::format_windivert(&out, Layer::Network).unwrap(),
            out,
            "{src}"
        );
    }
    for (src, out) in [
        ("inbound and tcp.Syn", "inbound and tcp.Syn"),
        ("not outbound", "not outbound"),
        ("not tcp.Syn and !udp", "not tcp.Syn and not udp"),
        ("ip.DstAddr==10.0.0.1", "ip.DstAddr == 10.0.0.1"),
        ("localAddr == 127.0.0.1", "localAddr == ::ffff:127.0.0.1"),
        (
            "packet16[2] = 0x54 || packet[-1] < 3",
            "packet16[4b] == 84 or packet[-1] < 3",
        ),
        (
            "(tcp ? tcp.DstPort == 80 or tcp.SrcPort == 80 : (udp && udp.DstPort == 53))",
            "(tcp? tcp.DstPort == 80 or tcp.SrcPort == 80: udp and udp.DstPort == 53)",
        ),
        ("(tcp or udp) and ip", "(tcp or udp) and ip"),
        ("ip.TTL > -1", "ip.TTL > -1"),
    ] {
        assert_eq!(
            Filter::format_windivert(src, Layer::Network).unwrap(),
            out,
            "{src}"
        );
    }
    assert!(Filter::format_windivert("tcp.Bogus", Layer::Network).is_err());
}

/// WinDivert's deepest filters: 341 levels of parentheses, and conditionals nested 127 deep (the
/// 256-test limit) in conditions and in branches. A conditional is one IR node, so nesting in
/// conditions does not blow up.
#[test]
fn windivert_deepest_filters() {
    extern crate std;
    std::thread::Builder::new()
        .stack_size(8 << 20)
        .spawn(|| {
            let n = 341;
            let parens = "(".repeat(n) + "tcp" + &")".repeat(n);
            let in_cond = (0..127).fold("tcp".to_string(), |e, _| format!("({e}? udp: ip)"));
            let in_branch = (0..127).fold("tcp".to_string(), |e, _| format!("(udp? {e}: ip)"));
            let frame = super::frames::https_syn();
            for src in [&parens, &in_cond, &in_branch] {
                let f = wd(src);
                let pkt = Packet::parse(&frame[14..], Link::Ip);
                let ir = f.matches(&pkt, &meta());
                match f.program() {
                    Ok(p) => {
                        let bytes = p.to_bytes();
                        assert_eq!(bytecode::verify(&bytes).unwrap().matches(&pkt, &meta()), ir);
                    }
                    Err(e) => panic!("{e}"),
                }
            }
            // Printed natively, conditions nested in conditions double at every level.
            assert_eq!(wd(&in_cond).ir().native_tests(), usize::MAX);
            assert_eq!(wd(&in_branch).ir().native_tests(), 3 * 127 + 1);
            let deeper = "(".repeat(n + 1) + "tcp" + &")".repeat(n + 1);
            assert_eq!(
                error(&deeper, Layer::Network),
                "the filter nests too deeply"
            );
        })
        .unwrap()
        .join()
        .unwrap();
}
