//! Arbitrary filter source through the parser, the formatter, the checker, the IR evaluator and
//! the bytecode. Nothing may panic, `filter fmt` output must parse back to itself, and the
//! bytecode must agree with the IR evaluator.
//!
//! Input: the filter source, a NUL byte, a flags byte, then the packet.

#![no_main]

use avulse_filter::{Filter, Meta, bytecode, parse};
use avulse_proto::{Link, Packet};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let (src, rest) = data.split_at(split);
    let Ok(src) = std::str::from_utf8(src) else {
        return;
    };
    let (flags, packet) = match rest.get(1..) {
        Some([flags, packet @ ..]) => (*flags, packet),
        _ => (0, &[][..]),
    };

    if let Ok(ast) = parse(src) {
        let printed = ast.to_string();
        let again = parse(&printed).unwrap_or_else(|e| {
            panic!("{src:?} formats as {printed:?}, which does not parse:\n{}", e.render(&printed))
        });
        assert_eq!(again.to_string(), printed, "formatting {src:?} is not stable");
    }

    let filter = match Filter::compile(src) {
        Ok(f) => f,
        Err(e) => {
            e.render(src);
            return;
        }
    };
    let link = if flags & 1 == 0 { Link::Ethernet } else { Link::Ip };
    let meta = Meta {
        outbound: flags & 2 != 0,
        loopback: flags & 4 != 0,
        iface: (flags & 8 != 0).then_some("eth0"),
        process_name: (flags & 16 != 0).then_some("curl"),
        ..Meta::default()
    };
    let pkt = Packet::parse(packet, link);
    let expected = filter.matches(&pkt, &meta);
    if let Ok(program) = filter.program() {
        let bytes = program.to_bytes();
        let verified = bytecode::verify(&bytes)
            .unwrap_or_else(|e| panic!("{src:?}: the compiled program fails to verify: {e}"));
        assert_eq!(
            verified.matches(&pkt, &meta),
            expected,
            "{src:?}: the bytecode disagrees with the IR evaluator\n{program}"
        );
    }
});
