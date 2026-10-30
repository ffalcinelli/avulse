//! Arbitrary WinDivert filters through the front-end, the IR evaluator, the bytecode and the
//! native form `avulse filter convert` prints. Nothing may panic, and when the native form
//! compiles (it can exceed native limits), all three must agree.
//!
//! Input: a layer byte, the filter source, a NUL byte, a flags byte, then the packet.

#![no_main]

use avulse_filter::{Filter, Layer, Meta, bytecode};
use avulse_proto::{Link, Packet};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [layer, rest @ ..] = data else {
        return;
    };
    let layer = match layer % 5 {
        0 => Layer::Network,
        1 => Layer::NetworkForward,
        2 => Layer::Flow,
        3 => Layer::Socket,
        _ => Layer::Reflect,
    };
    let split = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    let (src, rest) = rest.split_at(split);
    let Ok(src) = std::str::from_utf8(src) else {
        return;
    };
    let (flags, packet) = match rest.get(1..) {
        Some([flags, packet @ ..]) => (*flags, packet),
        _ => (0, &[][..]),
    };
    let filter = match Filter::compile_windivert(src, layer) {
        Ok(f) => f,
        Err(e) => {
            e.render(src);
            return;
        }
    };
    let meta = Meta {
        layer,
        outbound: flags & 1 != 0,
        loopback: flags & 2 != 0,
        timestamp: i64::from(flags as i8) * 1000,
        hash: u64::from(flags).wrapping_mul(0x9e37_79b9_7f4a_7c15),
        ..Meta::default()
    };
    let pkt = Packet::parse(packet, Link::Ip);
    let expected = filter.matches(&pkt, &meta);
    if let Ok(program) = filter.program() {
        let bytes = program.to_bytes();
        let verified = bytecode::verify(&bytes)
            .unwrap_or_else(|e| panic!("{src:?}: the compiled program fails to verify: {e}"));
        assert_eq!(verified.matches(&pkt, &meta), expected, "{src:?}: bytecode\n{program}");
    }
    if filter.ir().native_tests() <= 10_000 {
        let native = filter.ir().native().to_string();
        if let Ok(n) = Filter::compile(&native) {
            assert_eq!(n.matches(&pkt, &meta), expected, "{src:?}: native `{native}`");
        }
    }
});
