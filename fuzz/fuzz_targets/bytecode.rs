//! Arbitrary programs through the verifier, and the accepted ones through the interpreter, which
//! must never panic.
//!
//! Input: a flags byte, an instruction count, a packet length, then the program and the packet
//! (the last bytes). Unless flag 0x80 is set, the program is a body (instructions, then the pool)
//! and the target writes a valid header for it, so that the fuzzer gets past the header checks
//! quickly. With the flag, the bytes are the whole program, header included.

#![no_main]

use avulse_filter::bytecode::{self, VERSION};
use avulse_filter::{Layer, Meta};
use avulse_proto::{Link, Packet};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [flags, count, packet_len, rest @ ..] = data else {
        return;
    };
    let (body, packet) = rest.split_at(rest.len() - usize::from(*packet_len).min(rest.len()));
    let program = if flags & 0x80 != 0 {
        body.to_vec()
    } else {
        let count = usize::from(*count).min(body.len() / 8).max(1);
        let pool = body.len().saturating_sub(count * 8);
        let mut p = b"AVBC".to_vec();
        p.extend_from_slice(&VERSION.to_le_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(&(count as u32).to_le_bytes());
        p.extend_from_slice(&(pool as u32).to_le_bytes());
        p.extend_from_slice(body);
        p
    };
    let Ok(verified) = bytecode::verify(&program) else {
        return;
    };
    let link = if flags & 1 == 0 { Link::Ethernet } else { Link::Ip };
    let meta = Meta {
        layer: if flags & 2 == 0 { Layer::Network } else { Layer::Ethernet },
        outbound: flags & 4 != 0,
        loopback: flags & 8 != 0,
        iface: (flags & 16 != 0).then_some("eth0"),
        ..Meta::default()
    };
    verified.matches(&Packet::parse(packet, link), &meta);
});
