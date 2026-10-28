//! WinDivert's filter object, serialized as `WinDivertHelperCompileFilter` does (`@WinDiv_…`):
//! what WinDivert reports as the data of a REFLECT event. The tests are WinDivert's, after its
//! simplification of decided comparisons, flattened into jumps in WinDivert's order, so the text
//! is the one WinDivert produces for the same filter.

use alloc::string::String;
use alloc::vec::Vec;

use super::parse::{Expr, Op, Test};
use super::{Def, Lower, Proto};
use crate::error::{Diagnostic, Span};

/// The continuations that end evaluation.
const ACCEPT: u16 = 0x7ffe;
const REJECT: u16 = 0x7fff;
/// WinDivert's longest object.
const MAX_LEN: usize = 256;

/// A test of the object (`WINDIVERT_FILTER`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Insn {
    field: u32,
    test: u32,
    neg: bool,
    arg: [u32; 4],
    succ: u16,
    fail: u16,
}

/// `WINDIVERT_FILTER_FIELD_*` of a field.
fn field_id(name: &str) -> u32 {
    match name {
        "zero" | "true" | "false" => 0,
        "inbound" => 1,
        "outbound" => 2,
        "ifIdx" => 3,
        "subIfIdx" => 4,
        "ip" => 5,
        "ipv6" => 6,
        "icmp" => 7,
        "tcp" => 8,
        "udp" => 9,
        "icmpv6" => 10,
        "ip.HdrLength" => 11,
        "ip.TOS" => 12,
        "ip.Length" => 13,
        "ip.Id" => 14,
        "ip.DF" => 15,
        "ip.MF" => 16,
        "ip.FragOff" => 17,
        "ip.TTL" => 18,
        "ip.Protocol" => 19,
        "ip.Checksum" => 20,
        "ip.SrcAddr" => 21,
        "ip.DstAddr" => 22,
        "ipv6.TrafficClass" => 23,
        "ipv6.FlowLabel" => 24,
        "ipv6.Length" => 25,
        "ipv6.NextHdr" => 26,
        "ipv6.HopLimit" => 27,
        "ipv6.SrcAddr" => 28,
        "ipv6.DstAddr" => 29,
        "icmp.Type" => 30,
        "icmp.Code" => 31,
        "icmp.Checksum" => 32,
        "icmp.Body" => 33,
        "icmpv6.Type" => 34,
        "icmpv6.Code" => 35,
        "icmpv6.Checksum" => 36,
        "icmpv6.Body" => 37,
        "tcp.SrcPort" => 38,
        "tcp.DstPort" => 39,
        "tcp.SeqNum" => 40,
        "tcp.AckNum" => 41,
        "tcp.HdrLength" => 42,
        "tcp.Urg" => 43,
        "tcp.Ack" => 44,
        "tcp.Psh" => 45,
        "tcp.Rst" => 46,
        "tcp.Syn" => 47,
        "tcp.Fin" => 48,
        "tcp.Window" => 49,
        "tcp.Checksum" => 50,
        "tcp.UrgPtr" => 51,
        "tcp.PayloadLength" => 52,
        "udp.SrcPort" => 53,
        "udp.DstPort" => 54,
        "udp.Length" => 55,
        "udp.Checksum" => 56,
        "udp.PayloadLength" => 57,
        "loopback" => 58,
        "impostor" => 59,
        "processId" => 60,
        "localAddr" => 61,
        "remoteAddr" => 62,
        "localPort" => 63,
        "remotePort" => 64,
        "protocol" => 65,
        "endpointId" => 66,
        "parentEndpointId" => 67,
        "layer" => 68,
        "priority" => 69,
        "event" => 70,
        "packet" => 71,
        "packet16" => 72,
        "packet32" => 73,
        "tcp.Payload" => 74,
        "tcp.Payload16" => 75,
        "tcp.Payload32" => 76,
        "udp.Payload" => 77,
        "udp.Payload16" => 78,
        "udp.Payload32" => 79,
        "length" => 80,
        "timestamp" => 81,
        "random8" => 82,
        "random16" => 83,
        "random32" => 84,
        "fragment" => 85,
        _ => u32::MAX,
    }
}

fn proto_id(p: Proto) -> u32 {
    match p {
        Proto::Ip => 5,
        Proto::Ipv6 => 6,
        Proto::Icmp => 7,
        Proto::Tcp => 8,
        Proto::Udp => 9,
        Proto::Icmpv6 => 10,
    }
}

fn test_id(op: Op) -> u32 {
    match op {
        Op::Eq => 0,
        Op::Ne => 1,
        Op::Lt => 2,
        Op::Le => 3,
        Op::Gt => 4,
        Op::Ge => 5,
    }
}

/// A test after WinDivert's simplification: a constant, or a test to emit.
enum Leaf {
    Const(bool),
    Test(Insn),
}

/// `WinDivertSimplifyTest`: a comparison the field's range decides becomes a test of the field's
/// protocol (`tcp.Syn <= 1` is `tcp == 1`), or a constant when the field has none. WinDivert
/// leaves `loopback` and `impostor` alone, unlike the evaluator, whose result is the same.
fn simplify(t: &Test) -> Leaf {
    let def: &Def = t.def;
    let decided = match def.name {
        "loopback" | "impostor" => None,
        _ => def
            .range
            .as_ref()
            .and_then(|r| r.decide(t.op, (t.neg, t.val)).map(|b| (r.ty, b))),
    };
    let insn = |field, test, neg, arg| Insn {
        field,
        test,
        neg,
        arg,
        succ: 0,
        fail: 0,
    };
    match decided {
        Some((None, b)) => Leaf::Const(b),
        Some((Some(p), b)) => Leaf::Test(insn(proto_id(p), 0, false, [b.into(), 0, 0, 0])),
        None => {
            let v = t.val;
            let mut arg = [
                v as u32,
                (v >> 32) as u32,
                (v >> 64) as u32,
                (v >> 96) as u32,
            ];
            if let Lower::Data(..) = def.lower {
                arg[1] = t.index as u32;
            }
            Leaf::Test(insn(field_id(def.name), test_id(t.op), t.neg, arg))
        }
    }
}

/// `WinDivertFlattenExpr`: the tests in reverse order of evaluation, each jumping to labels
/// (indexes in `stack`) or to `ACCEPT`/`REJECT`. Returns the label evaluation starts at.
fn flatten(e: &Expr, mut succ: u16, mut fail: u16, stack: &mut Vec<Insn>) -> Option<u16> {
    match e {
        Expr::And(v) => {
            for x in v.iter().rev() {
                succ = flatten(x, succ, fail, stack)?;
            }
            Some(succ)
        }
        Expr::Or(v) => {
            for x in v.iter().rev() {
                fail = flatten(x, succ, fail, stack)?;
            }
            Some(fail)
        }
        Expr::Cond(c, a, b) => {
            let fail1 = flatten(b, succ, fail, stack)?;
            let succ1 = flatten(a, succ, fail, stack)?;
            flatten(c, succ1, fail1, stack)
        }
        Expr::Test(t) => match simplify(t) {
            Leaf::Const(b) => Some(if b { succ } else { fail }),
            Leaf::Test(mut insn) => {
                if stack.len() >= MAX_LEN {
                    return None;
                }
                insn.succ = succ;
                insn.fail = fail;
                stack.push(insn);
                Some((stack.len() - 1) as u16)
            }
        },
    }
}

const DIGITS: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+=";

/// `WinDivertSerializeNumber`: 5-bit digits, most significant first (the first one has 2 bits),
/// without leading zeros; the last digit comes from the upper half of the alphabet.
fn number(out: &mut String, v: u32) {
    let mut dig = 6;
    while dig > 0 && v >> (5 * dig) == 0 {
        dig -= 1;
    }
    loop {
        let d = (v >> (5 * dig)) & 0x1f;
        let last = dig == 0;
        out.push(DIGITS[d as usize + if last { 32 } else { 0 }] as char);
        if last {
            return;
        }
        dig -= 1;
    }
}

fn label(out: &mut String, l: u16) {
    match l {
        ACCEPT => out.push('A'),
        REJECT => out.push('X'),
        l => {
            out.push('L');
            number(out, l.into());
        }
    }
}

/// WinDivert's serialized filter object for a WinDivert filter at `layer`.
pub(crate) fn object(src: &str, layer: crate::meta::Layer) -> Result<String, Diagnostic> {
    super::compile(src, layer)?;
    let e = super::parse::parse(src, layer)?;
    let mut stack = Vec::new();
    let entry = flatten(&e, ACCEPT, REJECT, &mut stack).ok_or_else(|| {
        Diagnostic::error(Span::new(0, src.len()), "the filter is too long")
            .help("WinDivert's filter object holds at most 256 tests")
    })?;
    // `WinDivertEmitFilter`: the entry first, labels counted from it.
    let insns: Vec<Insn> = match entry {
        ACCEPT | REJECT => alloc::vec![Insn {
            field: 0,
            test: 0,
            neg: false,
            arg: [0; 4],
            succ: entry,
            fail: entry,
        }],
        _ => {
            let to = |l: u16| match l {
                ACCEPT | REJECT => l,
                l => entry - l,
            };
            (0..=entry)
                .map(|i| {
                    let mut t = stack[usize::from(entry - i)];
                    t.succ = to(t.succ);
                    t.fail = to(t.fail);
                    t
                })
                .collect()
        }
    };
    let mut out = String::from("@WinDiv_");
    number(&mut out, 0);
    // WinDivert writes the length as a byte.
    number(&mut out, u32::from(insns.len() as u8));
    for t in &insns {
        out.push('_');
        for v in [t.field, t.test, t.neg.into(), t.arg[0]] {
            number(&mut out, v);
        }
        match t.field {
            // IPv6, local and remote addresses: all four words.
            28 | 29 | 61 | 62 => {
                for &a in &t.arg[1..] {
                    number(&mut out, a);
                }
            }
            // 64-bit fields: the second word.
            66 | 67 | 81 => number(&mut out, t.arg[1]),
            // Indexed fields: the index, offset to be positive.
            71..=79 => number(&mut out, (t.arg[1] as i32).wrapping_add(0xffff) as u32),
            _ => {}
        }
        label(&mut out, t.succ);
        label(&mut out, t.fail);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every field the front-end knows has an id in the object.
    #[test]
    fn every_field_has_an_id() {
        for d in super::super::FIELDS {
            assert_ne!(field_id(d.name), u32::MAX, "{}", d.name);
        }
    }

    #[test]
    fn numbers() {
        let s = |v| {
            let mut o = String::new();
            number(&mut o, v);
            o
        };
        assert_eq!(s(0), "W");
        assert_eq!(s(31), "=");
        assert_eq!(s(32), "1W");
        assert_eq!(s(0xffff_ffff), "3VVVVV=");
    }
}
