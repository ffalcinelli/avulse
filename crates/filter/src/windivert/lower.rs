//! WinDivert tests to native IR, with WinDivert's simplification of decided comparisons.

use alloc::boxed::Box;
use alloc::vec;
use core::cmp::Ordering;

use super::parse::{Expr, Op, Test as WdTest};
use super::{Base, Lower, Num, Proto, Range};
use crate::fields::{Field, Ty};
use crate::ir::{CmpOp, Lit, Quant, SetItem, Slice, SliceEnd, Test, Value};
use crate::meta::Layer;

pub(super) fn expr(e: &Expr, layer: Layer) -> Test {
    match e {
        Expr::Test(t) => test(t, layer),
        Expr::And(v) => Test::And(v.iter().map(|e| expr(e, layer)).collect()),
        Expr::Or(v) => Test::Or(v.iter().map(|e| expr(e, layer)).collect()),
        Expr::Cond(c, a, b) => Test::If(
            Box::new(expr(c, layer)),
            Box::new(expr(a, layer)),
            Box::new(expr(b, layer)),
        ),
    }
}

/// WinDivert's signed comparison: the sign first (so `-0` is below `0`), then the magnitude.
fn cmp128(a: Num, b: Num) -> Ordering {
    match (a.0, b.0) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => a.1.cmp(&b.1),
        (true, true) => b.1.cmp(&a.1),
    }
}

fn holds(op: Op, o: Ordering) -> bool {
    match op {
        Op::Eq => o.is_eq(),
        Op::Ne => o.is_ne(),
        Op::Lt => o.is_lt(),
        Op::Le => o.is_le(),
        Op::Gt => o.is_gt(),
        Op::Ge => o.is_ge(),
    }
}

/// Whether a field whose value is `v` passes `op c`.
fn passes(v: Num, op: Op, c: Num) -> bool {
    holds(op, cmp128(v, c))
}

impl Range {
    /// The result of `field op c` when the range decides it, as WinDivert's compiler computes it.
    pub(super) fn decide(&self, op: Op, c: Num) -> Option<bool> {
        let (lo, hi) = (cmp128(c, self.lo), cmp128(c, self.hi));
        let outside = lo.is_lt() || hi.is_gt();
        match op {
            Op::Eq | Op::Ne if outside => Some(op == Op::Ne),
            Op::Eq | Op::Ne if self.eq && lo.is_eq() => Some(op == Op::Eq),
            Op::Lt if hi.is_gt() => Some(true),
            Op::Lt if lo.is_le() => Some(false),
            Op::Le if hi.is_ge() => Some(true),
            Op::Le if lo.is_lt() => Some(false),
            Op::Gt if hi.is_ge() => Some(false),
            Op::Gt if lo.is_lt() => Some(true),
            Op::Ge if hi.is_gt() => Some(false),
            Op::Ge if lo.is_le() => Some(true),
            _ => None,
        }
    }
}

fn field(f: Field) -> Value {
    Value::Field(f)
}

fn exists(v: Value) -> Test {
    Test::Exists(v)
}

fn not(t: Test) -> Test {
    Test::Not(Box::new(t))
}

fn cmp_op(op: Op) -> (CmpOp, Quant) {
    match op {
        Op::Eq => (CmpOp::Eq, Quant::Any),
        Op::Ne => (CmpOp::Ne, Quant::All),
        Op::Lt => (CmpOp::Lt, Quant::Any),
        Op::Le => (CmpOp::Le, Quant::Any),
        Op::Gt => (CmpOp::Gt, Quant::Any),
        Op::Ge => (CmpOp::Ge, Quant::Any),
    }
}

fn cmp(lhs: Value, op: Op, rhs: Lit) -> Test {
    let (op, quant) = cmp_op(op);
    Test::Cmp {
        lhs,
        op,
        quant,
        rhs: Value::Lit(rhs),
    }
}

/// The address is an IPv4 (`v6` false) or IPv6 address.
fn family(f: Field, v6: bool) -> Test {
    let any = if v6 {
        Lit::Ipv6([0; 16], 0)
    } else {
        Lit::Ipv4([0; 4], 0)
    };
    Test::Member {
        lhs: field(f),
        set: vec![SetItem::One(any)],
        quant: Quant::Any,
        negate: false,
    }
}

/// The packet (or flow) has protocol `p`.
fn has(p: Proto, layer: Layer) -> Test {
    let packet = matches!(layer, Layer::Network | Layer::NetworkForward);
    let protocol = |n: u64| cmp(field(Field::Protocol), Op::Eq, Lit::Uint(n));
    match (p, packet) {
        (Proto::Ip, true) => exists(field(Field::Ip)),
        (Proto::Ipv6, true) => exists(field(Field::Ipv6)),
        (Proto::Icmp, true) => exists(field(Field::Icmp)),
        (Proto::Icmpv6, true) => exists(field(Field::Icmpv6)),
        (Proto::Tcp, true) => exists(field(Field::Tcp)),
        (Proto::Udp, true) => exists(field(Field::Udp)),
        // FLOW and SOCKET: the flow's family and protocol.
        (Proto::Ip, false) => family(Field::LocalAddr, false),
        (Proto::Ipv6, false) => family(Field::LocalAddr, true),
        (Proto::Icmp, false) => Test::And(vec![family(Field::LocalAddr, false), protocol(1)]),
        (Proto::Icmpv6, false) => Test::And(vec![family(Field::LocalAddr, true), protocol(58)]),
        (Proto::Tcp, false) => protocol(6),
        (Proto::Udp, false) => protocol(17),
    }
}

/// A test on a value that is 0 or 1: `one` holds when it is 1, `zero` when it is 0, and `either`
/// when it is present at all.
fn bit(op: Op, c: Num, one: Test, zero: Test, either: Test) -> Test {
    match (passes((false, 0), op, c), passes((false, 1), op, c)) {
        (true, true) => either,
        (false, true) => one,
        (true, false) => zero,
        (false, false) => Test::Const(false),
    }
}

/// `v op c` where every value of `v` is above `c`.
fn above(v: Value, op: Op) -> Test {
    match op {
        Op::Ne | Op::Gt | Op::Ge => exists(v),
        Op::Eq | Op::Lt | Op::Le => Test::Const(false),
    }
}

/// `v op c` where every value of `v` is below `c`.
fn below(v: Value, op: Op) -> Test {
    match op {
        Op::Ne | Op::Lt | Op::Le => exists(v),
        Op::Eq | Op::Gt | Op::Ge => Test::Const(false),
    }
}

/// A numeric comparison with a signed constant.
fn num(v: Value, op: Op, c: Num) -> Test {
    // The largest value the native field can hold: a constant above it decides the test (and
    // would not compile as a native filter).
    let max = match &v {
        Value::Field(f) => match crate::fields::def(*f).ty {
            Ty::Uint(bits) if bits < 64 => (1u128 << bits) - 1,
            _ => u128::from(u64::MAX),
        },
        _ => u128::from(u64::MAX),
    };
    match c {
        (false, m) if m > max => below(v, op),
        (false, m) => cmp(v, op, Lit::Uint(m as u64)),
        // `-0` is below every value of a field, but above the negative ones.
        (true, 0) => match op {
            Op::Eq => Test::Const(false),
            Op::Ne => exists(v),
            Op::Lt | Op::Le => cmp(v, Op::Lt, Lit::Int(0)),
            Op::Gt | Op::Ge => cmp(v, Op::Ge, Lit::Int(0)),
        },
        (true, m) => match i64::try_from(m) {
            Ok(m) => cmp(v, op, Lit::Int(-m)),
            Err(_) if m == 1 << 63 => cmp(v, op, Lit::Int(i64::MIN)),
            Err(_) => above(v, op),
        },
    }
}

/// A comparison of `width` big-endian bytes with a constant.
fn bytes(v: Value, op: Op, c: Num, width: u8) -> Test {
    match c {
        (true, _) => above(v, op),
        (false, m) if m >> (8 * u32::from(width)) != 0 => below(v, op),
        (false, m) => {
            let be = m.to_be_bytes();
            cmp(v, op, Lit::Bytes(be[16 - usize::from(width)..].to_vec()))
        }
    }
}

fn slice(base: Field, start: i64, len: i64) -> Value {
    Value::Slice(
        Box::new(field(base)),
        vec![Slice {
            start,
            end: SliceEnd::Len(len),
        }],
    )
}

/// `localAddr` or `remoteAddr`: IPv4 addresses are `::ffff:a.b.c.d`, and a packet without IP has
/// address 0.
fn addr(f: Field, op: Op, c: Num) -> Test {
    const LO: u128 = super::MAPPED;
    const HI: u128 = super::MAPPED | super::U32;
    let v4 = match c {
        (true, _) => above(field(f), op),
        (false, m) if m < LO => above(field(f), op),
        (false, m) if m > HI => below(field(f), op),
        (false, m) => cmp(field(f), op, Lit::Ipv4((m as u32).to_be_bytes(), 32)),
    };
    let v6 = match c {
        (true, _) => above(field(f), op),
        (false, m) => cmp(field(f), op, Lit::Ipv6(m.to_be_bytes(), 128)),
    };
    // The comparison is false for an address of the other family, except `!=`, which is true.
    let only = |t: Test, v6: bool| match t {
        Test::Exists(_) => family(f, v6),
        t if op == Op::Ne => Test::And(vec![family(f, v6), t]),
        t => t,
    };
    Test::Or(vec![
        only(v4, false),
        only(v6, true),
        Test::And(vec![
            not(exists(field(f))),
            Test::Const(passes((false, 0), op, c)),
        ]),
    ])
}

/// `localPort` (`local`) or `remotePort` at the NETWORK layer: the TCP or UDP port on that side;
/// for ICMP, the type on the sending side and 0 on the other; otherwise 0.
fn port(local: bool, op: Op, c: Num) -> Test {
    let f = if local {
        Field::LocalPort
    } else {
        Field::RemotePort
    };
    // The local side sends outbound packets.
    let sender = Test::Truthy(field(if local {
        Field::Outbound
    } else {
        Field::Inbound
    }));
    let zero = Test::Const(passes((false, 0), op, c));
    let icmp = Test::Or(vec![
        exists(field(Field::Icmp)),
        exists(field(Field::Icmpv6)),
    ]);
    Test::Or(vec![
        num(field(f), op, c),
        Test::And(vec![
            sender.clone(),
            Test::Or(vec![
                num(field(Field::IcmpType), op, c),
                num(field(Field::Icmpv6Type), op, c),
            ]),
        ]),
        Test::And(vec![not(sender), icmp.clone(), zero.clone()]),
        Test::And(vec![
            not(exists(field(Field::Tcp))),
            not(exists(field(Field::Udp))),
            not(icmp),
            zero,
        ]),
    ])
}

fn test(t: &WdTest, layer: Layer) -> Test {
    let def = t.def;
    let op = t.op;
    if let Some(r) = &def.range
        && let Some(result) = r.decide(op, (t.neg, t.val))
    {
        return match (r.ty, result) {
            (None, b) => Test::Const(b),
            (Some(p), true) => has(p, layer),
            (Some(p), false) => not(has(p, layer)),
        };
    }
    // Fields narrower than 64 bits compare the low 32 bits of the value.
    let c = (t.neg, if def.big { t.val } else { t.val & super::U32 });
    let index = i64::from(t.index);
    match def.lower {
        Lower::Const(v) => Test::Const(passes((false, v), op, c)),
        Lower::Num(f) => num(field(f), op, c),
        Lower::Flag(f) => bit(
            op,
            c,
            Test::Truthy(field(f)),
            not(Test::Truthy(field(f))),
            Test::Const(true),
        ),
        Lower::Bit(f, p) => bit(
            op,
            c,
            cmp(field(f), Op::Eq, Lit::Bool(true)),
            cmp(field(f), Op::Eq, Lit::Bool(false)),
            has(p, layer),
        ),
        Lower::Present(p) => bit(op, c, has(p, layer), not(has(p, layer)), Test::Const(true)),
        Lower::Words(f) => match c {
            (false, m) => num(field(f), op, (false, m.saturating_mul(4))),
            c => num(field(f), op, c),
        },
        Lower::Addr4(f) => match c {
            (false, m) if (super::MAPPED..=super::MAPPED | super::U32).contains(&m) => {
                cmp(field(f), op, Lit::Ipv4((m as u32).to_be_bytes(), 32))
            }
            // The range check above decides every other value.
            (true, _) => above(field(f), op),
            (false, m) if m < super::MAPPED => above(field(f), op),
            (false, _) => below(field(f), op),
        },
        Lower::Addr6(f) => match c {
            (true, _) => above(field(f), op),
            (false, m) => cmp(field(f), op, Lit::Ipv6(m.to_be_bytes(), 128)),
        },
        Lower::Addr(f) => addr(f, op, c),
        Lower::Port(local) => match layer {
            Layer::Network | Layer::NetworkForward => port(local, op, c),
            _ => num(
                field(if local {
                    Field::LocalPort
                } else {
                    Field::RemotePort
                }),
                op,
                c,
            ),
        },
        Lower::PayloadLen(p) => {
            let payload = if p == Proto::Tcp {
                Field::TcpPayload
            } else {
                Field::UdpPayload
            };
            // The native payload field is absent when it is empty.
            Test::Or(vec![
                num(Value::Len(Box::new(field(payload))), op, c),
                Test::And(vec![
                    has(p, layer),
                    not(exists(field(payload))),
                    Test::Const(passes((false, 0), op, c)),
                ]),
            ])
        }
        Lower::Data(base, width) => {
            let base = match base {
                Base::Frame => Field::Frame,
                Base::Tcp => Field::TcpPayload,
                Base::Udp => Field::UdpPayload,
            };
            bytes(slice(base, index, width.into()), op, c, width)
        }
        Lower::Body(p) => {
            let msg = if p == Proto::Icmp {
                Field::Icmp
            } else {
                Field::Icmpv6
            };
            bytes(slice(msg, 4, 4), op, c, 4)
        }
    }
}
