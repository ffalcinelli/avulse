//! IR interpreter, the reference implementation of the filter semantics. It does not allocate
//! (except `matches`), so it can run in kernel contexts. The operations on values live in
//! [`crate::value`], shared with the bytecode interpreter.

use avulse_proto::Packet;

use crate::ir::{SetItem, Test, Value};
use crate::meta::Meta;
use crate::regex::{self, Regex};
use crate::value::{self, V, Vals, lit, quantify};

struct Cx<'a> {
    pkt: &'a Packet<'a>,
    meta: &'a Meta<'a>,
    regexes: &'a [Regex],
}

pub(crate) fn matches(t: &Test, pkt: &Packet<'_>, meta: &Meta<'_>, regexes: &[Regex]) -> bool {
    test(t, &Cx { pkt, meta, regexes })
}

fn test<'a>(t: &'a Test, cx: &Cx<'a>) -> bool {
    match t {
        Test::Const(b) => *b,
        Test::Exists(v) => !value(v, cx).as_slice().is_empty(),
        Test::Truthy(v) => value(v, cx).as_slice().iter().any(V::truthy),
        Test::Cmp {
            lhs,
            op,
            quant,
            rhs,
        } => value::cmp_test(*op, *quant, &value(lhs, cx), &value(rhs, cx)),
        Test::Member {
            lhs,
            set,
            quant,
            negate,
        } => value::member_test(&value(lhs, cx), set_items(set), *quant, *negate),
        Test::Contains { lhs, rhs, quant } => {
            value::contains_test(*quant, &value(lhs, cx), &value(rhs, cx))
        }
        Test::Matches {
            lhs, index, quant, ..
        } => {
            let Some(re) = cx.regexes.get(*index) else {
                return false;
            };
            let l = value(lhs, cx);
            let l = l.as_slice();
            !l.is_empty() && quantify(*quant, l.iter().map(|v| regex_match(re, v)))
        }
        Test::Not(t) => !test(t, cx),
        Test::And(v) => v.iter().all(|t| test(t, cx)),
        Test::Or(v) => v.iter().any(|t| test(t, cx)),
        Test::Xor(a, b) => test(a, cx) != test(b, cx),
        Test::If(c, a, b) => {
            if test(c, cx) {
                test(a, cx)
            } else {
                test(b, cx)
            }
        }
    }
}

/// The items of a set, as [`value::member_test`] takes them.
fn set_items(set: &[SetItem]) -> impl Iterator<Item = (V<'_>, Option<V<'_>>)> + Clone {
    set.iter().map(|item| match item {
        SetItem::One(l) => (lit(l), None),
        SetItem::Range(lo, hi) => (lit(lo), Some(lit(hi))),
    })
}

/// Runs a pattern over a value. This is the one place where evaluation may allocate (inside the
/// regex engine, and to fold `upper()`/`lower()` strings): `matches` is user space only.
fn regex_match(re: &Regex, v: &V<'_>) -> bool {
    match v {
        V::Folded(..) => v.seq().is_some_and(|s| {
            let folded: alloc::vec::Vec<u8> = s.iter().collect();
            regex::is_match(re, &folded)
        }),
        v => v.bytes().is_some_and(|b| regex::is_match(re, b)),
    }
}

fn value<'a>(v: &'a Value, cx: &Cx<'a>) -> Vals<'a> {
    let (p, m) = (cx.pkt, cx.meta);
    match v {
        Value::Lit(l) => Vals::one(lit(l)),
        Value::Field(f) => value::load(*f, p, m),
        Value::Layer(f, ranges) => value::load_layer(*f, ranges.iter().copied(), p, m),
        Value::Raw(f, layers) => {
            value::load_raw(*f, layers.as_ref().map(|l| l.iter().copied()), p, m)
        }
        Value::Slice(base, ranges) => value::slice_vals(&value(base, cx), ranges.iter().copied()),
        Value::BitAnd(a, b) => value::bitand(&value(a, cx), &value(b, cx)),
        Value::Arith(op, a, b) => value::arith(*op, &value(a, cx), &value(b, cx)),
        Value::Neg(a) => value::neg_abs(&value(a, cx), false),
        Value::Abs(a) => value::neg_abs(&value(a, cx), true),
        Value::Extreme { max, args } => args.iter().fold(Vals::new(), |best, a| {
            value::extreme(*max, &best, &value(a, cx))
        }),
        Value::Len(base) => value::len(&value(base, cx)),
        Value::Count(base) => value::count(&value(base, cx)),
        Value::Case { upper, value: base } => value::case(&value(base, cx), *upper),
    }
}
