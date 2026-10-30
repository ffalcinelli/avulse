//! IR to native filter syntax: what `avulse filter convert` prints for a WinDivert filter.

use core::fmt::{self, Display, Formatter, Write};

use crate::ast::{Quant, fmt_layers, fmt_str};
use crate::fields::{Origin, Ty, def};
use crate::ir::{CmpOp, Lit, SetItem, Test, Value};

/// A [`Test`] printed in native syntax, from [`Test::native`].
pub struct Native<'a>(&'a Test);

impl Test {
    /// The test in native filter syntax. Compiling the text gives a filter that selects the same
    /// packets.
    ///
    /// ```
    /// use avulse_filter::{Filter, Layer};
    ///
    /// let f = Filter::compile_windivert("packet16[1] == 0x54 or ip.HdrLength > 5", Layer::Network)
    ///     .unwrap();
    /// assert_eq!(
    ///     f.ir().native().to_string(),
    ///     "frame[2:2] == 00:54 or ip.hdr_len > 20"
    /// );
    /// ```
    pub fn native(&self) -> Native<'_> {
        Native(self)
    }

    /// How many tests [`native`](Self::native) prints (saturating). It can be much larger than
    /// the test itself: native syntax has no conditional, so each `If` prints its condition
    /// twice, and conditionals nested in conditions double at every level.
    pub fn native_tests(&self) -> usize {
        match self {
            Test::Not(t) => t.native_tests(),
            Test::And(v) | Test::Or(v) => v
                .iter()
                .fold(0usize, |n, t| n.saturating_add(t.native_tests())),
            Test::Xor(a, b) => a.native_tests().saturating_add(b.native_tests()),
            Test::If(c, a, b) => c
                .native_tests()
                .saturating_mul(2)
                .saturating_add(a.native_tests())
                .saturating_add(b.native_tests()),
            _ => 1,
        }
    }
}

impl Display for Native<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        test(f, self.0, 0)
    }
}

/// Binding strength: `or` < `xor` < `and` < `not` < a test.
fn prec(t: &Test) -> u8 {
    match t {
        Test::Or(_) => 1,
        Test::Xor(..) => 2,
        // Printed as `c and a or not c and b`.
        Test::If(..) => 1,
        Test::And(_) => 3,
        Test::Not(_) => 4,
        _ => 5,
    }
}

fn test(f: &mut Formatter<'_>, t: &Test, min: u8) -> fmt::Result {
    if prec(t) < min {
        f.write_char('(')?;
        test(f, t, 0)?;
        return f.write_char(')');
    }
    match t {
        Test::Const(b) => write!(f, "{b}"),
        Test::Exists(v) => match v {
            // Metadata flags are always present, and a bare one tests that it is true.
            Value::Field(x) if def(*x).origin == Origin::Flag => f.write_str("true"),
            // A bare boolean field tests presence, with a warning.
            Value::Field(x) | Value::Layer(x, _) if def(*x).ty == Ty::Bool => {
                f.write_str("count(")?;
                value(f, v)?;
                f.write_str(") > 0")
            }
            v => value(f, v),
        },
        Test::Truthy(v) => match v {
            Value::Field(x) if def(*x).origin == Origin::Flag => f.write_str(def(*x).name),
            Value::Field(x) if def(*x).ty == Ty::Bool => write!(f, "{} == true", def(*x).name),
            Value::Layer(x, _) if def(*x).ty == Ty::Bool => {
                f.write_str("any ")?;
                value(f, v)?;
                f.write_str(" == true")
            }
            Value::Field(x) | Value::Layer(x, _)
                if def(*x).ty != Ty::Proto && !def(*x).ty.is_bytes() =>
            {
                f.write_str("any ")?;
                value(f, v)?;
                f.write_str(" != 0")
            }
            Value::Len(_) | Value::Count(_) | Value::Abs(_) | Value::Extreme { .. } => {
                f.write_str("any ")?;
                value(f, v)?;
                f.write_str(" != 0")
            }
            v => value(f, v),
        },
        Test::Cmp {
            lhs,
            op,
            quant,
            rhs,
        } => {
            let sym = match (op, quant) {
                (CmpOp::Eq, Quant::Any) => "==",
                (CmpOp::Eq, Quant::All) => "===",
                (CmpOp::Ne, Quant::All) => "!=",
                (CmpOp::Ne, Quant::Any) => "!==",
                (CmpOp::Lt, _) => "<",
                (CmpOp::Le, _) => "<=",
                (CmpOp::Gt, _) => ">",
                (CmpOp::Ge, _) => ">=",
            };
            if *quant == Quant::All && !matches!(op, CmpOp::Eq | CmpOp::Ne) {
                f.write_str("all ")?;
            }
            value_for(f, lhs, is_str(rhs))?;
            write!(f, " {sym} ")?;
            value_for(f, rhs, is_str(lhs))
        }
        Test::Member {
            lhs,
            set,
            quant,
            negate,
        } => {
            if *quant == Quant::All {
                f.write_str("all ")?;
            }
            let as_str = is_str(lhs);
            value(f, lhs)?;
            f.write_str(if *negate { " not in {" } else { " in {" })?;
            for (i, item) in set.iter().enumerate() {
                if i > 0 {
                    if matches!(
                        item,
                        SetItem::One(Lit::Int(n)) | SetItem::Range(Lit::Int(n), _) if *n < 0
                    ) {
                        f.write_str(", ")?;
                    } else {
                        f.write_char(' ')?;
                    }
                }
                match item {
                    SetItem::One(l) => lit_for(f, l, as_str)?,
                    SetItem::Range(a, b) => {
                        lit_for(f, a, as_str)?;
                        f.write_str("..")?;
                        lit_for(f, b, as_str)?;
                    }
                }
            }
            f.write_char('}')
        }
        Test::Contains { lhs, rhs, quant } => {
            if *quant == Quant::All {
                f.write_str("all ")?;
            }
            value(f, lhs)?;
            f.write_str(" contains ")?;
            value_for(f, rhs, is_str(lhs))
        }
        Test::Matches {
            lhs,
            pattern,
            quant,
            ..
        } => {
            if *quant == Quant::All {
                f.write_str("all ")?;
            }
            value(f, lhs)?;
            f.write_str(" matches \"")?;
            for c in pattern.chars() {
                match c {
                    '"' | '\\' => write!(f, "\\{c}")?,
                    c => f.write_char(c)?,
                }
            }
            f.write_char('"')
        }
        Test::Not(t) => {
            f.write_str("not ")?;
            test(f, t, 4)
        }
        Test::And(v) => junction(f, v, " and ", 3),
        Test::Or(v) => junction(f, v, " or ", 1),
        Test::Xor(a, b) => {
            test(f, a, 3)?;
            f.write_str(" xor ")?;
            test(f, b, 3)
        }
        // Native filters have no conditional; this repeats the condition.
        Test::If(c, a, b) => {
            test(f, c, 4)?;
            f.write_str(" and ")?;
            test(f, a, 4)?;
            f.write_str(" or not ")?;
            test(f, c, 4)?;
            f.write_str(" and ")?;
            test(f, b, 4)
        }
    }
}

fn junction(f: &mut Formatter<'_>, v: &[Test], sep: &str, p: u8) -> fmt::Result {
    for (i, t) in v.iter().enumerate() {
        if i > 0 {
            f.write_str(sep)?;
        }
        // Children of the same kind are flattened by `simplify`; parenthesize looser ones.
        test(f, t, p + 1)?;
    }
    Ok(())
}

fn value(f: &mut Formatter<'_>, v: &Value) -> fmt::Result {
    match v {
        Value::Field(x) => f.write_str(def(*x).name),
        Value::Layer(x, layers) => {
            f.write_str(def(*x).name)?;
            fmt_layers(f, layers)
        }
        Value::Raw(x, layers) => {
            write!(f, "@{}", def(*x).name)?;
            match layers {
                Some(l) => fmt_layers(f, l),
                None => Ok(()),
            }
        }
        Value::Slice(base, ranges) => {
            grouped(f, base)?;
            f.write_char('[')?;
            for (i, r) in ranges.iter().enumerate() {
                if i > 0 {
                    f.write_char(',')?;
                }
                write!(f, "{r}")?;
            }
            f.write_char(']')
        }
        Value::BitAnd(a, b) => {
            value(f, a)?;
            f.write_str(" & ")?;
            value(f, b)
        }
        Value::Len(v) => call(f, "len", v),
        Value::Count(v) => call(f, "count", v),
        Value::Case { upper, value: v } => call(f, if *upper { "upper" } else { "lower" }, v),
        Value::Arith(op, a, b) => {
            f.write_char('{')?;
            grouped(f, a)?;
            write!(f, " {op} ")?;
            grouped(f, b)?;
            f.write_char('}')
        }
        Value::Neg(v) => {
            f.write_char('-')?;
            grouped(f, v)
        }
        Value::Abs(v) => call(f, "abs", v),
        Value::Extreme { max, args } => {
            f.write_str(if *max { "max(" } else { "min(" })?;
            for (i, a) in args.iter().enumerate() {
                if i > 0 {
                    f.write_str(", ")?;
                }
                value(f, a)?;
            }
            f.write_char(')')
        }
        Value::Lit(l) => lit_for(f, l, false),
    }
}

fn grouped(f: &mut Formatter<'_>, v: &Value) -> fmt::Result {
    if matches!(v, Value::BitAnd(..)) {
        f.write_char('{')?;
        value(f, v)?;
        f.write_char('}')
    } else {
        value(f, v)
    }
}

fn is_str(v: &Value) -> bool {
    match v {
        Value::Field(x) | Value::Layer(x, _) => def(*x).ty == Ty::Str,
        Value::Case { .. } => true,
        _ => false,
    }
}

fn value_for(f: &mut Formatter<'_>, v: &Value, as_str: bool) -> fmt::Result {
    match v {
        Value::Lit(l) => lit_for(f, l, as_str),
        _ => value(f, v),
    }
}

fn call(f: &mut Formatter<'_>, name: &str, v: &Value) -> fmt::Result {
    write!(f, "{name}(")?;
    value(f, v)?;
    f.write_char(')')
}

fn lit_for(f: &mut Formatter<'_>, l: &Lit, as_str: bool) -> fmt::Result {
    match l {
        Lit::Bytes(b) if as_str => fmt_str(f, b),
        // One byte in hex would read as a decimal integer: write it as one.
        Lit::Bytes(b) if b.len() == 1 => write!(f, "0x{:02x}", b[0]),
        l => write!(f, "{l}"),
    }
}
