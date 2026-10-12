//! Typed intermediate representation. Every backend runs this: the interpreter directly, the eBPF
//! code generator and the bytecode compiler (planned) by lowering it.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

pub use crate::ast::{Slice, SliceEnd};
use crate::fields::{Field, def};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Test {
    Const(bool),
    /// The value has at least one occurrence.
    Exists(Value),
    /// Some occurrence is true or non-zero.
    Truthy(Value),
    Cmp {
        lhs: Value,
        op: CmpOp,
        rhs: Value,
    },
    /// Some occurrence is in the set.
    In {
        lhs: Value,
        set: Vec<SetItem>,
    },
    /// Some occurrence contains some occurrence of `rhs` as a byte substring.
    Contains {
        lhs: Value,
        rhs: Value,
    },
    Not(Box<Test>),
    And(Vec<Test>),
    Or(Vec<Test>),
    Xor(Box<Test>, Box<Test>),
}

/// Comparison with Wireshark's quantifiers over multi-occurrence fields (`ip.addr`, `tcp.port`,
/// `vlan.id`). Every comparison is false when either side has no occurrence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpOp {
    /// Some pair is equal.
    Eq,
    /// No pair is equal (`!=` is `all_ne` since Wireshark 3.6).
    Ne,
    /// Every pair is equal.
    AllEq,
    /// Some pair differs.
    AnyNe,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Field(Field),
    Slice(Box<Value>, Slice),
    BitAnd(Box<Value>, Box<Value>),
    /// Byte length of each occurrence.
    Len(Box<Value>),
    /// Number of occurrences.
    Count(Box<Value>),
    Lit(Lit),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetItem {
    One(Lit),
    /// Inclusive range.
    Range(Lit, Lit),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lit {
    Bool(bool),
    Uint(u64),
    /// Address and prefix length (32 for a single address).
    Ipv4([u8; 4], u8),
    /// Address and prefix length (128 for a single address).
    Ipv6([u8; 16], u8),
    Ether([u8; 6]),
    Bytes(Vec<u8>),
}

impl Lit {
    pub(crate) fn has_prefix(&self) -> bool {
        matches!(self, Lit::Ipv4(_, p) if *p < 32) || matches!(self, Lit::Ipv6(_, p) if *p < 128)
    }
}

/// Flattens nested `and`/`or`, removes double negations and folds constants.
pub fn simplify(t: Test) -> Test {
    match t {
        Test::Not(inner) => match simplify(*inner) {
            Test::Not(x) => *x,
            Test::Const(b) => Test::Const(!b),
            x => Test::Not(Box::new(x)),
        },
        Test::And(v) => junction(v, true),
        Test::Or(v) => junction(v, false),
        Test::Xor(a, b) => match (simplify(*a), simplify(*b)) {
            (Test::Const(a), Test::Const(b)) => Test::Const(a != b),
            (a, b) => Test::Xor(Box::new(a), Box::new(b)),
        },
        t => t,
    }
}

/// `and` when `is_and`, else `or`.
fn junction(v: Vec<Test>, is_and: bool) -> Test {
    let mut out = Vec::with_capacity(v.len());
    for t in v.into_iter().map(simplify) {
        match t {
            // `x and true`, `x or false`: drop.
            Test::Const(b) if b == is_and => {}
            // `x and false`, `x or true`: the whole junction is decided.
            Test::Const(b) => return Test::Const(b),
            Test::And(inner) if is_and => out.extend(inner),
            Test::Or(inner) if !is_and => out.extend(inner),
            t => out.push(t),
        }
    }
    match out.len() {
        0 => Test::Const(is_and),
        1 => out.remove(0),
        _ if is_and => Test::And(out),
        _ => Test::Or(out),
    }
}

impl fmt::Display for Test {
    /// S-expression form, shown by `avulse filter explain`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Test::Const(b) => write!(f, "{b}"),
            Test::Exists(v) => write!(f, "(exists {v})"),
            Test::Truthy(v) => write!(f, "(true {v})"),
            Test::Cmp { lhs, op, rhs } => write!(f, "({op} {lhs} {rhs})"),
            Test::In { lhs, set } => {
                write!(f, "(in {lhs}")?;
                for item in set {
                    match item {
                        SetItem::One(l) => write!(f, " {l}")?,
                        SetItem::Range(a, b) => write!(f, " {a}..{b}")?,
                    }
                }
                write!(f, ")")
            }
            Test::Contains { lhs, rhs } => write!(f, "(contains {lhs} {rhs})"),
            Test::Not(t) => write!(f, "(not {t})"),
            Test::And(v) => list(f, "and", v),
            Test::Or(v) => list(f, "or", v),
            Test::Xor(a, b) => write!(f, "(xor {a} {b})"),
        }
    }
}

fn list(f: &mut fmt::Formatter<'_>, name: &str, v: &[Test]) -> fmt::Result {
    write!(f, "({name}")?;
    for t in v {
        write!(f, " {t}")?;
    }
    write!(f, ")")
}

impl fmt::Display for CmpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CmpOp::Eq => "any_eq",
            CmpOp::Ne => "all_ne",
            CmpOp::AllEq => "all_eq",
            CmpOp::AnyNe => "any_ne",
            CmpOp::Lt => "lt",
            CmpOp::Le => "le",
            CmpOp::Gt => "gt",
            CmpOp::Ge => "ge",
        })
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Field(field) => f.write_str(def(*field).name),
            Value::Slice(v, s) => match s.end {
                SliceEnd::Len(n) => write!(f, "{v}[{}:{n}]", s.start),
                SliceEnd::Inclusive(e) => write!(f, "{v}[{}-{e}]", s.start),
                SliceEnd::Open => write!(f, "{v}[{}:]", s.start),
            },
            Value::BitAnd(a, b) => write!(f, "(& {a} {b})"),
            Value::Len(v) => write!(f, "(len {v})"),
            Value::Count(v) => write!(f, "(count {v})"),
            Value::Lit(l) => write!(f, "{l}"),
        }
    }
}

impl fmt::Display for Lit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Lit::Bool(b) => write!(f, "{b}"),
            Lit::Uint(v) => write!(f, "{v}"),
            Lit::Ipv4(a, p) => {
                write!(f, "{}", core::net::Ipv4Addr::from(*a))?;
                if *p < 32 { write!(f, "/{p}") } else { Ok(()) }
            }
            Lit::Ipv6(a, p) => {
                write!(f, "{}", core::net::Ipv6Addr::from(*a))?;
                if *p < 128 { write!(f, "/{p}") } else { Ok(()) }
            }
            Lit::Ether(m) => {
                write!(
                    f,
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    m[0], m[1], m[2], m[3], m[4], m[5]
                )
            }
            Lit::Bytes(b) => {
                for (i, x) in b.iter().enumerate() {
                    if i > 0 {
                        write!(f, ":")?;
                    }
                    write!(f, "{x:02x}")?;
                }
                if b.is_empty() {
                    write!(f, "\"\"")
                } else {
                    Ok(())
                }
            }
        }
    }
}
