//! Typed intermediate representation. Every backend runs this: the interpreter directly, the eBPF
//! code generator and the bytecode compiler (planned) by lowering it.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub use crate::ast::{ArithOp, Quant, Slice, SliceEnd};
use crate::fields::{Field, def};

/// A typed, name-resolved test: what [`Filter::matches`](crate::Filter::matches) evaluates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Test {
    /// Always true or always false.
    Const(bool),
    /// The value has at least one occurrence.
    Exists(Value),
    /// Some occurrence is true or non-zero.
    Truthy(Value),
    /// `quant` pair of occurrences satisfies `op`.
    Cmp {
        /// The left value.
        lhs: Value,
        /// The comparison.
        op: CmpOp,
        /// Which pairs must satisfy it.
        quant: Quant,
        /// The right value.
        rhs: Value,
    },
    /// Set membership. Without `negate`, `quant` occurrence is in the set (`in`, `all … in`). With
    /// it, the value is present and that is not the case (`not in`, `all … not in`), as in
    /// Wireshark.
    Member {
        /// The value tested.
        lhs: Value,
        /// The set.
        set: Vec<SetItem>,
        /// Which occurrences must be in the set.
        quant: Quant,
        /// Whether this is `not in`.
        negate: bool,
    },
    /// `quant` occurrence of `lhs` contains an occurrence of `rhs` as a byte substring.
    Contains {
        /// The haystack.
        lhs: Value,
        /// The needle.
        rhs: Value,
        /// Which occurrences of `lhs` must contain it.
        quant: Quant,
    },
    /// `quant` occurrence of `lhs` matches a regular expression: byte-oriented, case-insensitive
    /// unless the pattern says `(?-i)`. `index` refers to the patterns compiled with the filter.
    /// User space only.
    Matches {
        /// The value matched.
        lhs: Value,
        /// The pattern, as compiled.
        pattern: String,
        /// Index of the compiled pattern.
        index: usize,
        /// Which occurrences must match.
        quant: Quant,
    },
    /// Negation.
    Not(Box<Test>),
    /// Conjunction; an empty list is true.
    And(Vec<Test>),
    /// Disjunction; an empty list is false.
    Or(Vec<Test>),
    /// Exclusive or.
    Xor(Box<Test>, Box<Test>),
}

/// A comparison, applied to pairs of occurrences of multi-occurrence fields (`ip.addr`,
/// `tcp.port`, `vlan.id`) under a [`Quant`]. Wireshark's operators are an operator and a
/// quantifier: `==` is any `Eq`, `!=` all `Ne` (since Wireshark 3.6), `===` all `Eq`, `!==` any
/// `Ne`, and the orderings any; an explicit `any`/`all` overrides it. Every comparison is false when
/// either side has no occurrence. These semantics are checked against tshark 4.6 and 4.7 by
/// `tests/tshark.rs`. Known differences: Avulse matches only the outermost headers (not the
/// datagram an ICMP error quotes) and drops a header that is cut short, where Wireshark keeps the
/// fields that fit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpOp {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Less than.
    Lt,
    /// Less than or equal.
    Le,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Ge,
}

/// A typed value: zero or more occurrences, read from the packet, its metadata, or a literal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Every occurrence of a field.
    Field(Field),
    /// The occurrences of a field in the given protocol layers (`vlan.id#2`).
    Layer(Field, Vec<Slice>),
    /// `@field`: the bytes on the wire of each occurrence, optionally in some layers only.
    Raw(Field, Option<Vec<Slice>>),
    /// The bytes in `ranges`, concatenated; ranges that do not fit are skipped, as in Wireshark.
    Slice(Box<Value>, Vec<Slice>),
    /// Bitwise and of every pair of occurrences (integers, or byte strings cut to the shorter one).
    BitAnd(Box<Value>, Box<Value>),
    /// Byte length of each occurrence.
    Len(Box<Value>),
    /// Number of occurrences.
    Count(Box<Value>),
    /// A string field read through `upper()` or `lower()` (ASCII case folding).
    Case {
        /// `upper()` if true, `lower()` if false.
        upper: bool,
        /// The string value.
        value: Box<Value>,
    },
    /// Signed arithmetic on every pair of occurrences. Overflow and division by zero give no
    /// value.
    Arith(ArithOp, Box<Value>, Box<Value>),
    /// Signed negation.
    Neg(Box<Value>),
    /// Absolute value.
    Abs(Box<Value>),
    /// The largest (or smallest) of all occurrences of all arguments; absent arguments are
    /// skipped.
    Extreme {
        /// `max()` if true, `min()` if false.
        max: bool,
        /// The arguments.
        args: Vec<Value>,
    },
    /// A constant.
    Lit(Lit),
}

/// Checked signed arithmetic, shared by constant folding and evaluation.
pub(crate) fn arith(op: ArithOp, a: i64, b: i64) -> Option<i64> {
    match op {
        ArithOp::Add => a.checked_add(b),
        ArithOp::Sub => a.checked_sub(b),
        ArithOp::Mul => a.checked_mul(b),
        ArithOp::Div => a.checked_div(b),
        ArithOp::Mod => a.checked_rem(b),
    }
}

/// An item of a set in [`Test::Member`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetItem {
    /// A single value (an address may carry a prefix).
    One(Lit),
    /// Inclusive range.
    Range(Lit, Lit),
}

/// A literal value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lit {
    /// A boolean.
    Bool(bool),
    /// An unsigned integer.
    Uint(u64),
    /// A signed integer, for arithmetic.
    Int(i64),
    /// Address and prefix length (32 for a single address).
    Ipv4([u8; 4], u8),
    /// Address and prefix length (128 for a single address).
    Ipv6([u8; 16], u8),
    /// A MAC address.
    Ether([u8; 6]),
    /// A byte string (also strings and protocol bytes).
    Bytes(Vec<u8>),
}

impl Lit {
    pub(crate) fn has_prefix(&self) -> bool {
        matches!(self, Lit::Ipv4(_, p) if *p < 32) || matches!(self, Lit::Ipv6(_, p) if *p < 128)
    }
}

impl Test {
    /// Whether the test needs user space (it uses `matches`).
    pub fn user_space_only(&self) -> bool {
        match self {
            Test::Matches { .. } => true,
            Test::Not(t) => t.user_space_only(),
            Test::And(v) | Test::Or(v) => v.iter().any(Test::user_space_only),
            Test::Xor(a, b) => a.user_space_only() || b.user_space_only(),
            _ => false,
        }
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
            Test::Cmp {
                lhs,
                op,
                quant,
                rhs,
            } => match (quant, op) {
                (Quant::Any, CmpOp::Lt | CmpOp::Le | CmpOp::Gt | CmpOp::Ge) => {
                    write!(f, "({op} {lhs} {rhs})")
                }
                _ => write!(f, "({quant}_{op} {lhs} {rhs})"),
            },
            Test::Member {
                lhs,
                set,
                quant,
                negate,
            } => {
                let all = if *quant == Quant::All { "all_" } else { "" };
                let not = if *negate { "not_" } else { "" };
                write!(f, "({all}{not}in {lhs}")?;
                for item in set {
                    match item {
                        SetItem::One(l) => write!(f, " {l}")?,
                        SetItem::Range(a, b) => write!(f, " {a}..{b}")?,
                    }
                }
                write!(f, ")")
            }
            Test::Contains { lhs, rhs, quant } => match quant {
                Quant::Any => write!(f, "(contains {lhs} {rhs})"),
                Quant::All => write!(f, "(all_contains {lhs} {rhs})"),
            },
            Test::Matches {
                lhs,
                pattern,
                quant,
                ..
            } => {
                let all = if *quant == Quant::All { "all_" } else { "" };
                write!(f, "({all}matches {lhs} {pattern:?})")
            }
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
            CmpOp::Eq => "eq",
            CmpOp::Ne => "ne",
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
            Value::Layer(field, layers) => {
                f.write_str(def(*field).name)?;
                crate::ast::fmt_layers(f, layers)
            }
            Value::Raw(field, layers) => {
                write!(f, "@{}", def(*field).name)?;
                match layers {
                    Some(l) => crate::ast::fmt_layers(f, l),
                    None => Ok(()),
                }
            }
            Value::Slice(v, ranges) => {
                write!(f, "{v}[")?;
                for (i, s) in ranges.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    match s.end {
                        SliceEnd::Len(n) => write!(f, "{}:{n}", s.start)?,
                        SliceEnd::Inclusive(e) => write!(f, "{}-{e}", s.start)?,
                        SliceEnd::Open => write!(f, "{}:", s.start)?,
                    }
                }
                write!(f, "]")
            }
            Value::BitAnd(a, b) => write!(f, "(& {a} {b})"),
            Value::Len(v) => write!(f, "(len {v})"),
            Value::Count(v) => write!(f, "(count {v})"),
            Value::Case { upper, value } => {
                write!(f, "({} {value})", if *upper { "upper" } else { "lower" })
            }
            Value::Arith(op, a, b) => write!(f, "({op} {a} {b})"),
            Value::Neg(v) => write!(f, "(neg {v})"),
            Value::Abs(v) => write!(f, "(abs {v})"),
            Value::Extreme { max, args } => {
                write!(f, "({}", if *max { "max" } else { "min" })?;
                for a in args {
                    write!(f, " {a}")?;
                }
                write!(f, ")")
            }
            Value::Lit(l) => write!(f, "{l}"),
        }
    }
}

impl fmt::Display for Lit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Lit::Bool(b) => write!(f, "{b}"),
            Lit::Uint(v) => write!(f, "{v}"),
            Lit::Int(v) => write!(f, "{v}"),
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
