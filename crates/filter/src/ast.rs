//! Untyped syntax tree. `Display` prints the canonical form used by `avulse filter fmt`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::error::Span;

/// A whole filter: the `let` definitions, then the expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    /// The `let` definitions, in source order.
    pub lets: Vec<Let>,
    /// The filter expression.
    pub expr: Expr,
}

/// `let name = body` (Avulse extension), used as `$name` or `${name}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Let {
    /// The macro name, without `$`.
    pub name: String,
    /// Where the definition is.
    pub span: Span,
    /// What `$name` expands to.
    pub body: MacroBody,
}

/// The body of a `let`: an expression, or a set usable after `in`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MacroBody {
    /// A test or a value, such as `tcp.port == 80` or `tcp.port`.
    Expr(Expr),
    /// A set, such as `{80, 443}`.
    Set(Set),
}

/// A test: the logical operators and the relations between operands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    /// `a or b or …` (also `||`).
    Or(Vec<Expr>),
    /// `a xor b` (also `^^`).
    Xor(Box<Expr>, Box<Expr>),
    /// `a and b and …` (also `&&`).
    And(Vec<Expr>),
    /// `not a` (also `!`), with the span of the operator.
    Not(Box<Expr>, Span),
    /// A relation, such as `tcp.port == 80` or `ip.src in {10.0.0.0/8}`.
    Rel {
        /// `any` or `all` before the relation; `None` keeps the operator's default.
        quant: Option<Quant>,
        /// The left operand.
        lhs: Operand,
        /// The operator.
        op: RelOp,
        /// The right operand or set.
        rhs: Rhs,
        /// The span of the whole relation.
        span: Span,
    },
    /// A bare operand: a field or protocol (presence), a flag, a bitwise `&` (non-zero), a macro.
    Test(Operand),
}

/// How a relation combines the occurrences of multi-valued operands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quant {
    /// Some pair (or value) satisfies the relation.
    Any,
    /// Every pair (or value) satisfies the relation.
    All,
}

/// A relational operator, as written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelOp {
    /// `==`, `eq`, `any_eq`
    Eq,
    /// `!=`, `ne`, `all_ne`
    Ne,
    /// `===`, `all_eq`
    AllEq,
    /// `!==`, `~=`, `any_ne`
    AnyNe,
    /// `<`, `lt`
    Lt,
    /// `<=`, `le`
    Le,
    /// `>`, `gt`
    Gt,
    /// `>=`, `ge`
    Ge,
    /// `contains`
    Contains,
    /// `matches`, `~`
    Matches,
    /// `in`
    In,
    /// `not in`
    NotIn,
}

/// The right side of a relation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rhs {
    /// A value.
    Operand(Operand),
    /// A set (after `in` and `not in`).
    Set(Set),
}

/// A set of values and ranges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Set {
    /// `{a, b..c}`: the items and the span of the braces.
    Items(Vec<SetItem>, Span),
    /// `$name`: a set defined by `let`.
    Macro(String, Span),
}

/// One item of a set: a value, or an inclusive range `lo..hi`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetItem {
    /// The value, or the start of the range.
    pub lo: Operand,
    /// The inclusive end of the range.
    pub hi: Option<Operand>,
}

/// A value: a field, literal, slice, function call or arithmetic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operand {
    /// A field, protocol, constant or literal, resolved by the checker.
    Word(String, Span),
    /// A quoted string, after escape processing.
    Str(Vec<u8>, Span),
    /// A character literal (`'a'`, `'\\x41'`).
    Char(u8, Span),
    /// `$name`: a value defined by `let`.
    Macro(String, Span),
    /// `base[ranges]`; several ranges concatenate (`frame[0:2,4]`).
    Slice(Box<Operand>, Vec<Slice>, Span),
    /// `field#n` or `field#[ranges]`: the occurrences in the given protocol layers (1-based,
    /// negative from the last).
    Layer(Box<Operand>, Vec<Slice>, Span),
    /// `a & b`: bitwise and of integers or byte strings.
    BitAnd(Box<Operand>, Box<Operand>, Span),
    /// `a + b`, `a - b`, `a * b`, `a / b`, `a % b`.
    Arith(ArithOp, Box<Operand>, Box<Operand>, Span),
    /// Unary `-a`.
    Neg(Box<Operand>, Span),
    /// `@field`: the bytes a field covers on the wire.
    Raw(Box<Operand>, Span),
    /// `{ … }`, which groups arithmetic (parentheses group tests).
    Group(Box<Operand>, Span),
    /// A function call such as `len(tcp.payload)`: the name and the arguments.
    Call(String, Vec<Operand>, Span),
}

/// An arithmetic operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArithOp {
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mul,
    /// `/`
    Div,
    /// `%`
    Mod,
}

impl fmt::Display for ArithOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ArithOp::Add => "+",
            ArithOp::Sub => "-",
            ArithOp::Mul => "*",
            ArithOp::Div => "/",
            ArithOp::Mod => "%",
        })
    }
}

impl Operand {
    /// The span of the operand in the source.
    pub fn span(&self) -> Span {
        match self {
            Operand::Word(_, s)
            | Operand::Str(_, s)
            | Operand::Char(_, s)
            | Operand::Macro(_, s)
            | Operand::Slice(_, _, s)
            | Operand::Layer(_, _, s)
            | Operand::BitAnd(_, _, s)
            | Operand::Arith(_, _, _, s)
            | Operand::Neg(_, s)
            | Operand::Group(_, s)
            | Operand::Raw(_, s)
            | Operand::Call(_, _, s) => *s,
        }
    }
}

/// A byte range: `[i]`, `[i:n]` (start and length), `[i-j]` (inclusive end), `[i:]`. Negative
/// offsets count from the end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slice {
    /// The first byte; negative counts from the end.
    pub start: i64,
    /// Where the range ends.
    pub end: SliceEnd,
}

/// How a [`Slice`] ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SliceEnd {
    /// `[i:n]`: `n` bytes.
    Len(i64),
    /// `[i-j]`: up to and including byte `j`.
    Inclusive(i64),
    /// `[i:]`: up to the end.
    Open,
}

impl fmt::Display for Slice {
    /// The inside of the brackets: `2`, `2:3`, `2-4`, `2:`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.end {
            SliceEnd::Len(1) => write!(f, "{}", self.start),
            SliceEnd::Len(n) => write!(f, "{}:{n}", self.start),
            SliceEnd::Inclusive(e) => write!(f, "{}-{e}", self.start),
            SliceEnd::Open => write!(f, "{}:", self.start),
        }
    }
}

/// Writes a layer selector: `#2`, or `#[1-2,4]`.
pub(crate) fn fmt_layers(f: &mut fmt::Formatter<'_>, layers: &[Slice]) -> fmt::Result {
    if let [s] = layers
        && s.end == SliceEnd::Len(1)
        && s.start >= 0
    {
        return write!(f, "#{}", s.start);
    }
    write!(f, "#[")?;
    for (i, s) in layers.iter().enumerate() {
        if i > 0 {
            write!(f, ",")?;
        }
        write!(f, "{s}")?;
    }
    write!(f, "]")
}

impl Expr {
    fn precedence(&self) -> u8 {
        match self {
            Expr::Or(_) => 1,
            Expr::Xor(..) => 2,
            Expr::And(_) => 3,
            Expr::Not(..) => 4,
            Expr::Rel { .. } | Expr::Test(_) => 5,
        }
    }

    fn fmt_prec(&self, f: &mut fmt::Formatter<'_>, parent: u8) -> fmt::Result {
        let p = self.precedence();
        if p < parent {
            write!(f, "(")?;
        }
        match self {
            Expr::Or(v) => join(f, v, " or ", p + 1)?,
            Expr::And(v) => join(f, v, " and ", p + 1)?,
            Expr::Xor(a, b) => {
                a.fmt_prec(f, p)?;
                write!(f, " xor ")?;
                b.fmt_prec(f, p + 1)?;
            }
            Expr::Not(e, _) => {
                write!(f, "not ")?;
                e.fmt_prec(f, p)?;
            }
            Expr::Rel {
                quant,
                lhs,
                op,
                rhs,
                ..
            } => {
                if let Some(q) = quant {
                    write!(f, "{q} ")?;
                }
                write!(f, "{lhs} {op} ")?;
                match rhs {
                    Rhs::Operand(o) => write!(f, "{o}")?,
                    Rhs::Set(s) => write!(f, "{s}")?,
                }
            }
            Expr::Test(o) => write!(f, "{o}")?,
        }
        if p < parent {
            write!(f, ")")?;
        }
        Ok(())
    }
}

fn join(f: &mut fmt::Formatter<'_>, v: &[Expr], sep: &str, prec: u8) -> fmt::Result {
    for (i, e) in v.iter().enumerate() {
        if i > 0 {
            write!(f, "{sep}")?;
        }
        e.fmt_prec(f, prec)?;
    }
    Ok(())
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_prec(f, 0)
    }
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for l in &self.lets {
            match &l.body {
                MacroBody::Expr(e) => writeln!(f, "let {} = {e}", l.name)?,
                MacroBody::Set(s) => writeln!(f, "let {} = {s}", l.name)?,
            }
        }
        write!(f, "{}", self.expr)
    }
}

impl fmt::Display for RelOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RelOp::Eq => "==",
            RelOp::Ne => "!=",
            RelOp::AllEq => "===",
            RelOp::AnyNe => "!==",
            RelOp::Lt => "<",
            RelOp::Le => "<=",
            RelOp::Gt => ">",
            RelOp::Ge => ">=",
            RelOp::Contains => "contains",
            RelOp::Matches => "matches",
            RelOp::In => "in",
            RelOp::NotIn => "not in",
        })
    }
}

impl fmt::Display for Quant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Quant::Any => "any",
            Quant::All => "all",
        })
    }
}

impl fmt::Display for Set {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Set::Macro(m, _) => write!(f, "${m}"),
            Set::Items(items, _) => {
                write!(f, "{{")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", item.lo)?;
                    if let Some(hi) = &item.hi {
                        write!(f, "..{hi}")?;
                    }
                }
                write!(f, "}}")
            }
        }
    }
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Word(w, _) => f.write_str(w),
            Operand::Str(s, _) => {
                write!(f, "\"")?;
                for &c in s {
                    match c {
                        b'"' => write!(f, "\\\"")?,
                        b'\\' => write!(f, "\\\\")?,
                        b'\n' => write!(f, "\\n")?,
                        b'\t' => write!(f, "\\t")?,
                        b'\r' => write!(f, "\\r")?,
                        0x20..=0x7e => write!(f, "{}", c as char)?,
                        _ => write!(f, "\\x{c:02x}")?,
                    }
                }
                write!(f, "\"")
            }
            Operand::Char(c, _) => match c {
                b'\'' => write!(f, "'\\''"),
                b'\\' => write!(f, "'\\\\'"),
                0x20..=0x7e => write!(f, "'{}'", *c as char),
                _ => write!(f, "'\\x{c:02x}'"),
            },
            Operand::Macro(m, _) => write!(f, "${m}"),
            Operand::Slice(base, ranges, _) => {
                write!(f, "{base}[")?;
                for (i, s) in ranges.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{s}")?;
                }
                write!(f, "]")
            }
            Operand::Layer(base, layers, _) => {
                write!(f, "{base}")?;
                fmt_layers(f, layers)
            }
            Operand::BitAnd(a, b, _) => write!(f, "{a} & {b}"),
            Operand::Arith(op, a, b, _) => write!(f, "{a} {op} {b}"),
            Operand::Neg(a, _) => write!(f, "-{a}"),
            Operand::Group(a, _) => write!(f, "{{{a}}}"),
            Operand::Raw(a, _) => write!(f, "@{a}"),
            Operand::Call(name, args, _) => {
                write!(f, "{name}(")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{a}")?;
                }
                write!(f, ")")
            }
        }
    }
}
