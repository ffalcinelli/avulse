//! Untyped syntax tree. `Display` prints the canonical form used by `avulse filter fmt`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::error::Span;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    pub lets: Vec<Let>,
    pub expr: Expr,
}

/// `let name = body` (Avulse extension), used as `$name` or `${name}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Let {
    pub name: String,
    pub span: Span,
    pub body: MacroBody,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MacroBody {
    Expr(Expr),
    Set(Set),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    Or(Vec<Expr>),
    Xor(Box<Expr>, Box<Expr>),
    And(Vec<Expr>),
    Not(Box<Expr>, Span),
    Rel {
        /// `any` or `all` before the relation; `None` keeps the operator's default.
        quant: Option<Quant>,
        lhs: Operand,
        op: RelOp,
        rhs: Rhs,
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
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
    Matches,
    In,
    NotIn,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rhs {
    Operand(Operand),
    Set(Set),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Set {
    Items(Vec<SetItem>, Span),
    Macro(String, Span),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetItem {
    pub lo: Operand,
    pub hi: Option<Operand>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operand {
    /// A field, protocol, constant or literal, resolved by the checker.
    Word(String, Span),
    Str(Vec<u8>, Span),
    Char(u8, Span),
    Macro(String, Span),
    Slice(Box<Operand>, Slice, Span),
    BitAnd(Box<Operand>, Box<Operand>, Span),
    Call(String, Vec<Operand>, Span),
}

impl Operand {
    pub fn span(&self) -> Span {
        match self {
            Operand::Word(_, s)
            | Operand::Str(_, s)
            | Operand::Char(_, s)
            | Operand::Macro(_, s)
            | Operand::Slice(_, _, s)
            | Operand::BitAnd(_, _, s)
            | Operand::Call(_, _, s) => *s,
        }
    }
}

/// A byte range: `[i]`, `[i:n]` (start and length), `[i-j]` (inclusive end), `[i:]`. Negative
/// offsets count from the end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slice {
    pub start: i64,
    pub end: SliceEnd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SliceEnd {
    Len(i64),
    Inclusive(i64),
    Open,
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
            Operand::Slice(base, s, _) => {
                write!(f, "{base}[")?;
                match s.end {
                    SliceEnd::Len(1) => write!(f, "{}", s.start)?,
                    SliceEnd::Len(n) => write!(f, "{}:{n}", s.start)?,
                    SliceEnd::Inclusive(e) => write!(f, "{}-{e}", s.start)?,
                    SliceEnd::Open => write!(f, "{}:", s.start)?,
                }
                write!(f, "]")
            }
            Operand::BitAnd(a, b, _) => write!(f, "{a} & {b}"),
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
