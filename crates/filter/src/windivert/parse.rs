//! WinDivert's filter syntax: tokens and grammar, with WinDivert's limits.

use alloc::boxed::Box;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use super::{Def, FIELDS, MACROS};
use crate::error::{Diagnostic, Span};
use crate::meta::Layer;

type Result<T> = core::result::Result<T, Diagnostic>;

/// Longest token, as in WinDivert.
const TOKEN_MAX: usize = 40;
/// Most tokens: five per test of the longest filter.
const TOKENS_MAX: usize = 5 * super::TESTS_MAX - 1;
/// Deepest nesting of parentheses. WinDivert's parser gives up at 1024 levels of recursion, three
/// per parenthesis.
const NEST_MAX: usize = 1024 / 3;
/// Largest index into a packet or payload: WinDivert's largest MTU.
const INDEX_MAX: u128 = 40 + 0xffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl Op {
    /// The operator of `not a op b`: WinDivert's `not` negates the comparison, not the test.
    fn negate(self) -> Op {
        match self {
            Op::Eq => Op::Ne,
            Op::Ne => Op::Eq,
            Op::Lt => Op::Ge,
            Op::Le => Op::Gt,
            Op::Gt => Op::Le,
            Op::Ge => Op::Lt,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Tok {
    Open,
    Close,
    SquareOpen,
    SquareClose,
    Minus,
    Not,
    Op(Op),
    Colon,
    Question,
    And,
    Or,
    /// The `b` of a byte index.
    Bytes,
    Number(u128),
    Field(&'static Def),
    /// A macro that has no value at this layer (`CONNECT` at the NETWORK layer).
    Macro(&'static str),
    End,
}

struct Token {
    tok: Tok,
    span: Span,
}

fn is_word(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'.' || c == b':' || c == b'_'
}

fn bad_token(span: Span, word: &str) -> Diagnostic {
    Diagnostic::error(span, format!("unknown token `{word}`"))
        .help("WinDivert field names and macros are case-sensitive, e.g. `tcp.DstPort`, `TCP`")
}

/// A number: decimal, hexadecimal with `0x`, IPv4 (as `::ffff:a.b.c.d`) or IPv6, in this order.
fn number(word: &str) -> Option<u128> {
    if let Ok(v) = word.parse::<u128>() {
        return Some(v);
    }
    if let Some(hex) = word.strip_prefix("0x")
        && !hex.is_empty()
        && hex.len() <= 32
        && hex.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return u128::from_str_radix(hex, 16).ok();
    }
    if let Ok(a) = word.parse::<core::net::Ipv4Addr>() {
        return Some(0xffff_u128 << 32 | u128::from(u32::from(a)));
    }
    word.parse::<core::net::Ipv6Addr>().ok().map(u128::from)
}

fn tokenize(src: &str, layer: Layer) -> Result<Vec<Token>> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        if out.len() >= TOKENS_MAX {
            return Err(Diagnostic::error(Span::new(i, i), "the filter is too long")
                .help(format!("WinDivert accepts at most {TOKENS_MAX} tokens")));
        }
        while b.get(i).is_some_and(|c| c.is_ascii_whitespace()) {
            i += 1;
        }
        let start = i;
        let Some(&c) = b.get(i) else {
            out.push(Token {
                tok: Tok::End,
                span: Span::new(i, i),
            });
            return Ok(out);
        };
        i += 1;
        let next = b.get(i).copied();
        let mut two = |t: Tok| {
            i += 1;
            t
        };
        let tok = match c {
            b'(' => Tok::Open,
            b')' => Tok::Close,
            b'[' => Tok::SquareOpen,
            b']' => Tok::SquareClose,
            b'-' => Tok::Minus,
            b'!' if next == Some(b'=') => two(Tok::Op(Op::Ne)),
            b'!' => Tok::Not,
            b'=' if next == Some(b'=') => two(Tok::Op(Op::Eq)),
            b'=' => Tok::Op(Op::Eq),
            b'<' if next == Some(b'=') => two(Tok::Op(Op::Le)),
            b'<' => Tok::Op(Op::Lt),
            b'>' if next == Some(b'=') => two(Tok::Op(Op::Ge)),
            b'>' => Tok::Op(Op::Gt),
            // `::` starts an IPv6 address.
            b':' if next != Some(b':') => Tok::Colon,
            b'?' => Tok::Question,
            b'&' if next == Some(b'&') => two(Tok::And),
            b'|' if next == Some(b'|') => two(Tok::Or),
            c if is_word(c) => {
                while b.get(i).copied().is_some_and(is_word) {
                    i += 1;
                }
                // A trailing colon ends a ternary branch (`a? b: c`), unless it is `::`.
                if b[i - 1] == b':' && (i - start == 1 || b[i - 2] != b':') {
                    i -= 1;
                }
                let word = &src[start..i];
                let span = Span::new(start, i);
                if word.len() >= TOKEN_MAX {
                    return Err(Diagnostic::error(span, "token too long"));
                }
                word_token(word, span, layer, &mut out)?;
                continue;
            }
            _ => {
                let end = src[start..]
                    .chars()
                    .next()
                    .map_or(start, |c| start + c.len_utf8());
                return Err(bad_token(Span::new(start, end), &src[start..end]));
            }
        };
        out.push(Token {
            tok,
            span: Span::new(start, i),
        });
    }
}

fn word_token(word: &str, span: Span, layer: Layer, out: &mut Vec<Token>) -> Result<()> {
    let mut push = |tok| out.push(Token { tok, span });
    match word {
        "and" => push(Tok::And),
        "or" => push(Tok::Or),
        "not" => push(Tok::Not),
        "b" => push(Tok::Bytes),
        _ => {
            if let Some(def) = FIELDS.iter().find(|d| d.name == word) {
                if !def.valid_at(layer) {
                    return Err(Diagnostic::error(
                        span,
                        format!(
                            "`{word}` is not available at the {} layer",
                            super::layer_name(layer)
                        ),
                    ));
                }
                push(Tok::Field(def));
            } else if let Some(m) = MACROS.iter().find(|m| m.name == word) {
                push(match (m.value)(layer) {
                    Some(v) => Tok::Number(v.into()),
                    None => Tok::Macro(m.name),
                });
            } else if let Some(v) = number(word) {
                push(Tok::Number(v));
            } else if let Some(v) = word.strip_suffix('b').and_then(|n| n.parse::<u128>().ok()) {
                // `55b`: a byte index.
                out.push(Token {
                    tok: Tok::Number(v),
                    span: Span::new(span.start, span.end - 1),
                });
                out.push(Token {
                    tok: Tok::Bytes,
                    span: Span::new(span.end - 1, span.end),
                });
            } else {
                return Err(bad_token(span, word));
            }
        }
    }
    Ok(())
}

/// A parsed filter.
#[derive(Debug)]
pub(super) enum Expr {
    Test(Test),
    And(Vec<Expr>),
    Or(Vec<Expr>),
    /// `(a? b: c)`
    Cond(Box<Expr>, Box<Expr>, Box<Expr>),
}

/// `field op value`, after `not` has been folded into `op`. A bare field is `field != 0`.
#[derive(Debug)]
pub(super) struct Test {
    pub(super) def: &'static Def,
    /// Byte offset of `packet[i]` and friends; negative from the end.
    pub(super) index: i32,
    pub(super) op: Op,
    /// The value: a sign and a 128-bit magnitude, as WinDivert keeps it.
    pub(super) neg: bool,
    pub(super) val: u128,
}

impl Expr {
    /// Number of tests, the measure of WinDivert's length limit.
    pub(super) fn tests(&self) -> usize {
        match self {
            Expr::Test(_) => 1,
            Expr::And(v) | Expr::Or(v) => v.iter().map(Expr::tests).sum(),
            Expr::Cond(a, b, c) => a.tests() + b.tests() + c.tests(),
        }
    }
}

struct Parser {
    toks: Vec<Token>,
    i: usize,
    /// Open parentheses.
    nest: usize,
}

pub(super) fn parse(src: &str, layer: Layer) -> Result<Expr> {
    if src.starts_with('@') {
        return Err(Diagnostic::error(
            Span::new(0, src.len()),
            "compiled WinDivert filter objects are not supported",
        )
        .help("pass the filter string instead"));
    }
    let mut p = Parser {
        toks: tokenize(src, layer)?,
        i: 0,
        nest: 0,
    };
    let e = p.filter()?;
    if p.peek() != Tok::End {
        return Err(p.unexpected());
    }
    Ok(e)
}

impl Parser {
    fn peek(&self) -> Tok {
        self.toks.get(self.i).map_or(Tok::End, |t| t.tok)
    }

    fn span(&self) -> Span {
        self.toks.get(self.i).map_or(Span::new(0, 0), |t| t.span)
    }

    fn unexpected(&self) -> Diagnostic {
        let msg = match self.peek() {
            Tok::End => "unexpected end of filter".into(),
            Tok::Macro(m) => format!("`{m}` has no value at this layer"),
            _ => "unexpected token".into(),
        };
        Diagnostic::error(self.span(), msg)
    }

    /// A disjunction of conjunctions: `and` binds tighter than `or`. WinDivert nests them to the
    /// right; they are associative, so lists do as well and keep the tree shallow.
    fn filter(&mut self) -> Result<Expr> {
        let mut ors = Vec::new();
        loop {
            let mut ands = vec![self.operand()?];
            while self.peek() == Tok::And {
                self.i += 1;
                ands.push(self.operand()?);
            }
            ors.push(if ands.len() == 1 {
                ands.remove(0)
            } else {
                Expr::And(ands)
            });
            if self.peek() != Tok::Or {
                break;
            }
            self.i += 1;
        }
        Ok(if ors.len() == 1 {
            ors.remove(0)
        } else {
            Expr::Or(ors)
        })
    }

    /// `(filter)`, `(filter? filter: filter)` or a test.
    fn operand(&mut self) -> Result<Expr> {
        if self.peek() != Tok::Open {
            return self.test().map(Expr::Test);
        }
        if self.nest >= NEST_MAX {
            return Err(
                Diagnostic::error(self.span(), "the filter nests too deeply").help(format!(
                    "Avulse accepts at most {NEST_MAX} levels of parentheses"
                )),
            );
        }
        self.nest += 1;
        self.i += 1;
        let cond = self.filter()?;
        let e = match self.peek() {
            Tok::Close => {
                self.i += 1;
                cond
            }
            Tok::Question => {
                self.i += 1;
                let then = self.filter()?;
                self.expect(Tok::Colon)?;
                let other = self.filter()?;
                self.expect(Tok::Close)?;
                Expr::Cond(Box::new(cond), Box::new(then), Box::new(other))
            }
            _ => return Err(self.unexpected()),
        };
        self.nest -= 1;
        Ok(e)
    }

    fn expect(&mut self, t: Tok) -> Result<()> {
        if self.peek() == t {
            self.i += 1;
            Ok(())
        } else {
            Err(self.unexpected())
        }
    }

    /// `-`? number
    fn signed(&mut self) -> Result<(bool, u128)> {
        let neg = self.peek() == Tok::Minus;
        if neg {
            self.i += 1;
        }
        match self.peek() {
            Tok::Number(v) => {
                self.i += 1;
                Ok((neg, v))
            }
            _ => Err(self.unexpected()),
        }
    }

    fn test(&mut self) -> Result<Test> {
        let mut not = false;
        while self.peek() == Tok::Not {
            not = !not;
            self.i += 1;
        }
        let Tok::Field(def) = self.peek() else {
            return Err(self.unexpected());
        };
        self.i += 1;
        let mut index = 0;
        if let Some(width) = def.indexed() {
            index = self.index(width)?;
        }
        let (op, neg, val) = match self.peek() {
            Tok::Op(op) => {
                self.i += 1;
                let (neg, val) = self.signed()?;
                (op, neg, val)
            }
            _ => (Op::Ne, false, 0),
        };
        Ok(Test {
            def,
            index,
            op: if not { op.negate() } else { op },
            neg,
            val,
        })
    }

    /// `[i]`, `[-i]`, `[ib]` or `[-ib]`: a byte offset, negative from the end.
    fn index(&mut self, width: u8) -> Result<i32> {
        self.expect(Tok::SquareOpen)?;
        let start = self.span().start;
        let (neg, n) = self.signed()?;
        let oob =
            |p: &Self| Diagnostic::error(Span::new(start, p.span().end), "index out of bounds");
        let too_far = |p: &Self| oob(p).help("WinDivert indexes at most 65535 bytes into a packet");
        if n > INDEX_MAX {
            return Err(too_far(self));
        }
        let mut idx = n as u32;
        if self.peek() == Tok::Bytes {
            self.i += 1;
        } else {
            idx *= u32::from(width);
        }
        let w = u32::from(width);
        if neg && idx < w {
            return Err(oob(self).help(format!(
                "a {w}-byte word from the end starts at least {w} bytes back: `[-{w}b]`"
            )));
        }
        if (!neg && idx > 0xffff - w) || (neg && idx > 0xffff) {
            return Err(too_far(self));
        }
        self.expect(Tok::SquareClose)?;
        let idx = idx as i32;
        Ok(if neg { -idx } else { idx })
    }
}

/// The tests of the vectors' precedence and ternaries parse as WinDivert does.
#[cfg(test)]
pub(crate) fn shape(src: &str) -> alloc::string::String {
    fn go(e: &Expr) -> alloc::string::String {
        match e {
            Expr::Test(t) => t.def.name.into(),
            Expr::And(v) => format!("(and {})", v.iter().map(go).collect::<Vec<_>>().join(" ")),
            Expr::Or(v) => format!("(or {})", v.iter().map(go).collect::<Vec<_>>().join(" ")),
            Expr::Cond(a, b, c) => format!("(? {} {} {})", go(a), go(b), go(c)),
        }
    }
    parse(src, Layer::Network)
        .map(|e| go(&e))
        .unwrap_or_else(|e| e.message)
}
