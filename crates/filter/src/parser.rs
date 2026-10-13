//! Recursive-descent parser. Precedence follows Wireshark: `not` binds tightest, then `and`,
//! `xor`, `or`. Inside a value, unary `-` binds tightest, then `* / %`, `+ -` and `&`, all
//! tighter than comparisons.

use alloc::boxed::Box;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use crate::ast::*;
use crate::error::{Diagnostic, Result, Span};
use crate::lexer::{Tok, Token, lex};

/// Function names recognized before `(`.
const FUNCTIONS: &[&str] = &[
    "len", "count", "string", "upper", "lower", "abs", "max", "min", "vals", "dec", "hex",
];

pub fn parse(src: &str) -> Result<Program> {
    let mut p = Parser {
        toks: lex(src)?,
        pos: 0,
    };
    let mut lets = Vec::new();
    while p.is_word("let") {
        lets.push(p.let_stmt()?);
    }
    if p.peek() == &Tok::Eof {
        return Err(Diagnostic::error(p.span(), "empty filter").help("`true` matches everything"));
    }
    let expr = p.expr()?;
    if p.peek() != &Tok::Eof {
        let t = p.peek().describe();
        return Err(Diagnostic::error(
            p.span(),
            format!("expected `and`, `or` or the end of the filter, found {t}"),
        ));
    }
    Ok(Program { lets, expr })
}

struct Parser {
    toks: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> &Tok {
        &self.toks[self.pos].tok
    }

    fn peek_at(&self, n: usize) -> &Tok {
        &self.toks[(self.pos + n).min(self.toks.len() - 1)].tok
    }

    fn span(&self) -> Span {
        self.toks[self.pos].span
    }

    fn prev_span(&self) -> Span {
        self.toks[self.pos.saturating_sub(1)].span
    }

    fn bump(&mut self) -> Token {
        let t = self.toks[self.pos].clone();
        if self.pos < self.toks.len() - 1 {
            self.pos += 1;
        }
        t
    }

    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == t {
            self.bump();
            true
        } else {
            false
        }
    }

    fn is_word(&self, w: &str) -> bool {
        matches!(self.peek(), Tok::Word(x) if x == w)
    }

    fn eat_word(&mut self, words: &[&str]) -> bool {
        if words.iter().any(|w| self.is_word(w)) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, t: Tok, what: &str) -> Result<Span> {
        if self.peek() == &t {
            Ok(self.bump().span)
        } else {
            let found = self.peek().describe();
            Err(Diagnostic::error(
                self.span(),
                format!("expected {what}, found {found}"),
            ))
        }
    }

    fn let_stmt(&mut self) -> Result<Let> {
        let start = self.bump().span;
        let (name, span) = match self.bump() {
            Token {
                tok: Tok::Word(w),
                span,
            } if is_ident(&w) => (w, span),
            t => {
                return Err(Diagnostic::error(
                    t.span,
                    format!("expected a name after `let`, found {}", t.tok.describe()),
                ));
            }
        };
        self.expect(Tok::Assign, "`=`")?;
        let body = if self.peek() == &Tok::LBrace {
            MacroBody::Set(self.set()?)
        } else {
            MacroBody::Expr(self.expr()?)
        };
        self.eat(&Tok::Semi);
        Ok(Let {
            name,
            span: start.to(span),
            body,
        })
    }

    fn expr(&mut self) -> Result<Expr> {
        let mut v = vec![self.xor()?];
        while self.eat(&Tok::OrOr) || self.eat_word(&["or", "OR"]) {
            v.push(self.xor()?);
        }
        Ok(if v.len() == 1 {
            v.remove(0)
        } else {
            Expr::Or(v)
        })
    }

    fn xor(&mut self) -> Result<Expr> {
        let mut e = self.and()?;
        while self.eat(&Tok::XorXor) || self.eat_word(&["xor", "XOR"]) {
            e = Expr::Xor(Box::new(e), Box::new(self.and()?));
        }
        Ok(e)
    }

    fn and(&mut self) -> Result<Expr> {
        let mut v = vec![self.unary()?];
        while self.eat(&Tok::AndAnd) || self.eat_word(&["and", "AND"]) {
            v.push(self.unary()?);
        }
        Ok(if v.len() == 1 {
            v.remove(0)
        } else {
            Expr::And(v)
        })
    }

    fn unary(&mut self) -> Result<Expr> {
        let span = self.span();
        if self.eat(&Tok::Bang) || self.eat_word(&["not", "NOT"]) {
            return Ok(Expr::Not(Box::new(self.unary()?), span));
        }
        self.relation()
    }

    fn relop(&mut self) -> Option<RelOp> {
        let op = match self.peek() {
            Tok::Eq => RelOp::Eq,
            Tok::Ne => RelOp::Ne,
            Tok::AllEq => RelOp::AllEq,
            Tok::AnyNe => RelOp::AnyNe,
            Tok::Lt => RelOp::Lt,
            Tok::Le => RelOp::Le,
            Tok::Gt => RelOp::Gt,
            Tok::Ge => RelOp::Ge,
            Tok::Tilde => RelOp::Matches,
            Tok::Word(w) => match w.as_str() {
                "eq" | "any_eq" => RelOp::Eq,
                "ne" | "all_ne" => RelOp::Ne,
                "all_eq" => RelOp::AllEq,
                "any_ne" => RelOp::AnyNe,
                "lt" => RelOp::Lt,
                "le" => RelOp::Le,
                "gt" => RelOp::Gt,
                "ge" => RelOp::Ge,
                "contains" => RelOp::Contains,
                "matches" => RelOp::Matches,
                "in" => RelOp::In,
                "not" if matches!(self.peek_at(1), Tok::Word(w) if w == "in") => {
                    self.bump();
                    RelOp::NotIn
                }
                _ => return None,
            },
            _ => return None,
        };
        self.bump();
        Some(op)
    }

    fn relation(&mut self) -> Result<Expr> {
        let start = self.span();
        let quant = self.quantifier();
        let lhs = self.value()?;
        let Some(op) = self.relop() else {
            if let Some(q) = quant {
                return Err(Diagnostic::error(
                    start.to(self.prev_span()),
                    format!("`{q}` needs a relation after it"),
                )
                .help(format!("e.g. `{q} tcp.port > 1024`")));
            }
            return Ok(lhs);
        };
        let lhs = into_operand(lhs, start, &format!("before `{op}`"))?;
        let rhs = match op {
            RelOp::In | RelOp::NotIn => Rhs::Set(self.set()?),
            _ => {
                let s = self.span();
                Rhs::Operand(into_operand(self.value()?, s, &format!("after `{op}`"))?)
            }
        };
        let span = start.to(self.prev_span());
        Ok(Expr::Rel {
            quant,
            lhs,
            op,
            rhs,
            span,
        })
    }

    /// `any` or `all` in front of a relation (a word that is followed by an operand).
    fn quantifier(&mut self) -> Option<Quant> {
        let q = match self.peek() {
            Tok::Word(w) if w == "any" => Quant::Any,
            Tok::Word(w) if w == "all" => Quant::All,
            _ => return None,
        };
        let operand_follows = match self.peek_at(1) {
            Tok::Word(w) => !is_keyword(w),
            Tok::Str(_)
            | Tok::Char(_)
            | Tok::Macro(_)
            | Tok::LParen
            | Tok::LBrace
            | Tok::Minus
            | Tok::At => true,
            _ => false,
        };
        if !operand_follows {
            return None;
        }
        self.bump();
        Some(q)
    }

    /// A value: `&` chains of sums of products of (possibly negated) primaries.
    fn value(&mut self) -> Result<Expr> {
        let start = self.span();
        let mut e = self.sum()?;
        while self.eat(&Tok::Amp) {
            let lhs = into_operand(e, start, "before `&`")?;
            let s = self.span();
            let rhs = into_operand(self.sum()?, s, "after `&`")?;
            let span = start.to(self.prev_span());
            e = Expr::Test(Operand::BitAnd(Box::new(lhs), Box::new(rhs), span));
        }
        Ok(e)
    }

    fn sum(&mut self) -> Result<Expr> {
        let start = self.span();
        let mut e = self.product()?;
        loop {
            let op = if self.eat(&Tok::Plus) {
                ArithOp::Add
            } else if self.eat(&Tok::Minus) || self.split_negative() {
                ArithOp::Sub
            } else {
                break;
            };
            e = self.arith(e, start, op, Self::product)?;
        }
        Ok(e)
    }

    fn product(&mut self) -> Result<Expr> {
        let start = self.span();
        let mut e = self.negation()?;
        loop {
            let op = match self.peek() {
                Tok::Star => ArithOp::Mul,
                Tok::Slash => ArithOp::Div,
                Tok::Percent => ArithOp::Mod,
                _ => break,
            };
            self.bump();
            e = self.arith(e, start, op, Self::negation)?;
        }
        Ok(e)
    }

    fn arith(
        &mut self,
        lhs: Expr,
        start: Span,
        op: ArithOp,
        next: fn(&mut Self) -> Result<Expr>,
    ) -> Result<Expr> {
        let lhs = into_operand(lhs, start, &format!("before `{op}`"))?;
        let s = self.span();
        let rhs = into_operand(next(self)?, s, &format!("after `{op}`"))?;
        let span = start.to(self.prev_span());
        Ok(Expr::Test(Operand::Arith(
            op,
            Box::new(lhs),
            Box::new(rhs),
            span,
        )))
    }

    fn negation(&mut self) -> Result<Expr> {
        let start = self.span();
        if !self.eat(&Tok::Minus) {
            return self.primary();
        }
        let s = self.span();
        let inner = into_operand(self.negation()?, s, "after `-`")?;
        let span = start.to(self.prev_span());
        Ok(Expr::Test(Operand::Neg(Box::new(inner), span)))
    }

    /// After an operand, `a -1` is a subtraction: the lexer saw the word `-1`, so turn it into
    /// `-` followed by `1`.
    fn split_negative(&mut self) -> bool {
        let Tok::Word(w) = self.peek() else {
            return false;
        };
        let Some(rest) = w
            .strip_prefix('-')
            .filter(|r| r.starts_with(|c: char| c.is_ascii_digit()))
        else {
            return false;
        };
        let rest = rest.into();
        let span = self.span();
        self.toks[self.pos] = Token {
            tok: Tok::Word(rest),
            span: Span::new(span.start + 1, span.end),
        };
        true
    }

    fn primary(&mut self) -> Result<Expr> {
        let mut t = self.bump();
        // `@field#layer[slice]`: the layer belongs to the field, the slice to its bytes.
        let raw = if t.tok == Tok::At {
            let at = t.span;
            t = self.bump();
            if !matches!(t.tok, Tok::Word(_)) {
                return Err(Diagnostic::error(t.span, "expected a field name after `@`"));
            }
            Some(at)
        } else {
            None
        };
        let operand = match t.tok {
            Tok::LParen => {
                let e = self.expr()?;
                self.expect(Tok::RParen, "`)`")?;
                return Ok(e);
            }
            Tok::LBrace => {
                let s = self.span();
                let inner = into_operand(self.value()?, s, "inside `{ }`")?;
                let end = self.expect(Tok::RBrace, "`}`")?;
                Operand::Group(Box::new(inner), t.span.to(end))
            }
            Tok::Word(w) if is_keyword(&w) => {
                return Err(Diagnostic::error(
                    t.span,
                    format!("expected a field or a value, found `{w}`"),
                ));
            }
            Tok::Word(w) if self.peek() == &Tok::LParen && FUNCTIONS.contains(&w.as_str()) => {
                self.bump();
                let mut args = Vec::new();
                if self.peek() != &Tok::RParen {
                    loop {
                        let s = self.span();
                        args.push(into_operand(self.value()?, s, "as a function argument")?);
                        if !self.eat(&Tok::Comma) {
                            break;
                        }
                    }
                }
                let end = self.expect(Tok::RParen, "`)`")?;
                Operand::Call(w, args, t.span.to(end))
            }
            Tok::Word(w) => Operand::Word(w, t.span),
            Tok::Str(s) => Operand::Str(s, t.span),
            Tok::Char(c) => Operand::Char(c, t.span),
            Tok::Macro(m) => Operand::Macro(m, t.span),
            other => {
                return Err(Diagnostic::error(
                    t.span,
                    format!("expected a field or a value, found {}", other.describe()),
                ));
            }
        };
        let mut operand = operand;
        if let Tok::Layer(text) = self.peek().clone() {
            let t = self.bump();
            let layers = text
                .split(',')
                .map(|r| parse_slice(r.trim()).filter(same_sign))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                    Diagnostic::error(t.span, format!("invalid layer range `#[{text}]`"))
                        .help("layers are `#n`, `#[a-b]`, `#[a:count]`, `#[a:]` or a list such as `#[1,3]`; negative ones count from the last")
                })?;
            let span = operand.span().to(t.span);
            operand = Operand::Layer(Box::new(operand), layers, span);
        }
        if let Some(at) = raw {
            let span = at.to(operand.span());
            operand = Operand::Raw(Box::new(operand), span);
        }
        while self.peek() == &Tok::LBracket {
            let open = self.bump().span;
            let mut ranges = Vec::new();
            loop {
                ranges.push(match self.bump() {
                    Token {
                        tok: Tok::Word(w),
                        span,
                    } => parse_slice(&w).ok_or_else(|| {
                        Diagnostic::error(span, format!("invalid slice `[{w}]`")).help(SLICE_HELP)
                    })?,
                    t => {
                        return Err(
                            Diagnostic::error(t.span, "expected a slice range").help(SLICE_HELP)
                        );
                    }
                });
                if !self.eat(&Tok::Comma) {
                    break;
                }
            }
            let close = self.expect(Tok::RBracket, "`]`")?;
            let span = operand.span().to(close).to(open);
            operand = Operand::Slice(Box::new(operand), ranges, span);
        }
        Ok(Expr::Test(operand))
    }

    fn set(&mut self) -> Result<Set> {
        if let Tok::Macro(m) = self.peek().clone() {
            let span = self.bump().span;
            return Ok(Set::Macro(m, span));
        }
        let open = self.expect(Tok::LBrace, "`{` or a macro")?;
        let mut items = Vec::new();
        while self.peek() != &Tok::RBrace {
            let s = self.span();
            let lo = into_operand(self.value()?, s, "in a set")?;
            let hi = if self.eat(&Tok::DotDot) {
                let s = self.span();
                Some(into_operand(self.value()?, s, "after `..`")?)
            } else {
                None
            };
            items.push(SetItem { lo, hi });
            if !self.eat(&Tok::Comma) && self.peek() == &Tok::Eof {
                break;
            }
        }
        let close = self.expect(Tok::RBrace, "`}`")?;
        if items.is_empty() {
            return Err(Diagnostic::error(open.to(close), "empty set"));
        }
        Ok(Set::Items(items, open.to(close)))
    }
}

const SLICE_HELP: &str = "slices are `[i]`, `[i:len]`, `[i-j]` (inclusive), `[i:]`, `[:len]`, or a list such as `[0:2,4]`";

fn into_operand(e: Expr, span: Span, ctx: &str) -> Result<Operand> {
    match e {
        Expr::Test(o) => Ok(o),
        _ => Err(Diagnostic::error(
            span,
            format!("expected a value {ctx}, found a logical expression"),
        )),
    }
}

fn is_keyword(w: &str) -> bool {
    matches!(
        w,
        "and"
            | "or"
            | "xor"
            | "not"
            | "in"
            | "contains"
            | "matches"
            | "eq"
            | "ne"
            | "any_eq"
            | "all_ne"
            | "all_eq"
            | "any_ne"
            | "gt"
            | "ge"
            | "lt"
            | "le"
            | "let"
            | "any"
            | "all"
            | "AND"
            | "OR"
            | "XOR"
            | "NOT"
    )
}

fn is_ident(w: &str) -> bool {
    let mut b = w.bytes();
    b.next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

fn int(s: &str) -> Option<i64> {
    let (neg, digits) = match s.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, s),
    };
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let v: i64 = digits.parse().ok()?;
    Some(if neg { -v } else { v })
}

/// `a-b` with a negative and a positive end is ambiguous, so Wireshark rejects it.
fn same_sign(s: &Slice) -> bool {
    match s.end {
        SliceEnd::Inclusive(e) => (s.start < 0) == (e < 0) && s.start <= e,
        _ => true,
    }
}

fn parse_slice(text: &str) -> Option<Slice> {
    if let Some((a, b)) = text.split_once(':') {
        let start = if a.is_empty() { 0 } else { int(a)? };
        let end = if b.is_empty() {
            SliceEnd::Open
        } else {
            SliceEnd::Len(int(b).filter(|n| *n >= 0)?)
        };
        return Some(Slice { start, end });
    }
    // `i-j`: the separator is a `-` that is not a leading sign.
    if let Some(idx) = text
        .char_indices()
        .skip(1)
        .find(|&(_, c)| c == '-')
        .map(|(i, _)| i)
    {
        let (a, b) = (&text[..idx], &text[idx + 1..]);
        return Some(Slice {
            start: int(a)?,
            end: SliceEnd::Inclusive(int(b)?),
        });
    }
    Some(Slice {
        start: int(text)?,
        end: SliceEnd::Len(1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};

    fn fmt(src: &str) -> String {
        parse(src).unwrap().to_string()
    }

    #[test]
    fn precedence() {
        assert_eq!(fmt("a or b and c"), "a or b and c");
        assert_eq!(fmt("(a or b) and c"), "(a or b) and c");
        assert_eq!(fmt("a && b || c ^^ d"), "a and b or c xor d");
        assert_eq!(fmt("!a and not (b or c)"), "not a and not (b or c)");
        let p = parse("a or b and c").unwrap();
        assert!(matches!(p.expr, Expr::Or(ref v) if v.len() == 2 && matches!(v[1], Expr::And(_))));
    }

    #[test]
    fn relations_and_operators() {
        assert_eq!(
            fmt("tcp.port eq 80 and ip.src ne 1.2.3.4"),
            "tcp.port == 80 and ip.src != 1.2.3.4"
        );
        assert_eq!(fmt("ip.addr ~= 1.2.3.4"), "ip.addr !== 1.2.3.4");
        assert_eq!(fmt("tcp.flags & 0x02 == 0x02"), "tcp.flags & 0x02 == 0x02");
        assert_eq!(fmt("tcp.flags & syn"), "tcp.flags & syn");
        assert_eq!(
            fmt("tcp.payload contains \"GET\""),
            "tcp.payload contains \"GET\""
        );
        assert_eq!(fmt("http.host ~ \"x\""), "http.host matches \"x\"");
        assert_eq!(
            fmt("all tcp.port > 1 or any ip.addr not in {1.2.3.4}"),
            "all tcp.port > 1 or any ip.addr not in {1.2.3.4}"
        );
        // `any`/`all` are quantifiers only in front of an operand.
        assert_eq!(fmt("not all .tcp.port<1"), "not all .tcp.port < 1");
        assert_eq!(
            fmt("tcp.srcport-1==a -1 and {a+1}*-b / 2%3 & 4"),
            "tcp.srcport-1 == a - 1 and {a + 1} * -b / 2 % 3 & 4"
        );
    }

    #[test]
    fn sets() {
        assert_eq!(
            fmt("tcp.port in {80 443 8000..8100}"),
            "tcp.port in {80, 443, 8000..8100}"
        );
        assert_eq!(fmt("ip.dst not in $lan"), "ip.dst not in $lan");
        assert!(
            parse("tcp.port in {}")
                .unwrap_err()
                .message
                .contains("empty set")
        );
    }

    #[test]
    fn slices_and_calls() {
        assert_eq!(fmt("eth.src[0:3] == 00:11:22"), "eth.src[0:3] == 00:11:22");
        assert_eq!(fmt("frame[-1] == 0xff"), "frame[-1] == 0xff");
        assert_eq!(
            fmt("tcp.payload[1-3] == \"abc\""),
            "tcp.payload[1-3] == \"abc\""
        );
        assert_eq!(fmt("udp.payload[2:]"), "udp.payload[2:]");
        assert_eq!(fmt("frame[:4]"), "frame[0:4]");
        assert_eq!(fmt("len(tcp.payload) > 0"), "len(tcp.payload) > 0");
        assert!(parse("frame[a:b]").is_err());
    }

    #[test]
    fn lets() {
        let src = "let lan = {10.0.0.0/8, 192.168.0.0/16}; let web = tcp.port in {80, 443}\nip.dst in $lan and $web";
        assert_eq!(
            fmt(src),
            "let lan = {10.0.0.0/8, 192.168.0.0/16}\nlet web = tcp.port in {80, 443}\nip.dst in $lan and $web"
        );
        // The formatted form parses back to the same tree.
        assert_eq!(parse(&fmt(src)).unwrap().to_string(), fmt(src));
    }

    #[test]
    fn errors() {
        assert!(parse("").unwrap_err().message.contains("empty"));
        assert!(
            parse("tcp and")
                .unwrap_err()
                .message
                .contains("end of the filter")
        );
        assert!(
            parse("tcp udp")
                .unwrap_err()
                .message
                .contains("expected `and`")
        );
        assert!(
            parse("(tcp or udp) == 1")
                .unwrap_err()
                .message
                .contains("logical expression")
        );
        assert!(
            parse("tcp.port == (80")
                .unwrap_err()
                .message
                .contains("`)`")
        );
    }
}
