//! Tokenizer for the Wireshark display-filter syntax plus Avulse extensions.
//!
//! Field names, numbers, addresses and byte strings are all lexed as *words* (runs of
//! alphanumerics and `_ . : / -`). The checker resolves each word by context, as Wireshark does.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Diagnostic, Result, Span};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Tok {
    Word(String),
    Str(Vec<u8>),
    Char(u8),
    Macro(String),
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Comma,
    Semi,
    DotDot,
    Assign,
    Eq,
    Ne,
    AllEq,
    AnyNe,
    Lt,
    Le,
    Gt,
    Ge,
    AndAnd,
    OrOr,
    XorXor,
    Bang,
    Amp,
    Tilde,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    Eof,
}

impl Tok {
    pub(crate) fn describe(&self) -> String {
        match self {
            Tok::Word(w) => format!("`{w}`"),
            Tok::Str(_) => "a string".into(),
            Tok::Char(_) => "a character".into(),
            Tok::Macro(m) => format!("`${m}`"),
            Tok::Eof => "the end of the filter".into(),
            t => format!("`{}`", t.symbol()),
        }
    }

    fn symbol(&self) -> &'static str {
        match self {
            Tok::LParen => "(",
            Tok::RParen => ")",
            Tok::LBrace => "{",
            Tok::RBrace => "}",
            Tok::LBracket => "[",
            Tok::RBracket => "]",
            Tok::Comma => ",",
            Tok::Semi => ";",
            Tok::DotDot => "..",
            Tok::Assign => "=",
            Tok::Eq => "==",
            Tok::Ne => "!=",
            Tok::AllEq => "===",
            Tok::AnyNe => "!==",
            Tok::Lt => "<",
            Tok::Le => "<=",
            Tok::Gt => ">",
            Tok::Ge => ">=",
            Tok::AndAnd => "&&",
            Tok::OrOr => "||",
            Tok::XorXor => "^^",
            Tok::Bang => "!",
            Tok::Amp => "&",
            Tok::Tilde => "~",
            Tok::Plus => "+",
            Tok::Minus => "-",
            Tok::Star => "*",
            Tok::Slash => "/",
            Tok::Percent => "%",
            _ => "?",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Token {
    pub tok: Tok,
    pub span: Span,
}

pub(crate) fn is_word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b':' | b'/' | b'-')
}

pub(crate) fn lex(src: &str) -> Result<Vec<Token>> {
    let b = src.as_bytes();
    let mut toks = Vec::new();
    let mut i = 0;
    let at = |i: usize| b.get(i).copied().unwrap_or(0);
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        let tok = match c {
            b'#' => {
                if i > 0 && is_word_byte(b[i - 1]) {
                    let end = i + 1 + b[i + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
                    return Err(Diagnostic::error(
                        Span::new(i, end),
                        "the layer operator `#` is not supported",
                    )
                    .help(
                        "Avulse does not decode tunnels, so each protocol appears at most once",
                    ));
                }
                i += b[i..]
                    .iter()
                    .position(|&c| c == b'\n')
                    .unwrap_or(b.len() - i);
                continue;
            }
            b'/' if at(i + 1) == b'/' => {
                i += b[i..]
                    .iter()
                    .position(|&c| c == b'\n')
                    .unwrap_or(b.len() - i);
                continue;
            }
            b'/' if at(i + 1) == b'*' => match src[i + 2..].find("*/") {
                Some(n) => {
                    i += n + 4;
                    continue;
                }
                None => {
                    return Err(Diagnostic::error(
                        Span::new(i, i + 2),
                        "unterminated comment",
                    ));
                }
            },
            // `-` and `/` also occur inside words (`00-11-22`, `10.0.0.0/8`, `[1-3]`), so as in
            // Wireshark they are operators only where a word cannot start: `a - 1`, `-a`, `a / 2`.
            // `-1` stays a word, a negative number, which the parser splits after an operand.
            b'-' if !at(i + 1).is_ascii_digit() => single(&mut i, Tok::Minus),
            b'/' => single(&mut i, Tok::Slash),
            b'+' => single(&mut i, Tok::Plus),
            b'*' => single(&mut i, Tok::Star),
            b'%' => single(&mut i, Tok::Percent),
            b'(' => single(&mut i, Tok::LParen),
            b')' => single(&mut i, Tok::RParen),
            b'{' => single(&mut i, Tok::LBrace),
            b'}' => single(&mut i, Tok::RBrace),
            b'[' => single(&mut i, Tok::LBracket),
            b']' => single(&mut i, Tok::RBracket),
            b',' => single(&mut i, Tok::Comma),
            b';' => single(&mut i, Tok::Semi),
            b'=' if at(i + 1) == b'=' && at(i + 2) == b'=' => multi(&mut i, 3, Tok::AllEq),
            b'=' if at(i + 1) == b'=' => multi(&mut i, 2, Tok::Eq),
            b'=' => single(&mut i, Tok::Assign),
            b'!' if at(i + 1) == b'=' && at(i + 2) == b'=' => multi(&mut i, 3, Tok::AnyNe),
            b'!' if at(i + 1) == b'=' => multi(&mut i, 2, Tok::Ne),
            b'!' => single(&mut i, Tok::Bang),
            b'~' if at(i + 1) == b'=' => multi(&mut i, 2, Tok::AnyNe),
            b'~' => single(&mut i, Tok::Tilde),
            b'<' if at(i + 1) == b'=' => multi(&mut i, 2, Tok::Le),
            b'<' => single(&mut i, Tok::Lt),
            b'>' if at(i + 1) == b'=' => multi(&mut i, 2, Tok::Ge),
            b'>' => single(&mut i, Tok::Gt),
            b'&' if at(i + 1) == b'&' => multi(&mut i, 2, Tok::AndAnd),
            b'&' => single(&mut i, Tok::Amp),
            b'|' if at(i + 1) == b'|' => multi(&mut i, 2, Tok::OrOr),
            b'^' if at(i + 1) == b'^' => multi(&mut i, 2, Tok::XorXor),
            b'|' | b'^' => {
                return Err(Diagnostic::error(
                    Span::new(i, i + 1),
                    format!("`{}` is not an operator", c as char),
                )
                .help(if c == b'|' {
                    "use `or` or `||`"
                } else {
                    "use `xor` or `^^`"
                }));
            }
            b'.' if at(i + 1) == b'.' => multi(&mut i, 2, Tok::DotDot),
            b'"' => Tok::Str(string(b, &mut i, false)?),
            b'r' if at(i + 1) == b'"' => {
                i += 1;
                Tok::Str(string(b, &mut i, true)?)
            }
            b'\'' => Tok::Char(char_lit(b, &mut i)?),
            b'$' => Tok::Macro(macro_name(src, &mut i)?),
            c if is_word_byte(c) => {
                while i < b.len() && is_word_byte(b[i]) && !(b[i] == b'.' && at(i + 1) == b'.') {
                    i += 1;
                }
                Tok::Word(src[start..i].into())
            }
            _ => {
                let ch = src[i..].chars().next().unwrap_or('?');
                return Err(Diagnostic::error(
                    Span::new(i, i + ch.len_utf8()),
                    format!("unexpected character `{ch}`"),
                ));
            }
        };
        toks.push(Token {
            tok,
            span: Span::new(start, i),
        });
    }
    toks.push(Token {
        tok: Tok::Eof,
        span: Span::new(b.len(), b.len()),
    });
    Ok(toks)
}

fn single(i: &mut usize, t: Tok) -> Tok {
    *i += 1;
    t
}

fn multi(i: &mut usize, n: usize, t: Tok) -> Tok {
    *i += n;
    t
}

/// Parses a quoted string starting at the opening quote; leaves `i` after the closing quote.
fn string(b: &[u8], i: &mut usize, raw: bool) -> Result<Vec<u8>> {
    let open = *i;
    *i += 1;
    let mut out = Vec::new();
    loop {
        match b.get(*i) {
            None => {
                return Err(Diagnostic::error(
                    Span::new(open, b.len()),
                    "unterminated string",
                ));
            }
            Some(b'"') => {
                *i += 1;
                return Ok(out);
            }
            Some(b'\\') if !raw => out.push(escape(b, i)?),
            Some(b'\\') if b.get(*i + 1) == Some(&b'"') => {
                out.extend_from_slice(b"\\\"");
                *i += 2;
            }
            Some(&c) => {
                out.push(c);
                *i += 1;
            }
        }
    }
}

fn char_lit(b: &[u8], i: &mut usize) -> Result<u8> {
    let open = *i;
    *i += 1;
    let c = match b.get(*i) {
        Some(b'\\') => escape(b, i)?,
        Some(&c) if c != b'\'' && c.is_ascii() => {
            *i += 1;
            c
        }
        _ => {
            return Err(Diagnostic::error(
                Span::new(open, *i + 1),
                "invalid character literal",
            ));
        }
    };
    if b.get(*i) != Some(&b'\'') {
        return Err(
            Diagnostic::error(Span::new(open, *i), "unterminated character literal")
                .help("character literals hold one ASCII character, like 'a' or '\\x41'"),
        );
    }
    *i += 1;
    Ok(c)
}

/// Parses an escape sequence starting at the backslash.
fn escape(b: &[u8], i: &mut usize) -> Result<u8> {
    let start = *i;
    let c = b.get(*i + 1).copied();
    *i += 2;
    let hex = |d: u8| (d as char).to_digit(16);
    let v = match c {
        Some(b'n') => b'\n',
        Some(b'r') => b'\r',
        Some(b't') => b'\t',
        Some(b'a') => 0x07,
        Some(b'b') => 0x08,
        Some(b'f') => 0x0c,
        Some(b'v') => 0x0b,
        Some(c @ (b'\\' | b'"' | b'\'')) => c,
        Some(b'x') => {
            let digits: Vec<u32> = b[*i..].iter().take(2).map_while(|&d| hex(d)).collect();
            if digits.is_empty() {
                return Err(Diagnostic::error(
                    Span::new(start, *i),
                    "`\\x` needs one or two hex digits",
                ));
            }
            *i += digits.len();
            digits.iter().fold(0, |a, d| a * 16 + d) as u8
        }
        Some(c @ b'0'..=b'7') => {
            let mut v = (c - b'0') as u32;
            for _ in 0..2 {
                match b.get(*i) {
                    Some(&d @ b'0'..=b'7') => {
                        v = v * 8 + (d - b'0') as u32;
                        *i += 1;
                    }
                    _ => break,
                }
            }
            if v > 0xff {
                return Err(Diagnostic::error(
                    Span::new(start, *i),
                    "octal escape out of range",
                ));
            }
            v as u8
        }
        _ => {
            return Err(Diagnostic::error(
                Span::new(start, (*i).min(b.len())),
                "unknown escape sequence",
            ));
        }
    };
    Ok(v)
}

/// `$name` or `${name}`.
fn macro_name(src: &str, i: &mut usize) -> Result<String> {
    let start = *i;
    let b = src.as_bytes();
    let ident = |c: &u8| c.is_ascii_alphanumeric() || *c == b'_';
    let name = if b.get(*i + 1) == Some(&b'{') {
        let Some(len) = src[*i + 2..].find('}') else {
            return Err(Diagnostic::error(
                Span::new(start, b.len()),
                "unterminated `${`",
            ));
        };
        let name = &src[*i + 2..*i + 2 + len];
        *i += len + 3;
        if name.contains('.') {
            return Err(Diagnostic::error(Span::new(start, *i), "field references are not supported")
                .help("`${field}` refers to the packet selected in Wireshark; compare against a value instead"));
        }
        if name.contains(':') || name.contains(';') {
            return Err(Diagnostic::error(
                Span::new(start, *i),
                "macro arguments are not supported",
            ));
        }
        name
    } else {
        let len = b[*i + 1..].iter().take_while(|c| ident(c)).count();
        *i += len + 1;
        &src[start + 1..*i]
    };
    if name.is_empty() || !name.bytes().all(|c| ident(&c)) {
        return Err(Diagnostic::error(
            Span::new(start, *i),
            "expected a macro name after `$`",
        ));
    }
    Ok(name.into())
}

#[cfg(test)]
pub(crate) fn kinds(src: &str) -> Vec<Tok> {
    lex(src).unwrap().into_iter().map(|t| t.tok).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn w(s: &str) -> Tok {
        Tok::Word(s.into())
    }

    #[test]
    fn words_cover_fields_and_literals() {
        assert_eq!(
            kinds("ip.src==10.0.0.0/8 and eth.dst != 00:11:22:33:44:55 or ipv6.addr == fe80::1"),
            vec![
                w("ip.src"),
                Tok::Eq,
                w("10.0.0.0/8"),
                w("and"),
                w("eth.dst"),
                Tok::Ne,
                w("00:11:22:33:44:55"),
                w("or"),
                w("ipv6.addr"),
                Tok::Eq,
                w("fe80::1"),
                Tok::Eof
            ]
        );
    }

    #[test]
    fn ranges_split_words() {
        assert_eq!(
            kinds("{80, 8000..8100}"),
            vec![
                Tok::LBrace,
                w("80"),
                Tok::Comma,
                w("8000"),
                Tok::DotDot,
                w("8100"),
                Tok::RBrace,
                Tok::Eof
            ]
        );
    }

    #[test]
    fn operators() {
        assert_eq!(
            kinds("== != === !== ~= ~ < <= > >= && || ^^ ! & ="),
            vec![
                Tok::Eq,
                Tok::Ne,
                Tok::AllEq,
                Tok::AnyNe,
                Tok::AnyNe,
                Tok::Tilde,
                Tok::Lt,
                Tok::Le,
                Tok::Gt,
                Tok::Ge,
                Tok::AndAnd,
                Tok::OrOr,
                Tok::XorXor,
                Tok::Bang,
                Tok::Amp,
                Tok::Assign,
                Tok::Eof
            ]
        );
    }

    #[test]
    fn strings_chars_and_escapes() {
        assert_eq!(
            kinds(r#""GET \x2f\101\n""#),
            vec![Tok::Str(b"GET /A\n".to_vec()), Tok::Eof]
        );
        assert_eq!(
            kinds(r#"r"a\d""#),
            vec![Tok::Str(b"a\\d".to_vec()), Tok::Eof]
        );
        assert_eq!(
            kinds(r"'a' '\x41' '\n'"),
            vec![Tok::Char(b'a'), Tok::Char(0x41), Tok::Char(b'\n'), Tok::Eof]
        );
    }

    #[test]
    fn comments_and_macros() {
        assert_eq!(
            kinds("# full line\ntcp // rest\n/* block */ and $web or ${lan}"),
            vec![
                w("tcp"),
                w("and"),
                Tok::Macro("web".into()),
                w("or"),
                Tok::Macro("lan".into()),
                Tok::Eof
            ]
        );
    }

    #[test]
    fn errors() {
        assert!(
            lex("ip.src#2 == 1.2.3.4")
                .unwrap_err()
                .message
                .contains("layer operator")
        );
        assert!(lex("tcp | udp").unwrap_err().help.unwrap().contains("or"));
        assert!(lex("\"open").unwrap_err().message.contains("unterminated"));
        assert!(
            lex("${ip.src}")
                .unwrap_err()
                .message
                .contains("field references")
        );
        assert!(lex("tcp @ udp").unwrap_err().message.contains("unexpected"));
    }

    #[test]
    fn arithmetic() {
        assert_eq!(
            kinds("a + 1 - b * -2 / c % d -1 -e"),
            vec![
                w("a"),
                Tok::Plus,
                w("1"),
                Tok::Minus,
                w("b"),
                Tok::Star,
                w("-2"),
                Tok::Slash,
                w("c"),
                Tok::Percent,
                w("d"),
                w("-1"),
                Tok::Minus,
                w("e"),
                Tok::Eof
            ]
        );
        // Inside a word, `-` and `/` are not operators.
        assert_eq!(
            kinds("tcp.port-1 10.0.0.0/8 aa-bb"),
            vec![w("tcp.port-1"), w("10.0.0.0/8"), w("aa-bb"), Tok::Eof]
        );
    }
}
