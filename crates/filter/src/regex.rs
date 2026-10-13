//! Regular expressions for `matches` / `~`, with Wireshark's semantics: the pattern runs over bytes
//! (not UTF-8), and it is case-insensitive unless it says `(?-i)`. Without the `regex` feature,
//! [`Regex`] is uninhabited and the checker rejects `matches`.

use alloc::string::String;

#[cfg(feature = "regex")]
pub type Regex = regex_automata::meta::Regex;

/// No regular expressions without the `regex` feature.
#[cfg(not(feature = "regex"))]
pub type Regex = core::convert::Infallible;

/// The pattern text: the bytes of the filter string, with bytes that are not UTF-8 written as
/// `\xNN` escapes (which match that byte, since patterns run over bytes).
pub(crate) fn pattern(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        for b in chunk.invalid() {
            out.push_str(&alloc::format!("\\x{b:02x}"));
        }
    }
    out
}

/// Compiles a pattern, or says why it is not valid (in Rust's regex syntax, which has no
/// look-around and no backreferences, unlike Wireshark's PCRE2).
#[cfg(feature = "regex")]
pub(crate) fn compile(pattern: &str) -> Result<Regex, String> {
    use regex_automata::meta::Builder;
    use regex_automata::util::syntax::Config;
    let syntax = Config::new()
        .unicode(false)
        .utf8(false)
        .case_insensitive(true);
    Builder::new().syntax(syntax).build(pattern).map_err(|e| {
        // The syntax error ends with a one-line reason; other build errors are one line.
        let text = match e.syntax_error() {
            Some(s) => alloc::string::ToString::to_string(s),
            None => alloc::string::ToString::to_string(&e),
        };
        let last = text.lines().last().unwrap_or_default();
        String::from(last.strip_prefix("error: ").unwrap_or(last))
    })
}

#[cfg(not(feature = "regex"))]
pub(crate) fn compile(_: &str) -> Result<Regex, String> {
    Err(String::from(
        "`matches` needs Avulse built with the `regex` feature",
    ))
}

#[cfg(feature = "regex")]
pub(crate) fn is_match(re: &Regex, haystack: &[u8]) -> bool {
    re.is_match(haystack)
}

#[cfg(not(feature = "regex"))]
pub(crate) fn is_match(re: &Regex, _: &[u8]) -> bool {
    match *re {}
}
