//! The [Avulse] filter language: Wireshark display filters, restricted to what one packet
//! determines, plus a few extensions.
//!
//! ```
//! use avulse_filter::{Filter, Meta};
//! use avulse_proto::{Link, Packet};
//!
//! let filter = Filter::compile(
//!     "let web = {80, 443, 8000..8100}\n\
//!      outbound and tcp.dstport in $web and not ip.dst == 10.0.0.0/8",
//! )
//! .unwrap();
//!
//! // IPv4 + TCP SYN from 192.168.1.2:40000 to 93.184.215.14:443.
//! let bytes = [
//!     0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0, 192, 168, 1, 2, 93, 184, 215, 14, //
//!     0x9c, 0x40, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
//! ];
//! let packet = Packet::parse(&bytes, Link::Ip);
//! assert!(filter.matches(&packet, &Meta { outbound: true, ..Meta::default() }));
//! assert!(!filter.matches(&packet, &Meta::default())); // inbound
//! ```
//!
//! # Pipeline
//!
//! [`parse`] builds the syntax tree ([`ast`]), whose `Display` is the canonical form.
//! [`Filter::compile`] parses, resolves names against the field registry ([`fields`]) and the
//! `let` macros, checks types, and lowers the tree to the typed [`ir`], which
//! [`Filter::matches`] evaluates against a [`Packet`] and its [`Meta`]. Errors and warnings are
//! [`Diagnostic`]s with a source span and, often, a "did you mean" hint.
//!
//! # Semantics
//!
//! A filter that Wireshark 4.6+ accepts and Avulse compiles selects the same packets: a test
//! compares the two with `tshark` on every supported field. Fields can have several occurrences
//! (`ip.addr`, `tcp.port`, `vlan.id`): `==` means some pair is equal, `!=` that no pair is, and any
//! comparison with an absent field is false. The [guide] describes the language and lists the
//! intentional differences from Wireshark.
//!
//! # `no_std` and allocation
//!
//! The crate is `no_std` with `alloc`, and has no `unsafe` code. Compiling allocates; evaluating
//! does not (except `matches`), so the same evaluator can run in kernel contexts. To keep it so,
//! filters whose intermediate values could exceed fixed buffers are rejected at compile time.
//!
//! # Features
//!
//! - `regex`: the `matches` (`~`) operator, through `regex-automata` (still `no_std`). Without it,
//!   filters that use `matches` fail to compile. Kernel backends run such filters in user space
//!   ([`Filter::user_space_only`]).
//!
//! [Avulse]: https://ffalcinelli.github.io/avulse/
//! [guide]: https://ffalcinelli.github.io/avulse/guide/
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_logo_url = "https://ffalcinelli.github.io/avulse/favicon.svg")]
#![doc(html_favicon_url = "https://ffalcinelli.github.io/avulse/favicon.svg")]

extern crate alloc;

pub mod ast;
pub mod bytecode;
mod check;
/// Diagnostics and source spans.
pub mod error;
mod eval;
pub mod fields;
pub mod ir;
mod labels;
mod lexer;
mod lit;
pub mod meta;
mod native;
mod parser;
pub mod regex;
mod value;
mod windivert;

use alloc::string::String;
use alloc::vec::Vec;

use avulse_proto::Packet;

pub use error::{Diagnostic, Level, Span};
pub use meta::{Event, FlowTuple, Layer, Meta};
pub use parser::parse;

/// A compiled filter, ready to match packets.
///
/// Compile once, then call [`matches`](Self::matches) for each packet: it does not allocate.
#[derive(Clone, Debug)]
pub struct Filter {
    ir: ir::Test,
    warnings: Vec<Diagnostic>,
    /// The compiled patterns of `matches`, indexed by `ir::Test::Matches::index`.
    regexes: Vec<regex::Regex>,
}

impl Filter {
    /// Compiles a filter.
    ///
    /// # Errors
    ///
    /// The first error: syntax, an unknown field or macro, a type mismatch, a literal out of
    /// range, a field that needs stream state (`tcp.seq`), or a value that could exceed the
    /// evaluator's buffers. [`Diagnostic::render`] formats it with the offending source.
    ///
    /// ```
    /// use avulse_filter::Filter;
    ///
    /// let err = Filter::compile("tcp.prot == 80").unwrap_err();
    /// assert_eq!(err.message, "unknown field `tcp.prot`");
    /// assert_eq!(err.help.as_deref(), Some("did you mean `tcp.port`?"));
    /// ```
    pub fn compile(src: &str) -> Result<Self, Diagnostic> {
        let program = parse(src)?;
        let mut checker = check::Checker::new(&program.lets);
        let ir = ir::simplify(checker.program(&program)?);
        Ok(Filter {
            ir,
            warnings: checker.warnings,
            regexes: checker.regexes,
        })
    }

    /// Compiles a WinDivert filter for a handle at `layer`, with WinDivert 2.2's syntax and
    /// semantics (see the [guide]). The result is an ordinary filter: it matches packets, compiles
    /// to bytecode, and its [`ir`](Self::ir) prints as a native filter.
    ///
    /// ```
    /// use avulse_filter::{Filter, Layer};
    ///
    /// let f = Filter::compile_windivert("outbound and tcp.DstPort == 80", Layer::Network).unwrap();
    /// assert_eq!(f.ir().native().to_string(), "outbound and tcp.dstport == 80");
    /// ```
    ///
    /// # Errors
    ///
    /// The first error, as WinDivert reports it: an unknown token (names are case-sensitive), a
    /// field or macro that the layer does not have, an index out of bounds, or a filter too long
    /// or too deep. The ETHERNET layer has no WinDivert filters.
    ///
    /// [guide]: https://ffalcinelli.github.io/avulse/guide/filters/windivert.html
    pub fn compile_windivert(src: &str, layer: meta::Layer) -> Result<Self, Diagnostic> {
        Ok(Filter {
            ir: windivert::compile(src, layer)?,
            warnings: Vec::new(),
            regexes: Vec::new(),
        })
    }

    /// A WinDivert filter for `layer`, reformatted in WinDivert syntax: one space around
    /// operators, flags as bare names (`tcp`, `not outbound`), addresses in their notation, and
    /// byte offsets for indexes (`packet16[4b]`). The result compiles to the same filter. This is
    /// what the WinDivert-compatible libraries return for `WinDivertHelperFormatFilter`, whose
    /// own output (a decompilation of WinDivert's filter object) can differ in form.
    ///
    /// ```
    /// use avulse_filter::{Filter, Layer};
    ///
    /// let s = Filter::format_windivert("not  outbound and(tcp.DstPort==80 or udp)", Layer::Network);
    /// assert_eq!(s.unwrap(), "not outbound and (tcp.DstPort == 80 or udp)");
    /// ```
    ///
    /// # Errors
    ///
    /// The errors of [`compile_windivert`](Self::compile_windivert).
    pub fn format_windivert(src: &str, layer: meta::Layer) -> Result<String, Diagnostic> {
        windivert::format(src, layer)
    }

    /// Whether `packet`, with metadata `meta`, matches the filter.
    ///
    /// This does not allocate unless the filter uses `matches`, and never panics.
    pub fn matches(&self, packet: &Packet<'_>, meta: &Meta<'_>) -> bool {
        eval::matches(&self.ir, packet, meta, &self.regexes)
    }

    /// Whether the filter needs user space: `matches` cannot run in the kernel backends.
    pub fn user_space_only(&self) -> bool {
        self.ir.user_space_only()
    }

    /// The filter compiled to bytecode, for the kernel backends. Its results are the same as
    /// [`matches`](Self::matches)'s.
    ///
    /// # Errors
    ///
    /// [`bytecode::EncodeError`]: the filter uses `matches` (which runs in user space only), or is
    /// too deep or too large for the bytecode.
    pub fn program(&self) -> Result<bytecode::Program, bytecode::EncodeError> {
        bytecode::Program::compile(&self.ir)
    }

    /// The compiled, simplified test. Its `Display` is what `avulse filter explain` prints.
    pub fn ir(&self) -> &ir::Test {
        &self.ir
    }

    /// Non-fatal diagnostics, such as a bare boolean field that only tests presence.
    ///
    /// ```
    /// use avulse_filter::{Filter, Level};
    ///
    /// let f = Filter::compile("tcp.flags.syn").unwrap();
    /// assert_eq!(f.warnings()[0].level, Level::Warning);
    /// ```
    pub fn warnings(&self) -> &[Diagnostic] {
        &self.warnings
    }
}

#[cfg(test)]
mod tests;

/// Runs the Rust examples of the READMEs as doctests.
#[cfg(doctest)]
mod readme {
    #[doc = include_str!("../README.md")]
    struct Crate;

    #[doc = include_str!("../../../README.md")]
    struct Workspace;
}
