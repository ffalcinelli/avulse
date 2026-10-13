//! The Avulse filter language: a Wireshark display-filter subset plus extensions.
//!
//! ```
//! use avulse_filter::{Filter, Meta};
//! use avulse_proto::{Link, Packet};
//!
//! let f = Filter::compile("let web = {80, 443}\noutbound and tcp.dstport in $web").unwrap();
//! # let bytes = [0u8; 0];
//! let pkt = Packet::parse(&bytes, Link::Ip);
//! assert!(!f.matches(&pkt, &Meta { outbound: true, ..Meta::default() }));
//! ```
//!
//! [`parse`] builds the syntax tree, [`Filter::compile`] resolves names, checks types and lowers
//! the tree to the [`ir`], which [`Filter::matches`] evaluates without allocating. The crate is
//! `no_std` (with `alloc`) so that the same evaluator runs in kernel contexts.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod ast;
mod check;
pub mod error;
mod eval;
pub mod fields;
pub mod ir;
mod labels;
mod lexer;
mod lit;
pub mod meta;
mod parser;
pub mod regex;

use alloc::vec::Vec;

use avulse_proto::Packet;

pub use error::{Diagnostic, Level, Span};
pub use meta::{Event, FlowTuple, Layer, Meta};
pub use parser::parse;

/// A compiled filter.
#[derive(Clone, Debug)]
pub struct Filter {
    ir: ir::Test,
    warnings: Vec<Diagnostic>,
    /// The compiled patterns of `matches`, indexed by `ir::Test::Matches::index`.
    regexes: Vec<regex::Regex>,
}

impl Filter {
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

    pub fn matches(&self, packet: &Packet<'_>, meta: &Meta<'_>) -> bool {
        eval::matches(&self.ir, packet, meta, &self.regexes)
    }

    /// Whether the filter needs user space: `matches` cannot run in the kernel backends.
    pub fn user_space_only(&self) -> bool {
        self.ir.user_space_only()
    }

    pub fn ir(&self) -> &ir::Test {
        &self.ir
    }

    /// Non-fatal diagnostics, such as a bare boolean field that only tests presence.
    pub fn warnings(&self) -> &[Diagnostic] {
        &self.warnings
    }
}

#[cfg(test)]
mod tests;
