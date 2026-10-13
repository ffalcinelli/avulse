//! The Avulse filter engine compiled to WebAssembly, for the playground on the website.
//!
//! The functions here are plain Rust, tested natively. On `wasm32`, thin `wasm-bindgen` wrappers
//! export them to JavaScript, converting the results with `serde`.

use avulse_filter::fields::FIELDS;
use avulse_filter::{Diagnostic, Filter, Layer, Level, Meta, parse};
use avulse_proto::{Link, Packet};
use serde::Serialize;

mod samples;

pub use samples::{Sample, samples};

/// A compile error or warning, with its span in UTF-16 code units for the browser.
#[derive(Debug, Serialize)]
pub struct Diag {
    /// `"error"` or `"warning"`.
    pub level: &'static str,
    /// Start of the span, in UTF-16 code units.
    pub start: usize,
    /// End of the span, in UTF-16 code units.
    pub end: usize,
    /// What is wrong.
    pub message: String,
    /// How to fix it.
    pub help: Option<String>,
    /// The diagnostic with the source line underlined, as the CLI prints it.
    pub rendered: String,
}

impl Diag {
    fn new(d: &Diagnostic, src: &str) -> Self {
        let utf16 = |byte: usize| {
            let byte = byte.min(src.len());
            // A span always falls on character boundaries; be safe anyway.
            let byte = (0..=byte)
                .rev()
                .find(|&b| src.is_char_boundary(b))
                .unwrap_or(0);
            src[..byte].encode_utf16().count()
        };
        Diag {
            level: match d.level {
                Level::Error => "error",
                Level::Warning => "warning",
            },
            start: utf16(d.span.start),
            end: utf16(d.span.end),
            message: d.message.clone(),
            help: d.help.clone(),
            rendered: d.render(src),
        }
    }
}

/// Everything the playground shows about a filter.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Analysis {
    /// Errors and warnings. At most one error.
    pub diagnostics: Vec<Diag>,
    /// The canonical form (`avulse filter fmt`), if the filter parses.
    pub canonical: Option<String>,
    /// The compiled filter (`avulse filter explain`), if it compiles.
    pub ir: Option<String>,
    /// Whether the filter needs user space (`matches`).
    pub user_space_only: bool,
    /// Whether each sample matches, in [`samples`] order; empty if the filter does not compile.
    pub verdicts: Vec<bool>,
}

/// The metadata a packet is evaluated with.
#[derive(Debug, Default)]
pub struct Context<'a> {
    /// Whether the packet is outbound.
    pub outbound: bool,
    /// The interface name; empty for none.
    pub iface: &'a str,
}

impl Context<'_> {
    fn meta(&self, link: Link) -> Meta<'_> {
        Meta {
            layer: match link {
                Link::Ethernet => Layer::Ethernet,
                Link::Ip => Layer::Network,
            },
            outbound: self.outbound,
            iface: (!self.iface.is_empty()).then_some(self.iface),
            ..Meta::default()
        }
    }
}

/// Compiles `src` and runs it over the samples.
pub fn analyze(src: &str, ctx: &Context<'_>) -> Analysis {
    let canonical = parse(src).ok().map(|p| p.to_string());
    match Filter::compile(src) {
        Ok(filter) => Analysis {
            diagnostics: filter
                .warnings()
                .iter()
                .map(|w| Diag::new(w, src))
                .collect(),
            canonical,
            ir: Some(filter.ir().to_string()),
            user_space_only: filter.user_space_only(),
            verdicts: samples()
                .iter()
                .map(|s| {
                    let packet = Packet::parse(&s.bytes, Link::Ethernet);
                    filter.matches(&packet, &ctx.meta(Link::Ethernet))
                })
                .collect(),
        },
        Err(e) => Analysis {
            diagnostics: vec![Diag::new(&e, src)],
            canonical,
            ir: None,
            user_space_only: false,
            verdicts: Vec::new(),
        },
    }
}

/// Evaluates `src` against a packet given in hex, as `avulse filter eval` does.
///
/// # Errors
///
/// A message if the hex is invalid or the filter does not compile.
pub fn eval_hex(src: &str, hex: &str, link: Link, ctx: &Context<'_>) -> Result<bool, String> {
    let bytes = decode_hex(hex)?;
    let filter = Filter::compile(src).map_err(|e| e.message)?;
    Ok(filter.matches(&Packet::parse(&bytes, link), &ctx.meta(link)))
}

/// Decodes hex digits, ignoring whitespace, `:` and `-`.
///
/// # Errors
///
/// A message for a character that is not a hex digit, or an odd number of digits.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = s
        .bytes()
        .filter(|c| !c.is_ascii_whitespace() && *c != b':' && *c != b'-')
        .collect();
    if let Some(&c) = digits.iter().find(|c| !c.is_ascii_hexdigit()) {
        return Err(format!("`{}` is not a hex digit", char::from(c)));
    }
    if !digits.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    Ok(digits
        .chunks(2)
        .map(|p| (hex_value(p[0]) << 4) | hex_value(p[1]))
        .collect())
}

fn hex_value(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => c - b'A' + 10,
    }
}

/// Encodes bytes as hex, 16 bytes per line in groups of two.
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, b) in bytes.iter().enumerate() {
        if i % 16 == 0 && i > 0 {
            out.push('\n');
        } else if i % 2 == 0 && i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A field, for the playground's field list.
#[derive(Debug, Serialize)]
pub struct FieldInfo {
    /// The name.
    pub name: &'static str,
    /// The type, such as "an unsigned integer".
    pub ty: &'static str,
    /// The description.
    pub desc: &'static str,
    /// Whether it is an Avulse extension rather than a Wireshark field.
    pub extension: bool,
}

/// Every field.
pub fn fields() -> Vec<FieldInfo> {
    FIELDS
        .iter()
        .map(|d| FieldInfo {
            name: d.name,
            ty: d.ty.name(),
            desc: d.desc,
            extension: d.origin != avulse_filter::fields::Origin::Wireshark,
        })
        .collect()
}

#[cfg(target_arch = "wasm32")]
mod bindings {
    //! The JavaScript API.

    use serde::Serialize;
    use wasm_bindgen::prelude::*;

    use super::*;

    fn to_js<T: Serialize>(value: &T) -> JsValue {
        serde_wasm_bindgen::to_value(value).unwrap_or(JsValue::NULL)
    }

    /// `{ diagnostics, canonical, ir, userSpaceOnly, verdicts }` for a filter.
    #[wasm_bindgen]
    pub fn analyze(src: &str, outbound: bool, iface: &str) -> JsValue {
        to_js(&super::analyze(src, &Context { outbound, iface }))
    }

    /// `true` or `false`, or a string with the error.
    #[wasm_bindgen(js_name = evalHex)]
    pub fn eval_hex(src: &str, hex: &str, ip: bool, outbound: bool, iface: &str) -> JsValue {
        let link = if ip { Link::Ip } else { Link::Ethernet };
        match super::eval_hex(src, hex, link, &Context { outbound, iface }) {
            Ok(v) => JsValue::from_bool(v),
            Err(e) => JsValue::from_str(&e),
        }
    }

    #[derive(Serialize)]
    struct JsSample {
        name: &'static str,
        summary: &'static str,
        hex: String,
    }

    /// `[{ name, summary, hex }]`: the sample Ethernet frames.
    #[wasm_bindgen]
    pub fn samples() -> JsValue {
        let samples: Vec<_> = super::samples()
            .into_iter()
            .map(|s| JsSample {
                name: s.name,
                summary: s.summary,
                hex: encode_hex(&s.bytes),
            })
            .collect();
        to_js(&samples)
    }

    /// `[{ name, ty, desc, extension }]`: every field.
    #[wasm_bindgen]
    pub fn fields() -> JsValue {
        to_js(&super::fields())
    }

    /// The crate version.
    #[wasm_bindgen]
    pub fn version() -> String {
        env!("CARGO_PKG_VERSION").into()
    }
}

#[cfg(test)]
mod tests;
