//! The report: one JSON object per line, `{"probe", "name", "ok", "value"}`, echoed to stdout.

use std::fs::{File, OpenOptions};
use std::io::Write;

pub struct Report {
    out: File,
    probe: String,
}

/// A JSON string literal.
pub fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

impl Report {
    pub fn open(path: &str) -> Self {
        let out = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap_or_else(|e| panic!("cannot open {path}: {e}"));
        Report {
            out,
            probe: String::new(),
        }
    }

    pub fn section(&mut self, probe: &str) {
        self.probe = probe.to_string();
        println!("== {probe}");
    }

    fn write(&mut self, name: &str, ok: Option<bool>, value: String) {
        let ok = match ok {
            Some(b) => b.to_string(),
            None => "null".into(),
        };
        let line = format!(
            "{{\"probe\":{},\"name\":{},\"ok\":{ok},\"value\":{value}}}",
            json_str(&self.probe),
            json_str(name)
        );
        println!("{line}");
        let _ = writeln!(self.out, "{line}");
    }

    /// A fact (no verdict).
    pub fn info(&mut self, name: &str, value: impl AsRef<str>) {
        self.write(name, None, json_str(value.as_ref()));
    }

    /// A number (no verdict).
    pub fn num(&mut self, name: &str, value: f64) {
        let v = if value.is_finite() {
            format!("{value}")
        } else {
            "null".into()
        };
        self.write(name, None, v);
    }

    /// A check that passed or failed, with what was seen.
    pub fn check(&mut self, name: &str, ok: bool, value: impl AsRef<str>) {
        self.write(name, Some(ok), json_str(value.as_ref()));
    }

    pub fn fail(&mut self, name: &str, value: impl AsRef<str>) {
        self.check(name, false, value);
    }
}
