use alloc::format;
use alloc::string::String;
use core::fmt;

/// A byte range in the filter source.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Span {
    /// Offset of the first byte.
    pub start: usize,
    /// Offset just past the last byte.
    pub end: usize,
}

impl Span {
    /// The span from `start` to `end` (exclusive).
    pub const fn new(start: usize, end: usize) -> Self {
        Span { start, end }
    }

    /// The smallest span covering both.
    pub fn to(self, other: Span) -> Span {
        Span {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

/// How serious a [`Diagnostic`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// The filter is rejected.
    Error,
    /// The filter compiles, but probably does not mean what it says.
    Warning,
}

/// A compile error or warning, pointing into the filter source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    /// Error or warning.
    pub level: Level,
    /// The part of the source it is about.
    pub span: Span,
    /// What is wrong, in one line.
    pub message: String,
    /// How to fix it, such as "did you mean `tcp.port`?".
    pub help: Option<String>,
}

/// The result of parsing or compiling a filter.
pub type Result<T> = core::result::Result<T, Diagnostic>;

impl Diagnostic {
    pub(crate) fn error(span: Span, message: impl Into<String>) -> Self {
        Diagnostic {
            level: Level::Error,
            span,
            message: message.into(),
            help: None,
        }
    }

    pub(crate) fn warning(span: Span, message: impl Into<String>) -> Self {
        Diagnostic {
            level: Level::Warning,
            span,
            message: message.into(),
            help: None,
        }
    }

    pub(crate) fn help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    /// Renders the diagnostic with the offending source line underlined, like rustc does.
    pub fn render(&self, src: &str) -> String {
        // Snap to character boundaries, so that a span inside a character cannot panic.
        let floor = |mut i: usize| {
            i = i.min(src.len());
            while !src.is_char_boundary(i) {
                i -= 1;
            }
            i
        };
        let start = floor(self.span.start);
        let line_start = src[..start].rfind('\n').map_or(0, |i| i + 1);
        let line_end = src[start..].find('\n').map_or(src.len(), |i| start + i);
        let line_no = src[..start].matches('\n').count() + 1;
        let col = src[line_start..start].chars().count();
        let end = floor(self.span.end).clamp(start, line_end);
        let width = src[start..end].chars().count().max(1);
        let gutter = format!("{line_no}").len();
        let level = match self.level {
            Level::Error => "error",
            Level::Warning => "warning",
        };
        let mut out = format!(
            "{level}: {msg}\n{pad} |\n{line_no} | {line}\n{pad} | {sp}{carets}\n",
            msg = self.message,
            pad = " ".repeat(gutter),
            line = &src[line_start..line_end],
            sp = " ".repeat(col),
            carets = "^".repeat(width),
        );
        if let Some(help) = &self.help {
            out += &format!("{pad} = help: {help}\n", pad = " ".repeat(gutter));
        }
        out
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(help) = &self.help {
            write!(f, " (help: {help})")?;
        }
        Ok(())
    }
}

impl core::error::Error for Diagnostic {}
