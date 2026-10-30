//! Errors of the handle API.

use std::fmt;
use std::io;

use avulse_filter::Diagnostic;

/// The result of a handle operation.
pub type Result<T> = core::result::Result<T, Error>;

/// Why a handle operation failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The filter does not compile. [`Diagnostic::render`] shows where and why.
    Filter(Diagnostic),
    /// An argument is out of range, or does not apply to the handle (its layer or flags).
    InvalidArgument(&'static str),
    /// This platform's backend cannot do it (see [`capabilities`](crate::capabilities)).
    Unsupported(&'static str),
    /// The handle was shut down in this direction (and, when receiving, its queue is empty).
    Shutdown,
    /// `recv_timeout` waited for its whole timeout.
    Timeout,
    /// The packet does not fit the buffer; it is dropped. `needed` is its length.
    BufferTooSmall {
        /// The packet's length.
        needed: usize,
    },
    /// The operating system refused, such as for lack of privileges.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Filter(d) => write!(f, "invalid filter: {d}"),
            Error::InvalidArgument(what) => write!(f, "invalid argument: {what}"),
            Error::Unsupported(what) => write!(f, "not supported: {what}"),
            Error::Shutdown => f.write_str("the handle is shut down"),
            Error::Timeout => f.write_str("timed out"),
            Error::BufferTooSmall { needed } => {
                write!(f, "the packet ({needed} bytes) does not fit the buffer")
            }
            Error::Io(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Filter(d) => Some(d),
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<Diagnostic> for Error {
    fn from(d: Diagnostic) -> Self {
        Error::Filter(d)
    }
}
