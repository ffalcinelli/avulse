//! The interface between [`Handle`](crate::Handle) and the platform backends, and what each
//! backend supports.
//!
//! A backend opens handles ([`Backend::open`]) after [`OpenOptions`](crate::OpenOptions) has
//! checked the arguments and compiled the filter. The open handle ([`Opened`]) then only sees
//! calls that apply to it: `Handle` checks the flags, the layer and the parameter ranges first.

#[cfg(unix)]
use std::os::fd::BorrowedFd;
use std::time::Duration;

use avulse_filter::{Filter, Layer};

use crate::{Address, Error, Flags, Param, Result, Shutdown};

/// What a backend gets to open a handle.
// The backends read every field (Linux from Step 8); until then only the tests do.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct Spec<'a> {
    pub filter: &'a Filter,
    pub layer: Layer,
    pub priority: i16,
    pub flags: Flags,
    /// The interfaces to capture on; empty means all of them.
    pub interfaces: &'a [String],
    /// The starting values of the parameters, indexed by [`Param::index`].
    pub params: [u64; 3],
}

/// A platform backend.
pub(crate) trait Backend: Sync {
    fn capabilities(&self) -> Capabilities;
    fn open(&self, spec: &Spec<'_>) -> Result<Box<dyn Opened>>;
}

/// A handle a backend opened.
pub(crate) trait Opened: Send + Sync {
    /// Waits for a packet, at most `timeout` if there is one.
    fn recv(&self, buf: &mut [u8], timeout: Option<Duration>) -> Result<(usize, Address)>;
    fn send(&self, packet: &[u8], addr: &Address) -> Result<usize>;
    fn shutdown(&self, how: Shutdown) -> Result<()>;
    /// Applies a parameter; `value` is in range.
    fn set_param(&self, param: Param, value: u64) -> Result<()>;
    /// A descriptor that is readable when `recv` would not block.
    #[cfg(unix)]
    fn as_fd(&self) -> BorrowedFd<'_>;
    /// Detaches and frees everything, after any call in progress returns.
    fn close(self: Box<Self>) -> Result<()>;
}

/// The backend of this platform.
pub(crate) fn platform() -> &'static dyn Backend {
    &Unavailable
}

/// The backend of platforms that have none yet.
struct Unavailable;

impl Backend for Unavailable {
    fn capabilities(&self) -> Capabilities {
        Capabilities::NONE
    }

    fn open(&self, _: &Spec<'_>) -> Result<Box<dyn Opened>> {
        Err(Error::Unsupported(if cfg!(target_os = "linux") {
            "the Linux backend is not implemented yet"
        } else {
            "there is no backend for this platform yet"
        }))
    }
}

/// What a backend supports at one layer ([`Capabilities::layer`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LayerSupport {
    /// Handles can be opened at this layer. When it is false, the other fields are too.
    pub open: bool,
    /// Matching packets or events can be taken off their path, without [`Flags::SNIFF`].
    pub divert: bool,
    /// Matching packets or events can be dropped or refused ([`Flags::DROP`]).
    pub drop: bool,
    /// Handles can send packets.
    pub inject: bool,
    /// A diverted packet can be sent back modified. Where it is false but `inject` is true, the
    /// backend emulates it by dropping the packet and injecting the new one.
    pub modify: bool,
}

/// What the backend of this platform supports, per layer ([`capabilities`](crate::capabilities)).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capabilities {
    layers: [LayerSupport; 6],
}

impl Capabilities {
    /// Nothing at all.
    pub const NONE: Capabilities = Capabilities {
        layers: [LayerSupport {
            open: false,
            divert: false,
            drop: false,
            inject: false,
            modify: false,
        }; 6],
    };

    /// What the backend supports at `layer`.
    pub fn layer(&self, layer: Layer) -> LayerSupport {
        self.layers[layer as usize]
    }

    #[cfg(test)]
    pub(crate) fn with(mut self, layer: Layer, support: LayerSupport) -> Self {
        self.layers[layer as usize] = support;
        self
    }
}

#[cfg(test)]
impl LayerSupport {
    pub(crate) const ALL: LayerSupport = LayerSupport {
        open: true,
        divert: true,
        drop: true,
        inject: true,
        modify: true,
    };
}
