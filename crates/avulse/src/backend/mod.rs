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
use avulse_proto::{Link, Packet};

use crate::{Address, Error, Flags, Param, Result, Shutdown, Stats, Syntax};

/// What a backend gets to open a handle. Without a backend, only the tests' fake one reads it,
/// and not all of it.
#[cfg_attr(not(any(target_os = "linux", target_os = "windows")), allow(dead_code))]
pub(crate) struct Spec<'a> {
    pub filter: &'a Filter,
    /// The filter as written, and its language: what REFLECT reports.
    pub source: &'a str,
    pub syntax: Syntax,
    pub layer: Layer,
    pub priority: i16,
    pub flags: Flags,
    /// The interfaces to capture on; empty means all of them.
    pub interfaces: &'a [String],
    /// The starting values of the parameters, indexed by [`Param::index`].
    pub params: [u64; 3],
    /// The name of the driver's kernel service (Windows).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub service: &'a str,
    /// Where the Windows driver is, if not in the default place.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub driver: Option<&'a std::path::Path>,
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

/// A platform backend.
pub(crate) trait Backend: Sync {
    fn capabilities(&self) -> Capabilities;
    fn open(&self, spec: &Spec<'_>) -> Result<Box<dyn Opened>>;
    /// Removes what processes that died without closing their handles left behind, and returns
    /// how many handles that was.
    fn cleanup(&self) -> Result<usize> {
        Ok(0)
    }
}

/// A handle a backend opened.
pub(crate) trait Opened: Send + Sync {
    /// Waits for a packet, at most `timeout` if there is one.
    fn recv(&self, buf: &mut [u8], timeout: Option<Duration>) -> Result<(usize, Address)>;
    /// A packet that is already there and fits `buf`, without waiting; `None` otherwise, and a
    /// packet that does not fit stays first in line (for [`Handle::recv_batch`]).
    ///
    /// [`Handle::recv_batch`]: crate::Handle::recv_batch
    fn recv_ready(&self, _buf: &mut [u8]) -> Result<Option<(usize, Address)>> {
        Ok(None)
    }
    fn send(&self, packet: &[u8], addr: &Address) -> Result<usize>;
    fn shutdown(&self, how: Shutdown) -> Result<()>;
    /// Applies a parameter; `value` is in range.
    fn set_param(&self, param: Param, value: u64) -> Result<()>;
    /// The handle's counters.
    fn stats(&self) -> Result<Stats> {
        Err(Error::Unsupported("statistics"))
    }
    /// A descriptor that is readable when `recv` would not block.
    #[cfg(unix)]
    fn as_fd(&self) -> BorrowedFd<'_>;
    /// The file of the Windows driver's device that the handle uses, if it has one.
    #[cfg(windows)]
    fn device(&self) -> Option<std::os::windows::io::BorrowedHandle<'_>> {
        None
    }
    /// Detaches and frees everything, after any call in progress returns.
    fn close(self: Box<Self>) -> Result<()>;
}

/// The backend of this platform.
pub(crate) fn platform() -> &'static dyn Backend {
    #[cfg(target_os = "linux")]
    return &linux::Linux;
    #[cfg(target_os = "windows")]
    return &windows::Windows;
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    return &Unavailable;
}

/// The backend of platforms that have none yet.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
struct Unavailable;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
impl Backend for Unavailable {
    fn capabilities(&self) -> Capabilities {
        Capabilities::NONE
    }

    fn open(&self, _: &Spec<'_>) -> Result<Box<dyn Opened>> {
        Err(crate::Error::Unsupported(
            "there is no backend for this platform yet",
        ))
    }
}

/// The length of an Ethernet header.
const ETH_LEN: usize = 14;

/// Where the IP header of `packet` starts, after checking that the packet suits the layer:
/// `None` for a frame that carries no IP packet (ETHERNET).
#[cfg_attr(not(any(target_os = "linux", target_os = "windows")), allow(dead_code))]
pub(crate) fn ip_offset(packet: &[u8], layer: Layer) -> Result<Option<usize>> {
    if layer == Layer::Ethernet {
        if packet.len() < ETH_LEN {
            return Err(Error::InvalidArgument(
                "the frame is shorter than an Ethernet header",
            ));
        }
        let p = Packet::parse(packet, Link::Ethernet);
        return Ok(p
            .l3_offset()
            .filter(|_| p.ipv4().is_some() || p.ipv6().is_some()));
    }
    match packet[0] >> 4 {
        4 if packet.len() >= 20 => Ok(Some(0)),
        6 if packet.len() >= 40 => Ok(Some(0)),
        _ => Err(Error::InvalidArgument("not an IPv4 or IPv6 packet")),
    }
}

/// What WinDivert does to the packets an application sends with the impostor flag: decrement
/// the TTL (hop limit), so that two handles that reinject each other's packets cannot loop
/// forever. `ip` starts with the IP header.
#[cfg_attr(not(any(target_os = "linux", target_os = "windows")), allow(dead_code))]
pub(crate) fn decrement_ttl(ip: &mut [u8]) -> Result<()> {
    let at = match ip[0] >> 4 {
        4 => 8,
        6 => 7,
        _ => return Ok(()),
    };
    if ip[at] <= 1 {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::HostUnreachable,
            "the TTL of the impostor packet ran out",
        )));
    }
    ip[at] -= 1;
    if at == 8 {
        // The header checksum, updated: the word TTL|protocol went down by 0x100.
        let c = u16::from_be_bytes([ip[10], ip[11]]) as u32 + 0x100;
        let c = (c & 0xffff) + (c >> 16);
        ip[10..12].copy_from_slice(&(c as u16).to_be_bytes());
    }
    Ok(())
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
