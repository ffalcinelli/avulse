//! Divert, modify and re-inject network packets on Linux, Windows and macOS.
//!
//! **Pre-alpha.** On Linux, handles divert, sniff, drop and send packets at the NETWORK,
//! NETWORK_FORWARD and ETHERNET layers, with eBPF programs on the TC hooks, and report flows,
//! socket calls (refusing binds and connects) and other handles at the FLOW, SOCKET and REFLECT
//! layers. Opening a handle needs `CAP_BPF`, `CAP_NET_ADMIN` and `CAP_NET_RAW` (or root). Other platforms have no backend yet, so
//! [`Handle::open`] returns [`Error::Unsupported`] there (see the
//! [implementation plan](https://github.com/ffalcinelli/avulse/blob/main/docs/implementation-plan.md)).
//!
//! The model is WinDivert's, extended. A [`Handle`] is opened at a [`Layer`] with a filter, a
//! priority and [`Flags`]. It receives the packets or events the filter matches, each with an
//! [`Address`], and it can send packets back, modified or not. The filter is a Wireshark display
//! filter (see the [guide](https://ffalcinelli.github.io/avulse/guide/)), or a WinDivert one
//! ([`Handle::open_windivert`]).
//!
//! ```no_run
//! use avulse::{Flags, Handle, Layer, MAX_PACKET_LEN};
//! use avulse::proto::{Link, Packet};
//!
//! // Watch DNS queries without diverting them.
//! let handle = Handle::open("udp.dstport == 53", Layer::Network, 0, Flags::SNIFF)?;
//! let mut buf = vec![0; MAX_PACKET_LEN];
//! loop {
//!     let (len, addr) = handle.recv(&mut buf)?;
//!     let packet = Packet::parse(&buf[..len], Link::Ip);
//!     let port = packet.udp().map(|udp| udp.src_port());
//!     println!("{len} bytes, outbound: {}, from port {port:?}", addr.outbound);
//! }
//! # Ok::<(), avulse::Error>(())
//! ```
//!
//! [`capabilities`] tells what this platform's backend supports at each layer.

mod address;
mod backend;
mod error;
mod flags;
mod handle;
mod stats;
#[cfg(test)]
mod tests;

pub use address::{
    ADDRESS_VERSION, Address, CONTEXT_LEN, Context, Flow, PROCESS_NAME_LEN, Reflect,
};
pub use avulse_filter as filter;
pub use avulse_filter::{Diagnostic, Event, Filter, Layer};
pub use avulse_proto as proto;
pub use backend::{Capabilities, LayerSupport};
pub use error::{Error, Result};
pub use flags::{Flags, Param, Shutdown};
pub use handle::{Handle, OpenOptions, PRIORITY_HIGHEST, PRIORITY_LOWEST, Syntax};
pub use stats::Stats;

/// A buffer of this many bytes holds any packet: the largest IP packet with an Ethernet header
/// and two VLAN tags.
pub const MAX_PACKET_LEN: usize = 65_600;

/// What the backend of this platform supports, per layer.
pub fn capabilities() -> Capabilities {
    backend::platform().capabilities()
}

/// Removes what processes that died without closing their handles left behind, and returns how
/// many handles that was. Opening a handle does it too.
///
/// On Linux, the TC filters of a dead process stay attached (they pass every packet once its
/// heartbeat stops) until this runs; `avulse cleanup` calls it. It needs the same privileges as
/// opening a handle. Elsewhere it does nothing.
pub fn cleanup() -> Result<usize> {
    backend::platform().cleanup()
}

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
