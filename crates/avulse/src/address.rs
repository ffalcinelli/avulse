//! The address of a packet or event: everything a handle knows about it besides its bytes.

use core::fmt;
use core::net::{IpAddr, Ipv6Addr};

use avulse_filter::{Event, FlowTuple, Layer, Meta};

use crate::Flags;

/// The version of the [`Address`] layout. It changes whenever a field is added, moved or resized.
pub const ADDRESS_VERSION: u16 = 2;

/// Size of the reinjection context ([`Context`]).
pub const CONTEXT_LEN: usize = 64;

/// What a handle knows about a packet or event, besides its bytes.
///
/// `recv` fills one per packet. To reinject a packet, send it with the address it was received
/// with: the direction, interface and [`context`](Address::context) tell the backend where it
/// goes. To inject a new packet, start from [`Address::new`] and set the direction and interface.
///
/// The layout is `#[repr(C)]` and versioned ([`ADDRESS_VERSION`]), so that the C ABI can expose it.
/// Which fields are meaningful depends on the layer:
///
/// | Layer | Fields |
/// | --- | --- |
/// | NETWORK, NETWORK_FORWARD, ETHERNET | direction, interface, VLAN, checksum flags, `context` |
/// | FLOW, SOCKET | [`flow`](Address::flow) |
/// | REFLECT | [`reflect`](Address::reflect) |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
#[non_exhaustive]
pub struct Address {
    /// When the packet or event was seen, in nanoseconds of the backend's monotonic clock
    /// (`CLOCK_MONOTONIC` on Linux).
    pub timestamp: i64,
    pub(crate) version: u16,
    /// The layer of the handle that received it.
    pub layer: Layer,
    /// What happened: [`Event::Packet`] at the packet layers.
    pub event: Event,
    /// Whether the packet is outbound. When sending, chooses the direction.
    pub outbound: bool,
    /// Whether the packet is on a loopback interface.
    pub loopback: bool,
    /// Whether another handle injected the packet.
    pub impostor: bool,
    /// Whether the handle received a copy ([`Flags::SNIFF`]), so the packet went on.
    pub sniffed: bool,
    /// Whether the packet is IPv6 (at the ETHERNET layer: whether it carries IPv6).
    pub ipv6: bool,
    /// Whether the IPv4 header checksum is known to be valid. When sending, `false` asks the
    /// backend to compute it.
    pub ip_checksum: bool,
    /// Whether the TCP checksum is known to be valid. When sending, `false` asks the backend to
    /// compute it.
    pub tcp_checksum: bool,
    /// Whether the UDP checksum is known to be valid. When sending, `false` asks the backend to
    /// compute it.
    pub udp_checksum: bool,
    /// Interface index.
    pub if_idx: u32,
    /// Sub-interface index (0 where the platform has none).
    pub sub_if_idx: u32,
    /// The outer VLAN tag control information, when [`vlan`](Address::vlan) is set. At the
    /// NETWORK layers, the tag the packet carried on the wire.
    pub vlan_tci: u16,
    /// Whether the packet carried a VLAN tag.
    pub vlan: bool,
    reserved: u8,
    /// The flow or socket of an event (FLOW and SOCKET layers).
    pub flow: Flow,
    /// The handle an event is about (REFLECT layer).
    pub reflect: Reflect,
    /// What the backend needs to reinject a captured packet unchanged.
    pub context: Context,
}

impl Address {
    /// An empty address at `layer`: inbound, no interface, every checksum to be computed.
    pub const fn new(layer: Layer) -> Self {
        Address {
            timestamp: 0,
            version: ADDRESS_VERSION,
            layer,
            event: Event::Packet,
            outbound: false,
            loopback: false,
            impostor: false,
            sniffed: false,
            ipv6: false,
            ip_checksum: false,
            tcp_checksum: false,
            udp_checksum: false,
            if_idx: 0,
            sub_if_idx: 0,
            vlan_tci: 0,
            vlan: false,
            reserved: 0,
            flow: Flow::EMPTY,
            reflect: Reflect::EMPTY,
            context: Context::EMPTY,
        }
    }

    /// The layout version this address was made with ([`ADDRESS_VERSION`]).
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// The metadata a filter sees for this packet or event, as
    /// [`Filter::matches`](avulse_filter::Filter::matches) takes it. The interface name is not
    /// part of the address, so `iface` never matches.
    pub fn meta(&self) -> Meta<'_> {
        let mut meta = Meta {
            layer: self.layer,
            event: self.event,
            outbound: self.outbound,
            loopback: self.loopback,
            impostor: self.impostor,
            ifidx: self.if_idx,
            subifidx: self.sub_if_idx,
            timestamp: self.timestamp,
            ..Meta::default()
        };
        match self.layer {
            Layer::Flow | Layer::Socket => {
                let f = &self.flow;
                meta.process_id = Some(f.process_id);
                meta.process_name = f.process_name();
                meta.endpoint_id = Some(f.endpoint_id);
                meta.parent_endpoint_id = Some(f.parent_endpoint_id);
                meta.flow = Some(FlowTuple {
                    local_addr: f.local_addr(),
                    remote_addr: f.remote_addr(),
                    local_port: f.local_port,
                    remote_port: f.remote_port,
                    protocol: f.protocol,
                });
            }
            // The handle the event is about: WinDivert's `layer` and `priority` at REFLECT.
            Layer::Reflect => {
                meta.process_id = Some(self.reflect.process_id);
                meta.priority = self.reflect.priority;
                meta.layer = self.reflect.layer;
            }
            Layer::Network | Layer::NetworkForward | Layer::Ethernet => {}
        }
        meta
    }
}

impl Default for Address {
    fn default() -> Self {
        Address::new(Layer::Network)
    }
}

/// The flow or socket of a FLOW or SOCKET event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
#[non_exhaustive]
pub struct Flow {
    /// The endpoint (socket) ID.
    pub endpoint_id: u64,
    /// The parent endpoint ID.
    pub parent_endpoint_id: u64,
    /// The ID of the process that owns the socket.
    pub process_id: u32,
    /// Local port.
    pub local_port: u16,
    /// Remote port.
    pub remote_port: u16,
    /// Local address, IPv4 as IPv4-mapped IPv6 (`::ffff:a.b.c.d`).
    pub local_addr: [u8; 16],
    /// Remote address, IPv4 as IPv4-mapped IPv6.
    pub remote_addr: [u8; 16],
    /// IP protocol number.
    pub protocol: u8,
    reserved: [u8; 7],
    /// The name of the process, UTF-8 and NUL-padded ([`process_name`](Flow::process_name)).
    pub(crate) process_name: [u8; PROCESS_NAME_LEN],
}

/// The room for a process name in a [`Flow`].
pub const PROCESS_NAME_LEN: usize = 32;

impl Flow {
    const EMPTY: Flow = Flow {
        endpoint_id: 0,
        parent_endpoint_id: 0,
        process_id: 0,
        local_port: 0,
        remote_port: 0,
        local_addr: [0; 16],
        remote_addr: [0; 16],
        protocol: 0,
        reserved: [0; 7],
        process_name: [0; PROCESS_NAME_LEN],
    };

    /// The local address, IPv4-mapped addresses as IPv4.
    pub fn local_addr(&self) -> IpAddr {
        Ipv6Addr::from(self.local_addr).to_canonical()
    }

    /// The remote address, IPv4-mapped addresses as IPv4.
    pub fn remote_addr(&self) -> IpAddr {
        Ipv6Addr::from(self.remote_addr).to_canonical()
    }

    /// Sets the local address.
    pub fn set_local_addr(&mut self, addr: IpAddr) {
        self.local_addr = mapped(addr);
    }

    /// Sets the remote address.
    pub fn set_remote_addr(&mut self, addr: IpAddr) {
        self.remote_addr = mapped(addr);
    }

    /// The name of the process that owns the socket, when the backend knows it (on Linux, its
    /// `comm`: at most 15 bytes).
    pub fn process_name(&self) -> Option<&str> {
        let n = self
            .process_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(PROCESS_NAME_LEN);
        core::str::from_utf8(&self.process_name[..n])
            .ok()
            .filter(|s| !s.is_empty())
    }

    /// Sets the process name, cut to [`PROCESS_NAME_LEN`] bytes at a character boundary.
    pub fn set_process_name(&mut self, name: &str) {
        let mut n = name.len().min(PROCESS_NAME_LEN);
        while !name.is_char_boundary(n) {
            n -= 1;
        }
        self.process_name = [0; PROCESS_NAME_LEN];
        self.process_name[..n].copy_from_slice(&name.as_bytes()[..n]);
    }
}

fn mapped(addr: IpAddr) -> [u8; 16] {
    match addr {
        IpAddr::V4(a) => a.to_ipv6_mapped().octets(),
        IpAddr::V6(a) => a.octets(),
    }
}

impl Default for Flow {
    fn default() -> Self {
        Flow::EMPTY
    }
}

/// The handle a REFLECT event is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
#[non_exhaustive]
pub struct Reflect {
    /// When it was opened, on the same clock as [`Address::timestamp`].
    pub timestamp: i64,
    /// Its flags.
    pub flags: Flags,
    /// The ID of the process that opened it.
    pub process_id: u32,
    /// Its priority.
    pub priority: i16,
    /// Its layer.
    pub layer: Layer,
    reserved: u8,
}

impl Reflect {
    const EMPTY: Reflect = Reflect {
        timestamp: 0,
        flags: Flags::NONE,
        process_id: 0,
        priority: 0,
        layer: Layer::Network,
        reserved: 0,
    };
}

impl Default for Reflect {
    fn default() -> Self {
        Reflect::EMPTY
    }
}

/// What a backend needs to reinject a captured packet unchanged. On Linux, for example: the
/// link-layer header that the NETWORK layers strip, the segmentation size of a GSO packet, and
/// the interface it was captured on.
///
/// It is opaque to applications. Copy it with the rest of the address from a received packet to
/// the packet you send back; a packet you build yourself goes out with an empty one, and the
/// backend routes it.
///
/// A backend uses at most the first 56 bytes and leaves the rest zero: the WinDivert-compatible
/// library keeps only those, in WinDivert's 80-byte address.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Context([u8; CONTEXT_LEN]);

impl Context {
    /// No context.
    pub const EMPTY: Context = Context([0; CONTEXT_LEN]);

    /// A context with these bytes. For backends.
    pub const fn from_bytes(bytes: [u8; CONTEXT_LEN]) -> Self {
        Context(bytes)
    }

    /// The bytes. For backends.
    pub const fn as_bytes(&self) -> &[u8; CONTEXT_LEN] {
        &self.0
    }

    /// Whether the context is empty (all zeros).
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl Default for Context {
    fn default() -> Self {
        Context::EMPTY
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            f.write_str("Context(empty)")
        } else {
            f.write_str("Context(")?;
            for b in &self.0 {
                write!(f, "{b:02x}")?;
            }
            f.write_str(")")
        }
    }
}
