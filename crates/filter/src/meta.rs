//! What the backend knows about a packet or event besides its bytes.

use core::net::IpAddr;

/// Layer of a handle. The first five match WinDivert's numbering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Layer {
    /// IP packets on the local host (WinDivert's NETWORK layer).
    #[default]
    Network = 0,
    /// IP packets being forwarded (NETWORK_FORWARD).
    NetworkForward = 1,
    /// Flow established and deleted events (FLOW).
    Flow = 2,
    /// Socket operations (SOCKET).
    Socket = 3,
    /// Other handles opening and closing (REFLECT).
    Reflect = 4,
    /// Ethernet frames (an Avulse addition).
    Ethernet = 5,
}

/// Event of a packet or notification. Matches WinDivert's numbering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Event {
    /// A packet (NETWORK, NETWORK_FORWARD and ETHERNET layers).
    #[default]
    Packet = 0,
    /// A flow was established.
    FlowEstablished = 1,
    /// A flow was deleted.
    FlowDeleted = 2,
    /// A socket was bound.
    SocketBind = 3,
    /// A socket connected.
    SocketConnect = 4,
    /// A socket started listening.
    SocketListen = 5,
    /// A socket accepted a connection.
    SocketAccept = 6,
    /// A socket was closed.
    SocketClose = 7,
    /// A handle was opened.
    ReflectOpen = 8,
    /// A handle was closed.
    ReflectClose = 9,
}

impl TryFrom<u8> for Layer {
    type Error = u8;

    /// The layer of number `n` (WinDivert's numbering); `Err(n)` if there is none.
    fn try_from(n: u8) -> Result<Layer, u8> {
        Ok(match n {
            0 => Layer::Network,
            1 => Layer::NetworkForward,
            2 => Layer::Flow,
            3 => Layer::Socket,
            4 => Layer::Reflect,
            5 => Layer::Ethernet,
            _ => return Err(n),
        })
    }
}

impl TryFrom<u8> for Event {
    type Error = u8;

    /// The event of number `n` (WinDivert's numbering); `Err(n)` if there is none.
    fn try_from(n: u8) -> Result<Event, u8> {
        Ok(match n {
            0 => Event::Packet,
            1 => Event::FlowEstablished,
            2 => Event::FlowDeleted,
            3 => Event::SocketBind,
            4 => Event::SocketConnect,
            5 => Event::SocketListen,
            6 => Event::SocketAccept,
            7 => Event::SocketClose,
            8 => Event::ReflectOpen,
            9 => Event::ReflectClose,
            _ => return Err(n),
        })
    }
}

/// Endpoints of a flow or socket event (FLOW and SOCKET layers have no packet).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    /// Local address.
    pub local_addr: IpAddr,
    /// Remote address.
    pub remote_addr: IpAddr,
    /// Local port.
    pub local_port: u16,
    /// Remote port.
    pub remote_port: u16,
    /// IP protocol number.
    pub protocol: u8,
}

/// Metadata for the extension fields (`outbound`, `iface`, `process.pid`, ...).
#[derive(Clone, Copy, Debug, Default)]
pub struct Meta<'a> {
    /// The handle's layer (`layer`).
    pub layer: Layer,
    /// The event (`event`).
    pub event: Event,
    /// Whether the packet is outbound (`outbound`; `inbound` is its negation).
    pub outbound: bool,
    /// Whether the packet is on a loopback interface (`loopback`).
    pub loopback: bool,
    /// Whether the packet was injected by another handle (`impostor`).
    pub impostor: bool,
    /// Interface index.
    pub ifidx: u32,
    /// Sub-interface index.
    pub subifidx: u32,
    /// Interface name (`iface`, `frame.interface_name`).
    pub iface: Option<&'a str>,
    /// Process ID (`process.pid`).
    pub process_id: Option<u32>,
    /// Process name (`process.name`).
    pub process_name: Option<&'a str>,
    /// Endpoint ID (`endpoint.id`).
    pub endpoint_id: Option<u64>,
    /// Parent endpoint ID (`parent.endpoint.id`).
    pub parent_endpoint_id: Option<u64>,
    /// Flow endpoints, for the FLOW and SOCKET layers (`local.addr`, `remote.port`, …).
    pub flow: Option<FlowTuple>,
    /// Timestamp of the packet or event (`timestamp`), in the backend's units.
    pub timestamp: i64,
    /// Priority of the handle (`priority`); at the REFLECT layer, of the handle the event is
    /// about.
    pub priority: i16,
    /// A deterministic per-packet hash, which the `random8`, `random16` and `random32` fields read
    /// as WinDivert does: bits 48 to 55, 32 to 47, and 0 to 31.
    pub hash: u64,
}
