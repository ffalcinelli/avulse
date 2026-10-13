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
}
