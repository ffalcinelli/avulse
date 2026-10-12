//! What the backend knows about a packet or event besides its bytes.

use core::net::IpAddr;

/// Layer of a handle. The first five match WinDivert's numbering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Layer {
    #[default]
    Network = 0,
    NetworkForward = 1,
    Flow = 2,
    Socket = 3,
    Reflect = 4,
    Ethernet = 5,
}

/// Event of a packet or notification. Matches WinDivert's numbering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Event {
    #[default]
    Packet = 0,
    FlowEstablished = 1,
    FlowDeleted = 2,
    SocketBind = 3,
    SocketConnect = 4,
    SocketListen = 5,
    SocketAccept = 6,
    SocketClose = 7,
    ReflectOpen = 8,
    ReflectClose = 9,
}

/// Endpoints of a flow or socket event (FLOW and SOCKET layers have no packet).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    pub local_addr: IpAddr,
    pub remote_addr: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: u8,
}

/// Metadata for the extension fields (`outbound`, `iface`, `process.pid`, ...).
#[derive(Clone, Copy, Debug, Default)]
pub struct Meta<'a> {
    pub layer: Layer,
    pub event: Event,
    pub outbound: bool,
    pub loopback: bool,
    pub impostor: bool,
    pub ifidx: u32,
    pub subifidx: u32,
    pub iface: Option<&'a str>,
    pub process_id: Option<u32>,
    pub process_name: Option<&'a str>,
    pub endpoint_id: Option<u64>,
    pub parent_endpoint_id: Option<u64>,
    pub flow: Option<FlowTuple>,
}
