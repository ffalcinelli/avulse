//! The protocol between the macOS backend and the avulse system extension, and the reinjection
//! context of the macOS backend.
//!
//! The extension serves an XPC Mach service, [`MACH_SERVICE`]. Each message is a dictionary with
//! one data value, `"d"`: a [`Request`] from the backend, a response from the extension. As with
//! the Windows driver's IOCTLs, everything is plain bytes in little-endian order, encoded and
//! decoded here, and the payloads reuse [`ioctl`](crate::ioctl)'s encodings.
//!
//! | [`Op`] | Payload | Response's payload |
//! | --- | --- | --- |
//! | `Open` | [`OpenRequest`](crate::ioctl::OpenRequest) | the handle, `u64` |
//! | `Recv` | [`encode_recv`]: timeout and size | [`Record`](crate::ioctl::Record)s, back to back, at least one |
//! | `Send` | `Record`s, back to back | a [`SendResult`] byte per record |
//! | `Shutdown` | how, `u32` (1 receive, 2 send, 3 both) | nothing |
//! | `SetParam` | [`encode_set_param`](crate::ioctl::encode_set_param) | nothing |
//! | `Stats` | nothing | [`encode_stats`](crate::ioctl::encode_stats) |
//! | `Close` | nothing | nothing |
//! | `Capabilities` | nothing | [`encode_capabilities`]: a byte per layer |
//! | `TestPacket` | [`encode_test_packet`] | the verdict, `u32`, and the token, `u64` |
//! | `TestFlow` | [`TestFlow::encode`] | the verdict, `u32`, four zero bytes, the flow's id, `u64`, and whether its end is wanted, `u8`, then seven zero bytes |
//!
//! A response starts with a [`Status`]. The extension serves root clients only, and each client
//! connection owns the handles it opened: they close when it goes away.
//!
//! **Sending.** The extension does not inject. A diverted packet is held (delayed) in the
//! extension, and its address's [`MacContext::token`] names it. A packet sent back unchanged goes
//! on from where it was ([`SendResult::Sent`]); otherwise the extension drops the original, notes
//! the new packet and its sender's priority, so that handles at that priority and above skip it,
//! and the backend sends it itself ([`SendResult::Inject`]).

use crate::ioctl::{Malformed, Reader};
use crate::{CONTEXT_LEN, Context};

extern crate alloc;

use alloc::vec::Vec;

/// The extension's XPC Mach service (its `NEMachServiceName`). A sandboxed system extension's
/// service name must start with one of its application groups, which a signed build prefixes
/// with the team ID.
pub const MACH_SERVICE: &str = "group.com.github.ffalcinelli.avulse";

/// What a request asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Op {
    /// Opens a handle.
    Open = 1,
    /// Receives packets: answers when one is queued, the handle is shut down, or the timeout
    /// passes.
    Recv = 2,
    /// Sends packets back, or new ones.
    Send = 3,
    /// Shuts the handle down in one direction or both.
    Shutdown = 4,
    /// Sets a queue parameter.
    SetParam = 5,
    /// Reads the handle's counters.
    Stats = 6,
    /// Closes the handle.
    Close = 7,
    /// What the extension supports, per layer.
    Capabilities = 8,
    /// Runs a packet through the packet path as the provider would: only when the extension
    /// runs in its test mode, without the provider.
    TestPacket = 9,
    /// Runs a flow's start or end through the flow path as the data provider would: only in
    /// test mode.
    TestFlow = 10,
}

impl TryFrom<u32> for Op {
    type Error = Malformed;

    fn try_from(v: u32) -> Result<Op, Malformed> {
        Ok(match v {
            1 => Op::Open,
            2 => Op::Recv,
            3 => Op::Send,
            4 => Op::Shutdown,
            5 => Op::SetParam,
            6 => Op::Stats,
            7 => Op::Close,
            8 => Op::Capabilities,
            9 => Op::TestPacket,
            10 => Op::TestFlow,
            _ => return Err(Malformed::Value),
        })
    }
}

/// How a request went: 0, or a negative `errno` value (macOS numbering).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Status {
    /// Done.
    Ok = 0,
    /// The client is not root (`EPERM`).
    Denied = -1,
    /// No such handle, or not the client's (`EBADF`).
    NoHandle = -9,
    /// Out of memory (`ENOMEM`).
    NoMemory = -12,
    /// A malformed request, or an argument out of range (`EINVAL`).
    Invalid = -22,
    /// Not supported: a layer or operation the extension does not serve (`ENOTSUP`).
    Unsupported = -45,
    /// The handle is shut down in that direction (`ESHUTDOWN`).
    Shutdown = -58,
    /// Nothing came before the timeout (`ETIMEDOUT`).
    Timeout = -60,
}

impl TryFrom<i32> for Status {
    type Error = Malformed;

    fn try_from(v: i32) -> Result<Status, Malformed> {
        Ok(match v {
            0 => Status::Ok,
            -1 => Status::Denied,
            -9 => Status::NoHandle,
            -12 => Status::NoMemory,
            -22 => Status::Invalid,
            -45 => Status::Unsupported,
            -58 => Status::Shutdown,
            -60 => Status::Timeout,
            _ => return Err(Malformed::Value),
        })
    }
}

/// A request: the operation, the handle it is about (0 for `Open` and `Capabilities`), and its
/// payload. The layout is the operation (`u32`), four zero bytes, the handle (`u64`), then the
/// payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    /// The operation.
    pub op: Op,
    /// The handle.
    pub handle: u64,
    /// The operation's payload.
    pub payload: &'a [u8],
}

const HEADER: usize = 16;

impl<'a> Request<'a> {
    /// The request's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(HEADER + self.payload.len());
        b.extend_from_slice(&(self.op as u32).to_le_bytes());
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&self.handle.to_le_bytes());
        b.extend_from_slice(self.payload);
        b
    }

    /// The request in `b`, checked.
    pub fn decode(b: &'a [u8]) -> Result<Self, Malformed> {
        let mut r = Reader { b };
        let op = Op::try_from(r.u32()?)?;
        r.take(4)?;
        let handle = r.u64()?;
        Ok(Request {
            op,
            handle,
            payload: r.b,
        })
    }
}

/// A response's bytes: the status (`i32`), four zero bytes, then the payload.
pub fn encode_response(status: Status, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(8 + payload.len());
    b.extend_from_slice(&(status as i32).to_le_bytes());
    b.extend_from_slice(&[0; 4]);
    b.extend_from_slice(payload);
    b
}

/// The status and payload of a response.
pub fn decode_response(b: &[u8]) -> Result<(Status, &[u8]), Malformed> {
    let mut r = Reader { b };
    let status = Status::try_from(r.u32()? as i32)?;
    r.take(4)?;
    Ok((status, r.b))
}

/// `Recv`'s payload: how long to wait at most, in milliseconds (0: do not wait), and how many
/// bytes of records the response may hold (at least one record is returned, whatever its size).
pub fn encode_recv(timeout_ms: u32, max_bytes: u32) -> [u8; 8] {
    let mut b = [0; 8];
    b[..4].copy_from_slice(&timeout_ms.to_le_bytes());
    b[4..].copy_from_slice(&max_bytes.to_le_bytes());
    b
}

/// The timeout and size of a `Recv` payload.
pub fn decode_recv(b: &[u8]) -> Result<(u32, u32), Malformed> {
    let mut r = Reader { b };
    let v = (r.u32()?, r.u32()?);
    if !r.b.is_empty() {
        return Err(Malformed::Value);
    }
    Ok(v)
}

/// What became of a record the backend sent, in `Send`'s response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SendResult {
    /// The extension let the held original go on: the record was it, unchanged.
    Sent = 0,
    /// The backend must send it: a new or modified packet, which the extension noted.
    Inject = 1,
}

impl TryFrom<u8> for SendResult {
    type Error = Malformed;

    fn try_from(v: u8) -> Result<SendResult, Malformed> {
        match v {
            0 => Ok(SendResult::Sent),
            1 => Ok(SendResult::Inject),
            _ => Err(Malformed::Value),
        }
    }
}

/// What a layer supports, as `Capabilities` reports it: the bits of a byte.
pub mod support {
    /// Handles can be opened.
    pub const OPEN: u8 = 1;
    /// Packets can be diverted.
    pub const DIVERT: u8 = 2;
    /// Packets can be dropped.
    pub const DROP: u8 = 4;
    /// Packets can be sent.
    pub const INJECT: u8 = 8;
    /// A diverted packet can be sent back modified.
    pub const MODIFY: u8 = 16;
}

/// `Capabilities`' response: a [`support`] byte per layer, in layer order.
pub fn encode_capabilities(layers: [u8; 6]) -> [u8; 6] {
    layers
}

/// The [`support`] bytes of a `Capabilities` response.
pub fn decode_capabilities(b: &[u8]) -> Result<[u8; 6], Malformed> {
    let mut r = Reader { b };
    let mut layers = [0; 6];
    for l in &mut layers {
        *l = r.u8()?;
        if *l & !0x1f != 0 {
            return Err(Malformed::Value);
        }
    }
    Ok(layers)
}

/// A packet for `TestPacket`, as the provider gets it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TestPacket<'a> {
    /// The interface's index.
    pub ifindex: u32,
    /// Whether it is outbound.
    pub outbound: bool,
    /// Whether the interface is a loopback one.
    pub loopback: bool,
    /// The bytes: a frame, or an IP packet.
    pub data: &'a [u8],
}

/// `TestPacket`'s payload: the interface index (`u32`), a flags byte (1 outbound, 2 loopback),
/// three zero bytes, then the packet.
pub fn encode_test_packet(p: &TestPacket<'_>) -> Vec<u8> {
    let mut b = Vec::with_capacity(8 + p.data.len());
    b.extend_from_slice(&p.ifindex.to_le_bytes());
    b.push(u8::from(p.outbound) | (u8::from(p.loopback) << 1));
    b.extend_from_slice(&[0; 3]);
    b.extend_from_slice(p.data);
    b
}

/// The packet of a `TestPacket` payload.
pub fn decode_test_packet(b: &[u8]) -> Result<TestPacket<'_>, Malformed> {
    let mut r = Reader { b };
    let ifindex = r.u32()?;
    let flags = r.u8()?;
    if flags & !3 != 0 || r.take(3)? != [0; 3] {
        return Err(Malformed::Value);
    }
    Ok(TestPacket {
        ifindex,
        outbound: flags & 1 != 0,
        loopback: flags & 2 != 0,
        data: r.b,
    })
}

/// What the macOS backend keeps in [`Address::context`](crate::Address::context): the interface
/// a packet was captured on, the Ethernet header the NETWORK layer strips (with up to 2 VLAN
/// tags), and, for a packet the extension diverted, the token of the original it holds.
///
/// | Offset | Size | |
/// | --- | --- | --- |
/// | 0 | 1 | [`MacContext::MAGIC`] |
/// | 1 | 1 | length of the link-layer header |
/// | 4 | 4 | the interface it was captured on |
/// | 8 | 22 | the link-layer header |
/// | 40 | 8 | the extension's token, 0 for none |
///
/// The numbers are in the host's byte order: a context only goes back to the host it came from.
/// It fits the first 56 bytes, which the WinDivert shim keeps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MacContext {
    /// The interface the packet was captured on.
    pub ifindex: u32,
    /// The extension's token for the original it holds, 0 for none.
    pub token: u64,
    l2_len: u8,
    l2: [u8; MacContext::L2_MAX],
}

const _: () = assert!(MacContext::TOKEN_AT + 8 <= 56);

impl MacContext {
    /// The first byte of the context: the backend and version of the layout.
    pub const MAGIC: u8 = 0xc1;
    /// The longest link-layer header kept: Ethernet with two VLAN tags.
    pub const L2_MAX: usize = 22;
    const L2_AT: usize = 8;
    const TOKEN_AT: usize = 40;

    /// A context for a packet captured on `ifindex` behind `l2` (`None` if it is longer than
    /// [`L2_MAX`](Self::L2_MAX)), with the extension's `token`.
    pub fn new(ifindex: u32, l2: &[u8], token: u64) -> Option<MacContext> {
        if l2.len() > Self::L2_MAX {
            return None;
        }
        let mut c = MacContext {
            ifindex,
            token,
            l2_len: l2.len() as u8,
            l2: [0; Self::L2_MAX],
        };
        c.l2[..l2.len()].copy_from_slice(l2);
        Some(c)
    }

    /// The saved link-layer header (empty at the ETHERNET layer, and on links without one).
    pub fn l2(&self) -> &[u8] {
        &self.l2[..self.l2_len as usize]
    }

    /// The context's bytes.
    pub fn encode(&self) -> Context {
        let mut b = [0u8; CONTEXT_LEN];
        b[0] = Self::MAGIC;
        b[1] = self.l2_len;
        b[4..8].copy_from_slice(&self.ifindex.to_ne_bytes());
        b[Self::L2_AT..Self::L2_AT + Self::L2_MAX].copy_from_slice(&self.l2);
        b[Self::TOKEN_AT..Self::TOKEN_AT + 8].copy_from_slice(&self.token.to_ne_bytes());
        Context::from_bytes(b)
    }

    /// The context of a captured packet; `None` for an empty one (a packet the application
    /// built), or one this backend did not make.
    pub fn decode(c: &Context) -> Option<MacContext> {
        let b = c.as_bytes();
        if b[0] != Self::MAGIC || b[1] as usize > Self::L2_MAX {
            return None;
        }
        let mut l2 = [0; Self::L2_MAX];
        l2.copy_from_slice(&b[Self::L2_AT..Self::L2_AT + Self::L2_MAX]);
        let mut token = [0; 8];
        token.copy_from_slice(&b[Self::TOKEN_AT..Self::TOKEN_AT + 8]);
        Some(MacContext {
            ifindex: u32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
            token: u64::from_ne_bytes(token),
            l2_len: b[1],
            l2,
        })
    }
}

/// A flow for `TestFlow`, as the data provider reports it: its start (a connect or an accept,
/// with its endpoints and process) or its end.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TestFlow {
    /// Whether this is the flow's end, which [`id`](Self::id) names; else its start.
    pub end: bool,
    /// The flow's id, from its start's response (for an end).
    pub id: u64,
    /// Whether the local side opened it (a connect), rather than accepted it.
    pub outbound: bool,
    /// The IP protocol.
    pub protocol: u8,
    /// The process that owns the socket.
    pub pid: u32,
    /// The local address, IPv4-mapped for IPv4, and port.
    pub local_addr: [u8; 16],
    /// The local port.
    pub local_port: u16,
    /// The remote address, IPv4-mapped for IPv4.
    pub remote_addr: [u8; 16],
    /// The remote port.
    pub remote_port: u16,
}

impl TestFlow {
    /// The encoded length.
    pub const LEN: usize = 56;

    /// The payload: the kind (`u8`: 1 start, 2 end), outbound (`u8`), the protocol (`u8`), a
    /// zero byte, the pid (`u32`), the id (`u64`), the local and remote ports (`u16` each), four
    /// zero bytes, then the local and remote addresses.
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut b = [0; Self::LEN];
        b[0] = if self.end { 2 } else { 1 };
        b[1] = u8::from(self.outbound);
        b[2] = self.protocol;
        b[4..8].copy_from_slice(&self.pid.to_le_bytes());
        b[8..16].copy_from_slice(&self.id.to_le_bytes());
        b[16..18].copy_from_slice(&self.local_port.to_le_bytes());
        b[18..20].copy_from_slice(&self.remote_port.to_le_bytes());
        b[24..40].copy_from_slice(&self.local_addr);
        b[40..56].copy_from_slice(&self.remote_addr);
        b
    }

    /// The flow in a `TestFlow` payload.
    pub fn decode(b: &[u8]) -> Result<TestFlow, Malformed> {
        let mut r = Reader { b };
        let end = match r.u8()? {
            1 => false,
            2 => true,
            _ => return Err(Malformed::Value),
        };
        let outbound = r.u8()?;
        let protocol = r.u8()?;
        r.take(1)?;
        let pid = r.u32()?;
        let id = r.u64()?;
        let (local_port, remote_port) = (r.u16()?, r.u16()?);
        r.take(4)?;
        let mut local_addr = [0; 16];
        local_addr.copy_from_slice(r.take(16)?);
        let mut remote_addr = [0; 16];
        remote_addr.copy_from_slice(r.take(16)?);
        if outbound > 1 || !r.b.is_empty() {
            return Err(Malformed::Value);
        }
        Ok(TestFlow {
            end,
            id,
            outbound: outbound == 1,
            protocol,
            pid,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
        })
    }
}
