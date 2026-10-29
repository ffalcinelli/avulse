//! The protocol between the user-mode backend and the Windows driver: the device, its IOCTL codes,
//! and the byte layout of each request.
//!
//! Every request is plain bytes in host (little-endian) order, encoded and decoded here, so that
//! the driver checks everything it reads from user mode the same way the backend writes it.
//!
//! | IOCTL | Input | Output |
//! | --- | --- | --- |
//! | [`OPEN`] | [`OpenRequest`] | nothing |
//! | [`RECV`] | nothing | [`Record`]s, back to back, at least one |
//! | [`SEND`] | [`Record`]s, back to back | how many were sent, `u32` |
//! | [`SHUTDOWN`] | how, `u32` (1 receive, 2 send, 3 both) | nothing |
//! | [`SET_PARAM`] | [`Param::index`], `u32`; value, `u64` | nothing |
//! | [`GET_PARAM`] | [`Param::index`], `u32` | value, `u64` |
//! | [`STATS`] | nothing | [`Stats`], eight `u64`s |
//! | [`EVAL`] | one [`Record`] | 1 if the handle's filter matches it, else 0, `u32` |
//!
//! A handle is a file object of the device: `OPEN` once after creating it, then the others. Closing
//! the file (or the process exiting) closes the handle.

extern crate alloc;

use alloc::vec::Vec;

use avulse_filter::{Event, Layer};

use crate::{ADDRESS_VERSION, Address, CONTEXT_LEN, Context, Flags, Param, Stats, Syntax};

/// The control device, for `CreateFile`.
pub const DEVICE_PATH: &str = r"\\.\Avulse";
/// The version of this protocol, which [`OpenRequest`] carries. The driver refuses others.
pub const PROTOCOL_VERSION: u32 = 1;

/// `FILE_DEVICE_NETWORK`.
const DEVICE_TYPE: u32 = 0x12;
const METHOD_BUFFERED: u32 = 0;
const METHOD_OUT_DIRECT: u32 = 2;
/// `FILE_READ_DATA | FILE_WRITE_DATA`.
const ACCESS: u32 = 3;

/// `CTL_CODE(FILE_DEVICE_NETWORK, function, method, FILE_READ_DATA | FILE_WRITE_DATA)`.
const fn ctl_code(function: u32, method: u32) -> u32 {
    (DEVICE_TYPE << 16) | (ACCESS << 14) | (function << 2) | method
}

/// Opens the handle: [`OpenRequest`].
pub const OPEN: u32 = ctl_code(0x921, METHOD_BUFFERED);
/// Receives packets or events: completes when at least one is queued.
pub const RECV: u32 = ctl_code(0x922, METHOD_OUT_DIRECT);
/// Sends packets.
pub const SEND: u32 = ctl_code(0x923, METHOD_BUFFERED);
/// Shuts the handle down in one direction or both.
pub const SHUTDOWN: u32 = ctl_code(0x924, METHOD_BUFFERED);
/// Sets a queue parameter.
pub const SET_PARAM: u32 = ctl_code(0x925, METHOD_BUFFERED);
/// Reads a queue parameter.
pub const GET_PARAM: u32 = ctl_code(0x926, METHOD_BUFFERED);
/// Reads the handle's counters.
pub const STATS: u32 = ctl_code(0x927, METHOD_BUFFERED);
/// Runs the handle's filter on a packet and its address, in the kernel, as the packet hooks do:
/// what the tests compare with the evaluator. It changes nothing.
pub const EVAL: u32 = ctl_code(0x928, METHOD_BUFFERED);

/// Why bytes from the other side are refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed {
    /// Shorter than their header, or than the lengths it gives.
    Truncated,
    /// Another protocol version.
    Version,
    /// A value out of its range: an unknown layer, event, flag or syntax, or a `bool` that is
    /// neither 0 nor 1.
    Value,
}

/// Little-endian reads that fail instead of panicking.
struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        if self.b.len() < n {
            return Err(Malformed::Truncated);
        }
        let (head, tail) = self.b.split_at(n);
        self.b = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Malformed> {
        let mut a = [0; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }

    fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, Malformed> {
        self.array().map(u16::from_le_bytes)
    }

    fn u32(&mut self) -> Result<u32, Malformed> {
        self.array().map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Result<u64, Malformed> {
        self.array().map(u64::from_le_bytes)
    }

    fn bool(&mut self) -> Result<bool, Malformed> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Malformed::Value),
        }
    }
}

/// The size of an encoded [`Address`]: its `#[repr(C)]` size.
pub const ADDRESS_LEN: usize = 216;

/// The address as bytes, at the offsets of its `#[repr(C)]` layout.
pub fn encode_address(a: &Address) -> [u8; ADDRESS_LEN] {
    let mut b = [0u8; ADDRESS_LEN];
    let mut put = |at: usize, bytes: &[u8]| b[at..at + bytes.len()].copy_from_slice(bytes);
    put(0, &a.timestamp.to_le_bytes());
    put(8, &a.version.to_le_bytes());
    put(10, &[a.layer as u8, a.event as u8]);
    put(
        12,
        &[
            a.outbound.into(),
            a.loopback.into(),
            a.impostor.into(),
            a.sniffed.into(),
            a.ipv6.into(),
            a.ip_checksum.into(),
            a.tcp_checksum.into(),
            a.udp_checksum.into(),
        ],
    );
    put(20, &a.if_idx.to_le_bytes());
    put(24, &a.sub_if_idx.to_le_bytes());
    put(28, &a.vlan_tci.to_le_bytes());
    put(30, &[a.vlan.into()]);
    let f = &a.flow;
    put(32, &f.endpoint_id.to_le_bytes());
    put(40, &f.parent_endpoint_id.to_le_bytes());
    put(48, &f.process_id.to_le_bytes());
    put(52, &f.local_port.to_le_bytes());
    put(54, &f.remote_port.to_le_bytes());
    put(56, &f.local_addr);
    put(72, &f.remote_addr);
    put(88, &[f.protocol]);
    put(96, &f.process_name);
    let r = &a.reflect;
    put(128, &r.timestamp.to_le_bytes());
    put(136, &r.flags.bits().to_le_bytes());
    put(144, &r.process_id.to_le_bytes());
    put(148, &r.priority.to_le_bytes());
    put(150, &[r.layer as u8, r.syntax as u8]);
    put(152, a.context.as_bytes());
    b
}

/// The address the bytes encode, checked: each enum, flag word and `bool` must be valid, and the
/// version must be [`ADDRESS_VERSION`].
pub fn decode_address(b: &[u8]) -> Result<Address, Malformed> {
    let mut r = Reader { b };
    let timestamp = r.u64()? as i64;
    if r.u16()? != ADDRESS_VERSION {
        return Err(Malformed::Version);
    }
    let layer = Layer::try_from(r.u8()?).map_err(|_| Malformed::Value)?;
    let mut a = Address::new(layer);
    a.timestamp = timestamp;
    a.event = Event::try_from(r.u8()?).map_err(|_| Malformed::Value)?;
    a.outbound = r.bool()?;
    a.loopback = r.bool()?;
    a.impostor = r.bool()?;
    a.sniffed = r.bool()?;
    a.ipv6 = r.bool()?;
    a.ip_checksum = r.bool()?;
    a.tcp_checksum = r.bool()?;
    a.udp_checksum = r.bool()?;
    a.if_idx = r.u32()?;
    a.sub_if_idx = r.u32()?;
    a.vlan_tci = r.u16()?;
    a.vlan = r.bool()?;
    r.take(1)?;
    let f = &mut a.flow;
    f.endpoint_id = r.u64()?;
    f.parent_endpoint_id = r.u64()?;
    f.process_id = r.u32()?;
    f.local_port = r.u16()?;
    f.remote_port = r.u16()?;
    f.local_addr = r.array()?;
    f.remote_addr = r.array()?;
    f.protocol = r.u8()?;
    r.take(7)?;
    f.process_name = r.array()?;
    let rf = &mut a.reflect;
    rf.timestamp = r.u64()? as i64;
    rf.flags = Flags::from_bits(r.u64()?).ok_or(Malformed::Value)?;
    rf.process_id = r.u32()?;
    rf.priority = r.u16()? as i16;
    rf.layer = Layer::try_from(r.u8()?).map_err(|_| Malformed::Value)?;
    rf.syntax = Syntax::try_from(r.u8()?).map_err(|_| Malformed::Value)?;
    a.context = Context::from_bytes(r.array::<CONTEXT_LEN>()?);
    Ok(a)
}

/// What [`OPEN`] carries: the handle's layer, priority and flags, the filter compiled to bytecode
/// (which the driver verifies), the interfaces to capture on, and the filter's text and syntax
/// (for REFLECT).
///
/// The layout is a 32-byte header (version `u32`, layer `u8`, syntax `u8`, two zero bytes, flags
/// `u64`, priority `i16`, interface count `u16`, program length `u32`, filter length `u32`, four
/// zero bytes), then the interface indexes (`u32` each), the program and the filter text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenRequest<'a> {
    /// The layer.
    pub layer: Layer,
    /// The priority, -30000 to 30000.
    pub priority: i16,
    /// The flags.
    pub flags: Flags,
    /// The filter's bytecode (`avulse_filter::Filter::program`).
    pub program: &'a [u8],
    /// The interface indexes to capture on; empty for all of them.
    pub interfaces: Vec<u32>,
    /// The filter as written.
    pub filter: &'a str,
    /// Its language.
    pub syntax: Syntax,
}

const OPEN_HEADER: usize = 32;

impl<'a> OpenRequest<'a> {
    /// The request's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(
            OPEN_HEADER + 4 * self.interfaces.len() + self.program.len() + self.filter.len(),
        );
        b.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        b.extend_from_slice(&[self.layer as u8, self.syntax as u8, 0, 0]);
        b.extend_from_slice(&self.flags.bits().to_le_bytes());
        b.extend_from_slice(&self.priority.to_le_bytes());
        b.extend_from_slice(&(self.interfaces.len() as u16).to_le_bytes());
        b.extend_from_slice(&(self.program.len() as u32).to_le_bytes());
        b.extend_from_slice(&(self.filter.len() as u32).to_le_bytes());
        b.extend_from_slice(&[0; 4]);
        for i in &self.interfaces {
            b.extend_from_slice(&i.to_le_bytes());
        }
        b.extend_from_slice(self.program);
        b.extend_from_slice(self.filter.as_bytes());
        b
    }

    /// The request in `b`, checked. The program still has to be verified.
    pub fn decode(b: &'a [u8]) -> Result<Self, Malformed> {
        let mut r = Reader { b };
        if r.u32()? != PROTOCOL_VERSION {
            return Err(Malformed::Version);
        }
        let layer = Layer::try_from(r.u8()?).map_err(|_| Malformed::Value)?;
        let syntax = Syntax::try_from(r.u8()?).map_err(|_| Malformed::Value)?;
        r.take(2)?;
        let flags = Flags::from_bits(r.u64()?).ok_or(Malformed::Value)?;
        let priority = r.u16()? as i16;
        let count = usize::from(r.u16()?);
        let (program_len, filter_len) = (r.u32()? as usize, r.u32()? as usize);
        r.take(4)?;
        let interfaces = (0..count).map(|_| r.u32()).collect::<Result<_, _>>()?;
        let program = r.take(program_len)?;
        let filter = core::str::from_utf8(r.take(filter_len)?).map_err(|_| Malformed::Value)?;
        if !r.b.is_empty() {
            return Err(Malformed::Value);
        }
        Ok(OpenRequest {
            layer,
            priority,
            flags,
            program,
            interfaces,
            filter,
            syntax,
        })
    }
}

/// A packet or event, as [`RECV`] returns them and [`SEND`] takes them: its encoded [`Address`],
/// the data's length (`u32`), four zero bytes, then the data, padded with zeros to a multiple of 8
/// bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    /// The address.
    pub addr: Address,
    /// The packet, or an event's data.
    pub data: &'a [u8],
}

const RECORD_HEADER: usize = ADDRESS_LEN + 8;

impl<'a> Record<'a> {
    /// How many bytes the record takes.
    pub fn encoded_len(data_len: usize) -> usize {
        RECORD_HEADER + data_len.next_multiple_of(8)
    }

    /// Appends the record to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&encode_address(&self.addr));
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(self.data);
        let pad = self.data.len().next_multiple_of(8) - self.data.len();
        out.extend_from_slice(&[0; 8][..pad]);
    }

    /// The records in `b`, in order. Iteration stops at the first malformed one, which it yields
    /// as an error.
    pub fn decode_all(b: &'a [u8]) -> Records<'a> {
        Records { r: Reader { b } }
    }
}

/// The records of a buffer ([`Record::decode_all`]).
#[derive(Debug)]
pub struct Records<'a> {
    r: Reader<'a>,
}

impl core::fmt::Debug for Reader<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} bytes", self.b.len())
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = Result<Record<'a>, Malformed>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.r.b.is_empty() {
            return None;
        }
        let record = (|| {
            let addr = decode_address(self.r.take(ADDRESS_LEN)?)?;
            let len = self.r.u32()? as usize;
            self.r.take(4)?;
            let data = self.r.take(len)?;
            self.r.take(len.next_multiple_of(8) - len)?;
            Ok(Record { addr, data })
        })();
        if record.is_err() {
            self.r.b = &[];
        }
        Some(record)
    }
}

/// What the driver keeps in [`Address::context`] for a frame it captured at the ETHERNET layer,
/// so that sending it back restores what the network card was to do with it: put a VLAN tag back
/// into the out-of-band information, or segment a large send (LSO).
///
/// The layout is a marker byte ([`EthernetContext::MARKER`]), the flags, two zero bytes, the
/// interface index (`u32`) and the LSO MSS (`u32`); the rest of the context is zero. It applies
/// only when the frame goes back on the interface it was captured on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EthernetContext {
    /// The interface the frame was captured on.
    pub if_idx: u32,
    /// [`EthernetContext::VLAN_OFFLOADED`], [`EthernetContext::LSO_V1`],
    /// [`EthernetContext::LSO_V2`].
    pub flags: u8,
    /// The segment size of a large send (with `LSO_V1` or `LSO_V2`).
    pub lso_mss: u32,
}

impl EthernetContext {
    /// The first byte of an encoded context, so that an empty one decodes as none.
    pub const MARKER: u8 = 0xe7;
    /// The outer VLAN tag (802.1Q) came out of band: the driver put it into the frame.
    pub const VLAN_OFFLOADED: u8 = 1;
    /// The frame is a large send, version 1.
    pub const LSO_V1: u8 = 2;
    /// The frame is a large send, version 2.
    pub const LSO_V2: u8 = 4;
    const ALL: u8 = Self::VLAN_OFFLOADED | Self::LSO_V1 | Self::LSO_V2;

    /// The context's bytes.
    pub fn encode(&self) -> Context {
        let mut b = [0; CONTEXT_LEN];
        b[0] = Self::MARKER;
        b[1] = self.flags;
        b[4..8].copy_from_slice(&self.if_idx.to_le_bytes());
        b[8..12].copy_from_slice(&self.lso_mss.to_le_bytes());
        Context::from_bytes(b)
    }

    /// The ETHERNET context in `c`, if it holds one (any other bytes are `None`).
    pub fn decode(c: &Context) -> Option<EthernetContext> {
        let b = c.as_bytes();
        if b[0] != Self::MARKER || b[1] & !Self::ALL != 0 || b[2..4] != [0, 0] {
            return None;
        }
        if b[12..].iter().any(|&x| x != 0) {
            return None;
        }
        Some(EthernetContext {
            flags: b[1],
            if_idx: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            lso_mss: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
        })
    }

    /// Whether the frame is a large send.
    pub fn lso(&self) -> bool {
        self.flags & (Self::LSO_V1 | Self::LSO_V2) != 0
    }
}

/// [`SET_PARAM`]'s input.
pub fn encode_set_param(p: Param, value: u64) -> [u8; 12] {
    let mut b = [0; 12];
    b[..4].copy_from_slice(&(p.index() as u32).to_le_bytes());
    b[4..].copy_from_slice(&value.to_le_bytes());
    b
}

/// The parameter of a [`SET_PARAM`] or [`GET_PARAM`] input, and the value for `SET_PARAM`.
/// The value's range is the caller's to check ([`Param::range`]).
pub fn decode_param(b: &[u8]) -> Result<(Param, Option<u64>), Malformed> {
    let mut r = Reader { b };
    let p = *Param::ALL.get(r.u32()? as usize).ok_or(Malformed::Value)?;
    let value = if r.b.is_empty() { None } else { Some(r.u64()?) };
    Ok((p, value))
}

/// [`STATS`]'s output.
pub fn encode_stats(s: &Stats) -> [u8; 64] {
    let mut b = [0; 64];
    let values = [
        s.diverted,
        s.sniffed,
        s.dropped,
        s.ring_full,
        s.owner_gone,
        s.too_big,
        s.load_errors,
        s.queue_drops,
    ];
    for (i, v) in values.iter().enumerate() {
        b[8 * i..8 * i + 8].copy_from_slice(&v.to_le_bytes());
    }
    b
}

/// The counters in [`STATS`]'s output.
pub fn decode_stats(b: &[u8]) -> Result<Stats, Malformed> {
    let mut r = Reader { b };
    let mut s = Stats::default();
    for v in [
        &mut s.diverted,
        &mut s.sniffed,
        &mut s.dropped,
        &mut s.ring_full,
        &mut s.owner_gone,
        &mut s.too_big,
        &mut s.load_errors,
        &mut s.queue_drops,
    ] {
        *v = r.u64()?;
    }
    Ok(s)
}
