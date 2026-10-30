//! `WINDIVERT_ADDRESS`, WinDivert 2.2's 80-byte address (`struct ebpfdivert_address` on Linux),
//! and its conversion to and from [`Address`]. The WinDivert shim (`avulse-windivert-compat`)
//! uses it in user space, and the Windows driver to answer WinDivert's own receive request.

use avulse_filter::{Event, Layer};

use crate::{Address, CONTEXT_LEN, Context, Flags};

/// How much of avulse's reinjection [`Context`] fits in the union at the NETWORK layers, after
/// `IfIdx` and `SubIfIdx`. Backends keep their context within it.
pub const CONTEXT_KEPT: usize = 56;

/// `WINDIVERT_ADDRESS`: a timestamp, a word of bitfields and a 64-byte union of the layer's data.
///
/// The bitfields are, from the least significant bit: `Layer` (8 bits), `Event` (8), `Sniffed`,
/// `Outbound`, `Loopback`, `Impostor`, `IPv6`, `IPChecksum`, `TCPChecksum`, `UDPChecksum`. The
/// union holds, by layer:
///
/// | Layer | Data |
/// | --- | --- |
/// | NETWORK, NETWORK_FORWARD | `IfIdx` (0), `SubIfIdx` (4); avulse keeps its reinjection context in bytes 8 to 63 |
/// | FLOW, SOCKET | `EndpointId` (0), `ParentEndpointId` (8), `ProcessId` (16), `LocalAddr` (20), `RemoteAddr` (36), `LocalPort` (52), `RemotePort` (54), `Protocol` (56) |
/// | REFLECT | `Timestamp` (0), `ProcessId` (8), `Layer` (12), `Flags` (16), `Priority` (24) |
///
/// Addresses are four 32-bit words with the least significant first, each in host order, and
/// IPv4 addresses are mapped (`::ffff:a.b.c.d`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WdAddress {
    /// `Timestamp`.
    pub timestamp: i64,
    /// The bitfields.
    pub bits: u32,
    /// `Reserved2`.
    pub reserved: u32,
    /// The layer's data.
    pub data: [u8; 64],
}

const _: () = assert!(core::mem::size_of::<WdAddress>() == 80);

const SNIFFED: u32 = 1 << 16;
const OUTBOUND: u32 = 1 << 17;
const LOOPBACK: u32 = 1 << 18;
const IMPOSTOR: u32 = 1 << 19;
const IPV6: u32 = 1 << 20;
const IP_CHECKSUM: u32 = 1 << 21;
const TCP_CHECKSUM: u32 = 1 << 22;
const UDP_CHECKSUM: u32 = 1 << 23;

/// Why a `WINDIVERT_ADDRESS` cannot become an [`Address`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadAddress(pub &'static str);

impl Default for WdAddress {
    fn default() -> Self {
        WdAddress {
            timestamp: 0,
            bits: 0,
            reserved: 0,
            data: [0; 64],
        }
    }
}

impl WdAddress {
    /// The address's bytes, as `#[repr(C)]` lays them out on a little-endian machine (every
    /// Windows target): what WinDivert's callers read.
    pub fn to_bytes(&self) -> [u8; 80] {
        let mut b = [0; 80];
        b[..8].copy_from_slice(&self.timestamp.to_le_bytes());
        b[8..12].copy_from_slice(&self.bits.to_le_bytes());
        b[12..16].copy_from_slice(&self.reserved.to_le_bytes());
        b[16..].copy_from_slice(&self.data);
        b
    }

    /// The `Layer` bitfield.
    pub fn layer(&self) -> u8 {
        self.bits as u8
    }

    /// The `Event` bitfield.
    pub fn event(&self) -> u8 {
        (self.bits >> 8) as u8
    }

    fn bit(&self, b: u32) -> bool {
        self.bits & b != 0
    }

    /// Sets the bits of the checksums that are known to be right, as WinDivert's
    /// `WinDivertHelperCalcChecksums` does for those it computed.
    pub fn set_checksums(&mut self, ip: bool, tcp: bool, udp: bool) {
        for (on, b) in [(ip, IP_CHECKSUM), (tcp, TCP_CHECKSUM), (udp, UDP_CHECKSUM)] {
            if on {
                self.bits |= b;
            }
        }
    }

    fn get<const N: usize>(&self, at: usize) -> [u8; N] {
        let mut b = [0; N];
        b.copy_from_slice(&self.data[at..at + N]);
        b
    }

    fn put(&mut self, at: usize, bytes: &[u8]) {
        self.data[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn get_addr(&self, at: usize) -> [u8; 16] {
        let mut v = 0u128;
        for i in 0..4 {
            let w = u32::from_ne_bytes(self.get(at + 4 * i));
            v |= u128::from(w) << (32 * i);
        }
        v.to_be_bytes()
    }

    fn put_addr(&mut self, at: usize, addr: &[u8; 16]) {
        let v = u128::from_be_bytes(*addr);
        for i in 0..4 {
            self.put(at + 4 * i, &((v >> (32 * i)) as u32).to_ne_bytes());
        }
    }

    /// The avulse address. The union is read by the address's layer. At the NETWORK layers,
    /// bytes 8 to 63 become the first [`CONTEXT_KEPT`] bytes of the reinjection context.
    ///
    /// # Errors
    ///
    /// An unknown layer or event, a layer WinDivert does not have (ETHERNET), or unknown flags
    /// at REFLECT.
    pub fn to_avulse(&self) -> Result<Address, BadAddress> {
        let layer = match Layer::try_from(self.layer()) {
            Ok(Layer::Ethernet) | Err(_) => return Err(BadAddress("unknown layer")),
            Ok(l) => l,
        };
        let mut a = Address::new(layer);
        a.timestamp = self.timestamp;
        a.event = Event::try_from(self.event()).map_err(|_| BadAddress("unknown event"))?;
        a.sniffed = self.bit(SNIFFED);
        a.outbound = self.bit(OUTBOUND);
        a.loopback = self.bit(LOOPBACK);
        a.impostor = self.bit(IMPOSTOR);
        a.ipv6 = self.bit(IPV6);
        a.ip_checksum = self.bit(IP_CHECKSUM);
        a.tcp_checksum = self.bit(TCP_CHECKSUM);
        a.udp_checksum = self.bit(UDP_CHECKSUM);
        match layer {
            Layer::Network | Layer::NetworkForward | Layer::Ethernet => {
                a.if_idx = u32::from_ne_bytes(self.get(0));
                a.sub_if_idx = u32::from_ne_bytes(self.get(4));
                let mut c = [0; CONTEXT_LEN];
                c[..CONTEXT_KEPT].copy_from_slice(&self.data[8..]);
                a.context = Context::from_bytes(c);
            }
            Layer::Flow | Layer::Socket => {
                let f = &mut a.flow;
                f.endpoint_id = u64::from_ne_bytes(self.get(0));
                f.parent_endpoint_id = u64::from_ne_bytes(self.get(8));
                f.process_id = u32::from_ne_bytes(self.get(16));
                f.local_addr = self.get_addr(20);
                f.remote_addr = self.get_addr(36);
                f.local_port = u16::from_ne_bytes(self.get(52));
                f.remote_port = u16::from_ne_bytes(self.get(54));
                f.protocol = self.data[56];
            }
            Layer::Reflect => {
                let r = &mut a.reflect;
                r.timestamp = i64::from_ne_bytes(self.get(0));
                r.process_id = u32::from_ne_bytes(self.get(8));
                r.layer = u8::try_from(u32::from_ne_bytes(self.get(12)))
                    .ok()
                    .and_then(|l| Layer::try_from(l).ok())
                    .ok_or(BadAddress("unknown layer in the reflect data"))?;
                r.flags = Flags::from_bits(u64::from_ne_bytes(self.get(16)))
                    .ok_or(BadAddress("unknown flags in the reflect data"))?;
                r.priority = i16::from_ne_bytes(self.get(24));
            }
        }
        Ok(a)
    }

    /// The WinDivert address of `a`. What WinDivert has no room for is left out: the VLAN tag,
    /// the process name, and the end of the reinjection context past [`CONTEXT_KEPT`] bytes,
    /// which backends leave empty.
    pub fn from_avulse(a: &Address) -> WdAddress {
        let flag = |on: bool, b: u32| if on { b } else { 0 };
        let mut w = WdAddress {
            timestamp: a.timestamp,
            bits: u32::from(a.layer as u8)
                | u32::from(a.event as u8) << 8
                | flag(a.sniffed, SNIFFED)
                | flag(a.outbound, OUTBOUND)
                | flag(a.loopback, LOOPBACK)
                | flag(a.impostor, IMPOSTOR)
                | flag(a.ipv6, IPV6)
                | flag(a.ip_checksum, IP_CHECKSUM)
                | flag(a.tcp_checksum, TCP_CHECKSUM)
                | flag(a.udp_checksum, UDP_CHECKSUM),
            ..WdAddress::default()
        };
        match a.layer {
            Layer::Network | Layer::NetworkForward | Layer::Ethernet => {
                w.put(0, &a.if_idx.to_ne_bytes());
                w.put(4, &a.sub_if_idx.to_ne_bytes());
                let c = a.context.as_bytes();
                debug_assert!(
                    c[CONTEXT_KEPT..].iter().all(|&b| b == 0),
                    "a backend's context is longer than {CONTEXT_KEPT} bytes"
                );
                w.put(8, &c[..CONTEXT_KEPT]);
            }
            Layer::Flow | Layer::Socket => {
                let f = &a.flow;
                w.put(0, &f.endpoint_id.to_ne_bytes());
                w.put(8, &f.parent_endpoint_id.to_ne_bytes());
                w.put(16, &f.process_id.to_ne_bytes());
                w.put_addr(20, &f.local_addr);
                w.put_addr(36, &f.remote_addr);
                w.put(52, &f.local_port.to_ne_bytes());
                w.put(54, &f.remote_port.to_ne_bytes());
                w.data[56] = f.protocol;
            }
            Layer::Reflect => {
                let r = &a.reflect;
                w.put(0, &r.timestamp.to_ne_bytes());
                w.put(8, &r.process_id.to_ne_bytes());
                w.put(12, &u32::from(r.layer as u8).to_ne_bytes());
                w.put(16, &r.flags.bits().to_ne_bytes());
                w.put(24, &r.priority.to_ne_bytes());
            }
        }
        w
    }
}
