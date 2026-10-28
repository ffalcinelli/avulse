//! From a ring buffer record to a packet and its [`Address`], with the reinjection context.

use avulse_ebpf::abi::Record;
use avulse_ebpf::facts::{
    F_IPV6, M_IMPOSTOR, M_LOOPBACK, M_OUTBOUND, M_SNIFFED, M_VLAN, M_VLAN_AD,
};
use avulse_filter::{Event, Layer};
use avulse_proto::{Link, checksum};

use crate::{Address, CONTEXT_LEN, Context};

/// A packet waiting in a handle's queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub addr: Address,
    /// From the IP header at the NETWORK layers, from the Ethernet header at ETHERNET.
    pub data: Vec<u8>,
}

/// The reinjection context of the Linux backend, in the address's 64 bytes:
///
/// | Offset | Size | |
/// | --- | --- | --- |
/// | 0 | 1 | [`Ctx::MAGIC`]: the backend and version of the layout |
/// | 1 | 1 | length of the link-layer header |
/// | 2 | 2 | GSO segment size, 0 if not GSO |
/// | 4 | 4 | the interface it was captured on |
/// | 8 | 2 | GSO segment count |
/// | 10 | 2 | 0 |
/// | 12 | 30 | the link-layer header the NETWORK layers strip (Ethernet and up to 4 VLAN tags) |
///
/// The numbers are in the host's byte order: a context only goes back to the host it came from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ctx {
    pub ifindex: u32,
    pub gso_size: u16,
    pub gso_segs: u16,
    l2_len: u8,
    l2: [u8; Ctx::L2_MAX],
}

// The WinDivert-compatible library keeps the first 56 bytes of a context (`Context`).
const _: () = assert!(Ctx::L2_AT + Ctx::L2_MAX <= 56);

impl Ctx {
    const MAGIC: u8 = 0xa1;
    const L2_MAX: usize = 30;
    const L2_AT: usize = 12;

    /// The saved link-layer header (empty at the ETHERNET layer, whose packets carry theirs).
    pub fn l2(&self) -> &[u8] {
        &self.l2[..self.l2_len as usize]
    }

    pub fn encode(&self) -> Context {
        let mut b = [0u8; CONTEXT_LEN];
        b[0] = Self::MAGIC;
        b[1] = self.l2_len;
        b[2..4].copy_from_slice(&self.gso_size.to_ne_bytes());
        b[4..8].copy_from_slice(&self.ifindex.to_ne_bytes());
        b[8..10].copy_from_slice(&self.gso_segs.to_ne_bytes());
        b[Self::L2_AT..Self::L2_AT + Self::L2_MAX].copy_from_slice(&self.l2);
        Context::from_bytes(b)
    }

    /// The context of a captured packet; `None` for an empty one (a packet the application
    /// built), or one this backend did not make.
    pub fn decode(c: &Context) -> Option<Ctx> {
        let b = c.as_bytes();
        if b[0] != Self::MAGIC || b[1] as usize > Self::L2_MAX {
            return None;
        }
        let mut l2 = [0; Self::L2_MAX];
        l2.copy_from_slice(&b[Self::L2_AT..Self::L2_AT + Self::L2_MAX]);
        Some(Ctx {
            ifindex: u32::from_ne_bytes(b[4..8].try_into().unwrap()),
            gso_size: u16::from_ne_bytes([b[2], b[3]]),
            gso_segs: u16::from_ne_bytes([b[8], b[9]]),
            l2_len: b[1],
            l2,
        })
    }
}

fn is_vlan(ethertype: &[u8]) -> bool {
    matches!(ethertype, [0x81, 0x00] | [0x88, 0xa8] | [0x91, 0x00])
}

/// The packet of a record and its address, for a handle at `layer`; `None` if the record is
/// inconsistent.
///
/// A VLAN tag the device took off (offload, [`M_VLAN`]) goes back into the frame as it was on the
/// wire, with its TPID (0x88a8 with [`M_VLAN_AD`], else 0x8100): in the packet at the ETHERNET
/// layer, in the saved link-layer header at the NETWORK layers.
pub fn entry(rec: &Record<'_>, layer: Layer) -> Option<Entry> {
    let mut frame = rec.data.to_vec();
    let mut l3 = rec.l3 as usize;
    if rec.meta & M_VLAN != 0 && frame.len() >= 12 {
        let [hi, lo] = rec.vlan_tci.to_be_bytes();
        let tpid = if rec.meta & M_VLAN_AD != 0 {
            [0x88, 0xa8]
        } else {
            [0x81, 0x00]
        };
        frame.splice(12..12, [tpid[0], tpid[1], hi, lo]);
        l3 += 4;
    }
    let network = layer != Layer::Ethernet;
    let (l2, data) = if network {
        if l3 > frame.len() || l3 > Ctx::L2_MAX {
            return None;
        }
        let data = frame.split_off(l3);
        (frame, data)
    } else {
        (Vec::new(), frame)
    };
    // The outer tag, from the header the packet came with.
    let header = if network { &l2 } else { &data };
    let vlan_tci = match header.get(12..16) {
        Some(t) if is_vlan(&t[..2]) => Some(u16::from_be_bytes([t[2], t[3]])),
        _ => None,
    };

    let link = if network { Link::Ip } else { Link::Ethernet };
    let valid = checksum::verify(&data, link);
    let mut ctx = Ctx {
        ifindex: rec.ifindex,
        gso_size: rec.gso_size,
        gso_segs: rec.gso_segs,
        l2_len: l2.len() as u8,
        l2: [0; Ctx::L2_MAX],
    };
    ctx.l2[..l2.len()].copy_from_slice(&l2);

    let mut addr = Address::new(layer);
    addr.timestamp = rec.timestamp as i64;
    addr.event = Event::Packet;
    addr.outbound = rec.meta & M_OUTBOUND != 0;
    addr.loopback = rec.meta & M_LOOPBACK != 0;
    addr.impostor = rec.meta & M_IMPOSTOR != 0;
    addr.sniffed = rec.meta & M_SNIFFED != 0;
    addr.ipv6 = rec.flags as u32 & F_IPV6 != 0;
    addr.ip_checksum = valid.ipv4;
    addr.tcp_checksum = valid.tcp;
    addr.udp_checksum = valid.udp;
    addr.if_idx = rec.ifindex;
    addr.vlan = vlan_tci.is_some();
    addr.vlan_tci = vlan_tci.unwrap_or(0);
    addr.context = ctx.encode();
    Some(Entry { addr, data })
}

/// A hash of the packet's bytes (64-bit FNV-1a), for the `random*` fields of filters evaluated in
/// user space.
pub fn hash(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ b as u64).wrapping_mul(0x0100_0000_01b3)
    })
}
