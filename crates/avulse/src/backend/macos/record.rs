//! From what a bpf device reads to packets and their [`Address`]es, with the reinjection
//! context.

use avulse_filter::{Event, Layer};
use avulse_proto::{Link, Packet, checksum};

use super::sys::{DLT_EN10MB, DLT_NULL};
pub use crate::backend::queue::Entry;
use crate::{Address, CONTEXT_LEN, Context};

/// The length of `struct bpf_hdr` with its 32-bit `timeval`. `bh_hdrlen` may be larger: bpf
/// pads it so that the network header is aligned.
const HDR_LEN: usize = 18;

/// One record of a bpf read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Nanoseconds since the Unix epoch.
    pub wall_ns: i64,
    /// Whether the packet was cut short (`caplen < datalen`).
    pub truncated: bool,
    pub data: &'a [u8],
}

/// The records of one read, in order; it stops at the first inconsistent one.
pub fn frames(mut b: &[u8]) -> impl Iterator<Item = Frame<'_>> {
    std::iter::from_fn(move || {
        let u32_at = |b: &[u8], o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        if b.len() < HDR_LEN {
            return None;
        }
        let sec = u32_at(b, 0);
        let usec = u32_at(b, 4);
        let caplen = u32_at(b, 8) as usize;
        let datalen = u32_at(b, 12) as usize;
        let hdrlen = usize::from(u16::from_ne_bytes([b[16], b[17]]));
        if hdrlen < HDR_LEN || hdrlen.checked_add(caplen)? > b.len() {
            b = &[];
            return None;
        }
        let frame = Frame {
            wall_ns: i64::from(sec) * 1_000_000_000 + i64::from(usec) * 1000,
            truncated: caplen < datalen,
            data: &b[hdrlen..hdrlen + caplen],
        };
        // Records are aligned to 4 bytes (`BPF_WORDALIGN`).
        let next = (hdrlen + caplen).div_ceil(4) * 4;
        b = b.get(next..).unwrap_or(&[]);
        Some(frame)
    })
}

/// The interface a bpf device is bound to: what records need to become addresses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Source {
    /// The direction the device captures (`BIOCSDIRECTION`): `Some(true)` outbound only,
    /// `Some(false)` inbound only, `None` both, where the ioctl is missing.
    pub outbound: Option<bool>,
    pub ifindex: u32,
    pub dlt: u32,
    pub loopback: bool,
    pub mac: Option<[u8; 6]>,
    pub addrs: Vec<std::net::IpAddr>,
}

impl Source {
    /// Whether a packet is outbound: the device's direction if it has one. Otherwise, on
    /// Ethernet, the packet comes from the interface's own address; on other links (`utun`),
    /// from one of its IP addresses. On a loopback interface, every packet is outbound, as on
    /// Windows.
    fn is_outbound(&self, frame: &[u8], ip: Option<&[u8]>) -> bool {
        if let Some(out) = self.outbound {
            return out;
        }
        if self.loopback {
            return true;
        }
        if self.dlt == DLT_EN10MB {
            return self.mac.is_some_and(|m| frame.get(6..12) == Some(&m[..]));
        }
        let src = ip.and_then(|ip| match ip.first()? >> 4 {
            4 => Some(std::net::IpAddr::from(
                <[u8; 4]>::try_from(ip.get(12..16)?).ok()?,
            )),
            6 => Some(std::net::IpAddr::from(
                <[u8; 16]>::try_from(ip.get(8..24)?).ok()?,
            )),
            _ => None,
        });
        src.is_some_and(|s| self.addrs.contains(&s))
    }
}

/// The reinjection context of the macOS backend, in the address's 64 bytes:
///
/// | Offset | Size | |
/// | --- | --- | --- |
/// | 0 | 1 | [`Ctx::MAGIC`]: the backend and version of the layout |
/// | 1 | 1 | length of the link-layer header |
/// | 4 | 4 | the interface it was captured on |
/// | 8 | 22 | the Ethernet header the NETWORK layers strip, with up to 2 VLAN tags |
///
/// The numbers are in the host's byte order: a context only goes back to the host it came from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ctx {
    pub ifindex: u32,
    l2_len: u8,
    l2: [u8; Ctx::L2_MAX],
}

// The WinDivert-compatible library keeps the first 56 bytes of a context.
const _: () = assert!(Ctx::L2_AT + Ctx::L2_MAX <= 56);

impl Ctx {
    const MAGIC: u8 = 0xc1;
    const L2_MAX: usize = 22;
    const L2_AT: usize = 8;

    /// The saved link-layer header (empty at the ETHERNET layer, and on links without one).
    pub fn l2(&self) -> &[u8] {
        &self.l2[..self.l2_len as usize]
    }

    pub fn encode(&self) -> Context {
        let mut b = [0u8; CONTEXT_LEN];
        b[0] = Self::MAGIC;
        b[1] = self.l2_len;
        b[4..8].copy_from_slice(&self.ifindex.to_ne_bytes());
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
            ifindex: u32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
            l2_len: b[1],
            l2,
        })
    }
}

/// The packet of a frame and its address, for a handle at `layer`; `None` if the frame does
/// not suit the layer (no IP packet at the NETWORK layer, a truncated capture). `mono_offset`
/// turns the wall-clock timestamp into the monotonic clock's.
pub fn entry(f: &Frame<'_>, src: &Source, layer: Layer, mono_offset: i64) -> Option<Entry> {
    if f.truncated {
        return None;
    }
    let (l3, link) = match src.dlt {
        DLT_EN10MB => {
            let p = Packet::parse(f.data, Link::Ethernet);
            let l3 = p
                .l3_offset()
                .filter(|_| p.ipv4().is_some() || p.ipv6().is_some());
            (l3, Link::Ethernet)
        }
        DLT_NULL if layer != Layer::Ethernet => {
            let ip = f.data.get(4..)?;
            let v = ip.first()? >> 4;
            ((v == 4 || v == 6).then_some(4), Link::Ip)
        }
        _ => return None,
    };
    let ip = l3.and_then(|at| f.data.get(at..));
    let network = layer != Layer::Ethernet;
    let (l2, data) = if network {
        let at = l3?;
        let l2 = if link == Link::Ethernet {
            &f.data[..at]
        } else {
            &[][..]
        };
        if l2.len() > Ctx::L2_MAX {
            return None;
        }
        (l2, &f.data[at..])
    } else {
        (&[][..], f.data)
    };
    let header = if network { l2 } else { data };
    let vlan_tci = match header.get(12..16) {
        Some(t) if matches!(t[..2], [0x81, 0x00] | [0x88, 0xa8] | [0x91, 0x00]) => {
            Some(u16::from_be_bytes([t[2], t[3]]))
        }
        _ => None,
    };
    let valid = checksum::verify(data, if network { Link::Ip } else { Link::Ethernet });
    let mut ctx = Ctx {
        ifindex: src.ifindex,
        l2_len: l2.len() as u8,
        l2: [0; Ctx::L2_MAX],
    };
    ctx.l2[..l2.len()].copy_from_slice(l2);

    let mut addr = Address::new(layer);
    addr.timestamp = f.wall_ns.saturating_add(mono_offset);
    addr.event = Event::Packet;
    addr.outbound = src.is_outbound(f.data, ip);
    addr.loopback = src.loopback;
    // Without the system extension, every handle gets a copy.
    addr.sniffed = true;
    addr.ipv6 = ip.and_then(|ip| ip.first()).is_some_and(|v| v >> 4 == 6);
    addr.ip_checksum = valid.ipv4;
    addr.tcp_checksum = valid.tcp;
    addr.udp_checksum = valid.udp;
    addr.if_idx = src.ifindex;
    addr.vlan = vlan_tci.is_some();
    addr.vlan_tci = vlan_tci.unwrap_or(0);
    addr.context = ctx.encode();
    Some(Entry {
        addr,
        data: data.to_vec(),
    })
}

/// A hash of the packet's bytes (64-bit FNV-1a), for the `random*` fields of filters.
pub fn hash(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ b as u64).wrapping_mul(0x0100_0000_01b3)
    })
}
