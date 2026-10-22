//! Sending packets back into the network stack, by ebpfdivert's paths:
//!
//! | Packet | Path |
//! | --- | --- |
//! | Loopback | A raw IP socket: routed, so that 127/8 and `::1` are not dropped as martians. |
//! | Outbound or forwarded, with its context | `AF_PACKET` out of the interface it was captured on, behind the saved link-layer header (none on devices without one: tun, WireGuard, IP tunnels). |
//! | Outbound, without a context | A raw IP socket: routed like any local packet. |
//! | Inbound | `AF_PACKET` on `lo`, marked `MARK_REDIRECT \| ifindex`: `lo`'s ingress program redirects it to the interface's ingress. |
//! | ETHERNET | The frame, through `AF_PACKET`: out of the interface, or through `lo` when inbound. |
//!
//! Every packet carries the handle's mark, `MARK_INJECTED | tc_priority`, so that the handle and
//! the ones before it skip it. A packet larger than the device's MTU goes out as a GSO packet,
//! described by a `virtio_net_hdr`, which the kernel segments.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use avulse_ebpf::{abi, loader};
use avulse_filter::Layer;
use avulse_proto::checksum::{self, Updated};
use avulse_proto::{Link, Packet, Transport};

use super::record::Ctx;
use super::{lock, sys};
use crate::{Address, Error, Result};

const ETH_LEN: usize = 14;
/// `struct virtio_net_hdr`.
const VNET_LEN: usize = 10;
const VNET_F_NEEDS_CSUM: u8 = 1;
const VNET_GSO_TCPV4: u8 = 1;
const VNET_GSO_TCPV6: u8 = 4;
const VNET_GSO_UDP_L4: u8 = 5;
/// How long an interface's MTU is trusted.
const MTU_TTL: Duration = Duration::from_secs(1);

/// The way a packet goes back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Path {
    /// A raw IP socket.
    Raw,
    /// `AF_PACKET` out of `ifindex`, behind `l2` (empty at ETHERNET, whose frames carry theirs).
    Out { ifindex: u32, l2: Vec<u8> },
    /// `AF_PACKET` on `lo`, redirected to the ingress of `ifindex`, behind `l2` (`None`: an
    /// Ethernet header to the interface's address).
    In { ifindex: u32, l2: Option<Vec<u8>> },
}

/// Where the IP header of `packet` starts, after checking that the packet suits the layer:
/// `None` for a frame that carries no IP packet (ETHERNET).
pub fn ip_offset(packet: &[u8], layer: Layer) -> Result<Option<usize>> {
    if layer == Layer::Ethernet {
        if packet.len() < ETH_LEN {
            return Err(Error::InvalidArgument(
                "the frame is shorter than an Ethernet header",
            ));
        }
        let p = Packet::parse(packet, Link::Ethernet);
        return Ok(p
            .l3_offset()
            .filter(|_| p.ipv4().is_some() || p.ipv6().is_some()));
    }
    match packet[0] >> 4 {
        4 if packet.len() >= 20 => Ok(Some(0)),
        6 if packet.len() >= 40 => Ok(Some(0)),
        _ => Err(Error::InvalidArgument("not an IPv4 or IPv6 packet")),
    }
}

/// The path of `packet` (checked by [`ip_offset`]), at `layer`, with `addr`.
pub fn path(layer: Layer, addr: &Address, packet: &[u8], lo: u32) -> Result<Path> {
    let ifindex = addr.if_idx;
    if layer == Layer::Ethernet {
        if ifindex == 0 {
            return Err(Error::InvalidArgument(
                "an ETHERNET packet needs its interface (if_idx)",
            ));
        }
        return Ok(if addr.outbound || addr.loopback || ifindex == lo {
            Path::Out {
                ifindex,
                l2: Vec::new(),
            }
        } else {
            Path::In {
                ifindex,
                l2: Some(Vec::new()),
            }
        });
    }
    if addr.loopback || ifindex == lo {
        return Ok(Path::Raw);
    }
    // The saved header applies on the interface it came from.
    let v6 = packet[0] >> 4 == 6;
    let ctx = Ctx::decode(&addr.context).filter(|c| c.ifindex == ifindex);
    let l2 = ctx
        .filter(|c| c.l2().len() >= ETH_LEN)
        .map(|c| link_header(c.l2(), v6));
    if addr.outbound || layer == Layer::NetworkForward {
        return Ok(match l2 {
            Some(l2) => Path::Out { ifindex, l2 },
            // Captured on a device without a link-layer header: out of it, as it is.
            None if ctx.is_some_and(|c| c.l2().is_empty()) => Path::Out {
                ifindex,
                l2: Vec::new(),
            },
            None => Path::Raw,
        });
    }
    if ifindex == 0 {
        // Inbound, to no interface: delivered locally if the destination is local.
        return Ok(Path::Raw);
    }
    Ok(Path::In { ifindex, l2 })
}

fn ethertype_ip(v6: bool) -> u16 {
    if v6 { 0x86dd } else { 0x0800 }
}

/// `l2` with its last EtherType (after the VLAN tags) set for the IP version.
fn link_header(l2: &[u8], v6: bool) -> Vec<u8> {
    let mut l2 = l2.to_vec();
    let n = l2.len();
    l2[n - 2..].copy_from_slice(&ethertype_ip(v6).to_be_bytes());
    l2
}

/// What WinDivert does to the packets an application sends with the impostor flag: decrement
/// the TTL (hop limit), so that two handles that reinject each other's packets cannot loop
/// forever. `ip` starts with the IP header.
pub fn decrement_ttl(ip: &mut [u8]) -> Result<()> {
    let at = match ip[0] >> 4 {
        4 => 8,
        6 => 7,
        _ => return Ok(()),
    };
    if ip[at] <= 1 {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::HostUnreachable,
            "the TTL of the impostor packet ran out",
        )));
    }
    ip[at] -= 1;
    if at == 8 {
        // The header checksum, updated: the word TTL|protocol went down by 0x100.
        let c = u16::from_be_bytes([ip[10], ip[11]]) as u32 + 0x100;
        let c = (c & 0xffff) + (c >> 16);
        ip[10..12].copy_from_slice(&(c as u16).to_be_bytes());
    }
    Ok(())
}

/// The `virtio_net_hdr` that has the kernel segment the TCP or UDP packet at `at` in `frame`
/// into segments of `gso_size` bytes (0: as many as fit `mtu`), and the pseudo-header sum it
/// needs in the checksum field. `None` if the packet cannot be segmented (a fragment, or another
/// protocol).
pub fn gso(frame: &mut [u8], at: usize, mtu: u32, gso_size: u16) -> Option<[u8; VNET_LEN]> {
    let p = Packet::parse(&frame[at..], Link::Ip);
    if p.fragment().is_some() {
        return None;
    }
    let v6 = p.ipv6().is_some();
    let (kind, field) = match p.transport() {
        Transport::Tcp(_) if v6 => (VNET_GSO_TCPV6, 16),
        Transport::Tcp(_) => (VNET_GSO_TCPV4, 16),
        Transport::Udp(_) => (VNET_GSO_UDP_L4, 6),
        _ => return None,
    };
    let l4 = p.l4_offset()?;
    let proto = p.ip_protocol()?;
    let headers = p.payload_range().start;
    let len = p.payload_range().end - l4;
    let ip = &frame[at..];
    let addrs = if v6 { &ip[8..40] } else { &ip[12..20] };
    let pseudo = !checksum::finish(checksum::sum(addrs, proto as u64 + len as u64));
    let gso_size = match gso_size {
        0 => u16::try_from(mtu.checked_sub(headers as u32)?).ok()?,
        n => n,
    };
    let csum = at + l4 + field;
    frame[csum..csum + 2].copy_from_slice(&pseudo.to_be_bytes());
    let mut h = [0; VNET_LEN];
    h[0] = VNET_F_NEEDS_CSUM;
    h[1] = kind;
    // In the host's byte order (the legacy virtio header of packet sockets).
    h[2..4].copy_from_slice(&((at + headers) as u16).to_ne_bytes());
    h[4..6].copy_from_slice(&gso_size.to_ne_bytes());
    h[6..8].copy_from_slice(&((at + l4) as u16).to_ne_bytes());
    h[8..10].copy_from_slice(&(field as u16).to_ne_bytes());
    Some(h)
}

/// The destination of a raw IP packet, and its scope (an interface index, for IPv6 loopback
/// and link-local destinations).
fn destination(ip: &[u8], addr: &Address, lo: u32) -> (IpAddr, u32) {
    if ip[0] >> 4 == 4 {
        let d: [u8; 4] = ip[16..20].try_into().unwrap();
        return (IpAddr::V4(Ipv4Addr::from(d)), 0);
    }
    let d: [u8; 16] = ip[24..40].try_into().unwrap();
    let d = Ipv6Addr::from(d);
    let scope = if d.is_loopback() {
        lo
    } else if d.is_unicast_link_local() {
        if addr.if_idx != 0 { addr.if_idx } else { lo }
    } else {
        0
    };
    (IpAddr::V6(d), scope)
}

/// A handle's sending side: its sockets, made on first use.
pub struct Tx {
    lo: u32,
    socks: Mutex<Socks>,
}

#[derive(Default)]
struct Socks {
    raw4: Option<OwnedFd>,
    raw6: Option<OwnedFd>,
    /// `AF_PACKET` sockets by mark.
    packet: HashMap<u32, OwnedFd>,
    /// Interfaces' MTUs, and when they were read.
    mtus: HashMap<u32, (u32, Instant)>,
}

impl Tx {
    pub fn new(lo: u32) -> Tx {
        Tx {
            lo,
            socks: Mutex::new(Socks::default()),
        }
    }

    /// Sends `packet`, with the mark of TC priority `tc_priority`. `user`: the application sends
    /// it, so an impostor's TTL goes down (WinDivert's rule); otherwise the handle reinjects a
    /// packet its filter did not match. Either way, the checksums whose flags are clear are
    /// computed.
    pub fn send(
        &self,
        packet: &[u8],
        addr: &Address,
        layer: Layer,
        tc_priority: u16,
        user: bool,
    ) -> Result<()> {
        let at = ip_offset(packet, layer)?;
        let path = path(layer, addr, packet, self.lo)?;
        let mut pkt = packet.to_vec();
        if user
            && addr.impostor
            && let Some(at) = at
        {
            decrement_ttl(&mut pkt[at..])?;
        }
        let fix = Updated {
            ipv4: !addr.ip_checksum,
            tcp: !addr.tcp_checksum,
            udp: !addr.udp_checksum,
            ..Updated::default()
        };
        let gso_size = Ctx::decode(&addr.context)
            .filter(|c| c.ifindex == addr.if_idx)
            .map_or(0, |c| c.gso_size);
        let injected = abi::MARK_INJECTED | tc_priority as u32;
        let mut socks = lock(&self.socks);
        match path {
            Path::Raw => {
                checksum::recalculate_only(&mut pkt, Link::Ip, fix);
                let v6 = pkt[0] >> 4 == 6;
                let (dst, scope) = destination(&pkt, addr, self.lo);
                let fd = socks.raw(v6, injected)?;
                sys::send_ip(fd.as_fd(), &pkt, dst, scope)?;
            }
            Path::Out { ifindex, l2 } => {
                let frame = Frame {
                    l2,
                    pkt,
                    at,
                    fix,
                    gso_size,
                };
                socks.send(frame, ifindex, ifindex, injected, None)?;
            }
            Path::In { ifindex, l2 } => {
                let target = u16::try_from(ifindex).map_err(|_| {
                    Error::Unsupported("inbound packets to an interface index above 65535")
                })?;
                let l2 = l2.unwrap_or_else(|| {
                    let mac = loader::if_name(ifindex)
                        .and_then(|n| sys::mac(&n))
                        .unwrap_or_default();
                    let mut l2 = mac.to_vec();
                    l2.extend([0; 6]);
                    l2.extend(ethertype_ip(pkt[0] >> 4 == 6).to_be_bytes());
                    l2
                });
                let frame = Frame {
                    l2,
                    pkt,
                    at,
                    fix,
                    gso_size,
                };
                let mark = abi::MARK_REDIRECT | target as u32;
                let priority = abi::PRIO_INJECTED | tc_priority as u32;
                socks.send(frame, self.lo, ifindex, mark, Some(priority))?;
            }
        }
        Ok(())
    }
}

/// A frame to send through `AF_PACKET`.
struct Frame {
    /// The link-layer header to put in front (empty at ETHERNET, and for devices without one).
    l2: Vec<u8>,
    pkt: Vec<u8>,
    /// Where the IP header is in `pkt`: 0 when there is no link-layer header at all.
    at: Option<usize>,
    /// The checksums to compute.
    fix: Updated,
    /// The GSO segment size it was captured with.
    gso_size: u16,
}

impl Socks {
    fn raw(&mut self, v6: bool, mark: u32) -> io::Result<&OwnedFd> {
        let slot = if v6 { &mut self.raw6 } else { &mut self.raw4 };
        if slot.is_none() {
            *slot = Some(sys::raw_socket(v6, mark)?);
        }
        Ok(slot.as_ref().unwrap())
    }

    fn mtu(&mut self, ifindex: u32) -> u32 {
        let now = Instant::now();
        if let Some(&(mtu, at)) = self.mtus.get(&ifindex)
            && now.duration_since(at) < MTU_TTL
        {
            return mtu;
        }
        let mtu = loader::if_name(ifindex)
            .and_then(|n| sys::mtu(&n))
            .unwrap_or(1500);
        self.mtus.insert(ifindex, (mtu, now));
        mtu
    }

    /// Sends `f` out of `dev`, toward `target` (whose MTU decides on GSO).
    fn send(
        &mut self,
        f: Frame,
        dev: u32,
        target: u32,
        mark: u32,
        priority: Option<u32>,
    ) -> io::Result<()> {
        let mut frame = vec![0; VNET_LEN];
        frame.extend(&f.l2);
        frame.extend(&f.pkt);
        let body = &mut frame[VNET_LEN..];
        let ethertype = if f.l2.is_empty() && f.at == Some(0) {
            ethertype_ip(body[0] >> 4 == 6)
        } else {
            u16::from_be_bytes([body[12], body[13]])
        };
        let mut vnet = None;
        if let Some(at) = f.at.map(|a| a + f.l2.len()) {
            let len = body.len() - at;
            let mtu = self.mtu(target);
            if len > 576 && len > mtu as usize {
                let ip = Updated {
                    ipv4: f.fix.ipv4,
                    ..Updated::default()
                };
                checksum::recalculate_only(&mut body[at..], Link::Ip, ip);
                vnet = gso(body, at, mtu, f.gso_size);
            }
            if vnet.is_none() {
                checksum::recalculate_only(&mut body[at..], Link::Ip, f.fix);
            }
        }
        if let Some(h) = vnet {
            frame[..VNET_LEN].copy_from_slice(&h);
        }
        let fd = match self.packet.entry(mark) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(sys::packet_socket(mark, priority)?),
        };
        sys::send_frame(fd.as_fd(), &frame, dev, ethertype)
    }
}
