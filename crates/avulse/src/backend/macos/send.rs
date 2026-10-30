//! Sending packets, by the paths Spike C found:
//!
//! | Packet | Path |
//! | --- | --- |
//! | IPv4, either direction | A raw IP socket (`IP_HDRINCL`, with `ip_len` and `ip_off` in host byte order): routed out, or delivered to a local destination on the interface that owns it. |
//! | IPv6, outbound, with its context | bpf, out of the interface it was captured on, behind the saved Ethernet header. |
//! | IPv6, inbound | A `utun` device of the handle's: the stack receives the packet from that interface, not from `if_idx`. |
//! | ETHERNET, outbound | bpf, out of the interface. |
//! | ETHERNET, inbound, carrying IP | As at the NETWORK layer, without the Ethernet header. |
//!
//! bpf cannot inject inbound, and macOS has no `IPV6_HDRINCL`, so inbound frames that do not
//! carry IP, and outbound IPv6 packets with no Ethernet header to go behind (built by the
//! application, or on `lo0`), are refused with [`Error::Unsupported`].

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use avulse_filter::Layer;
use avulse_proto::Link;
use avulse_proto::checksum::{self, Updated};

use avulse_abi::macos::MacContext;

use super::record::hash;
use super::{lock, sys};
use crate::backend::{decrement_ttl, ip_offset};
use crate::{Address, Error, Result};

const ETH_LEN: usize = 14;
/// How long a sent packet is remembered, so that the handle does not capture it back.
const SENT_TTL: Duration = Duration::from_secs(2);
/// How many sent packets are remembered at most.
const SENT_MAX: usize = 256;

/// The way a packet goes out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Path {
    /// The raw IPv4 socket; the packet starts at `at` (after an Ethernet header at ETHERNET).
    Raw { at: usize },
    /// A bpf write on `ifindex`, behind `l2` (empty when the packet is a whole frame).
    Bpf { ifindex: u32, l2: Vec<u8> },
    /// The handle's `utun`; the IP packet starts at `at`.
    Utun { at: usize },
}

/// The path of `packet` at `layer`, with `addr`.
pub fn path(layer: Layer, addr: &Address, packet: &[u8]) -> Result<Path> {
    let at = ip_offset(packet, layer)?;
    let v4 = at.is_some_and(|at| packet[at] >> 4 == 4);
    if layer == Layer::Ethernet {
        if addr.if_idx == 0 {
            return Err(Error::InvalidArgument(
                "an ETHERNET packet needs its interface (if_idx)",
            ));
        }
        if addr.outbound {
            return Ok(Path::Bpf {
                ifindex: addr.if_idx,
                l2: Vec::new(),
            });
        }
        return match at {
            Some(at) if v4 => Ok(Path::Raw { at }),
            Some(at) => Ok(Path::Utun { at }),
            None => Err(Error::Unsupported(
                "inbound frames that do not carry IP (bpf cannot inject inbound on macOS)",
            )),
        };
    }
    if v4 {
        return Ok(Path::Raw { at: 0 });
    }
    if !addr.outbound {
        return Ok(Path::Utun { at: 0 });
    }
    // Outbound IPv6: out of the interface it was captured on, behind its Ethernet header.
    let ctx = MacContext::decode(&addr.context).filter(|c| c.ifindex == addr.if_idx);
    match ctx {
        Some(c) if !addr.loopback && c.l2().len() >= ETH_LEN => {
            let mut l2 = c.l2().to_vec();
            let n = l2.len();
            l2[n - 2..].copy_from_slice(&0x86ddu16.to_be_bytes());
            Ok(Path::Bpf {
                ifindex: addr.if_idx,
                l2,
            })
        }
        _ => Err(Error::Unsupported(
            "outbound IPv6 packets that were not captured on Ethernet (macOS has no \
             IPV6_HDRINCL)",
        )),
    }
}

/// A handle's sending side: its sockets and devices, made on first use, and what it sent
/// lately.
pub struct Tx {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    raw: Option<OwnedFd>,
    /// Write-only bpf devices, by interface index.
    writers: HashMap<u32, sys::Bpf>,
    utun: Option<sys::Utun>,
    /// Hashes of the packets sent lately, and when.
    sent: Vec<(u64, Instant)>,
}

impl Tx {
    pub fn new() -> Tx {
        Tx {
            state: Mutex::new(State::default()),
        }
    }

    /// Sends `packet` at `layer`. An impostor's TTL goes down first (WinDivert's rule), and the
    /// checksums whose flags are clear are computed.
    pub fn send(&self, packet: &[u8], addr: &Address, layer: Layer) -> Result<()> {
        let path = path(layer, addr, packet)?;
        let mut pkt = packet.to_vec();
        if let Some(at) = ip_offset(packet, layer)? {
            if addr.impostor {
                decrement_ttl(&mut pkt[at..])?;
            }
            let fix = Updated {
                ipv4: !addr.ip_checksum,
                tcp: !addr.tcp_checksum,
                udp: !addr.udp_checksum,
                ..Updated::default()
            };
            checksum::recalculate_only(&mut pkt[at..], Link::Ip, fix);
        }
        let mut st = lock(&self.state);
        match path {
            Path::Raw { at } => {
                let fd = match st.raw.take() {
                    Some(fd) => fd,
                    None => sys::raw_socket()?,
                };
                let sent = sys::send_ip4(fd.as_fd(), &pkt[at..]);
                st.raw = Some(fd);
                sent?;
                // Captured again at the NETWORK layers, from the IP header.
                st.remember(hash(&pkt[at..]));
            }
            Path::Utun { at } => {
                let utun = match st.utun.take() {
                    Some(u) => u,
                    None => sys::Utun::open()?,
                };
                let sent = utun.write(&pkt[at..]);
                st.utun = Some(utun);
                sent?;
            }
            Path::Bpf { ifindex, l2 } => {
                let mut frame = l2;
                frame.extend_from_slice(&pkt);
                let dev = match st.writers.entry(ifindex) {
                    Entry::Occupied(e) => e.into_mut(),
                    Entry::Vacant(e) => e.insert(sys::Bpf::writer(&if_name(ifindex)?)?),
                };
                dev.write(&frame)?;
                st.remember(hash(if layer == Layer::Ethernet {
                    &frame
                } else {
                    &pkt
                }));
            }
        }
        Ok(())
    }

    /// Whether the handle sent a packet with these bytes lately; forgets it if so, since each
    /// send is captured once.
    pub fn sent(&self, data: &[u8]) -> bool {
        let mut st = lock(&self.state);
        if st.sent.is_empty() {
            return false;
        }
        let h = hash(data);
        let now = Instant::now();
        st.sent.retain(|&(_, at)| now.duration_since(at) < SENT_TTL);
        match st.sent.iter().position(|&(s, _)| s == h) {
            Some(i) => {
                st.sent.swap_remove(i);
                true
            }
            None => false,
        }
    }
}

impl State {
    fn remember(&mut self, h: u64) {
        if self.sent.len() >= SENT_MAX {
            self.sent.remove(0);
        }
        self.sent.push((h, Instant::now()));
    }
}

/// The index of the interface named `name`.
pub fn if_index(name: &str) -> Result<u32> {
    let c = std::ffi::CString::new(name).map_err(|_| Error::InvalidArgument("interface name"))?;
    // SAFETY: a NUL-terminated name.
    match unsafe { libc::if_nametoindex(c.as_ptr()) } {
        0 => Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no interface {name}"),
        ))),
        i => Ok(i),
    }
}

/// The name of the interface with index `ifindex`.
pub fn if_name(ifindex: u32) -> Result<String> {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    // SAFETY: `buf` has room for IF_NAMESIZE bytes.
    let p = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr().cast()) };
    if p.is_null() {
        return Err(Error::InvalidArgument(
            "no interface with this index (if_idx)",
        ));
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
}
