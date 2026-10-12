use core::ops::Range;

use crate::headers::*;

/// What the first byte of a buffer is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Link {
    /// An Ethernet frame (ETHERNET layer).
    Ethernet,
    /// An IPv4 or IPv6 packet, picked by the version nibble (NETWORK layers).
    Ip,
}

/// Up to this many VLAN tags are parsed (802.1ad QinQ).
pub const MAX_VLANS: usize = 2;

/// Up to this many IPv6 extension headers are walked.
const MAX_IPV6_EXT: usize = 8;

#[derive(Clone, Copy, Debug)]
pub enum Network<'a> {
    None,
    Arp(Arp<'a>),
    Ipv4(Ipv4<'a>),
    Ipv6(Ipv6<'a>),
}

#[derive(Clone, Copy, Debug)]
pub enum Transport<'a> {
    None,
    Tcp(Tcp<'a>),
    Udp(Udp<'a>),
    Icmp(Icmp<'a>),
    Icmpv6(Icmpv6<'a>),
}

/// A parsed packet: header views and offsets into the original buffer.
///
/// Parsing never fails. It stops at the first header that is truncated, malformed or of an unknown
/// type, and everything after it is the payload.
#[derive(Clone, Debug)]
pub struct Packet<'a> {
    data: &'a [u8],
    eth: Option<Ethernet<'a>>,
    vlans: [VlanTag; MAX_VLANS],
    vlan_count: usize,
    ethertype: Option<u16>,
    network: Network<'a>,
    l3_offset: Option<usize>,
    protocol: Option<u8>,
    fragment: Option<Fragment>,
    transport: Transport<'a>,
    l4_offset: Option<usize>,
    payload: Range<usize>,
}

impl<'a> Packet<'a> {
    pub fn parse(data: &'a [u8], link: Link) -> Self {
        let mut p = Packet {
            data,
            eth: None,
            vlans: [VlanTag::default(); MAX_VLANS],
            vlan_count: 0,
            ethertype: None,
            network: Network::None,
            l3_offset: None,
            protocol: None,
            fragment: None,
            transport: Transport::None,
            l4_offset: None,
            payload: data.len()..data.len(),
        };
        let (ethertype, off) = match link {
            Link::Ethernet => match p.parse_ethernet() {
                Some(v) => v,
                None => return p,
            },
            Link::Ip => match data.first().map(|b| b >> 4) {
                Some(4) => (ethertype::IPV4, 0),
                Some(6) => (ethertype::IPV6, 0),
                _ => {
                    p.payload = 0..data.len();
                    return p;
                }
            },
        };
        p.payload = off..data.len();
        match ethertype {
            ethertype::ARP => p.parse_arp(off),
            ethertype::IPV4 => p.parse_ipv4(off),
            ethertype::IPV6 => p.parse_ipv6(off),
            _ => {}
        }
        p
    }

    fn parse_ethernet(&mut self) -> Option<(u16, usize)> {
        let eth = Ethernet::new(self.data)?;
        self.eth = Some(eth);
        let mut off = Ethernet::LEN;
        let mut et = eth.ethertype();
        self.payload = off..self.data.len();
        while ethertype::is_vlan(et) && self.vlan_count < MAX_VLANS {
            let t = self.data.get(off..off + VlanTag::LEN)?;
            let tag = VlanTag {
                tpid: et,
                tci: be16(t, 0),
                ethertype: be16(t, 2),
            };
            self.vlans[self.vlan_count] = tag;
            self.vlan_count += 1;
            off += VlanTag::LEN;
            et = tag.ethertype;
            self.payload = off..self.data.len();
        }
        if ethertype::is_vlan(et) {
            return None;
        }
        self.ethertype = Some(et);
        Some((et, off))
    }

    fn parse_arp(&mut self, off: usize) {
        if let Some(arp) = Arp::new(&self.data[off..]) {
            self.network = Network::Arp(arp);
            self.l3_offset = Some(off);
            let end = off + arp.bytes().len();
            self.payload = end..end;
        }
    }

    fn parse_ipv4(&mut self, off: usize) {
        let Some(ip) = Ipv4::new(&self.data[off..]) else {
            return;
        };
        let hl = ip.header_len();
        let total = ip.total_len() as usize;
        // Trim Ethernet padding; keep the whole buffer when the length is bogus or 0 (GSO).
        let end = if total >= hl && off + total <= self.data.len() {
            off + total
        } else {
            self.data.len()
        };
        self.network = Network::Ipv4(ip);
        self.l3_offset = Some(off);
        self.protocol = Some(ip.protocol());
        if ip.is_fragment() {
            self.fragment = Some(Fragment {
                offset: ip.frag_offset(),
                more: ip.more_fragments(),
                id: ip.id() as u32,
            });
        }
        self.payload = off + hl..end;
        if ip.frag_offset() == 0 {
            self.parse_transport(ip.protocol(), off + hl, end);
        }
    }

    fn parse_ipv6(&mut self, off: usize) {
        let Some(ip) = Ipv6::new(&self.data[off..]) else {
            return;
        };
        let plen = ip.payload_len() as usize;
        let mut end = off + Ipv6::LEN + plen;
        if plen == 0 || end > self.data.len() {
            end = self.data.len();
        }
        self.network = Network::Ipv6(ip);
        self.l3_offset = Some(off);
        let mut nh = ip.next_header();
        let mut cur = off + Ipv6::LEN;
        for _ in 0..MAX_IPV6_EXT {
            let len = match nh {
                ip_proto::HOPOPT | ip_proto::IPV6_ROUTE | ip_proto::IPV6_OPTS | ip_proto::AH => {
                    let Some(h) = self.data[..end].get(cur..cur + 2) else {
                        break;
                    };
                    if nh == ip_proto::AH {
                        (h[1] as usize + 2) * 4
                    } else {
                        (h[1] as usize + 1) * 8
                    }
                }
                ip_proto::IPV6_FRAG => {
                    let Some(h) = self.data[..end].get(cur..cur + 8) else {
                        break;
                    };
                    let field = be16(h, 2);
                    self.fragment = Some(Fragment {
                        offset: field >> 3,
                        more: field & 1 != 0,
                        id: be32(h, 4),
                    });
                    8
                }
                _ => break,
            };
            if cur + len > end {
                break;
            }
            nh = self.data[cur];
            cur += len;
        }
        self.protocol = Some(nh);
        self.payload = cur..end;
        if self.fragment.is_none_or(|f| f.offset == 0) {
            self.parse_transport(nh, cur, end);
        }
    }

    fn parse_transport(&mut self, proto: u8, off: usize, mut end: usize) {
        let seg = &self.data[off..end];
        let (transport, header_len) = match proto {
            ip_proto::TCP => match Tcp::new(seg) {
                Some(t) => (Transport::Tcp(t), t.header_len()),
                None => return,
            },
            ip_proto::UDP => match Udp::new(seg) {
                Some(u) => {
                    let ulen = u.length() as usize;
                    if (Udp::LEN..=seg.len()).contains(&ulen) {
                        end = off + ulen;
                    }
                    (Transport::Udp(u), Udp::LEN)
                }
                None => return,
            },
            ip_proto::ICMP => match Icmp::new(seg) {
                Some(i) => (Transport::Icmp(i), Icmp::HEADER_LEN),
                None => return,
            },
            ip_proto::ICMPV6 => match Icmpv6::new(seg) {
                Some(i) => (Transport::Icmpv6(i), seg.len().min(8)),
                None => return,
            },
            _ => return,
        };
        self.transport = transport;
        self.l4_offset = Some(off);
        self.payload = off + header_len..end;
    }

    /// The whole buffer.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }
    pub fn eth(&self) -> Option<Ethernet<'a>> {
        self.eth
    }
    pub fn vlans(&self) -> &[VlanTag] {
        &self.vlans[..self.vlan_count]
    }
    /// The EtherType after the VLAN tags (Ethernet frames only).
    pub fn ethertype(&self) -> Option<u16> {
        self.ethertype
    }
    pub fn network(&self) -> Network<'a> {
        self.network
    }
    pub fn arp(&self) -> Option<Arp<'a>> {
        match self.network {
            Network::Arp(a) => Some(a),
            _ => None,
        }
    }
    pub fn ipv4(&self) -> Option<Ipv4<'a>> {
        match self.network {
            Network::Ipv4(ip) => Some(ip),
            _ => None,
        }
    }
    pub fn ipv6(&self) -> Option<Ipv6<'a>> {
        match self.network {
            Network::Ipv6(ip) => Some(ip),
            _ => None,
        }
    }
    /// Offset of the ARP/IP header.
    pub fn l3_offset(&self) -> Option<usize> {
        self.l3_offset
    }
    /// The transport protocol: IPv4 protocol, or the IPv6 next header after extension headers.
    pub fn ip_protocol(&self) -> Option<u8> {
        self.protocol
    }
    pub fn fragment(&self) -> Option<Fragment> {
        self.fragment
    }
    pub fn transport(&self) -> Transport<'a> {
        self.transport
    }
    pub fn tcp(&self) -> Option<Tcp<'a>> {
        match self.transport {
            Transport::Tcp(t) => Some(t),
            _ => None,
        }
    }
    pub fn udp(&self) -> Option<Udp<'a>> {
        match self.transport {
            Transport::Udp(u) => Some(u),
            _ => None,
        }
    }
    pub fn icmp(&self) -> Option<Icmp<'a>> {
        match self.transport {
            Transport::Icmp(i) => Some(i),
            _ => None,
        }
    }
    pub fn icmpv6(&self) -> Option<Icmpv6<'a>> {
        match self.transport {
            Transport::Icmpv6(i) => Some(i),
            _ => None,
        }
    }
    /// Offset of the transport header.
    pub fn l4_offset(&self) -> Option<usize> {
        self.l4_offset
    }
    /// The bytes after the last parsed header (Ethernet padding and IP trailers excluded).
    pub fn payload(&self) -> &'a [u8] {
        &self.data[self.payload.clone()]
    }
    pub fn payload_range(&self) -> Range<usize> {
        self.payload.clone()
    }
}
