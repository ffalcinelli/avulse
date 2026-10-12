//! Zero-copy header views.
//!
//! Each view wraps a slice whose length was validated by its `new` constructor, so the accessors
//! index without bounds failures.

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

#[inline]
pub(crate) fn be16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

#[inline]
pub(crate) fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[inline]
fn array<const N: usize>(b: &[u8], o: usize) -> [u8; N] {
    let mut a = [0; N];
    a.copy_from_slice(&b[o..o + N]);
    a
}

/// EtherType values.
pub mod ethertype {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const VLAN: u16 = 0x8100;
    pub const IPV6: u16 = 0x86dd;
    pub const MPLS: u16 = 0x8847;
    pub const PPPOE_DISCOVERY: u16 = 0x8863;
    pub const PPPOE_SESSION: u16 = 0x8864;
    pub const EAPOL: u16 = 0x888e;
    pub const QINQ: u16 = 0x88a8;
    pub const LLDP: u16 = 0x88cc;
    /// Pre-standard QinQ outer tag.
    pub const VLAN_9100: u16 = 0x9100;

    /// Whether `t` is the TPID of an 802.1Q/802.1ad tag.
    pub const fn is_vlan(t: u16) -> bool {
        matches!(t, VLAN | QINQ | VLAN_9100)
    }
}

/// IP protocol numbers (IPv4 protocol, IPv6 next header).
pub mod ip_proto {
    pub const HOPOPT: u8 = 0;
    pub const ICMP: u8 = 1;
    pub const IGMP: u8 = 2;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const IPV6_ROUTE: u8 = 43;
    pub const IPV6_FRAG: u8 = 44;
    pub const GRE: u8 = 47;
    pub const ESP: u8 = 50;
    pub const AH: u8 = 51;
    pub const ICMPV6: u8 = 58;
    pub const IPV6_NONXT: u8 = 59;
    pub const IPV6_OPTS: u8 = 60;
    pub const SCTP: u8 = 132;
}

/// A 48-bit MAC address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = &self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Ethernet II header (14 bytes).
#[derive(Clone, Copy, Debug)]
pub struct Ethernet<'a>(&'a [u8]);

impl<'a> Ethernet<'a> {
    pub const LEN: usize = 14;

    pub fn new(b: &'a [u8]) -> Option<Self> {
        b.get(..Self::LEN).map(Self)
    }
    pub fn dst(&self) -> MacAddr {
        MacAddr(array(self.0, 0))
    }
    pub fn src(&self) -> MacAddr {
        MacAddr(array(self.0, 6))
    }
    /// EtherType, or the 802.3 length when below 0x0600.
    pub fn ethertype(&self) -> u16 {
        be16(self.0, 12)
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// An 802.1Q / 802.1ad tag.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VlanTag {
    /// Tag protocol identifier (0x8100, 0x88a8 or 0x9100).
    pub tpid: u16,
    /// Tag control information: priority (3 bits), DEI (1 bit), VLAN ID (12 bits).
    pub tci: u16,
    /// EtherType that follows the tag.
    pub ethertype: u16,
}

impl VlanTag {
    pub const LEN: usize = 4;

    pub fn priority(&self) -> u8 {
        (self.tci >> 13) as u8
    }
    pub fn dei(&self) -> bool {
        self.tci & 0x1000 != 0
    }
    pub fn id(&self) -> u16 {
        self.tci & 0x0fff
    }
}

/// ARP packet (any hardware and protocol address sizes).
#[derive(Clone, Copy, Debug)]
pub struct Arp<'a>(&'a [u8]);

impl<'a> Arp<'a> {
    pub fn new(b: &'a [u8]) -> Option<Self> {
        let (h, p) = (*b.get(4)? as usize, *b.get(5)? as usize);
        b.get(..8 + 2 * (h + p)).map(Self)
    }
    pub fn hw_type(&self) -> u16 {
        be16(self.0, 0)
    }
    pub fn proto_type(&self) -> u16 {
        be16(self.0, 2)
    }
    pub fn hw_size(&self) -> u8 {
        self.0[4]
    }
    pub fn proto_size(&self) -> u8 {
        self.0[5]
    }
    pub fn opcode(&self) -> u16 {
        be16(self.0, 6)
    }
    fn field(&self, index: usize) -> &'a [u8] {
        let (h, p) = (self.hw_size() as usize, self.proto_size() as usize);
        let start = 8 + (index / 2) * (h + p) + (index % 2) * h;
        &self.0[start..start + if index.is_multiple_of(2) { h } else { p }]
    }
    pub fn sender_hw(&self) -> &'a [u8] {
        self.field(0)
    }
    pub fn sender_proto(&self) -> &'a [u8] {
        self.field(1)
    }
    pub fn target_hw(&self) -> &'a [u8] {
        self.field(2)
    }
    pub fn target_proto(&self) -> &'a [u8] {
        self.field(3)
    }
    pub fn sender_mac(&self) -> Option<MacAddr> {
        (self.hw_size() == 6).then(|| MacAddr(array(self.sender_hw(), 0)))
    }
    pub fn target_mac(&self) -> Option<MacAddr> {
        (self.hw_size() == 6).then(|| MacAddr(array(self.target_hw(), 0)))
    }
    fn is_ipv4(&self) -> bool {
        self.proto_type() == ethertype::IPV4 && self.proto_size() == 4
    }
    pub fn sender_ipv4(&self) -> Option<Ipv4Addr> {
        self.is_ipv4()
            .then(|| Ipv4Addr::from(array::<4>(self.sender_proto(), 0)))
    }
    pub fn target_ipv4(&self) -> Option<Ipv4Addr> {
        self.is_ipv4()
            .then(|| Ipv4Addr::from(array::<4>(self.target_proto(), 0)))
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// IPv4 header, options included.
#[derive(Clone, Copy, Debug)]
pub struct Ipv4<'a>(&'a [u8]);

impl<'a> Ipv4<'a> {
    pub const MIN_LEN: usize = 20;

    pub fn new(b: &'a [u8]) -> Option<Self> {
        let v = *b.first()?;
        let hl = (v & 0x0f) as usize * 4;
        if v >> 4 != 4 || hl < Self::MIN_LEN {
            return None;
        }
        b.get(..hl).map(Self)
    }
    pub fn version(&self) -> u8 {
        self.0[0] >> 4
    }
    /// Header length in bytes.
    pub fn header_len(&self) -> usize {
        self.0.len()
    }
    /// The DS field: DSCP (6 bits) and ECN (2 bits).
    pub fn dsfield(&self) -> u8 {
        self.0[1]
    }
    pub fn dscp(&self) -> u8 {
        self.0[1] >> 2
    }
    pub fn ecn(&self) -> u8 {
        self.0[1] & 3
    }
    pub fn total_len(&self) -> u16 {
        be16(self.0, 2)
    }
    pub fn id(&self) -> u16 {
        be16(self.0, 4)
    }
    /// The three flag bits: reserved, DF, MF.
    pub fn flags(&self) -> u8 {
        self.0[6] >> 5
    }
    pub fn reserved_flag(&self) -> bool {
        self.0[6] & 0x80 != 0
    }
    pub fn dont_fragment(&self) -> bool {
        self.0[6] & 0x40 != 0
    }
    pub fn more_fragments(&self) -> bool {
        self.0[6] & 0x20 != 0
    }
    /// Fragment offset in 8-byte units.
    pub fn frag_offset(&self) -> u16 {
        be16(self.0, 6) & 0x1fff
    }
    pub fn is_fragment(&self) -> bool {
        self.more_fragments() || self.frag_offset() != 0
    }
    pub fn ttl(&self) -> u8 {
        self.0[8]
    }
    pub fn protocol(&self) -> u8 {
        self.0[9]
    }
    pub fn checksum(&self) -> u16 {
        be16(self.0, 10)
    }
    pub fn src(&self) -> Ipv4Addr {
        Ipv4Addr::from(array::<4>(self.0, 12))
    }
    pub fn dst(&self) -> Ipv4Addr {
        Ipv4Addr::from(array::<4>(self.0, 16))
    }
    pub fn options(&self) -> &'a [u8] {
        &self.0[20..]
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// IPv6 fixed header (40 bytes).
#[derive(Clone, Copy, Debug)]
pub struct Ipv6<'a>(&'a [u8]);

impl<'a> Ipv6<'a> {
    pub const LEN: usize = 40;

    pub fn new(b: &'a [u8]) -> Option<Self> {
        if b.first()? >> 4 != 6 {
            return None;
        }
        b.get(..Self::LEN).map(Self)
    }
    pub fn version(&self) -> u8 {
        self.0[0] >> 4
    }
    pub fn traffic_class(&self) -> u8 {
        (be32(self.0, 0) >> 20) as u8
    }
    pub fn dscp(&self) -> u8 {
        self.traffic_class() >> 2
    }
    pub fn ecn(&self) -> u8 {
        self.traffic_class() & 3
    }
    pub fn flow_label(&self) -> u32 {
        be32(self.0, 0) & 0x000f_ffff
    }
    pub fn payload_len(&self) -> u16 {
        be16(self.0, 4)
    }
    pub fn next_header(&self) -> u8 {
        self.0[6]
    }
    pub fn hop_limit(&self) -> u8 {
        self.0[7]
    }
    pub fn src(&self) -> Ipv6Addr {
        Ipv6Addr::from(array::<16>(self.0, 8))
    }
    pub fn dst(&self) -> Ipv6Addr {
        Ipv6Addr::from(array::<16>(self.0, 24))
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// IP fragmentation info, from the IPv4 header or the IPv6 fragment header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment {
    /// Offset in 8-byte units.
    pub offset: u16,
    pub more: bool,
    pub id: u32,
}

/// TCP header, options included.
#[derive(Clone, Copy, Debug)]
pub struct Tcp<'a>(&'a [u8]);

impl<'a> Tcp<'a> {
    pub const MIN_LEN: usize = 20;

    pub const FIN: u16 = 0x001;
    pub const SYN: u16 = 0x002;
    pub const RST: u16 = 0x004;
    pub const PSH: u16 = 0x008;
    pub const ACK: u16 = 0x010;
    pub const URG: u16 = 0x020;
    pub const ECE: u16 = 0x040;
    pub const CWR: u16 = 0x080;
    /// Accurate ECN (formerly NS).
    pub const AE: u16 = 0x100;

    pub fn new(b: &'a [u8]) -> Option<Self> {
        let hl = (*b.get(12)? >> 4) as usize * 4;
        if hl < Self::MIN_LEN {
            return None;
        }
        b.get(..hl).map(Self)
    }
    pub fn src_port(&self) -> u16 {
        be16(self.0, 0)
    }
    pub fn dst_port(&self) -> u16 {
        be16(self.0, 2)
    }
    pub fn seq(&self) -> u32 {
        be32(self.0, 4)
    }
    pub fn ack(&self) -> u32 {
        be32(self.0, 8)
    }
    /// Header length in bytes.
    pub fn header_len(&self) -> usize {
        self.0.len()
    }
    /// The 12 flag bits (3 reserved, AE, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN).
    pub fn flags(&self) -> u16 {
        be16(self.0, 12) & 0x0fff
    }
    pub fn has(&self, flag: u16) -> bool {
        self.flags() & flag != 0
    }
    /// The three reserved bits.
    pub fn reserved(&self) -> u8 {
        (self.0[12] >> 1) & 7
    }
    pub fn window(&self) -> u16 {
        be16(self.0, 14)
    }
    pub fn checksum(&self) -> u16 {
        be16(self.0, 16)
    }
    pub fn urgent_ptr(&self) -> u16 {
        be16(self.0, 18)
    }
    pub fn options(&self) -> &'a [u8] {
        &self.0[20..]
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// UDP header (8 bytes).
#[derive(Clone, Copy, Debug)]
pub struct Udp<'a>(&'a [u8]);

impl<'a> Udp<'a> {
    pub const LEN: usize = 8;

    pub fn new(b: &'a [u8]) -> Option<Self> {
        b.get(..Self::LEN).map(Self)
    }
    pub fn src_port(&self) -> u16 {
        be16(self.0, 0)
    }
    pub fn dst_port(&self) -> u16 {
        be16(self.0, 2)
    }
    pub fn length(&self) -> u16 {
        be16(self.0, 4)
    }
    pub fn checksum(&self) -> u16 {
        be16(self.0, 6)
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// ICMP message (8-byte header and body).
#[derive(Clone, Copy, Debug)]
pub struct Icmp<'a>(&'a [u8]);

impl<'a> Icmp<'a> {
    pub const HEADER_LEN: usize = 8;

    pub fn new(b: &'a [u8]) -> Option<Self> {
        (b.len() >= Self::HEADER_LEN).then_some(Self(b))
    }
    pub fn icmp_type(&self) -> u8 {
        self.0[0]
    }
    pub fn code(&self) -> u8 {
        self.0[1]
    }
    pub fn checksum(&self) -> u16 {
        be16(self.0, 2)
    }
    fn has_ident(&self) -> bool {
        // Echo, timestamp, information and address mask requests and replies.
        matches!(self.icmp_type(), 0 | 8 | 13..=18)
    }
    /// Identifier of echo-like messages.
    pub fn ident(&self) -> Option<u16> {
        self.has_ident().then(|| be16(self.0, 4))
    }
    /// Sequence number of echo-like messages.
    pub fn seq(&self) -> Option<u16> {
        self.has_ident().then(|| be16(self.0, 6))
    }
    /// The whole message.
    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// ICMPv6 message (4-byte header and body).
#[derive(Clone, Copy, Debug)]
pub struct Icmpv6<'a>(&'a [u8]);

impl<'a> Icmpv6<'a> {
    pub const HEADER_LEN: usize = 4;

    pub fn new(b: &'a [u8]) -> Option<Self> {
        (b.len() >= Self::HEADER_LEN).then_some(Self(b))
    }
    pub fn icmp_type(&self) -> u8 {
        self.0[0]
    }
    pub fn code(&self) -> u8 {
        self.0[1]
    }
    pub fn checksum(&self) -> u16 {
        be16(self.0, 2)
    }
    fn is_echo(&self) -> bool {
        matches!(self.icmp_type(), 128 | 129) && self.0.len() >= 8
    }
    pub fn echo_ident(&self) -> Option<u16> {
        self.is_echo().then(|| be16(self.0, 4))
    }
    pub fn echo_seq(&self) -> Option<u16> {
        self.is_echo().then(|| be16(self.0, 6))
    }
    /// The whole message.
    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }
}
