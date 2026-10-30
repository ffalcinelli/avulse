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
    /// IPv4.
    pub const IPV4: u16 = 0x0800;
    /// ARP.
    pub const ARP: u16 = 0x0806;
    /// 802.1Q VLAN tag (C-tag).
    pub const VLAN: u16 = 0x8100;
    /// IPv6.
    pub const IPV6: u16 = 0x86dd;
    /// MPLS unicast.
    pub const MPLS: u16 = 0x8847;
    /// PPPoE discovery stage.
    pub const PPPOE_DISCOVERY: u16 = 0x8863;
    /// PPPoE session stage.
    pub const PPPOE_SESSION: u16 = 0x8864;
    /// EAP over LAN (802.1X).
    pub const EAPOL: u16 = 0x888e;
    /// 802.1ad service tag (S-tag, QinQ outer tag).
    pub const QINQ: u16 = 0x88a8;
    /// Link Layer Discovery Protocol.
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
    /// IPv6 hop-by-hop options.
    pub const HOPOPT: u8 = 0;
    /// ICMP.
    pub const ICMP: u8 = 1;
    /// IGMP.
    pub const IGMP: u8 = 2;
    /// TCP.
    pub const TCP: u8 = 6;
    /// UDP.
    pub const UDP: u8 = 17;
    /// IPv6 routing header.
    pub const IPV6_ROUTE: u8 = 43;
    /// IPv6 fragment header.
    pub const IPV6_FRAG: u8 = 44;
    /// Generic Routing Encapsulation.
    pub const GRE: u8 = 47;
    /// IPsec Encapsulating Security Payload.
    pub const ESP: u8 = 50;
    /// IPsec Authentication Header.
    pub const AH: u8 = 51;
    /// ICMPv6.
    pub const ICMPV6: u8 = 58;
    /// IPv6 "no next header".
    pub const IPV6_NONXT: u8 = 59;
    /// IPv6 destination options.
    pub const IPV6_OPTS: u8 = 60;
    /// SCTP.
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
    /// Header length in bytes.
    pub const LEN: usize = 14;

    /// Wraps the header at the start of `b`, or returns `None` if `b` is too short or not this
    /// header.
    pub fn new(b: &'a [u8]) -> Option<Self> {
        b.get(..Self::LEN).map(Self)
    }
    /// Destination MAC address.
    pub fn dst(&self) -> MacAddr {
        MacAddr(array(self.0, 0))
    }
    /// Source MAC address.
    pub fn src(&self) -> MacAddr {
        MacAddr(array(self.0, 6))
    }
    /// EtherType, or the 802.3 length when below 0x0600.
    pub fn ethertype(&self) -> u16 {
        be16(self.0, 12)
    }
    /// The 14 header bytes.
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
    /// Header length in bytes.
    pub const LEN: usize = 4;

    /// Priority code point (3 bits).
    pub fn priority(&self) -> u8 {
        (self.tci >> 13) as u8
    }
    /// Drop eligible indicator.
    pub fn dei(&self) -> bool {
        self.tci & 0x1000 != 0
    }
    /// VLAN identifier (12 bits).
    pub fn id(&self) -> u16 {
        self.tci & 0x0fff
    }
}

/// ARP packet (any hardware and protocol address sizes).
#[derive(Clone, Copy, Debug)]
pub struct Arp<'a>(&'a [u8]);

impl<'a> Arp<'a> {
    /// Wraps the ARP packet at the start of `b`, or returns `None` if `b` is shorter than its
    /// address sizes say.
    pub fn new(b: &'a [u8]) -> Option<Self> {
        let (h, p) = (*b.get(4)? as usize, *b.get(5)? as usize);
        b.get(..8 + 2 * (h + p)).map(Self)
    }
    /// Hardware type (1 for Ethernet).
    pub fn hw_type(&self) -> u16 {
        be16(self.0, 0)
    }
    /// Protocol type (an EtherType, 0x0800 for IPv4).
    pub fn proto_type(&self) -> u16 {
        be16(self.0, 2)
    }
    /// Hardware address length in bytes.
    pub fn hw_size(&self) -> u8 {
        self.0[4]
    }
    /// Protocol address length in bytes.
    pub fn proto_size(&self) -> u8 {
        self.0[5]
    }
    /// Operation (1 request, 2 reply).
    pub fn opcode(&self) -> u16 {
        be16(self.0, 6)
    }
    fn field(&self, index: usize) -> &'a [u8] {
        let (h, p) = (self.hw_size() as usize, self.proto_size() as usize);
        let start = 8 + (index / 2) * (h + p) + (index % 2) * h;
        &self.0[start..start + if index.is_multiple_of(2) { h } else { p }]
    }
    /// Sender hardware address bytes.
    pub fn sender_hw(&self) -> &'a [u8] {
        self.field(0)
    }
    /// Sender protocol address bytes.
    pub fn sender_proto(&self) -> &'a [u8] {
        self.field(1)
    }
    /// Target hardware address bytes.
    pub fn target_hw(&self) -> &'a [u8] {
        self.field(2)
    }
    /// Target protocol address bytes.
    pub fn target_proto(&self) -> &'a [u8] {
        self.field(3)
    }
    /// Sender MAC address, if the hardware address is 6 bytes long.
    pub fn sender_mac(&self) -> Option<MacAddr> {
        (self.hw_size() == 6).then(|| MacAddr(array(self.sender_hw(), 0)))
    }
    /// Target MAC address, if the hardware address is 6 bytes long.
    pub fn target_mac(&self) -> Option<MacAddr> {
        (self.hw_size() == 6).then(|| MacAddr(array(self.target_hw(), 0)))
    }
    fn is_ipv4(&self) -> bool {
        self.proto_type() == ethertype::IPV4 && self.proto_size() == 4
    }
    /// Sender IPv4 address, if the protocol is IPv4.
    pub fn sender_ipv4(&self) -> Option<Ipv4Addr> {
        self.is_ipv4()
            .then(|| Ipv4Addr::from(array::<4>(self.sender_proto(), 0)))
    }
    /// Target IPv4 address, if the protocol is IPv4.
    pub fn target_ipv4(&self) -> Option<Ipv4Addr> {
        self.is_ipv4()
            .then(|| Ipv4Addr::from(array::<4>(self.target_proto(), 0)))
    }
    /// The whole ARP packet.
    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// IPv4 header, options included.
#[derive(Clone, Copy, Debug)]
pub struct Ipv4<'a>(&'a [u8]);

impl<'a> Ipv4<'a> {
    /// Minimum header length in bytes (no options).
    pub const MIN_LEN: usize = 20;

    /// Wraps the IPv4 header at the start of `b`, or returns `None` if the version is not 4, the
    /// header length is below 20, or `b` is shorter than the header.
    pub fn new(b: &'a [u8]) -> Option<Self> {
        let v = *b.first()?;
        let hl = (v & 0x0f) as usize * 4;
        if v >> 4 != 4 || hl < Self::MIN_LEN {
            return None;
        }
        b.get(..hl).map(Self)
    }
    /// Version field (always 4).
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
    /// Differentiated Services Code Point (6 bits).
    pub fn dscp(&self) -> u8 {
        self.0[1] >> 2
    }
    /// Explicit Congestion Notification (2 bits).
    pub fn ecn(&self) -> u8 {
        self.0[1] & 3
    }
    /// Total length field (header and payload) in bytes.
    pub fn total_len(&self) -> u16 {
        be16(self.0, 2)
    }
    /// Identification field.
    pub fn id(&self) -> u16 {
        be16(self.0, 4)
    }
    /// The three flag bits: reserved, DF, MF.
    pub fn flags(&self) -> u8 {
        self.0[6] >> 5
    }
    /// The reserved (evil) flag bit.
    pub fn reserved_flag(&self) -> bool {
        self.0[6] & 0x80 != 0
    }
    /// The Don't Fragment flag.
    pub fn dont_fragment(&self) -> bool {
        self.0[6] & 0x40 != 0
    }
    /// The More Fragments flag.
    pub fn more_fragments(&self) -> bool {
        self.0[6] & 0x20 != 0
    }
    /// Fragment offset in 8-byte units.
    pub fn frag_offset(&self) -> u16 {
        be16(self.0, 6) & 0x1fff
    }
    /// Whether this is a fragment: MF set or a non-zero offset.
    pub fn is_fragment(&self) -> bool {
        self.more_fragments() || self.frag_offset() != 0
    }
    /// Time to live.
    pub fn ttl(&self) -> u8 {
        self.0[8]
    }
    /// Protocol of the payload (see [`ip_proto`]).
    pub fn protocol(&self) -> u8 {
        self.0[9]
    }
    /// Checksum field, as on the wire.
    pub fn checksum(&self) -> u16 {
        be16(self.0, 10)
    }
    /// Source address.
    pub fn src(&self) -> Ipv4Addr {
        Ipv4Addr::from(array::<4>(self.0, 12))
    }
    /// Destination address.
    pub fn dst(&self) -> Ipv4Addr {
        Ipv4Addr::from(array::<4>(self.0, 16))
    }
    /// The option bytes after the fixed header (may be empty).
    pub fn options(&self) -> &'a [u8] {
        &self.0[20..]
    }
    /// The options, in order. The walk ends after an End of Option List, and at an option whose
    /// length is missing, below 2, or past the header, as Wireshark's does.
    pub fn option_iter(&self) -> TcpOptions<'a> {
        TcpOptions {
            b: self.options(),
            at: 0,
        }
    }
    /// The first option of `kind` (see [`tcp_option`]).
    ///
    /// ```
    /// use avulse_proto::{Tcp, tcp_option};
    ///
    /// // A SYN with MSS 1460 and window scale 7.
    /// let hdr = [
    ///     0x9c, 0x40, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x70, 0x02, 0xff, 0xff, 0, 0, 0, 0,
    ///     2, 4, 0x05, 0xb4, 1, 3, 3, 7,
    /// ];
    /// let tcp = Tcp::new(&hdr).unwrap();
    /// assert_eq!(tcp.option(tcp_option::MSS).and_then(|o| o.mss()), Some(1460));
    /// assert_eq!(tcp.option(tcp_option::WSCALE).and_then(|o| o.wscale_shift()), Some(7));
    /// assert!(tcp.option(tcp_option::SACK_PERM).is_none());
    /// ```
    pub fn option(&self, kind: u8) -> Option<TcpOption<'a>> {
        self.option_iter().find(|o| o.kind() == kind)
    }
    /// The header bytes, options included.
    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// IPv6 fixed header (40 bytes).
#[derive(Clone, Copy, Debug)]
pub struct Ipv6<'a>(&'a [u8]);

impl<'a> Ipv6<'a> {
    /// Header length in bytes.
    pub const LEN: usize = 40;

    /// Wraps the IPv6 fixed header at the start of `b`, or returns `None` if the version is not 6
    /// or `b` is shorter than 40 bytes.
    pub fn new(b: &'a [u8]) -> Option<Self> {
        if b.first()? >> 4 != 6 {
            return None;
        }
        b.get(..Self::LEN).map(Self)
    }
    /// Version field (always 6).
    pub fn version(&self) -> u8 {
        self.0[0] >> 4
    }
    /// Traffic class (DSCP and ECN).
    pub fn traffic_class(&self) -> u8 {
        (be32(self.0, 0) >> 20) as u8
    }
    /// Differentiated Services Code Point (6 bits).
    pub fn dscp(&self) -> u8 {
        self.traffic_class() >> 2
    }
    /// Explicit Congestion Notification (2 bits).
    pub fn ecn(&self) -> u8 {
        self.traffic_class() & 3
    }
    /// Flow label (20 bits).
    pub fn flow_label(&self) -> u32 {
        be32(self.0, 0) & 0x000f_ffff
    }
    /// Payload length field: everything after the fixed header, extension headers included.
    pub fn payload_len(&self) -> u16 {
        be16(self.0, 4)
    }
    /// Next header field of the fixed header (see [`ip_proto`]).
    pub fn next_header(&self) -> u8 {
        self.0[6]
    }
    /// Hop limit.
    pub fn hop_limit(&self) -> u8 {
        self.0[7]
    }
    /// Source address.
    pub fn src(&self) -> Ipv6Addr {
        Ipv6Addr::from(array::<16>(self.0, 8))
    }
    /// Destination address.
    pub fn dst(&self) -> Ipv6Addr {
        Ipv6Addr::from(array::<16>(self.0, 24))
    }
    /// The 40 bytes of the fixed header.
    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// IP fragmentation info, from the IPv4 header or the IPv6 fragment header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment {
    /// Offset in 8-byte units.
    pub offset: u16,
    /// More Fragments: another fragment follows.
    pub more: bool,
    /// Identification: 16 bits for IPv4, 32 for IPv6.
    pub id: u32,
}

/// TCP header, options included.
#[derive(Clone, Copy, Debug)]
pub struct Tcp<'a>(&'a [u8]);

impl<'a> Tcp<'a> {
    /// Minimum header length in bytes (no options).
    pub const MIN_LEN: usize = 20;

    /// FIN flag.
    pub const FIN: u16 = 0x001;
    /// SYN flag.
    pub const SYN: u16 = 0x002;
    /// RST flag.
    pub const RST: u16 = 0x004;
    /// PSH flag.
    pub const PSH: u16 = 0x008;
    /// ACK flag.
    pub const ACK: u16 = 0x010;
    /// URG flag.
    pub const URG: u16 = 0x020;
    /// ECN-Echo flag.
    pub const ECE: u16 = 0x040;
    /// Congestion Window Reduced flag.
    pub const CWR: u16 = 0x080;
    /// Accurate ECN (formerly NS).
    pub const AE: u16 = 0x100;

    /// Wraps the TCP header at the start of `b`, or returns `None` if the data offset is below 5
    /// words or `b` is shorter than the header.
    pub fn new(b: &'a [u8]) -> Option<Self> {
        let hl = (*b.get(12)? >> 4) as usize * 4;
        if hl < Self::MIN_LEN {
            return None;
        }
        b.get(..hl).map(Self)
    }
    /// Source port.
    pub fn src_port(&self) -> u16 {
        be16(self.0, 0)
    }
    /// Destination port.
    pub fn dst_port(&self) -> u16 {
        be16(self.0, 2)
    }
    /// Sequence number.
    pub fn seq(&self) -> u32 {
        be32(self.0, 4)
    }
    /// Acknowledgment number.
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
    /// Whether any of the bits in `flag` is set, e.g. `tcp.has(Tcp::SYN)`.
    pub fn has(&self, flag: u16) -> bool {
        self.flags() & flag != 0
    }
    /// The three reserved bits.
    pub fn reserved(&self) -> u8 {
        (self.0[12] >> 1) & 7
    }
    /// Window size, unscaled.
    pub fn window(&self) -> u16 {
        be16(self.0, 14)
    }
    /// Checksum field, as on the wire.
    pub fn checksum(&self) -> u16 {
        be16(self.0, 16)
    }
    /// Urgent pointer.
    pub fn urgent_ptr(&self) -> u16 {
        be16(self.0, 18)
    }
    /// The option bytes after the fixed header (may be empty).
    pub fn options(&self) -> &'a [u8] {
        &self.0[20..]
    }
    /// The options, in order. The walk ends after an End of Option List, and at an option whose
    /// length is missing, below 2, or past the header, as Wireshark's does.
    pub fn option_iter(&self) -> TcpOptions<'a> {
        TcpOptions {
            b: self.options(),
            at: 0,
        }
    }
    /// The first option of `kind` (see [`tcp_option`]).
    ///
    /// ```
    /// use avulse_proto::{Tcp, tcp_option};
    ///
    /// // A SYN with MSS 1460 and window scale 7.
    /// let hdr = [
    ///     0x9c, 0x40, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x70, 0x02, 0xff, 0xff, 0, 0, 0, 0,
    ///     2, 4, 0x05, 0xb4, 1, 3, 3, 7,
    /// ];
    /// let tcp = Tcp::new(&hdr).unwrap();
    /// assert_eq!(tcp.option(tcp_option::MSS).and_then(|o| o.mss()), Some(1460));
    /// assert_eq!(tcp.option(tcp_option::WSCALE).and_then(|o| o.wscale_shift()), Some(7));
    /// assert!(tcp.option(tcp_option::SACK_PERM).is_none());
    /// ```
    pub fn option(&self, kind: u8) -> Option<TcpOption<'a>> {
        self.option_iter().find(|o| o.kind() == kind)
    }
    /// The header bytes, options included.
    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// TCP option kinds.
pub mod tcp_option {
    /// End of Option List.
    pub const EOL: u8 = 0;
    /// No-Operation (padding).
    pub const NOP: u8 = 1;
    /// Maximum Segment Size.
    pub const MSS: u8 = 2;
    /// Window Scale.
    pub const WSCALE: u8 = 3;
    /// SACK Permitted.
    pub const SACK_PERM: u8 = 4;
    /// SACK blocks.
    pub const SACK: u8 = 5;
    /// Timestamps.
    pub const TIMESTAMP: u8 = 8;
}

/// One TCP option: its kind, where it starts in the TCP header, and its bytes (kind and length
/// included).
#[derive(Clone, Copy, Debug)]
pub struct TcpOption<'a> {
    offset: usize,
    bytes: &'a [u8],
}

impl<'a> TcpOption<'a> {
    /// The option kind (see [`tcp_option`]).
    pub fn kind(&self) -> u8 {
        self.bytes.first().copied().unwrap_or_default()
    }
    /// Offset of the option from the start of the TCP header.
    pub fn offset(&self) -> usize {
        self.offset
    }
    /// The option's bytes, as long as its length field says (one byte for EOL and NOP).
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    /// The data after kind and length, when the option has the given kind and length.
    fn data<const N: usize>(&self, kind: u8) -> Option<[u8; N]> {
        if self.kind() != kind || self.bytes.len() != N + 2 {
            return None;
        }
        self.bytes.get(2..)?.try_into().ok()
    }
    /// The MSS, for a well-formed MSS option (length 4).
    pub fn mss(&self) -> Option<u16> {
        self.data(tcp_option::MSS).map(u16::from_be_bytes)
    }
    /// The shift count, for a well-formed Window Scale option (length 3).
    pub fn wscale_shift(&self) -> Option<u8> {
        self.data::<1>(tcp_option::WSCALE).map(|[s]| s)
    }
    /// Timestamp value and echo reply, for a well-formed Timestamps option (length 10).
    pub fn timestamps(&self) -> Option<(u32, u32)> {
        let d = self.data::<8>(tcp_option::TIMESTAMP)?;
        Some((be32(&d, 0), be32(&d, 4)))
    }
}

/// The options of a TCP header, from [`Tcp::option_iter`].
#[derive(Clone, Debug)]
pub struct TcpOptions<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Iterator for TcpOptions<'a> {
    type Item = TcpOption<'a>;

    fn next(&mut self) -> Option<TcpOption<'a>> {
        let offset = self.at;
        let len = match *self.b.get(offset)? {
            tcp_option::NOP => 1,
            tcp_option::EOL => {
                // Nothing after the end of the list is an option.
                self.at = self.b.len();
                return Some(TcpOption {
                    offset: 20 + offset,
                    bytes: self.b.get(offset..offset + 1)?,
                });
            }
            _ => match self.b.get(offset + 1) {
                Some(&n) if n >= 2 => n as usize,
                _ => {
                    self.at = self.b.len();
                    return None;
                }
            },
        };
        let Some(bytes) = self.b.get(offset..offset + len) else {
            self.at = self.b.len();
            return None;
        };
        self.at = offset + len;
        Some(TcpOption {
            offset: 20 + offset,
            bytes,
        })
    }
}

/// UDP header (8 bytes).
#[derive(Clone, Copy, Debug)]
pub struct Udp<'a>(&'a [u8]);

impl<'a> Udp<'a> {
    /// Header length in bytes.
    pub const LEN: usize = 8;

    /// Wraps the UDP header at the start of `b`, or returns `None` if `b` is shorter than 8 bytes.
    pub fn new(b: &'a [u8]) -> Option<Self> {
        b.get(..Self::LEN).map(Self)
    }
    /// Source port.
    pub fn src_port(&self) -> u16 {
        be16(self.0, 0)
    }
    /// Destination port.
    pub fn dst_port(&self) -> u16 {
        be16(self.0, 2)
    }
    /// Length field: header and payload, in bytes.
    pub fn length(&self) -> u16 {
        be16(self.0, 4)
    }
    /// Checksum field, as on the wire.
    pub fn checksum(&self) -> u16 {
        be16(self.0, 6)
    }
    /// The 8 header bytes.
    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }
}

/// ICMP message (8-byte header and body).
#[derive(Clone, Copy, Debug)]
pub struct Icmp<'a>(&'a [u8]);

impl<'a> Icmp<'a> {
    /// Length of the fixed header in bytes.
    pub const HEADER_LEN: usize = 8;

    /// Wraps the ICMP message in `b`, or returns `None` if `b` is shorter than 8 bytes.
    pub fn new(b: &'a [u8]) -> Option<Self> {
        (b.len() >= Self::HEADER_LEN).then_some(Self(b))
    }
    /// Message type.
    pub fn icmp_type(&self) -> u8 {
        self.0[0]
    }
    /// Message code.
    pub fn code(&self) -> u8 {
        self.0[1]
    }
    /// Checksum field, as on the wire.
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
    /// Length of the fixed header in bytes.
    pub const HEADER_LEN: usize = 4;

    /// Wraps the ICMPv6 message in `b`, or returns `None` if `b` is shorter than 4 bytes.
    pub fn new(b: &'a [u8]) -> Option<Self> {
        (b.len() >= Self::HEADER_LEN).then_some(Self(b))
    }
    /// Message type.
    pub fn icmp_type(&self) -> u8 {
        self.0[0]
    }
    /// Message code.
    pub fn code(&self) -> u8 {
        self.0[1]
    }
    /// Checksum field, as on the wire.
    pub fn checksum(&self) -> u16 {
        be16(self.0, 2)
    }
    fn is_echo(&self) -> bool {
        matches!(self.icmp_type(), 128 | 129) && self.0.len() >= 8
    }
    /// Identifier of echo requests and replies.
    pub fn echo_ident(&self) -> Option<u16> {
        self.is_echo().then(|| be16(self.0, 4))
    }
    /// Sequence number of echo requests and replies.
    pub fn echo_seq(&self) -> Option<u16> {
        self.is_echo().then(|| be16(self.0, 6))
    }
    /// The whole message.
    pub fn bytes(&self) -> &'a [u8] {
        self.0
    }
}
