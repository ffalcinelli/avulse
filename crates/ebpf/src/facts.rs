//! The facts the static TC program leaves for the generated matcher, as laid out in
//! `bpf/facts.h`. The two must agree; the header asserts the offsets below.

use avulse_proto::{Network, Packet, Transport};

/// `struct avulse_facts`: one per CPU, in the `avulse_facts` map.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// Frame length.
    pub len: u32,
    /// Presence bits ([`F_ETH`] and the others).
    pub flags: u32,
    /// Offset of the ARP or IP header (0 when absent).
    pub l3: u32,
    /// Offset of the transport header (0 when absent).
    pub l4: u32,
    /// Transport header length.
    pub l4_len: u32,
    /// Payload start.
    pub pay: u32,
    /// Payload end, after the IP and UDP lengths are applied.
    pub pay_end: u32,
    /// IPv4 protocol, or the IPv6 next header after the extension headers.
    pub proto: u8,
    /// IPv4 header length.
    pub l3_len: u8,
    /// Written by the matcher: 1 if the filter matches.
    pub verdict: u8,
    /// The handle's layer (`avulse_filter::Layer` as a number).
    pub layer: u8,
    /// Where what the filter sees starts: 0, or [`l3`](Facts::l3) at the NETWORK layers.
    pub base: u32,
    /// The device the packet is on.
    pub ifindex: u32,
    /// The offloaded outer VLAN tag, when [`meta`](Facts::meta) has [`M_VLAN`].
    pub vlan_tci: u16,
    /// Metadata bits ([`M_OUTBOUND`] and the others).
    pub meta: u8,
    /// Padding.
    pub pad: u8,
    /// Reserved.
    pub reserved: u32,
}

/// Byte offsets of the [`Facts`] fields, for the generated code.
pub mod off {
    /// [`Facts::len`](super::Facts::len).
    pub const LEN: i16 = 0;
    /// [`Facts::flags`](super::Facts::flags).
    pub const FLAGS: i16 = 4;
    /// [`Facts::l3`](super::Facts::l3).
    pub const L3: i16 = 8;
    /// [`Facts::l4`](super::Facts::l4).
    pub const L4: i16 = 12;
    /// [`Facts::l4_len`](super::Facts::l4_len).
    pub const L4_LEN: i16 = 16;
    /// [`Facts::pay`](super::Facts::pay).
    pub const PAY: i16 = 20;
    /// [`Facts::pay_end`](super::Facts::pay_end).
    pub const PAY_END: i16 = 24;
    /// [`Facts::proto`](super::Facts::proto).
    pub const PROTO: i16 = 28;
    /// [`Facts::l3_len`](super::Facts::l3_len).
    pub const L3_LEN: i16 = 29;
    /// [`Facts::verdict`](super::Facts::verdict).
    pub const VERDICT: i16 = 30;
    /// [`Facts::layer`](super::Facts::layer).
    pub const LAYER: i16 = 31;
    /// [`Facts::base`](super::Facts::base).
    pub const BASE: i16 = 32;
    /// [`Facts::ifindex`](super::Facts::ifindex).
    pub const IFINDEX: i16 = 36;
    /// [`Facts::vlan_tci`](super::Facts::vlan_tci).
    pub const VLAN_TCI: i16 = 40;
    /// [`Facts::meta`](super::Facts::meta).
    pub const META: i16 = 42;
}

/// Size of [`Facts`] in bytes.
pub const SIZE: usize = 48;

/// An Ethernet header.
pub const F_ETH: u32 = 1 << 0;
/// An IPv4 header.
pub const F_IPV4: u32 = 1 << 1;
/// An IPv6 header.
pub const F_IPV6: u32 = 1 << 2;
/// An ARP packet.
pub const F_ARP: u32 = 1 << 3;
/// A TCP header.
pub const F_TCP: u32 = 1 << 4;
/// A UDP header.
pub const F_UDP: u32 = 1 << 5;
/// An ICMP header.
pub const F_ICMP: u32 = 1 << 6;
/// An ICMPv6 header.
pub const F_ICMPV6: u32 = 1 << 7;
/// An IPv4 fragment, or an IPv6 fragment header.
pub const F_FRAG: u32 = 1 << 8;
/// A fragment with more to come.
pub const F_MORE: u32 = 1 << 9;

/// Egress.
pub const M_OUTBOUND: u8 = 1 << 0;
/// On the loopback device.
pub const M_LOOPBACK: u8 = 1 << 1;
/// Injected by a handle of lower or equal priority.
pub const M_IMPOSTOR: u8 = 1 << 2;
/// [`Facts::vlan_tci`] holds an offloaded outer VLAN tag.
pub const M_VLAN: u8 = 1 << 3;
/// Forwarded (NETWORK_FORWARD).
pub const M_FORWARD: u8 = 1 << 4;
/// Records only: the packet was copied and went on.
pub const M_SNIFFED: u8 = 1 << 5;

/// The program array slot of the generated matcher.
pub const SLOT_MATCHER: u32 = 0;
/// The program array slot of the action program, which the matcher tail-calls.
pub const SLOT_ACTION: u32 = 1;

impl Facts {
    /// The facts of a parsed Ethernet frame: what the static TC program computes from the same
    /// bytes. This is the contract the program is tested against.
    pub fn from_packet(p: &Packet<'_>) -> Facts {
        let mut flags = 0;
        if p.eth().is_some() {
            flags |= F_ETH;
        }
        flags |= match p.network() {
            Network::None => 0,
            Network::Arp(_) => F_ARP,
            Network::Ipv4(_) => F_IPV4,
            Network::Ipv6(_) => F_IPV6,
        };
        flags |= match p.transport() {
            Transport::None => 0,
            Transport::Tcp(_) => F_TCP,
            Transport::Udp(_) => F_UDP,
            Transport::Icmp(_) => F_ICMP,
            Transport::Icmpv6(_) => F_ICMPV6,
        };
        if let Some(fr) = p.fragment() {
            flags |= F_FRAG;
            if fr.more {
                flags |= F_MORE;
            }
        }
        let pay = p.payload_range();
        let l4 = p.l4_offset();
        Facts {
            len: p.data().len() as u32,
            flags,
            l3: p.l3_offset().unwrap_or(0) as u32,
            l4: l4.unwrap_or(0) as u32,
            l4_len: l4.map_or(0, |o| pay.start - o) as u32,
            pay: pay.start as u32,
            pay_end: pay.end as u32,
            proto: p.ip_protocol().unwrap_or(0),
            l3_len: p.ipv4().map_or(0, |h| h.header_len()) as u8,
            ..Facts::default()
        }
    }

    /// The facts at the NETWORK layers, from those of the Ethernet frame: the filter sees the
    /// IP packet, so the Ethernet header is absent and what it sees starts at the IP header.
    /// They are what [`from_packet`](Facts::from_packet) gives for the IP packet parsed alone
    /// (`Link::Ip`), with offsets still counted from the start of the frame.
    pub fn at_network(mut self) -> Facts {
        self.flags &= !F_ETH;
        self.base = self.l3;
        self
    }

    /// The bytes of the facts, as the kernel lays them out.
    pub fn to_bytes(&self) -> [u8; SIZE] {
        let mut b = [0; SIZE];
        let words = [
            self.len,
            self.flags,
            self.l3,
            self.l4,
            self.l4_len,
            self.pay,
            self.pay_end,
        ];
        for (i, w) in words.iter().enumerate() {
            b[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
        }
        b[28..32].copy_from_slice(&[self.proto, self.l3_len, self.verdict, self.layer]);
        b[32..36].copy_from_slice(&self.base.to_ne_bytes());
        b[36..40].copy_from_slice(&self.ifindex.to_ne_bytes());
        b[40..42].copy_from_slice(&self.vlan_tci.to_ne_bytes());
        b[42] = self.meta;
        b[43] = self.pad;
        b[44..48].copy_from_slice(&self.reserved.to_ne_bytes());
        b
    }
}
