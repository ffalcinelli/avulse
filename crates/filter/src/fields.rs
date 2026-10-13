//! The field registry: Wireshark field names Avulse supports, Avulse extensions, symbolic
//! constants, and the Wireshark fields that are rejected because they need state.

use core::fmt;

/// Static type of a field or value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ty {
    /// `true` or `false`.
    Bool,
    /// Unsigned integer of the given width in bits.
    Uint(u8),
    /// Signed 64-bit integer: the result of arithmetic.
    Int,
    /// An IPv4 address.
    Ipv4,
    /// An IPv6 address.
    Ipv6,
    /// IPv4 or IPv6 (extension fields such as `local.addr`).
    Ip,
    /// A MAC address.
    Ether,
    /// A byte string.
    Bytes,
    /// A text string.
    Str,
    /// A protocol: present or not, sliceable as its header bytes.
    Proto,
}

impl Ty {
    /// The type's name with an article, for diagnostics ("an unsigned integer").
    pub fn name(self) -> &'static str {
        match self {
            Ty::Bool => "a boolean",
            Ty::Uint(_) => "an unsigned integer",
            Ty::Int => "an integer",
            Ty::Ipv4 => "an IPv4 address",
            Ty::Ipv6 => "an IPv6 address",
            Ty::Ip => "an IP address",
            Ty::Ether => "a MAC address",
            Ty::Bytes => "a byte string",
            Ty::Str => "a string",
            Ty::Proto => "a protocol",
        }
    }

    /// Whether values of this type have a byte representation (sliceable, `contains`).
    pub fn is_bytes(self) -> bool {
        matches!(
            self,
            Ty::Ether | Ty::Bytes | Ty::Str | Ty::Proto | Ty::Ipv4 | Ty::Ipv6 | Ty::Ip
        )
    }

    /// Whether `<`, `<=`, `>` and `>=` apply to values of this type.
    pub fn is_ordered(self) -> bool {
        matches!(
            self,
            Ty::Uint(_) | Ty::Int | Ty::Ipv4 | Ty::Ipv6 | Ty::Ip | Ty::Ether | Ty::Bytes | Ty::Str
        )
    }
}

impl fmt::Display for Ty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Where a field name comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Same name and meaning as in Wireshark.
    Wireshark,
    /// Avulse extension.
    Extension,
    /// Avulse extension whose bare use tests that the value is true (`outbound`, `loopback`).
    Flag,
}

/// A table of symbolic constants: name and value. Lookups ignore case.
pub type Consts = &'static [(&'static str, u64)];

/// The registry entry of a [`Field`].
#[derive(Debug)]
pub struct FieldDef {
    /// The name used in filters, such as `tcp.dstport`.
    pub name: &'static str,
    /// The field.
    pub field: Field,
    /// Its type.
    pub ty: Ty,
    /// Whether it is a Wireshark field or an Avulse extension.
    pub origin: Origin,
    /// Symbolic names accepted as values, such as `syn` for `tcp.flags`.
    pub consts: Consts,
    /// One-line description, shown by `avulse filter fields`.
    pub desc: &'static str,
}

const U8: Ty = Ty::Uint(8);
const U16: Ty = Ty::Uint(16);
const U32: Ty = Ty::Uint(32);
const U64: Ty = Ty::Uint(64);
const NONE: Consts = &[];

/// EtherType names, for `eth.type` and `vlan.etype`.
pub const ETHERTYPES: Consts = &[
    ("ipv4", 0x0800),
    ("ip", 0x0800),
    ("arp", 0x0806),
    ("vlan", 0x8100),
    ("ipv6", 0x86dd),
    ("mpls", 0x8847),
    ("pppoe-discovery", 0x8863),
    ("pppoe-session", 0x8864),
    ("eapol", 0x888e),
    ("qinq", 0x88a8),
    ("lldp", 0x88cc),
];

/// IP protocol names, for `ip.proto` and `ipv6.nxt`.
pub const IP_PROTOS: Consts = &[
    ("hopopt", 0),
    ("icmp", 1),
    ("igmp", 2),
    ("tcp", 6),
    ("udp", 17),
    ("ipv6-route", 43),
    ("ipv6-frag", 44),
    ("gre", 47),
    ("esp", 50),
    ("ah", 51),
    ("icmpv6", 58),
    ("ipv6-nonxt", 59),
    ("ipv6-opts", 60),
    ("sctp", 132),
];

/// ARP operation names, for `arp.opcode`.
pub const ARP_OPCODES: Consts = &[
    ("request", 1),
    ("reply", 2),
    ("rarp-request", 3),
    ("rarp-reply", 4),
];

/// ICMP type names, for `icmp.type`.
pub const ICMP_TYPES: Consts = &[
    ("echo-reply", 0),
    ("dest-unreachable", 3),
    ("source-quench", 4),
    ("redirect", 5),
    ("echo-request", 8),
    ("router-advertisement", 9),
    ("router-solicitation", 10),
    ("time-exceeded", 11),
    ("parameter-problem", 12),
    ("timestamp-request", 13),
    ("timestamp-reply", 14),
];

/// ICMPv6 type names, for `icmpv6.type`.
pub const ICMPV6_TYPES: Consts = &[
    ("dest-unreachable", 1),
    ("packet-too-big", 2),
    ("time-exceeded", 3),
    ("parameter-problem", 4),
    ("echo-request", 128),
    ("echo-reply", 129),
    ("mld-query", 130),
    ("mld-report", 131),
    ("mld-done", 132),
    ("router-solicitation", 133),
    ("router-advertisement", 134),
    ("neighbor-solicitation", 135),
    ("neighbor-advertisement", 136),
    ("redirect", 137),
    ("mldv2-report", 143),
];

/// TCP flag names, for `tcp.flags`.
pub const TCP_FLAGS: Consts = &[
    ("fin", 0x001),
    ("syn", 0x002),
    ("rst", 0x004),
    ("reset", 0x004),
    ("psh", 0x008),
    ("push", 0x008),
    ("ack", 0x010),
    ("urg", 0x020),
    ("ece", 0x040),
    ("cwr", 0x080),
    ("ae", 0x100),
];

/// Layer names, for `layer`.
pub const LAYERS: Consts = &[
    ("network", 0),
    ("network-forward", 1),
    ("flow", 2),
    ("socket", 3),
    ("reflect", 4),
    ("ethernet", 5),
];

/// Event names, for `event`.
pub const EVENTS: Consts = &[
    ("packet", 0),
    ("established", 1),
    ("deleted", 2),
    ("bind", 3),
    ("connect", 4),
    ("listen", 5),
    ("accept", 6),
    ("close", 7),
    ("open", 8),
    ("reflect-open", 8),
    ("reflect-close", 9),
];

macro_rules! fields {
    ($($v:ident: $name:literal, $ty:expr, $origin:ident, $consts:expr, $desc:literal;)*) => {
        /// A field the filter can read.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum Field { $(#[doc = concat!("`", $name, "`: ", $desc, ".")] $v,)* }

        /// Every supported field, in documentation order.
        pub static FIELDS: &[FieldDef] = &[
            $(FieldDef { name: $name, field: Field::$v, ty: $ty, origin: Origin::$origin, consts: $consts, desc: $desc },)*
        ];
    };
}

fields! {
    Frame: "frame", Ty::Proto, Wireshark, NONE, "The whole packet";
    FrameLen: "frame.len", U32, Wireshark, NONE, "Packet length in bytes";
    FrameCapLen: "frame.cap_len", U32, Wireshark, NONE, "Captured length in bytes (same as frame.len)";
    FrameInterfaceName: "frame.interface_name", Ty::Str, Wireshark, NONE, "Interface name";

    Eth: "eth", Ty::Proto, Wireshark, NONE, "Ethernet header (ETHERNET layer)";
    EthDst: "eth.dst", Ty::Ether, Wireshark, NONE, "Destination MAC";
    EthSrc: "eth.src", Ty::Ether, Wireshark, NONE, "Source MAC";
    EthAddr: "eth.addr", Ty::Ether, Wireshark, NONE, "Source or destination MAC";
    EthType: "eth.type", U16, Wireshark, ETHERTYPES, "EtherType of the outer header";

    Vlan: "vlan", Ty::Proto, Wireshark, NONE, "802.1Q tag (each tag; 802.1ad tags are `ieee8021ad`)";
    VlanPriority: "vlan.priority", Ty::Uint(3), Wireshark, NONE, "Priority code point";
    VlanDei: "vlan.dei", Ty::Bool, Wireshark, NONE, "Drop eligible indicator";
    VlanId: "vlan.id", Ty::Uint(12), Wireshark, NONE, "VLAN ID";
    VlanEtype: "vlan.etype", U16, Wireshark, ETHERTYPES, "EtherType after the tag";

    Ieee8021ad: "ieee8021ad", Ty::Proto, Wireshark, NONE, "802.1ad service tag (TPID 0x88a8, outer QinQ tag)";
    Ieee8021adPriority: "ieee8021ad.priority", Ty::Uint(3), Wireshark, NONE, "Priority code point";
    Ieee8021adDei: "ieee8021ad.dei", Ty::Uint(1), Wireshark, NONE, "Drop eligible indicator";
    Ieee8021adId: "ieee8021ad.id", Ty::Uint(12), Wireshark, NONE, "Service VLAN ID";

    Arp: "arp", Ty::Proto, Wireshark, NONE, "ARP packet";
    ArpHwType: "arp.hw.type", U16, Wireshark, NONE, "Hardware type";
    ArpProtoType: "arp.proto.type", U16, Wireshark, ETHERTYPES, "Protocol type";
    ArpHwSize: "arp.hw.size", U8, Wireshark, NONE, "Hardware address size";
    ArpProtoSize: "arp.proto.size", U8, Wireshark, NONE, "Protocol address size";
    ArpOpcode: "arp.opcode", U16, Wireshark, ARP_OPCODES, "Operation";
    ArpSrcHwMac: "arp.src.hw_mac", Ty::Ether, Wireshark, NONE, "Sender MAC";
    ArpSrcProtoIpv4: "arp.src.proto_ipv4", Ty::Ipv4, Wireshark, NONE, "Sender IPv4 address";
    ArpDstHwMac: "arp.dst.hw_mac", Ty::Ether, Wireshark, NONE, "Target MAC";
    ArpDstProtoIpv4: "arp.dst.proto_ipv4", Ty::Ipv4, Wireshark, NONE, "Target IPv4 address";

    Ip: "ip", Ty::Proto, Wireshark, NONE, "IPv4 header";
    IpVersion: "ip.version", Ty::Uint(4), Wireshark, NONE, "Version (of the IPv4 or the IPv6 header, as in Wireshark)";
    IpHdrLen: "ip.hdr_len", U8, Wireshark, NONE, "Header length in bytes";
    IpDsfield: "ip.dsfield", U8, Wireshark, NONE, "Differentiated services field";
    IpDsfieldDscp: "ip.dsfield.dscp", Ty::Uint(6), Wireshark, NONE, "DSCP";
    IpDsfieldEcn: "ip.dsfield.ecn", Ty::Uint(2), Wireshark, NONE, "ECN";
    IpLen: "ip.len", U16, Wireshark, NONE, "Total length";
    IpId: "ip.id", U16, Wireshark, NONE, "Identification";
    IpFlags: "ip.flags", Ty::Uint(3), Wireshark, NONE, "Flags (reserved, DF, MF)";
    IpFlagsRb: "ip.flags.rb", Ty::Bool, Wireshark, NONE, "Reserved flag";
    IpFlagsDf: "ip.flags.df", Ty::Bool, Wireshark, NONE, "Don't fragment";
    IpFlagsMf: "ip.flags.mf", Ty::Bool, Wireshark, NONE, "More fragments";
    IpFragOffset: "ip.frag_offset", Ty::Uint(13), Wireshark, NONE, "Fragment offset (8-byte units)";
    IpTtl: "ip.ttl", U8, Wireshark, NONE, "Time to live";
    IpProto: "ip.proto", U8, Wireshark, IP_PROTOS, "Protocol";
    IpChecksum: "ip.checksum", U16, Wireshark, NONE, "Header checksum";
    IpSrc: "ip.src", Ty::Ipv4, Wireshark, NONE, "Source address";
    IpDst: "ip.dst", Ty::Ipv4, Wireshark, NONE, "Destination address";
    IpAddr: "ip.addr", Ty::Ipv4, Wireshark, NONE, "Source or destination address";

    Ipv6: "ipv6", Ty::Proto, Wireshark, NONE, "IPv6 header and extension headers";
    Ipv6Version: "ipv6.version", Ty::Uint(4), Wireshark, NONE, "Version";
    Ipv6Tclass: "ipv6.tclass", U8, Wireshark, NONE, "Traffic class";
    Ipv6TclassDscp: "ipv6.tclass.dscp", Ty::Uint(6), Wireshark, NONE, "DSCP";
    Ipv6TclassEcn: "ipv6.tclass.ecn", Ty::Uint(2), Wireshark, NONE, "ECN";
    Ipv6Flow: "ipv6.flow", Ty::Uint(20), Wireshark, NONE, "Flow label";
    Ipv6Plen: "ipv6.plen", U16, Wireshark, NONE, "Payload length";
    Ipv6Nxt: "ipv6.nxt", U8, Wireshark, IP_PROTOS, "Next header (in the fixed header)";
    Ipv6Hlim: "ipv6.hlim", U8, Wireshark, NONE, "Hop limit";
    Ipv6Src: "ipv6.src", Ty::Ipv6, Wireshark, NONE, "Source address";
    Ipv6Dst: "ipv6.dst", Ty::Ipv6, Wireshark, NONE, "Destination address";
    Ipv6Addr: "ipv6.addr", Ty::Ipv6, Wireshark, NONE, "Source or destination address";
    Ipv6FraghdrOffset: "ipv6.fraghdr.offset", Ty::Uint(13), Wireshark, NONE, "Fragment offset (8-byte units)";
    Ipv6FraghdrMore: "ipv6.fraghdr.more", Ty::Bool, Wireshark, NONE, "More fragments";
    Ipv6FraghdrIdent: "ipv6.fraghdr.ident", U32, Wireshark, NONE, "Fragment identification";

    Tcp: "tcp", Ty::Proto, Wireshark, NONE, "TCP header";
    TcpSrcport: "tcp.srcport", U16, Wireshark, NONE, "Source port";
    TcpDstport: "tcp.dstport", U16, Wireshark, NONE, "Destination port";
    TcpPort: "tcp.port", U16, Wireshark, NONE, "Source or destination port";
    TcpSeqRaw: "tcp.seq_raw", U32, Wireshark, NONE, "Sequence number";
    TcpAckRaw: "tcp.ack_raw", U32, Wireshark, NONE, "Acknowledgment number";
    TcpHdrLen: "tcp.hdr_len", U8, Wireshark, NONE, "Header length in bytes";
    TcpFlags: "tcp.flags", Ty::Uint(12), Wireshark, TCP_FLAGS, "Flags";
    TcpFlagsRes: "tcp.flags.res", Ty::Bool, Wireshark, NONE, "Reserved bits set";
    TcpFlagsAe: "tcp.flags.ae", Ty::Bool, Wireshark, NONE, "Accurate ECN";
    TcpFlagsCwr: "tcp.flags.cwr", Ty::Bool, Wireshark, NONE, "CWR";
    TcpFlagsEce: "tcp.flags.ece", Ty::Bool, Wireshark, NONE, "ECE";
    TcpFlagsUrg: "tcp.flags.urg", Ty::Bool, Wireshark, NONE, "URG";
    TcpFlagsAck: "tcp.flags.ack", Ty::Bool, Wireshark, NONE, "ACK";
    TcpFlagsPush: "tcp.flags.push", Ty::Bool, Wireshark, NONE, "PSH";
    TcpFlagsReset: "tcp.flags.reset", Ty::Bool, Wireshark, NONE, "RST";
    TcpFlagsSyn: "tcp.flags.syn", Ty::Bool, Wireshark, NONE, "SYN";
    TcpFlagsFin: "tcp.flags.fin", Ty::Bool, Wireshark, NONE, "FIN";
    TcpWindowSizeValue: "tcp.window_size_value", U16, Wireshark, NONE, "Window (unscaled)";
    TcpChecksum: "tcp.checksum", U16, Wireshark, NONE, "Checksum";
    TcpUrgentPointer: "tcp.urgent_pointer", U16, Wireshark, NONE, "Urgent pointer";
    TcpLen: "tcp.len", U32, Wireshark, NONE, "Payload length (absent on IP fragments)";
    TcpPayload: "tcp.payload", Ty::Bytes, Wireshark, NONE, "Payload (when not empty)";

    Udp: "udp", Ty::Proto, Wireshark, NONE, "UDP header";
    UdpSrcport: "udp.srcport", U16, Wireshark, NONE, "Source port";
    UdpDstport: "udp.dstport", U16, Wireshark, NONE, "Destination port";
    UdpPort: "udp.port", U16, Wireshark, NONE, "Source or destination port";
    UdpLength: "udp.length", U16, Wireshark, NONE, "Length";
    UdpChecksum: "udp.checksum", U16, Wireshark, NONE, "Checksum";
    UdpPayload: "udp.payload", Ty::Bytes, Wireshark, NONE, "Payload (when not empty)";

    Icmp: "icmp", Ty::Proto, Wireshark, NONE, "ICMP message";
    IcmpType: "icmp.type", U8, Wireshark, ICMP_TYPES, "Type";
    IcmpCode: "icmp.code", U8, Wireshark, NONE, "Code";
    IcmpChecksum: "icmp.checksum", U16, Wireshark, NONE, "Checksum";
    IcmpIdent: "icmp.ident", U16, Wireshark, NONE, "Identifier (echo, timestamp, information)";
    IcmpSeq: "icmp.seq", U16, Wireshark, NONE, "Sequence number (echo, timestamp, information)";

    Icmpv6: "icmpv6", Ty::Proto, Wireshark, NONE, "ICMPv6 message";
    Icmpv6Type: "icmpv6.type", U8, Wireshark, ICMPV6_TYPES, "Type";
    Icmpv6Code: "icmpv6.code", U8, Wireshark, NONE, "Code";
    Icmpv6Checksum: "icmpv6.checksum", U16, Wireshark, NONE, "Checksum";
    Icmpv6EchoIdentifier: "icmpv6.echo.identifier", U16, Wireshark, NONE, "Echo identifier";
    Icmpv6EchoSequenceNumber: "icmpv6.echo.sequence_number", U16, Wireshark, NONE, "Echo sequence number";

    Inbound: "inbound", Ty::Bool, Flag, NONE, "Inbound packet";
    Outbound: "outbound", Ty::Bool, Flag, NONE, "Outbound packet";
    Loopback: "loopback", Ty::Bool, Flag, NONE, "Loopback packet";
    Impostor: "impostor", Ty::Bool, Flag, NONE, "Packet injected by another handle";
    Fragment: "fragment", Ty::Bool, Flag, NONE, "IP fragment";
    Ifidx: "ifidx", U32, Extension, NONE, "Interface index";
    Subifidx: "subifidx", U32, Extension, NONE, "Sub-interface index";
    Iface: "iface", Ty::Str, Extension, NONE, "Interface name";
    Layer: "layer", U8, Extension, LAYERS, "Layer of the handle";
    Event: "event", U8, Extension, EVENTS, "Event";
    Protocol: "protocol", U8, Extension, IP_PROTOS, "Transport protocol (after IPv6 extension headers)";
    LocalAddr: "local.addr", Ty::Ip, Extension, NONE, "Local address";
    RemoteAddr: "remote.addr", Ty::Ip, Extension, NONE, "Remote address";
    LocalPort: "local.port", U16, Extension, NONE, "Local port";
    RemotePort: "remote.port", U16, Extension, NONE, "Remote port";
    ProcessPid: "process.pid", U32, Extension, NONE, "Process ID (FLOW, SOCKET layers)";
    ProcessName: "process.name", Ty::Str, Extension, NONE, "Process name (FLOW, SOCKET layers)";
    EndpointId: "endpoint.id", U64, Extension, NONE, "Endpoint ID (FLOW, SOCKET layers)";
    ParentEndpointId: "parent.endpoint.id", U64, Extension, NONE, "Parent endpoint ID (FLOW, SOCKET layers)";
}

/// The field named `name`, if Avulse supports it.
///
/// ```
/// use avulse_filter::fields::{Origin, lookup};
///
/// let def = lookup("tcp.dstport").unwrap();
/// assert_eq!(def.ty.name(), "an unsigned integer");
/// assert_eq!(def.origin, Origin::Wireshark);
/// assert!(lookup("tcp.stream").is_none());
/// ```
pub fn lookup(name: &str) -> Option<&'static FieldDef> {
    FIELDS.iter().find(|d| d.name == name)
}

/// The registry entry of `field`.
pub fn def(field: Field) -> &'static FieldDef {
    FIELDS
        .iter()
        .find(|d| d.field == field)
        .expect("every Field has a FieldDef")
}

/// The value of the constant `name` in `consts`, ignoring case.
pub fn constant(consts: Consts, name: &str) -> Option<u64> {
    consts
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|&(_, v)| v)
}

/// Wireshark fields that exist but cannot be computed from one packet.
pub const UNSUPPORTED: &[(&str, &str)] = &[
    (
        "tcp.seq",
        "relative sequence numbers need stream tracking; use `tcp.seq_raw`",
    ),
    (
        "tcp.ack",
        "relative acknowledgment numbers need stream tracking; use `tcp.ack_raw`",
    ),
    ("tcp.nxtseq", "needs stream tracking"),
    (
        "tcp.window_size",
        "the scaled window needs the handshake; use `tcp.window_size_value`",
    ),
    ("tcp.window_size_scalefactor", "needs the handshake"),
    ("tcp.stream", "stream indexes need connection tracking"),
    ("udp.stream", "stream indexes need connection tracking"),
    ("tcp.analysis", "TCP analysis needs stream tracking"),
    ("tcp.time_delta", "needs stream tracking"),
    ("tcp.time_relative", "needs stream tracking"),
    ("tcp.segment", "needs TCP reassembly"),
    ("tcp.reassembled", "needs TCP reassembly"),
    (
        "tcp.options",
        "TCP options are not decoded yet; slice `tcp` instead, e.g. `tcp[20:1] == 02`",
    ),
    ("ip.host", "host names need DNS; compare addresses"),
    ("ip.src_host", "host names need DNS; compare addresses"),
    ("ip.dst_host", "host names need DNS; compare addresses"),
    ("ipv6.host", "host names need DNS; compare addresses"),
    ("ipv6.src_host", "host names need DNS; compare addresses"),
    ("ipv6.dst_host", "host names need DNS; compare addresses"),
    (
        "eth.src_resolved",
        "vendor names are not resolved; compare addresses",
    ),
    (
        "eth.dst_resolved",
        "vendor names are not resolved; compare addresses",
    ),
    ("frame.time", "timestamps are not filterable"),
    ("frame.number", "packet numbers are not filterable"),
    (
        "frame.protocols",
        "use the protocol names directly, e.g. `tcp`",
    ),
];

/// Protocols decoded by Wireshark dissectors above the transport layer.
pub const APPLICATION: &[&str] = &[
    "http",
    "http2",
    "http3",
    "tls",
    "ssl",
    "dtls",
    "dns",
    "mdns",
    "llmnr",
    "nbns",
    "quic",
    "dhcp",
    "bootp",
    "dhcpv6",
    "ssh",
    "smb",
    "smb2",
    "ftp",
    "ftp-data",
    "smtp",
    "imap",
    "pop",
    "ntp",
    "snmp",
    "sip",
    "rtp",
    "rtcp",
    "kerberos",
    "ldap",
    "ssdp",
    "websocket",
    "mqtt",
    "grpc",
    "telnet",
    "rdp",
    "nfs",
    "data",
    "igmp",
    "gre",
    "sctp",
    "esp",
    "ah",
    "stp",
    "cdp",
    "lldp",
    "eapol",
    "pppoe",
    "mpls",
    "vxlan",
    "geneve",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_and_lookups_round_trip() {
        for (i, d) in FIELDS.iter().enumerate() {
            assert!(
                FIELDS[..i].iter().all(|o| o.name != d.name),
                "duplicate {}",
                d.name
            );
            assert_eq!(def(d.field).name, d.name);
            assert_eq!(lookup(d.name).unwrap().field, d.field);
        }
    }

    #[test]
    fn constants_fit_their_fields() {
        for d in FIELDS {
            if let Ty::Uint(bits) = d.ty {
                for (n, v) in d.consts {
                    assert!(
                        bits >= 64 || *v < 1 << bits,
                        "{} = {v} does not fit {}",
                        n,
                        d.name
                    );
                }
            }
        }
    }
}
