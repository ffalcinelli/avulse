//! The WinDivert filter language, compiled to the same IR as native filters
//! ([`Filter::compile_windivert`](crate::Filter::compile_windivert)).
//!
//! It accepts what WinDivert 2.2 accepts and gives the results WinDivert gives, including its
//! quirks:
//!
//! - Names are case-sensitive: `tcp.DstPort`, `TCP`.
//! - `not` negates one comparison, not the test: `not tcp.DstPort == 80` is
//!   `tcp.DstPort != 80`, false on a UDP packet. It cannot apply to a parenthesized filter.
//! - A test on a header the packet lacks is false. A bare field is `field != 0`.
//! - Values are 128-bit numbers with a sign. IPv4 addresses are `::ffff:a.b.c.d`, so
//!   `ipv6.DstAddr >= 1000` and `tcp.Syn == ::1` are valid. A field narrower than 64 bits only
//!   compares the low 32 bits of the value.
//! - When a comparison cannot depend on the field's value, given its range, WinDivert replaces it
//!   by a test on the field's protocol: `ip.TOS < 0` becomes `not ip`, which is true on an IPv6
//!   packet, and `tcp.Syn <= 1` becomes `tcp`.
//! - `(a? b: c)` is a conditional, and `and` binds tighter than `or`.
//!
//! Every WinDivert test lowers to native IR (`packet16[2]` reads `frame[4:2]`, `ip.HdrLength`
//! compares `ip.hdr_len` against four times the value), so `avulse filter convert` can print a
//! native equivalent. The `random8/16/32` fields read [`Meta::hash`](crate::Meta::hash), which a
//! WinDivert-compatible backend fills with WinDivert's packet hash.
//!
//! Known differences, on packets WinDivert's own parser treats differently from
//! [`avulse_proto`]: the UDP payload ends at the UDP length rather than the IP length, IPv6
//! mobility headers (135) are not skipped, ICMP is recognized after IPv6, and a TCP header whose
//! options are cut short is dropped rather than shortened.

mod lower;
mod parse;

use alloc::format;

use crate::error::{Diagnostic, Span};
use crate::fields::Field;
use crate::ir;
use crate::meta::Layer;

/// WinDivert's longest filter, in tests.
const TESTS_MAX: usize = 256;

/// Compiles a WinDivert filter for `layer` into a simplified IR test.
pub(crate) fn compile(src: &str, layer: Layer) -> Result<ir::Test, Diagnostic> {
    if layer == Layer::Ethernet {
        return Err(Diagnostic::error(
            Span::new(0, 0),
            "WinDivert filters have no ETHERNET layer",
        ));
    }
    let e = parse::parse(src, layer)?;
    if e.tests() > TESTS_MAX {
        return Err(
            Diagnostic::error(Span::new(0, src.len()), "the filter is too long")
                .help(format!("WinDivert accepts at most {TESTS_MAX} tests")),
        );
    }
    Ok(ir::simplify(lower::expr(&e, layer)))
}

fn layer_name(layer: Layer) -> &'static str {
    match layer {
        Layer::Network => "NETWORK",
        Layer::NetworkForward => "NETWORK_FORWARD",
        Layer::Flow => "FLOW",
        Layer::Socket => "SOCKET",
        Layer::Reflect => "REFLECT",
        Layer::Ethernet => "ETHERNET",
    }
}

// Layers a field is valid at, one bit per `Layer` value.
const N: u8 = 1 << Layer::Network as u8;
const M: u8 = 1 << Layer::NetworkForward as u8;
const F: u8 = 1 << Layer::Flow as u8;
const S: u8 = 1 << Layer::Socket as u8;
const R: u8 = 1 << Layer::Reflect as u8;

/// A protocol a header field belongs to, or that a protocol field tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Proto {
    Ip,
    Ipv6,
    Icmp,
    Icmpv6,
    Tcp,
    Udp,
}

/// Where `packet[i]` and the payload fields read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Base {
    Frame,
    Tcp,
    Udp,
}

/// How a field lowers to native IR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lower {
    /// `zero`, `true`, `false`.
    Const(u128),
    /// A number, absent when its header is.
    Num(Field),
    /// A flag of the metadata, always present: `outbound`, `loopback`.
    Flag(Field),
    /// A one-bit header field: `tcp.Syn`, `ip.DF`.
    Bit(Field, Proto),
    /// `ip`, `tcp`, …: 1 when the packet has that header.
    Present(Proto),
    /// A header length in 32-bit words; the native field counts bytes.
    Words(Field),
    /// `ip.SrcAddr`, `ip.DstAddr`.
    Addr4(Field),
    /// `ipv6.SrcAddr`, `ipv6.DstAddr`.
    Addr6(Field),
    /// `localAddr`, `remoteAddr`: either family.
    Addr(Field),
    /// `localPort` (`true`) or `remotePort`.
    Port(bool),
    /// `tcp.PayloadLength`, `udp.PayloadLength`: 0 when there is no payload.
    PayloadLen(Proto),
    /// `packet[i]`, `tcp.Payload16[i]`, …: a big-endian word of the given width.
    Data(Base, u8),
    /// `icmp.Body`, `icmpv6.Body`: bytes 4 to 7 of the message.
    Body(Proto),
}

/// A signed 128-bit value, as WinDivert keeps it: a sign and a magnitude.
type Num = (bool, u128);

/// The range WinDivert knows a field's values lie in. A comparison that the range decides is
/// replaced by `ty == result`, where `ty` is the field's protocol (or the constant 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Range {
    ty: Option<Proto>,
    lo: Num,
    hi: Num,
    /// The range is one value (`zero`, `true`, `false`), so equality is decided too.
    eq: bool,
}

/// A WinDivert field.
#[derive(Debug, PartialEq, Eq)]
struct Def {
    name: &'static str,
    layers: u8,
    lower: Lower,
    range: Option<Range>,
    /// Compared on all 128 bits; other fields compare only the low 32 bits of the value.
    big: bool,
}

impl Def {
    fn valid_at(&self, layer: Layer) -> bool {
        self.layers & (1 << layer as u8) != 0
    }

    /// The word width of an indexed field (`packet16[i]`).
    fn indexed(&self) -> Option<u8> {
        match self.lower {
            Lower::Data(_, w) => Some(w),
            _ => None,
        }
    }
}

const fn range(ty: Option<Proto>, lo: u128, hi: u128) -> Option<Range> {
    Some(Range {
        ty,
        lo: (false, lo),
        hi: (false, hi),
        eq: false,
    })
}

const U8: u128 = 0xff;
const U16: u128 = 0xffff;
const U32: u128 = 0xffff_ffff;
const U64: u128 = u64::MAX as u128;
const MAPPED: u128 = 0xffff << 32;

macro_rules! defs {
    ($($name:literal, $layers:expr, $lower:expr, $range:expr $(, $big:ident)?;)*) => {
        &[$(Def {
            name: $name,
            layers: $layers,
            lower: $lower,
            range: $range,
            big: defs!(@big $($big)?),
        },)*]
    };
    (@big) => { false };
    (@big big) => { true };
}

use Lower::*;
use Proto::{Icmp, Icmpv6, Ip, Ipv6, Tcp, Udp};

/// Every WinDivert field, with the layers it is valid at and the range WinDivert simplifies with.
static FIELDS: &[Def] = defs! {
    "zero", N | M | F | S | R, Const(0), Some(Range { ty: None, lo: (false, 0), hi: (false, 0), eq: true });
    "true", N | M | F | S | R, Const(1), Some(Range { ty: None, lo: (false, 1), hi: (false, 1), eq: true });
    "false", N | M | F | S | R, Const(0), Some(Range { ty: None, lo: (false, 0), hi: (false, 0), eq: true });
    "timestamp", N | M | F | S | R, Num(Field::Timestamp),
        Some(Range { ty: None, lo: (true, 1 << 63), hi: (false, (1 << 63) - 1), eq: false }), big;
    "event", N | M | F | S | R, Num(Field::Event), range(None, 0, 9);
    "outbound", N | F | S, Flag(Field::Outbound), range(None, 0, 1);
    "inbound", N | F | S, Flag(Field::Inbound), range(None, 0, 1);
    "ifIdx", N | M, Num(Field::Ifidx), range(None, 0, U32);
    "subIfIdx", N | M, Num(Field::Subifidx), range(None, 0, U32);
    "loopback", N | F | S, Flag(Field::Loopback), range(None, 0, 1);
    "impostor", N | M, Flag(Field::Impostor), range(None, 0, 1);
    "fragment", N | M, Flag(Field::Fragment), range(None, 0, 1);
    "endpointId", F | S, Num(Field::EndpointId), range(None, 0, U64), big;
    "parentEndpointId", F | S, Num(Field::ParentEndpointId), range(None, 0, U64), big;
    "processId", F | S | R, Num(Field::ProcessPid), range(None, 0, U32);
    "random8", N | M, Num(Field::Random8), range(None, 0, U8);
    "random16", N | M, Num(Field::Random16), range(None, 0, U16);
    "random32", N | M, Num(Field::Random32), range(None, 0, U32);
    "layer", R, Num(Field::Layer), range(None, 0, 4);
    "priority", R, Num(Field::Priority),
        Some(Range { ty: None, lo: (true, 30000), hi: (false, 30000), eq: false });
    "packet", N | M, Data(Base::Frame, 1), range(None, 0, U8);
    "packet16", N | M, Data(Base::Frame, 2), range(None, 0, U16);
    "packet32", N | M, Data(Base::Frame, 4), None;
    "length", N | M, Num(Field::FrameLen), range(None, 20, 40 + U16);
    "ip", N | M | F | S, Present(Ip), range(None, 0, 1);
    "ipv6", N | M | F | S, Present(Ipv6), range(None, 0, 1);
    "icmp", N | M | F | S, Present(Icmp), range(None, 0, 1);
    "icmpv6", N | M | F | S, Present(Icmpv6), range(None, 0, 1);
    "tcp", N | M | F | S, Present(Tcp), range(None, 0, 1);
    "udp", N | M | F | S, Present(Udp), range(None, 0, 1);
    "protocol", N | F | S, Num(Field::Protocol), range(None, 0, U8);
    "localAddr", N | F | S, Addr(Field::LocalAddr), range(None, 0, u128::MAX), big;
    "remoteAddr", N | F | S, Addr(Field::RemoteAddr), range(None, 0, u128::MAX), big;
    "localPort", N | F | S, Port(true), range(None, 0, U16);
    "remotePort", N | F | S, Port(false), range(None, 0, U16);
    "ip.HdrLength", N | M, Words(Field::IpHdrLen), range(Some(Ip), 0, 0xf);
    // WinDivert's range for the 8-bit TOS is 16 bits wide.
    "ip.TOS", N | M, Num(Field::IpDsfield), range(Some(Ip), 0, U16);
    "ip.Length", N | M, Num(Field::IpLen), range(Some(Ip), 0, U16);
    "ip.Id", N | M, Num(Field::IpId), range(Some(Ip), 0, U16);
    "ip.DF", N | M, Bit(Field::IpFlagsDf, Ip), range(Some(Ip), 0, 1);
    "ip.MF", N | M, Bit(Field::IpFlagsMf, Ip), range(Some(Ip), 0, 1);
    "ip.FragOff", N | M, Num(Field::IpFragOffset), range(Some(Ip), 0, 0x1fff);
    "ip.TTL", N | M, Num(Field::IpTtl), range(Some(Ip), 0, U8);
    "ip.Protocol", N | M, Num(Field::IpProto), range(Some(Ip), 0, U8);
    "ip.Checksum", N | M, Num(Field::IpChecksum), range(Some(Ip), 0, U16);
    "ip.SrcAddr", N | M, Addr4(Field::IpSrc), range(Some(Ip), MAPPED, MAPPED | U32), big;
    "ip.DstAddr", N | M, Addr4(Field::IpDst), range(Some(Ip), MAPPED, MAPPED | U32), big;
    "ipv6.TrafficClass", N | M, Num(Field::Ipv6Tclass), range(Some(Ipv6), 0, U8);
    "ipv6.FlowLabel", N | M, Num(Field::Ipv6Flow), range(Some(Ipv6), 0, 0xf_ffff);
    "ipv6.Length", N | M, Num(Field::Ipv6Plen), range(Some(Ipv6), 0, U16);
    "ipv6.NextHdr", N | M, Num(Field::Ipv6Nxt), range(Some(Ipv6), 0, U8);
    "ipv6.HopLimit", N | M, Num(Field::Ipv6Hlim), range(Some(Ipv6), 0, U8);
    "ipv6.SrcAddr", N | M, Addr6(Field::Ipv6Src), range(Some(Ipv6), 0, u128::MAX), big;
    "ipv6.DstAddr", N | M, Addr6(Field::Ipv6Dst), range(Some(Ipv6), 0, u128::MAX), big;
    "icmp.Type", N | M, Num(Field::IcmpType), range(Some(Icmp), 0, U8);
    "icmp.Code", N | M, Num(Field::IcmpCode), range(Some(Icmp), 0, U8);
    "icmp.Checksum", N | M, Num(Field::IcmpChecksum), range(Some(Icmp), 0, U16);
    "icmp.Body", N | M, Body(Icmp), None;
    "icmpv6.Type", N | M, Num(Field::Icmpv6Type), range(Some(Icmpv6), 0, U8);
    "icmpv6.Code", N | M, Num(Field::Icmpv6Code), range(Some(Icmpv6), 0, U8);
    "icmpv6.Checksum", N | M, Num(Field::Icmpv6Checksum), range(Some(Icmpv6), 0, U16);
    "icmpv6.Body", N | M, Body(Icmpv6), None;
    "tcp.SrcPort", N | M, Num(Field::TcpSrcport), range(Some(Tcp), 0, U16);
    "tcp.DstPort", N | M, Num(Field::TcpDstport), range(Some(Tcp), 0, U16);
    "tcp.SeqNum", N | M, Num(Field::TcpSeqRaw), None;
    "tcp.AckNum", N | M, Num(Field::TcpAckRaw), None;
    "tcp.HdrLength", N | M, Words(Field::TcpHdrLen), range(Some(Tcp), 0, 0xf);
    "tcp.Urg", N | M, Bit(Field::TcpFlagsUrg, Tcp), range(Some(Tcp), 0, 1);
    "tcp.Ack", N | M, Bit(Field::TcpFlagsAck, Tcp), range(Some(Tcp), 0, 1);
    "tcp.Psh", N | M, Bit(Field::TcpFlagsPush, Tcp), range(Some(Tcp), 0, 1);
    "tcp.Rst", N | M, Bit(Field::TcpFlagsReset, Tcp), range(Some(Tcp), 0, 1);
    "tcp.Syn", N | M, Bit(Field::TcpFlagsSyn, Tcp), range(Some(Tcp), 0, 1);
    "tcp.Fin", N | M, Bit(Field::TcpFlagsFin, Tcp), range(Some(Tcp), 0, 1);
    "tcp.Window", N | M, Num(Field::TcpWindowSizeValue), range(Some(Tcp), 0, U16);
    "tcp.Checksum", N | M, Num(Field::TcpChecksum), range(Some(Tcp), 0, U16);
    "tcp.UrgPtr", N | M, Num(Field::TcpUrgentPointer), range(Some(Tcp), 0, U16);
    "tcp.PayloadLength", N | M, PayloadLen(Tcp), range(Some(Tcp), 0, U16);
    "tcp.Payload", N | M, Data(Base::Tcp, 1), range(Some(Tcp), 0, U8);
    "tcp.Payload16", N | M, Data(Base::Tcp, 2), range(Some(Tcp), 0, U16);
    "tcp.Payload32", N | M, Data(Base::Tcp, 4), range(Some(Tcp), 0, U32);
    "udp.SrcPort", N | M, Num(Field::UdpSrcport), range(Some(Udp), 0, U16);
    "udp.DstPort", N | M, Num(Field::UdpDstport), range(Some(Udp), 0, U16);
    "udp.Length", N | M, Num(Field::UdpLength), range(Some(Udp), 0, U16);
    "udp.Checksum", N | M, Num(Field::UdpChecksum), range(Some(Udp), 0, U16);
    "udp.PayloadLength", N | M, PayloadLen(Udp), range(Some(Udp), 0, U16);
    "udp.Payload", N | M, Data(Base::Udp, 1), range(Some(Udp), 0, U8);
    "udp.Payload16", N | M, Data(Base::Udp, 2), range(Some(Udp), 0, U16);
    "udp.Payload32", N | M, Data(Base::Udp, 4), range(Some(Udp), 0, U32);
};

/// A layer-specific macro: its value at a layer, if it has one there.
struct Macro {
    name: &'static str,
    value: fn(Layer) -> Option<u32>,
}

macro_rules! macros {
    ($($name:literal => $value:expr;)*) => {
        &[$(Macro { name: $name, value: $value },)*]
    };
}

static MACROS: &[Macro] = macros! {
    "TRUE" => |_| Some(1);
    "FALSE" => |_| Some(0);
    "TCP" => |_| Some(6);
    "UDP" => |_| Some(17);
    "ICMP" => |_| Some(1);
    "ICMPV6" => |_| Some(58);
    "NETWORK" => |_| Some(0);
    "NETWORK_FORWARD" => |_| Some(1);
    "FLOW" => |_| Some(2);
    "SOCKET" => |_| Some(3);
    "REFLECT" => |_| Some(4);
    "PACKET" => |l| matches!(l, Layer::Network | Layer::NetworkForward).then_some(0);
    "ESTABLISHED" => |l| (l == Layer::Flow).then_some(1);
    "DELETED" => |l| (l == Layer::Flow).then_some(2);
    "BIND" => |l| (l == Layer::Socket).then_some(3);
    "CONNECT" => |l| (l == Layer::Socket).then_some(4);
    "LISTEN" => |l| (l == Layer::Socket).then_some(5);
    "ACCEPT" => |l| (l == Layer::Socket).then_some(6);
    "OPEN" => |l| (l == Layer::Reflect).then_some(8);
    "CLOSE" => |l| match l {
        Layer::Socket => Some(7),
        Layer::Reflect => Some(9),
        _ => None,
    };
};

#[cfg(test)]
pub(crate) use parse::shape;
