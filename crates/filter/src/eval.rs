//! IR interpreter. It does not allocate, so it can run in kernel contexts.

use core::cmp::Ordering;
use core::net::IpAddr;

use avulse_proto::{Network, Packet, VlanTag, ethertype};

use crate::fields::Field;
use crate::ir::{CmpOp, Lit, Quant, SetItem, SliceEnd, Test, Value};
use crate::meta::Meta;

/// Most occurrences a value can have (two VLAN tags, source and destination).
const MAX: usize = 4;

#[derive(Clone, Copy, Debug)]
enum V<'a> {
    Bool(bool),
    Uint(u64),
    Ipv4([u8; 4], u8),
    Ipv6([u8; 16], u8),
    Ether([u8; 6]),
    Bytes(&'a [u8]),
    /// Bytes copied out of an address by a slice.
    Owned([u8; 16], u8),
}

impl V<'_> {
    fn bytes(&self) -> Option<&[u8]> {
        match self {
            V::Ipv4(a, _) => Some(a),
            V::Ipv6(a, _) => Some(a),
            V::Ether(m) => Some(m),
            V::Bytes(b) => Some(b),
            V::Owned(a, n) => Some(&a[..*n as usize]),
            V::Bool(_) | V::Uint(_) => None,
        }
    }

    fn truthy(&self) -> bool {
        match self {
            V::Bool(b) => *b,
            V::Uint(v) => *v != 0,
            v => v.bytes().is_some_and(|b| !b.is_empty()),
        }
    }
}

struct Vals<'a> {
    n: usize,
    v: [V<'a>; MAX],
}

impl<'a> Vals<'a> {
    fn new() -> Self {
        Vals {
            n: 0,
            v: [V::Bool(false); MAX],
        }
    }

    fn one(v: V<'a>) -> Self {
        let mut s = Self::new();
        s.push(v);
        s
    }

    fn push(&mut self, v: V<'a>) {
        if self.n < MAX {
            self.v[self.n] = v;
            self.n += 1;
        }
    }

    fn opt(&mut self, v: Option<V<'a>>) {
        if let Some(v) = v {
            self.push(v);
        }
    }

    fn as_slice(&self) -> &[V<'a>] {
        &self.v[..self.n]
    }
}

struct Cx<'a> {
    pkt: &'a Packet<'a>,
    meta: &'a Meta<'a>,
}

pub(crate) fn matches(t: &Test, pkt: &Packet<'_>, meta: &Meta<'_>) -> bool {
    test(t, &Cx { pkt, meta })
}

fn test<'a>(t: &'a Test, cx: &Cx<'a>) -> bool {
    match t {
        Test::Const(b) => *b,
        Test::Exists(v) => value(v, cx).n > 0,
        Test::Truthy(v) => value(v, cx).as_slice().iter().any(V::truthy),
        Test::Cmp {
            lhs,
            op,
            quant,
            rhs,
        } => {
            let (l, r) = (value(lhs, cx), value(rhs, cx));
            pairs(*quant, l.as_slice(), r.as_slice(), |a, b| {
                compare(*op, a, b)
            })
        }
        Test::Member {
            lhs,
            set,
            quant,
            negate,
        } => {
            let l = value(lhs, cx);
            let l = l.as_slice();
            !l.is_empty() && quantify(*quant, l.iter().map(|v| member(v, set))) != *negate
        }
        Test::Contains { lhs, rhs, quant } => {
            let (l, r) = (value(lhs, cx), value(rhs, cx));
            let bytes_only = |v: &&V<'_>| v.bytes().is_some();
            let has = |vals: &Vals<'_>| vals.as_slice().iter().any(|v| v.bytes().is_some());
            has(&l)
                && has(&r)
                && quantify(
                    *quant,
                    l.as_slice().iter().filter(bytes_only).flat_map(|a| {
                        r.as_slice()
                            .iter()
                            .filter(bytes_only)
                            .map(move |b| matches!((a.bytes(), b.bytes()), (Some(h), Some(n)) if contains(h, n)))
                    }),
                )
        }
        Test::Not(t) => !test(t, cx),
        Test::And(v) => v.iter().all(|t| test(t, cx)),
        Test::Or(v) => v.iter().any(|t| test(t, cx)),
        Test::Xor(a, b) => test(a, cx) != test(b, cx),
    }
}

fn quantify(q: Quant, mut it: impl Iterator<Item = bool>) -> bool {
    match q {
        Quant::Any => it.any(|b| b),
        Quant::All => it.all(|b| b),
    }
}

/// `pred` over every pair of occurrences, under `q`; false when either side is empty.
fn pairs<'a>(q: Quant, l: &[V<'a>], r: &[V<'a>], pred: impl Fn(&V<'a>, &V<'a>) -> bool) -> bool {
    !l.is_empty()
        && !r.is_empty()
        && quantify(
            q,
            l.iter()
                .flat_map(|a| r.iter().map(move |b| (a, b)))
                .map(|(a, b)| pred(a, b)),
        )
}

fn compare(op: CmpOp, a: &V<'_>, b: &V<'_>) -> bool {
    match op {
        CmpOp::Eq => eq(a, b),
        CmpOp::Ne => !eq(a, b),
        CmpOp::Lt => ord(a, b) == Some(Ordering::Less),
        CmpOp::Le => matches!(ord(a, b), Some(Ordering::Less | Ordering::Equal)),
        CmpOp::Gt => ord(a, b) == Some(Ordering::Greater),
        CmpOp::Ge => matches!(ord(a, b), Some(Ordering::Greater | Ordering::Equal)),
    }
}

fn member(v: &V<'_>, set: &[SetItem]) -> bool {
    set.iter().any(|item| match item {
        SetItem::One(l) => eq(v, &lit(l)),
        SetItem::Range(lo, hi) => {
            matches!(ord(v, &lit(lo)), Some(Ordering::Greater | Ordering::Equal))
                && matches!(ord(v, &lit(hi)), Some(Ordering::Less | Ordering::Equal))
        }
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
}

fn prefix_eq(a: &[u8], b: &[u8], bits: u8) -> bool {
    let (full, rest) = ((bits / 8) as usize, bits % 8);
    if a[..full] != b[..full] {
        return false;
    }
    rest == 0 || {
        let mask = 0xffu8 << (8 - rest);
        a[full] & mask == b[full] & mask
    }
}

fn eq(a: &V<'_>, b: &V<'_>) -> bool {
    match (a, b) {
        (V::Uint(x), V::Uint(y)) => x == y,
        (V::Bool(x), V::Bool(y)) => x == y,
        (V::Ipv4(x, p), V::Ipv4(y, q)) => prefix_eq(x, y, *p.min(q)),
        (V::Ipv6(x, p), V::Ipv6(y, q)) => prefix_eq(x, y, *p.min(q)),
        (V::Ipv4(..), V::Ipv6(..)) | (V::Ipv6(..), V::Ipv4(..)) => false,
        _ => matches!((a.bytes(), b.bytes()), (Some(x), Some(y)) if x == y),
    }
}

fn ord(a: &V<'_>, b: &V<'_>) -> Option<Ordering> {
    match (a, b) {
        (V::Uint(x), V::Uint(y)) => Some(x.cmp(y)),
        (V::Ipv4(..), V::Ipv6(..)) | (V::Ipv6(..), V::Ipv4(..)) => None,
        (V::Bool(_), _) | (_, V::Bool(_)) | (V::Uint(_), _) | (_, V::Uint(_)) => None,
        _ => Some(a.bytes()?.cmp(b.bytes()?)),
    }
}

fn lit(l: &Lit) -> V<'_> {
    match l {
        Lit::Bool(b) => V::Bool(*b),
        Lit::Uint(v) => V::Uint(*v),
        Lit::Ipv4(a, p) => V::Ipv4(*a, *p),
        Lit::Ipv6(a, p) => V::Ipv6(*a, *p),
        Lit::Ether(m) => V::Ether(*m),
        Lit::Bytes(b) => V::Bytes(b),
    }
}

fn value<'a>(v: &'a Value, cx: &Cx<'a>) -> Vals<'a> {
    match v {
        Value::Lit(l) => Vals::one(lit(l)),
        Value::Field(f) => load(*f, cx),
        Value::Slice(base, s) => {
            let mut out = Vals::new();
            for x in value(base, cx).as_slice() {
                out.opt(slice(*x, s.start, s.end));
            }
            out
        }
        Value::BitAnd(a, b) => {
            let (a, b) = (value(a, cx), value(b, cx));
            let mut out = Vals::new();
            for x in a.as_slice() {
                for y in b.as_slice() {
                    if let (V::Uint(x), V::Uint(y)) = (x, y) {
                        out.push(V::Uint(x & y));
                    }
                }
            }
            out
        }
        Value::Len(base) => {
            let mut out = Vals::new();
            for x in value(base, cx).as_slice() {
                out.opt(x.bytes().map(|b| V::Uint(b.len() as u64)));
            }
            out
        }
        Value::Count(base) => Vals::one(V::Uint(value(base, cx).n as u64)),
    }
}

fn slice<'a>(v: V<'a>, start: i64, end: SliceEnd) -> Option<V<'a>> {
    let len = v.bytes()?.len() as i64;
    let abs = |i: i64| if i < 0 { len + i } else { i };
    let s = abs(start);
    let e = match end {
        SliceEnd::Len(n) => s + n,
        SliceEnd::Inclusive(e) => abs(e) + 1,
        SliceEnd::Open => len,
    };
    if s < 0 || e < s || e > len {
        return None;
    }
    let (s, e) = (s as usize, e as usize);
    Some(match v {
        V::Bytes(b) => V::Bytes(&b[s..e]),
        other => {
            let src = other.bytes()?;
            let mut a = [0; 16];
            a[..e - s].copy_from_slice(&src[s..e]);
            V::Owned(a, (e - s) as u8)
        }
    })
}

fn ip(a: IpAddr) -> V<'static> {
    match a {
        IpAddr::V4(a) => V::Ipv4(a.octets(), 32),
        IpAddr::V6(a) => V::Ipv6(a.octets(), 128),
    }
}

/// VLAN tags with their position: the 802.1ad (TPID 0x88a8) tags when `ad`, else the others,
/// which Wireshark dissects as `vlan`.
fn tags<'p>(p: &'p Packet<'_>, ad: bool) -> impl Iterator<Item = (usize, &'p VlanTag)> {
    p.vlans()
        .iter()
        .enumerate()
        .filter(move |(_, t)| (t.tpid == ethertype::QINQ) == ad)
}

/// Source and destination addresses of the IP header.
fn ip_pair(pkt: &Packet<'_>) -> Option<(V<'static>, V<'static>)> {
    match pkt.network() {
        Network::Ipv4(h) => Some((V::Ipv4(h.src().octets(), 32), V::Ipv4(h.dst().octets(), 32))),
        Network::Ipv6(h) => Some((
            V::Ipv6(h.src().octets(), 128),
            V::Ipv6(h.dst().octets(), 128),
        )),
        _ => None,
    }
}

fn port_pair(pkt: &Packet<'_>) -> Option<(u16, u16)> {
    pkt.tcp()
        .map(|t| (t.src_port(), t.dst_port()))
        .or_else(|| pkt.udp().map(|u| (u.src_port(), u.dst_port())))
}

fn load<'a>(f: Field, cx: &Cx<'a>) -> Vals<'a> {
    let p = cx.pkt;
    let m = cx.meta;
    let mut o = Vals::new();
    let u = |v: u64| Some(V::Uint(v));
    let b = |v: bool| Some(V::Bool(v));
    match f {
        Field::Frame => o.push(V::Bytes(p.data())),
        Field::FrameLen | Field::FrameCapLen => o.push(V::Uint(p.data().len() as u64)),
        Field::FrameInterfaceName | Field::Iface => o.opt(m.iface.map(|s| V::Bytes(s.as_bytes()))),

        Field::Eth => o.opt(p.eth().map(|e| V::Bytes(e.bytes()))),
        Field::EthDst => o.opt(p.eth().map(|e| V::Ether(e.dst().0))),
        Field::EthSrc => o.opt(p.eth().map(|e| V::Ether(e.src().0))),
        Field::EthAddr => {
            if let Some(e) = p.eth() {
                o.push(V::Ether(e.dst().0));
                o.push(V::Ether(e.src().0));
            }
        }
        Field::EthType => o.opt(p.eth().and_then(|e| u(e.ethertype() as u64))),

        Field::Vlan | Field::Ieee8021ad => {
            for (i, _) in tags(p, f == Field::Ieee8021ad) {
                // The tag body (TCI and inner EtherType) follows each TPID.
                let off = 14 + 4 * i;
                o.opt(p.data().get(off..off + 4).map(V::Bytes));
            }
        }
        Field::VlanPriority => {
            tags(p, false).for_each(|(_, t)| o.push(V::Uint(t.priority() as u64)))
        }
        Field::VlanDei => tags(p, false).for_each(|(_, t)| o.push(V::Bool(t.dei()))),
        Field::VlanId => tags(p, false).for_each(|(_, t)| o.push(V::Uint(t.id() as u64))),
        Field::VlanEtype => tags(p, false).for_each(|(_, t)| o.push(V::Uint(t.ethertype as u64))),
        Field::Ieee8021adPriority => {
            tags(p, true).for_each(|(_, t)| o.push(V::Uint(t.priority() as u64)))
        }
        Field::Ieee8021adDei => tags(p, true).for_each(|(_, t)| o.push(V::Uint(t.dei() as u64))),
        Field::Ieee8021adId => tags(p, true).for_each(|(_, t)| o.push(V::Uint(t.id() as u64))),

        Field::Arp => o.opt(p.arp().map(|a| V::Bytes(a.bytes()))),
        Field::ArpHwType => o.opt(p.arp().and_then(|a| u(a.hw_type() as u64))),
        Field::ArpProtoType => o.opt(p.arp().and_then(|a| u(a.proto_type() as u64))),
        Field::ArpHwSize => o.opt(p.arp().and_then(|a| u(a.hw_size() as u64))),
        Field::ArpProtoSize => o.opt(p.arp().and_then(|a| u(a.proto_size() as u64))),
        Field::ArpOpcode => o.opt(p.arp().and_then(|a| u(a.opcode() as u64))),
        Field::ArpSrcHwMac => o.opt(p.arp().and_then(|a| a.sender_mac()).map(|m| V::Ether(m.0))),
        Field::ArpDstHwMac => o.opt(p.arp().and_then(|a| a.target_mac()).map(|m| V::Ether(m.0))),
        Field::ArpSrcProtoIpv4 => o.opt(
            p.arp()
                .and_then(|a| a.sender_ipv4())
                .map(|a| V::Ipv4(a.octets(), 32)),
        ),
        Field::ArpDstProtoIpv4 => o.opt(
            p.arp()
                .and_then(|a| a.target_ipv4())
                .map(|a| V::Ipv4(a.octets(), 32)),
        ),

        Field::Ip => o.opt(p.ipv4().map(|h| V::Bytes(h.bytes()))),
        // Wireshark's IPv6 dissector also sets `ip.version`.
        Field::IpVersion => o.opt(
            p.ipv4()
                .map(|h| h.version())
                .or(p.ipv6().map(|h| h.version()))
                .map(|v| V::Uint(v as u64)),
        ),
        Field::IpHdrLen => o.opt(p.ipv4().and_then(|h| u(h.header_len() as u64))),
        Field::IpDsfield => o.opt(p.ipv4().and_then(|h| u(h.dsfield() as u64))),
        Field::IpDsfieldDscp => o.opt(p.ipv4().and_then(|h| u(h.dscp() as u64))),
        Field::IpDsfieldEcn => o.opt(p.ipv4().and_then(|h| u(h.ecn() as u64))),
        Field::IpLen => o.opt(p.ipv4().and_then(|h| u(h.total_len() as u64))),
        Field::IpId => o.opt(p.ipv4().and_then(|h| u(h.id() as u64))),
        Field::IpFlags => o.opt(p.ipv4().and_then(|h| u(h.flags() as u64))),
        Field::IpFlagsRb => o.opt(p.ipv4().and_then(|h| b(h.reserved_flag()))),
        Field::IpFlagsDf => o.opt(p.ipv4().and_then(|h| b(h.dont_fragment()))),
        Field::IpFlagsMf => o.opt(p.ipv4().and_then(|h| b(h.more_fragments()))),
        Field::IpFragOffset => o.opt(p.ipv4().and_then(|h| u(h.frag_offset() as u64))),
        Field::IpTtl => o.opt(p.ipv4().and_then(|h| u(h.ttl() as u64))),
        Field::IpProto => o.opt(p.ipv4().and_then(|h| u(h.protocol() as u64))),
        Field::IpChecksum => o.opt(p.ipv4().and_then(|h| u(h.checksum() as u64))),
        Field::IpSrc => o.opt(p.ipv4().map(|h| V::Ipv4(h.src().octets(), 32))),
        Field::IpDst => o.opt(p.ipv4().map(|h| V::Ipv4(h.dst().octets(), 32))),
        Field::IpAddr => {
            if let Some(h) = p.ipv4() {
                o.push(V::Ipv4(h.src().octets(), 32));
                o.push(V::Ipv4(h.dst().octets(), 32));
            }
        }

        // Like Wireshark's `ipv6` protocol item, the fixed header and the extension headers.
        Field::Ipv6 => o.opt(p.ipv6().and_then(|_| {
            let start = p.l3_offset()?;
            let end = p.l4_offset().unwrap_or(p.payload_range().start);
            p.data().get(start..end).map(V::Bytes)
        })),
        Field::Ipv6Version => o.opt(p.ipv6().and_then(|h| u(h.version() as u64))),
        Field::Ipv6Tclass => o.opt(p.ipv6().and_then(|h| u(h.traffic_class() as u64))),
        Field::Ipv6TclassDscp => o.opt(p.ipv6().and_then(|h| u(h.dscp() as u64))),
        Field::Ipv6TclassEcn => o.opt(p.ipv6().and_then(|h| u(h.ecn() as u64))),
        Field::Ipv6Flow => o.opt(p.ipv6().and_then(|h| u(h.flow_label() as u64))),
        Field::Ipv6Plen => o.opt(p.ipv6().and_then(|h| u(h.payload_len() as u64))),
        Field::Ipv6Nxt => o.opt(p.ipv6().and_then(|h| u(h.next_header() as u64))),
        Field::Ipv6Hlim => o.opt(p.ipv6().and_then(|h| u(h.hop_limit() as u64))),
        Field::Ipv6Src => o.opt(p.ipv6().map(|h| V::Ipv6(h.src().octets(), 128))),
        Field::Ipv6Dst => o.opt(p.ipv6().map(|h| V::Ipv6(h.dst().octets(), 128))),
        Field::Ipv6Addr => {
            if let Some(h) = p.ipv6() {
                o.push(V::Ipv6(h.src().octets(), 128));
                o.push(V::Ipv6(h.dst().octets(), 128));
            }
        }
        Field::Ipv6FraghdrOffset | Field::Ipv6FraghdrMore | Field::Ipv6FraghdrIdent => {
            if let (Some(_), Some(fr)) = (p.ipv6(), p.fragment()) {
                o.push(match f {
                    Field::Ipv6FraghdrOffset => V::Uint(fr.offset as u64),
                    Field::Ipv6FraghdrMore => V::Bool(fr.more),
                    _ => V::Uint(fr.id as u64),
                });
            }
        }

        Field::Tcp => o.opt(p.tcp().map(|t| V::Bytes(t.bytes()))),
        Field::TcpSrcport => o.opt(p.tcp().and_then(|t| u(t.src_port() as u64))),
        Field::TcpDstport => o.opt(p.tcp().and_then(|t| u(t.dst_port() as u64))),
        Field::TcpPort => {
            if let Some(t) = p.tcp() {
                o.push(V::Uint(t.src_port() as u64));
                o.push(V::Uint(t.dst_port() as u64));
            }
        }
        Field::TcpSeqRaw => o.opt(p.tcp().and_then(|t| u(t.seq() as u64))),
        Field::TcpAckRaw => o.opt(p.tcp().and_then(|t| u(t.ack() as u64))),
        Field::TcpHdrLen => o.opt(p.tcp().and_then(|t| u(t.header_len() as u64))),
        Field::TcpFlags => o.opt(p.tcp().and_then(|t| u(t.flags() as u64))),
        Field::TcpFlagsRes => o.opt(p.tcp().and_then(|t| b(t.reserved() != 0))),
        Field::TcpFlagsAe => o.opt(p.tcp().and_then(|t| b(t.has(avulse_proto::Tcp::AE)))),
        Field::TcpFlagsCwr => o.opt(p.tcp().and_then(|t| b(t.has(avulse_proto::Tcp::CWR)))),
        Field::TcpFlagsEce => o.opt(p.tcp().and_then(|t| b(t.has(avulse_proto::Tcp::ECE)))),
        Field::TcpFlagsUrg => o.opt(p.tcp().and_then(|t| b(t.has(avulse_proto::Tcp::URG)))),
        Field::TcpFlagsAck => o.opt(p.tcp().and_then(|t| b(t.has(avulse_proto::Tcp::ACK)))),
        Field::TcpFlagsPush => o.opt(p.tcp().and_then(|t| b(t.has(avulse_proto::Tcp::PSH)))),
        Field::TcpFlagsReset => o.opt(p.tcp().and_then(|t| b(t.has(avulse_proto::Tcp::RST)))),
        Field::TcpFlagsSyn => o.opt(p.tcp().and_then(|t| b(t.has(avulse_proto::Tcp::SYN)))),
        Field::TcpFlagsFin => o.opt(p.tcp().and_then(|t| b(t.has(avulse_proto::Tcp::FIN)))),
        Field::TcpWindowSizeValue => o.opt(p.tcp().and_then(|t| u(t.window() as u64))),
        Field::TcpChecksum => o.opt(p.tcp().and_then(|t| u(t.checksum() as u64))),
        Field::TcpUrgentPointer => o.opt(p.tcp().and_then(|t| u(t.urgent_ptr() as u64))),
        // Without reassembly, Wireshark leaves `tcp.len` unset on a first fragment.
        Field::TcpLen => o.opt(
            p.tcp()
                .filter(|_| p.fragment().is_none())
                .and_then(|_| u(p.payload().len() as u64)),
        ),
        Field::TcpPayload => o.opt(
            p.tcp()
                .filter(|_| !p.payload().is_empty())
                .map(|_| V::Bytes(p.payload())),
        ),

        Field::Udp => o.opt(p.udp().map(|h| V::Bytes(h.bytes()))),
        Field::UdpSrcport => o.opt(p.udp().and_then(|h| u(h.src_port() as u64))),
        Field::UdpDstport => o.opt(p.udp().and_then(|h| u(h.dst_port() as u64))),
        Field::UdpPort => {
            if let Some(h) = p.udp() {
                o.push(V::Uint(h.src_port() as u64));
                o.push(V::Uint(h.dst_port() as u64));
            }
        }
        Field::UdpLength => o.opt(p.udp().and_then(|h| u(h.length() as u64))),
        Field::UdpChecksum => o.opt(p.udp().and_then(|h| u(h.checksum() as u64))),
        Field::UdpPayload => o.opt(
            p.udp()
                .filter(|_| !p.payload().is_empty())
                .map(|_| V::Bytes(p.payload())),
        ),

        Field::Icmp => o.opt(p.icmp().map(|i| V::Bytes(i.bytes()))),
        Field::IcmpType => o.opt(p.icmp().and_then(|i| u(i.icmp_type() as u64))),
        Field::IcmpCode => o.opt(p.icmp().and_then(|i| u(i.code() as u64))),
        Field::IcmpChecksum => o.opt(p.icmp().and_then(|i| u(i.checksum() as u64))),
        Field::IcmpIdent => o.opt(p.icmp().and_then(|i| i.ident()).map(|v| V::Uint(v as u64))),
        Field::IcmpSeq => o.opt(p.icmp().and_then(|i| i.seq()).map(|v| V::Uint(v as u64))),

        Field::Icmpv6 => o.opt(p.icmpv6().map(|i| V::Bytes(i.bytes()))),
        Field::Icmpv6Type => o.opt(p.icmpv6().and_then(|i| u(i.icmp_type() as u64))),
        Field::Icmpv6Code => o.opt(p.icmpv6().and_then(|i| u(i.code() as u64))),
        Field::Icmpv6Checksum => o.opt(p.icmpv6().and_then(|i| u(i.checksum() as u64))),
        Field::Icmpv6EchoIdentifier => o.opt(
            p.icmpv6()
                .and_then(|i| i.echo_ident())
                .map(|v| V::Uint(v as u64)),
        ),
        Field::Icmpv6EchoSequenceNumber => o.opt(
            p.icmpv6()
                .and_then(|i| i.echo_seq())
                .map(|v| V::Uint(v as u64)),
        ),

        Field::Inbound => o.push(V::Bool(!m.outbound)),
        Field::Outbound => o.push(V::Bool(m.outbound)),
        Field::Loopback => o.push(V::Bool(m.loopback)),
        Field::Impostor => o.push(V::Bool(m.impostor)),
        Field::Fragment => o.push(V::Bool(p.fragment().is_some())),
        Field::Ifidx => o.push(V::Uint(m.ifidx as u64)),
        Field::Subifidx => o.push(V::Uint(m.subifidx as u64)),
        Field::Layer => o.push(V::Uint(m.layer as u64)),
        Field::Event => o.push(V::Uint(m.event as u64)),
        Field::Protocol => o.opt(
            m.flow
                .map(|fl| fl.protocol)
                .or(p.ip_protocol())
                .map(|v| V::Uint(v as u64)),
        ),
        Field::LocalAddr | Field::RemoteAddr => {
            let local = f == Field::LocalAddr;
            if let Some(fl) = m.flow {
                o.push(ip(if local { fl.local_addr } else { fl.remote_addr }));
            } else if let Some((src, dst)) = ip_pair(p) {
                o.push(if local == m.outbound { src } else { dst });
            }
        }
        Field::LocalPort | Field::RemotePort => {
            let local = f == Field::LocalPort;
            if let Some(fl) = m.flow {
                o.push(V::Uint(
                    if local { fl.local_port } else { fl.remote_port } as u64
                ));
            } else if let Some((src, dst)) = port_pair(p) {
                o.push(V::Uint(if local == m.outbound { src } else { dst } as u64));
            }
        }
        Field::ProcessPid => o.opt(m.process_id.map(|v| V::Uint(v as u64))),
        Field::ProcessName => o.opt(m.process_name.map(|s| V::Bytes(s.as_bytes()))),
        Field::EndpointId => o.opt(m.endpoint_id.map(V::Uint)),
        Field::ParentEndpointId => o.opt(m.parent_endpoint_id.map(V::Uint)),
    }
    o
}
