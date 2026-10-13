//! IR interpreter. It does not allocate, so it can run in kernel contexts.

use core::cmp::Ordering;
use core::net::IpAddr;

use avulse_proto::{Network, Packet, VlanTag, ethertype};

use crate::fields::Field;
use crate::ir::{self, CmpOp, Lit, Quant, SetItem, Slice, SliceEnd, Test, Value};
use crate::meta::Meta;
use crate::regex::{self, Regex};

/// Most occurrences a value can have (two VLAN tags, source and destination).
const MAX: usize = 4;

/// Longest byte string computed during evaluation (slices of addresses, `&` on bytes). Longer
/// results give no value.
const OWNED: usize = 32;

#[derive(Clone, Copy, Debug)]
enum V<'a> {
    Bool(bool),
    Uint(u64),
    Int(i64),
    Ipv4([u8; 4], u8),
    Ipv6([u8; 16], u8),
    Ether([u8; 6]),
    Bytes(&'a [u8]),
    /// A computed byte string: a slice of an address, or the result of `&`.
    Owned([u8; OWNED], u8),
    /// A string seen through `upper()` (`true`) or `lower()`, folded as it is compared.
    Folded(&'a [u8], bool),
}

impl<'a> V<'a> {
    /// The bytes of the value, as stored (before any case folding).
    fn bytes(&self) -> Option<&[u8]> {
        match self {
            V::Ipv4(a, _) => Some(a),
            V::Ipv6(a, _) => Some(a),
            V::Ether(m) => Some(m),
            V::Bytes(b) | V::Folded(b, _) => Some(b),
            V::Owned(a, n) => a.get(..*n as usize),
            V::Bool(_) | V::Uint(_) | V::Int(_) => None,
        }
    }

    /// The bytes of the value as comparisons see them.
    fn seq(&self) -> Option<Seq<'_>> {
        match self {
            V::Folded(b, upper) => Some(Seq {
                b,
                fold: Some(*upper),
            }),
            v => v.bytes().map(|b| Seq { b, fold: None }),
        }
    }

    /// The value as a signed integer, for arithmetic.
    fn int(&self) -> Option<i64> {
        match self {
            V::Uint(v) => i64::try_from(*v).ok(),
            V::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// The value as a number that holds every unsigned and signed value, for comparisons.
    fn num(&self) -> Option<i128> {
        match self {
            V::Uint(v) => Some(*v as i128),
            V::Int(v) => Some(*v as i128),
            _ => None,
        }
    }

    fn truthy(&self) -> bool {
        match self {
            V::Bool(b) => *b,
            V::Uint(v) => *v != 0,
            V::Int(v) => *v != 0,
            // Wireshark's NOT_ALL_ZERO: some byte is set.
            v => v.bytes().is_some_and(|b| b.iter().any(|&c| c != 0)),
        }
    }
}

/// A byte string, possibly folded to upper or lower case on the fly, so that `upper()` and
/// `lower()` need no copy.
#[derive(Clone, Copy)]
struct Seq<'a> {
    b: &'a [u8],
    fold: Option<bool>,
}

impl<'a> Seq<'a> {
    fn len(&self) -> usize {
        self.b.len()
    }

    fn iter(self) -> impl Iterator<Item = u8> + 'a {
        self.b.iter().map(move |&c| match self.fold {
            Some(true) => c.to_ascii_uppercase(),
            Some(false) => c.to_ascii_lowercase(),
            None => c,
        })
    }

    fn eq(self, other: Seq<'_>) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
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
    regexes: &'a [Regex],
}

pub(crate) fn matches(t: &Test, pkt: &Packet<'_>, meta: &Meta<'_>, regexes: &[Regex]) -> bool {
    test(t, &Cx { pkt, meta, regexes })
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
            let bytes_only = |v: &&V<'_>| v.seq().is_some();
            let has = |vals: &Vals<'_>| vals.as_slice().iter().any(|v| v.seq().is_some());
            has(&l)
                && has(&r)
                && quantify(
                    *quant,
                    l.as_slice().iter().filter(bytes_only).flat_map(|a| {
                        r.as_slice().iter().filter(bytes_only).map(
                            move |b| matches!((a.seq(), b.seq()), (Some(h), Some(n)) if contains(h, n)),
                        )
                    }),
                )
        }
        Test::Matches {
            lhs, index, quant, ..
        } => {
            let Some(re) = cx.regexes.get(*index) else {
                return false;
            };
            let l = value(lhs, cx);
            let l = l.as_slice();
            !l.is_empty() && quantify(*quant, l.iter().map(|v| regex_match(re, v)))
        }
        Test::Not(t) => !test(t, cx),
        Test::And(v) => v.iter().all(|t| test(t, cx)),
        Test::Or(v) => v.iter().any(|t| test(t, cx)),
        Test::Xor(a, b) => test(a, cx) != test(b, cx),
    }
}

/// Runs a pattern over a value. This is the one place where evaluation may allocate (inside the
/// regex engine, and to fold `upper()`/`lower()` strings): `matches` is user space only.
fn regex_match(re: &Regex, v: &V<'_>) -> bool {
    match v {
        V::Folded(..) => v.seq().is_some_and(|s| {
            let folded: alloc::vec::Vec<u8> = s.iter().collect();
            regex::is_match(re, &folded)
        }),
        v => v.bytes().is_some_and(|b| regex::is_match(re, b)),
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

fn contains(haystack: Seq<'_>, needle: Seq<'_>) -> bool {
    needle.len() == 0
        || haystack.b.windows(needle.len()).any(|w| {
            Seq {
                b: w,
                fold: haystack.fold,
            }
            .eq(needle)
        })
}

/// Byte-wise AND, as long as the shorter operand. Addresses keep their type, so that
/// `ip.src & 255.0.0.0 == 10.0.0.0` compares addresses.
fn and_bytes<'a>(a: &V<'a>, b: &V<'a>) -> Option<V<'a>> {
    fn and<const N: usize>(x: &[u8; N], y: &[u8; N]) -> [u8; N] {
        core::array::from_fn(|i| x[i] & y[i])
    }
    Some(match (a, b) {
        (V::Ipv4(x, _), V::Ipv4(y, _)) => V::Ipv4(and(x, y), 32),
        (V::Ipv6(x, _), V::Ipv6(y, _)) => V::Ipv6(and(x, y), 128),
        (V::Ether(x), V::Ether(y)) => V::Ether(and(x, y)),
        _ => {
            let (x, y) = (a.bytes()?, b.bytes()?);
            let n = x.len().min(y.len());
            if n > OWNED {
                return None;
            }
            let mut out = [0; OWNED];
            for (o, (p, q)) in out.iter_mut().zip(x.iter().zip(y)) {
                *o = p & q;
            }
            V::Owned(out, n as u8)
        }
    })
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
    if let (Some(x), Some(y)) = (a.num(), b.num()) {
        return x == y;
    }
    match (a, b) {
        (V::Bool(x), V::Bool(y)) => x == y,
        (V::Ipv4(x, p), V::Ipv4(y, q)) => prefix_eq(x, y, *p.min(q)),
        (V::Ipv6(x, p), V::Ipv6(y, q)) => prefix_eq(x, y, *p.min(q)),
        (V::Ipv4(..), V::Ipv6(..)) | (V::Ipv6(..), V::Ipv4(..)) => false,
        _ => matches!((a.seq(), b.seq()), (Some(x), Some(y)) if x.eq(y)),
    }
}

fn ord(a: &V<'_>, b: &V<'_>) -> Option<Ordering> {
    if let (Some(x), Some(y)) = (a.num(), b.num()) {
        return Some(x.cmp(&y));
    }
    match (a, b) {
        (V::Ipv4(..), V::Ipv6(..)) | (V::Ipv6(..), V::Ipv4(..)) => None,
        (V::Bool(_), _)
        | (_, V::Bool(_))
        | (V::Uint(_) | V::Int(_), _)
        | (_, V::Uint(_) | V::Int(_)) => None,
        _ => Some(a.seq()?.iter().cmp(b.seq()?.iter())),
    }
}

fn lit(l: &Lit) -> V<'_> {
    match l {
        Lit::Bool(b) => V::Bool(*b),
        Lit::Uint(v) => V::Uint(*v),
        Lit::Int(v) => V::Int(*v),
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
        Value::Layer(f, ranges) => load_layer(*f, ranges, cx),
        Value::Raw(f, layers) => load_raw(*f, layers.as_deref(), cx),
        Value::Slice(base, ranges) => {
            let mut out = Vals::new();
            for x in value(base, cx).as_slice() {
                out.opt(match ranges.as_slice() {
                    [s] => slice(*x, s.start, s.end),
                    _ => concat(*x, ranges),
                });
            }
            out
        }
        Value::BitAnd(a, b) => {
            let (a, b) = (value(a, cx), value(b, cx));
            let mut out = Vals::new();
            for x in a.as_slice() {
                for y in b.as_slice() {
                    match (x, y) {
                        (V::Uint(x), V::Uint(y)) => out.push(V::Uint(x & y)),
                        _ => match x.int().zip(y.int()) {
                            Some((x, y)) => out.push(V::Int(x & y)),
                            None => out.opt(and_bytes(x, y)),
                        },
                    }
                }
            }
            out
        }
        Value::Arith(op, a, b) => {
            let (a, b) = (value(a, cx), value(b, cx));
            let mut out = Vals::new();
            for x in a.as_slice().iter().filter_map(V::int) {
                for y in b.as_slice().iter().filter_map(V::int) {
                    out.opt(ir::arith(*op, x, y).map(V::Int));
                }
            }
            out
        }
        Value::Neg(a) | Value::Abs(a) => {
            let abs = matches!(v, Value::Abs(_));
            let mut out = Vals::new();
            for x in value(a, cx).as_slice().iter().filter_map(V::int) {
                out.opt(
                    if abs {
                        x.checked_abs()
                    } else {
                        x.checked_neg()
                    }
                    .map(V::Int),
                );
            }
            out
        }
        Value::Extreme { max, args } => {
            let best = args
                .iter()
                .flat_map(|a| {
                    let vals = value(a, cx);
                    let (n, v) = (vals.n, vals.v);
                    v.into_iter().take(n).filter_map(|x| x.int())
                })
                .reduce(|a, b| if *max { a.max(b) } else { a.min(b) });
            let mut out = Vals::new();
            out.opt(best.map(V::Int));
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
        Value::Case { upper, value: base } => {
            let mut out = Vals::new();
            for x in value(base, cx).as_slice() {
                // Strings are borrowed from the metadata, so they keep their lifetime.
                if let V::Bytes(b) | V::Folded(b, _) = *x {
                    out.push(V::Folded(b, *upper));
                }
            }
            out
        }
    }
}

/// Several ranges of `v`, concatenated (folded if `v` is). Ranges that do not fit are skipped; no
/// fitting range, or more than [`OWNED`] bytes, gives no value.
fn concat<'a>(v: V<'a>, ranges: &[Slice]) -> Option<V<'a>> {
    let mut out = [0; OWNED];
    let mut n = 0;
    let mut any = false;
    for r in ranges {
        let Some(part) = slice(v, r.start, r.end) else {
            continue;
        };
        any = true;
        for b in part.seq()?.iter() {
            *out.get_mut(n)? = b;
            n += 1;
        }
    }
    any.then_some(V::Owned(out, n as u8))
}

fn slice<'a>(v: V<'a>, start: i64, end: SliceEnd) -> Option<V<'a>> {
    let len = v.bytes()?.len() as i64;
    let abs = |i: i64| if i < 0 { len.saturating_add(i) } else { i };
    let s = abs(start);
    let e = match end {
        SliceEnd::Len(n) => s.saturating_add(n),
        SliceEnd::Inclusive(e) => abs(e).saturating_add(1),
        SliceEnd::Open => len,
    };
    if s < 0 || e < s || e > len {
        return None;
    }
    let (s, e) = (s as usize, e as usize);
    Some(match v {
        V::Bytes(b) => V::Bytes(b.get(s..e)?),
        V::Folded(b, upper) => V::Folded(b.get(s..e)?, upper),
        other => {
            let src = other.bytes()?.get(s..e)?;
            let mut a = [0; OWNED];
            a.get_mut(..src.len())?.copy_from_slice(src);
            V::Owned(a, src.len() as u8)
        }
    })
}

fn ip(a: IpAddr) -> V<'static> {
    match a {
        IpAddr::V4(a) => V::Ipv4(a.octets(), 32),
        IpAddr::V6(a) => V::Ipv6(a.octets(), 128),
    }
}

/// Which tags a VLAN field reads: `Some(true)` for 802.1ad, `Some(false)` for 802.1Q, `None` for
/// fields that are not per tag.
fn tag_kind(f: Field) -> Option<bool> {
    match f {
        Field::Vlan | Field::VlanPriority | Field::VlanDei | Field::VlanId | Field::VlanEtype => {
            Some(false)
        }
        Field::Ieee8021ad
        | Field::Ieee8021adPriority
        | Field::Ieee8021adDei
        | Field::Ieee8021adId => Some(true),
        _ => None,
    }
}

/// The value of a per-tag field for the tag at position `i` of the tag stack.
fn tag_value<'a>(f: Field, i: usize, t: &VlanTag, p: &Packet<'a>) -> Option<V<'a>> {
    Some(match f {
        // The tag body (TCI and inner EtherType) follows each TPID.
        Field::Vlan | Field::Ieee8021ad => V::Bytes(p.data().get(14 + 4 * i..18 + 4 * i)?),
        Field::VlanPriority | Field::Ieee8021adPriority => V::Uint(t.priority() as u64),
        Field::VlanDei => V::Bool(t.dei()),
        Field::Ieee8021adDei => V::Uint(t.dei() as u64),
        Field::VlanId | Field::Ieee8021adId => V::Uint(t.id() as u64),
        Field::VlanEtype => V::Uint(t.ethertype as u64),
        _ => return None,
    })
}

/// Whether protocol layer `layer` (1-based) of `count` is selected by `ranges`, where negative
/// positions count from the last layer, as in Wireshark.
fn in_layers(ranges: &[Slice], layer: i64, count: i64) -> bool {
    let abs = |i: i64| {
        if i < 0 {
            i.saturating_add(count + 1)
        } else {
            i
        }
    };
    ranges.iter().any(|r| {
        let start = abs(r.start);
        let end = match r.end {
            SliceEnd::Len(n) => start.saturating_add(n).saturating_sub(1),
            SliceEnd::Inclusive(e) => abs(e),
            SliceEnd::Open => count,
        };
        (start..=end).contains(&layer)
    })
}

/// The occurrences of `f` in the selected layers. Each VLAN tag is a layer of its protocol; every
/// other protocol appears once, as layer 1, because only the outermost headers are parsed.
fn load_layer<'a>(f: Field, ranges: &[Slice], cx: &Cx<'a>) -> Vals<'a> {
    let p = cx.pkt;
    let Some(ad) = tag_kind(f) else {
        return if in_layers(ranges, 1, 1) {
            load(f, cx)
        } else {
            Vals::new()
        };
    };
    let count = tags(p, ad).count() as i64;
    let mut o = Vals::new();
    for (layer, (i, t)) in (1..).zip(tags(p, ad)) {
        if in_layers(ranges, layer, count) {
            o.opt(tag_value(f, i, t, p));
        }
    }
    o
}

/// Where the occurrences of a field lie in the packet: `(layer, start, length)` each.
pub(crate) struct Spans {
    n: usize,
    v: [(i64, usize, usize); MAX],
}

impl Spans {
    fn push(&mut self, layer: i64, start: usize, len: usize) {
        if self.n < MAX {
            self.v[self.n] = (layer, start, len);
            self.n += 1;
        }
    }

    pub(crate) fn as_slice(&self) -> &[(i64, usize, usize)] {
        &self.v[..self.n]
    }
}

/// The bytes on the wire of each occurrence of `f`, as Wireshark's `@field` reads them: a bit
/// field covers the whole bytes it sits in, and a computed field (`frame.len`, `tcp.len`) covers
/// none. Spans exist exactly when the field has values.
pub(crate) fn raw_spans(f: Field, p: &Packet<'_>, meta: &Meta<'_>) -> Spans {
    let mut s = Spans {
        n: 0,
        v: [(0, 0, 0); MAX],
    };
    let cx = Cx {
        pkt: p,
        meta,
        regexes: &[],
    };
    if load(f, &cx).n == 0 {
        return s;
    }
    // Per-tag fields: each tag is a layer of its protocol.
    if let Some(ad) = tag_kind(f) {
        for (layer, (i, _)) in (1..).zip(tags(p, ad)) {
            let tag = 14 + 4 * i;
            match f {
                Field::Vlan | Field::Ieee8021ad => s.push(layer, tag, 4),
                Field::VlanEtype => s.push(layer, tag + 2, 2),
                // Unlike 802.1Q's, these two 802.1ad fields are one-byte bit fields.
                Field::Ieee8021adPriority | Field::Ieee8021adDei => s.push(layer, tag, 1),
                _ => s.push(layer, tag, 2),
            }
        }
        return s;
    }
    let (l3, l4) = (p.l3_offset().unwrap_or(0), p.l4_offset().unwrap_or(0));
    let mut at = |start: usize, len: usize| s.push(1, start, len);
    match f {
        Field::Frame => at(0, p.data().len()),
        Field::FrameLen | Field::FrameCapLen => at(0, 0),
        Field::Eth => at(0, 14),
        Field::EthDst => at(0, 6),
        Field::EthSrc => at(6, 6),
        Field::EthAddr => {
            at(0, 6);
            at(6, 6);
        }
        Field::EthType => at(12, 2),
        Field::Arp | Field::ArpHwType | Field::ArpProtoType | Field::ArpHwSize => {
            let len = p.arp().map_or(0, |a| a.bytes().len());
            match f {
                Field::Arp => at(l3, len),
                Field::ArpHwType => at(l3, 2),
                Field::ArpProtoType => at(l3 + 2, 2),
                _ => at(l3 + 4, 1),
            }
        }
        Field::ArpProtoSize => at(l3 + 5, 1),
        Field::ArpOpcode => at(l3 + 6, 2),
        Field::ArpSrcHwMac
        | Field::ArpSrcProtoIpv4
        | Field::ArpDstHwMac
        | Field::ArpDstProtoIpv4 => {
            let (hs, ps) = p
                .arp()
                .map_or((0, 0), |a| (a.hw_size() as usize, a.proto_size() as usize));
            match f {
                Field::ArpSrcHwMac => at(l3 + 8, hs),
                Field::ArpSrcProtoIpv4 => at(l3 + 8 + hs, ps),
                Field::ArpDstHwMac => at(l3 + 8 + hs + ps, hs),
                _ => at(l3 + 8 + 2 * hs + ps, ps),
            }
        }
        Field::Ip => at(l3, p.ipv4().map_or(0, |h| h.header_len())),
        Field::IpVersion | Field::IpHdrLen | Field::Ipv6Version => at(l3, 1),
        Field::IpDsfield | Field::IpDsfieldDscp | Field::IpDsfieldEcn => at(l3 + 1, 1),
        Field::IpLen => at(l3 + 2, 2),
        Field::IpId => at(l3 + 4, 2),
        Field::IpFlags | Field::IpFlagsRb | Field::IpFlagsDf | Field::IpFlagsMf => at(l3 + 6, 1),
        Field::IpFragOffset => at(l3 + 6, 2),
        Field::IpTtl => at(l3 + 8, 1),
        Field::IpProto => at(l3 + 9, 1),
        Field::IpChecksum => at(l3 + 10, 2),
        Field::IpSrc => at(l3 + 12, 4),
        Field::IpDst => at(l3 + 16, 4),
        Field::IpAddr => {
            at(l3 + 12, 4);
            at(l3 + 16, 4);
        }
        Field::Ipv6 => {
            let end = p.l4_offset().unwrap_or(p.payload_range().start);
            at(l3, end.saturating_sub(l3));
        }
        Field::Ipv6Tclass | Field::Ipv6TclassDscp | Field::Ipv6TclassEcn => at(l3, 4),
        Field::Ipv6Flow => at(l3 + 1, 3),
        Field::Ipv6Plen => at(l3 + 4, 2),
        Field::Ipv6Nxt => at(l3 + 6, 1),
        Field::Ipv6Hlim => at(l3 + 7, 1),
        Field::Ipv6Src => at(l3 + 8, 16),
        Field::Ipv6Dst => at(l3 + 24, 16),
        Field::Ipv6Addr => {
            at(l3 + 8, 16);
            at(l3 + 24, 16);
        }
        Field::Ipv6FraghdrOffset | Field::Ipv6FraghdrMore | Field::Ipv6FraghdrIdent => {
            let h = p.ipv6_fragment_header().unwrap_or(0);
            match f {
                Field::Ipv6FraghdrIdent => at(h + 4, 4),
                _ => at(h + 2, 2),
            }
        }
        Field::Tcp => at(l4, p.tcp().map_or(0, |t| t.header_len())),
        Field::TcpSrcport | Field::UdpSrcport => at(l4, 2),
        Field::TcpDstport | Field::UdpDstport => at(l4 + 2, 2),
        Field::TcpPort | Field::UdpPort => {
            at(l4, 2);
            at(l4 + 2, 2);
        }
        Field::TcpSeqRaw => at(l4 + 4, 4),
        Field::TcpAckRaw => at(l4 + 8, 4),
        Field::TcpHdrLen => at(l4 + 12, 1),
        Field::TcpFlags => at(l4 + 12, 2),
        // Each flag covers only the byte it is in.
        Field::TcpFlagsRes | Field::TcpFlagsAe => at(l4 + 12, 1),
        Field::TcpFlagsCwr
        | Field::TcpFlagsEce
        | Field::TcpFlagsUrg
        | Field::TcpFlagsAck
        | Field::TcpFlagsPush
        | Field::TcpFlagsReset
        | Field::TcpFlagsSyn
        | Field::TcpFlagsFin => at(l4 + 13, 1),
        Field::TcpWindowSizeValue => at(l4 + 14, 2),
        Field::TcpChecksum => at(l4 + 16, 2),
        Field::TcpUrgentPointer => at(l4 + 18, 2),
        Field::TcpLen => at(l4, 0),
        Field::TcpPayload | Field::UdpPayload => {
            let r = p.payload_range();
            at(r.start, r.len());
        }
        Field::Udp => at(l4, 8),
        Field::UdpLength => at(l4 + 4, 2),
        Field::UdpChecksum => at(l4 + 6, 2),
        Field::IcmpChecksum | Field::Icmpv6Checksum => at(l4 + 2, 2),
        Field::Icmp => at(l4, p.icmp().map_or(0, |i| i.bytes().len())),
        Field::Icmpv6 => at(l4, p.icmpv6().map_or(0, |i| i.bytes().len())),
        Field::IcmpType | Field::Icmpv6Type => at(l4, 1),
        Field::IcmpCode | Field::Icmpv6Code => at(l4 + 1, 1),
        Field::IcmpIdent | Field::Icmpv6EchoIdentifier => at(l4 + 4, 2),
        Field::IcmpSeq | Field::Icmpv6EchoSequenceNumber => at(l4 + 6, 2),
        // Metadata (and the per-tag fields, handled above) have no span here.
        _ => {}
    }
    s
}

/// `@field`: the bytes of each occurrence in the selected layers.
fn load_raw<'a>(f: Field, layers: Option<&[Slice]>, cx: &Cx<'a>) -> Vals<'a> {
    let p = cx.pkt;
    let count = tag_kind(f).map_or(1, |ad| tags(p, ad).count() as i64);
    let mut o = Vals::new();
    for &(layer, start, len) in raw_spans(f, p, cx.meta).as_slice() {
        if layers.is_none_or(|r| in_layers(r, layer, count)) {
            o.opt(p.data().get(start..start.saturating_add(len)).map(V::Bytes));
        }
    }
    o
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

        Field::Vlan
        | Field::VlanPriority
        | Field::VlanDei
        | Field::VlanId
        | Field::VlanEtype
        | Field::Ieee8021ad
        | Field::Ieee8021adPriority
        | Field::Ieee8021adDei
        | Field::Ieee8021adId => {
            let ad = tag_kind(f) == Some(true);
            tags(p, ad).for_each(|(i, t)| o.opt(tag_value(f, i, t, p)));
        }

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
        // Without reassembly, Wireshark leaves `tcp.len` unset on a first fragment. An IPv6
        // atomic fragment (offset 0, no more fragments, RFC 6946) is a whole datagram.
        Field::TcpLen => o.opt(
            p.tcp()
                .filter(|_| p.fragment().is_none_or(|fr| fr.offset == 0 && !fr.more))
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
