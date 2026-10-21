//! Code generation: a filter's IR to an eBPF matcher.
//!
//! The matcher is a `BPF_PROG_TYPE_SCHED_CLS` program that the static TC program tail-calls
//! after it has parsed the headers into the [`Facts`](crate::facts::Facts). It reads the facts,
//! loads header fields and byte ranges with `bpf_skb_load_bytes`, writes its verdict to the
//! facts, and tail-calls the action program. Tests compile to short-circuit jumps, all forward.
//!
//! What it covers:
//!
//! - `and`, `or`, `not`, `xor` (each side compiled once, through a stack slot), conditionals;
//! - presence, comparisons and set membership (sorted ranges searched by a tree of jumps) of the
//!   fixed header fields of Ethernet, VLAN tags, IPv4, IPv6, TCP (with the first MSS, window
//!   scale, SACK permitted and timestamps options), UDP and ICMP, with their quantifiers over
//!   several occurrences (`ip.addr`, `eth.addr`, `vlan.id`, …);
//! - IPv6 and MAC addresses, prefixes and ranges, and the ordering of fixed-length bytes;
//! - `==`, `!=`, set membership and `contains` (for headers of at most 64 bytes) on header and
//!   payload bytes and their slices;
//! - `len()`, `count()`, arithmetic, `&`, `abs()`, `max()` and `min()` on numbers, when no
//!   intermediate result can overflow, and comparisons of two numeric fields;
//! - the metadata: direction, loopback, impostor, fragment, interface (by name or index),
//!   protocol, `local.*`/`remote.*`, and the handle's constants (layer, event, priority), which
//!   [`Env`] gives.
//!
//! Anything else is [`Error::Unsupported`]. [`compile_superset`] then replaces each unsupported
//! test by `true` or `false`, so that the kernel takes a superset of the packets, and the
//! backend filters them exactly in user space.

use core::fmt;

use avulse_filter::Layer;
use avulse_filter::fields::{Field, def};
use avulse_filter::ir::{self, ArithOp, CmpOp, Lit, Quant, SetItem, Slice, SliceEnd, Test, Value};

use crate::facts::{
    F_ARP, F_ETH, F_FRAG, F_ICMP, F_ICMPV6, F_IPV4, F_IPV6, F_MORE, F_TCP, F_UDP, M_IMPOSTOR,
    M_LOOPBACK, M_OUTBOUND, M_VLAN, M_VLAN_AD, SLOT_ACTION, off,
};
use crate::insn::{Alu, Asm, AsmError, Cond, FP, Insn, Label, MapRef, MapRefs, Reg, Size};

const MAP_LOOKUP_ELEM: i32 = 1;
const TAIL_CALL: i32 = 12;
const SKB_LOAD_BYTES: i32 = 26;
/// What the matcher returns when it cannot reach the action program: pass the packet to the
/// next classifier (fail-open).
const TC_ACT_UNSPEC: i32 = -1;

/// The skb, for the whole program.
const CTX: Reg = 6;
/// The facts, for the whole program.
const FACTS: Reg = 7;
/// The value under test, or the start of a byte range.
const VAL: Reg = 8;
/// The length of a byte range.
const LEN: Reg = 9;

/// Stack slot of a header field (up to 4 bytes).
const SCRATCH: i16 = -8;
/// Stack buffer for byte comparisons.
const BUF: i16 = -80;
/// Its size.
const CHUNK: usize = 64;
/// The first 8-byte stack slot for intermediate values; the others follow downwards.
const SLOT0: i16 = -88;
/// How many slots fit in the 512-byte stack.
const SLOTS: usize = 52;
/// Above this many ranges, a set is searched by a tree of jumps.
const TREE: usize = 4;
/// The most bytes `contains` searches times the needle's length (each byte is one compare).
const CONTAINS_WORK: usize = 4096;

/// The constants of the handle a matcher is generated for: the filter reads them as fields
/// (`layer`, `priority`, `event`, `iface`), but they do not change from packet to packet.
#[derive(Clone, Copy)]
pub struct Env<'a> {
    /// The handle's layer.
    pub layer: Layer,
    /// The handle's priority.
    pub priority: i16,
    /// The index of an interface by name, for `iface`. Resolved when the matcher is generated:
    /// an interface renamed afterwards is not seen under its new name.
    pub ifindex: &'a dyn Fn(&str) -> Option<u32>,
}

fn no_interfaces(_: &str) -> Option<u32> {
    None
}

impl Env<'static> {
    /// A handle at `layer`, priority 0, that knows no interface names (so `iface == "…"` never
    /// matches).
    pub fn new(layer: Layer) -> Self {
        Env {
            layer,
            priority: 0,
            ifindex: &no_interfaces,
        }
    }
}

impl fmt::Debug for Env<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Env")
            .field("layer", &self.layer)
            .field("priority", &self.priority)
            .finish_non_exhaustive()
    }
}

/// A generated matcher: instructions, and where they refer to maps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matcher {
    insns: Vec<Insn>,
    maps: MapRefs,
    exact: bool,
    options: bool,
}

impl Matcher {
    /// The instructions, with the map fds still unset.
    pub fn insns(&self) -> &[Insn] {
        &self.insns
    }

    /// The `ld_imm64` instructions that load a map, by index.
    pub fn map_refs(&self) -> &[(usize, MapRef)] {
        &self.maps
    }

    /// Whether the matcher matches exactly the packets the filter does. When it does not, it
    /// matches a superset of them, which user space must filter again.
    pub fn exact(&self) -> bool {
        self.exact
    }

    /// Whether the matcher reads TCP options, which the static program then finds first
    /// ([`CFG_TCP_OPTIONS`](crate::abi::CFG_TCP_OPTIONS)).
    pub fn reads_tcp_options(&self) -> bool {
        self.options
    }

    /// The instructions with the map fds filled in.
    pub fn with_fds(&self, facts: i32, progs: i32) -> Vec<Insn> {
        let mut out = self.insns.clone();
        for &(at, m) in &self.maps {
            out[at].imm = match m {
                MapRef::Facts => facts,
                MapRef::Progs => progs,
            };
        }
        out
    }
}

/// Why a filter could not be compiled to eBPF.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The filter uses something the generator does not support (yet); filter in user space.
    Unsupported(String),
    /// The program would be too large.
    TooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unsupported(what) => write!(f, "the eBPF generator does not support {what}"),
            Error::TooLarge => f.write_str("the generated eBPF program would be too large"),
        }
    }
}

impl std::error::Error for Error {}

impl From<AsmError> for Error {
    fn from(_: AsmError) -> Self {
        Error::TooLarge
    }
}

fn unsupported<T>(what: impl Into<String>) -> Result<T, Error> {
    Err(Error::Unsupported(what.into()))
}

/// Compiles `test` to a matcher for a handle with `env`, exactly. The matcher is still inexact
/// ([`Matcher::exact`]) in one case: at the ETHERNET layer, a filter that reads the link-layer
/// layout (`eth.type`, VLAN fields, `frame` bytes and length) matches every frame whose outer
/// VLAN tag the device took off (`skb->vlan_tci`), because the kernel does not see it in place.
pub fn compile(test: &Test, env: &Env<'_>) -> Result<Matcher, Error> {
    emit(&lower(test, env), env)
}

/// A filter widened to what the kernel can run: [`compile`] accepts `test`, and every packet
/// the original filter matches, it matches too. `exact` tells whether it is the original.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Superset {
    /// The widened filter.
    pub test: Test,
    /// Whether nothing had to be widened.
    pub exact: bool,
}

/// Widens `test`: each test the generator does not support becomes `true`, or `false` under an
/// odd number of `not`s (`xor` and conditionals are first written with `and`, `or` and `not`).
pub fn superset(test: &Test, env: &Env<'_>) -> Superset {
    if supported(test, env) {
        return Superset {
            test: test.clone(),
            exact: true,
        };
    }
    let (test, exact) = widen(test, true, env);
    Superset {
        test: ir::simplify(test),
        exact,
    }
}

/// Compiles `test` exactly when the generator supports it, or else its [`superset`]
/// ([`Matcher::exact`] is then false).
pub fn compile_superset(test: &Test, env: &Env<'_>) -> Result<Matcher, Error> {
    match compile(test, env) {
        Err(Error::Unsupported(_)) => {
            let s = superset(test, env);
            let mut m = compile(&s.test, env)?;
            m.exact &= s.exact;
            Ok(m)
        }
        r => r,
    }
}

/// A matcher that takes every packet of the layer, the last resort when the verifier refuses
/// the others: never exact.
pub fn everything(env: &Env<'_>) -> Result<Matcher, Error> {
    let mut m = emit(&Test::Const(true), env)?;
    m.exact = false;
    Ok(m)
}

fn supported(test: &Test, env: &Env<'_>) -> bool {
    !matches!(compile(test, env), Err(Error::Unsupported(_)))
}

/// A test `w` such that `test ⇒ w` when `up`, and `w ⇒ test` otherwise; and whether `w` is
/// `test`.
fn widen(test: &Test, up: bool, env: &Env<'_>) -> (Test, bool) {
    let all = |xs: &[Test]| {
        let v: Vec<(Test, bool)> = xs.iter().map(|x| widen(x, up, env)).collect();
        let exact = v.iter().all(|(_, e)| *e);
        (v.into_iter().map(|(t, _)| t).collect::<Vec<_>>(), exact)
    };
    let not = |t: &Test| Test::Not(Box::new(t.clone()));
    match test {
        Test::Const(_) => (test.clone(), true),
        Test::Not(x) => {
            let (w, e) = widen(x, !up, env);
            (Test::Not(Box::new(w)), e)
        }
        Test::And(xs) => {
            let (v, e) = all(xs);
            (Test::And(v), e)
        }
        Test::Or(xs) => {
            let (v, e) = all(xs);
            (Test::Or(v), e)
        }
        _ if supported(test, env) => (test.clone(), true),
        Test::Xor(a, b) => widen(
            &Test::Or(vec![
                Test::And(vec![(**a).clone(), not(b)]),
                Test::And(vec![not(a), (**b).clone()]),
            ]),
            up,
            env,
        ),
        Test::If(c, a, b) => widen(
            &Test::Or(vec![
                Test::And(vec![(**c).clone(), (**a).clone()]),
                Test::And(vec![not(c), (**b).clone()]),
            ]),
            up,
            env,
        ),
        _ => (Test::Const(up), false),
    }
}

// ---------------------------------------------------------------------------------------------
// Lowering of the metadata to tests the generator knows.

/// Rewrites the tests of metadata fields: handle constants are decided, `iface` becomes
/// `ifidx`, and `local.*`/`remote.*` become conditionals on the direction over the header
/// fields, as `value::load` defines them at the packet layers.
fn lower(test: &Test, env: &Env<'_>) -> Test {
    ir::simplify(lower_rec(test, env))
}

fn lower_rec(test: &Test, env: &Env<'_>) -> Test {
    let b = |t: &Test| Box::new(lower_rec(t, env));
    match test {
        Test::Not(x) => Test::Not(b(x)),
        Test::And(xs) => Test::And(xs.iter().map(|x| lower_rec(x, env)).collect()),
        Test::Or(xs) => Test::Or(xs.iter().map(|x| lower_rec(x, env)).collect()),
        Test::Xor(x, y) => Test::Xor(b(x), b(y)),
        Test::If(c, x, y) => Test::If(b(c), b(x), b(y)),
        leaf => lower_leaf(leaf, env).unwrap_or_else(|| leaf.clone()),
    }
}

/// The field a leaf tests against constants, with the constant on the right.
fn leaf_field(test: &Test) -> Option<(Field, Test)> {
    match test {
        Test::Exists(Value::Field(f)) | Test::Truthy(Value::Field(f)) => Some((*f, test.clone())),
        Test::Cmp {
            lhs: Value::Field(f),
            rhs: Value::Lit(_),
            ..
        }
        | Test::Member {
            lhs: Value::Field(f),
            ..
        } => Some((*f, test.clone())),
        Test::Cmp {
            lhs: Value::Lit(l),
            op,
            quant,
            rhs: Value::Field(f),
        } => Some((
            *f,
            Test::Cmp {
                lhs: Value::Field(*f),
                op: mirror(*op),
                quant: *quant,
                rhs: Value::Lit(l.clone()),
            },
        )),
        _ => None,
    }
}

/// The same test of another field.
fn with_field(test: &Test, f: Field) -> Test {
    let mut t = test.clone();
    match &mut t {
        Test::Exists(v)
        | Test::Truthy(v)
        | Test::Cmp { lhs: v, .. }
        | Test::Member { lhs: v, .. } => *v = Value::Field(f),
        _ => {}
    }
    t
}

fn exists(f: Field) -> Test {
    Test::Exists(Value::Field(f))
}

fn if_then(c: Test, a: Test, b: Test) -> Test {
    Test::If(Box::new(c), Box::new(a), Box::new(b))
}

fn lower_leaf(test: &Test, env: &Env<'_>) -> Option<Test> {
    let (f, t) = leaf_field(test)?;
    match f {
        Field::Layer | Field::Event | Field::Priority | Field::Subifidx => {
            let v = match f {
                Field::Layer => env.layer as i128,
                Field::Priority => env.priority as i128,
                // The packet layers have no events, and Linux no sub-interfaces.
                _ => 0,
            };
            decide(&t, v).map(Test::Const)
        }
        Field::Iface | Field::FrameInterfaceName => lower_iface(&t, env),
        // A tag is there when its ID is, which the generator reads also from an offloaded tag.
        Field::Vlan | Field::Ieee8021ad => match t {
            Test::Exists(_) => Some(exists(if f == Field::Vlan {
                Field::VlanId
            } else {
                Field::Ieee8021adId
            })),
            _ => None,
        },
        Field::LocalAddr | Field::RemoteAddr => lower_addr(&t, f == Field::LocalAddr),
        Field::LocalPort | Field::RemotePort => {
            let local = f == Field::LocalPort;
            if let Test::Exists(_) = t {
                return Some(Test::Or(vec![exists(Field::Tcp), exists(Field::Udp)]));
            }
            if let Test::Truthy(_) = t {
                return None;
            }
            let dir = |src, dst| {
                let (out, inb) = if local { (src, dst) } else { (dst, src) };
                if_then(outbound(), with_field(&t, out), with_field(&t, inb))
            };
            Some(if_then(
                exists(Field::Tcp),
                dir(Field::TcpSrcport, Field::TcpDstport),
                if_then(
                    exists(Field::Udp),
                    dir(Field::UdpSrcport, Field::UdpDstport),
                    Test::Const(false),
                ),
            ))
        }
        _ => None,
    }
}

fn outbound() -> Test {
    Test::Truthy(Value::Field(Field::Outbound))
}

/// A test of a constant field with value `v`.
fn decide(test: &Test, v: i128) -> Option<bool> {
    Some(match test {
        Test::Exists(_) => true,
        Test::Truthy(_) => v != 0,
        Test::Cmp {
            op,
            rhs: Value::Lit(l),
            ..
        } => {
            let n = num(l)?;
            match op {
                CmpOp::Eq => v == n,
                CmpOp::Ne => v != n,
                CmpOp::Lt => v < n,
                CmpOp::Le => v <= n,
                CmpOp::Gt => v > n,
                CmpOp::Ge => v >= n,
            }
        }
        Test::Member { set, negate, .. } => {
            let mut hit = false;
            for item in set {
                hit |= match item {
                    SetItem::One(l) => num(l)? == v,
                    SetItem::Range(lo, hi) => num(lo)? <= v && v <= num(hi)?,
                };
            }
            hit != *negate
        }
        _ => return None,
    })
}

/// `iface` by name: the index of the interface with that name now.
fn lower_iface(test: &Test, env: &Env<'_>) -> Option<Test> {
    let index = |l: &Lit| match l {
        Lit::Bytes(b) => Some(core::str::from_utf8(b).ok().and_then(|s| (env.ifindex)(s))),
        _ => None,
    };
    Some(match test {
        Test::Exists(_) => Test::Const(true),
        Test::Cmp {
            op: op @ (CmpOp::Eq | CmpOp::Ne),
            quant,
            rhs: Value::Lit(l),
            ..
        } => match index(l)? {
            Some(i) => Test::Cmp {
                lhs: Value::Field(Field::Ifidx),
                op: *op,
                quant: *quant,
                rhs: Value::Lit(Lit::Uint(i.into())),
            },
            None => Test::Const(*op == CmpOp::Ne),
        },
        Test::Member {
            set, quant, negate, ..
        } => {
            let mut items = Vec::new();
            for item in set {
                let SetItem::One(l) = item else { return None };
                if let Some(i) = index(l)? {
                    items.push(SetItem::One(Lit::Uint(i.into())));
                }
            }
            Test::Member {
                lhs: Value::Field(Field::Ifidx),
                set: items,
                quant: *quant,
                negate: *negate,
            }
        }
        _ => return None,
    })
}

/// `local.addr`/`remote.addr`: the source or the destination address by direction. Against an
/// address of the other family, `!=` and `not in` hold and the rest does not.
fn lower_addr(test: &Test, local: bool) -> Option<Test> {
    let pick = |t: &Test, src, dst| {
        let (out, inb) = if local { (src, dst) } else { (dst, src) };
        if_then(outbound(), with_field(t, out), with_field(t, inb))
    };
    let v4 = |t: &Test| pick(t, Field::IpSrc, Field::IpDst);
    let v6 = |t: &Test| pick(t, Field::Ipv6Src, Field::Ipv6Dst);
    let by_family = |a: Test, b: Test| {
        if_then(
            exists(Field::Ip),
            a,
            if_then(exists(Field::Ipv6), b, Test::Const(false)),
        )
    };
    Some(match test {
        Test::Exists(_) => Test::Or(vec![exists(Field::Ip), exists(Field::Ipv6)]),
        Test::Cmp {
            op,
            rhs: Value::Lit(l),
            ..
        } => {
            let other = Test::Const(*op == CmpOp::Ne);
            match l {
                Lit::Ipv4(..) => by_family(v4(test), other),
                Lit::Ipv6(..) => by_family(other, v6(test)),
                _ => return None,
            }
        }
        Test::Member {
            lhs,
            set,
            quant,
            negate,
        } => {
            let family = |six: bool| {
                let items = set
                    .iter()
                    .filter(|i| {
                        let l = match i {
                            SetItem::One(l) | SetItem::Range(l, _) => l,
                        };
                        matches!(l, Lit::Ipv6(..)) == six
                    })
                    .cloned()
                    .collect();
                Test::Member {
                    lhs: lhs.clone(),
                    set: items,
                    quant: *quant,
                    negate: *negate,
                }
            };
            by_family(v4(&family(false)), v6(&family(true)))
        }
        _ => return None,
    })
}

/// Whether the filter reads link-layer bytes whose place an offloaded VLAN tag changes (the
/// fields of the tags, `eth.type` and `frame.len` take the offloaded tag into account).
fn l2_sensitive(test: &Test) -> bool {
    fn value(v: &Value) -> bool {
        match v {
            Value::Field(f) | Value::Layer(f, _) | Value::Raw(f, _) => matches!(
                f,
                Field::Frame | Field::Eth | Field::Vlan | Field::Ieee8021ad
            ),
            Value::Slice(v, _)
            | Value::Len(v)
            | Value::Count(v)
            | Value::Neg(v)
            | Value::Abs(v)
            | Value::Case { value: v, .. } => value(v),
            Value::BitAnd(a, b) | Value::Arith(_, a, b) => value(a) || value(b),
            Value::Extreme { args, .. } => args.iter().any(value),
            Value::Lit(_) => false,
        }
    }
    match test {
        Test::Const(_) => false,
        Test::Exists(v) | Test::Truthy(v) | Test::Member { lhs: v, .. } => value(v),
        Test::Cmp { lhs, rhs, .. } | Test::Contains { lhs, rhs, .. } => value(lhs) || value(rhs),
        Test::Matches { lhs, .. } => value(lhs),
        Test::Not(x) => l2_sensitive(x),
        Test::And(xs) | Test::Or(xs) => xs.iter().any(l2_sensitive),
        Test::Xor(a, b) => l2_sensitive(a) || l2_sensitive(b),
        Test::If(c, a, b) => l2_sensitive(c) || l2_sensitive(a) || l2_sensitive(b),
    }
}

// ---------------------------------------------------------------------------------------------
// Operands.

/// The header a field is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hdr {
    Eth,
    Ipv4,
    Ipv6,
    /// IPv4 or IPv6 (`ip.version`).
    Ip,
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Arp,
}

impl Hdr {
    fn flags(self) -> u32 {
        match self {
            Hdr::Eth => F_ETH,
            Hdr::Ipv4 => F_IPV4,
            Hdr::Ipv6 => F_IPV6,
            Hdr::Ip => F_IPV4 | F_IPV6,
            Hdr::Tcp => F_TCP,
            Hdr::Udp => F_UDP,
            Hdr::Icmp => F_ICMP,
            Hdr::Icmpv6 => F_ICMPV6,
            Hdr::Arp => F_ARP,
        }
    }

    /// Where the facts keep the header's offset; `None` for offset 0.
    fn base(self) -> Option<i16> {
        match self {
            Hdr::Eth => None,
            Hdr::Ipv4 | Hdr::Ipv6 | Hdr::Ip | Hdr::Arp => Some(off::L3),
            Hdr::Tcp | Hdr::Udp | Hdr::Icmp | Hdr::Icmpv6 => Some(off::L4),
        }
    }
}

/// How a field's value is read: `width` big-endian bytes at `off`, shifted right, masked and
/// multiplied.
#[derive(Clone, Copy, Debug)]
struct Bits {
    off: i32,
    width: u8,
    shift: u8,
    mask: u32,
    mul: u8,
}

impl Bits {
    /// The largest value it can read.
    fn max(self) -> i128 {
        let raw = (1i128 << (8 * self.width as u32)) - 1;
        ((raw >> self.shift) & self.mask as i128) * self.mul as i128
    }
}

fn bits(off: i32, width: u8, shift: u8, mask: u32) -> Bits {
    Bits {
        off,
        width,
        shift,
        mask,
        mul: 1,
    }
}

fn whole(off: i32, width: u8) -> Bits {
    bits(off, width, 0, u32::MAX)
}

/// One occurrence of a numeric field.
#[derive(Clone, Copy, Debug)]
enum Scalar {
    At(Hdr, Bits),
    /// `frame.len`, 4 more than the kernel sees when a VLAN tag was offloaded at ETHERNET.
    FrameLen,
    /// `eth.type`: the TPID of an offloaded VLAN tag, else the EtherType in the frame.
    EthType,
    /// An IPv4 address of an ARP packet (the target's if `true`), when its protocol is IPv4.
    ArpIp(bool),
    /// `tcp.len`: the payload length, absent on fragments with more to come.
    TcpLen,
    /// A field of the facts, masked; with `invert`, the masked bits flipped.
    Fact {
        off: i16,
        size: Size,
        mask: u32,
        invert: bool,
    },
    /// Of VLAN tag `i`, if it is an 802.1ad tag (`true`) or not: bits from the frame start (the
    /// TCI at `14 + 4 * i`, the inner EtherType at `16 + 4 * i`). At ETHERNET, an offloaded tag
    /// is tag 0 and the tags in the frame follow.
    Tag(u8, bool, Bits),
    /// Of the first TCP option in slot `n` of the facts, if its length is `len`: bits from the
    /// option start.
    Opt(u8, u8, Bits),
    /// `tcp.options.wscale.multiplier`: 2 to the shift, at most 2^14.
    WscaleMul,
}

impl Scalar {
    fn max(self) -> i128 {
        match self {
            Scalar::At(_, b) | Scalar::Tag(_, _, b) | Scalar::Opt(_, _, b) => b.max(),
            Scalar::FrameLen | Scalar::TcpLen => u32::MAX as i128,
            Scalar::EthType => 0xffff,
            Scalar::ArpIp(_) => u32::MAX as i128,
            Scalar::Fact { mask, .. } => mask as i128,
            Scalar::WscaleMul => 1 << 14,
        }
    }

    /// Whether the occurrence may be absent when its header is present.
    fn dynamic(self) -> bool {
        matches!(
            self,
            Scalar::TcpLen
                | Scalar::Tag(..)
                | Scalar::Opt(..)
                | Scalar::WscaleMul
                | Scalar::ArpIp(_)
        )
    }
}

/// How a numeric field compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Uint,
    Bool,
    /// An IPv4 address.
    Addr,
    /// A signed result of arithmetic.
    Int,
}

/// A byte range of the packet.
#[derive(Clone, Copy, Debug)]
enum Region {
    Frame,
    /// A fixed range of a header.
    At(Hdr, i32, i32),
    Ipv4Hdr,
    TcpHdr,
    /// From the transport header to the end of the IP payload (ICMP, ICMPv6).
    L4ToEnd(Hdr),
    /// The payload after the transport header, absent when empty.
    Payload(Hdr),
    /// The options of the TCP header, absent when there are none.
    TcpOpts,
    /// The first TCP option in slot `n` of the facts.
    Opt(u8),
    /// VLAN tag `i` (TCI and inner EtherType), if it is an 802.1ad tag (`true`) or not.
    Tag(u8, bool),
    /// The ARP packet.
    Arp,
    /// A MAC address of an ARP packet (the target's if `true`), when it has 6-byte ones.
    ArpMac(bool),
}

impl Region {
    /// The length, when it is always the same.
    fn fixed(self) -> Option<usize> {
        match self {
            Region::At(_, _, len) => Some(len as usize),
            Region::Tag(..) => Some(4),
            Region::ArpMac(_) => Some(6),
            _ => None,
        }
    }

    /// The longest it can be, when that is small.
    fn max(self) -> Option<usize> {
        match self {
            Region::At(_, _, len) => Some(len as usize),
            Region::Tag(..) => Some(4),
            Region::ArpMac(_) => Some(6),
            Region::Ipv4Hdr | Region::TcpHdr => Some(60),
            Region::TcpOpts | Region::Opt(_) => Some(40),
            _ => None,
        }
    }

    fn dynamic(self) -> bool {
        matches!(
            self,
            Region::Payload(_)
                | Region::TcpOpts
                | Region::Opt(_)
                | Region::Tag(..)
                | Region::ArpMac(_)
        )
    }
}

/// One occurrence of a byte value: a region, maybe sliced.
#[derive(Clone, Copy, Debug)]
struct Bytes {
    r: Region,
    s: Option<Slice>,
}

impl Bytes {
    /// The length, when it is always the same (as `value::slice` cuts it).
    fn fixed(self) -> Option<usize> {
        let Some(s) = self.s else {
            return self.r.fixed();
        };
        // A slice of a constant length has that length whenever it fits.
        match s.end {
            SliceEnd::Len(n) => return usize::try_from(n).ok(),
            SliceEnd::Inclusive(e) if (s.start >= 0) == (e >= 0) => {
                return usize::try_from(e - s.start + 1).ok();
            }
            _ => {}
        }
        let len = self.r.fixed()? as i64;
        let start = if s.start < 0 { len + s.start } else { s.start };
        let end = match s.end {
            SliceEnd::Len(n) => start + n,
            SliceEnd::Inclusive(e) if e >= 0 => e + 1,
            SliceEnd::Inclusive(e) => len + e + 1,
            SliceEnd::Open => len,
        };
        (start >= 0 && end >= start && end <= len).then(|| (end - start) as usize)
    }

    fn max(self) -> Option<usize> {
        self.r.max()
    }
}

/// One occurrence of a numeric value.
#[derive(Clone, Debug)]
enum Num {
    Load(Scalar),
    /// The length of a byte occurrence.
    Len(Bytes),
    Const(i64),
    /// The number of present occurrences.
    Count(Vec<Occ>),
    Arith(ArithOp, Box<Num>, Box<Num>),
    And(Box<Num>, Box<Num>),
    Neg(Box<Num>),
    Abs(Box<Num>),
    /// The largest (`true`) or smallest of the present values.
    Extreme(bool, Vec<Num>),
    /// A value that is absent unless one of these presence bits is set.
    Need(u32, Box<Num>),
}

#[derive(Clone, Debug)]
enum Occ {
    Num(Num),
    Bytes(Bytes),
}

impl Num {
    /// The values it can take, when they are all in `i64`.
    fn range(&self) -> Option<(i128, i128)> {
        let fits = |(lo, hi): (i128, i128)| {
            (lo >= i64::MIN as i128 && hi <= i64::MAX as i128).then_some((lo, hi))
        };
        fits(match self {
            Num::Load(s) => (0, s.max()),
            Num::Len(_) => (0, u32::MAX as i128),
            Num::Const(c) => (*c as i128, *c as i128),
            Num::Count(v) => (0, v.len() as i128),
            Num::Arith(op, a, b) => {
                let (a, b) = (a.range()?, b.range()?);
                match op {
                    ArithOp::Add => (a.0 + b.0, a.1 + b.1),
                    ArithOp::Sub => (a.0 - b.1, a.1 - b.0),
                    ArithOp::Mul => {
                        let p = [a.0 * b.0, a.0 * b.1, a.1 * b.0, a.1 * b.1];
                        (*p.iter().min()?, *p.iter().max()?)
                    }
                    // Unsigned division is what the BPF of 5.15 has: both sides non-negative.
                    ArithOp::Div if a.0 >= 0 && b.0 >= 0 => (a.0 / b.1.max(1), a.1 / b.0.max(1)),
                    ArithOp::Mod if a.0 >= 0 && b.0 >= 0 => (0, a.1.min(b.1 - 1).max(0)),
                    _ => return None,
                }
            }
            Num::And(a, b) => {
                let (a, b) = (a.range()?, b.range()?);
                if a.0 >= 0 && b.0 >= 0 {
                    (0, a.1.min(b.1))
                } else {
                    (i64::MIN as i128, i64::MAX as i128)
                }
            }
            Num::Neg(a) => {
                let a = a.range()?;
                (-a.1, -a.0)
            }
            Num::Abs(a) => {
                let a = a.range()?;
                let m = a.0.abs().max(a.1.abs());
                (if a.0 >= 0 { a.0 } else { 0 }, m)
            }
            Num::Extreme(_, v) => {
                let r: Option<Vec<_>> = v.iter().map(Num::range).collect();
                let r = r?;
                (r.iter().map(|x| x.0).min()?, r.iter().map(|x| x.1).max()?)
            }
            Num::Need(_, x) => x.range()?,
        })
    }

    /// Whether it may have no value when its headers are present.
    fn dynamic(&self) -> bool {
        match self {
            Num::Load(s) => s.dynamic(),
            Num::Len(b) => b.r.dynamic() || b.s.is_some(),
            Num::Const(_) | Num::Count(_) => false,
            Num::Arith(op, a, b) => {
                matches!(op, ArithOp::Div | ArithOp::Mod) || a.dynamic() || b.dynamic()
            }
            Num::And(a, b) => a.dynamic() || b.dynamic(),
            Num::Neg(a) | Num::Abs(a) => a.dynamic(),
            Num::Extreme(..) | Num::Need(..) => true,
        }
    }
}

enum Operand {
    Num {
        kind: Kind,
        need: u32,
        occ: Vec<Num>,
    },
    Bytes {
        need: u32,
        occ: Vec<Bytes>,
    },
    /// A protocol whose bytes the generator does not read: only presence.
    Presence(u32),
}

fn at(h: Hdr, off: i32, width: u8) -> Scalar {
    Scalar::At(h, whole(off, width))
}

fn at_bits(h: Hdr, off: i32, width: u8, shift: u8, mask: u32) -> Scalar {
    Scalar::At(h, bits(off, width, shift, mask))
}

fn hdr_len(h: Hdr, off: i32, shift: u8) -> Scalar {
    Scalar::At(
        h,
        Bits {
            mul: 4,
            ..bits(off, 1, shift, 0xf)
        },
    )
}

fn meta_bit(mask: u8, invert: bool) -> Scalar {
    Scalar::Fact {
        off: off::META,
        size: Size::B,
        mask: mask as u32,
        invert,
    }
}

/// The occurrences of a per-tag field: the TCI (or inner EtherType) bits of each tag.
fn tags(ad: bool, b: impl Fn(i32) -> Bits) -> Vec<Scalar> {
    (0..2)
        .map(|i| Scalar::Tag(i, ad, b(14 + 4 * i as i32)))
        .collect()
}

/// The value of a numeric field: its kind, the presence bits it needs, and its occurrences.
fn scalar(f: Field) -> Option<(Kind, u32, Vec<Scalar>)> {
    use Hdr::*;
    use Kind::*;
    let tcp_flag = |m| (Bool, F_TCP, vec![at_bits(Tcp, 12, 2, 0, m)]);
    let flag = |s| (Bool, 0, vec![s]);
    let opt = |slot, len, b| (Uint, F_TCP, vec![Scalar::Opt(slot, len, b)]);
    let h = |h: Hdr, occ: Vec<Scalar>| (Uint, h.flags(), occ);
    Some(match f {
        Field::EthType => h(Eth, vec![Scalar::EthType]),
        Field::ArpHwType => h(Arp, vec![at(Arp, 0, 2)]),
        Field::ArpProtoType => h(Arp, vec![at(Arp, 2, 2)]),
        Field::ArpHwSize => h(Arp, vec![at(Arp, 4, 1)]),
        Field::ArpProtoSize => h(Arp, vec![at(Arp, 5, 1)]),
        Field::ArpOpcode => h(Arp, vec![at(Arp, 6, 2)]),
        Field::ArpSrcProtoIpv4 => (Addr, F_ARP, vec![Scalar::ArpIp(false)]),
        Field::ArpDstProtoIpv4 => (Addr, F_ARP, vec![Scalar::ArpIp(true)]),
        Field::VlanPriority => (Uint, F_ETH, tags(false, |o| bits(o, 2, 13, 7))),
        Field::VlanDei => (Bool, F_ETH, tags(false, |o| bits(o, 2, 12, 1))),
        Field::VlanId => (Uint, F_ETH, tags(false, |o| bits(o, 2, 0, 0xfff))),
        Field::VlanEtype => (Uint, F_ETH, tags(false, |o| whole(o + 2, 2))),
        Field::Ieee8021adPriority => (Uint, F_ETH, tags(true, |o| bits(o, 2, 13, 7))),
        Field::Ieee8021adDei => (Uint, F_ETH, tags(true, |o| bits(o, 2, 12, 1))),
        Field::Ieee8021adId => (Uint, F_ETH, tags(true, |o| bits(o, 2, 0, 0xfff))),

        Field::IpVersion => h(Ip, vec![at_bits(Ip, 0, 1, 4, 0xf)]),
        Field::IpHdrLen => h(Ipv4, vec![hdr_len(Ipv4, 0, 0)]),
        Field::IpDsfield => h(Ipv4, vec![at(Ipv4, 1, 1)]),
        Field::IpDsfieldDscp => h(Ipv4, vec![at_bits(Ipv4, 1, 1, 2, 0x3f)]),
        Field::IpDsfieldEcn => h(Ipv4, vec![at_bits(Ipv4, 1, 1, 0, 3)]),
        Field::IpLen => h(Ipv4, vec![at(Ipv4, 2, 2)]),
        Field::IpId => h(Ipv4, vec![at(Ipv4, 4, 2)]),
        Field::IpFlags => h(Ipv4, vec![at_bits(Ipv4, 6, 1, 5, 7)]),
        Field::IpFlagsRb => (Bool, F_IPV4, vec![at_bits(Ipv4, 6, 1, 0, 0x80)]),
        Field::IpFlagsDf => (Bool, F_IPV4, vec![at_bits(Ipv4, 6, 1, 0, 0x40)]),
        Field::IpFlagsMf => (Bool, F_IPV4, vec![at_bits(Ipv4, 6, 1, 0, 0x20)]),
        Field::IpFragOffset => h(Ipv4, vec![at_bits(Ipv4, 6, 2, 0, 0x1fff)]),
        Field::IpTtl => h(Ipv4, vec![at(Ipv4, 8, 1)]),
        Field::IpProto => h(Ipv4, vec![at(Ipv4, 9, 1)]),
        Field::IpChecksum => h(Ipv4, vec![at(Ipv4, 10, 2)]),
        Field::IpSrc => (Addr, F_IPV4, vec![at(Ipv4, 12, 4)]),
        Field::IpDst => (Addr, F_IPV4, vec![at(Ipv4, 16, 4)]),
        Field::IpAddr => (Addr, F_IPV4, vec![at(Ipv4, 12, 4), at(Ipv4, 16, 4)]),

        Field::Ipv6Version => h(Ipv6, vec![at_bits(Ipv6, 0, 1, 4, 0xf)]),
        Field::Ipv6Tclass => h(Ipv6, vec![at_bits(Ipv6, 0, 4, 20, 0xff)]),
        Field::Ipv6TclassDscp => h(Ipv6, vec![at_bits(Ipv6, 0, 4, 22, 0x3f)]),
        Field::Ipv6TclassEcn => h(Ipv6, vec![at_bits(Ipv6, 0, 4, 20, 3)]),
        Field::Ipv6Flow => h(Ipv6, vec![at_bits(Ipv6, 0, 4, 0, 0xfffff)]),
        Field::Ipv6Plen => h(Ipv6, vec![at(Ipv6, 4, 2)]),
        Field::Ipv6Nxt => h(Ipv6, vec![at(Ipv6, 6, 1)]),
        Field::Ipv6Hlim => h(Ipv6, vec![at(Ipv6, 7, 1)]),

        Field::TcpSrcport => h(Tcp, vec![at(Tcp, 0, 2)]),
        Field::TcpDstport => h(Tcp, vec![at(Tcp, 2, 2)]),
        Field::TcpPort => h(Tcp, vec![at(Tcp, 0, 2), at(Tcp, 2, 2)]),
        Field::TcpSeqRaw => h(Tcp, vec![at(Tcp, 4, 4)]),
        Field::TcpAckRaw => h(Tcp, vec![at(Tcp, 8, 4)]),
        Field::TcpHdrLen => h(Tcp, vec![hdr_len(Tcp, 12, 4)]),
        Field::TcpFlags => h(Tcp, vec![at_bits(Tcp, 12, 2, 0, 0xfff)]),
        Field::TcpFlagsRes => (Bool, F_TCP, vec![at_bits(Tcp, 12, 1, 0, 0x0e)]),
        Field::TcpFlagsAe => tcp_flag(0x100),
        Field::TcpFlagsCwr => tcp_flag(0x80),
        Field::TcpFlagsEce => tcp_flag(0x40),
        Field::TcpFlagsUrg => tcp_flag(0x20),
        Field::TcpFlagsAck => tcp_flag(0x10),
        Field::TcpFlagsPush => tcp_flag(0x08),
        Field::TcpFlagsReset => tcp_flag(0x04),
        Field::TcpFlagsSyn => tcp_flag(0x02),
        Field::TcpFlagsFin => tcp_flag(0x01),
        Field::TcpWindowSizeValue => h(Tcp, vec![at(Tcp, 14, 2)]),
        Field::TcpChecksum => h(Tcp, vec![at(Tcp, 16, 2)]),
        Field::TcpUrgentPointer => h(Tcp, vec![at(Tcp, 18, 2)]),
        Field::TcpLen => h(Tcp, vec![Scalar::TcpLen]),
        Field::TcpOptionsMssVal => opt(0, 4, whole(2, 2)),
        Field::TcpOptionsWscaleShift => opt(1, 3, whole(2, 1)),
        Field::TcpOptionsWscaleMultiplier => (Uint, F_TCP, vec![Scalar::WscaleMul]),
        Field::TcpOptionsTimestampTsval => opt(3, 10, whole(2, 4)),
        Field::TcpOptionsTimestampTsecr => opt(3, 10, whole(6, 4)),

        Field::UdpSrcport => h(Udp, vec![at(Udp, 0, 2)]),
        Field::UdpDstport => h(Udp, vec![at(Udp, 2, 2)]),
        Field::UdpPort => h(Udp, vec![at(Udp, 0, 2), at(Udp, 2, 2)]),
        Field::UdpLength => h(Udp, vec![at(Udp, 4, 2)]),
        Field::UdpChecksum => h(Udp, vec![at(Udp, 6, 2)]),

        Field::IcmpType => h(Icmp, vec![at(Icmp, 0, 1)]),
        Field::IcmpCode => h(Icmp, vec![at(Icmp, 1, 1)]),
        Field::IcmpChecksum => h(Icmp, vec![at(Icmp, 2, 2)]),
        Field::Icmpv6Type => h(Icmpv6, vec![at(Icmpv6, 0, 1)]),
        Field::Icmpv6Code => h(Icmpv6, vec![at(Icmpv6, 1, 1)]),
        Field::Icmpv6Checksum => h(Icmpv6, vec![at(Icmpv6, 2, 2)]),

        Field::FrameLen | Field::FrameCapLen => (Uint, 0, vec![Scalar::FrameLen]),
        Field::Inbound => flag(meta_bit(M_OUTBOUND, true)),
        Field::Outbound => flag(meta_bit(M_OUTBOUND, false)),
        Field::Loopback => flag(meta_bit(M_LOOPBACK, false)),
        Field::Impostor => flag(meta_bit(M_IMPOSTOR, false)),
        Field::Fragment => flag(Scalar::Fact {
            off: off::FLAGS,
            size: Size::W,
            mask: F_FRAG,
            invert: false,
        }),
        Field::Ifidx => (
            Uint,
            0,
            vec![Scalar::Fact {
                off: off::IFINDEX,
                size: Size::W,
                mask: u32::MAX,
                invert: false,
            }],
        ),
        Field::Protocol => (
            Uint,
            F_IPV4 | F_IPV6,
            vec![Scalar::Fact {
                off: off::PROTO,
                size: Size::B,
                mask: 0xff,
                invert: false,
            }],
        ),
        _ => return None,
    })
}

/// The byte occurrences of a field.
fn regions(f: Field) -> Option<(u32, Vec<Region>)> {
    use Region::*;
    let one = |r| Some((0, vec![r]));
    match f {
        Field::Frame => one(Frame),
        Field::Eth => one(At(Hdr::Eth, 0, 14)),
        Field::EthDst => one(At(Hdr::Eth, 0, 6)),
        Field::EthSrc => one(At(Hdr::Eth, 6, 6)),
        Field::EthAddr => Some((F_ETH, vec![At(Hdr::Eth, 0, 6), At(Hdr::Eth, 6, 6)])),
        Field::Vlan => Some((F_ETH, vec![Tag(0, false), Tag(1, false)])),
        Field::Ieee8021ad => Some((F_ETH, vec![Tag(0, true), Tag(1, true)])),
        Field::Arp => one(Arp),
        Field::ArpSrcHwMac => one(ArpMac(false)),
        Field::ArpDstHwMac => one(ArpMac(true)),
        Field::Ip => one(Ipv4Hdr),
        Field::Ipv6Src => one(At(Hdr::Ipv6, 8, 16)),
        Field::Ipv6Dst => one(At(Hdr::Ipv6, 24, 16)),
        Field::Ipv6Addr => Some((F_IPV6, vec![At(Hdr::Ipv6, 8, 16), At(Hdr::Ipv6, 24, 16)])),
        Field::Tcp => one(TcpHdr),
        Field::TcpPayload => one(Payload(Hdr::Tcp)),
        Field::TcpOptions => one(TcpOpts),
        Field::TcpOptionsMss => one(Opt(0)),
        Field::TcpOptionsWscale => one(Opt(1)),
        Field::TcpOptionsSackPerm => one(Opt(2)),
        Field::TcpOptionsTimestamp => one(Opt(3)),
        Field::Udp => one(At(Hdr::Udp, 0, 8)),
        Field::UdpPayload => one(Payload(Hdr::Udp)),
        Field::Icmp => one(L4ToEnd(Hdr::Icmp)),
        Field::Icmpv6 => one(L4ToEnd(Hdr::Icmpv6)),
        _ => None,
    }
}

fn operand(v: &Value) -> Result<Operand, Error> {
    match v {
        Value::Field(f) => {
            if let Some((kind, need, occ)) = scalar(*f) {
                return Ok(Operand::Num {
                    kind,
                    need,
                    occ: occ.into_iter().map(Num::Load).collect(),
                });
            }
            if let Some((need, rs)) = regions(*f) {
                return Ok(Operand::Bytes {
                    need,
                    occ: rs.into_iter().map(|r| Bytes { r, s: None }).collect(),
                });
            }
            match f {
                Field::Ipv6 => Ok(Operand::Presence(F_IPV6)),
                _ => unsupported(format!("the field `{}`", def(*f).name)),
            }
        }
        Value::Slice(base, ranges) => match (operand(base)?, ranges.as_slice()) {
            (Operand::Bytes { need, occ }, [s]) => Ok(Operand::Bytes {
                need,
                occ: occ
                    .into_iter()
                    .map(|b| match b.s {
                        None => Ok(Bytes {
                            r: b.r,
                            s: Some(*s),
                        }),
                        Some(_) => unsupported("slices of slices"),
                    })
                    .collect::<Result<_, _>>()?,
            }),
            _ => unsupported("this slice"),
        },
        Value::Len(base) => match operand(base)? {
            Operand::Bytes { need, occ } => Ok(Operand::Num {
                kind: Kind::Uint,
                need,
                occ: occ.into_iter().map(Num::Len).collect(),
            }),
            Operand::Num {
                kind: Kind::Addr,
                need,
                occ,
            } => Ok(Operand::Num {
                kind: Kind::Uint,
                need,
                occ: occ.iter().map(|_| Num::Const(4)).collect(),
            }),
            _ => unsupported("`len()` of this value"),
        },
        Value::Count(base) => {
            if !matches!(&**base, Value::Field(_)) {
                return unsupported("`count()` of a computed value");
            }
            let occ = match operand(base)? {
                Operand::Num { need, occ, .. } => occ
                    .into_iter()
                    .map(|x| Occ::Num(Num::need(need, x)))
                    .collect(),
                // Regions test their own headers.
                Operand::Bytes { occ, .. } => occ.into_iter().map(Occ::Bytes).collect(),
                Operand::Presence(_) => return unsupported("`count()` of this protocol"),
            };
            Ok(Operand::Num {
                kind: Kind::Uint,
                need: 0,
                occ: vec![Num::Count(occ)],
            })
        }
        Value::BitAnd(a, b) => binary(a, b, |x, y| Num::And(Box::new(x), Box::new(y))),
        Value::Arith(op, a, b) => binary(a, b, |x, y| Num::Arith(*op, Box::new(x), Box::new(y))),
        Value::Neg(a) | Value::Abs(a) => {
            let (need, occ) = numbers(a)?;
            let abs = matches!(v, Value::Abs(_));
            Ok(Operand::Num {
                kind: Kind::Int,
                need,
                occ: occ
                    .into_iter()
                    .map(|x| {
                        if abs {
                            Num::Abs(Box::new(x))
                        } else {
                            Num::Neg(Box::new(x))
                        }
                    })
                    .collect(),
            })
        }
        Value::Extreme { max, args } => {
            let mut all = Vec::new();
            for a in args {
                // An absent argument is skipped.
                let (need, occ) = numbers(a)?;
                all.extend(occ.into_iter().map(|x| Num::need(need, x)));
            }
            Ok(Operand::Num {
                kind: Kind::Int,
                need: 0,
                occ: vec![Num::Extreme(*max, all)],
            })
        }
        Value::Lit(Lit::Uint(n)) => match i64::try_from(*n) {
            Ok(n) => Ok(Operand::Num {
                kind: Kind::Int,
                need: 0,
                occ: vec![Num::Const(n)],
            }),
            Err(_) => unsupported("this constant"),
        },
        Value::Lit(Lit::Int(n)) => Ok(Operand::Num {
            kind: Kind::Int,
            need: 0,
            occ: vec![Num::Const(*n)],
        }),
        Value::Layer(..) => unsupported("layer operators (`#n`)"),
        Value::Raw(..) => unsupported("`@field`"),
        Value::Case { .. } => unsupported("`upper()` and `lower()`"),
        Value::Lit(_) => unsupported("a constant here"),
    }
}

impl Num {
    /// `x`, absent unless one of the presence bits `need` is set.
    fn need(need: u32, x: Num) -> Num {
        if need == 0 {
            x
        } else {
            Num::Need(need, Box::new(x))
        }
    }
}

/// The numeric occurrences of a value, and the presence bits they need.
fn numbers(v: &Value) -> Result<(u32, Vec<Num>), Error> {
    match operand(v)? {
        Operand::Num {
            kind: Kind::Uint | Kind::Int,
            need,
            occ,
        } => Ok((need, occ)),
        _ => unsupported("arithmetic on this value"),
    }
}

/// Every pair of occurrences, combined; at most 4, as `value::Vals` holds.
fn binary(a: &Value, b: &Value, f: impl Fn(Num, Num) -> Num) -> Result<Operand, Error> {
    let (na, a) = numbers(a)?;
    let (nb, b) = numbers(b)?;
    if a.len() * b.len() > 4 {
        return unsupported("arithmetic with more than 4 results");
    }
    // One test of the headers up front when both sides need the same, else one per side.
    let (need, a, b) = match (na, nb) {
        (0, n) | (n, 0) => (n, a, b),
        (x, y) if x == y => (x, a, b),
        (x, y) => (
            0,
            a.into_iter().map(|v| Num::need(x, v)).collect(),
            b.into_iter().map(|v| Num::need(y, v)).collect(),
        ),
    };
    let mut occ = Vec::new();
    for x in &a {
        for y in &b {
            occ.push(f(x.clone(), y.clone()));
        }
    }
    Ok(Operand::Num {
        kind: Kind::Int,
        need,
        occ,
    })
}

// ---------------------------------------------------------------------------------------------
// Predicates.

/// A test of one numeric occurrence, in [`VAL`].
#[derive(Clone, Debug)]
enum Pred {
    Const(bool),
    /// `VAL cond value`, on the low 32 bits.
    Cmp(Cond, u32),
    /// `(VAL & mask) cond value`.
    Masked(Cond, u32, u32),
    Truthy,
    Range(u32, u32),
    /// A signed 64-bit comparison.
    SCmp(CmpOp, i64),
    SRange(i64, i64),
    Any(Vec<Pred>),
}

/// The unsigned jump condition of a comparison.
fn jcond(op: CmpOp) -> Cond {
    match op {
        CmpOp::Eq => Cond::Eq,
        CmpOp::Ne => Cond::Ne,
        CmpOp::Lt => Cond::Lt,
        CmpOp::Le => Cond::Le,
        CmpOp::Gt => Cond::Gt,
        CmpOp::Ge => Cond::Ge,
    }
}

/// The signed jump condition of a comparison.
fn scond(op: CmpOp) -> Cond {
    match op {
        CmpOp::Eq => Cond::Eq,
        CmpOp::Ne => Cond::Ne,
        CmpOp::Lt => Cond::Slt,
        CmpOp::Le => Cond::Sle,
        CmpOp::Gt => Cond::Sgt,
        CmpOp::Ge => Cond::Sge,
    }
}

fn mirror(op: CmpOp) -> CmpOp {
    match op {
        CmpOp::Lt => CmpOp::Gt,
        CmpOp::Le => CmpOp::Ge,
        CmpOp::Gt => CmpOp::Lt,
        CmpOp::Ge => CmpOp::Le,
        op => op,
    }
}

fn num(l: &Lit) -> Option<i128> {
    match l {
        Lit::Uint(v) => Some(*v as i128),
        Lit::Int(v) => Some(*v as i128),
        _ => None,
    }
}

/// A comparison decided by a constant out of the value's range: a value is greater than any
/// constant below its range, smaller than any above.
fn decided(op: CmpOp, above: bool) -> Pred {
    Pred::Const(match op {
        CmpOp::Eq => false,
        CmpOp::Ne => true,
        CmpOp::Lt | CmpOp::Le => above,
        CmpOp::Gt | CmpOp::Ge => !above,
    })
}

/// `VAL op lit`, as `value::compare` decides it for a value of `kind`.
fn cmp_pred(kind: Kind, op: CmpOp, l: &Lit) -> Result<Pred, Error> {
    let ord = !matches!(op, CmpOp::Eq | CmpOp::Ne);
    Ok(match (kind, l) {
        (Kind::Uint, l) if num(l).is_some() => {
            let n = num(l).unwrap_or_default();
            match u32::try_from(n) {
                Ok(v) => Pred::Cmp(jcond(op), v),
                Err(_) => decided(op, n > 0),
            }
        }
        (Kind::Int, l) if num(l).is_some() => {
            let n = num(l).unwrap_or_default();
            match i64::try_from(n) {
                Ok(v) => Pred::SCmp(op, v),
                Err(_) => decided(op, n > 0),
            }
        }
        // Booleans have no order.
        (Kind::Bool, Lit::Bool(_)) if ord => Pred::Const(false),
        (Kind::Bool, Lit::Bool(b)) => {
            if *b == (op == CmpOp::Eq) {
                Pred::Truthy
            } else {
                Pred::Cmp(Cond::Eq, 0)
            }
        }
        (Kind::Addr, Lit::Ipv4(a, p)) => {
            let v = u32::from_be_bytes(*a);
            // Equality honours the prefix; order compares the address bytes.
            if ord || *p >= 32 {
                Pred::Cmp(jcond(op), v)
            } else {
                let mask = u32::MAX.checked_shl(32 - *p as u32).unwrap_or(0);
                Pred::Masked(jcond(op), mask, v & mask)
            }
        }
        _ => return unsupported("a comparison of different types"),
    })
}

fn member_pred(kind: Kind, item: &SetItem) -> Result<Pred, Error> {
    match item {
        SetItem::One(l) => cmp_pred(kind, CmpOp::Eq, l),
        SetItem::Range(lo, hi) => Ok(match (kind, lo, hi) {
            (Kind::Uint, lo, hi) if num(lo).is_some() && num(hi).is_some() => {
                let lo = num(lo).unwrap_or_default().max(0);
                let hi = num(hi).unwrap_or_default().min(u32::MAX as i128);
                if lo > hi {
                    Pred::Const(false)
                } else {
                    Pred::Range(lo as u32, hi as u32)
                }
            }
            (Kind::Int, lo, hi) if num(lo).is_some() && num(hi).is_some() => {
                let lo = num(lo).unwrap_or_default().max(i64::MIN as i128);
                let hi = num(hi).unwrap_or_default().min(i64::MAX as i128);
                if lo > hi {
                    Pred::Const(false)
                } else {
                    Pred::SRange(lo as i64, hi as i64)
                }
            }
            (Kind::Addr, Lit::Ipv4(lo, _), Lit::Ipv4(hi, _)) => {
                Pred::Range(u32::from_be_bytes(*lo), u32::from_be_bytes(*hi))
            }
            (Kind::Bool, Lit::Bool(_), Lit::Bool(_)) => Pred::Const(false),
            _ => return unsupported("a set of a different type"),
        }),
    }
}

/// The items of a set as sorted, disjoint unsigned ranges, when they all are ranges.
fn as_ranges(items: &[Pred]) -> Option<Vec<(u32, u32)>> {
    let mut v = Vec::new();
    for p in items {
        match *p {
            Pred::Const(false) => {}
            Pred::Cmp(Cond::Eq, x) => v.push((x, x)),
            Pred::Range(lo, hi) => v.push((lo, hi)),
            // A prefix: the addresses from the network to the broadcast address.
            Pred::Masked(Cond::Eq, mask, x)
                if mask.leading_ones() + mask.trailing_zeros() == 32 =>
            {
                v.push((x, x | !mask))
            }
            _ => return None,
        }
    }
    v.sort_unstable();
    let mut out: Vec<(u32, u32)> = Vec::with_capacity(v.len());
    for (lo, hi) in v {
        match out.last_mut() {
            Some(last) if lo as u64 <= last.1 as u64 + 1 => last.1 = last.1.max(hi),
            _ => out.push((lo, hi)),
        }
    }
    Some(out)
}

/// A test of one byte occurrence, whose start and length are in [`VAL`] and [`LEN`].
#[derive(Clone, Debug)]
enum BPred {
    Const(bool),
    /// Equal to the bytes; an address compares only its first `bits` bits.
    Eq(Vec<u8>, usize),
    Not(Box<BPred>),
    /// Ordered against the bytes, as `value::ord` orders byte strings (lexicographically).
    Ord(CmpOp, Vec<u8>),
    Range(Vec<u8>, Vec<u8>),
    Contains(Vec<u8>),
    Any(Vec<BPred>),
}

/// The bytes of a literal, and how many of their bits equality compares.
fn lit_bytes(l: &Lit) -> Result<(Vec<u8>, usize), Error> {
    match l {
        Lit::Bytes(b) => Ok((b.clone(), 8 * b.len())),
        Lit::Ether(m) => Ok((m.to_vec(), 48)),
        Lit::Ipv6(a, p) => Ok((a.to_vec(), (*p as usize).min(128))),
        _ => unsupported("a comparison of different types"),
    }
}

fn bytes_cmp_pred(op: CmpOp, l: &Lit) -> Result<BPred, Error> {
    let (b, bits) = lit_bytes(l)?;
    Ok(match op {
        CmpOp::Eq => BPred::Eq(b, bits),
        CmpOp::Ne => BPred::Not(Box::new(BPred::Eq(b, bits))),
        op => BPred::Ord(op, b),
    })
}

fn bytes_member_pred(item: &SetItem) -> Result<BPred, Error> {
    match item {
        SetItem::One(l) => bytes_cmp_pred(CmpOp::Eq, l),
        SetItem::Range(lo, hi) => Ok(BPred::Range(lit_bytes(lo)?.0, lit_bytes(hi)?.0)),
    }
}

/// The value of `n` bytes as the machine loads them from memory.
fn ne_word(b: &[u8]) -> u64 {
    let mut w = [0u8; 8];
    w[..b.len()].copy_from_slice(b);
    let w = u64::from_ne_bytes(w);
    if cfg!(target_endian = "big") {
        w >> (64 - 8 * b.len())
    } else {
        w
    }
}

/// The value of up to 4 bytes read big-endian.
fn be_word(b: &[u8]) -> u32 {
    b.iter().fold(0, |acc, &x| acc << 8 | x as u32)
}

// ---------------------------------------------------------------------------------------------
// Code.

fn emit(test: &Test, env: &Env<'_>) -> Result<Matcher, Error> {
    let mut g = Gen {
        a: Asm::default(),
        slots: 0,
        options: false,
        ethernet: env.layer == Layer::Ethernet,
    };
    let vlan = env.layer == Layer::Ethernet && l2_sensitive(test);
    let a = &mut g.a;
    let (yes, no, act, out) = (a.label(), a.label(), a.label(), a.label());
    a.alu64_reg(Alu::Mov, CTX, 1);
    a.store_imm(Size::W, FP, -4, 0);
    a.alu64_reg(Alu::Mov, 2, FP);
    a.alu64_imm(Alu::Add, 2, -4);
    a.ld_map(1, MapRef::Facts);
    a.call(MAP_LOOKUP_ELEM);
    a.jmp_imm(Cond::Eq, 0, 0, out);
    a.alu64_reg(Alu::Mov, FACTS, 0);
    if vlan {
        // The kernel sees the frame without its outer tag: let user space decide.
        a.load(Size::B, 1, FACTS, off::META);
        a.jmp32_imm(Cond::Set, 1, M_VLAN as u32, yes);
    }
    g.test(test, yes, no)?;
    let a = &mut g.a;
    a.bind(yes);
    a.store_imm(Size::B, FACTS, off::VERDICT, 1);
    a.ja(act);
    a.bind(no);
    a.store_imm(Size::B, FACTS, off::VERDICT, 0);
    a.bind(act);
    a.alu64_reg(Alu::Mov, 1, CTX);
    a.ld_map(2, MapRef::Progs);
    a.alu64_imm(Alu::Mov, 3, SLOT_ACTION as i32);
    a.call(TAIL_CALL);
    a.bind(out);
    a.alu64_imm(Alu::Mov, 0, TC_ACT_UNSPEC);
    a.exit();
    let (insns, maps) = g.a.finish()?;
    Ok(Matcher {
        insns,
        maps,
        exact: !vlan,
        options: g.options,
    })
}

struct Gen {
    a: Asm,
    /// Stack slots in use.
    slots: usize,
    /// Whether the code reads the TCP options of the facts.
    options: bool,
    /// Whether the handle is at the ETHERNET layer, where a VLAN tag may have been offloaded.
    ethernet: bool,
}

impl Gen {
    /// Takes a stack slot for an intermediate value.
    fn push(&mut self) -> Result<i16, Error> {
        if self.slots >= SLOTS {
            return unsupported("this much nesting");
        }
        let at = SLOT0 - 8 * self.slots as i16;
        self.slots += 1;
        Ok(at)
    }

    fn pop(&mut self) {
        self.slots -= 1;
    }

    /// Jumps to `t` if `test` holds, else to `f`.
    fn test(&mut self, test: &Test, t: Label, f: Label) -> Result<(), Error> {
        self.a.check_size()?;
        match test {
            Test::Const(b) => self.a.ja(if *b { t } else { f }),
            Test::Not(x) => self.test(x, f, t)?,
            Test::And(xs) | Test::Or(xs) => {
                let and = matches!(test, Test::And(_));
                let Some((last, init)) = xs.split_last() else {
                    self.a.ja(if and { t } else { f });
                    return Ok(());
                };
                for x in init {
                    let next = self.a.label();
                    if and {
                        self.test(x, next, f)?;
                    } else {
                        self.test(x, t, next)?;
                    }
                    self.a.bind(next);
                }
                self.test(last, t, f)?;
            }
            Test::Xor(x, y) => {
                // Keep the first result on the stack, so that each side is compiled once.
                let slot = self.push()?;
                let (xt, xf, done) = (self.a.label(), self.a.label(), self.a.label());
                self.test(x, xt, xf)?;
                self.a.bind(xt);
                self.a.store_imm(Size::DW, FP, slot, 1);
                self.a.ja(done);
                self.a.bind(xf);
                self.a.store_imm(Size::DW, FP, slot, 0);
                self.a.bind(done);
                let (yt, yf) = (self.a.label(), self.a.label());
                self.test(y, yt, yf)?;
                let a = &mut self.a;
                a.bind(yt);
                a.load(Size::DW, 1, FP, slot);
                a.jmp_imm(Cond::Ne, 1, 0, f);
                a.ja(t);
                a.bind(yf);
                a.load(Size::DW, 1, FP, slot);
                a.jmp_imm(Cond::Ne, 1, 0, t);
                a.ja(f);
                self.pop();
            }
            Test::If(c, x, y) => {
                let (ct, cf) = (self.a.label(), self.a.label());
                self.test(c, ct, cf)?;
                self.a.bind(ct);
                self.test(x, t, f)?;
                self.a.bind(cf);
                self.test(y, t, f)?;
            }
            Test::Exists(v) => match operand(v)? {
                Operand::Num { need, occ, .. } => {
                    if occ.iter().any(Num::dynamic) {
                        self.quant(need, &occ, Quant::Any, false, &Pred::Const(true), t, f)?;
                    } else {
                        self.need(need, f);
                        self.a.ja(t);
                    }
                }
                Operand::Bytes { need, occ } => {
                    self.quant_bytes(need, &occ, Quant::Any, false, &BPred::Const(true), t, f)?
                }
                Operand::Presence(flags) => {
                    self.need(flags, f);
                    self.a.ja(t);
                }
            },
            Test::Truthy(v) => match operand(v)? {
                Operand::Num { need, occ, .. } => {
                    self.quant(need, &occ, Quant::Any, false, &Pred::Truthy, t, f)?
                }
                _ => return unsupported("the truth value of bytes"),
            },
            Test::Cmp {
                lhs,
                op,
                quant,
                rhs,
            } => {
                let (v, op, l) = match (lhs, rhs) {
                    (v, Value::Lit(l)) if !matches!(v, Value::Lit(_)) => (v, *op, l),
                    (Value::Lit(l), v) if !matches!(v, Value::Lit(_)) => (v, mirror(*op), l),
                    _ => return self.pairs(lhs, *op, *quant, rhs, t, f),
                };
                match operand(v)? {
                    Operand::Num { kind, need, occ } => {
                        let p = cmp_pred(kind, op, l)?;
                        self.quant(need, &occ, *quant, false, &p, t, f)?;
                    }
                    Operand::Bytes { need, occ } => {
                        let p = bytes_cmp_pred(op, l)?;
                        self.quant_bytes(need, &occ, *quant, false, &p, t, f)?;
                    }
                    Operand::Presence(_) => return unsupported("the bytes of this protocol"),
                }
            }
            Test::Member {
                lhs,
                set,
                quant,
                negate,
            } => match operand(lhs)? {
                Operand::Num { kind, need, occ } => {
                    let items = set
                        .iter()
                        .map(|i| member_pred(kind, i))
                        .collect::<Result<Vec<_>, _>>()?;
                    self.quant(need, &occ, *quant, *negate, &Pred::Any(items), t, f)?;
                }
                Operand::Bytes { need, occ } => {
                    let items = set
                        .iter()
                        .map(bytes_member_pred)
                        .collect::<Result<Vec<_>, _>>()?;
                    self.quant_bytes(need, &occ, *quant, *negate, &BPred::Any(items), t, f)?;
                }
                Operand::Presence(_) => return unsupported("sets of this protocol"),
            },
            Test::Contains { lhs, rhs, quant } => {
                let needle = match rhs {
                    Value::Lit(l) => lit_bytes(l)?.0,
                    _ => return unsupported("`contains` of a field"),
                };
                match operand(lhs)? {
                    Operand::Bytes { need, occ } => {
                        let p = BPred::Contains(needle);
                        self.quant_bytes(need, &occ, *quant, false, &p, t, f)?;
                    }
                    _ => return unsupported("`contains` on this value"),
                }
            }
            Test::Matches { .. } => return unsupported("`matches` (user space only)"),
        }
        Ok(())
    }

    /// Jumps to `absent` unless one of `flags` is set.
    fn need(&mut self, flags: u32, absent: Label) {
        if flags == 0 {
            return;
        }
        self.a.load(Size::W, 1, FACTS, off::FLAGS);
        self.a.alu32_imm(Alu::And, 1, flags as i32);
        self.a.jmp32_imm(Cond::Eq, 1, 0, absent);
    }

    /// `quant` occurrence satisfies `pred` (or, with `negate`, the value is present and that is
    /// not the case). Occurrences that are absent do not count; with none, the test is false.
    #[allow(clippy::too_many_arguments)]
    fn quant(
        &mut self,
        need: u32,
        occ: &[Num],
        quant: Quant,
        negate: bool,
        pred: &Pred,
        t: Label,
        f: Label,
    ) -> Result<(), Error> {
        for x in occ {
            if x.range().is_none() {
                return unsupported("arithmetic that may overflow or divide signed values");
            }
        }
        self.need(need, f);
        let absent = f;
        let (t, f) = if negate { (f, t) } else { (t, f) };
        let seen = self.seen(occ.len() > 1 && occ.iter().any(Num::dynamic))?;
        let end = self.a.label();
        for (i, x) in occ.iter().enumerate() {
            let last = i + 1 == occ.len();
            let next = if last { end } else { self.a.label() };
            self.num(x, if occ.len() == 1 { absent } else { next })?;
            if let Some(s) = seen {
                self.a.store_imm(Size::DW, FP, s, 1);
            }
            match quant {
                Quant::Any => self.pred(pred, t, next),
                Quant::All => self.pred(pred, next, f),
            }
            if !last {
                self.a.bind(next);
            }
        }
        self.end(end, seen, quant, t, f, absent);
        Ok(())
    }

    /// The same over byte occurrences.
    #[allow(clippy::too_many_arguments)]
    fn quant_bytes(
        &mut self,
        need: u32,
        occ: &[Bytes],
        quant: Quant,
        negate: bool,
        pred: &BPred,
        t: Label,
        f: Label,
    ) -> Result<(), Error> {
        self.need(need, f);
        let absent = f;
        let (t, f) = if negate { (f, t) } else { (t, f) };
        let dynamic = occ.iter().any(|b| b.r.dynamic() || b.s.is_some());
        let seen = self.seen(occ.len() > 1 && dynamic)?;
        let end = self.a.label();
        for (i, b) in occ.iter().enumerate() {
            let last = i + 1 == occ.len();
            let next = if last { end } else { self.a.label() };
            self.region(b.r, b.s, if occ.len() == 1 { absent } else { next })?;
            if let Some(s) = seen {
                self.a.store_imm(Size::DW, FP, s, 1);
            }
            match quant {
                Quant::Any => self.bpred(pred, *b, t, next, absent)?,
                Quant::All => self.bpred(pred, *b, next, f, absent)?,
            }
            if !last {
                self.a.bind(next);
            }
        }
        self.end(end, seen, quant, t, f, absent);
        Ok(())
    }

    /// A slot that records whether some occurrence was present, when that can vary.
    fn seen(&mut self, dynamic: bool) -> Result<Option<i16>, Error> {
        if !dynamic {
            return Ok(None);
        }
        let s = self.push()?;
        self.a.store_imm(Size::DW, FP, s, 0);
        Ok(Some(s))
    }

    /// After the last occurrence: none satisfied the predicate (any), or all did (all), unless
    /// none was present.
    fn end(
        &mut self,
        end: Label,
        seen: Option<i16>,
        quant: Quant,
        t: Label,
        f: Label,
        absent: Label,
    ) {
        self.a.bind(end);
        if let Some(s) = seen {
            self.a.load(Size::DW, 1, FP, s);
            self.a.jmp_imm(Cond::Eq, 1, 0, absent);
            self.pop();
        }
        self.a.ja(match quant {
            Quant::Any => f,
            Quant::All => t,
        });
    }

    /// A comparison of two numeric values, over `quant` pair of their occurrences.
    fn pairs(
        &mut self,
        lhs: &Value,
        op: CmpOp,
        quant: Quant,
        rhs: &Value,
        t: Label,
        f: Label,
    ) -> Result<(), Error> {
        let side = |v: &Value| match operand(v)? {
            Operand::Num { kind, need, occ } => {
                if occ.iter().any(|x| x.range().is_none()) {
                    return unsupported("arithmetic that may overflow or divide signed values");
                }
                Ok((kind, need, occ))
            }
            _ => unsupported("a comparison of two values that are not numbers"),
        };
        let (kl, nl, l) = side(lhs)?;
        let (kr, nr, r) = side(rhs)?;
        let ord = !matches!(op, CmpOp::Eq | CmpOp::Ne);
        if (kl == Kind::Bool) != (kr == Kind::Bool) || (kl == Kind::Addr) != (kr == Kind::Addr) {
            return unsupported("a comparison of different types");
        }
        if kl == Kind::Bool && ord {
            self.a.ja(f);
            return Ok(());
        }
        let c = if kl == Kind::Int || kr == Kind::Int {
            scond(op)
        } else {
            jcond(op)
        };
        let bool_kind = kl == Kind::Bool;
        self.need(nl, f);
        self.need(nr, f);
        let absent = f;
        let dynamic = l.iter().chain(&r).any(Num::dynamic) && l.len() * r.len() > 1;
        let seen = self.seen(dynamic)?;
        let left = self.push()?;
        let end = self.a.label();
        let single = l.len() * r.len() == 1;
        for (i, x) in l.iter().enumerate() {
            let after_x = if i + 1 == l.len() {
                end
            } else {
                self.a.label()
            };
            self.num(x, if single { absent } else { after_x })?;
            if bool_kind {
                self.truth();
            }
            self.a.store(Size::DW, FP, left, VAL);
            for (j, y) in r.iter().enumerate() {
                let next = if j + 1 == r.len() {
                    after_x
                } else {
                    self.a.label()
                };
                self.num(y, if single { absent } else { next })?;
                if bool_kind {
                    self.truth();
                }
                if let Some(s) = seen {
                    self.a.store_imm(Size::DW, FP, s, 1);
                }
                self.a.load(Size::DW, 1, FP, left);
                match quant {
                    Quant::Any => {
                        self.a.jmp_reg(c, 1, VAL, t);
                        self.a.ja(next);
                    }
                    Quant::All => {
                        self.a.jmp_reg(c, 1, VAL, next);
                        self.a.ja(f);
                    }
                }
                if j + 1 != r.len() {
                    self.a.bind(next);
                }
            }
            if i + 1 != l.len() {
                self.a.bind(after_x);
            }
        }
        self.pop();
        self.end(end, seen, quant, t, f, absent);
        Ok(())
    }

    /// [`VAL`] = 1 if it is non-zero, else 0.
    fn truth(&mut self) {
        let z = self.a.label();
        self.a.jmp_imm(Cond::Eq, VAL, 0, z);
        self.a.alu64_imm(Alu::Mov, VAL, 1);
        self.a.bind(z);
    }

    /// Computes one numeric occurrence into [`VAL`], or jumps to `absent` when it has no value.
    fn num(&mut self, n: &Num, absent: Label) -> Result<(), Error> {
        self.a.check_size()?;
        match n {
            Num::Load(s) => self.scalar(*s, absent),
            Num::Len(b) => {
                self.region(b.r, b.s, absent)?;
                self.a.alu64_reg(Alu::Mov, VAL, LEN);
            }
            Num::Const(c) => self.constant(VAL, *c),
            Num::Count(occ) => {
                let slot = self.push()?;
                self.a.store_imm(Size::DW, FP, slot, 0);
                for o in occ {
                    let skip = self.a.label();
                    match o {
                        Occ::Num(x) => self.num(x, skip)?,
                        Occ::Bytes(b) => self.region(b.r, b.s, skip)?,
                    }
                    self.a.load(Size::DW, 1, FP, slot);
                    self.a.alu64_imm(Alu::Add, 1, 1);
                    self.a.store(Size::DW, FP, slot, 1);
                    self.a.bind(skip);
                }
                self.a.load(Size::DW, VAL, FP, slot);
                self.pop();
            }
            Num::Arith(op, x, y) => {
                let alu = match op {
                    ArithOp::Add => Alu::Add,
                    ArithOp::Sub => Alu::Sub,
                    ArithOp::Mul => Alu::Mul,
                    ArithOp::Div => Alu::Div,
                    ArithOp::Mod => Alu::Mod,
                };
                self.binary(alu, x, y, absent)?;
            }
            Num::And(x, y) => self.binary(Alu::And, x, y, absent)?,
            Num::Neg(x) => {
                self.num(x, absent)?;
                self.negate();
            }
            Num::Abs(x) => {
                self.num(x, absent)?;
                let done = self.a.label();
                self.a.jmp_imm(Cond::Sge, VAL, 0, done);
                self.negate();
                self.a.bind(done);
            }
            Num::Extreme(max, xs) => {
                let have = self.push()?;
                let best = self.push()?;
                self.a.store_imm(Size::DW, FP, have, 0);
                for x in xs {
                    let (skip, take) = (self.a.label(), self.a.label());
                    self.num(x, skip)?;
                    let a = &mut self.a;
                    a.load(Size::DW, 1, FP, have);
                    a.jmp_imm(Cond::Eq, 1, 0, take);
                    a.load(Size::DW, 1, FP, best);
                    a.jmp_reg(if *max { Cond::Sle } else { Cond::Sge }, VAL, 1, skip);
                    a.bind(take);
                    a.store(Size::DW, FP, best, VAL);
                    a.store_imm(Size::DW, FP, have, 1);
                    a.bind(skip);
                }
                let a = &mut self.a;
                a.load(Size::DW, 1, FP, have);
                a.jmp_imm(Cond::Eq, 1, 0, absent);
                a.load(Size::DW, VAL, FP, best);
                self.pop();
                self.pop();
            }
            Num::Need(flags, x) => {
                self.need(*flags, absent);
                self.num(x, absent)?;
            }
        }
        Ok(())
    }

    fn constant(&mut self, reg: Reg, c: i64) {
        match i32::try_from(c) {
            Ok(v) => self.a.alu64_imm(Alu::Mov, reg, v),
            Err(_) => self.a.ld_imm64(reg, c as u64),
        }
    }

    fn negate(&mut self) {
        self.a.alu64_imm(Alu::Mov, 1, 0);
        self.a.alu64_reg(Alu::Sub, 1, VAL);
        self.a.alu64_reg(Alu::Mov, VAL, 1);
    }

    /// `VAL = x alu y`, 64 bits; division by zero has no value. The ranges were checked: no
    /// overflow, and both sides of a division are non-negative.
    fn binary(&mut self, alu: Alu, x: &Num, y: &Num, absent: Label) -> Result<(), Error> {
        let divides = matches!(alu, Alu::Div | Alu::Mod);
        if let Num::Const(c) = y
            && let Ok(v) = i32::try_from(*c)
        {
            if divides && v == 0 {
                self.a.ja(absent);
                return Ok(());
            }
            self.num(x, absent)?;
            self.a.alu64_imm(alu, VAL, v);
            return Ok(());
        }
        self.num(x, absent)?;
        let slot = self.push()?;
        self.a.store(Size::DW, FP, slot, VAL);
        self.num(y, absent)?;
        let a = &mut self.a;
        a.load(Size::DW, 1, FP, slot);
        if divides {
            a.jmp_imm(Cond::Eq, VAL, 0, absent);
        }
        a.alu64_reg(alu, 1, VAL);
        a.alu64_reg(Alu::Mov, VAL, 1);
        self.pop();
        Ok(())
    }

    /// Loads `b.width` bytes at `R2 + b.off` into [`VAL`], shifted, masked and multiplied.
    fn read(&mut self, b: Bits, fail: Label) {
        let a = &mut self.a;
        a.alu64_reg(Alu::Mov, 1, CTX);
        if b.off != 0 {
            a.alu64_imm(Alu::Add, 2, b.off);
        }
        a.alu64_reg(Alu::Mov, 3, FP);
        a.alu64_imm(Alu::Add, 3, SCRATCH as i32);
        a.alu64_imm(Alu::Mov, 4, b.width as i32);
        a.call(SKB_LOAD_BYTES);
        a.jmp_imm(Cond::Ne, 0, 0, fail);
        a.load(Size::of(b.width as usize), VAL, FP, SCRATCH);
        if b.width > 1 {
            a.to_be(VAL, b.width as i32 * 8);
        }
        if b.shift != 0 {
            a.alu32_imm(Alu::Rsh, VAL, b.shift as i32);
        }
        if b.mask != u32::MAX {
            a.alu32_imm(Alu::And, VAL, b.mask as i32);
        }
        if b.mul != 1 {
            a.alu32_imm(Alu::Mul, VAL, b.mul as i32);
        }
    }

    /// Loads bits `b` of the tag in the frame at position `i`, or jumps to `fail`.
    fn tag_bits(&mut self, i: u8, ad: bool, b: Bits, fail: Label) {
        self.tag(i, ad, fail);
        self.a.alu64_imm(Alu::Mov, 2, 0);
        self.read(b, fail);
    }

    /// Jumps to `absent` unless VLAN tag `i` exists and is an 802.1ad tag (`ad`) or not.
    fn tag(&mut self, i: u8, ad: bool, absent: Label) {
        let a = &mut self.a;
        a.load(Size::B, 1, FACTS, off::VLANS);
        a.jmp32_imm(Cond::Le, 1, i as u32, absent);
        // The TPID of tag `i`: the outer EtherType, or the inner one of the tag before.
        a.alu64_reg(Alu::Mov, 1, CTX);
        a.alu64_imm(Alu::Mov, 2, 12 + 4 * i as i32);
        a.alu64_reg(Alu::Mov, 3, FP);
        a.alu64_imm(Alu::Add, 3, SCRATCH as i32);
        a.alu64_imm(Alu::Mov, 4, 2);
        a.call(SKB_LOAD_BYTES);
        a.jmp_imm(Cond::Ne, 0, 0, absent);
        a.load(Size::H, 1, FP, SCRATCH);
        a.to_be(1, 16);
        a.jmp32_imm(if ad { Cond::Ne } else { Cond::Eq }, 1, 0x88a8, absent);
    }

    /// Puts the start of the first TCP option in slot `n` in [`VAL`] and its length byte in
    /// [`LEN`], or jumps to `absent`.
    fn option(&mut self, n: u8, absent: Label) {
        self.options = true;
        let a = &mut self.a;
        a.load(Size::B, 1, FACTS, off::OPTS + n as i16);
        a.jmp_imm(Cond::Eq, 1, 0, absent);
        a.load(Size::W, VAL, FACTS, off::L4);
        a.alu64_reg(Alu::Add, VAL, 1);
        a.alu64_reg(Alu::Mov, 1, CTX);
        a.alu64_reg(Alu::Mov, 2, VAL);
        a.alu64_imm(Alu::Add, 2, 1);
        a.alu64_reg(Alu::Mov, 3, FP);
        a.alu64_imm(Alu::Add, 3, SCRATCH as i32);
        a.alu64_imm(Alu::Mov, 4, 1);
        a.call(SKB_LOAD_BYTES);
        a.jmp_imm(Cond::Ne, 0, 0, absent);
        a.load(Size::B, LEN, FP, SCRATCH);
    }

    /// Loads one occurrence into [`VAL`], or jumps to `fail` when it is absent. The parser has
    /// checked that the header fits, so a header load does not fail.
    fn scalar(&mut self, s: Scalar, fail: Label) {
        match s {
            Scalar::FrameLen => {
                let a = &mut self.a;
                a.load(Size::W, VAL, FACTS, off::LEN);
                a.load(Size::W, 1, FACTS, off::BASE);
                a.alu32_reg(Alu::Sub, VAL, 1);
                if self.ethernet {
                    let done = a.label();
                    a.load(Size::B, 1, FACTS, off::META);
                    a.alu32_imm(Alu::And, 1, M_VLAN as i32);
                    a.jmp32_imm(Cond::Eq, 1, 0, done);
                    a.alu32_imm(Alu::Add, VAL, 4);
                    a.bind(done);
                }
            }
            Scalar::EthType => {
                let (inband, done) = (self.a.label(), self.a.label());
                if self.ethernet {
                    let a = &mut self.a;
                    a.load(Size::B, 1, FACTS, off::META);
                    a.alu32_imm(Alu::And, 1, M_VLAN as i32);
                    a.jmp32_imm(Cond::Eq, 1, 0, inband);
                    a.alu64_imm(Alu::Mov, VAL, 0x8100);
                    a.load(Size::B, 1, FACTS, off::META);
                    a.alu32_imm(Alu::And, 1, M_VLAN_AD as i32);
                    a.jmp32_imm(Cond::Eq, 1, 0, done);
                    a.alu64_imm(Alu::Mov, VAL, 0x88a8);
                    a.ja(done);
                }
                self.a.bind(inband);
                self.a.alu64_imm(Alu::Mov, 2, 0);
                self.read(whole(12, 2), fail);
                self.a.bind(done);
            }
            Scalar::ArpIp(target) => {
                // The protocol must be IPv4, with 4-byte addresses; they follow the
                // hardware addresses, whose size the packet gives.
                for (off, want) in [(2, 0x0800), (5, 4)] {
                    self.a.load(Size::W, 2, FACTS, off::L3);
                    self.read(whole(off, if off == 2 { 2 } else { 1 }), fail);
                    self.a.jmp_imm(Cond::Ne, VAL, want, fail);
                }
                self.a.load(Size::W, 2, FACTS, off::L3);
                self.read(whole(4, 1), fail);
                let a = &mut self.a;
                a.alu64_reg(Alu::Mov, 2, VAL);
                if target {
                    a.alu64_reg(Alu::Add, 2, VAL);
                    a.alu64_imm(Alu::Add, 2, 4);
                }
                a.alu64_imm(Alu::Add, 2, 8);
                a.load(Size::W, 1, FACTS, off::L3);
                a.alu64_reg(Alu::Add, 2, 1);
                self.read(whole(0, 4), fail);
            }
            Scalar::TcpLen => {
                let a = &mut self.a;
                a.load(Size::W, 1, FACTS, off::FLAGS);
                a.jmp32_imm(Cond::Set, 1, F_MORE, fail);
                a.load(Size::W, VAL, FACTS, off::PAY_END);
                a.load(Size::W, 1, FACTS, off::PAY);
                a.alu32_reg(Alu::Sub, VAL, 1);
            }
            Scalar::At(h, b) => {
                match h.base() {
                    None => self.a.alu64_imm(Alu::Mov, 2, 0),
                    Some(base) => self.a.load(Size::W, 2, FACTS, base),
                }
                self.read(b, fail);
            }
            Scalar::Fact {
                off,
                size,
                mask,
                invert,
            } => {
                let a = &mut self.a;
                a.load(size, VAL, FACTS, off);
                if mask != u32::MAX && !(size == Size::B && mask == 0xff) {
                    a.alu32_imm(Alu::And, VAL, mask as i32);
                }
                if invert {
                    a.alu32_imm(Alu::Xor, VAL, mask as i32);
                }
            }
            Scalar::Tag(i, ad, b) if self.ethernet => {
                // With an offloaded tag, it is tag 0 and the tags in the frame come after.
                let (offloaded, done) = (self.a.label(), self.a.label());
                let a = &mut self.a;
                a.load(Size::B, 1, FACTS, off::META);
                a.jmp32_imm(Cond::Set, 1, M_VLAN as u32, offloaded);
                self.tag_bits(i, ad, b, fail);
                self.a.ja(done);
                self.a.bind(offloaded);
                if i == 0 {
                    let a = &mut self.a;
                    a.load(Size::B, 1, FACTS, off::META);
                    a.alu32_imm(Alu::And, 1, M_VLAN_AD as i32);
                    a.jmp32_imm(if ad { Cond::Eq } else { Cond::Ne }, 1, 0, fail);
                    if b.off == 14 {
                        a.load(Size::H, VAL, FACTS, off::VLAN_TCI);
                        if b.shift != 0 {
                            a.alu32_imm(Alu::Rsh, VAL, b.shift as i32);
                        }
                        a.alu32_imm(Alu::And, VAL, b.mask as i32);
                    } else {
                        // The EtherType after the offloaded tag is the frame's.
                        a.alu64_imm(Alu::Mov, 2, 0);
                        self.read(whole(12, 2), fail);
                    }
                } else {
                    self.tag_bits(
                        i - 1,
                        ad,
                        Bits {
                            off: b.off - 4,
                            ..b
                        },
                        fail,
                    );
                }
                self.a.bind(done);
            }
            Scalar::Tag(i, ad, b) => self.tag_bits(i, ad, b, fail),
            Scalar::Opt(n, len, b) => {
                self.option(n, fail);
                self.a.jmp_imm(Cond::Ne, LEN, len as i32, fail);
                self.a.alu64_reg(Alu::Mov, 2, VAL);
                self.read(b, fail);
            }
            Scalar::WscaleMul => {
                self.scalar(Scalar::Opt(1, 3, whole(2, 1)), fail);
                let a = &mut self.a;
                let small = a.label();
                a.jmp_imm(Cond::Le, VAL, 14, small);
                a.alu64_imm(Alu::Mov, VAL, 14);
                a.bind(small);
                a.alu64_imm(Alu::Mov, 1, 1);
                a.alu64_reg(Alu::Lsh, 1, VAL);
                a.alu64_reg(Alu::Mov, VAL, 1);
            }
        }
    }

    fn pred(&mut self, p: &Pred, t: Label, f: Label) {
        let a = &mut self.a;
        match p {
            Pred::Const(b) => a.ja(if *b { t } else { f }),
            Pred::Cmp(c, v) => {
                a.jmp32_imm(*c, VAL, *v, t);
                a.ja(f);
            }
            Pred::Masked(c, mask, v) => {
                a.alu32_reg(Alu::Mov, 1, VAL);
                a.alu32_imm(Alu::And, 1, *mask as i32);
                a.jmp32_imm(*c, 1, *v, t);
                a.ja(f);
            }
            Pred::Truthy => {
                a.jmp_imm(Cond::Ne, VAL, 0, t);
                a.ja(f);
            }
            Pred::Range(lo, hi) => {
                a.jmp32_imm(Cond::Lt, VAL, *lo, f);
                a.jmp32_imm(Cond::Gt, VAL, *hi, f);
                a.ja(t);
            }
            Pred::SCmp(op, v) => {
                self.sjump(scond(*op), *v, t);
                self.a.ja(f);
            }
            Pred::SRange(lo, hi) => {
                self.sjump(Cond::Slt, *lo, f);
                self.sjump(Cond::Sgt, *hi, f);
                self.a.ja(t);
            }
            // Merged ranges are never more tests than the items, often far fewer.
            Pred::Any(items) => match as_ranges(items) {
                Some(r) => self.tree(&r, t, f),
                _ => {
                    for p in items {
                        let next = self.a.label();
                        self.pred(p, t, next);
                        self.a.bind(next);
                    }
                    self.a.ja(f);
                }
            },
        }
    }

    /// Jumps to `l` if `VAL cond v`, 64 bits.
    fn sjump(&mut self, c: Cond, v: i64, l: Label) {
        match i32::try_from(v) {
            Ok(imm) => self.a.jmp_imm(c, VAL, imm, l),
            Err(_) => {
                self.a.ld_imm64(1, v as u64);
                self.a.jmp_reg(c, VAL, 1, l);
            }
        }
    }

    /// Searches sorted, disjoint ranges with a tree of jumps (all forward: the left half comes
    /// after the right one).
    fn tree(&mut self, r: &[(u32, u32)], t: Label, f: Label) {
        if r.len() <= TREE {
            for &(lo, hi) in r {
                let next = self.a.label();
                if lo == hi {
                    self.a.jmp32_imm(Cond::Eq, VAL, lo, t);
                } else {
                    self.a.jmp32_imm(Cond::Lt, VAL, lo, next);
                    self.a.jmp32_imm(Cond::Le, VAL, hi, t);
                }
                self.a.bind(next);
            }
            self.a.ja(f);
            return;
        }
        let mid = r.len() / 2;
        let left = self.a.label();
        self.a.jmp32_imm(Cond::Lt, VAL, r[mid].0, left);
        self.a.jmp32_imm(Cond::Le, VAL, r[mid].1, t);
        self.tree(&r[mid + 1..], t, f);
        self.a.bind(left);
        self.tree(&r[..mid], t, f);
    }

    /// Puts the start of the byte range in [`VAL`] and its length in [`LEN`], or jumps to
    /// `absent` when the range does not exist (as `value::slice` decides).
    fn region(&mut self, r: Region, s: Option<Slice>, absent: Label) -> Result<(), Error> {
        match r {
            Region::Frame => {
                let a = &mut self.a;
                a.load(Size::W, VAL, FACTS, off::BASE);
                a.load(Size::W, LEN, FACTS, off::LEN);
                a.alu64_reg(Alu::Sub, LEN, VAL);
            }
            Region::At(h, start, len) => {
                self.need(h.flags(), absent);
                let a = &mut self.a;
                match h.base() {
                    None => a.alu64_imm(Alu::Mov, VAL, start),
                    Some(base) => {
                        a.load(Size::W, VAL, FACTS, base);
                        a.alu64_imm(Alu::Add, VAL, start);
                    }
                }
                a.alu64_imm(Alu::Mov, LEN, len);
            }
            Region::Ipv4Hdr => {
                self.need(F_IPV4, absent);
                self.a.load(Size::W, VAL, FACTS, off::L3);
                self.a.load(Size::B, LEN, FACTS, off::L3_LEN);
            }
            Region::TcpHdr => {
                self.need(F_TCP, absent);
                self.a.load(Size::W, VAL, FACTS, off::L4);
                self.a.load(Size::W, LEN, FACTS, off::L4_LEN);
            }
            Region::L4ToEnd(h) => {
                self.need(h.flags(), absent);
                self.a.load(Size::W, VAL, FACTS, off::L4);
                self.a.load(Size::W, LEN, FACTS, off::PAY_END);
                self.a.alu64_reg(Alu::Sub, LEN, VAL);
            }
            Region::Payload(h) => {
                self.need(h.flags(), absent);
                let a = &mut self.a;
                a.load(Size::W, VAL, FACTS, off::PAY);
                a.load(Size::W, LEN, FACTS, off::PAY_END);
                a.alu64_reg(Alu::Sub, LEN, VAL);
                a.jmp_imm(Cond::Eq, LEN, 0, absent);
            }
            Region::TcpOpts => {
                self.need(F_TCP, absent);
                let a = &mut self.a;
                a.load(Size::W, VAL, FACTS, off::L4);
                a.alu64_imm(Alu::Add, VAL, 20);
                a.load(Size::W, LEN, FACTS, off::L4_LEN);
                a.alu64_imm(Alu::Add, LEN, -20);
                a.jmp_imm(Cond::Eq, LEN, 0, absent);
            }
            Region::Opt(n) => {
                self.need(F_TCP, absent);
                self.option(n, absent);
            }
            Region::Tag(i, ad) => {
                self.need(F_ETH, absent);
                self.tag(i, ad, absent);
                self.a.alu64_imm(Alu::Mov, VAL, 14 + 4 * i as i32);
                self.a.alu64_imm(Alu::Mov, LEN, 4);
            }
            Region::Arp => {
                self.need(F_ARP, absent);
                let a = &mut self.a;
                a.load(Size::W, VAL, FACTS, off::L3);
                a.load(Size::W, LEN, FACTS, off::PAY);
                a.alu64_reg(Alu::Sub, LEN, VAL);
            }
            Region::ArpMac(target) => {
                self.need(F_ARP, absent);
                self.a.load(Size::W, 2, FACTS, off::L3);
                self.read(whole(4, 1), absent);
                self.a.jmp_imm(Cond::Ne, VAL, 6, absent);
                if target {
                    // After the sender's addresses: 8 + 6 + the protocol address size.
                    self.a.load(Size::W, 2, FACTS, off::L3);
                    self.read(whole(5, 1), absent);
                    self.a.alu64_imm(Alu::Add, VAL, 14);
                } else {
                    self.a.alu64_imm(Alu::Mov, VAL, 8);
                }
                let a = &mut self.a;
                a.load(Size::W, 1, FACTS, off::L3);
                a.alu64_reg(Alu::Add, VAL, 1);
                a.alu64_imm(Alu::Mov, LEN, 6);
            }
        }
        if let Some(s) = s {
            self.slice(s, absent)?;
        }
        Ok(())
    }

    /// Narrows [`VAL`]/[`LEN`] to the slice, with `value::slice`'s rules: negative indexes
    /// count from the end, and a range that does not fit is absent.
    fn slice(&mut self, s: Slice, absent: Label) -> Result<(), Error> {
        let imm = |v: i64| i32::try_from(v).map_err(|_| Error::Unsupported("this slice".into()));
        let a = &mut self.a;
        if s.start >= 0 {
            a.alu64_imm(Alu::Mov, 1, imm(s.start)?);
        } else {
            a.alu64_reg(Alu::Mov, 1, LEN);
            a.alu64_imm(Alu::Add, 1, imm(s.start)?);
        }
        match s.end {
            SliceEnd::Len(n) => {
                a.alu64_reg(Alu::Mov, 2, 1);
                a.alu64_imm(Alu::Add, 2, imm(n)?);
            }
            SliceEnd::Inclusive(e) if e >= 0 => a.alu64_imm(Alu::Mov, 2, imm(e + 1)?),
            SliceEnd::Inclusive(e) => {
                a.alu64_reg(Alu::Mov, 2, LEN);
                a.alu64_imm(Alu::Add, 2, imm(e + 1)?);
            }
            SliceEnd::Open => a.alu64_reg(Alu::Mov, 2, LEN),
        }
        a.jmp_imm(Cond::Slt, 1, 0, absent);
        a.jmp_reg(Cond::Slt, 2, 1, absent);
        a.jmp_reg(Cond::Sgt, 2, LEN, absent);
        a.alu64_reg(Alu::Add, VAL, 1);
        a.alu64_reg(Alu::Mov, LEN, 2);
        a.alu64_reg(Alu::Sub, LEN, 1);
        Ok(())
    }

    /// Tests the byte occurrence in [`VAL`]/[`LEN`]; `fail` is where a failed load goes.
    fn bpred(&mut self, p: &BPred, b: Bytes, t: Label, f: Label, fail: Label) -> Result<(), Error> {
        self.a.check_size()?;
        match p {
            BPred::Const(x) => self.a.ja(if *x { t } else { f }),
            BPred::Not(x) => self.bpred(x, b, f, t, fail)?,
            BPred::Eq(lit, bits) => self.bytes_eq(lit, *bits, t, f, fail)?,
            BPred::Ord(op, lit) => {
                let n = self.load_fixed(b, fail)?;
                self.lexi(lit, n, *op, t, f);
            }
            BPred::Range(lo, hi) => {
                let n = self.load_fixed(b, fail)?;
                let next = self.a.label();
                self.lexi(lo, n, CmpOp::Ge, next, f);
                self.a.bind(next);
                self.lexi(hi, n, CmpOp::Le, t, f);
            }
            BPred::Contains(needle) => {
                let max = b.max().filter(|&m| m <= CHUNK);
                let Some(max) = max else {
                    return unsupported("`contains` on bytes that may be longer than 64");
                };
                self.contains(needle, max, t, f)?;
            }
            BPred::Any(items) => {
                for p in items {
                    let next = self.a.label();
                    self.bpred(p, b, t, next, fail)?;
                    self.a.bind(next);
                }
                self.a.ja(f);
            }
        }
        Ok(())
    }

    /// Loads the whole occurrence, of fixed length, into the stack buffer; returns its length.
    fn load_fixed(&mut self, b: Bytes, fail: Label) -> Result<usize, Error> {
        let n = b.fixed().filter(|&n| n > 0 && n <= CHUNK);
        let Some(n) = n else {
            return unsupported("ordering of bytes of varying length");
        };
        let a = &mut self.a;
        a.alu64_reg(Alu::Mov, 1, CTX);
        a.alu64_reg(Alu::Mov, 2, VAL);
        a.alu64_reg(Alu::Mov, 3, FP);
        a.alu64_imm(Alu::Add, 3, BUF as i32);
        a.alu64_imm(Alu::Mov, 4, n as i32);
        a.call(SKB_LOAD_BYTES);
        a.jmp_imm(Cond::Ne, 0, 0, fail);
        Ok(n)
    }

    /// Compares the `n` bytes in the stack buffer with `lit` lexicographically, as `value::ord`
    /// does, and jumps to `t` if the result satisfies `op`.
    fn lexi(&mut self, lit: &[u8], n: usize, op: CmpOp, t: Label, f: Label) {
        let a = &mut self.a;
        let (less, greater, equal) = (a.label(), a.label(), a.label());
        let k = n.min(lit.len());
        let mut at = 0;
        while at < k {
            let w = [4, 2, 1]
                .into_iter()
                .find(|&w| w <= k - at && at % w == 0)
                .unwrap_or(1);
            a.load(Size::of(w), 1, FP, BUF + at as i16);
            if w > 1 {
                a.to_be(1, 8 * w as i32);
            }
            let v = be_word(&lit[at..at + w]);
            a.jmp32_imm(Cond::Lt, 1, v, less);
            a.jmp32_imm(Cond::Gt, 1, v, greater);
            at += w;
        }
        a.ja(match n.cmp(&lit.len()) {
            core::cmp::Ordering::Less => less,
            core::cmp::Ordering::Greater => greater,
            core::cmp::Ordering::Equal => equal,
        });
        let pick = |l: bool, e: bool, g: bool| {
            (
                if l { t } else { f },
                if e { t } else { f },
                if g { t } else { f },
            )
        };
        let (lt, eq, gt) = match op {
            CmpOp::Lt => pick(true, false, false),
            CmpOp::Le => pick(true, true, false),
            CmpOp::Gt => pick(false, false, true),
            CmpOp::Ge => pick(false, true, true),
            CmpOp::Eq => pick(false, true, false),
            CmpOp::Ne => pick(true, false, true),
        };
        a.bind(less);
        a.ja(lt);
        a.bind(greater);
        a.ja(gt);
        a.bind(equal);
        a.ja(eq);
    }

    /// Jumps to `eq` if the range holds `lit` (its first `bits` bits, the rest of the length
    /// being equal), to `ne` if it does not, and to `fail` if a load fails.
    fn bytes_eq(
        &mut self,
        lit: &[u8],
        bits: usize,
        eq: Label,
        ne: Label,
        fail: Label,
    ) -> Result<(), Error> {
        let len = i32::try_from(lit.len()).map_err(|_| Error::TooLarge)?;
        let nbytes = bits.div_ceil(8).min(lit.len());
        let a = &mut self.a;
        a.jmp_imm(Cond::Ne, LEN, len, ne);
        for (i, chunk) in lit[..nbytes].chunks(CHUNK).enumerate() {
            a.check_size()?;
            a.alu64_reg(Alu::Mov, 1, CTX);
            a.alu64_reg(Alu::Mov, 2, VAL);
            if i > 0 {
                a.alu64_imm(Alu::Add, 2, (i * CHUNK) as i32);
            }
            a.alu64_reg(Alu::Mov, 3, FP);
            a.alu64_imm(Alu::Add, 3, BUF as i32);
            a.alu64_imm(Alu::Mov, 4, chunk.len() as i32);
            a.call(SKB_LOAD_BYTES);
            a.jmp_imm(Cond::Ne, 0, 0, fail);
            let mut at = 0;
            while at < chunk.len() {
                let n = [8, 4, 2, 1]
                    .into_iter()
                    .find(|&n| n <= chunk.len() - at)
                    .unwrap_or(1);
                // The bits of the prefix: every bit but those after `bits` in the last byte.
                let mask: Vec<u8> = (0..n)
                    .map(|j| {
                        let bit = 8 * (i * CHUNK + at + j);
                        if bit + 8 <= bits {
                            0xff
                        } else {
                            (0xffu16 << (8 - (bits - bit))) as u8
                        }
                    })
                    .collect();
                let word: Vec<u8> = (0..n).map(|j| chunk[at + j] & mask[j]).collect();
                let (word, mask) = (ne_word(&word), ne_word(&mask));
                let full = mask == ne_word(&vec![0xff; n]);
                a.load(Size::of(n), 1, FP, BUF + at as i16);
                if n == 8 {
                    if !full {
                        a.ld_imm64(2, mask);
                        a.alu64_reg(Alu::And, 1, 2);
                    }
                    a.ld_imm64(2, word);
                    a.jmp_reg(Cond::Ne, 1, 2, ne);
                } else {
                    if !full {
                        a.alu32_imm(Alu::And, 1, mask as u32 as i32);
                    }
                    a.jmp32_imm(Cond::Ne, 1, word as u32, ne);
                }
                at += n;
            }
        }
        a.ja(eq);
        Ok(())
    }

    /// Jumps to `t` if the range (at most `max` bytes) contains `needle`, else to `f`.
    fn contains(&mut self, needle: &[u8], max: usize, t: Label, f: Label) -> Result<(), Error> {
        let m = needle.len();
        if m == 0 {
            self.a.ja(t);
            return Ok(());
        }
        if m > max {
            self.a.ja(f);
            return Ok(());
        }
        if max * m > CONTAINS_WORK {
            return unsupported("`contains` of a long string");
        }
        let a = &mut self.a;
        // Bounds the verifier can follow: the length is in [m, max].
        a.jmp_imm(Cond::Gt, LEN, max as i32, f);
        a.jmp_imm(Cond::Lt, LEN, m as i32, f);
        // The 5.15 verifier wants the whole buffer initialized before a load of variable length
        // into it.
        for at in (0..max).step_by(8) {
            a.store_imm(Size::DW, FP, BUF + at as i16, 0);
        }
        a.alu64_reg(Alu::Mov, 1, CTX);
        a.alu64_reg(Alu::Mov, 2, VAL);
        a.alu64_reg(Alu::Mov, 3, FP);
        a.alu64_imm(Alu::Add, 3, BUF as i32);
        a.alu64_reg(Alu::Mov, 4, LEN);
        a.call(SKB_LOAD_BYTES);
        a.jmp_imm(Cond::Ne, 0, 0, f);
        for s in 0..=max - m {
            a.check_size()?;
            let next = a.label();
            if s > 0 {
                // The window runs past the end, and so will every later one.
                a.jmp_imm(Cond::Lt, LEN, (s + m) as i32, f);
            }
            for (k, &c) in needle.iter().enumerate() {
                a.load(Size::B, 1, FP, BUF + (s + k) as i16);
                a.jmp32_imm(Cond::Ne, 1, c as u32, next);
            }
            a.ja(t);
            a.bind(next);
        }
        a.ja(f);
        Ok(())
    }
}
