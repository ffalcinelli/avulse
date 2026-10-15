//! Code generation: a filter's IR to an eBPF matcher.
//!
//! The matcher is a `BPF_PROG_TYPE_SCHED_CLS` program that the static TC program tail-calls
//! after it has parsed the headers into the [`Facts`](crate::facts::Facts). It reads the facts,
//! loads header fields and byte ranges with `bpf_skb_load_bytes`, writes its verdict to the
//! facts, and tail-calls the action program. Tests compile to short-circuit jumps, all forward.
//!
//! This is the spike's subset of the IR: `and`, `or`, `not`, `xor`, conditionals, presence,
//! comparisons and set membership of the fixed header fields of Ethernet, IPv4, IPv6, TCP, UDP
//! and ICMP (with the two-valued `ip.addr`, `tcp.port`, `udp.port`), and `==`/`!=` on header and
//! payload bytes and their slices. Anything else is [`Error::Unsupported`], which a backend
//! answers by filtering in user space.

use core::fmt;

use avulse_filter::fields::{Field, def};
use avulse_filter::ir::{CmpOp, Lit, Quant, SetItem, Slice, SliceEnd, Test, Value};

use crate::facts::{
    F_ARP, F_ETH, F_ICMP, F_ICMPV6, F_IPV4, F_IPV6, F_MORE, F_TCP, F_UDP, SLOT_ACTION, off,
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
const BUF: i16 = -48;
/// Its size.
const CHUNK: usize = 32;

/// A generated matcher: instructions, and where they refer to maps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matcher {
    insns: Vec<Insn>,
    maps: MapRefs,
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

/// Compiles `test` to a matcher.
pub fn compile(test: &Test) -> Result<Matcher, Error> {
    let mut g = Gen { a: Asm::default() };
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
    Ok(Matcher { insns, maps })
}

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
        }
    }

    /// Where the facts keep the header's offset; `None` for offset 0.
    fn base(self) -> Option<i16> {
        match self {
            Hdr::Eth => None,
            Hdr::Ipv4 | Hdr::Ipv6 | Hdr::Ip => Some(off::L3),
            Hdr::Tcp | Hdr::Udp | Hdr::Icmp | Hdr::Icmpv6 => Some(off::L4),
        }
    }
}

/// How a field's value is read from its header: `width` big-endian bytes at `off`, shifted
/// right, masked and multiplied.
#[derive(Clone, Copy, Debug)]
struct Bits {
    off: i32,
    width: u8,
    shift: u8,
    mask: u32,
    mul: u8,
}

/// One occurrence of a numeric field.
#[derive(Clone, Copy, Debug)]
enum Scalar {
    At(Hdr, Bits),
    FrameLen,
    /// `tcp.len`: the payload length, absent on fragments with more to come.
    TcpLen,
}

/// How a numeric field compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Uint,
    Bool,
    /// An IPv4 address.
    Addr,
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
}

enum Operand {
    Scalar {
        kind: Kind,
        need: u32,
        occ: Vec<Scalar>,
    },
    Bytes(Region, Option<Slice>),
    /// A protocol whose bytes the generator does not read: only presence.
    Presence(u32),
}

fn at(h: Hdr, off: i32, width: u8) -> Scalar {
    Scalar::At(
        h,
        Bits {
            off,
            width,
            shift: 0,
            mask: u32::MAX,
            mul: 1,
        },
    )
}

fn bits(h: Hdr, off: i32, width: u8, shift: u8, mask: u32) -> Scalar {
    Scalar::At(
        h,
        Bits {
            off,
            width,
            shift,
            mask,
            mul: 1,
        },
    )
}

fn hdr_len(h: Hdr, off: i32, shift: u8) -> Scalar {
    Scalar::At(
        h,
        Bits {
            off,
            width: 1,
            shift,
            mask: 0xf,
            mul: 4,
        },
    )
}

/// The value of a numeric field: its kind, header and occurrences.
fn scalar(f: Field) -> Option<(Kind, Hdr, Vec<Scalar>)> {
    use Hdr::*;
    use Kind::*;
    let tcp_flag = |m| (Bool, Tcp, vec![bits(Tcp, 12, 2, 0, m)]);
    Some(match f {
        Field::EthType => (Uint, Eth, vec![at(Eth, 12, 2)]),

        Field::IpVersion => (Uint, Ip, vec![bits(Ip, 0, 1, 4, 0xf)]),
        Field::IpHdrLen => (Uint, Ipv4, vec![hdr_len(Ipv4, 0, 0)]),
        Field::IpDsfield => (Uint, Ipv4, vec![at(Ipv4, 1, 1)]),
        Field::IpDsfieldDscp => (Uint, Ipv4, vec![bits(Ipv4, 1, 1, 2, 0x3f)]),
        Field::IpDsfieldEcn => (Uint, Ipv4, vec![bits(Ipv4, 1, 1, 0, 3)]),
        Field::IpLen => (Uint, Ipv4, vec![at(Ipv4, 2, 2)]),
        Field::IpId => (Uint, Ipv4, vec![at(Ipv4, 4, 2)]),
        Field::IpFlags => (Uint, Ipv4, vec![bits(Ipv4, 6, 1, 5, 7)]),
        Field::IpFlagsRb => (Bool, Ipv4, vec![bits(Ipv4, 6, 1, 0, 0x80)]),
        Field::IpFlagsDf => (Bool, Ipv4, vec![bits(Ipv4, 6, 1, 0, 0x40)]),
        Field::IpFlagsMf => (Bool, Ipv4, vec![bits(Ipv4, 6, 1, 0, 0x20)]),
        Field::IpFragOffset => (Uint, Ipv4, vec![bits(Ipv4, 6, 2, 0, 0x1fff)]),
        Field::IpTtl => (Uint, Ipv4, vec![at(Ipv4, 8, 1)]),
        Field::IpProto => (Uint, Ipv4, vec![at(Ipv4, 9, 1)]),
        Field::IpChecksum => (Uint, Ipv4, vec![at(Ipv4, 10, 2)]),
        Field::IpSrc => (Addr, Ipv4, vec![at(Ipv4, 12, 4)]),
        Field::IpDst => (Addr, Ipv4, vec![at(Ipv4, 16, 4)]),
        Field::IpAddr => (Addr, Ipv4, vec![at(Ipv4, 12, 4), at(Ipv4, 16, 4)]),

        Field::Ipv6Version => (Uint, Ipv6, vec![bits(Ipv6, 0, 1, 4, 0xf)]),
        Field::Ipv6Tclass => (Uint, Ipv6, vec![bits(Ipv6, 0, 4, 20, 0xff)]),
        Field::Ipv6TclassDscp => (Uint, Ipv6, vec![bits(Ipv6, 0, 4, 22, 0x3f)]),
        Field::Ipv6TclassEcn => (Uint, Ipv6, vec![bits(Ipv6, 0, 4, 20, 3)]),
        Field::Ipv6Flow => (Uint, Ipv6, vec![bits(Ipv6, 0, 4, 0, 0xfffff)]),
        Field::Ipv6Plen => (Uint, Ipv6, vec![at(Ipv6, 4, 2)]),
        Field::Ipv6Nxt => (Uint, Ipv6, vec![at(Ipv6, 6, 1)]),
        Field::Ipv6Hlim => (Uint, Ipv6, vec![at(Ipv6, 7, 1)]),

        Field::TcpSrcport => (Uint, Tcp, vec![at(Tcp, 0, 2)]),
        Field::TcpDstport => (Uint, Tcp, vec![at(Tcp, 2, 2)]),
        Field::TcpPort => (Uint, Tcp, vec![at(Tcp, 0, 2), at(Tcp, 2, 2)]),
        Field::TcpSeqRaw => (Uint, Tcp, vec![at(Tcp, 4, 4)]),
        Field::TcpAckRaw => (Uint, Tcp, vec![at(Tcp, 8, 4)]),
        Field::TcpHdrLen => (Uint, Tcp, vec![hdr_len(Tcp, 12, 4)]),
        Field::TcpFlags => (Uint, Tcp, vec![bits(Tcp, 12, 2, 0, 0xfff)]),
        Field::TcpFlagsRes => (Bool, Tcp, vec![bits(Tcp, 12, 1, 0, 0x0e)]),
        Field::TcpFlagsAe => tcp_flag(0x100),
        Field::TcpFlagsCwr => tcp_flag(0x80),
        Field::TcpFlagsEce => tcp_flag(0x40),
        Field::TcpFlagsUrg => tcp_flag(0x20),
        Field::TcpFlagsAck => tcp_flag(0x10),
        Field::TcpFlagsPush => tcp_flag(0x08),
        Field::TcpFlagsReset => tcp_flag(0x04),
        Field::TcpFlagsSyn => tcp_flag(0x02),
        Field::TcpFlagsFin => tcp_flag(0x01),
        Field::TcpWindowSizeValue => (Uint, Tcp, vec![at(Tcp, 14, 2)]),
        Field::TcpChecksum => (Uint, Tcp, vec![at(Tcp, 16, 2)]),
        Field::TcpUrgentPointer => (Uint, Tcp, vec![at(Tcp, 18, 2)]),
        Field::TcpLen => (Uint, Tcp, vec![Scalar::TcpLen]),

        Field::UdpSrcport => (Uint, Udp, vec![at(Udp, 0, 2)]),
        Field::UdpDstport => (Uint, Udp, vec![at(Udp, 2, 2)]),
        Field::UdpPort => (Uint, Udp, vec![at(Udp, 0, 2), at(Udp, 2, 2)]),
        Field::UdpLength => (Uint, Udp, vec![at(Udp, 4, 2)]),
        Field::UdpChecksum => (Uint, Udp, vec![at(Udp, 6, 2)]),

        Field::IcmpType => (Uint, Icmp, vec![at(Icmp, 0, 1)]),
        Field::IcmpCode => (Uint, Icmp, vec![at(Icmp, 1, 1)]),
        Field::IcmpChecksum => (Uint, Icmp, vec![at(Icmp, 2, 2)]),
        Field::Icmpv6Type => (Uint, Icmpv6, vec![at(Icmpv6, 0, 1)]),
        Field::Icmpv6Code => (Uint, Icmpv6, vec![at(Icmpv6, 1, 1)]),
        Field::Icmpv6Checksum => (Uint, Icmpv6, vec![at(Icmpv6, 2, 2)]),
        _ => return None,
    })
}

fn region(f: Field) -> Option<Region> {
    Some(match f {
        Field::Frame => Region::Frame,
        Field::Eth => Region::At(Hdr::Eth, 0, 14),
        Field::EthDst => Region::At(Hdr::Eth, 0, 6),
        Field::EthSrc => Region::At(Hdr::Eth, 6, 6),
        Field::Ip => Region::Ipv4Hdr,
        Field::Tcp => Region::TcpHdr,
        Field::TcpPayload => Region::Payload(Hdr::Tcp),
        Field::Udp => Region::At(Hdr::Udp, 0, 8),
        Field::UdpPayload => Region::Payload(Hdr::Udp),
        Field::Icmp => Region::L4ToEnd(Hdr::Icmp),
        Field::Icmpv6 => Region::L4ToEnd(Hdr::Icmpv6),
        _ => return None,
    })
}

fn operand(v: &Value) -> Result<Operand, Error> {
    match v {
        Value::Field(Field::FrameLen | Field::FrameCapLen) => Ok(Operand::Scalar {
            kind: Kind::Uint,
            need: 0,
            occ: vec![Scalar::FrameLen],
        }),
        Value::Field(f) => {
            if let Some((kind, h, occ)) = scalar(*f) {
                return Ok(Operand::Scalar {
                    kind,
                    need: h.flags(),
                    occ,
                });
            }
            if let Some(r) = region(*f) {
                return Ok(Operand::Bytes(r, None));
            }
            match f {
                Field::Ipv6 => Ok(Operand::Presence(F_IPV6)),
                Field::Arp => Ok(Operand::Presence(F_ARP)),
                _ => unsupported(format!("the field `{}`", def(*f).name)),
            }
        }
        Value::Slice(base, ranges) => match (&**base, ranges.as_slice()) {
            (Value::Field(f), [s]) => match region(*f) {
                Some(r) => Ok(Operand::Bytes(r, Some(*s))),
                None => unsupported(format!("slices of `{}`", def(*f).name)),
            },
            _ => unsupported("this slice"),
        },
        Value::Layer(..) => unsupported("layer operators (`#n`)"),
        Value::Raw(..) => unsupported("`@field`"),
        Value::BitAnd(..) => unsupported("bitwise and"),
        Value::Len(_) => unsupported("`len()`"),
        Value::Count(_) => unsupported("`count()`"),
        Value::Case { .. } => unsupported("`upper()` and `lower()`"),
        Value::Arith(..) | Value::Neg(_) | Value::Abs(_) => unsupported("arithmetic"),
        Value::Extreme { .. } => unsupported("`max()` and `min()`"),
        Value::Lit(_) => unsupported("a comparison of constants"),
    }
}

/// A test of one occurrence of a numeric field, in [`VAL`].
#[derive(Clone, Debug)]
enum Pred {
    Const(bool),
    Cmp(Cond, u32),
    /// `(VAL & mask) cond value`.
    Masked(Cond, u32, u32),
    Truthy,
    Range(u32, u32),
    Any(Vec<Pred>),
}

fn cond(op: CmpOp) -> Cond {
    match op {
        CmpOp::Eq => Cond::Eq,
        CmpOp::Ne => Cond::Ne,
        CmpOp::Lt => Cond::Lt,
        CmpOp::Le => Cond::Le,
        CmpOp::Gt => Cond::Gt,
        CmpOp::Ge => Cond::Ge,
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

/// `VAL op lit`, as `value::compare` decides it for a field of `kind`. Fields hold at most 32
/// bits, so a constant out of that range decides the comparison.
fn cmp_pred(kind: Kind, op: CmpOp, l: &Lit) -> Result<Pred, Error> {
    let ord = !matches!(op, CmpOp::Eq | CmpOp::Ne);
    Ok(match (kind, l) {
        (Kind::Uint, l) if num(l).is_some() => {
            let n = num(l).unwrap_or_default();
            match u32::try_from(n) {
                Ok(v) => Pred::Cmp(cond(op), v),
                // The field is greater than a negative constant, smaller than a huge one.
                Err(_) => Pred::Const(match op {
                    CmpOp::Eq => false,
                    CmpOp::Ne => true,
                    CmpOp::Lt | CmpOp::Le => n > 0,
                    CmpOp::Gt | CmpOp::Ge => n < 0,
                }),
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
                Pred::Cmp(cond(op), v)
            } else {
                let mask = u32::MAX.checked_shl(32 - *p as u32).unwrap_or(0);
                Pred::Masked(cond(op), mask, v & mask)
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
            (Kind::Addr, Lit::Ipv4(lo, _), Lit::Ipv4(hi, _)) => {
                Pred::Range(u32::from_be_bytes(*lo), u32::from_be_bytes(*hi))
            }
            (Kind::Bool, Lit::Bool(_), Lit::Bool(_)) => Pred::Const(false),
            _ => return unsupported("a set of a different type"),
        }),
    }
}

struct Gen {
    a: Asm,
}

impl Gen {
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
                let (xt, xf) = (self.a.label(), self.a.label());
                self.test(x, xt, xf)?;
                self.a.bind(xt);
                self.test(y, f, t)?;
                self.a.bind(xf);
                self.test(y, t, f)?;
            }
            Test::If(c, x, y) => {
                let (ct, cf) = (self.a.label(), self.a.label());
                self.test(c, ct, cf)?;
                self.a.bind(ct);
                self.test(x, t, f)?;
                self.a.bind(cf);
                self.test(y, t, f)?;
            }
            Test::Exists(v) => {
                match operand(v)? {
                    Operand::Scalar { need, occ, .. } => {
                        self.need(need, f);
                        if matches!(occ[0], Scalar::TcpLen) {
                            self.no_more_fragments(f);
                        }
                    }
                    Operand::Bytes(r, s) => self.region(r, s, f)?,
                    Operand::Presence(flags) => self.need(flags, f),
                }
                self.a.ja(t);
            }
            Test::Truthy(v) => match operand(v)? {
                Operand::Scalar { need, occ, .. } => {
                    self.quant(need, &occ, Quant::Any, false, &Pred::Truthy, t, f)
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
                    _ => return unsupported("a comparison of two values"),
                };
                match operand(v)? {
                    Operand::Scalar { kind, need, occ } => {
                        let p = cmp_pred(kind, op, l)?;
                        self.quant(need, &occ, *quant, false, &p, t, f);
                    }
                    Operand::Bytes(r, s) => {
                        let bytes = match l {
                            Lit::Bytes(b) => b.as_slice(),
                            Lit::Ether(m) => m.as_slice(),
                            _ => return unsupported("a comparison of different types"),
                        };
                        match op {
                            CmpOp::Eq => self.bytes_eq(r, s, bytes, t, f, f)?,
                            CmpOp::Ne => self.bytes_eq(r, s, bytes, f, t, f)?,
                            _ => return unsupported("ordering of bytes"),
                        }
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
                Operand::Scalar { kind, need, occ } => {
                    let items = set
                        .iter()
                        .map(|i| member_pred(kind, i))
                        .collect::<Result<Vec<_>, _>>()?;
                    self.quant(need, &occ, *quant, *negate, &Pred::Any(items), t, f);
                }
                _ => return unsupported("sets of bytes"),
            },
            Test::Contains { .. } => return unsupported("`contains`"),
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

    fn no_more_fragments(&mut self, absent: Label) {
        self.a.load(Size::W, 1, FACTS, off::FLAGS);
        self.a.jmp32_imm(Cond::Set, 1, F_MORE, absent);
    }

    /// `quant` occurrence satisfies `pred` (or, with `negate`, the field is present and that is
    /// not the case).
    #[allow(clippy::too_many_arguments)]
    fn quant(
        &mut self,
        need: u32,
        occ: &[Scalar],
        quant: Quant,
        negate: bool,
        pred: &Pred,
        t: Label,
        f: Label,
    ) {
        self.need(need, f);
        if matches!(occ[0], Scalar::TcpLen) {
            self.no_more_fragments(f);
        }
        let absent = f;
        let (t, f) = if negate { (f, t) } else { (t, f) };
        for (i, s) in occ.iter().enumerate() {
            let next = (i + 1 < occ.len()).then(|| self.a.label());
            self.scalar(*s, absent);
            match quant {
                Quant::Any => self.pred(pred, t, next.unwrap_or(f)),
                Quant::All => self.pred(pred, next.unwrap_or(t), f),
            }
            if let Some(n) = next {
                self.a.bind(n);
            }
        }
    }

    /// Loads one occurrence into [`VAL`]. The parser has checked that the header fits, so the
    /// load does not fail; if it did, the test would be false.
    fn scalar(&mut self, s: Scalar, fail: Label) {
        let a = &mut self.a;
        match s {
            Scalar::FrameLen => {
                a.load(Size::W, VAL, FACTS, off::LEN);
                a.load(Size::W, 1, FACTS, off::BASE);
                a.alu32_reg(Alu::Sub, VAL, 1);
            }
            Scalar::TcpLen => {
                a.load(Size::W, VAL, FACTS, off::PAY_END);
                a.load(Size::W, 1, FACTS, off::PAY);
                a.alu32_reg(Alu::Sub, VAL, 1);
            }
            Scalar::At(h, b) => {
                a.alu64_reg(Alu::Mov, 1, CTX);
                match h.base() {
                    None => a.alu64_imm(Alu::Mov, 2, b.off),
                    Some(base) => {
                        a.load(Size::W, 2, FACTS, base);
                        if b.off != 0 {
                            a.alu64_imm(Alu::Add, 2, b.off);
                        }
                    }
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
                a.jmp32_imm(Cond::Ne, VAL, 0, t);
                a.ja(f);
            }
            Pred::Range(lo, hi) => {
                a.jmp32_imm(Cond::Lt, VAL, *lo, f);
                a.jmp32_imm(Cond::Gt, VAL, *hi, f);
                a.ja(t);
            }
            Pred::Any(items) => {
                for p in items {
                    let next = self.a.label();
                    self.pred(p, t, next);
                    self.a.bind(next);
                }
                self.a.ja(f);
            }
        }
    }

    /// Puts the start of the byte range in [`VAL`] and its length in [`LEN`], or jumps to
    /// `absent` when the range does not exist (as `value::slice` decides).
    fn region(&mut self, r: Region, s: Option<Slice>, absent: Label) -> Result<(), Error> {
        let a = &mut self.a;
        match r {
            Region::Frame => {
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
                self.a.load(Size::W, VAL, FACTS, off::PAY);
                self.a.load(Size::W, LEN, FACTS, off::PAY_END);
                self.a.alu64_reg(Alu::Sub, LEN, VAL);
                self.a.jmp_imm(Cond::Eq, LEN, 0, absent);
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

    /// Jumps to `eq` if the range exists and holds `bytes`, to `ne` if it exists and does not,
    /// and to `absent` if it does not exist.
    fn bytes_eq(
        &mut self,
        r: Region,
        s: Option<Slice>,
        bytes: &[u8],
        eq: Label,
        ne: Label,
        absent: Label,
    ) -> Result<(), Error> {
        self.region(r, s, absent)?;
        let len = i32::try_from(bytes.len()).map_err(|_| Error::TooLarge)?;
        let a = &mut self.a;
        a.jmp_imm(Cond::Ne, LEN, len, ne);
        for (i, chunk) in bytes.chunks(CHUNK).enumerate() {
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
            a.jmp_imm(Cond::Ne, 0, 0, absent);
            let mut at = 0;
            while at < chunk.len() {
                let n = [8, 4, 2, 1]
                    .into_iter()
                    .find(|&n| n <= chunk.len() - at)
                    .unwrap_or(1);
                let mut word = [0u8; 8];
                word[..n].copy_from_slice(&chunk[at..at + n]);
                let word = u64::from_ne_bytes(word);
                let word = if cfg!(target_endian = "big") {
                    word >> (64 - 8 * n)
                } else {
                    word
                };
                a.load(Size::of(n), 1, FP, BUF + at as i16);
                if n == 8 {
                    a.ld_imm64(2, word);
                    a.jmp_reg(Cond::Ne, 1, 2, ne);
                } else {
                    a.jmp32_imm(Cond::Ne, 1, word as u32, ne);
                }
                at += n;
            }
        }
        a.ja(eq);
        Ok(())
    }
}
