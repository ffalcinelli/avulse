//! Compiled filters: a flat, versioned program that kernel backends verify and run without walking
//! a heap IR.
//!
//! User space compiles a filter's [`ir::Test`](crate::ir::Test) into a [`Program`] and sends its
//! [bytes](Program::to_bytes) to the driver. The driver calls [`verify`] once, when the handle
//! opens, and then [`VerifiedProgram::matches`] for each packet. Neither verifying nor running
//! allocates, and neither panics. The interpreter shares every operation on values with the IR
//! evaluator ([`Filter::matches`](crate::Filter::matches)), which stays the reference; tests check
//! that the two agree on random filters and packets.
//!
//! ```
//! use avulse_filter::{Filter, Meta, bytecode};
//! use avulse_proto::{Link, Packet};
//!
//! let filter = Filter::compile("tcp.dstport in {80 443} and not ip.src == 10.0.0.0/8").unwrap();
//! let bytes = filter.program().unwrap().to_bytes();
//!
//! // In the driver:
//! let program = bytecode::verify(&bytes).unwrap();
//! let frame = [
//!     0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0, 192, 168, 1, 2, 93, 184, 215, 14, //
//!     0x9c, 0x40, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
//! ];
//! assert!(program.matches(&Packet::parse(&frame, Link::Ip), &Meta::default()));
//! ```
//!
//! # Format
//!
//! Every integer is little-endian.
//!
//! | Bytes | Content |
//! | --- | --- |
//! | 0..4 | Magic, `b"AVBC"` |
//! | 4..6 | [`VERSION`] |
//! | 6..8 | Flags, reserved: 0 |
//! | 8..12 | Number of instructions, at least 1 |
//! | 12..16 | Length of the constant pool |
//! | 16.. | The instructions, 8 bytes each, then the constant pool |
//!
//! A program is at most [`MAX_SIZE`] bytes, and the lengths must add up to its exact size. Field
//! ids are the field's index in [`FIELDS`], which can change between
//! releases: a program is only valid for the version of this crate that compiled it, and
//! [`VERSION`] changes whenever the field table or the encoding does.
//!
//! An instruction is `op: u8, a: u8, b: u8, c: u8, imm: u32`. Value instructions write register
//! `a` and read registers `b` and `c`. Test instructions set the accumulator, a boolean that the
//! program returns at the end; they read registers `b` and `c` and take flags in `a`. The
//! operands an instruction does not use must be zero.
//!
//! | Op | Name | Operands | Effect |
//! | --- | --- | --- | --- |
//! | 1 | `lit` | `a`, `imm` = constant | `r[a]` = a literal |
//! | 2 | `field` | `a`, `imm` = field | `r[a]` = every occurrence of the field |
//! | 3 | `layer` | `a`, `b + c·256` = field, `imm` = ranges | the occurrences in some layers (`#n`) |
//! | 4 | `raw` | `a`, `b + c·256` = field, `imm` = ranges or `u32::MAX` | `@field` |
//! | 5 | `slice` | `a`, `b`, `imm` = ranges | `r[a]` = `r[b][ranges]` |
//! | 6 | `bitand` | `a`, `b`, `c` | `r[a]` = `r[b] & r[c]` |
//! | 7 | `arith` | `a`, `b`, `c`, `imm` = `+ - * / %` (0 to 4) | `r[a]` = `r[b] op r[c]` |
//! | 8 | `neg` | `a`, `b` | `r[a]` = `-r[b]` |
//! | 9 | `abs` | `a`, `b` | `r[a]` = `abs(r[b])` |
//! | 10 | `ext` | `a`, `b`, `c`, `imm` = 1 for max, 0 for min | `r[a]` = the max (min) of `r[b]` and `r[c]` |
//! | 11 | `len` | `a`, `b` | `r[a]` = `len(r[b])` |
//! | 12 | `count` | `a`, `b` | `r[a]` = `count(r[b])` |
//! | 13 | `case` | `a`, `b`, `imm` = 1 for upper, 0 for lower | `r[a]` = `upper(r[b])` |
//! | 32 | `const` | `imm` = 0 or 1 | acc = `imm` |
//! | 33 | `exists` | `b` | acc = `r[b]` has an occurrence |
//! | 34 | `truthy` | `b` | acc = some occurrence of `r[b]` is true |
//! | 35 | `cmp` | `a` = op (`== != < <= > >=`, 0 to 5) + 8·quant, `b`, `c` | acc = `r[b] op r[c]` |
//! | 36 | `member` | `a` = quant + 2·negate, `b`, `imm` = set | acc = `r[b] in set` |
//! | 37 | `contains` | `a` = quant, `b`, `c` | acc = `r[b] contains r[c]` |
//! | 38 | `not` | | acc = not acc |
//! | 39 | `saveb` | `a` | `bool[a]` = acc |
//! | 40 | `xorb` | `a` | acc = acc xor `bool[a]` |
//! | 48 | `jt` | `imm` = target | jump to `imm` if acc |
//! | 49 | `jf` | `imm` = target | jump to `imm` unless acc |
//! | 50 | `jmp` | `imm` = target | jump to `imm` |
//!
//! The quantifier is 0 for `any` and 1 for `all`. A jump target is an instruction index greater
//! than the jump's own, or the number of instructions to end the program. Since every jump goes
//! forward, every program terminates after at most one pass.
//!
//! The constant pool holds tagged entries that instructions refer to by byte offset:
//!
//! | Tag | Entry | Payload |
//! | --- | --- | --- |
//! | 0 | Boolean | 1 byte, 0 or 1 |
//! | 1 | Unsigned integer | `u64` |
//! | 2 | Signed integer | `i64` |
//! | 3 | IPv4 address | 4 bytes, then the prefix length (at most 32) |
//! | 4 | IPv6 address | 16 bytes, then the prefix length (at most 128) |
//! | 5 | MAC address | 6 bytes |
//! | 6 | Byte string | `u16` length, then the bytes |
//! | 16 | Ranges | `u8` count (at least 1), then 17 bytes each: `start: i64`, the kind (0: `start:len`, with `len` at least 1; 1: `start-end`; 2: `start:`, `end` 0), `end: i64` |
//! | 17 | Set | `u16` count, then each item: 0 and a literal entry, or 1 and two literal entries (an inclusive range) |
//!
//! # Machine
//!
//! The interpreter has [`REGISTERS`] value registers, each holding up to four occurrences, that
//! start out empty; an accumulator; and [`BOOLEANS`] boolean registers, which save the left side
//! of an `xor`. The register file takes about 3 KiB of stack.
//!
//! # What the verifier proves
//!
//! [`verify`] checks the header, every opcode, that unused operands are zero, register and field
//! indexes, the range of every small operand, that jumps go forward and stay in the program, and
//! that every constant an instruction refers to is in the pool, of the expected kind and well
//! formed. Running a verified program therefore cannot read out of bounds, loop or panic.
//!
//! It does not check the types of register contents: like the IR evaluator, the interpreter is
//! total over every combination of values, and a mismatch (such as `len` of an integer) gives no
//! value or a false test. A register read before any write is empty.

mod encode;
mod exec;
mod verify;

use alloc::vec::Vec;
use core::fmt;

use avulse_proto::Packet;

use crate::fields::FIELDS;
use crate::ir::{ArithOp, CmpOp, Lit, Quant, Slice, SliceEnd};
use crate::meta::Meta;
use crate::value::{V, Vals};

pub use encode::EncodeError;
pub use verify::{VerifyError, VerifyErrorKind, verify};

/// The format version. A program of another version is rejected.
pub const VERSION: u16 = 3;

/// The largest program, header and pool included.
pub const MAX_SIZE: usize = 64 * 1024;

/// Number of value registers.
pub const REGISTERS: usize = 16;

/// Number of boolean registers, the deepest nesting of `xor` on the left-hand side.
pub const BOOLEANS: usize = 8;

const MAGIC: [u8; 4] = *b"AVBC";
const HEADER: usize = 16;
const INSN: usize = 8;
/// `imm` of `raw` without layers.
const NO_LAYERS: u32 = u32::MAX;
/// Bytes of one range in a ranges entry.
const RANGE: usize = 17;

/// Opcodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Op {
    Lit = 1,
    Field = 2,
    Layer = 3,
    Raw = 4,
    Slice = 5,
    BitAnd = 6,
    Arith = 7,
    Neg = 8,
    Abs = 9,
    Ext = 10,
    Len = 11,
    Count = 12,
    Case = 13,
    Const = 32,
    Exists = 33,
    Truthy = 34,
    Cmp = 35,
    Member = 36,
    Contains = 37,
    Not = 38,
    SaveB = 39,
    XorB = 40,
    Jt = 48,
    Jf = 49,
    Jmp = 50,
}

impl Op {
    const ALL: [Op; 25] = [
        Op::Lit,
        Op::Field,
        Op::Layer,
        Op::Raw,
        Op::Slice,
        Op::BitAnd,
        Op::Arith,
        Op::Neg,
        Op::Abs,
        Op::Ext,
        Op::Len,
        Op::Count,
        Op::Case,
        Op::Const,
        Op::Exists,
        Op::Truthy,
        Op::Cmp,
        Op::Member,
        Op::Contains,
        Op::Not,
        Op::SaveB,
        Op::XorB,
        Op::Jt,
        Op::Jf,
        Op::Jmp,
    ];

    fn from_u8(b: u8) -> Option<Op> {
        Op::ALL.into_iter().find(|op| *op as u8 == b)
    }

    fn name(self) -> &'static str {
        match self {
            Op::Lit => "lit",
            Op::Field => "field",
            Op::Layer => "layer",
            Op::Raw => "raw",
            Op::Slice => "slice",
            Op::BitAnd => "bitand",
            Op::Arith => "arith",
            Op::Neg => "neg",
            Op::Abs => "abs",
            Op::Ext => "ext",
            Op::Len => "len",
            Op::Count => "count",
            Op::Case => "case",
            Op::Const => "const",
            Op::Exists => "exists",
            Op::Truthy => "truthy",
            Op::Cmp => "cmp",
            Op::Member => "member",
            Op::Contains => "contains",
            Op::Not => "not",
            Op::SaveB => "saveb",
            Op::XorB => "xorb",
            Op::Jt => "jt",
            Op::Jf => "jf",
            Op::Jmp => "jmp",
        }
    }
}

/// One decoded instruction. `op` is the raw opcode; [`Op::from_u8`] gives its meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Insn {
    op: u8,
    a: u8,
    b: u8,
    c: u8,
    imm: u32,
}

impl Insn {
    fn decode(b: &[u8]) -> Option<Insn> {
        let &[op, a, bb, c, i0, i1, i2, i3] = b else {
            return None;
        };
        Some(Insn {
            op,
            a,
            b: bb,
            c,
            imm: u32::from_le_bytes([i0, i1, i2, i3]),
        })
    }

    fn encode(&self) -> [u8; INSN] {
        let i = self.imm.to_le_bytes();
        [self.op, self.a, self.b, self.c, i[0], i[1], i[2], i[3]]
    }

    /// The field id in `b` and `c` (`layer`, `raw`).
    fn wide_field(&self) -> u16 {
        u16::from_le_bytes([self.b, self.c])
    }
}

const ARITH: [ArithOp; 5] = [
    ArithOp::Add,
    ArithOp::Sub,
    ArithOp::Mul,
    ArithOp::Div,
    ArithOp::Mod,
];
const CMP: [CmpOp; 6] = [
    CmpOp::Eq,
    CmpOp::Ne,
    CmpOp::Lt,
    CmpOp::Le,
    CmpOp::Gt,
    CmpOp::Ge,
];

fn quant(bit: u8) -> Quant {
    if bit & 1 == 0 { Quant::Any } else { Quant::All }
}

/// Pool entry tags.
mod tag {
    pub(super) const BOOL: u8 = 0;
    pub(super) const UINT: u8 = 1;
    pub(super) const INT: u8 = 2;
    pub(super) const IPV4: u8 = 3;
    pub(super) const IPV6: u8 = 4;
    pub(super) const ETHER: u8 = 5;
    pub(super) const BYTES: u8 = 6;
    pub(super) const RANGES: u8 = 16;
    pub(super) const SET: u8 = 17;
}

/// Why a constant could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bad {
    /// The offset is past the end of the pool.
    OutOfBounds,
    /// The entry is not of the kind the instruction needs.
    Kind,
    /// The entry is cut short or holds an invalid value.
    Malformed,
}

/// A bounds-checked cursor over the pool.
#[derive(Clone)]
struct Reader<'p> {
    b: &'p [u8],
    at: usize,
}

impl<'p> Reader<'p> {
    /// A reader at `off`, which must be inside the pool.
    fn at(pool: &'p [u8], off: u32) -> Result<Self, Bad> {
        let at = off as usize;
        if at >= pool.len() {
            return Err(Bad::OutOfBounds);
        }
        Ok(Reader { b: pool, at })
    }

    fn take(&mut self, n: usize) -> Result<&'p [u8], Bad> {
        let end = self.at.checked_add(n).ok_or(Bad::Malformed)?;
        let s = self.b.get(self.at..end).ok_or(Bad::Malformed)?;
        self.at = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Bad> {
        self.take(N)?.try_into().map_err(|_| Bad::Malformed)
    }

    fn u8(&mut self) -> Result<u8, Bad> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, Bad> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    /// A literal entry.
    fn lit(&mut self) -> Result<V<'p>, Bad> {
        let prefix = |r: &mut Self, max: u8| match r.u8()? {
            p if p <= max => Ok(p),
            _ => Err(Bad::Malformed),
        };
        Ok(match self.u8()? {
            tag::BOOL => match self.u8()? {
                b @ (0 | 1) => V::Bool(b == 1),
                _ => return Err(Bad::Malformed),
            },
            tag::UINT => V::Uint(u64::from_le_bytes(self.array()?)),
            tag::INT => V::Int(i64::from_le_bytes(self.array()?)),
            tag::IPV4 => {
                let a = self.array()?;
                V::Ipv4(a, prefix(self, 32)?)
            }
            tag::IPV6 => {
                let a = self.array()?;
                V::Ipv6(a, prefix(self, 128)?)
            }
            tag::ETHER => V::Ether(self.array()?),
            tag::BYTES => {
                let n = self.u16()?;
                V::Bytes(self.take(n as usize)?)
            }
            _ => return Err(Bad::Kind),
        })
    }
}

/// The literal at `off`.
fn lit_at(pool: &[u8], off: u32) -> Result<V<'_>, Bad> {
    Reader::at(pool, off)?.lit()
}

/// The ranges entry at `off` (`slice`, `layer`, `raw`). Creating it checks the tag and the
/// bounds; the verifier checks each range with [`Ranges::check`].
#[derive(Clone)]
struct Ranges<'p> {
    body: &'p [u8],
}

impl<'p> Ranges<'p> {
    fn at(pool: &'p [u8], off: u32) -> Result<Self, Bad> {
        let mut r = Reader::at(pool, off)?;
        if r.u8()? != tag::RANGES {
            return Err(Bad::Kind);
        }
        let n = r.u8()?;
        if n == 0 {
            return Err(Bad::Malformed);
        }
        Ok(Ranges {
            body: r.take(n as usize * RANGE)?,
        })
    }

    fn decode(chunk: &[u8]) -> Result<Slice, Bad> {
        let mut r = Reader { b: chunk, at: 0 };
        let start = i64::from_le_bytes(r.array()?);
        let kind = r.u8()?;
        let end = i64::from_le_bytes(r.array()?);
        let end = match kind {
            0 if end >= 1 => SliceEnd::Len(end),
            1 => SliceEnd::Inclusive(end),
            2 if end == 0 => SliceEnd::Open,
            _ => return Err(Bad::Malformed),
        };
        Ok(Slice { start, end })
    }

    fn check(&self) -> Result<(), Bad> {
        self.body
            .chunks(RANGE)
            .try_for_each(|c| Ranges::decode(c).map(drop))
    }
}

impl Iterator for Ranges<'_> {
    type Item = Slice;

    fn next(&mut self) -> Option<Slice> {
        let (chunk, rest) = self.body.split_at_checked(RANGE)?;
        self.body = rest;
        Ranges::decode(chunk).ok()
    }
}

/// The set entry at `off` (`member`). It decodes items lazily; the verifier walks it with
/// [`Set::check`].
#[derive(Clone)]
struct Set<'p> {
    r: Reader<'p>,
    left: u16,
}

impl<'p> Set<'p> {
    fn at(pool: &'p [u8], off: u32) -> Result<Self, Bad> {
        let mut r = Reader::at(pool, off)?;
        if r.u8()? != tag::SET {
            return Err(Bad::Kind);
        }
        let left = r.u16()?;
        Ok(Set { r, left })
    }

    fn item(&mut self) -> Result<Option<(V<'p>, Option<V<'p>>)>, Bad> {
        if self.left == 0 {
            return Ok(None);
        }
        self.left -= 1;
        let range = match self.r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(Bad::Malformed),
        };
        let lo = self.r.lit()?;
        let hi = if range { Some(self.r.lit()?) } else { None };
        Ok(Some((lo, hi)))
    }

    fn check(mut self) -> Result<(), Bad> {
        while self.item()?.is_some() {}
        Ok(())
    }
}

impl<'p> Iterator for Set<'p> {
    type Item = (V<'p>, Option<V<'p>>);

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.item();
        if item.is_err() {
            self.left = 0;
        }
        item.ok().flatten()
    }
}

/// A compiled filter: instructions and a constant pool.
///
/// [`Filter::program`](crate::Filter::program) compiles one; [`to_bytes`](Self::to_bytes) gives
/// the wire format that [`verify`] accepts. Its `Display` is a disassembly, which `avulse filter
/// explain --bytecode` prints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    insns: Vec<Insn>,
    pool: Vec<u8>,
}

impl Program {
    /// The program in its wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + self.insns.len() * INSN + self.pool.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        // The encoder keeps both lengths far below `u32::MAX` (`MAX_SIZE`).
        out.extend_from_slice(&(self.insns.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.pool.len() as u32).to_le_bytes());
        for i in &self.insns {
            out.extend_from_slice(&i.encode());
        }
        out.extend_from_slice(&self.pool);
        out
    }

    /// Verifies a program in its wire format and decodes it.
    ///
    /// # Errors
    ///
    /// Whatever [`verify`] rejects.
    pub fn from_bytes(bytes: &[u8]) -> Result<Program, VerifyError> {
        let v = verify(bytes)?;
        Ok(Program {
            insns: v.code.chunks(INSN).filter_map(Insn::decode).collect(),
            pool: v.pool.to_vec(),
        })
    }

    /// Number of instructions.
    pub fn len(&self) -> usize {
        self.insns.len()
    }

    /// Whether the program has no instructions (never true of a compiled filter).
    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }
}

/// A program that [`verify`] accepted, borrowing its bytes.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedProgram<'p> {
    code: &'p [u8],
    pool: &'p [u8],
}

impl<'p> VerifiedProgram<'p> {
    /// Whether `packet`, with metadata `meta`, matches. This gives the same result as
    /// [`Filter::matches`](crate::Filter::matches) on the filter the program was compiled from. It
    /// does not allocate and never panics.
    pub fn matches(&self, packet: &Packet<'_>, meta: &Meta<'_>) -> bool {
        self.matches_in(&mut Registers::new(), packet, meta)
    }

    /// [`matches`](Self::matches) with a register file the caller provides, so that the
    /// interpreter's own stack frame stays small: a kernel driver keeps the registers out of its
    /// short stack (they take about 2.7 KiB). It can be reused: each run starts by emptying it.
    pub fn matches_in<'a>(
        &self,
        regs: &mut Registers<'a>,
        packet: &'a Packet<'a>,
        meta: &'a Meta<'a>,
    ) -> bool
    where
        'p: 'a,
    {
        exec::run(self.code, self.pool, packet, meta, &mut regs.0)
    }
}

/// The interpreter's register file ([`VerifiedProgram::matches_in`]). Its values may borrow from
/// the packet and the metadata of the evaluation it is used for, hence the lifetime.
pub struct Registers<'a>([Vals<'a>; REGISTERS]);

impl Registers<'_> {
    /// An empty register file.
    pub fn new() -> Self {
        Registers([Vals::new(); REGISTERS])
    }
}

impl Default for Registers<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Registers<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Registers")
    }
}

/// A decoded constant, for the disassembly.
fn show_lit(f: &mut fmt::Formatter<'_>, v: Result<V<'_>, Bad>) -> fmt::Result {
    let lit = match v {
        Ok(V::Bool(b)) => Lit::Bool(b),
        Ok(V::Uint(u)) => Lit::Uint(u),
        Ok(V::Int(i)) => Lit::Int(i),
        Ok(V::Ipv4(a, p)) => Lit::Ipv4(a, p),
        Ok(V::Ipv6(a, p)) => Lit::Ipv6(a, p),
        Ok(V::Ether(m)) => Lit::Ether(m),
        Ok(V::Bytes(b)) => Lit::Bytes(b.to_vec()),
        _ => return f.write_str("<bad constant>"),
    };
    write!(f, "{lit}")
}

fn show_ranges(f: &mut fmt::Formatter<'_>, pool: &[u8], off: u32) -> fmt::Result {
    let Ok(ranges) = Ranges::at(pool, off) else {
        return f.write_str("<bad ranges>");
    };
    f.write_str("[")?;
    for (i, s) in ranges.enumerate() {
        if i > 0 {
            f.write_str(",")?;
        }
        write!(f, "{s}")?;
    }
    f.write_str("]")
}

fn field_name(id: u32) -> &'static str {
    usize::try_from(id)
        .ok()
        .and_then(|i| FIELDS.get(i))
        .map_or("<bad field>", |d| d.name)
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let width =
            core::iter::successors(Some(self.insns.len()), |n| (*n >= 10).then_some(n / 10))
                .count();
        for (pc, i) in self.insns.iter().enumerate() {
            let Some(op) = Op::from_u8(i.op) else {
                writeln!(f, "{pc:>width$}  <bad opcode {}>", i.op)?;
                continue;
            };
            if op == Op::Not {
                writeln!(f, "{pc:>width$}  {}", op.name())?;
                continue;
            }
            write!(f, "{pc:>width$}  {:<8}", op.name())?;
            let (a, b, c) = (i.a, i.b, i.c);
            match op {
                Op::Lit => {
                    write!(f, " r{a}, ")?;
                    show_lit(f, lit_at(&self.pool, i.imm))?;
                }
                Op::Field => write!(f, " r{a}, {}", field_name(i.imm))?,
                Op::Layer | Op::Raw => {
                    write!(f, " r{a}, {}", field_name(i.wide_field().into()))?;
                    if i.imm != NO_LAYERS {
                        f.write_str("#")?;
                        show_ranges(f, &self.pool, i.imm)?;
                    }
                }
                Op::Slice => {
                    write!(f, " r{a}, r{b}")?;
                    show_ranges(f, &self.pool, i.imm)?;
                }
                Op::BitAnd => write!(f, " r{a}, r{b}, r{c}")?,
                Op::Arith => match ARITH.get(i.imm as usize) {
                    Some(o) => write!(f, " r{a}, r{b} {o} r{c}")?,
                    None => write!(f, " r{a}, r{b} <bad op> r{c}")?,
                },
                Op::Ext => {
                    let which = if i.imm == 1 { "max" } else { "min" };
                    write!(f, " r{a}, {which}(r{b}, r{c})")?;
                }
                Op::Case => {
                    let which = if i.imm == 1 { "upper" } else { "lower" };
                    write!(f, " r{a}, {which}(r{b})")?;
                }
                Op::Neg | Op::Abs | Op::Len | Op::Count => write!(f, " r{a}, r{b}")?,
                Op::Const => write!(f, " {}", i.imm == 1)?,
                Op::Exists | Op::Truthy => write!(f, " r{b}")?,
                Op::Cmp => match CMP.get(usize::from(a & 7)) {
                    Some(o) => write!(f, " {}_{o} r{b}, r{c}", quant(a >> 3))?,
                    None => write!(f, " <bad op> r{b}, r{c}")?,
                },
                Op::Member => {
                    let not = if a & 2 != 0 { "not_" } else { "" };
                    write!(f, " {}_{not}in r{b}, {{", quant(a))?;
                    match Set::at(&self.pool, i.imm) {
                        Ok(set) => {
                            for (n, (lo, hi)) in set.enumerate() {
                                if n > 0 {
                                    f.write_str(" ")?;
                                }
                                show_lit(f, Ok(lo))?;
                                if let Some(hi) = hi {
                                    f.write_str("..")?;
                                    show_lit(f, Ok(hi))?;
                                }
                            }
                        }
                        Err(_) => f.write_str("<bad set>")?,
                    }
                    f.write_str("}")?;
                }
                Op::Contains => write!(f, " {} r{b}, r{c}", quant(a))?,
                Op::Not => {}
                Op::SaveB | Op::XorB => write!(f, " b{a}")?,
                Op::Jt | Op::Jf | Op::Jmp => write!(f, " {}", i.imm)?,
            }
            writeln!(f)?;
        }
        Ok(())
    }
}
