//! IR to bytecode.

use alloc::vec::Vec;
use core::fmt;

use super::{
    ARITH, BOOLEANS, CMP, HEADER, INSN, Insn, MAX_SIZE, NO_LAYERS, Op, Program, REGISTERS, tag,
};
use crate::fields::Field;
use crate::ir::{Lit, Quant, SetItem, Slice, SliceEnd, Test, Value};

/// Why a filter could not be compiled to bytecode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// The filter uses `matches`, which runs in user space only.
    UserSpaceOnly,
    /// A value nests deeper than the [`REGISTERS`](super::REGISTERS), or `xor` deeper than the
    /// [`BOOLEANS`](super::BOOLEANS).
    TooDeep,
    /// The program would exceed [`MAX_SIZE`](super::MAX_SIZE), or a set or byte string its
    /// encoding.
    TooLarge,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            EncodeError::UserSpaceOnly => "`matches` runs in user space only",
            EncodeError::TooDeep => "the filter nests too deeply for the bytecode",
            EncodeError::TooLarge => "the filter is too large for the bytecode",
        })
    }
}

impl core::error::Error for EncodeError {}

type Result<T> = core::result::Result<T, EncodeError>;

impl Program {
    /// Compiles a test.
    ///
    /// # Errors
    ///
    /// [`EncodeError`]: the test uses `matches`, nests too deeply, or is too large.
    pub fn compile(t: &Test) -> Result<Program> {
        let mut e = Encoder {
            insns: Vec::new(),
            pool: Vec::new(),
        };
        e.test(t, 0)?;
        if HEADER + e.insns.len() * INSN + e.pool.len() > MAX_SIZE {
            return Err(EncodeError::TooLarge);
        }
        Ok(Program {
            insns: e.insns,
            pool: e.pool,
        })
    }
}

struct Encoder {
    insns: Vec<Insn>,
    pool: Vec<u8>,
}

fn reg(r: usize) -> Result<u8> {
    if r < REGISTERS {
        Ok(r as u8)
    } else {
        Err(EncodeError::TooDeep)
    }
}

fn field_id(f: Field) -> u16 {
    f as u16
}

fn quant(q: Quant) -> u8 {
    match q {
        Quant::Any => 0,
        Quant::All => 1,
    }
}

impl Encoder {
    fn emit(&mut self, op: Op, a: u8, b: u8, c: u8, imm: u32) -> Result<usize> {
        // Stop early on huge filters; `compile` checks the exact size.
        if self.insns.len() * INSN + self.pool.len() > MAX_SIZE {
            return Err(EncodeError::TooLarge);
        }
        self.insns.push(Insn {
            op: op as u8,
            a,
            b,
            c,
            imm,
        });
        Ok(self.insns.len() - 1)
    }

    /// The offset the next pool entry will have.
    fn here(&self) -> Result<u32> {
        u32::try_from(self.pool.len())
            .ok()
            .filter(|&n| n < NO_LAYERS)
            .ok_or(EncodeError::TooLarge)
    }

    fn lit_entry(&mut self, l: &Lit) -> Result<()> {
        let p = &mut self.pool;
        match l {
            Lit::Bool(b) => p.extend_from_slice(&[tag::BOOL, *b as u8]),
            Lit::Uint(v) => {
                p.push(tag::UINT);
                p.extend_from_slice(&v.to_le_bytes());
            }
            Lit::Int(v) => {
                p.push(tag::INT);
                p.extend_from_slice(&v.to_le_bytes());
            }
            Lit::Ipv4(a, prefix) => {
                p.push(tag::IPV4);
                p.extend_from_slice(a);
                p.push(*prefix);
            }
            Lit::Ipv6(a, prefix) => {
                p.push(tag::IPV6);
                p.extend_from_slice(a);
                p.push(*prefix);
            }
            Lit::Ether(m) => {
                p.push(tag::ETHER);
                p.extend_from_slice(m);
            }
            Lit::Bytes(b) => {
                let n = u16::try_from(b.len()).map_err(|_| EncodeError::TooLarge)?;
                p.push(tag::BYTES);
                p.extend_from_slice(&n.to_le_bytes());
                p.extend_from_slice(b);
            }
        }
        Ok(())
    }

    fn lit(&mut self, l: &Lit) -> Result<u32> {
        let at = self.here()?;
        self.lit_entry(l)?;
        Ok(at)
    }

    fn ranges(&mut self, ranges: &[Slice]) -> Result<u32> {
        let at = self.here()?;
        let n = u8::try_from(ranges.len()).map_err(|_| EncodeError::TooLarge)?;
        self.pool.extend_from_slice(&[tag::RANGES, n]);
        for s in ranges {
            let (kind, end) = match s.end {
                SliceEnd::Len(n) => (0, n),
                SliceEnd::Inclusive(e) => (1, e),
                SliceEnd::Open => (2, 0),
            };
            self.pool.extend_from_slice(&s.start.to_le_bytes());
            self.pool.push(kind);
            self.pool.extend_from_slice(&end.to_le_bytes());
        }
        Ok(at)
    }

    fn set(&mut self, set: &[SetItem]) -> Result<u32> {
        let at = self.here()?;
        let n = u16::try_from(set.len()).map_err(|_| EncodeError::TooLarge)?;
        self.pool.push(tag::SET);
        self.pool.extend_from_slice(&n.to_le_bytes());
        for item in set {
            match item {
                SetItem::One(l) => {
                    self.pool.push(0);
                    self.lit_entry(l)?;
                }
                SetItem::Range(lo, hi) => {
                    self.pool.push(1);
                    self.lit_entry(lo)?;
                    self.lit_entry(hi)?;
                }
            }
        }
        Ok(at)
    }

    /// Computes `v` into register `r`, using the registers above it as scratch.
    fn value(&mut self, v: &Value, r: usize) -> Result<()> {
        let a = reg(r)?;
        match v {
            Value::Lit(l) => {
                let at = self.lit(l)?;
                self.emit(Op::Lit, a, 0, 0, at)?;
            }
            Value::Field(f) => {
                self.emit(Op::Field, a, 0, 0, field_id(*f).into())?;
            }
            Value::Layer(f, ranges) => {
                let at = self.ranges(ranges)?;
                let [b, c] = field_id(*f).to_le_bytes();
                self.emit(Op::Layer, a, b, c, at)?;
            }
            Value::Raw(f, layers) => {
                let at = match layers {
                    Some(l) => self.ranges(l)?,
                    None => NO_LAYERS,
                };
                let [b, c] = field_id(*f).to_le_bytes();
                self.emit(Op::Raw, a, b, c, at)?;
            }
            Value::Slice(base, ranges) => {
                self.value(base, r)?;
                let at = self.ranges(ranges)?;
                self.emit(Op::Slice, a, a, 0, at)?;
            }
            Value::BitAnd(x, y) => self.binary(Op::BitAnd, x, y, r, 0)?,
            Value::Arith(op, x, y) => {
                let imm = ARITH.iter().position(|o| o == op).unwrap_or_default() as u32;
                self.binary(Op::Arith, x, y, r, imm)?;
            }
            Value::Neg(x) => self.unary(Op::Neg, x, r, 0)?,
            Value::Abs(x) => self.unary(Op::Abs, x, r, 0)?,
            Value::Len(x) => self.unary(Op::Len, x, r, 0)?,
            Value::Count(x) => self.unary(Op::Count, x, r, 0)?,
            Value::Case { upper, value } => self.unary(Op::Case, value, r, *upper as u32)?,
            Value::Extreme { max, args } => {
                let max = *max as u32;
                let mut args = args.iter();
                match args.next() {
                    Some(first) => {
                        self.value(first, r)?;
                        self.emit(Op::Ext, a, a, a, max)?;
                    }
                    // No argument (the checker never builds this): no value, which is what
                    // `ext` gives on a register without integers.
                    None => {
                        let at = self.lit(&Lit::Bool(false))?;
                        self.emit(Op::Lit, a, 0, 0, at)?;
                        self.emit(Op::Ext, a, a, a, max)?;
                    }
                }
                for arg in args {
                    self.value(arg, r + 1)?;
                    self.emit(Op::Ext, a, a, reg(r + 1)?, max)?;
                }
            }
        }
        Ok(())
    }

    fn unary(&mut self, op: Op, x: &Value, r: usize, imm: u32) -> Result<()> {
        self.value(x, r)?;
        let a = reg(r)?;
        self.emit(op, a, a, 0, imm)?;
        Ok(())
    }

    fn binary(&mut self, op: Op, x: &Value, y: &Value, r: usize, imm: u32) -> Result<()> {
        self.value(x, r)?;
        self.value(y, r + 1)?;
        let a = reg(r)?;
        self.emit(op, a, a, reg(r + 1)?, imm)?;
        Ok(())
    }

    /// Compiles `t` so that the accumulator holds its result, using boolean registers from
    /// `depth` up.
    fn test(&mut self, t: &Test, depth: usize) -> Result<()> {
        match t {
            Test::Const(b) => {
                self.emit(Op::Const, 0, 0, 0, *b as u32)?;
            }
            Test::Exists(v) => {
                self.value(v, 0)?;
                self.emit(Op::Exists, 0, 0, 0, 0)?;
            }
            Test::Truthy(v) => {
                self.value(v, 0)?;
                self.emit(Op::Truthy, 0, 0, 0, 0)?;
            }
            Test::Cmp {
                lhs,
                op,
                quant: q,
                rhs,
            } => {
                self.value(lhs, 0)?;
                self.value(rhs, 1)?;
                let op = CMP.iter().position(|o| o == op).unwrap_or_default() as u8;
                self.emit(Op::Cmp, op | quant(*q) << 3, 0, 1, 0)?;
            }
            Test::Member {
                lhs,
                set,
                quant: q,
                negate,
            } => {
                self.value(lhs, 0)?;
                let at = self.set(set)?;
                self.emit(Op::Member, quant(*q) | (*negate as u8) << 1, 0, 0, at)?;
            }
            Test::Contains { lhs, rhs, quant: q } => {
                self.value(lhs, 0)?;
                self.value(rhs, 1)?;
                self.emit(Op::Contains, quant(*q), 0, 1, 0)?;
            }
            Test::Matches { .. } => return Err(EncodeError::UserSpaceOnly),
            Test::Not(t) => {
                self.test(t, depth)?;
                self.emit(Op::Not, 0, 0, 0, 0)?;
            }
            Test::And(v) => self.junction(v, Op::Jf, depth)?,
            Test::Or(v) => self.junction(v, Op::Jt, depth)?,
            Test::Xor(x, y) => {
                if depth >= BOOLEANS {
                    return Err(EncodeError::TooDeep);
                }
                let k = depth as u8;
                self.test(x, depth)?;
                self.emit(Op::SaveB, k, 0, 0, 0)?;
                self.test(y, depth + 1)?;
                self.emit(Op::XorB, k, 0, 0, 0)?;
            }
        }
        Ok(())
    }

    /// `and` (`exit` = `jf`) or `or` (`exit` = `jt`): each operand, then a jump to the end when it
    /// decides the result. The last operand's result is the junction's.
    fn junction(&mut self, v: &[Test], exit: Op, depth: usize) -> Result<()> {
        let Some((last, rest)) = v.split_last() else {
            // An empty `and` is true, an empty `or` false.
            self.emit(Op::Const, 0, 0, 0, (exit == Op::Jf) as u32)?;
            return Ok(());
        };
        let mut jumps = Vec::with_capacity(rest.len());
        for t in rest {
            self.test(t, depth)?;
            jumps.push(self.emit(exit, 0, 0, 0, 0)?);
        }
        self.test(last, depth)?;
        let end = self.insns.len() as u32;
        for j in jumps {
            if let Some(i) = self.insns.get_mut(j) {
                i.imm = end;
            }
        }
        Ok(())
    }
}
