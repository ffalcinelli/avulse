//! The verifier. It runs once per program, does not allocate, and accepts only programs that the
//! interpreter can run without reading out of bounds, looping or panicking.

use core::fmt;

use super::{
    BOOLEANS, Bad, HEADER, INSN, Insn, MAGIC, MAX_SIZE, NO_LAYERS, Op, REGISTERS, Ranges, Set,
    VERSION, VerifiedProgram, lit_at,
};
use crate::fields::FIELDS;

/// What [`verify`] rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyErrorKind {
    /// The program is larger than [`MAX_SIZE`](super::MAX_SIZE).
    TooLarge,
    /// The header is cut short, or its lengths do not add up to the program's size.
    BadLength,
    /// The magic is not `AVBC`.
    BadMagic,
    /// The format version is not [`VERSION`](super::VERSION).
    BadVersion,
    /// A reserved header flag is set.
    BadFlags,
    /// The program has no instructions.
    Empty,
    /// Unknown opcode.
    BadOpcode,
    /// An operand the instruction does not use is not zero.
    ReservedOperand,
    /// A value register out of range.
    BadRegister,
    /// A boolean register out of range.
    BadBoolRegister,
    /// An unknown field id.
    BadField,
    /// A small operand (operator, quantifier, flag) out of range.
    BadOperand,
    /// A jump that does not go forward, or goes past the end.
    BadJump,
    /// A constant offset past the end of the pool.
    ConstantOutOfBounds,
    /// A constant of the wrong kind for the instruction.
    ConstantKind,
    /// A constant cut short or holding an invalid value.
    MalformedConstant,
}

/// A program [`verify`] rejected: why, and at which instruction (`None` for the header).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyError {
    /// What is wrong.
    pub kind: VerifyErrorKind,
    /// The index of the offending instruction.
    pub at: Option<usize>,
}

impl fmt::Display for VerifyErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            VerifyErrorKind::TooLarge => "program too large",
            VerifyErrorKind::BadLength => "lengths do not match the program size",
            VerifyErrorKind::BadMagic => "not an Avulse program",
            VerifyErrorKind::BadVersion => "unsupported version",
            VerifyErrorKind::BadFlags => "reserved flags set",
            VerifyErrorKind::Empty => "no instructions",
            VerifyErrorKind::BadOpcode => "unknown opcode",
            VerifyErrorKind::ReservedOperand => "unused operand not zero",
            VerifyErrorKind::BadRegister => "register out of range",
            VerifyErrorKind::BadBoolRegister => "boolean register out of range",
            VerifyErrorKind::BadField => "unknown field",
            VerifyErrorKind::BadOperand => "operand out of range",
            VerifyErrorKind::BadJump => "jump not forward or past the end",
            VerifyErrorKind::ConstantOutOfBounds => "constant out of bounds",
            VerifyErrorKind::ConstantKind => "constant of the wrong kind",
            VerifyErrorKind::MalformedConstant => "malformed constant",
        })
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.at {
            Some(pc) => write!(f, "instruction {pc}: {}", self.kind),
            None => write!(f, "header: {}", self.kind),
        }
    }
}

impl core::error::Error for VerifyError {}

impl From<Bad> for VerifyErrorKind {
    fn from(b: Bad) -> Self {
        match b {
            Bad::OutOfBounds => VerifyErrorKind::ConstantOutOfBounds,
            Bad::Kind => VerifyErrorKind::ConstantKind,
            Bad::Malformed => VerifyErrorKind::MalformedConstant,
        }
    }
}

/// Checks a program in its wire format (see the [module documentation](super)) and returns it,
/// ready to run.
///
/// # Errors
///
/// The first problem found, with the instruction it is in.
pub fn verify(bytes: &[u8]) -> Result<VerifiedProgram<'_>, VerifyError> {
    let header = |kind| VerifyError { kind, at: None };
    if bytes.len() > MAX_SIZE {
        return Err(header(VerifyErrorKind::TooLarge));
    }
    let Some((h, body)) = bytes.split_first_chunk::<HEADER>() else {
        return Err(header(VerifyErrorKind::BadLength));
    };
    let word = |at: usize| u32::from_le_bytes([h[at], h[at + 1], h[at + 2], h[at + 3]]);
    if h[..4] != MAGIC {
        return Err(header(VerifyErrorKind::BadMagic));
    }
    if u16::from_le_bytes([h[4], h[5]]) != VERSION {
        return Err(header(VerifyErrorKind::BadVersion));
    }
    if h[6] != 0 || h[7] != 0 {
        return Err(header(VerifyErrorKind::BadFlags));
    }
    let (count, pool_len) = (word(8) as usize, word(12) as usize);
    if count == 0 {
        return Err(header(VerifyErrorKind::Empty));
    }
    let code_len = count.checked_mul(INSN);
    if code_len.and_then(|c| c.checked_add(pool_len)) != Some(body.len()) {
        return Err(header(VerifyErrorKind::BadLength));
    }
    let (code, pool) = body.split_at(code_len.unwrap_or_default());
    for (pc, chunk) in code.chunks(INSN).enumerate() {
        let at = Some(pc);
        let insn = Insn::decode(chunk).ok_or(VerifyError {
            kind: VerifyErrorKind::BadLength,
            at,
        })?;
        check(&insn, pc, count, pool).map_err(|kind| VerifyError { kind, at })?;
    }
    Ok(VerifiedProgram { code, pool })
}

fn reg(r: u8) -> Result<(), VerifyErrorKind> {
    if (r as usize) < REGISTERS {
        Ok(())
    } else {
        Err(VerifyErrorKind::BadRegister)
    }
}

fn zero(x: u32) -> Result<(), VerifyErrorKind> {
    if x == 0 {
        Ok(())
    } else {
        Err(VerifyErrorKind::ReservedOperand)
    }
}

fn at_most(x: u32, max: u32) -> Result<(), VerifyErrorKind> {
    if x <= max {
        Ok(())
    } else {
        Err(VerifyErrorKind::BadOperand)
    }
}

fn field(id: u32) -> Result<(), VerifyErrorKind> {
    if (id as usize) < FIELDS.len() {
        Ok(())
    } else {
        Err(VerifyErrorKind::BadField)
    }
}

fn ranges(pool: &[u8], off: u32) -> Result<(), VerifyErrorKind> {
    Ok(Ranges::at(pool, off)?.check()?)
}

fn check(i: &Insn, pc: usize, count: usize, pool: &[u8]) -> Result<(), VerifyErrorKind> {
    let Some(op) = Op::from_u8(i.op) else {
        return Err(VerifyErrorKind::BadOpcode);
    };
    let (a, b, c) = (i.a, i.b, i.c);
    let (wa, wb, wc) = (u32::from(a), u32::from(b), u32::from(c));
    match op {
        Op::Lit => {
            reg(a)?;
            zero(wb | wc)?;
            lit_at(pool, i.imm)?;
        }
        Op::Field => {
            reg(a)?;
            zero(wb | wc)?;
            field(i.imm)?;
        }
        Op::Layer | Op::Raw => {
            reg(a)?;
            field(i.wide_field().into())?;
            if op == Op::Layer || i.imm != NO_LAYERS {
                ranges(pool, i.imm)?;
            }
        }
        Op::Slice => {
            reg(a)?;
            reg(b)?;
            zero(wc)?;
            ranges(pool, i.imm)?;
        }
        Op::BitAnd | Op::Arith | Op::Ext => {
            reg(a)?;
            reg(b)?;
            reg(c)?;
            match op {
                Op::BitAnd => zero(i.imm)?,
                Op::Arith => at_most(i.imm, super::ARITH.len() as u32 - 1)?,
                _ => at_most(i.imm, 1)?,
            }
        }
        Op::Neg | Op::Abs | Op::Len | Op::Count | Op::Case => {
            reg(a)?;
            reg(b)?;
            zero(wc)?;
            if op == Op::Case {
                at_most(i.imm, 1)?;
            } else {
                zero(i.imm)?;
            }
        }
        Op::Const => {
            zero(wa | wb | wc)?;
            at_most(i.imm, 1)?;
        }
        Op::Exists | Op::Truthy => {
            zero(wa | wc | i.imm)?;
            reg(b)?;
        }
        Op::Cmp => {
            at_most(wa & 7, super::CMP.len() as u32 - 1)?;
            at_most(wa >> 3, 1)?;
            reg(b)?;
            reg(c)?;
            zero(i.imm)?;
        }
        Op::Member => {
            at_most(wa, 3)?;
            reg(b)?;
            zero(wc)?;
            Set::at(pool, i.imm)?.check()?;
        }
        Op::Contains => {
            at_most(wa, 1)?;
            reg(b)?;
            reg(c)?;
            zero(i.imm)?;
        }
        Op::Not => zero(wa | wb | wc | i.imm)?,
        Op::SaveB | Op::XorB => {
            if a as usize >= BOOLEANS {
                return Err(VerifyErrorKind::BadBoolRegister);
            }
            zero(wb | wc | i.imm)?;
        }
        Op::Jt | Op::Jf => {
            zero(wa | wb | wc)?;
            let target = i.imm as usize;
            if target <= pc || target > count {
                return Err(VerifyErrorKind::BadJump);
            }
        }
    }
    Ok(())
}
