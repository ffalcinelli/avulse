//! The interpreter: one forward pass over a verified program. It does not allocate, and every
//! read is bounds-checked, so a program that somehow got past the verifier gives a wrong answer at
//! worst, never a panic or a loop.

use avulse_proto::Packet;

use super::{
    ARITH, BOOLEANS, CMP, INSN, Insn, NO_LAYERS, Op, REGISTERS, Ranges, Set, lit_at, quant,
};
use crate::fields::FIELDS;
use crate::meta::Meta;
use crate::value::{self, V, Vals};

pub(super) fn run(code: &[u8], pool: &[u8], pkt: &Packet<'_>, meta: &Meta<'_>) -> bool {
    run_in(code, pool, pkt, meta)
}

/// [`run`] with one lifetime for everything values may borrow from.
fn run_in<'a>(code: &'a [u8], pool: &'a [u8], p: &'a Packet<'a>, m: &'a Meta<'a>) -> bool {
    let mut regs = [Vals::new(); REGISTERS];
    let mut bools = [false; BOOLEANS];
    let mut acc = false;
    let mut pc = 0usize;
    let get = |regs: &[Vals<'a>; REGISTERS], r: u8| {
        regs.get(r as usize).copied().unwrap_or_else(Vals::new)
    };
    let field = |id: u32| FIELDS.get(id as usize).map(|d| d.field);
    while let Some(i) = code
        .get(pc.saturating_mul(INSN)..)
        .and_then(|c| c.get(..INSN))
        .and_then(Insn::decode)
    {
        pc += 1;
        let Some(op) = Op::from_u8(i.op) else {
            return false;
        };
        let (b, c) = (get(&regs, i.b), get(&regs, i.c));
        let out = match op {
            Op::Lit => lit_at(pool, i.imm)
                .map(Vals::one)
                .unwrap_or_else(|_| Vals::new()),
            Op::Field => field(i.imm).map_or_else(Vals::new, |f| value::load(f, p, m)),
            Op::Layer => match (field(i.wide_field().into()), Ranges::at(pool, i.imm)) {
                (Some(f), Ok(r)) => value::load_layer(f, r, p, m),
                _ => Vals::new(),
            },
            Op::Raw => {
                let layers = (i.imm != NO_LAYERS).then(|| Ranges::at(pool, i.imm));
                match (field(i.wide_field().into()), layers) {
                    (Some(f), None) => value::load_raw(f, None::<Ranges<'_>>, p, m),
                    (Some(f), Some(Ok(r))) => value::load_raw(f, Some(r), p, m),
                    _ => Vals::new(),
                }
            }
            Op::Slice => match Ranges::at(pool, i.imm) {
                Ok(r) => value::slice_vals(&b, r),
                Err(_) => Vals::new(),
            },
            Op::BitAnd => value::bitand(&b, &c),
            Op::Arith => match ARITH.get(i.imm as usize) {
                Some(op) => value::arith(*op, &b, &c),
                None => Vals::new(),
            },
            Op::Neg => value::neg_abs(&b, false),
            Op::Abs => value::neg_abs(&b, true),
            Op::Ext => value::extreme(i.imm == 1, &b, &c),
            Op::Len => value::len(&b),
            Op::Count => value::count(&b),
            Op::Case => value::case(&b, i.imm == 1),
            // Tests and control flow: they set the accumulator or jump, and write no register.
            _ => {
                match op {
                    Op::Const => acc = i.imm == 1,
                    Op::Exists => acc = !b.as_slice().is_empty(),
                    Op::Truthy => acc = b.as_slice().iter().any(V::truthy),
                    Op::Cmp => {
                        acc = CMP
                            .get(usize::from(i.a & 7))
                            .is_some_and(|op| value::cmp_test(*op, quant(i.a >> 3), &b, &c));
                    }
                    Op::Member => {
                        acc = match Set::at(pool, i.imm) {
                            Ok(set) => value::member_test(&b, set, quant(i.a), i.a & 2 != 0),
                            Err(_) => false,
                        };
                    }
                    Op::Contains => acc = value::contains_test(quant(i.a), &b, &c),
                    Op::Not => acc = !acc,
                    Op::SaveB => {
                        if let Some(slot) = bools.get_mut(i.a as usize) {
                            *slot = acc;
                        }
                    }
                    Op::XorB => acc ^= bools.get(i.a as usize).copied().unwrap_or(false),
                    // The verifier only accepts forward jumps; never go back regardless.
                    Op::Jt | Op::Jf if acc == (op == Op::Jt) => match i.imm as usize {
                        target if target < pc => return false,
                        target => pc = target,
                    },
                    _ => {}
                }
                continue;
            }
        };
        if let Some(slot) = regs.get_mut(i.a as usize) {
            *slot = out;
        }
    }
    acc
}
