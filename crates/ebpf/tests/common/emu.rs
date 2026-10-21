//! A small eBPF interpreter for the instructions the generator emits, so that the generated
//! matchers can be checked against the IR evaluator without a kernel. It also checks what the
//! verifier would: jumps go forward, registers are written before they are read, and memory
//! accesses stay in the stack and the facts.

use avulse_ebpf::facts::{self, Facts, SLOT_ACTION};
use avulse_ebpf::insn::{Insn, class};

pub const FACTS_FD: i32 = 101;
pub const PROGS_FD: i32 = 102;

const STACK_TOP: u64 = 0x1_0000_0000;
const STACK_SIZE: u64 = 512;
const FACTS_ADDR: u64 = 0x2_0000_0000;
const CTX_ADDR: u64 = 0x3_0000_0000;

/// How a run ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The matcher tail-called the action with this verdict.
    Verdict(bool),
    /// The program returned without reaching the action.
    Exit(u64),
}

struct Machine<'a> {
    regs: [Option<u64>; 11],
    stack: [u8; STACK_SIZE as usize],
    facts: [u8; facts::SIZE],
    frame: &'a [u8],
}

impl Machine<'_> {
    fn reg(&self, r: u8) -> u64 {
        self.regs[r as usize].unwrap_or_else(|| panic!("r{r} read before it is written"))
    }

    fn mem(&mut self, addr: u64, n: usize) -> &mut [u8] {
        if (STACK_TOP - STACK_SIZE..STACK_TOP).contains(&addr) && addr + n as u64 <= STACK_TOP {
            let at = (addr - (STACK_TOP - STACK_SIZE)) as usize;
            &mut self.stack[at..at + n]
        } else if (FACTS_ADDR..FACTS_ADDR + facts::SIZE as u64).contains(&addr)
            && addr + n as u64 <= FACTS_ADDR + facts::SIZE as u64
        {
            let at = (addr - FACTS_ADDR) as usize;
            &mut self.facts[at..at + n]
        } else {
            panic!("access of {n} bytes at {addr:#x}")
        }
    }

    fn read(&mut self, addr: u64, n: usize) -> u64 {
        let mut b = [0u8; 8];
        b[..n].copy_from_slice(self.mem(addr, n));
        if cfg!(target_endian = "big") {
            u64::from_be_bytes(b) >> (64 - 8 * n)
        } else {
            u64::from_le_bytes(b)
        }
    }

    fn write(&mut self, addr: u64, n: usize, v: u64) {
        let b = v.to_ne_bytes();
        let src = if cfg!(target_endian = "big") {
            &b[8 - n..]
        } else {
            &b[..n]
        };
        self.mem(addr, n).copy_from_slice(src);
    }
}

fn size(code: u8) -> usize {
    match code & 0x18 {
        0x10 => 1,
        0x08 => 2,
        0x00 => 4,
        _ => 8,
    }
}

/// Checks the shape the verifier requires before it runs anything: jumps forward and in range,
/// every instruction reachable, and no path that runs off the end.
pub fn check_shape(insns: &[Insn]) {
    let n = insns.len();
    let mut live = vec![false; n + 1];
    live[0] = true;
    let mut i = 0;
    while i < n {
        let ins = insns[i];
        assert!(live[i], "unreachable instruction {i}");
        let cls = ins.code & 7;
        if ins.code == 0x18 {
            live[i + 2] = true;
            i += 2;
            continue;
        }
        let op = ins.code & 0xf0;
        let jump = matches!(cls, class::JMP | class::JMP32) && !matches!(op, 0x80 | 0x90);
        if jump {
            assert!(ins.off >= 0, "backward jump at {i}");
            let t = i + 1 + ins.off as usize;
            assert!(t < n, "jump past the end at {i}");
            live[t] = true;
        }
        let ends = cls == class::JMP && matches!(op, 0x00 | 0x90);
        if !ends {
            live[i + 1] = true;
        }
        i += 1;
    }
    assert!(!live[n], "a path runs off the end");
}

/// Runs `insns` (with the fds set to [`FACTS_FD`] and [`PROGS_FD`]) on `frame` with `facts`.
pub fn run(insns: &[Insn], facts: &Facts, frame: &[u8]) -> Outcome {
    let mut m = Machine {
        regs: [None; 11],
        stack: [0; STACK_SIZE as usize],
        facts: facts.to_bytes(),
        frame,
    };
    m.regs[1] = Some(CTX_ADDR);
    m.regs[10] = Some(STACK_TOP);
    let mut pc = 0;
    loop {
        let i = insns[pc];
        let (dst, src) = (i.dst, i.src);
        let cls = i.code & 7;
        let jump = |pc: usize, off: i16| {
            assert!(off >= 0, "backward jump at {pc}");
            pc + 1 + off as usize
        };
        pc = match cls {
            class::ALU | class::ALU64 => {
                let op = i.code & 0xf0;
                let wide = cls == class::ALU64;
                if op == 0xd0 {
                    // Byte swap to big-endian.
                    let v = m.reg(dst);
                    m.regs[dst as usize] = Some(match (i.imm, cfg!(target_endian = "little")) {
                        (16, true) => (v as u16).swap_bytes() as u64,
                        (32, true) => (v as u32).swap_bytes() as u64,
                        (64, true) => v.swap_bytes(),
                        (16, false) => v as u16 as u64,
                        (32, false) => v as u32 as u64,
                        _ => v,
                    });
                } else {
                    let s = if i.code & 0x08 != 0 {
                        m.reg(src)
                    } else {
                        i.imm as i64 as u64
                    };
                    let d = if op == 0xb0 { 0 } else { m.reg(dst) };
                    let r = match op {
                        0x00 => d.wrapping_add(s),
                        0x10 => d.wrapping_sub(s),
                        0x20 => d.wrapping_mul(s),
                        0x30 if wide => d.checked_div(s).unwrap_or(0),
                        0x30 => (d as u32).checked_div(s as u32).unwrap_or(0) as u64,
                        0x40 => d | s,
                        0x50 => d & s,
                        0x60 => d << (s & if wide { 63 } else { 31 }),
                        0x70 if wide => d >> (s & 63),
                        0x70 => ((d as u32) >> (s & 31)) as u64,
                        0x90 if wide => d.checked_rem(s).unwrap_or(d),
                        0x90 => (d as u32).checked_rem(s as u32).unwrap_or(d as u32) as u64,
                        0xa0 => d ^ s,
                        0xb0 => s,
                        _ => panic!("ALU op {op:#x}"),
                    };
                    m.regs[dst as usize] = Some(if wide { r } else { r as u32 as u64 });
                }
                pc + 1
            }
            class::LDX => {
                let addr = m.reg(src).wrapping_add(i.off as i64 as u64);
                m.regs[dst as usize] = Some(m.read(addr, size(i.code)));
                pc + 1
            }
            class::ST | class::STX => {
                let addr = m.reg(dst).wrapping_add(i.off as i64 as u64);
                let v = if cls == class::ST {
                    i.imm as i64 as u64
                } else {
                    m.reg(src)
                };
                m.write(addr, size(i.code), v);
                pc + 1
            }
            class::LD => {
                assert_eq!(i.code, 0x18, "ld_imm64");
                let v = (i.imm as u32 as u64) | (insns[pc + 1].imm as u32 as u64) << 32;
                m.regs[dst as usize] = Some(v);
                pc + 2
            }
            class::JMP | class::JMP32 => {
                let op = i.code & 0xf0;
                match op {
                    0x00 => jump(pc, i.off),
                    0x80 => {
                        let r1 = m.reg(1);
                        match i.imm {
                            // bpf_map_lookup_elem
                            1 => {
                                assert_eq!(r1, FACTS_FD as u64, "lookup in an unknown map");
                                m.regs[0] = Some(FACTS_ADDR);
                            }
                            // bpf_tail_call
                            12 => {
                                assert_eq!(r1, CTX_ADDR);
                                assert_eq!(m.reg(2), PROGS_FD as u64);
                                assert_eq!(m.reg(3), SLOT_ACTION as u64);
                                return Outcome::Verdict(m.facts[30] != 0);
                            }
                            // bpf_skb_load_bytes
                            26 => {
                                assert_eq!(r1, CTX_ADDR);
                                let (off, to, n) = (m.reg(2), m.reg(3), m.reg(4) as usize);
                                assert!((1..=STACK_SIZE as usize).contains(&n));
                                let frame = m.frame;
                                match frame.get(off as usize..).and_then(|b| b.get(..n)) {
                                    Some(b) => {
                                        m.mem(to, n).copy_from_slice(b);
                                        m.regs[0] = Some(0);
                                    }
                                    None => m.regs[0] = Some(-14i64 as u64),
                                }
                            }
                            h => panic!("helper {h}"),
                        }
                        for r in 1..=5 {
                            m.regs[r] = None;
                        }
                        pc + 1
                    }
                    0x90 => return Outcome::Exit(m.reg(0)),
                    _ => {
                        let mut a = m.reg(dst);
                        let mut b = if i.code & 0x08 != 0 {
                            m.reg(src)
                        } else {
                            i.imm as i64 as u64
                        };
                        if cls == class::JMP32 {
                            a = a as u32 as u64;
                            b = b as u32 as u64;
                        }
                        let (sa, sb) = if cls == class::JMP32 {
                            (a as u32 as i32 as i64, b as u32 as i32 as i64)
                        } else {
                            (a as i64, b as i64)
                        };
                        let taken = match op {
                            0x10 => a == b,
                            0x20 => a > b,
                            0x30 => a >= b,
                            0x40 => a & b != 0,
                            0x50 => a != b,
                            0x60 => sa > sb,
                            0x70 => sa >= sb,
                            0xa0 => a < b,
                            0xb0 => a <= b,
                            0xc0 => sa < sb,
                            0xd0 => sa <= sb,
                            _ => panic!("jump op {op:#x}"),
                        };
                        if taken { jump(pc, i.off) } else { pc + 1 }
                    }
                }
            }
            _ => panic!("instruction class {cls}"),
        };
    }
}
