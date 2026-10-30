//! eBPF instructions and a small assembler with forward labels.
//!
//! Only what the code generator emits is here: 32- and 64-bit ALU operations with an immediate
//! or a register, loads and stores, `ld_imm64` (plain or with a map fd), helper calls, and
//! conditional jumps. Jumps go forward only, so a generated program has no loops and the
//! verifier explores each path once.

/// One 8-byte eBPF instruction (`struct bpf_insn`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    /// Opcode: class, size or operation, source and mode bits.
    pub code: u8,
    /// Destination register.
    pub dst: u8,
    /// Source register (or a pseudo source for `ld_imm64`).
    pub src: u8,
    /// Signed offset: of a jump, in instructions, or of a memory access, in bytes.
    pub off: i16,
    /// Signed immediate.
    pub imm: i32,
}

impl Insn {
    /// The instruction as the kernel reads it, in host byte order.
    pub fn to_bytes(self) -> [u8; 8] {
        let regs = if cfg!(target_endian = "little") {
            self.src << 4 | self.dst
        } else {
            self.dst << 4 | self.src
        };
        let off = self.off.to_ne_bytes();
        let imm = self.imm.to_ne_bytes();
        [
            self.code, regs, off[0], off[1], imm[0], imm[1], imm[2], imm[3],
        ]
    }
}

/// Instruction classes.
pub mod class {
    /// Non-standard loads (`ld_imm64`).
    pub const LD: u8 = 0x00;
    /// Loads from memory.
    pub const LDX: u8 = 0x01;
    /// Stores of an immediate.
    pub const ST: u8 = 0x02;
    /// Stores of a register.
    pub const STX: u8 = 0x03;
    /// 32-bit arithmetic (the result is zero-extended).
    pub const ALU: u8 = 0x04;
    /// 64-bit jumps, calls and exit.
    pub const JMP: u8 = 0x05;
    /// Jumps that compare the low 32 bits.
    pub const JMP32: u8 = 0x06;
    /// 64-bit arithmetic.
    pub const ALU64: u8 = 0x07;
}

/// Memory access sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Size {
    /// One byte.
    B = 0x10,
    /// Two bytes.
    H = 0x08,
    /// Four bytes.
    W = 0x00,
    /// Eight bytes.
    DW = 0x18,
}

impl Size {
    /// The size of `n` bytes (1, 2, 4 or 8).
    pub fn of(n: usize) -> Size {
        match n {
            1 => Size::B,
            2 => Size::H,
            4 => Size::W,
            _ => Size::DW,
        }
    }
}

/// Arithmetic operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alu {
    /// `dst += src`.
    Add = 0x00,
    /// `dst -= src`.
    Sub = 0x10,
    /// `dst *= src`.
    Mul = 0x20,
    /// `dst /= src` (unsigned; division by zero gives 0).
    Div = 0x30,
    /// `dst |= src`.
    Or = 0x40,
    /// `dst &= src`.
    And = 0x50,
    /// `dst <<= src`.
    Lsh = 0x60,
    /// `dst >>= src` (logical).
    Rsh = 0x70,
    /// `dst %= src` (unsigned; modulo zero leaves `dst`).
    Mod = 0x90,
    /// `dst ^= src`.
    Xor = 0xa0,
    /// `dst = src`.
    Mov = 0xb0,
}

/// Jump conditions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cond {
    /// Equal.
    Eq = 0x10,
    /// Unsigned greater.
    Gt = 0x20,
    /// Unsigned greater or equal.
    Ge = 0x30,
    /// Some bit in common (`dst & src != 0`).
    Set = 0x40,
    /// Not equal.
    Ne = 0x50,
    /// Signed greater.
    Sgt = 0x60,
    /// Signed greater or equal.
    Sge = 0x70,
    /// Unsigned less.
    Lt = 0xa0,
    /// Unsigned less or equal.
    Le = 0xb0,
    /// Signed less.
    Slt = 0xc0,
    /// Signed less or equal.
    Sle = 0xd0,
}

const K: u8 = 0x00;
const X: u8 = 0x08;
const MEM: u8 = 0x60;
const IMM: u8 = 0x00;
const JA: u8 = 0x00;
const CALL: u8 = 0x80;
const EXIT: u8 = 0x90;
const END: u8 = 0xd0;
const TO_BE: u8 = 0x08;

/// `BPF_PSEUDO_MAP_FD`: the immediate of an `ld_imm64` is a map fd.
pub const PSEUDO_MAP_FD: u8 = 1;

/// Registers. R0 holds return values, R1 to R5 helper arguments (clobbered by calls), R6 to R9
/// survive calls, R10 is the read-only frame pointer.
pub type Reg = u8;
/// The frame pointer.
pub const FP: Reg = 10;

/// A forward jump target, created by [`Asm::label`] and placed by [`Asm::bind`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Label(usize);

/// A map the program refers to by fd, filled in at load time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapRef {
    /// The per-CPU facts (`avulse_facts`).
    Facts,
    /// The program array (`avulse_progs`).
    Progs,
}

/// Where a program loads maps: the index of each `ld_imm64` and the map it names.
pub type MapRefs = Vec<(usize, MapRef)>;

/// Why assembling failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsmError {
    /// A jump is longer than an instruction offset can hold, or the program is over the limit.
    TooLarge,
}

/// Instructions, labels and map references, assembled by [`Asm::finish`].
#[derive(Default)]
pub struct Asm {
    insns: Vec<Insn>,
    labels: Vec<Option<usize>>,
    jumps: Vec<(usize, Label)>,
    maps: MapRefs,
}

/// The most instructions a program may have: what the kernel accepts from a privileged loader
/// (`BPF_COMPLEXITY_LIMIT_INSNS`) is far more, but jump offsets are 16-bit.
pub const MAX_INSNS: usize = 32_767;

impl Asm {
    /// The number of instructions so far.
    pub fn len(&self) -> usize {
        self.insns.len()
    }

    /// Whether no instruction was emitted.
    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }

    /// A new, unplaced label.
    pub fn label(&mut self) -> Label {
        self.labels.push(None);
        Label(self.labels.len() - 1)
    }

    /// Places `l` at the next instruction.
    pub fn bind(&mut self, l: Label) {
        debug_assert!(self.labels[l.0].is_none(), "label bound twice");
        self.labels[l.0] = Some(self.insns.len());
    }

    fn emit(&mut self, code: u8, dst: Reg, src: Reg, off: i16, imm: i32) {
        self.insns.push(Insn {
            code,
            dst,
            src,
            off,
            imm,
        });
    }

    /// 64-bit `dst op= imm`.
    pub fn alu64_imm(&mut self, op: Alu, dst: Reg, imm: i32) {
        self.emit(class::ALU64 | op as u8 | K, dst, 0, 0, imm);
    }

    /// 64-bit `dst op= src`.
    pub fn alu64_reg(&mut self, op: Alu, dst: Reg, src: Reg) {
        self.emit(class::ALU64 | op as u8 | X, dst, src, 0, 0);
    }

    /// 32-bit `dst op= imm`, zero-extending the result.
    pub fn alu32_imm(&mut self, op: Alu, dst: Reg, imm: i32) {
        self.emit(class::ALU | op as u8 | K, dst, 0, 0, imm);
    }

    /// 32-bit `dst op= src`, zero-extending the result.
    pub fn alu32_reg(&mut self, op: Alu, dst: Reg, src: Reg) {
        self.emit(class::ALU | op as u8 | X, dst, src, 0, 0);
    }

    /// `dst = htobe(dst)` on the low `bits` (16, 32 or 64) bits, zero-extended.
    pub fn to_be(&mut self, dst: Reg, bits: i32) {
        self.emit(class::ALU | END | TO_BE, dst, 0, 0, bits);
    }

    /// `dst = *(size *)(src + off)`.
    pub fn load(&mut self, size: Size, dst: Reg, src: Reg, off: i16) {
        self.emit(class::LDX | MEM | size as u8, dst, src, off, 0);
    }

    /// `*(size *)(dst + off) = src`.
    pub fn store(&mut self, size: Size, dst: Reg, off: i16, src: Reg) {
        self.emit(class::STX | MEM | size as u8, dst, src, off, 0);
    }

    /// `*(size *)(dst + off) = imm`.
    pub fn store_imm(&mut self, size: Size, dst: Reg, off: i16, imm: i32) {
        self.emit(class::ST | MEM | size as u8, dst, 0, off, imm);
    }

    /// `dst = imm` for any 64-bit value (two instructions).
    pub fn ld_imm64(&mut self, dst: Reg, imm: u64) {
        self.emit(
            class::LD | IMM | Size::DW as u8,
            dst,
            0,
            0,
            imm as u32 as i32,
        );
        self.emit(0, 0, 0, 0, (imm >> 32) as u32 as i32);
    }

    /// `dst = &map` (two instructions; the fd is filled in at load time).
    pub fn ld_map(&mut self, dst: Reg, map: MapRef) {
        self.maps.push((self.insns.len(), map));
        self.emit(class::LD | IMM | Size::DW as u8, dst, PSEUDO_MAP_FD, 0, 0);
        self.emit(0, 0, 0, 0, 0);
    }

    /// Calls helper `id`.
    pub fn call(&mut self, id: i32) {
        self.emit(class::JMP | CALL, 0, 0, 0, id);
    }

    /// Returns R0.
    pub fn exit(&mut self) {
        self.emit(class::JMP | EXIT, 0, 0, 0, 0);
    }

    /// Jumps to `l`.
    pub fn ja(&mut self, l: Label) {
        self.jumps.push((self.insns.len(), l));
        self.emit(class::JMP | JA, 0, 0, 0, 0);
    }

    /// Jumps to `l` if `dst cond imm`, comparing 64 bits (`imm` is sign-extended).
    pub fn jmp_imm(&mut self, cond: Cond, dst: Reg, imm: i32, l: Label) {
        self.jumps.push((self.insns.len(), l));
        self.emit(class::JMP | cond as u8 | K, dst, 0, 0, imm);
    }

    /// Jumps to `l` if `dst cond src`, comparing 64 bits.
    pub fn jmp_reg(&mut self, cond: Cond, dst: Reg, src: Reg, l: Label) {
        self.jumps.push((self.insns.len(), l));
        self.emit(class::JMP | cond as u8 | X, dst, src, 0, 0);
    }

    /// Jumps to `l` if `dst cond imm`, comparing the low 32 bits.
    pub fn jmp32_imm(&mut self, cond: Cond, dst: Reg, imm: u32, l: Label) {
        self.jumps.push((self.insns.len(), l));
        self.emit(class::JMP32 | cond as u8 | K, dst, 0, 0, imm as i32);
    }

    /// Fails once the program is over [`MAX_INSNS`], so that runaway generation stops early.
    pub fn check_size(&self) -> Result<(), AsmError> {
        if self.insns.len() > MAX_INSNS {
            Err(AsmError::TooLarge)
        } else {
            Ok(())
        }
    }

    /// Resolves the jumps and drops the instructions no path reaches, which the verifier
    /// rejects (`unreachable insn`). Every label must be bound after the jumps to it.
    pub fn finish(self) -> Result<(Vec<Insn>, MapRefs), AsmError> {
        self.check_size()?;
        let n = self.insns.len();
        let mut target = vec![None; n];
        for &(at, l) in &self.jumps {
            let t = self.labels[l.0].expect("jump to an unbound label");
            assert!(t > at && t < n, "backward jump, or past the end");
            target[at] = Some(t);
        }
        // Jumps go forward, so one pass in order finds every reachable instruction.
        let mut live = vec![false; n + 2];
        live[0] = true;
        let mut i = 0;
        while i < n {
            if live[i] {
                let code = self.insns[i].code;
                let op = code & 0xf0;
                let jmp = code & 7 == class::JMP || code & 7 == class::JMP32;
                if code == class::LD | IMM | Size::DW as u8 {
                    live[i + 1] = true;
                    live[i + 2] = true;
                    i += 2;
                    continue;
                }
                if let Some(t) = target[i] {
                    live[t] = true;
                }
                if !(jmp && (op == EXIT || op == JA && code & 7 == class::JMP)) {
                    live[i + 1] = true;
                }
            }
            i += 1;
        }
        let mut index = vec![0; n + 1];
        for i in 0..n {
            index[i + 1] = index[i] + live[i] as usize;
        }
        let mut insns = Vec::with_capacity(index[n]);
        for (i, mut insn) in self.insns.into_iter().enumerate() {
            if !live[i] {
                continue;
            }
            if let Some(t) = target[i] {
                insn.off =
                    i16::try_from(index[t] - index[i] - 1).map_err(|_| AsmError::TooLarge)?;
            }
            insns.push(insn);
        }
        let maps = self
            .maps
            .into_iter()
            .filter(|&(at, _)| live[at])
            .map(|(at, m)| (index[at], m))
            .collect();
        Ok((insns, maps))
    }
}
