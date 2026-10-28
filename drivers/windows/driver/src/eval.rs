//! Running a handle's program on a packet: on the current processor's scratch (the register file
//! and a copy buffer, allocated at load, so nothing is allocated per packet), at DISPATCH_LEVEL so
//! that the processor cannot change, and on an expanded stack when too little is left
//! (docs/spikes/windows-driver.md, finding 2).

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

use alloc::boxed::Box;
use avulse_filter::Meta;
use avulse_filter::bytecode::{Registers, VerifiedProgram};
use avulse_proto::{Link, Packet};

use crate::lock::SpinLock;
use crate::sys;

/// Stack the parser and the interpreter may use. Below it, they run on an expanded stack: NDIS
/// and WFP call filters deep in the network stack, and the x64 kernel stack is 24 KiB.
const STACK_BUDGET: usize = 12 * 1024;
/// The stack `KeExpandKernelStackAndCalloutEx` provides (at most `MAXIMUM_EXPANSION_SIZE`).
const EXPANSION: usize = 16 * 1024;
/// The largest packet a handle sees (WinDivert's MTU limit).
pub const MAX_PACKET: usize = 40 + 0xffff;

/// One processor's scratch. All zeros is a valid value, which is how it is allocated: building
/// it on the stack would overflow the kernel stack.
pub struct Scratch {
    /// Written afresh before each evaluation, for that evaluation's lifetime.
    regs: MaybeUninit<Registers<'static>>,
    /// For packets whose data is not contiguous (the packet hooks, from Step 25).
    #[allow(dead_code)]
    pub copy: [u8; MAX_PACKET],
}

/// Every processor's scratch, each behind its own lock, indexed by `KeGetCurrentProcessorNumberEx`.
/// The lock raises to DISPATCH_LEVEL, so the processor cannot change during an evaluation; it is
/// contended only if a thread moved between reading its processor number and taking the lock.
static SCRATCH: AtomicPtr<SpinLock<Scratch>> = AtomicPtr::new(null_mut());
static SCRATCH_LEN: AtomicUsize = AtomicUsize::new(0);

/// The least stack seen on entry to an evaluation, and how many evaluations ran on an expanded
/// stack or could not.
pub static MIN_STACK: AtomicU64 = AtomicU64::new(u64::MAX);
pub static EXPANDED: AtomicU64 = AtomicU64::new(0);
pub static EXPAND_FAILED: AtomicU64 = AtomicU64::new(0);

/// Allocates every processor's scratch. At PASSIVE_LEVEL, before any hook is registered.
pub fn init() {
    // SAFETY: a plain query.
    let n = unsafe { sys::KeQueryMaximumProcessorCountEx(sys::ALL_PROCESSOR_GROUPS as u16) };
    // SAFETY: all zeros is a valid `SpinLock<Scratch>`: an unlocked lock, uninitialized
    // registers and a zeroed buffer.
    let slots = unsafe { Box::<[SpinLock<Scratch>]>::new_zeroed_slice(n as usize).assume_init() };
    let len = slots.len();
    SCRATCH.store(Box::into_raw(slots).cast(), Ordering::Release);
    SCRATCH_LEN.store(len, Ordering::Release);
}

/// Frees the scratch. At unload, after every hook is gone.
pub fn free() {
    let len = SCRATCH_LEN.swap(0, Ordering::AcqRel);
    let p = SCRATCH.swap(null_mut(), Ordering::AcqRel);
    if !p.is_null() {
        // SAFETY: the slice `init` leaked, which nothing uses any more.
        drop(unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(p, len)) });
    }
}

/// Runs `f` with the current processor's scratch, at DISPATCH_LEVEL. `None` before `init`.
fn with_scratch<R>(f: impl FnOnce(&mut Scratch) -> R) -> Option<R> {
    let (p, len) = (
        SCRATCH.load(Ordering::Acquire),
        SCRATCH_LEN.load(Ordering::Acquire),
    );
    if p.is_null() || len == 0 {
        return None;
    }
    // SAFETY: a plain query.
    let cpu = unsafe { sys::KeGetCurrentProcessorNumberEx(null_mut()) } as usize;
    // SAFETY: `init` allocated `len` slots, which live until `free`, after every hook is gone.
    let slot = unsafe { &*p.add(cpu % len) };
    let mut scratch = slot.lock();
    Some(f(&mut scratch))
}

/// One evaluation, passed to the stack expansion callout.
struct Call<'a, 'b> {
    program: &'a VerifiedProgram<'a>,
    bytes: &'a [u8],
    link: Link,
    meta: &'a Meta<'b>,
    regs: *mut MaybeUninit<Registers<'static>>,
    matched: bool,
}

impl Call<'_, '_> {
    fn run(&mut self) {
        let packet = Packet::parse(self.bytes, self.link);
        // SAFETY: the slot belongs to this processor, which is at DISPATCH_LEVEL until the
        // evaluation ends. A fresh register file is written into it for this evaluation's
        // lifetime; nothing reads the slot as registers of another lifetime.
        let regs = unsafe {
            let slot = self.regs.cast::<Registers<'_>>();
            slot.write(Registers::new());
            &mut *slot
        };
        self.matched = self.program.matches_in(regs, &packet, self.meta);
    }
}

unsafe extern "C" fn expanded(call: *mut c_void) {
    // SAFETY: the `Call` that `evaluate` passed, alive for the whole callout.
    unsafe { (*call.cast::<Call<'_, '_>>()).run() }
}

/// Whether `program` matches the packet `bytes` (starting with the header `link` names) with
/// metadata `meta`. `None` if it could not run: no scratch, or no stack. The packet hooks then let
/// the packet through (fail open).
pub fn evaluate(
    program: &VerifiedProgram<'_>,
    bytes: &[u8],
    link: Link,
    meta: &Meta<'_>,
) -> Option<bool> {
    with_scratch(|scratch| {
        let stack = sys::remaining_stack();
        MIN_STACK.fetch_min(stack as u64, Ordering::Relaxed);
        let mut call = Call {
            program,
            bytes,
            link,
            meta,
            regs: &raw mut scratch.regs,
            matched: false,
        };
        if stack >= STACK_BUDGET {
            call.run();
            return Some(call.matched);
        }
        // SAFETY: `call` outlives the callout, which runs before this returns. `Wait` is FALSE,
        // as it must be at DISPATCH_LEVEL; the call then fails instead of waiting for a stack.
        let status = unsafe {
            sys::KeExpandKernelStackAndCalloutEx(
                Some(expanded),
                (&raw mut call).cast(),
                EXPANSION as _,
                0,
                null_mut(),
            )
        };
        if status != sys::STATUS_SUCCESS {
            EXPAND_FAILED.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        EXPANDED.fetch_add(1, Ordering::Relaxed);
        Some(call.matched)
    })
    .flatten()
}
