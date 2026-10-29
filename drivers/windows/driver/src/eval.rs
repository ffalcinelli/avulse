//! Running a handle's program on a packet: on the current processor's scratch (the register file
//! and a copy buffer, allocated at load, so nothing is allocated per packet), at DISPATCH_LEVEL so
//! that the processor cannot change, and on an expanded stack when too little is left
//! (docs/spikes/windows-driver.md, finding 2).

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

use alloc::boxed::Box;
use alloc::vec::Vec;
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
    /// For packets whose data is not contiguous, and frames with a VLAN tag put back.
    pub copy: [u8; MAX_PACKET + 4],
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

/// Runs `program` on `bytes` with the register slot `regs`, on an expanded stack when too little
/// is left. `None` if no stack could be had.
fn run(
    program: &VerifiedProgram<'_>,
    bytes: &[u8],
    link: Link,
    meta: &Meta<'_>,
    regs: *mut MaybeUninit<Registers<'static>>,
) -> Option<bool> {
    let stack = sys::remaining_stack();
    MIN_STACK.fetch_min(stack as u64, Ordering::Relaxed);
    let mut call = Call {
        program,
        bytes,
        link,
        meta,
        regs,
        matched: false,
    };
    if stack >= STACK_BUDGET {
        call.run();
        return Some(call.matched);
    }
    // SAFETY: `call` outlives the callout, which runs before this returns. `Wait` is FALSE, as it
    // must be at DISPATCH_LEVEL; the call then fails instead of waiting for a stack.
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
    with_scratch(|scratch| run(program, bytes, link, meta, &raw mut scratch.regs)).flatten()
}

/// [`evaluate`] on the data of `nb`, read in place when it is contiguous and through the
/// processor's copy buffer otherwise; with the packet's bytes when it matches and `keep` is set
/// (`Copied::Failed` if they could not be allocated). `None` if the packet could not be read or
/// evaluated.
///
/// # Safety
///
/// `nb` is a valid NET_BUFFER, at IRQL <= DISPATCH_LEVEL.
pub unsafe fn evaluate_nb(
    program: &VerifiedProgram<'_>,
    nb: *mut sys::NET_BUFFER,
    link: Link,
    meta: &Meta<'_>,
    keep: bool,
) -> Option<(bool, Copied)> {
    // SAFETY: `nb` is valid.
    let len = unsafe { sys::nb_data_length(nb) } as usize;
    if len == 0 || len > MAX_PACKET {
        return None;
    }
    with_scratch(|scratch| {
        // SAFETY: `nb` is valid; NDIS returns the data in place if it is contiguous, else copies
        // it into `copy`, which has room for `len` bytes.
        let p = unsafe {
            sys::NdisGetDataBuffer(nb, len as u32, scratch.copy.as_mut_ptr().cast(), 1, 0)
        };
        if p.is_null() {
            return None;
        }
        // SAFETY: NDIS returned `len` readable bytes, in the packet or in `copy`, which this
        // closure does not otherwise touch while the slice lives.
        let bytes = unsafe { core::slice::from_raw_parts(p.cast::<u8>(), len) };
        let matched = run(program, bytes, link, meta, &raw mut scratch.regs)?;
        let copy = match (matched && keep).then(|| sys::try_copy(bytes)) {
            None => Copied::None,
            Some(Some(data)) => Copied::Data(data),
            Some(None) => Copied::Failed,
        };
        Some((matched, copy))
    })
    .flatten()
}

/// The copy [`evaluate_nb`] made of a packet.
pub enum Copied {
    /// None was asked for.
    None,
    /// The packet's bytes.
    Data(Vec<u8>),
    /// The pool had no room for it.
    Failed,
}

/// A packet's bytes and the processor's register file, for [`with_frame`]: the handles of a hook
/// evaluate the same bytes in turn.
pub struct Frame<'a> {
    pub bytes: &'a [u8],
    regs: *mut MaybeUninit<Registers<'static>>,
}

impl Frame<'_> {
    /// Whether `program` matches the bytes, with `meta`; `None` if no stack could be had.
    pub fn matches(
        &self,
        program: &VerifiedProgram<'_>,
        link: Link,
        meta: &Meta<'_>,
    ) -> Option<bool> {
        run(program, self.bytes, link, meta, self.regs)
    }
}

/// Runs `f` on the data of `nb`, read in place when it is contiguous and through the processor's
/// copy buffer otherwise; with the VLAN tag control information `tag` put back after the MAC
/// addresses (TPID 0x8100), always in the copy buffer. `None` if the data could not be read.
///
/// # Safety
///
/// `nb` is a valid NET_BUFFER, at IRQL <= DISPATCH_LEVEL.
pub unsafe fn with_frame<R>(
    nb: *mut sys::NET_BUFFER,
    tag: Option<u16>,
    f: impl FnOnce(&Frame<'_>) -> R,
) -> Option<R> {
    // SAFETY: `nb` is valid.
    let len = unsafe { sys::nb_data_length(nb) } as usize;
    if !(14..=MAX_PACKET).contains(&len) {
        return None;
    }
    with_scratch(|scratch| {
        let copy = scratch.copy.as_mut_ptr();
        let at = if tag.is_some() { 4 } else { 0 };
        // SAFETY: `copy` has room for `len + 4` bytes; NDIS returns the data in place if it is
        // contiguous, else copies it to `copy + at`.
        let p = unsafe { sys::NdisGetDataBuffer(nb, len as u32, copy.add(at).cast(), 1, 0) };
        if p.is_null() {
            return None;
        }
        let bytes = match tag {
            // SAFETY: NDIS returned `len` readable bytes, which this closure does not otherwise
            // touch while the slice lives.
            None => unsafe { core::slice::from_raw_parts(p.cast::<u8>(), len) },
            Some(tci) => {
                // SAFETY: the frame is at `copy + 4` (copied there if NDIS returned it in
                // place); the MAC addresses move back 4 bytes, and the tag goes after them.
                unsafe {
                    let dst = copy.add(4);
                    if p.cast::<u8>() != dst {
                        core::ptr::copy_nonoverlapping(p.cast::<u8>(), dst, len);
                    }
                    core::ptr::copy(dst, copy, 12);
                    let [hi, lo] = tci.to_be_bytes();
                    core::ptr::copy_nonoverlapping([0x81, 0x00, hi, lo].as_ptr(), copy.add(12), 4);
                    core::slice::from_raw_parts(copy, len + 4)
                }
            }
        };
        let frame = Frame {
            bytes,
            regs: &raw mut scratch.regs,
        };
        Some(f(&frame))
    })
    .flatten()
}
