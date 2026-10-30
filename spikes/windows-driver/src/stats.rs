//! Counters, the packet evaluation both hooks share, and saving the counters to the registry.

use core::ffi::c_void;
use core::ptr::null_mut;
use core::slice;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::vec;
use avulse_filter::Meta;
use avulse_filter::bytecode::VerifiedProgram;
use avulse_proto::{Link, Packet};

use crate::{sys, unicode, w};

/// What the driver counts.
#[derive(Clone, Copy)]
pub(crate) enum Counter {
    WfpStatus,
    WfpInbound,
    WfpOutbound,
    WfpMatched,
    WfpBlocked,
    LwfAttached,
    LwfSent,
    LwfReceived,
    LwfMatched,
    LwfPing,
    /// Packets read through a copy because their data was not contiguous.
    Copied,
    /// Packets the program could not read.
    Unreadable,
    /// The least stack left when a packet reached the interpreter, in bytes.
    MinStack,
    /// Packets evaluated on an expanded stack, because too little was left.
    Expanded,
    /// Packets passed without evaluation, because the stack could not be expanded.
    ExpandFailed,
}

const NAMES: [&[u16]; 15] = [
    w!("WfpStatus"),
    w!("WfpInbound"),
    w!("WfpOutbound"),
    w!("WfpMatched"),
    w!("WfpBlocked"),
    w!("LwfAttached"),
    w!("LwfSent"),
    w!("LwfReceived"),
    w!("LwfMatched"),
    w!("LwfPing"),
    w!("Copied"),
    w!("Unreadable"),
    w!("MinStack"),
    w!("Expanded"),
    w!("ExpandFailed"),
];

#[allow(clippy::declare_interior_mutable_const)]
const ZERO: AtomicU64 = AtomicU64::new(0);
static COUNTERS: [AtomicU64; 15] = {
    let mut c = [ZERO; 15];
    c[Counter::MinStack as usize] = AtomicU64::new(u64::MAX);
    c
};

pub(crate) fn add(c: Counter, n: u64) {
    COUNTERS[c as usize].fetch_add(n, Ordering::Relaxed);
}

pub(crate) fn set(c: Counter, v: u64) {
    COUNTERS[c as usize].store(v, Ordering::Relaxed);
}

fn get(c: usize) -> u64 {
    COUNTERS[c].load(Ordering::Relaxed)
}

/// Runs `program` on the data of `nb`, as a buffer that starts with the header `link` names.
/// `None` if the data cannot be read.
///
/// # Safety
///
/// `nb` is a valid NET_BUFFER, at IRQL <= DISPATCH_LEVEL.
pub(crate) unsafe fn evaluate(
    program: &VerifiedProgram<'_>,
    nb: *mut sys::NET_BUFFER,
    link: Link,
    meta: &Meta<'_>,
) -> Option<bool> {
    // SAFETY: `nb` is valid.
    let len = unsafe { sys::nb_data_length(nb) };
    if len == 0 {
        return None;
    }
    // Contiguous data is read in place; otherwise NDIS copies it into `copy`.
    let mut copy = vec![];
    // SAFETY: `nb` is valid; without storage, NDIS returns null unless the data is contiguous.
    let mut p = unsafe { sys::NdisGetDataBuffer(nb, len, null_mut(), 1, 0) };
    if p.is_null() {
        add(Counter::Copied, 1);
        copy = vec![0u8; len as usize];
        // SAFETY: `copy` has room for `len` bytes.
        p = unsafe { sys::NdisGetDataBuffer(nb, len, copy.as_mut_ptr().cast(), 1, 0) };
    }
    if p.is_null() {
        add(Counter::Unreadable, 1);
        return None;
    }
    // SAFETY: NDIS returned `len` readable bytes, in the packet or in `copy`, which outlives
    // this borrow.
    let bytes = unsafe { slice::from_raw_parts(p.cast::<u8>(), len as usize) };
    let stack = sys::remaining_stack();
    COUNTERS[Counter::MinStack as usize].fetch_min(stack as u64, Ordering::Relaxed);
    let mut call = Call {
        program,
        bytes,
        link,
        meta,
        matched: false,
    };
    if stack >= STACK_BUDGET {
        call.run();
    } else {
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
        if status != 0 {
            add(Counter::ExpandFailed, 1);
            return None;
        }
        add(Counter::Expanded, 1);
    }
    drop(copy);
    Some(call.matched)
}

/// Stack the parser and the interpreter may use. Below it, they run on an expanded stack: NDIS
/// and WFP call filters deep in the network stack, and the x64 kernel stack is 24 KiB.
const STACK_BUDGET: usize = 12 * 1024;
/// The stack `KeExpandKernelStackAndCalloutEx` provides (at most `MAXIMUM_EXPANSION_SIZE`).
const EXPANSION: usize = 16 * 1024;

/// One evaluation, passed to the stack expansion callout.
struct Call<'a, 'b> {
    program: &'a VerifiedProgram<'a>,
    bytes: &'a [u8],
    link: Link,
    meta: &'a Meta<'b>,
    matched: bool,
}

impl Call<'_, '_> {
    fn run(&mut self) {
        self.matched = self
            .program
            .matches(&Packet::parse(self.bytes, self.link), self.meta);
    }
}

unsafe extern "C" fn expanded(call: *mut c_void) {
    // SAFETY: the `Call` that `evaluate` passed, alive for the whole callout.
    unsafe { (*call.cast::<Call<'_, '_>>()).run() }
}

pub(crate) fn log() {
    for (i, name) in NAMES.iter().enumerate() {
        let name: alloc::string::String = name[..name.len() - 1]
            .iter()
            .map(|&c| c as u8 as char)
            .collect();
        wdk::println!("avulse_spike: {name} = {}", get(i));
    }
}

/// Writes the counters as REG_QWORD values of `HKLM\SOFTWARE\AvulseSpike`.
///
/// # Safety
///
/// At PASSIVE_LEVEL.
pub(crate) unsafe fn save() {
    let mut name = unicode(w!("\\Registry\\Machine\\SOFTWARE\\AvulseSpike"));
    let mut attrs = sys::OBJECT_ATTRIBUTES {
        Length: size_of::<sys::OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: null_mut(),
        ObjectName: &mut name,
        Attributes: sys::OBJ_KERNEL_HANDLE | sys::OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: null_mut(),
        SecurityQualityOfService: null_mut(),
    };
    let mut key = null_mut();
    // SAFETY: the arguments are valid for the call.
    let status = unsafe {
        sys::ZwCreateKey(
            &mut key,
            sys::KEY_ALL_ACCESS,
            &mut attrs,
            0,
            null_mut(),
            0,
            null_mut(),
        )
    };
    if status != 0 {
        wdk::println!("avulse_spike: ZwCreateKey failed: {status:#x}");
        return;
    }
    for (i, name) in NAMES.iter().enumerate() {
        let mut value_name = unicode(name);
        let mut v = get(i);
        // SAFETY: `key` is open; the value is 8 bytes.
        let _ = unsafe {
            sys::ZwSetValueKey(
                key,
                &mut value_name,
                0,
                sys::REG_QWORD,
                (&raw mut v).cast(),
                8,
            )
        };
    }
    // SAFETY: `key` is open.
    let _ = unsafe { sys::ZwClose(key) };
}
