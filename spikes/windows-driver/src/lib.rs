//! Spike B: a Windows driver in Rust that registers WFP callouts (the NETWORK layer) and an NDIS
//! lightweight filter (the ETHERNET layer), and runs avulse's bytecode verifier and interpreter on
//! the packets of both.
//!
//! - The WFP callouts sit at the inbound and outbound IPv4 packet layers and block the packets
//!   the `WFP_FILTER` of `build.rs` matches (outbound DNS queries).
//! - The NDIS filter passes every frame through and counts those its `LWF_FILTER` and
//!   `PING_FILTER` match.
//!
//! Counters go to `HKLM\SOFTWARE\AvulseSpike` when the driver unloads. `DbgPrint` output says
//! the same. See `docs/spikes/windows-driver.md`.

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate wdk_panic;

use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering};

use alloc::boxed::Box;
use avulse_filter::bytecode::{self, VerifiedProgram};
#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

mod lwf;
mod stats;
mod sys;
mod wfp;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

/// The filters, compiled to bytecode by `build.rs`.
static WFP_PROGRAM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wfp.avbc"));
static LWF_PROGRAM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/lwf.avbc"));
static PING_PROGRAM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ping.avbc"));

/// The verified programs, set before any callback is registered and freed after every callback
/// is gone.
pub(crate) struct Programs {
    pub wfp: VerifiedProgram<'static>,
    pub lwf: VerifiedProgram<'static>,
    pub ping: VerifiedProgram<'static>,
}

static PROGRAMS: AtomicPtr<Programs> = AtomicPtr::new(null_mut());

pub(crate) fn programs() -> Option<&'static Programs> {
    // SAFETY: the pointer is either null or a leaked `Box` that lives until `unload` has
    // unregistered every callback that calls this.
    unsafe { PROGRAMS.load(Ordering::Acquire).as_ref() }
}

/// A NUL-terminated UTF-16 string from an ASCII literal.
macro_rules! w {
    ($s:literal) => {{
        const S: &str = concat!($s, "\0");
        const W: [u16; S.len()] = {
            let b = S.as_bytes();
            let mut w = [0u16; S.len()];
            let mut i = 0;
            while i < b.len() {
                w[i] = b[i] as u16;
                i += 1;
            }
            w
        };
        &W
    }};
}
pub(crate) use w;

/// A `UNICODE_STRING` over a static NUL-terminated UTF-16 string.
pub(crate) fn unicode(s: &'static [u16]) -> sys::UNICODE_STRING {
    sys::UNICODE_STRING {
        Length: ((s.len() - 1) * 2) as u16,
        MaximumLength: (s.len() * 2) as u16,
        Buffer: s.as_ptr().cast_mut(),
    }
}

/// The driver's entry point.
///
/// # Safety
///
/// Called by the I/O manager with a valid driver object.
#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver: *mut sys::DRIVER_OBJECT,
    _registry_path: *const sys::UNICODE_STRING,
) -> sys::NTSTATUS {
    let verified = (
        bytecode::verify(WFP_PROGRAM),
        bytecode::verify(LWF_PROGRAM),
        bytecode::verify(PING_PROGRAM),
    );
    let (wfp, lwf, ping) = match verified {
        (Ok(w), Ok(l), Ok(p)) => (w, l, p),
        (w, l, p) => {
            wdk::println!("avulse_spike: the verifier rejected a program: {w:?} {l:?} {p:?}");
            return wdk_sys::STATUS_INVALID_PARAMETER;
        }
    };
    PROGRAMS.store(
        Box::into_raw(Box::new(Programs { wfp, lwf, ping })),
        Ordering::Release,
    );
    wdk::println!(
        "avulse_spike: programs verified ({}, {} and {} bytes)",
        WFP_PROGRAM.len(),
        LWF_PROGRAM.len(),
        PING_PROGRAM.len()
    );

    // SAFETY: `driver` is valid for the whole call.
    unsafe { (*driver).DriverUnload = Some(unload) };

    // SAFETY: called once, at PASSIVE_LEVEL, with the driver object.
    let status = unsafe { lwf::register(driver) };
    if status != 0 {
        wdk::println!("avulse_spike: NdisFRegisterFilterDriver failed: {status:#x}");
        free_programs();
        return status;
    }
    // SAFETY: as above. A failure leaves the NDIS filter working: WFP needs the base filtering
    // engine, which may not be running yet at boot.
    let status = unsafe { wfp::register(driver) };
    stats::set(stats::Counter::WfpStatus, status as u32 as u64);
    if status != 0 {
        wdk::println!("avulse_spike: WFP registration failed: {status:#x}");
    }
    wdk::println!("avulse_spike: loaded");
    0
}

/// Unregisters everything, then saves the counters.
unsafe extern "C" fn unload(_driver: *mut sys::DRIVER_OBJECT) {
    // SAFETY: called once, at PASSIVE_LEVEL, after `driver_entry` succeeded.
    unsafe {
        wfp::unregister();
        lwf::unregister();
    }
    stats::log();
    // SAFETY: at PASSIVE_LEVEL.
    unsafe { stats::save() };
    free_programs();
}

fn free_programs() {
    let p = PROGRAMS.swap(null_mut(), Ordering::AcqRel);
    if !p.is_null() {
        // SAFETY: the pointer came from `Box::into_raw`, and no callback can use it any more.
        drop(unsafe { Box::from_raw(p) });
    }
}
