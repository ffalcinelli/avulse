//! The avulse Windows driver, `avulse.sys`.
//!
//! It creates the control device `\\.\Avulse`, through which the user-mode backend opens handles
//! (`avulse_abi::ioctl`). Each handle carries a filter compiled to avulse bytecode, which the
//! driver verifies when the handle opens and runs with the `no_std` interpreter on the packets of
//! its hooks. The hooks (WFP callouts for the WinDivert layers, an NDIS lightweight filter for
//! ETHERNET) come in the steps of Phase 5 (`docs/implementation-plan.md`); for now `EVAL` runs a
//! handle's filter on a packet user mode passes.

#![no_std]

extern crate alloc;
#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

mod device;
mod eval;
mod handle;
mod lock;
mod sys;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

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
    eval::init();
    // SAFETY: at PASSIVE_LEVEL, once, with the driver object.
    let status = unsafe { device::create(driver) };
    if status != sys::STATUS_SUCCESS {
        wdk::println!("avulse: creating the device failed: {status:#x}");
        eval::free();
        return status;
    }
    // SAFETY: `driver` is valid for the whole call.
    unsafe { (*driver).DriverUnload = Some(unload) };
    wdk::println!("avulse: loaded");
    sys::STATUS_SUCCESS
}

/// Removes the device, then frees the scratch. The I/O manager only unloads a driver whose files
/// are all closed.
unsafe extern "C" fn unload(_driver: *mut sys::DRIVER_OBJECT) {
    // SAFETY: at PASSIVE_LEVEL, after `driver_entry` succeeded.
    unsafe { device::delete() };
    eval::free();
    wdk::println!(
        "avulse: unloaded; least stack {} B, expanded {}, expansion failed {}",
        eval::MIN_STACK.load(core::sync::atomic::Ordering::Relaxed),
        eval::EXPANDED.load(core::sync::atomic::Ordering::Relaxed),
        eval::EXPAND_FAILED.load(core::sync::atomic::Ordering::Relaxed),
    );
}
