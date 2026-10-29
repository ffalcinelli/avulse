//! The avulse Windows driver, `avulse.sys`.
//!
//! It creates the control device `\\.\Avulse`, through which the user-mode backend opens handles
//! (`avulse_abi::ioctl`). Each handle carries a filter compiled to avulse bytecode, which the
//! driver verifies when the handle opens and runs with the `no_std` interpreter on the packets of
//! its hooks: WFP callouts for the NETWORK layers (`wfp`) and the FLOW and SOCKET layers (`ale`),
//! and an NDIS lightweight filter for ETHERNET (`lwf`), which needs the driver installed with its
//! INF. REFLECT reports the driver's own handles (`reflect`). `EVAL` runs a handle's filter
//! on a packet user mode passes, for the tests.

#![no_std]

extern crate alloc;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

mod ale;
mod device;
mod eval;
mod handle;
mod inject;
mod lock;
mod lwf;
mod reflect;
mod rx;
mod sys;
mod wfp;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

/// The bug check code of a panic in the driver. Its parameters are the line, the column, and the
/// address and length of the source file's name (`!analyze -v` shows them; `da <address>` the
/// name).
const BUGCHECK_PANIC: u32 = 0xA7E1_5E00;

/// A panic stops the machine with a crash dump. `wdk-panic`'s handler spins forever instead,
/// which hangs the processor, often at DISPATCH_LEVEL, and leaves nothing to debug. The packet
/// paths do not allocate infallibly (`sys::try_copy`), so that running out of pool is not a panic.
#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let (file, line, column) = info
        .location()
        .map_or(("", 0, 0), |l| (l.file(), l.line(), l.column()));
    // SAFETY: stops the system; the file name is a static string.
    unsafe {
        sys::KeBugCheckEx(
            BUGCHECK_PANIC,
            line as sys::ULONG_PTR,
            column as sys::ULONG_PTR,
            file.as_ptr() as sys::ULONG_PTR,
            file.len() as sys::ULONG_PTR,
        )
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
    eval::init();
    // SAFETY: at PASSIVE_LEVEL, once, with the driver object.
    let status = unsafe { device::create(driver) };
    if status != sys::STATUS_SUCCESS {
        wdk::println!("avulse: creating the device failed: {status:#x}");
        eval::free();
        return status;
    }
    // SAFETY: at PASSIVE_LEVEL, once, with the device just created.
    let mut status = unsafe { wfp::register(device::get()) };
    if status == sys::STATUS_SUCCESS {
        // SAFETY: at PASSIVE_LEVEL, once, with the driver object.
        status = unsafe { inject::init(driver) };
    }
    if status != sys::STATUS_SUCCESS {
        wdk::println!("avulse: WFP registration failed: {status:#x}");
        // SAFETY: as above; nothing uses the device yet.
        unsafe {
            wfp::unregister();
            inject::free();
            device::delete();
        }
        eval::free();
        return status;
    }
    // SAFETY: at PASSIVE_LEVEL, once, with the driver object. Without the INF's install there is
    // no filter to register: the ETHERNET layer is then unavailable, and the rest works.
    let status = unsafe { lwf::register(driver) };
    if status != sys::NDIS_STATUS_SUCCESS {
        wdk::println!("avulse: no lightweight filter ({status:#x}): no ETHERNET layer");
    }
    // SAFETY: `driver` is valid for the whole call.
    unsafe { (*driver).DriverUnload = Some(unload) };
    wdk::println!("avulse: loaded");
    sys::STATUS_SUCCESS
}

/// Removes the device, then frees the scratch. The I/O manager only unloads a driver whose files
/// are all closed.
unsafe extern "C" fn unload(_driver: *mut sys::DRIVER_OBJECT) {
    // SAFETY: at PASSIVE_LEVEL, after `driver_entry` succeeded; no file is open. The filter's
    // modules detach first, so no frame reaches the scratch once it is freed.
    unsafe {
        lwf::unregister();
        wfp::unregister();
        reflect::free();
        inject::free();
        device::delete();
    }
    eval::free();
    wdk::println!(
        "avulse: unloaded; least stack {} B, expanded {}, expansion failed {}",
        eval::MIN_STACK.load(core::sync::atomic::Ordering::Relaxed),
        eval::EXPANDED.load(core::sync::atomic::Ordering::Relaxed),
        eval::EXPAND_FAILED.load(core::sync::atomic::Ordering::Relaxed),
    );
}
