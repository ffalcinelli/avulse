//! The NDIS side: a modifying lightweight filter on Ethernet adapters that passes every frame
//! through and runs the programs on each.

use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering};

use alloc::boxed::Box;
use avulse_filter::{Layer, Meta};
use avulse_proto::Link;

use crate::stats::{self, Counter};
use crate::{programs, sys, unicode, w};

static DRIVER_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

/// One filter module: the filter on one adapter.
struct Module {
    handle: sys::NDIS_HANDLE,
}

/// Registers the filter driver. The `UniqueName` and `ServiceName` must match the INF.
///
/// # Safety
///
/// At PASSIVE_LEVEL, once, with the driver object.
pub(crate) unsafe fn register(driver: *mut sys::DRIVER_OBJECT) -> sys::NDIS_STATUS {
    let mut chars = sys::NDIS_FILTER_DRIVER_CHARACTERISTICS::default();
    chars.Header.Type = sys::NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS as u8;
    chars.Header.Revision = sys::NDIS_FILTER_CHARACTERISTICS_REVISION_2 as u8;
    chars.Header.Size = (core::mem::offset_of!(
        sys::NDIS_FILTER_DRIVER_CHARACTERISTICS,
        CancelDirectOidRequestHandler
    ) + size_of::<sys::FILTER_CANCEL_DIRECT_OID_REQUEST_HANDLER>()) as u16;
    chars.MajorNdisVersion = 6;
    chars.MinorNdisVersion = 30;
    chars.MajorDriverVersion = 0;
    chars.MinorDriverVersion = 1;
    chars.FriendlyName = unicode(w!("Avulse spike filter"));
    chars.UniqueName = unicode(w!("{6a3f8b2e-9d41-4c07-b5e2-7f18c0d94a63}"));
    chars.ServiceName = unicode(w!("avulse_spike"));
    chars.AttachHandler = Some(attach);
    chars.DetachHandler = Some(detach);
    chars.RestartHandler = Some(restart);
    chars.PauseHandler = Some(pause);
    chars.SendNetBufferListsHandler = Some(send);
    chars.SendNetBufferListsCompleteHandler = Some(send_complete);
    chars.ReceiveNetBufferListsHandler = Some(receive);
    chars.ReturnNetBufferListsHandler = Some(return_nbls);
    let mut handle = null_mut();
    // SAFETY: valid driver object and characteristics.
    let status =
        unsafe { sys::NdisFRegisterFilterDriver(driver, driver.cast(), &mut chars, &mut handle) };
    if status == sys::NDIS_STATUS_SUCCESS {
        DRIVER_HANDLE.store(handle, Ordering::Release);
    }
    status
}

/// Detaches every module and deregisters the filter driver.
///
/// # Safety
///
/// At PASSIVE_LEVEL, once.
pub(crate) unsafe fn unregister() {
    let handle = DRIVER_HANDLE.swap(null_mut(), Ordering::AcqRel);
    if !handle.is_null() {
        // SAFETY: registered by `register`; this waits for every module to detach.
        unsafe { sys::NdisFDeregisterFilterDriver(handle) };
    }
}

unsafe extern "C" fn attach(
    filter_handle: sys::NDIS_HANDLE,
    _driver_context: sys::NDIS_HANDLE,
    _params: sys::PNDIS_FILTER_ATTACH_PARAMETERS,
) -> sys::NDIS_STATUS {
    let module = Box::into_raw(Box::new(Module {
        handle: filter_handle,
    }));
    let mut attrs = sys::NDIS_FILTER_ATTRIBUTES::default();
    attrs.Header.Type = sys::NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES as u8;
    attrs.Header.Revision = sys::NDIS_FILTER_ATTRIBUTES_REVISION_1 as u8;
    attrs.Header.Size = size_of::<sys::NDIS_FILTER_ATTRIBUTES>() as u16;
    // SAFETY: called during attach, with NDIS's handle.
    let status = unsafe { sys::NdisFSetAttributes(filter_handle, module.cast(), &mut attrs) };
    if status != sys::NDIS_STATUS_SUCCESS {
        // SAFETY: from `Box::into_raw` above, not shared.
        drop(unsafe { Box::from_raw(module) });
        return status;
    }
    stats::add(Counter::LwfAttached, 1);
    sys::NDIS_STATUS_SUCCESS
}

unsafe extern "C" fn detach(module: sys::NDIS_HANDLE) {
    // SAFETY: the context set in `attach`; NDIS calls nothing else on this module after detach.
    drop(unsafe { Box::from_raw(module.cast::<Module>()) });
}

unsafe extern "C" fn restart(
    _module: sys::NDIS_HANDLE,
    _params: sys::PNDIS_FILTER_RESTART_PARAMETERS,
) -> sys::NDIS_STATUS {
    sys::NDIS_STATUS_SUCCESS
}

unsafe extern "C" fn pause(
    _module: sys::NDIS_HANDLE,
    _params: sys::PNDIS_FILTER_PAUSE_PARAMETERS,
) -> sys::NDIS_STATUS {
    // The filter originates no sends and holds no receives, so nothing is outstanding.
    sys::NDIS_STATUS_SUCCESS
}

/// Runs the programs on the first NET_BUFFER of each NET_BUFFER_LIST of the chain.
unsafe fn inspect(mut nbl: *mut sys::NET_BUFFER_LIST, outbound: bool) {
    let Some(p) = programs() else { return };
    let meta = Meta {
        layer: Layer::Ethernet,
        outbound,
        ..Meta::default()
    };
    while !nbl.is_null() {
        stats::add(
            if outbound {
                Counter::LwfSent
            } else {
                Counter::LwfReceived
            },
            1,
        );
        // SAFETY: NDIS passes a valid chain.
        let nb = unsafe { sys::nbl_first_nb(nbl) };
        for (program, counter) in [(&p.lwf, Counter::LwfMatched), (&p.ping, Counter::LwfPing)] {
            // SAFETY: `nb` is valid, at DISPATCH_LEVEL or below.
            if !nb.is_null()
                && unsafe { stats::evaluate(program, nb, Link::Ethernet, &meta) } == Some(true)
            {
                stats::add(counter, 1);
            }
        }
        // SAFETY: as above.
        nbl = unsafe { sys::nbl_next(nbl) };
    }
}

fn handle(module: sys::NDIS_HANDLE) -> sys::NDIS_HANDLE {
    // SAFETY: the context set in `attach`, alive until `detach`.
    unsafe { (*module.cast::<Module>()).handle }
}

unsafe extern "C" fn send(
    module: sys::NDIS_HANDLE,
    nbls: *mut sys::NET_BUFFER_LIST,
    port: sys::NDIS_PORT_NUMBER,
    flags: u32,
) {
    // SAFETY: NDIS passes a valid chain.
    unsafe {
        inspect(nbls, true);
        sys::NdisFSendNetBufferLists(handle(module), nbls, port, flags);
    }
}

unsafe extern "C" fn send_complete(
    module: sys::NDIS_HANDLE,
    nbls: *mut sys::NET_BUFFER_LIST,
    flags: u32,
) {
    // SAFETY: completes the sends `send` passed down.
    unsafe { sys::NdisFSendNetBufferListsComplete(handle(module), nbls, flags) };
}

unsafe extern "C" fn receive(
    module: sys::NDIS_HANDLE,
    nbls: *mut sys::NET_BUFFER_LIST,
    port: sys::NDIS_PORT_NUMBER,
    count: u32,
    flags: u32,
) {
    // SAFETY: NDIS passes a valid chain.
    unsafe {
        inspect(nbls, false);
        sys::NdisFIndicateReceiveNetBufferLists(handle(module), nbls, port, count, flags);
    }
}

unsafe extern "C" fn return_nbls(
    module: sys::NDIS_HANDLE,
    nbls: *mut sys::NET_BUFFER_LIST,
    flags: u32,
) {
    // SAFETY: returns the receives `receive` indicated up.
    unsafe { sys::NdisFReturnNetBufferLists(handle(module), nbls, flags) };
}
