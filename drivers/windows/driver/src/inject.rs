//! Sending packets: what `SEND` does. A packet goes out (`FwpsInjectNetworkSendAsync0`), in
//! (`FwpsInjectNetworkReceiveAsync0`, on the address's interfaces) or forward
//! (`FwpsInjectForwardAsync0`), from a copy in a NET_BUFFER_LIST that the completion frees.
//!
//! Every packet goes through the injection handle of its family, with the sending handle's priority as its
//! injection context. The hooks query it (`FwpsQueryPacketInjectionState0`): handles of the same
//! or a higher priority than the sender pass the packet by (they saw it first, or sent it), so a
//! handle never sees its own packets again; lower priorities see it as an impostor.

use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering};

use alloc::boxed::Box;
use avulse_abi::Address;
use avulse_filter::Layer;

use crate::sys;

/// The injection handles, IPv4 then IPv6: forward injection needs a family.
static INJECTION: [AtomicPtr<c_void>; 2] = [const { AtomicPtr::new(null_mut()) }; 2];
static GENERIC: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static POOL: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

/// A pool tag, `avlS`.
const TAG: u32 = u32::from_le_bytes(*b"avlS");

/// Creates the injection handle and the NET_BUFFER_LIST pool.
///
/// # Safety
///
/// At PASSIVE_LEVEL, once, from `DriverEntry`.
pub unsafe fn init(driver: *mut sys::DRIVER_OBJECT) -> sys::NTSTATUS {
    for (slot, family) in INJECTION.iter().zip([sys::AF_INET, sys::AF_INET6]) {
        let mut h = null_mut();
        // SAFETY: plain call with an out-parameter.
        let status = unsafe {
            sys::FwpsInjectionHandleCreate0(
                family as _,
                sys::FWPS_INJECTION_TYPE_NETWORK | sys::FWPS_INJECTION_TYPE_FORWARD,
                &mut h,
            )
        };
        if status != sys::STATUS_SUCCESS {
            return status;
        }
        slot.store(h, Ordering::Release);
    }
    // SAFETY: the driver object, valid in `DriverEntry`.
    let generic = unsafe { sys::NdisAllocateGenericObject(driver, TAG, 0) };
    if generic.is_null() {
        return sys::STATUS_INSUFFICIENT_RESOURCES;
    }
    GENERIC.store(generic.cast(), Ordering::Release);
    // SAFETY: all zeros, then the header and fields NDIS reads.
    let mut params: sys::NET_BUFFER_LIST_POOL_PARAMETERS = unsafe { core::mem::zeroed() };
    params.Header.Type = sys::NDIS_OBJECT_TYPE_DEFAULT as u8;
    params.Header.Revision = sys::NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1 as u8;
    params.Header.Size = core::mem::size_of::<sys::NET_BUFFER_LIST_POOL_PARAMETERS>() as u16;
    params.fAllocateNetBuffer = 1;
    params.PoolTag = TAG;
    // SAFETY: a valid generic object and parameters.
    let pool = unsafe { sys::NdisAllocateNetBufferListPool(generic.cast(), &params) };
    if pool.is_null() {
        return sys::STATUS_INSUFFICIENT_RESOURCES;
    }
    POOL.store(pool, Ordering::Release);
    sys::STATUS_SUCCESS
}

/// Frees what `init` made. At unload, after every injection completed (the I/O manager unloads
/// the driver only when its files are closed, and `close` waits for nothing: injections hold no
/// file; NDIS waits for the pool's lists to come back).
///
/// # Safety
///
/// At PASSIVE_LEVEL, at unload.
pub unsafe fn free() {
    let pool = POOL.swap(null_mut(), Ordering::AcqRel);
    if !pool.is_null() {
        // SAFETY: the pool `init` allocated.
        unsafe { sys::NdisFreeNetBufferListPool(pool) };
    }
    let generic = GENERIC.swap(null_mut(), Ordering::AcqRel);
    if !generic.is_null() {
        // SAFETY: the object `init` allocated.
        unsafe { sys::NdisFreeGenericObject(generic.cast()) };
    }
    for slot in &INJECTION {
        let h = slot.swap(null_mut(), Ordering::AcqRel);
        if !h.is_null() {
            // SAFETY: a handle `init` created.
            let _ = unsafe { sys::FwpsInjectionHandleDestroy0(h) };
        }
    }
}

/// The injection context of a packet a handle of `priority` sends: never null.
fn context(priority: i16) -> sys::HANDLE {
    (i32::from(priority) + 30_001) as usize as sys::HANDLE
}

/// Whether the packet in `nbl` (IPv6 if `v6`) was sent by a handle of this driver, and if so at
/// which priority.
///
/// # Safety
///
/// `nbl` is a valid NET_BUFFER_LIST, at IRQL <= DISPATCH_LEVEL.
pub unsafe fn sender(nbl: *mut sys::NET_BUFFER_LIST, v6: bool) -> Option<i16> {
    let h = INJECTION[usize::from(v6)].load(Ordering::Acquire);
    if h.is_null() {
        return None;
    }
    let mut ctx: sys::HANDLE = null_mut();
    // SAFETY: the caller's contract.
    let state = unsafe { sys::FwpsQueryPacketInjectionState0(h, nbl, &mut ctx) };
    match state {
        sys::FWPS_PACKET_INJECTION_STATE_::FWPS_PACKET_INJECTED_BY_SELF
        | sys::FWPS_PACKET_INJECTION_STATE_::FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF => {
            Some((ctx as usize as i32 - 30_001) as i16)
        }
        _ => None,
    }
}

/// What the completion frees.
struct Sent {
    data: Box<[u8]>,
    mdl: *mut sys::MDL,
}

unsafe extern "C" fn completed(
    context: *mut c_void,
    nbl: *mut sys::NET_BUFFER_LIST,
    _dispatch: u8,
) {
    // SAFETY: the `Sent` `send` leaked for this NBL, which the injection is done with.
    unsafe {
        sys::FwpsFreeNetBufferList0(nbl);
        let sent = Box::from_raw(context.cast::<Sent>());
        sys::IoFreeMdl(sent.mdl);
        drop(sent.data);
    }
}

/// Sends `packet` (from the IP header) where `addr` says, for a handle of `priority` at `layer`.
pub fn send(packet: &[u8], addr: &Address, layer: Layer, priority: i16) -> sys::NTSTATUS {
    let v6 = match packet.first().map(|b| b >> 4) {
        Some(4) => false,
        Some(6) => true,
        _ => return sys::STATUS_INVALID_PARAMETER,
    };
    let h = INJECTION[usize::from(v6)].load(Ordering::Acquire);
    let pool = POOL.load(Ordering::Acquire);
    if h.is_null() || pool.is_null() {
        return sys::STATUS_INVALID_DEVICE_STATE;
    }
    let Some(data) = sys::try_box(packet) else {
        return sys::STATUS_INSUFFICIENT_RESOURCES;
    };
    let len = data.len() as u32;
    // SAFETY: a nonpaged buffer of `len` bytes, which lives until the completion.
    let mdl = unsafe { sys::IoAllocateMdl(data.as_ptr().cast_mut().cast(), len, 0, 0, null_mut()) };
    if mdl.is_null() {
        return sys::STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: the MDL describes nonpaged memory.
    unsafe { sys::MmBuildMdlForNonPagedPool(mdl) };
    let mut nbl = null_mut();
    // SAFETY: a valid pool and MDL.
    let status = unsafe {
        sys::FwpsAllocateNetBufferAndNetBufferList0(pool, 0, 0, mdl, 0, len as _, &mut nbl)
    };
    if status != sys::STATUS_SUCCESS {
        // SAFETY: allocated above, unused.
        unsafe { sys::IoFreeMdl(mdl) };
        return status;
    }
    let Some(sent) = sys::try_new(Sent { data, mdl }) else {
        // SAFETY: allocated above, unused.
        unsafe {
            sys::FwpsFreeNetBufferList0(nbl);
            sys::IoFreeMdl(mdl);
        }
        return sys::STATUS_INSUFFICIENT_RESOURCES;
    };
    let sent = Box::into_raw(sent);
    let ctx = context(priority);
    // UNSPECIFIED_COMPARTMENT_ID: the default compartment.
    let compartment = 0;
    // SAFETY: valid handle and NBL; the completion frees them, and is called whatever happens
    // once the call succeeds.
    let status = unsafe {
        if layer == Layer::NetworkForward {
            sys::FwpsInjectForwardAsync0(
                h,
                ctx,
                0,
                if v6 { sys::AF_INET6 } else { sys::AF_INET } as _,
                compartment,
                addr.if_idx,
                nbl,
                Some(completed),
                sent.cast(),
            )
        } else if addr.outbound {
            sys::FwpsInjectNetworkSendAsync0(
                h,
                ctx,
                0,
                compartment,
                nbl,
                Some(completed),
                sent.cast(),
            )
        } else {
            sys::FwpsInjectNetworkReceiveAsync0(
                h,
                ctx,
                0,
                compartment,
                addr.if_idx,
                addr.sub_if_idx,
                nbl,
                Some(completed),
                sent.cast(),
            )
        }
    };
    if status != sys::STATUS_SUCCESS {
        // The completion will not run: free here.
        // SAFETY: as in `completed`.
        unsafe { completed(sent.cast(), nbl, 0) };
    }
    status
}
