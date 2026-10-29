//! The receive side of a handle: the queue of packets or events waiting for user mode, and the
//! `RECV` requests waiting for them (the inverted-call model).
//!
//! A `RECV` completes at once with what is queued, as many records as fit its buffer, or waits.
//! A waiting request has a cancel routine, so user mode can give up on it (`CancelIoEx`, which is
//! how timeouts work). Once the handle is shut down for receiving and its queue is empty, requests
//! end with `STATUS_PIPE_EMPTY` (`ERROR_NO_DATA` in user mode); cleanup cancels them all.

use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering};

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use avulse_abi::Address;
use avulse_abi::ioctl::{self, Record};
use avulse_abi::windivert::WdAddress;

use crate::handle::File;
use crate::lock::SpinLock;
use crate::sys;

/// A packet or event waiting for user mode.
pub struct Entry {
    pub addr: Address,
    pub data: Vec<u8>,
    /// What a [`ioctl::WD_RECV`] returns in place of `data`, if it differs: WinDivert's filter
    /// object in a REFLECT event.
    pub windivert: Option<Arc<[u8]>>,
}

impl Entry {
    /// The data as WinDivert's receive returns it.
    fn windivert_data(&self) -> &[u8] {
        self.windivert.as_deref().unwrap_or(&self.data)
    }
}

#[derive(Default)]
pub struct Rx {
    /// The waiting `RECV` requests, oldest first (as `usize`, for `Send`).
    pending: VecDeque<usize>,
    packets: VecDeque<Entry>,
    /// Bytes of data queued, for the `QUEUE_SIZE` parameter.
    pub bytes: usize,
    /// Shut down for receiving: requests end once the queue is empty.
    pub shut: bool,
}

/// What to do with an IRP once the lock is released.
enum Done {
    Complete(*mut sys::IRP, sys::NTSTATUS, usize),
    Pending,
}

/// `IoSetCancelRoutine`, a macro: swaps the IRP's cancel routine and returns the previous one.
///
/// # Safety
///
/// `irp` is a valid IRP.
unsafe fn set_cancel_routine(
    irp: *mut sys::IRP,
    routine: sys::PDRIVER_CANCEL,
) -> sys::PDRIVER_CANCEL {
    // SAFETY: `CancelRoutine` is a pointer-sized field that the I/O manager also swaps
    // atomically; `Option<fn>` has the pointer's layout.
    unsafe {
        let field = (&raw mut (*irp).CancelRoutine).cast::<AtomicPtr<c_void>>();
        let new = core::mem::transmute::<sys::PDRIVER_CANCEL, *mut c_void>(routine);
        let old = (*field).swap(new, Ordering::AcqRel);
        core::mem::transmute::<*mut c_void, sys::PDRIVER_CANCEL>(old)
    }
}

/// The output buffer of a `METHOD_OUT_DIRECT` request, mapped into system space.
///
/// # Safety
///
/// `irp` is a valid IRP of a `METHOD_OUT_DIRECT` request.
unsafe fn output(irp: *mut sys::IRP, len: usize) -> Option<&'static mut [u8]> {
    // SAFETY: the I/O manager built the MDL for the request's output buffer.
    unsafe { mapped((*irp).MdlAddress, len) }
}

/// The `len` bytes an MDL describes, mapped into system space (`MmGetSystemAddressForMdlSafe`,
/// an inline function).
///
/// # Safety
///
/// `mdl` is NULL or an MDL of locked pages, for at least `len` bytes.
pub unsafe fn mapped(mdl: *mut sys::MDL, len: usize) -> Option<&'static mut [u8]> {
    // SAFETY: the caller's contract.
    unsafe {
        if mdl.is_null() || len == 0 {
            return None;
        }
        // MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL.
        let va = if (*mdl).MdlFlags as u16 & (0x0001 | 0x0004) != 0 {
            (*mdl).MappedSystemVa
        } else {
            // KernelMode, MmCached, NormalPagePriority | MdlMappingNoExecute.
            sys::MmMapLockedPagesSpecifyCache(mdl, 0, 1, null_mut(), 0, 16 | 0x4000_0000)
        };
        if va.is_null() {
            return None;
        }
        Some(core::slice::from_raw_parts_mut(va.cast::<u8>(), len))
    }
}

/// The length of the output buffer of `irp`'s request.
///
/// # Safety
///
/// `irp` is a valid device control IRP.
unsafe fn output_len(irp: *mut sys::IRP) -> usize {
    // SAFETY: as above.
    unsafe {
        let sl = sys::current_stack_location(irp);
        (*sl).Parameters.DeviceIoControl.OutputBufferLength as usize
    }
}

/// Answers `irp` with what is queued, at least one record: as avulse's records, or as
/// WinDivert's packets and addresses. With nothing queued, the IRP waits (`None`).
///
/// # Safety
///
/// `irp` is a valid `RECV` or `WD_RECV` IRP; a `WD_RECV` one has the MDLs `wd_recv` chained.
unsafe fn fill(rx: &mut Rx, irp: *mut sys::IRP) -> Option<(sys::NTSTATUS, usize)> {
    // SAFETY: the caller's contract.
    let code = unsafe {
        (*sys::current_stack_location(irp))
            .Parameters
            .DeviceIoControl
            .IoControlCode
    };
    if code == ioctl::WD_RECV {
        // SAFETY: as above.
        return unsafe { fill_windivert(rx, irp) };
    }
    let first = rx.packets.front()?;
    // SAFETY: the caller's contract.
    let len = unsafe { output_len(irp) };
    if Record::encoded_len(first.data.len()) > len {
        // Too small for the first record: it is dropped, as WinDivert does.
        let e = rx.packets.pop_front()?;
        rx.bytes -= e.data.len();
        return Some((sys::STATUS_BUFFER_TOO_SMALL, 0));
    }
    // SAFETY: the caller's contract.
    let Some(out) = (unsafe { output(irp, len) }) else {
        return Some((sys::STATUS_INSUFFICIENT_RESOURCES, 0));
    };
    let mut buf = Vec::new();
    while let Some(e) = rx.packets.front() {
        if buf.len() + Record::encoded_len(e.data.len()) > len {
            break;
        }
        Record {
            addr: e.addr,
            data: &e.data,
        }
        .encode_into(&mut buf);
        let e = rx.packets.pop_front()?;
        rx.bytes -= e.data.len();
    }
    out[..buf.len()].copy_from_slice(&buf);
    Some((sys::STATUS_SUCCESS, buf.len()))
}

/// Answers a `WD_RECV` IRP as WinDivert's driver does: packets back to back in the output
/// buffer, at most as many as the caller has room for addresses, the addresses in the caller's
/// buffer (the MDL after the output's), and their length in bytes in the caller's `UINT` (the
/// MDL after that one, if any).
///
/// # Safety
///
/// As [`fill`].
unsafe fn fill_windivert(rx: &mut Rx, irp: *mut sys::IRP) -> Option<(sys::NTSTATUS, usize)> {
    let first = rx.packets.front()?;
    // SAFETY: the caller's contract: the output MDL, then the addresses', then maybe the
    // length's, all locked.
    let (len, addrs_mdl, len_mdl) = unsafe {
        let out = (*irp).MdlAddress;
        let addrs = if out.is_null() {
            null_mut()
        } else {
            (*out).Next
        };
        let len_mdl = if addrs.is_null() {
            null_mut()
        } else {
            (*addrs).Next
        };
        (output_len(irp), addrs, len_mdl)
    };
    if first.windivert_data().len() > len {
        let e = rx.packets.pop_front()?;
        rx.bytes -= e.data.len();
        return Some((sys::STATUS_BUFFER_TOO_SMALL, 0));
    }
    // SAFETY: as above; the addresses' MDL holds `ByteCount` bytes, a multiple of 80.
    let (out, addrs, addr_len) = unsafe {
        let count = if addrs_mdl.is_null() {
            0
        } else {
            (*addrs_mdl).ByteCount as usize / 80
        };
        (
            output(irp, len),
            mapped(addrs_mdl, count * 80),
            mapped(len_mdl, 4),
        )
    };
    let (Some(out), Some(addrs)) = (out, addrs) else {
        return Some((sys::STATUS_INSUFFICIENT_RESOURCES, 0));
    };
    let (mut n, mut i) = (0, 0);
    while let Some(e) = rx.packets.front() {
        let data = e.windivert_data();
        if i == addrs.len() / 80 || n + data.len() > len {
            break;
        }
        out[n..n + data.len()].copy_from_slice(data);
        addrs[80 * i..80 * (i + 1)].copy_from_slice(&WdAddress::from_avulse(&e.addr).to_bytes());
        n += data.len();
        i += 1;
        let e = rx.packets.pop_front()?;
        rx.bytes -= e.data.len();
    }
    if let Some(l) = addr_len {
        l.copy_from_slice(&((80 * i) as u32).to_le_bytes());
    }
    Some((sys::STATUS_SUCCESS, n))
}

/// Locks the caller's buffers of a `WD_RECV` request, `req`, and chains their MDLs after the
/// output's, where `fill_windivert` finds them and the I/O manager unlocks and frees them when
/// the IRP completes. Then receives as [`recv`] does.
///
/// # Safety
///
/// `irp` is a valid `WD_RECV` IRP for `file`, owned by the driver, in the caller's context.
pub unsafe fn wd_recv(
    cell: &SpinLock<Rx>,
    irp: *mut sys::IRP,
    req: &ioctl::WdRecvRequest,
) -> sys::NTSTATUS {
    // SAFETY: the caller's contract.
    unsafe {
        let mode = (*irp).RequestorMode;
        let mut last = (*irp).MdlAddress;
        if last.is_null() {
            return sys::complete(irp, sys::STATUS_INVALID_PARAMETER, 0);
        }
        let Some(bytes) = (req.count as usize)
            .checked_mul(80)
            .filter(|&b| b <= u32::MAX as usize)
        else {
            return sys::complete(irp, sys::STATUS_INVALID_PARAMETER, 0);
        };
        let buffers = [(req.addrs, bytes as u32), (req.addr_len, 4)];
        for (va, len) in buffers {
            if va == 0 {
                continue;
            }
            let mdl = sys::IoAllocateMdl(va as *mut c_void, len, 0, 0, null_mut());
            if mdl.is_null() {
                return sys::complete(irp, sys::STATUS_INSUFFICIENT_RESOURCES, 0);
            }
            // IoWriteAccess.
            let status = sys::avulse_probe_and_lock(mdl, mode, 1);
            if status != sys::STATUS_SUCCESS {
                sys::IoFreeMdl(mdl);
                return sys::complete(irp, status, 0);
            }
            (*last).Next = mdl;
            last = mdl;
        }
        recv(cell, irp)
    }
}

/// A new `RECV` request on `file`: completed now, or left waiting. Returns its status.
///
/// # Safety
///
/// `irp` is a valid `RECV` IRP for `file`, owned by the driver.
pub unsafe fn recv(cell: &SpinLock<Rx>, irp: *mut sys::IRP) -> sys::NTSTATUS {
    let done = {
        let mut rx = cell.lock();
        // SAFETY: the caller's contract.
        match unsafe { fill(&mut rx, irp) } {
            Some((status, n)) => Done::Complete(irp, status, n),
            None if rx.shut => Done::Complete(irp, sys::STATUS_PIPE_EMPTY, 0),
            // No room to list it as waiting.
            None if rx.pending.try_reserve(1).is_err() => {
                Done::Complete(irp, sys::STATUS_INSUFFICIENT_RESOURCES, 0)
            }
            None => {
                // SAFETY: the IRP is ours; the cancel routine takes the same lock.
                unsafe {
                    set_cancel_routine(irp, Some(cancel));
                    if (*irp).Cancel != 0 && set_cancel_routine(irp, None).is_some() {
                        Done::Complete(irp, sys::STATUS_CANCELLED, 0)
                    } else {
                        // IoMarkIrpPending: SL_PENDING_RETURNED.
                        (*sys::current_stack_location(irp)).Control |= 0x01;
                        rx.pending.push_back(irp as usize);
                        Done::Pending
                    }
                }
            }
        }
    };
    match done {
        // SAFETY: the IRP is ours.
        Done::Complete(irp, status, n) => unsafe { sys::complete(irp, status, n) },
        Done::Pending => sys::STATUS_PENDING,
    }
}

/// Takes a waiting IRP off the list, unless its cancel routine already owns it.
fn take_pending(rx: &mut Rx) -> Option<*mut sys::IRP> {
    while let Some(irp) = rx.pending.pop_front() {
        let irp = irp as *mut sys::IRP;
        // SAFETY: a waiting IRP; clearing its cancel routine makes it ours, unless the routine is
        // already running, in which case it completes the IRP (and finds it gone from the list).
        if unsafe { set_cancel_routine(irp, None) }.is_some() {
            return Some(irp);
        }
    }
    None
}

/// Completes the waiting requests that can complete now: with records while some are queued,
/// then, if the handle is shut down, with `STATUS_PIPE_EMPTY`. At IRQL <= DISPATCH_LEVEL.
pub fn wake(cell: &SpinLock<Rx>) {
    let mut done = Vec::new();
    {
        let mut rx = cell.lock();
        while !rx.packets.is_empty() || rx.shut {
            let Some(irp) = take_pending(&mut rx) else {
                break;
            };
            // SAFETY: a waiting RECV IRP, now ours.
            match unsafe { fill(&mut rx, irp) } {
                Some((status, n)) => done.push((irp, status, n)),
                None => done.push((irp, sys::STATUS_PIPE_EMPTY, 0)),
            }
        }
    }
    for (irp, status, n) in done {
        // SAFETY: the IRPs are ours.
        unsafe { sys::complete(irp, status, n) };
    }
}

/// Cancels every waiting request: the file is being cleaned up.
pub fn cancel_all(cell: &SpinLock<Rx>) {
    let mut done = Vec::new();
    {
        let mut rx = cell.lock();
        while let Some(irp) = take_pending(&mut rx) {
            done.push(irp);
        }
        rx.packets.clear();
        rx.bytes = 0;
        rx.shut = true;
    }
    for irp in done {
        // SAFETY: the IRPs are ours.
        unsafe { sys::complete(irp, sys::STATUS_CANCELLED, 0) };
    }
}

/// The cancel routine of waiting `RECV` requests.
unsafe extern "C" fn cancel(_device: *mut sys::DEVICE_OBJECT, irp: *mut sys::IRP) {
    // SAFETY: the I/O manager calls it holding the cancel spin lock, with a valid IRP whose file
    // object is ours and alive (the IRP holds a reference to it).
    unsafe {
        sys::IoReleaseCancelSpinLock((*irp).CancelIrql);
        let fo = (*sys::current_stack_location(irp)).FileObject;
        if let Some(file) = (*fo).FsContext.cast::<File>().as_ref() {
            file.rx.lock().pending.retain(|&p| p != irp as usize);
        }
        sys::complete(irp, sys::STATUS_CANCELLED, 0);
    }
}

/// Queues `e` within the queue parameters, and completes a waiting request. Returns false if the
/// queue is full or shut down (the entry is dropped).
pub fn push(cell: &SpinLock<Rx>, e: Entry, max_len: usize, max_bytes: usize) -> bool {
    {
        let mut rx = cell.lock();
        if rx.shut
            || rx.packets.len() >= max_len
            || rx.bytes + e.data.len() > max_bytes
            || rx.packets.try_reserve(1).is_err()
        {
            return false;
        }
        rx.bytes += e.data.len();
        rx.packets.push_back(e);
    }
    wake(cell);
    true
}
