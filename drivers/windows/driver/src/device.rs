//! The control device, `\\.\Avulse`, and its dispatch routines. Only Administrators and the
//! system may open it (its security descriptor). A handle is a file object: `IRP_MJ_CREATE` makes
//! it, [`ioctl::OPEN`] opens it, `IRP_MJ_CLEANUP` closes it (also when the process exits), and
//! `IRP_MJ_CLOSE` frees it.

use core::ptr::{null, null_mut};
use core::slice;
use core::sync::atomic::{AtomicPtr, Ordering};

use alloc::boxed::Box;
use avulse_abi::ioctl::{self, Record};
use avulse_abi::{Param, Shutdown};
use avulse_filter::Layer;
use avulse_proto::Link;

use crate::handle::{self, File};
use crate::sys::{self, unicode, w};
use crate::{eval, inject, lwf, rx};

static DEVICE: AtomicPtr<sys::DEVICE_OBJECT> = AtomicPtr::new(null_mut());

fn device_name() -> sys::UNICODE_STRING {
    unicode(w!("\\Device\\Avulse"))
}

fn link_name() -> sys::UNICODE_STRING {
    unicode(w!("\\DosDevices\\Avulse"))
}

/// Creates the device and its link, and sets the dispatch routines.
///
/// # Safety
///
/// At PASSIVE_LEVEL, once, from `DriverEntry`, with the driver object.
pub unsafe fn create(driver: *mut sys::DRIVER_OBJECT) -> sys::NTSTATUS {
    let mut name = device_name();
    // SDDL_DEVOBJ_SYS_ALL_ADM_ALL: the system and Administrators only. (`IoCreateDeviceSecure` is a
    // macro for `WdmlibIoCreateDeviceSecure`.)
    let sddl = unicode(w!("D:P(A;;GA;;;SY)(A;;GA;;;BA)"));
    let mut device = null_mut();
    // SAFETY: the arguments are valid for the call.
    let status = unsafe {
        sys::WdmlibIoCreateDeviceSecure(
            driver,
            0,
            &mut name,
            sys::FILE_DEVICE_NETWORK,
            sys::FILE_DEVICE_SECURE_OPEN,
            0,
            &sddl,
            null(),
            &mut device,
        )
    };
    if status != sys::STATUS_SUCCESS {
        return status;
    }
    let (mut link, mut target) = (link_name(), device_name());
    // SAFETY: valid strings.
    let status = unsafe { sys::IoCreateSymbolicLink(&mut link, &mut target) };
    if status != sys::STATUS_SUCCESS {
        // SAFETY: created above, unused.
        unsafe { sys::IoDeleteDevice(device) };
        return status;
    }
    DEVICE.store(device, Ordering::Release);
    // SAFETY: `driver` is valid during `DriverEntry`.
    let major = unsafe { &mut (*driver).MajorFunction };
    for f in [
        sys::IRP_MJ_CREATE,
        sys::IRP_MJ_CLEANUP,
        sys::IRP_MJ_CLOSE,
        sys::IRP_MJ_DEVICE_CONTROL,
    ] {
        major[f as usize] = Some(dispatch);
    }
    sys::STATUS_SUCCESS
}

/// The device, for the WFP callouts.
pub fn get() -> *mut sys::DEVICE_OBJECT {
    DEVICE.load(Ordering::Acquire)
}

/// Deletes the link and the device.
///
/// # Safety
///
/// At PASSIVE_LEVEL, at unload, after `create` succeeded.
pub unsafe fn delete() {
    let device = DEVICE.swap(null_mut(), Ordering::AcqRel);
    if device.is_null() {
        return;
    }
    let mut link = link_name();
    // SAFETY: the link and device `create` made.
    unsafe {
        let _ = sys::IoDeleteSymbolicLink(&mut link);
        sys::IoDeleteDevice(device);
    }
}

/// Every major function the device handles.
unsafe extern "C" fn dispatch(
    _device: *mut sys::DEVICE_OBJECT,
    irp: *mut sys::IRP,
) -> sys::NTSTATUS {
    // SAFETY: the I/O manager passes a valid IRP, with a current stack location and file object.
    let (sl, fo) = unsafe {
        let sl = sys::current_stack_location(irp);
        (sl, (*sl).FileObject)
    };
    // SAFETY: as above.
    let major = u32::from(unsafe { (*sl).MajorFunction });
    match major {
        sys::IRP_MJ_CREATE => {
            let file = Box::new(File::new());
            // SAFETY: the file object is ours until IRP_MJ_CLOSE.
            unsafe { (*fo).FsContext = Box::into_raw(file).cast() };
            // SAFETY: the IRP is ours.
            unsafe { sys::complete(irp, sys::STATUS_SUCCESS, 0) }
        }
        sys::IRP_MJ_CLEANUP => {
            // SAFETY: set at IRP_MJ_CREATE, freed at IRP_MJ_CLOSE, which comes after.
            if let Some(file) = unsafe { (*fo).FsContext.cast::<File>().as_ref() } {
                // The program goes with the last reference to the handle.
                // SAFETY: at PASSIVE_LEVEL, in the dispatch routine.
                unsafe { handle::close(file) };
                rx::cancel_all(&file.rx);
            }
            // SAFETY: the IRP is ours.
            unsafe { sys::complete(irp, sys::STATUS_SUCCESS, 0) }
        }
        sys::IRP_MJ_CLOSE => {
            // SAFETY: set at IRP_MJ_CREATE; nothing uses the file any more.
            let file = unsafe { (*fo).FsContext.cast::<File>() };
            if !file.is_null() {
                // SAFETY: from `Box::into_raw` at IRP_MJ_CREATE.
                drop(unsafe { Box::from_raw(file) });
                // SAFETY: as above.
                unsafe { (*fo).FsContext = null_mut() };
            }
            // SAFETY: the IRP is ours.
            unsafe { sys::complete(irp, sys::STATUS_SUCCESS, 0) }
        }
        sys::IRP_MJ_DEVICE_CONTROL => {
            // SAFETY: set at IRP_MJ_CREATE, alive until IRP_MJ_CLOSE.
            let Some(file) = (unsafe { (*fo).FsContext.cast::<File>().as_ref() }) else {
                // SAFETY: the IRP is ours.
                return unsafe { sys::complete(irp, sys::STATUS_INVALID_DEVICE_STATE, 0) };
            };
            // SAFETY: the stack location of a device control request.
            let (code, in_len, out_len) = unsafe {
                let p = &(*sl).Parameters.DeviceIoControl;
                (
                    p.IoControlCode,
                    p.InputBufferLength as usize,
                    p.OutputBufferLength as usize,
                )
            };
            if code == ioctl::WD_RECV {
                // METHOD_OUT_DIRECT: the input is in the system buffer.
                // SAFETY: the I/O manager allocated it for this request, `in_len` bytes long.
                let input = unsafe {
                    let buf = (*irp).AssociatedIrp.SystemBuffer.cast::<u8>();
                    if buf.is_null() {
                        &[][..]
                    } else {
                        slice::from_raw_parts(buf, in_len)
                    }
                };
                let status = match (handle::get(file), ioctl::WdRecvRequest::decode(input)) {
                    (Ok(h), _) if h.flags.contains(avulse_abi::Flags::SEND_ONLY) => {
                        sys::STATUS_INVALID_DEVICE_REQUEST
                    }
                    // SAFETY: a WD_RECV IRP for `file`, ours, in the caller's context.
                    (Ok(_), Ok(req)) => return unsafe { rx::wd_recv(&file.rx, irp, &req) },
                    (Ok(_), Err(_)) => sys::STATUS_INVALID_PARAMETER,
                    (Err(s), _) => s,
                };
                // SAFETY: the IRP is ours.
                return unsafe { sys::complete(irp, status, 0) };
            }
            if code == ioctl::RECV {
                let status = match handle::get(file) {
                    Ok(h) if h.flags.contains(avulse_abi::Flags::SEND_ONLY) => {
                        sys::STATUS_INVALID_DEVICE_REQUEST
                    }
                    // SAFETY: a RECV IRP for `file`, ours.
                    Ok(_) => return unsafe { rx::recv(&file.rx, irp) },
                    Err(s) => s,
                };
                // SAFETY: the IRP is ours.
                return unsafe { sys::complete(irp, status, 0) };
            }
            // The buffered IOCTLs share one system buffer, as long as the longer of the two.
            // SAFETY: the I/O manager allocated it for this request.
            let buf = unsafe { (*irp).AssociatedIrp.SystemBuffer.cast::<u8>() };
            let io = Buffered {
                buf,
                in_len,
                out_len,
            };
            let (status, info) = match control(file, code, &io) {
                Ok(n) => (sys::STATUS_SUCCESS, n),
                Err(s) => (s, 0),
            };
            // SAFETY: the IRP is ours.
            unsafe { sys::complete(irp, status, info) }
        }
        // SAFETY: the IRP is ours.
        _ => unsafe { sys::complete(irp, sys::STATUS_INVALID_DEVICE_REQUEST, 0) },
    }
}

/// The system buffer of a `METHOD_BUFFERED` request.
struct Buffered {
    buf: *mut u8,
    in_len: usize,
    out_len: usize,
}

impl Buffered {
    fn input(&self) -> &[u8] {
        if self.buf.is_null() || self.in_len == 0 {
            return &[];
        }
        // SAFETY: the system buffer holds the input.
        unsafe { slice::from_raw_parts(self.buf, self.in_len) }
    }

    /// Writes `bytes` as the output; fails if the caller's buffer is too short.
    fn output(&self, bytes: &[u8]) -> Result<usize, sys::NTSTATUS> {
        if self.buf.is_null() || self.out_len < bytes.len() {
            return Err(sys::STATUS_BUFFER_TOO_SMALL);
        }
        // SAFETY: the system buffer has room for `out_len` bytes; the input is no longer read.
        unsafe { slice::from_raw_parts_mut(self.buf, bytes.len()) }.copy_from_slice(bytes);
        Ok(bytes.len())
    }
}

/// One device control request. Returns the length of its output.
fn control(file: &File, code: u32, io: &Buffered) -> Result<usize, sys::NTSTATUS> {
    let invalid = |_| sys::STATUS_INVALID_PARAMETER;
    match code {
        ioctl::OPEN => handle::open(file, io.input()).map(|()| 0),
        ioctl::SHUTDOWN => {
            let how = match io.input() {
                [1, 0, 0, 0] => Shutdown::Recv,
                [2, 0, 0, 0] => Shutdown::Send,
                [3, 0, 0, 0] => Shutdown::Both,
                _ => return Err(sys::STATUS_INVALID_PARAMETER),
            };
            let h = handle::get(file)?;
            h.mutable.lock().shut_send |= matches!(how, Shutdown::Send | Shutdown::Both);
            if matches!(how, Shutdown::Recv | Shutdown::Both) {
                file.rx.lock().shut = true;
                // What is queued is still delivered; then waiting requests end.
                rx::wake(&file.rx);
            }
            Ok(0)
        }
        ioctl::SET_PARAM => {
            let (p, value) = ioctl::decode_param(io.input()).map_err(invalid)?;
            let value = value.ok_or(sys::STATUS_INVALID_PARAMETER)?;
            if !Param::range(p).contains(&value) {
                return Err(sys::STATUS_INVALID_PARAMETER);
            }
            handle::get(file)?.mutable.lock().params[p.index()] = value;
            Ok(0)
        }
        ioctl::GET_PARAM => {
            let (p, _) = ioctl::decode_param(io.input()).map_err(invalid)?;
            let value = handle::get(file)?.mutable.lock().params[p.index()];
            io.output(&value.to_le_bytes())
        }
        ioctl::STATS => {
            let stats = handle::get(file)?.mutable.lock().stats;
            io.output(&ioctl::encode_stats(&stats))
        }
        ioctl::EVAL => {
            let h = handle::get(file)?;
            let mut records = Record::decode_all(io.input());
            let r = records.next().ok_or(sys::STATUS_INVALID_PARAMETER)?;
            let r = r.map_err(invalid)?;
            let link = if h.layer == Layer::Ethernet {
                Link::Ethernet
            } else {
                Link::Ip
            };
            let mut meta = r.addr.meta();
            meta.priority = h.priority;
            let matched = eval::evaluate(h.program(), r.data, link, &meta)
                .ok_or(sys::STATUS_INSUFFICIENT_RESOURCES)?;
            io.output(&u32::from(matched).to_le_bytes())
        }
        ioctl::SEND => {
            let h = handle::get(file)?;
            if h.flags.contains(avulse_abi::Flags::RECV_ONLY)
                || !matches!(
                    h.layer,
                    Layer::Network | Layer::NetworkForward | Layer::Ethernet
                )
            {
                return Err(sys::STATUS_INVALID_DEVICE_REQUEST);
            }
            if h.mutable.lock().shut_send {
                // ERROR_NO_DATA in user mode: shut down.
                return Err(sys::STATUS_PIPE_EMPTY);
            }
            let mut sent = 0u32;
            for r in Record::decode_all(io.input()) {
                let status = match r {
                    Ok(r) if r.data.len() <= eval::MAX_PACKET => match h.layer {
                        Layer::Ethernet => lwf::send(r.data, &r.addr, h.priority),
                        layer => inject::send(r.data, &r.addr, layer, h.priority),
                    },
                    _ => sys::STATUS_INVALID_PARAMETER,
                };
                if status != sys::STATUS_SUCCESS {
                    // Only the first failure is an error; after it, nothing more is sent.
                    if sent == 0 {
                        return Err(status);
                    }
                    break;
                }
                sent += 1;
            }
            io.output(&sent.to_le_bytes())
        }
        _ => Err(sys::STATUS_INVALID_DEVICE_REQUEST),
    }
}
