//! The Windows backend: the `avulse.sys` driver (`drivers/windows`), reached through its control
//! device with the IOCTLs of [`avulse_abi::ioctl`].
//!
//! Opening a handle starts the driver first, as WinDivert's library does: it installs the
//! `avulse` kernel service from `avulse.sys`, next to the executable or at `AVULSE_DRIVER`, unless
//! [`Flags::NO_INSTALL`] is set, and starts it. That needs Administrator rights.
//!
//! The ETHERNET layer also needs the driver installed as an NDIS lightweight filter, bound to the
//! adapters (`netcfg -l avulse.inf -c s -i avulse`, as Administrator). Opening a handle never does
//! that, because binding a filter restarts every adapter; [`capabilities`](Backend::capabilities)
//! reports the layer only once it is installed.
//!
//! Receiving keeps one `RECV` request in flight per call, and waits for it with a timeout; a
//! request that times out is cancelled (`CancelIoEx`). The driver returns as many records as fit,
//! and the ones `recv` does not take yet wait in a queue here.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use avulse_abi::ioctl::{self, OpenRequest, Record};
use avulse_filter::Layer;
use avulse_filter::bytecode::EncodeError;
use avulse_proto::Link;
use avulse_proto::checksum::{self, Updated};
use windows_sys::Win32::Foundation::{
    ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_NOT_SUPPORTED,
    ERROR_OPERATION_ABORTED, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST,
    ERROR_SERVICE_EXISTS, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::NetworkManagement::IpHelper::if_nametoindex;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::{
    CancelIoEx, DeviceIoControl, GetOverlappedResult, GetOverlappedResultEx, OVERLAPPED,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RegCloseKey, RegOpenKeyExW,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, CreateServiceW, OpenSCManagerW, OpenServiceW, SC_HANDLE,
    SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
    SERVICE_KERNEL_DRIVER, StartServiceW,
};
use windows_sys::Win32::System::Threading::CreateEventW;

use super::{Backend, Capabilities, LayerSupport, Opened, Spec};
use crate::{Address, Error, Flags, MAX_PACKET_LEN, Param, Result, Shutdown, Stats};

/// The kernel service's name.
const SERVICE: &str = "avulse";
/// The registry key of the lightweight filter's network component, which `netcfg` creates when it
/// installs `avulse.inf` (the class of network services, and the INF's `NetCfgInstanceId`).
const FILTER_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E974-E325-11CE-BFC1-08002BE10318}\{3c1d6e52-8b7a-4f19-a2d4-5e9b0c71f846}";
/// What one `RECV` may return: room for a few of the largest packets.
const RECV_BUFFER: usize = 4 * (MAX_PACKET_LEN + 256);

pub(crate) struct Windows;

impl Backend for Windows {
    fn capabilities(&self) -> Capabilities {
        let mut c = Capabilities::NONE;
        let ethernet = filter_installed().then_some(Layer::Ethernet);
        for layer in [Layer::Network, Layer::NetworkForward]
            .into_iter()
            .chain(ethernet)
        {
            c.layers[layer as usize] = LayerSupport {
                open: true,
                divert: true,
                drop: true,
                inject: true,
                modify: true,
            };
        }
        c
    }

    fn open(&self, spec: &Spec<'_>) -> Result<Box<dyn Opened>> {
        Ok(Box::new(Handle::open(spec)?))
    }
}

fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain([0]).collect()
}

fn last_error() -> Error {
    Error::Io(io::Error::last_os_error())
}

/// A service control manager or service handle, closed when dropped.
struct Service(SC_HANDLE);

impl Drop for Service {
    fn drop(&mut self) {
        // SAFETY: opened by `OpenSCManagerW`, `OpenServiceW` or `CreateServiceW`.
        unsafe { CloseServiceHandle(self.0) };
    }
}

/// Where `avulse.sys` is: `AVULSE_DRIVER`, or next to the executable.
fn driver_path() -> io::Result<PathBuf> {
    if let Some(p) = std::env::var_os("AVULSE_DRIVER") {
        return Ok(p.into());
    }
    Ok(std::env::current_exe()?.with_file_name("avulse.sys"))
}

/// Installs the kernel service if it is missing (unless `NO_INSTALL`), and starts it.
fn start_driver(flags: Flags) -> Result<()> {
    // SAFETY: plain call; the result is checked.
    let scm = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_ALL_ACCESS) };
    if scm.is_null() {
        return Err(last_error());
    }
    let scm = Service(scm);
    let name = wide(SERVICE);
    let open = || {
        // SAFETY: valid handle and name.
        let s = unsafe { OpenServiceW(scm.0, name.as_ptr(), SERVICE_ALL_ACCESS) };
        (!s.is_null()).then(|| Service(s))
    };
    let service = match open() {
        Some(s) => s,
        None if io::Error::last_os_error().raw_os_error()
            == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) =>
        {
            if flags.contains(Flags::NO_INSTALL) {
                return Err(Error::Unsupported(
                    "the avulse driver is not installed, and NO_INSTALL is set",
                ));
            }
            let path = driver_path().map_err(Error::Io)?;
            if !path.is_file() {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{} not found (set AVULSE_DRIVER)", path.display()),
                )));
            }
            let path = wide(&path);
            // SAFETY: valid handle and strings; the optional arguments are null.
            let s = unsafe {
                CreateServiceW(
                    scm.0,
                    name.as_ptr(),
                    name.as_ptr(),
                    SERVICE_ALL_ACCESS,
                    SERVICE_KERNEL_DRIVER,
                    SERVICE_DEMAND_START,
                    SERVICE_ERROR_NORMAL,
                    path.as_ptr(),
                    null(),
                    null_mut(),
                    null(),
                    null(),
                    null(),
                )
            };
            if !s.is_null() {
                Service(s)
            } else if io::Error::last_os_error().raw_os_error() == Some(ERROR_SERVICE_EXISTS as i32)
            {
                // Another process installed it meanwhile.
                open().ok_or_else(last_error)?
            } else {
                return Err(last_error());
            }
        }
        None => return Err(last_error()),
    };
    // SAFETY: a valid service handle, no arguments.
    if unsafe { StartServiceW(service.0, 0, null()) } == 0
        && io::Error::last_os_error().raw_os_error() != Some(ERROR_SERVICE_ALREADY_RUNNING as i32)
    {
        return Err(last_error());
    }
    Ok(())
}

/// Whether the driver is installed as a lightweight filter, which the ETHERNET layer needs.
fn filter_installed() -> bool {
    let path = wide(FILTER_KEY);
    let mut key: HKEY = null_mut();
    // SAFETY: a NUL-terminated path and an out-parameter.
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key) }
        != ERROR_SUCCESS
    {
        return false;
    }
    // SAFETY: the key just opened.
    unsafe { RegCloseKey(key) };
    true
}

/// An interface index from its name: a number, or what `if_nametoindex` knows.
fn interface_index(name: &str) -> Result<u32> {
    if let Ok(i) = name.parse() {
        return Ok(i);
    }
    let c = std::ffi::CString::new(name)
        .map_err(|_| Error::InvalidArgument("an interface name holds a NUL"))?;
    // SAFETY: a NUL-terminated string.
    match unsafe { if_nametoindex(c.as_ptr().cast()) } {
        0 => Err(Error::InvalidArgument("unknown interface")),
        i => Ok(i),
    }
}

/// An overlapped operation's event and structure.
struct Overlapped {
    ov: Box<OVERLAPPED>,
    /// The event `ov` signals; it must live as long as `ov`.
    _event: OwnedHandle,
}

impl Overlapped {
    fn new() -> Result<Overlapped> {
        // SAFETY: a manual-reset event, unnamed.
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            return Err(last_error());
        }
        // SAFETY: a fresh handle we own.
        let event = unsafe { OwnedHandle::from_raw_handle(event as RawHandle) };
        // SAFETY: all zeros is a valid OVERLAPPED.
        let mut ov: Box<OVERLAPPED> = Box::new(unsafe { std::mem::zeroed() });
        ov.hEvent = event.as_raw_handle() as HANDLE;
        Ok(Overlapped { ov, _event: event })
    }
}

/// What a waiting request ended with.
fn device_error(code: u32) -> Error {
    if code == ERROR_NO_DATA {
        // The driver ends requests with STATUS_PIPE_EMPTY once shut down and drained.
        Error::Shutdown
    } else {
        Error::Io(io::Error::from_raw_os_error(code as i32))
    }
}

struct Rx {
    buf: Vec<u8>,
    queue: VecDeque<(Vec<u8>, Address)>,
    ov: Overlapped,
}

struct Handle {
    device: OwnedHandle,
    layer: Layer,
    rx: Mutex<Rx>,
}

// SAFETY: the device handle and the overlapped structures may be used from any thread; each
// overlapped structure is used under its mutex.
unsafe impl Send for Handle {}
// SAFETY: as above.
unsafe impl Sync for Handle {}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Handle {
    fn open(spec: &Spec<'_>) -> Result<Handle> {
        let program = match spec.filter.program() {
            Ok(p) => p.to_bytes(),
            Err(EncodeError::UserSpaceOnly) => {
                return Err(Error::Unsupported(
                    "filters with `matches` on Windows (they come with injection)",
                ));
            }
            Err(_) => {
                return Err(Error::Unsupported(
                    "this filter is too large for the driver",
                ));
            }
        };
        let interfaces = spec
            .interfaces
            .iter()
            .map(|n| interface_index(n))
            .collect::<Result<Vec<_>>>()?;
        start_driver(spec.flags)?;
        let path = wide(ioctl::DEVICE_PATH);
        // SAFETY: a NUL-terminated path and valid arguments.
        let device = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        if device == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        let h = Handle {
            // SAFETY: a fresh handle we own.
            device: unsafe { OwnedHandle::from_raw_handle(device as RawHandle) },
            layer: spec.layer,
            rx: Mutex::new(Rx {
                buf: vec![0; RECV_BUFFER],
                queue: VecDeque::new(),
                ov: Overlapped::new()?,
            }),
        };
        let req = OpenRequest {
            layer: spec.layer,
            priority: spec.priority,
            flags: spec.flags,
            program: &program,
            interfaces,
            filter: spec.source,
            syntax: spec.syntax,
        };
        match h.call(ioctl::OPEN, &req.encode(), &mut []) {
            // The driver is not bound to the adapters as a filter (STATUS_NOT_SUPPORTED).
            Err(Error::Io(e))
                if spec.layer == Layer::Ethernet
                    && e.raw_os_error() == Some(ERROR_NOT_SUPPORTED as i32) =>
            {
                return Err(Error::Unsupported(
                    "the ETHERNET layer needs the avulse filter installed (netcfg -l avulse.inf -c s -i avulse)",
                ));
            }
            r => r?,
        };
        for p in Param::ALL {
            if spec.params[p.index()] != p.default_value() {
                h.call(
                    ioctl::SET_PARAM,
                    &ioctl::encode_set_param(p, spec.params[p.index()]),
                    &mut [],
                )?;
            }
        }
        Ok(h)
    }

    /// What the handle's packets start with.
    fn link(&self) -> Link {
        if self.layer == Layer::Ethernet {
            Link::Ethernet
        } else {
            Link::Ip
        }
    }

    fn raw(&self) -> HANDLE {
        self.device.as_raw_handle() as HANDLE
    }

    /// One IOCTL, waited for. Returns the output's length.
    fn call(&self, code: u32, input: &[u8], output: &mut [u8]) -> Result<usize> {
        let mut ov = Overlapped::new()?;
        let mut n = 0;
        // SAFETY: the buffers and `ov` outlive the request, which is waited for below.
        let ok = unsafe {
            DeviceIoControl(
                self.raw(),
                code,
                input.as_ptr().cast(),
                input.len() as u32,
                output.as_mut_ptr().cast(),
                output.len() as u32,
                &mut n,
                &mut *ov.ov,
            )
        };
        let pending =
            ok == 0 && io::Error::last_os_error().raw_os_error() == Some(ERROR_IO_PENDING as i32);
        if ok == 0 && !pending {
            return Err(device_error(
                io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32,
            ));
        }
        // SAFETY: the request started on this handle with `ov`; this waits for it.
        if unsafe { GetOverlappedResult(self.raw(), &*ov.ov, &mut n, 1) } == 0 {
            return Err(device_error(
                io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32,
            ));
        }
        Ok(n as usize)
    }

    /// One `RECV`, waited for at most `timeout`; its records go to the queue.
    fn fetch(&self, rx: &mut Rx, timeout: Option<Duration>) -> Result<()> {
        let Rx { buf, queue, ov } = rx;
        let mut n = 0;
        // SAFETY: `buf` and `ov` live in `rx`, which the caller holds until the request ends.
        let ok = unsafe {
            DeviceIoControl(
                self.raw(),
                ioctl::RECV,
                null(),
                0,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut n,
                &mut *ov.ov,
            )
        };
        let err = || io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        if ok == 0 {
            let e = err();
            if e != ERROR_IO_PENDING {
                return Err(device_error(e));
            }
            let ms = timeout.map_or(u32::MAX, |t| t.as_millis().min(u32::MAX as u128 - 1) as u32);
            // SAFETY: the request started with `ov`; this waits for it, up to `ms`.
            if unsafe { GetOverlappedResultEx(self.raw(), &*ov.ov, &mut n, ms, 0) } == 0 {
                // A zero timeout reports ERROR_IO_INCOMPLETE rather than WAIT_TIMEOUT.
                let e = err();
                if e != WAIT_TIMEOUT && e != ERROR_IO_INCOMPLETE {
                    return Err(device_error(e));
                }
                // Timed out: cancel, then wait for the request to end, cancelled or not.
                // SAFETY: the request is ours and still uses `buf` and `ov`.
                unsafe { CancelIoEx(self.raw(), &*ov.ov) };
                // SAFETY: as above; this waits until the driver is done with the buffer.
                if unsafe { GetOverlappedResult(self.raw(), &*ov.ov, &mut n, 1) } == 0 {
                    let e = err();
                    return Err(if e == ERROR_OPERATION_ABORTED {
                        Error::Timeout
                    } else {
                        device_error(e)
                    });
                }
            }
        }
        for r in Record::decode_all(&buf[..n as usize]) {
            let r =
                r.map_err(|_| Error::Io(io::Error::other("a malformed record from the driver")))?;
            // Which checksums are right, as on Linux: those that are not get computed when the
            // packet is sent back.
            let mut addr = r.addr;
            let valid = checksum::verify(r.data, self.link());
            addr.ip_checksum = valid.ipv4;
            addr.tcp_checksum = valid.tcp;
            addr.udp_checksum = valid.udp;
            queue.push_back((r.data.to_vec(), addr));
        }
        Ok(())
    }
}

impl Opened for Handle {
    fn recv(&self, buf: &mut [u8], timeout: Option<Duration>) -> Result<(usize, Address)> {
        let mut rx = lock(&self.rx);
        if rx.queue.is_empty() {
            self.fetch(&mut rx, timeout)?;
        }
        let Some((data, addr)) = rx.queue.pop_front() else {
            return Err(Error::Timeout);
        };
        let dst = buf
            .get_mut(..data.len())
            .ok_or(Error::BufferTooSmall { needed: data.len() })?;
        dst.copy_from_slice(&data);
        Ok((data.len(), addr))
    }

    fn recv_ready(&self, buf: &mut [u8]) -> Result<Option<(usize, Address)>> {
        let mut rx = lock(&self.rx);
        match rx.queue.front() {
            Some((data, _)) if data.len() <= buf.len() => {
                let (data, addr) = rx.queue.pop_front().expect("checked above");
                buf[..data.len()].copy_from_slice(&data);
                Ok(Some((data.len(), addr)))
            }
            _ => Ok(None),
        }
    }

    /// WinDivert's rules, as on Linux: an impostor loses a hop of TTL, and the checksums whose
    /// address flags are clear are computed; then the driver injects the packet. At the ETHERNET
    /// layer the frame goes out of, or in through, the adapter `if_idx` names.
    fn send(&self, packet: &[u8], addr: &Address) -> Result<usize> {
        if self.layer == Layer::Ethernet && addr.if_idx == 0 {
            return Err(Error::InvalidArgument(
                "an ETHERNET packet needs its interface (if_idx)",
            ));
        }
        let at = super::ip_offset(packet, self.layer)?;
        let mut pkt = packet.to_vec();
        if addr.impostor
            && let Some(at) = at
        {
            super::decrement_ttl(&mut pkt[at..])?;
        }
        let fix = Updated {
            ipv4: !addr.ip_checksum,
            tcp: !addr.tcp_checksum,
            udp: !addr.udp_checksum,
            ..Updated::default()
        };
        checksum::recalculate_only(&mut pkt, self.link(), fix);
        let mut input = Vec::with_capacity(Record::encoded_len(pkt.len()));
        Record {
            addr: *addr,
            data: &pkt,
        }
        .encode_into(&mut input);
        let mut sent = [0u8; 4];
        self.call(ioctl::SEND, &input, &mut sent)?;
        if u32::from_le_bytes(sent) != 1 {
            return Err(Error::Io(io::Error::other("the driver sent nothing")));
        }
        Ok(packet.len())
    }

    fn shutdown(&self, how: Shutdown) -> Result<()> {
        let how: u32 = match how {
            Shutdown::Recv => 1,
            Shutdown::Send => 2,
            Shutdown::Both => 3,
        };
        self.call(ioctl::SHUTDOWN, &how.to_le_bytes(), &mut [])
            .map(drop)
    }

    fn set_param(&self, param: Param, value: u64) -> Result<()> {
        self.call(
            ioctl::SET_PARAM,
            &ioctl::encode_set_param(param, value),
            &mut [],
        )
        .map(drop)
    }

    fn stats(&self) -> Result<Stats> {
        let mut out = [0u8; 64];
        self.call(ioctl::STATS, &[], &mut out)?;
        ioctl::decode_stats(&out).map_err(|_| Error::Io(io::Error::other("malformed statistics")))
    }

    fn close(self: Box<Self>) -> Result<()> {
        // Closing the device file closes the handle in the driver (IRP_MJ_CLEANUP).
        drop(self);
        Ok(())
    }
}
