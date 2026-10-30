//! WinDivert 2.2's API (`windivert.h`), over avulse: the exports of `WinDivert.dll`, which
//! programs and bindings written for WinDivert load in place of WinDivert's own.
//!
//! A handle is the file of avulse's device that [`Handle::device`] gives, so that callers can do
//! what they do with WinDivert's: wait for an overlapped `WinDivertRecvEx` with
//! `GetOverlappedResult`, and cancel it with `CancelIoEx`. Receiving is the driver's
//! WinDivert-style request ([`ioctl::WD_RECV`]), which writes the packets and their 80-byte
//! addresses straight into the caller's buffers. Sending goes through [`Handle::send`], at once:
//! an overlapped `WinDivertSendEx` completes before it returns.
//!
//! Failures return `FALSE` (`INVALID_HANDLE_VALUE` from `WinDivertOpen`) with the error in
//! `GetLastError`: `ERROR_INVALID_PARAMETER` for a bad argument or filter, `ERROR_NOT_SUPPORTED`
//! for what the backend cannot do, `ERROR_NO_DATA` once shut down, `ERROR_INSUFFICIENT_BUFFER`
//! for a packet larger than the buffer (it is dropped), `ERROR_IO_PENDING` for an overlapped
//! receive in progress, and the system's error otherwise. The driver, `avulse.sys` (or the same
//! file named `WinDivert64.sys`, in place of WinDivert's), is installed from next to the DLL (or
//! `AVULSE_DRIVER`) as the `WinDivert` service, as WinDivert's DLL installs its own; a driver
//! already running (as `avulse`, for instance) is used as it is. A panic aborts
//! the process (`extern "C"`); the code avoids them.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsString;
use std::ffi::{CStr, CString, c_char, c_void};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use avulse::{Error, Filter, Flags, Handle, Layer, OpenOptions, Param, Shutdown, Syntax};
use avulse_abi::ioctl::{self, WdRecvRequest};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_GEN_FAILURE, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_HANDLE,
    ERROR_INVALID_PARAMETER, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_NOT_SUPPORTED, FALSE, HANDLE,
    HMODULE, INVALID_HANDLE_VALUE, SetLastError, TRUE,
};
use windows_sys::Win32::System::IO::{
    CancelIoEx, DeviceIoControl, GetOverlappedResult, OVERLAPPED,
};
use windows_sys::Win32::System::LibraryLoader::{
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    GetModuleFileNameW, GetModuleHandleExW,
};
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent};
use windows_sys::core::BOOL;

use crate::WdAddress;
use crate::helpers::{self, Invalid};
use crate::packet::{self, Transport};

/// `WINDIVERT_MTU_MAX`: the largest packet `WinDivertSend` takes.
const MTU_MAX: usize = 40 + 0xffff;
/// `WINDIVERT_PARAM_VERSION_MAJOR` and `_MINOR`: the API level, 2.2.
const PARAM_VERSION_MAJOR: u32 = 3;
const PARAM_VERSION_MINOR: u32 = 4;

thread_local! {
    static TEXT: RefCell<CString> = RefCell::new(CString::default());
}

/// Keeps `s` for the calling thread, until its next call that returns text.
fn keep_text(s: &str) -> *const c_char {
    let s = CString::new(s.replace('\0', " ")).unwrap_or_default();
    TEXT.with(|t| {
        *t.borrow_mut() = s;
        t.borrow().as_ptr()
    })
}

/// An open handle, by the value of its device file.
struct Shim {
    handle: Handle,
    raw: HANDLE,
    /// Where the driver writes the address of a receive whose caller passed none. Dropped after
    /// `handle`, whose close ends the receives that use it.
    scratch: Box<[u8; 80]>,
}

// SAFETY: `raw` is the handle's own file, usable from any thread; the rest is `Send + Sync`.
unsafe impl Send for Shim {}
// SAFETY: as above.
unsafe impl Sync for Shim {}

static HANDLES: Mutex<Option<HashMap<usize, Arc<Shim>>>> = Mutex::new(None);

fn handles() -> MutexGuard<'static, Option<HashMap<usize, Arc<Shim>>>> {
    HANDLES.lock().unwrap_or_else(|e| e.into_inner())
}

fn shim(h: HANDLE) -> Option<Arc<Shim>> {
    handles().as_ref()?.get(&(h as usize)).cloned()
}

/// Fails with `code`.
fn fail(code: u32) -> BOOL {
    // SAFETY: plain call.
    unsafe { SetLastError(code) };
    FALSE
}

/// The Win32 error of `e`.
fn code(e: &Error) -> u32 {
    match e {
        Error::Filter(_) | Error::InvalidArgument(_) => ERROR_INVALID_PARAMETER,
        Error::Unsupported(_) => ERROR_NOT_SUPPORTED,
        Error::Shutdown => ERROR_NO_DATA,
        Error::BufferTooSmall { .. } => ERROR_INSUFFICIENT_BUFFER,
        Error::Io(io) => match io.raw_os_error() {
            Some(c) => c as u32,
            None if io.kind() == io::ErrorKind::NotFound => ERROR_FILE_NOT_FOUND,
            None => ERROR_GEN_FAILURE,
        },
        _ => ERROR_GEN_FAILURE,
    }
}

/// A C string as UTF-8.
///
/// # Safety
///
/// `s` is NULL or a NUL-terminated string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a str> {
    if s.is_null() {
        return None;
    }
    // SAFETY: the caller's contract.
    unsafe { CStr::from_ptr(s) }.to_str().ok()
}

/// A WinDivert layer (no ETHERNET).
fn layer(n: u32) -> Option<Layer> {
    match u8::try_from(n).ok().and_then(|n| Layer::try_from(n).ok()) {
        Some(Layer::Ethernet) | None => None,
        l => l,
    }
}

/// `len` bytes at `p`, or nothing.
///
/// # Safety
///
/// `p` is valid for `len` bytes, or NULL.
unsafe fn bytes<'a>(p: *const c_void, len: u32) -> &'a [u8] {
    if p.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe { std::slice::from_raw_parts(p.cast(), len as usize) }
}

/// `len` bytes at `p` to write, or nothing.
///
/// # Safety
///
/// `p` is valid for `len` bytes, or NULL.
unsafe fn bytes_mut<'a>(p: *mut c_void, len: u32) -> &'a mut [u8] {
    if p.is_null() || len == 0 {
        return &mut [];
    }
    // SAFETY: the caller's contract.
    unsafe { std::slice::from_raw_parts_mut(p.cast(), len as usize) }
}

/// Writes through `p` if it is not NULL.
///
/// # Safety
///
/// `p` is NULL or valid for a write.
unsafe fn put<T>(p: *mut T, v: T) {
    if !p.is_null() {
        // SAFETY: the caller's contract.
        unsafe { p.write(v) };
    }
}

/// The driver next to this DLL: `avulse.sys`, or else avulse's driver under WinDivert's name,
/// `WinDivert64.sys`, so that replacing WinDivert's two files is enough. `None`: avulse's default.
fn driver() -> Option<PathBuf> {
    let mut module: HMODULE = null_mut();
    // SAFETY: an address in this module, and an out-parameter; the reference count is unchanged,
    // and the module outlives the call.
    let found = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            driver as *const u16,
            &mut module,
        )
    };
    if found == FALSE {
        return None;
    }
    let mut name = vec![0u16; 32_768];
    // SAFETY: a valid module and buffer.
    let n = unsafe { GetModuleFileNameW(module, name.as_mut_ptr(), name.len() as u32) } as usize;
    if n == 0 || n >= name.len() {
        return None;
    }
    let dll = PathBuf::from(OsString::from_wide(&name[..n]));
    if dll.with_file_name("avulse.sys").is_file() {
        return None;
    }
    Some(dll.with_file_name("WinDivert64.sys")).filter(|p| p.is_file())
}

/// Opens a handle with a WinDivert filter at `layer`. Returns `INVALID_HANDLE_VALUE` on failure.
///
/// # Safety
///
/// `filter` is a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertOpen(
    filter: *const c_char,
    layer: u32,
    priority: i16,
    flags: u64,
) -> HANDLE {
    // SAFETY: the caller's contract.
    let (Some(src), Some(layer), Some(flags)) = (
        unsafe { text(filter) },
        self::layer(layer),
        Flags::from_bits(flags),
    ) else {
        fail(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    };
    let mut options = OpenOptions::new();
    options
        .priority(priority)
        .flags(flags)
        .syntax(Syntax::WinDivert)
        .service("WinDivert");
    if let Some(path) = driver() {
        options.driver(path);
    }
    let opened = options.open(src, layer);
    let handle = match opened {
        Ok(h) => h,
        Err(e) => {
            fail(code(&e));
            return INVALID_HANDLE_VALUE;
        }
    };
    let Some(raw) = handle.device().map(|d| d.as_raw_handle() as HANDLE) else {
        fail(ERROR_NOT_SUPPORTED);
        return INVALID_HANDLE_VALUE;
    };
    let shim = Arc::new(Shim {
        handle,
        raw,
        scratch: Box::new([0; 80]),
    });
    handles()
        .get_or_insert_with(HashMap::new)
        .insert(raw as usize, shim);
    raw
}

/// Receives one packet (or event), waiting for it.
///
/// # Safety
///
/// As [`WinDivertRecvEx`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertRecv(
    handle: HANDLE,
    packet: *mut c_void,
    packet_len: u32,
    recv_len: *mut u32,
    addr: *mut WdAddress,
) -> BOOL {
    // SAFETY: the caller's contract.
    unsafe {
        WinDivertRecvEx(
            handle,
            packet,
            packet_len,
            recv_len,
            0,
            addr,
            null_mut(),
            null_mut(),
        )
    }
}

/// Receives packets back to back in `packet`, as many as `*addr_len` has room for addresses
/// (one if `addr_len` is NULL), with their addresses in `addrs` and their total length in
/// `*recv_len`. With `overlapped`, the request may stay pending (`FALSE`, `ERROR_IO_PENDING`):
/// the caller waits for it with `GetOverlappedResult` on the handle, and may cancel it with
/// `CancelIoEx`. Without, the call waits.
///
/// # Safety
///
/// `packet` is valid for `packet_len` bytes; `recv_len` and `addr_len` are NULL or valid;
/// `addrs` is NULL or valid for `*addr_len` bytes (one address without `addr_len`); `overlapped`
/// is NULL or a valid `OVERLAPPED`; with `overlapped`, all of them stay valid until the request
/// ends.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertRecvEx(
    handle: HANDLE,
    packet: *mut c_void,
    packet_len: u32,
    recv_len: *mut u32,
    flags: u64,
    addrs: *mut WdAddress,
    addr_len: *mut u32,
    overlapped: *mut OVERLAPPED,
) -> BOOL {
    let Some(s) = shim(handle) else {
        return fail(ERROR_INVALID_HANDLE);
    };
    if flags != 0 || packet.is_null() || packet_len == 0 {
        return fail(ERROR_INVALID_PARAMETER);
    }
    let (addrs, count) = if addrs.is_null() {
        (s.scratch.as_ptr() as u64, 1)
    } else if addr_len.is_null() {
        (addrs as u64, 1)
    } else {
        // SAFETY: the caller's contract.
        (addrs as u64, unsafe { *addr_len } / 80)
    };
    if count == 0 {
        return fail(ERROR_INVALID_PARAMETER);
    }
    let req = WdRecvRequest {
        addrs,
        addr_len: addr_len as u64,
        count,
    }
    .encode();
    // SAFETY: the caller's contract; the request's input is copied by the I/O manager.
    unsafe { device_control(s.raw, &req, packet, packet_len, recv_len, overlapped) }
}

/// One `WD_RECV`: overlapped with the caller's `OVERLAPPED`, or waited for with one of its own.
///
/// # Safety
///
/// As [`WinDivertRecvEx`].
unsafe fn device_control(
    raw: HANDLE,
    req: &[u8],
    out: *mut c_void,
    out_len: u32,
    done_len: *mut u32,
    overlapped: *mut OVERLAPPED,
) -> BOOL {
    if !overlapped.is_null() {
        // SAFETY: the caller's contract.
        return unsafe {
            DeviceIoControl(
                raw,
                ioctl::WD_RECV,
                req.as_ptr().cast(),
                req.len() as u32,
                out,
                out_len,
                done_len,
                overlapped,
            )
        };
    }
    // The device is opened for overlapped I/O: wait here.
    // SAFETY: a manual-reset event, unnamed.
    let event = unsafe { CreateEventW(null(), TRUE, FALSE, null()) };
    if event.is_null() {
        return FALSE;
    }
    let event = Event(event);
    // SAFETY: all zeros is a valid OVERLAPPED.
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    ov.hEvent = event.0;
    let mut n = 0u32;
    // SAFETY: the buffers and `ov` outlive the request, which is waited for below.
    let ok = unsafe {
        DeviceIoControl(
            raw,
            ioctl::WD_RECV,
            req.as_ptr().cast(),
            req.len() as u32,
            out,
            out_len,
            &mut n,
            &mut ov,
        )
    };
    // SAFETY: plain call.
    if ok == FALSE && io::Error::last_os_error().raw_os_error() != Some(ERROR_IO_PENDING as i32) {
        return FALSE;
    }
    // SAFETY: the request started on `raw` with `ov`; this waits for it.
    if unsafe { GetOverlappedResult(raw, &ov, &mut n, TRUE) } == FALSE {
        return FALSE;
    }
    // SAFETY: the caller's contract.
    unsafe { put(done_len, n) };
    TRUE
}

/// An event handle, closed when dropped.
struct Event(HANDLE);

impl Drop for Event {
    fn drop(&mut self) {
        // SAFETY: an event this module created.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

/// Sends `pkt` where `addr` says.
fn send_one(h: &Handle, pkt: &[u8], addr: &WdAddress) -> Result<(), u32> {
    if pkt.len() > MTU_MAX {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let addr = addr.to_avulse().map_err(|_| ERROR_INVALID_PARAMETER)?;
    h.send(pkt, &addr).map(drop).map_err(|e| code(&e))
}

/// Sends (or reinjects) a packet. The address decides the direction and the interface.
///
/// # Safety
///
/// As [`WinDivertSendEx`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertSend(
    handle: HANDLE,
    packet: *const c_void,
    packet_len: u32,
    send_len: *mut u32,
    addr: *const WdAddress,
) -> BOOL {
    // SAFETY: the caller's contract.
    unsafe {
        WinDivertSendEx(
            handle,
            packet,
            packet_len,
            send_len,
            0,
            addr,
            80,
            null_mut(),
        )
    }
}

/// Sends the packets that are back to back in `packet`, each as long as its IP header says, one
/// per address in `addrs` (`addr_len` bytes). It fails only if the first packet does;
/// `*send_len` is the bytes sent. With `overlapped`, the request completes before the call
/// returns: its event is set, and `GetOverlappedResult` gives the bytes sent.
///
/// # Safety
///
/// `packet` is valid for `packet_len` bytes; `addrs` for `addr_len` bytes; `send_len` is NULL or
/// valid; `overlapped` is NULL or a valid `OVERLAPPED`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertSendEx(
    handle: HANDLE,
    packet: *const c_void,
    packet_len: u32,
    send_len: *mut u32,
    flags: u64,
    addrs: *const WdAddress,
    addr_len: u32,
    overlapped: *mut OVERLAPPED,
) -> BOOL {
    let Some(s) = shim(handle) else {
        return fail(ERROR_INVALID_HANDLE);
    };
    if flags != 0 || packet.is_null() || addrs.is_null() || addr_len < 80 {
        return fail(ERROR_INVALID_PARAMETER);
    }
    // SAFETY: the caller's contract.
    let all = unsafe { bytes(packet, packet_len) };
    let (mut off, mut sent, mut err) = (0, 0u32, 0);
    for i in 0..(addr_len / 80) as usize {
        if off >= all.len() {
            break;
        }
        let p = &all[off..];
        let len = match p.first().map(|b| b >> 4) {
            Some(4) if p.len() >= 20 => usize::from(u16::from_be_bytes([p[2], p[3]])),
            Some(6) if p.len() >= 40 => 40 + usize::from(u16::from_be_bytes([p[4], p[5]])),
            _ if i > 0 => break,
            _ => return fail(ERROR_INVALID_PARAMETER),
        };
        if len == 0 || len > p.len() {
            return fail(ERROR_INVALID_PARAMETER);
        }
        // SAFETY: the caller's contract: `addr_len` bytes of addresses.
        if let Err(e) = send_one(&s.handle, &p[..len], unsafe { &*addrs.add(i) }) {
            err = e;
            break;
        }
        off += len;
        sent += len as u32;
    }
    if sent == 0 && err != 0 {
        return fail(err);
    }
    // SAFETY: the caller's contract.
    unsafe {
        put(send_len, sent);
        if let Some(ov) = overlapped.as_mut() {
            // Done, as a request that completed at once: STATUS_SUCCESS and the bytes sent.
            ov.Internal = 0;
            ov.InternalHigh = sent as usize;
            if !ov.hEvent.is_null() {
                SetEvent(ov.hEvent);
            }
        }
    }
    TRUE
}

/// Stops receiving (1), sending (2) or both (3). Packets already queued are still received.
///
/// # Safety
///
/// `handle` is a handle `WinDivertOpen` returned, or anything else (refused).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertShutdown(handle: HANDLE, how: u32) -> BOOL {
    let Some(s) = shim(handle) else {
        return fail(ERROR_INVALID_HANDLE);
    };
    let how = match how {
        1 => Shutdown::Recv,
        2 => Shutdown::Send,
        3 => Shutdown::Both,
        _ => return fail(ERROR_INVALID_PARAMETER),
    };
    match s.handle.shutdown(how) {
        Ok(()) => TRUE,
        Err(e) => fail(code(&e)),
    }
}

/// Closes a handle: requests in progress on it end (`ERROR_OPERATION_ABORTED`), and the call
/// returns once the handle's file is closed.
///
/// # Safety
///
/// `handle` is a handle `WinDivertOpen` returned, or anything else (refused).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertClose(handle: HANDLE) -> BOOL {
    let Some(s) = handles()
        .as_mut()
        .and_then(|m| m.remove(&(handle as usize)))
    else {
        return fail(ERROR_INVALID_HANDLE);
    };
    // End every request in progress, the waits of other threads in this module included, and
    // wait for those threads to let the handle go.
    // SAFETY: the handle's own file.
    unsafe { CancelIoEx(s.raw, null()) };
    let _ = s.handle.shutdown(Shutdown::Both);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Arc::strong_count(&s) > 1 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    match Arc::try_unwrap(s) {
        Ok(s) => match s.handle.close() {
            Ok(()) => TRUE,
            Err(e) => fail(code(&e)),
        },
        // Still in use: it closes when the last call returns.
        Err(_) => TRUE,
    }
}

/// Sets a queue parameter (`QUEUE_LENGTH` 0, `QUEUE_TIME` 1, `QUEUE_SIZE` 2).
///
/// # Safety
///
/// `handle` is a handle `WinDivertOpen` returned, or anything else (refused).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertSetParam(handle: HANDLE, param: u32, value: u64) -> BOOL {
    let Some(s) = shim(handle) else {
        return fail(ERROR_INVALID_HANDLE);
    };
    let Some(&p) = Param::ALL.get(param as usize) else {
        return fail(ERROR_INVALID_PARAMETER);
    };
    match s.handle.set_param(p, value) {
        Ok(()) => TRUE,
        Err(e) => fail(code(&e)),
    }
}

/// Reads a queue parameter, or the API version (`VERSION_MAJOR` 3, `VERSION_MINOR` 4: 2.2).
///
/// # Safety
///
/// `handle` is a handle `WinDivertOpen` returned; `value` is valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertGetParam(handle: HANDLE, param: u32, value: *mut u64) -> BOOL {
    let Some(s) = shim(handle) else {
        return fail(ERROR_INVALID_HANDLE);
    };
    if value.is_null() {
        return fail(ERROR_INVALID_PARAMETER);
    }
    let v = match param {
        PARAM_VERSION_MAJOR | PARAM_VERSION_MINOR => 2,
        _ => match Param::ALL.get(param as usize) {
            Some(&p) => s.handle.param(p),
            None => return fail(ERROR_INVALID_PARAMETER),
        },
    };
    // SAFETY: the caller's contract.
    unsafe { value.write(v) };
    TRUE
}

/// WinDivert's hash of a packet's headers, seeded; 0 for a packet it cannot parse.
///
/// # Safety
///
/// `packet` is NULL or valid for `packet_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertHelperHashPacket(
    packet: *const c_void,
    packet_len: u32,
    seed: u64,
) -> u64 {
    // SAFETY: the caller's contract.
    helpers::hash_packet(unsafe { bytes(packet, packet_len) }, seed)
}

/// The headers of the first packet in `packet`, as WinDivert finds them, and where the next
/// packet of a batch starts. Each output is NULL (or 0) when absent; any output may be NULL.
///
/// # Safety
///
/// `packet` is valid for `packet_len` bytes; each output is NULL or valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertHelperParsePacket(
    packet: *const c_void,
    packet_len: u32,
    ip: *mut *const c_void,
    ipv6: *mut *const c_void,
    protocol: *mut u8,
    icmp: *mut *const c_void,
    icmpv6: *mut *const c_void,
    tcp: *mut *const c_void,
    udp: *mut *const c_void,
    data: *mut *const c_void,
    data_len: *mut u32,
    next: *mut *const c_void,
    next_len: *mut u32,
) -> BOOL {
    // SAFETY: the caller's contract.
    let all = unsafe { bytes(packet, packet_len) };
    let view = packet::parse(all);
    let at = |off: usize| all[off..].as_ptr().cast::<c_void>();
    // SAFETY: the outputs are NULL or valid, per the contract.
    unsafe {
        for p in [ip, ipv6, icmp, icmpv6, tcp, udp, data, next] {
            put(p, null());
        }
        put(protocol, 0);
        put(data_len, 0);
        put(next_len, 0);
        let Some(v) = view else {
            return fail(ERROR_INVALID_PARAMETER);
        };
        put(if v.ipv6 { ipv6 } else { ip }, at(0));
        put(protocol, v.protocol);
        if let Some((t, off)) = v.transport {
            let out = match t {
                Transport::Tcp(_) => tcp,
                Transport::Udp => udp,
                Transport::Icmp => icmp,
                Transport::Icmpv6 => icmpv6,
            };
            put(out, at(off));
        }
        if v.payload_len > 0 {
            put(data, at(v.payload));
            put(data_len, v.payload_len as u32);
        }
        // The packet ends where its IP length says; what follows is the next one.
        let end = (v.payload + v.payload_len).min(all.len());
        if end < all.len() {
            put(next, at(end));
            put(next_len, (all.len() - end) as u32);
        }
    }
    TRUE
}

/// Parses an IPv4 address into host byte order.
///
/// # Safety
///
/// `s` is a NUL-terminated string; `addr` is NULL or valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertHelperParseIPv4Address(s: *const c_char, addr: *mut u32) -> BOOL {
    // SAFETY: the caller's contract.
    match unsafe { text(s) }.and_then(|s| s.parse::<Ipv4Addr>().ok()) {
        Some(a) => {
            // SAFETY: as above.
            unsafe { put(addr, u32::from(a)) };
            TRUE
        }
        None => fail(ERROR_INVALID_PARAMETER),
    }
}

/// Parses an IPv6 address into four host-order words, the least significant first, as
/// WinDivert's addresses hold them.
///
/// # Safety
///
/// `s` is a NUL-terminated string; `addr` is NULL or valid for 4 words.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertHelperParseIPv6Address(s: *const c_char, addr: *mut u32) -> BOOL {
    // SAFETY: the caller's contract.
    match unsafe { text(s) }.and_then(|s| s.parse::<Ipv6Addr>().ok()) {
        Some(a) => {
            if !addr.is_null() {
                let v = u128::from(a);
                for i in 0..4 {
                    // SAFETY: as above.
                    unsafe { addr.add(i).write((v >> (32 * i)) as u32) };
                }
            }
            TRUE
        }
        None => fail(ERROR_INVALID_PARAMETER),
    }
}

/// Writes `text` and its NUL to `buf`, if they fit.
///
/// # Safety
///
/// `buf` is valid for `len` bytes.
unsafe fn write_text(text: &str, buf: *mut c_char, len: u32) -> BOOL {
    if buf.is_null() {
        return fail(ERROR_INVALID_PARAMETER);
    }
    if text.len() >= len as usize {
        return fail(ERROR_INSUFFICIENT_BUFFER);
    }
    // SAFETY: `buf` has room for the text and its NUL.
    unsafe {
        std::ptr::copy_nonoverlapping(text.as_ptr(), buf.cast(), text.len());
        *buf.add(text.len()) = 0;
    }
    TRUE
}

/// Formats an IPv4 address in host byte order.
///
/// # Safety
///
/// `buf` is valid for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertHelperFormatIPv4Address(
    addr: u32,
    buf: *mut c_char,
    len: u32,
) -> BOOL {
    // SAFETY: the caller's contract.
    unsafe { write_text(&Ipv4Addr::from(addr).to_string(), buf, len) }
}

/// Formats an IPv6 address given as four host-order words, the least significant first.
///
/// # Safety
///
/// `addr` is valid for 4 words; `buf` for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertHelperFormatIPv6Address(
    addr: *const u32,
    buf: *mut c_char,
    len: u32,
) -> BOOL {
    if addr.is_null() {
        return fail(ERROR_INVALID_PARAMETER);
    }
    // SAFETY: the caller's contract.
    let v = (0..4).fold(0u128, |v, i| {
        v | u128::from(unsafe { *addr.add(i) }) << (32 * i)
    });
    // SAFETY: as above.
    unsafe { write_text(&Ipv6Addr::from(v).to_string(), buf, len) }
}

/// Recomputes the checksums of a packet in place, except those `flags` excludes
/// (`WINDIVERT_HELPER_NO_*`), and sets the address's checksum bits for those it computed.
///
/// # Safety
///
/// `packet` is valid for `packet_len` bytes; `addr` is NULL or valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertHelperCalcChecksums(
    packet: *mut c_void,
    packet_len: u32,
    addr: *mut WdAddress,
    flags: u64,
) -> BOOL {
    if packet.is_null() {
        return fail(ERROR_INVALID_PARAMETER);
    }
    // SAFETY: the caller's contract.
    let (ok, set) = helpers::calc_checksums(unsafe { bytes_mut(packet, packet_len) }, flags);
    // SAFETY: valid or NULL, per the contract.
    if let Some(a) = unsafe { addr.as_mut() } {
        a.set_checksums(set.ip, set.tcp, set.udp);
    }
    if ok {
        TRUE
    } else {
        fail(ERROR_INVALID_PARAMETER)
    }
}

/// Decrements the TTL (hop limit) of a packet, and updates the IPv4 checksum. `FALSE` if it
/// would reach 0.
///
/// # Safety
///
/// `packet` is valid for `packet_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertHelperDecrementTTL(packet: *mut c_void, packet_len: u32) -> BOOL {
    // SAFETY: the caller's contract.
    let p = unsafe { bytes_mut(packet, packet_len) };
    let at = match p.first().map(|b| b >> 4) {
        Some(4) if p.len() >= 20 => 8,
        Some(6) if p.len() >= 40 => 7,
        _ => return fail(ERROR_INVALID_PARAMETER),
    };
    if p[at] <= 1 {
        return FALSE;
    }
    p[at] -= 1;
    if at == 8 {
        // The header checksum, updated: the word TTL|protocol went down by 0x100.
        let c = u32::from(u16::from_be_bytes([p[10], p[11]])) + 0x100;
        let c = (c & 0xffff) + (c >> 16);
        p[10..12].copy_from_slice(&(c as u16).to_be_bytes());
    }
    TRUE
}

/// Compiles a WinDivert filter for `layer` into WinDivert's object (written to `object`, if not
/// NULL). On error, `*error_str` (kept for the calling thread) and `*error_pos` say why and where.
///
/// # Safety
///
/// `filter` is a NUL-terminated string; `object` is NULL or valid for `object_len` bytes;
/// `error_str` and `error_pos` are NULL or valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertHelperCompileFilter(
    filter: *const c_char,
    layer: u32,
    object: *mut c_char,
    object_len: u32,
    error_str: *mut *const c_char,
    error_pos: *mut u32,
) -> BOOL {
    // SAFETY: valid or NULL, per the contract.
    unsafe {
        put(error_str, null());
        put(error_pos, 0);
    }
    // SAFETY: the caller's contract.
    let (Some(src), Some(layer)) = (unsafe { text(filter) }, self::layer(layer)) else {
        return fail(ERROR_INVALID_PARAMETER);
    };
    match Filter::windivert_object(src, layer) {
        // SAFETY: the caller's contract.
        Ok(o) if !object.is_null() => unsafe { write_text(&o, object, object_len) },
        Ok(_) => TRUE,
        Err(d) => {
            // SAFETY: valid or NULL, per the contract.
            unsafe {
                put(error_str, keep_text(&d.message));
                put(error_pos, d.span.start as u32);
            }
            fail(ERROR_INVALID_PARAMETER)
        }
    }
}

/// Whether a packet with its address matches a WinDivert filter (compiled at the address's
/// layer). `FALSE` with `ERROR_INVALID_PARAMETER` for a bad filter, packet or address.
///
/// # Safety
///
/// `filter` is a NUL-terminated string; `packet` is NULL or valid for `packet_len` bytes;
/// `addr` is valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertHelperEvalFilter(
    filter: *const c_char,
    packet: *const c_void,
    packet_len: u32,
    addr: *const WdAddress,
) -> BOOL {
    // SAFETY: the caller's contract.
    let (Some(src), Some(addr)) = (unsafe { text(filter) }, unsafe { addr.as_ref() }) else {
        return fail(ERROR_INVALID_PARAMETER);
    };
    let Ok(addr) = addr.to_avulse() else {
        return fail(ERROR_INVALID_PARAMETER);
    };
    // SAFETY: the caller's contract.
    match helpers::eval_filter(src, unsafe { bytes(packet, packet_len) }, &addr) {
        Ok(m) => {
            // SAFETY: plain call; a miss is not an error.
            unsafe { SetLastError(0) };
            BOOL::from(m)
        }
        Err(Invalid::Filter(_) | Invalid::Argument(_)) => fail(ERROR_INVALID_PARAMETER),
    }
}

/// Writes a WinDivert filter in canonical form to `buf`.
///
/// # Safety
///
/// `filter` is a NUL-terminated string; `buf` is valid for `buf_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertHelperFormatFilter(
    filter: *const c_char,
    layer: u32,
    buf: *mut c_char,
    buf_len: u32,
) -> BOOL {
    // SAFETY: the caller's contract.
    let (Some(src), Some(layer)) = (unsafe { text(filter) }, self::layer(layer)) else {
        return fail(ERROR_INVALID_PARAMETER);
    };
    match helpers::format_filter(src, layer) {
        // SAFETY: the caller's contract.
        Ok(out) => unsafe { write_text(&out, buf, buf_len) },
        Err(_) => fail(ERROR_INVALID_PARAMETER),
    }
}

/// `ntohs`.
#[unsafe(no_mangle)]
pub extern "C" fn WinDivertHelperNtohs(x: u16) -> u16 {
    u16::from_be(x)
}

/// `htons`.
#[unsafe(no_mangle)]
pub extern "C" fn WinDivertHelperHtons(x: u16) -> u16 {
    x.to_be()
}

/// `ntohl`.
#[unsafe(no_mangle)]
pub extern "C" fn WinDivertHelperNtohl(x: u32) -> u32 {
    u32::from_be(x)
}

/// `htonl`.
#[unsafe(no_mangle)]
pub extern "C" fn WinDivertHelperHtonl(x: u32) -> u32 {
    x.to_be()
}

/// The 64-bit `ntoh`.
#[unsafe(no_mangle)]
pub extern "C" fn WinDivertHelperNtohll(x: u64) -> u64 {
    u64::from_be(x)
}

/// The 64-bit `hton`.
#[unsafe(no_mangle)]
pub extern "C" fn WinDivertHelperHtonll(x: u64) -> u64 {
    x.to_be()
}

/// An IPv6 address in network order (as in a header) to WinDivert's four host-order words, the
/// least significant first.
///
/// # Safety
///
/// `inp` and `out` are valid for 4 words.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertHelperNtohIPv6Address(inp: *const u32, out: *mut u32) {
    // SAFETY: the caller's contract.
    unsafe { swap_ipv6(inp, out) }
}

/// WinDivert's four host-order words to an IPv6 address in network order.
///
/// # Safety
///
/// `inp` and `out` are valid for 4 words.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertHelperHtonIPv6Address(inp: *const u32, out: *mut u32) {
    // SAFETY: the caller's contract.
    unsafe { swap_ipv6(inp, out) }
}

/// The older spelling of [`WinDivertHelperNtohIPv6Address`].
///
/// # Safety
///
/// As [`WinDivertHelperNtohIPv6Address`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertHelperNtohIpv6Address(inp: *const u32, out: *mut u32) {
    // SAFETY: the caller's contract.
    unsafe { swap_ipv6(inp, out) }
}

/// The older spelling of [`WinDivertHelperHtonIPv6Address`].
///
/// # Safety
///
/// As [`WinDivertHelperHtonIPv6Address`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn WinDivertHelperHtonIpv6Address(inp: *const u32, out: *mut u32) {
    // SAFETY: the caller's contract.
    unsafe { swap_ipv6(inp, out) }
}

/// Reverses the order of the four words and of each word's bytes: the conversion is its own
/// inverse.
///
/// # Safety
///
/// `inp` and `out` are valid for 4 words; they may be the same.
unsafe fn swap_ipv6(inp: *const u32, out: *mut u32) {
    if inp.is_null() || out.is_null() {
        return;
    }
    // SAFETY: the caller's contract; read everything before writing, for `inp == out`.
    unsafe {
        let w = [*inp, *inp.add(1), *inp.add(2), *inp.add(3)];
        for i in 0..4 {
            out.add(i).write(w[3 - i].swap_bytes());
        }
    }
}
