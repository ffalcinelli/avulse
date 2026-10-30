//! libebpfdivert's C API (`include/ebpfdivert.h` in ebpfdivert), over avulse.
//!
//! Functions return 0 (or a count) on success and a negative `errno` on failure, as
//! libebpfdivert does: `EINVAL` for a bad argument or filter, `EOPNOTSUPP` for what the backend
//! cannot do, `ESHUTDOWN` once shut down, `EAGAIN` on a timeout, `ENOBUFS` for a packet larger
//! than the buffer (it is dropped), `EPERM` to receive on a `SEND_ONLY` handle or send on a
//! `RECV_ONLY` one, `EBADF` on a handle being closed, and the system's error otherwise. A panic
//! aborts the process (`extern "C"`); the code avoids them.

#![allow(non_camel_case_types)]

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

use avulse::{
    Address, Error, Filter, Flags, Handle, Layer, MAX_PACKET_LEN, OpenOptions, Param, Shutdown,
    Syntax,
};

use crate::WdAddress;
use crate::helpers::{self, Invalid};

/// `EBPFDIVERT_MTU_MAX`: the largest packet `send` takes.
const MTU_MAX: u32 = 40 + 0xffff;

/// `EBPFDIVERT_PARAM_VERSION_MAJOR` and `_MINOR`: the WinDivert API level, 2.2.
const PARAM_VERSION_MAJOR: c_int = 3;
const PARAM_VERSION_MINOR: c_int = 4;

/// libebpfdivert's statistics, in `STAT_*` order: diverted, dropped, sniffed, parsing errors,
/// ring buffer full, queue full, too big, owner gone.
const STATS: usize = 8;

thread_local! {
    static TEXT: RefCell<CString> = RefCell::new(CString::default());
    static SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Keeps `s` for the calling thread, until its next call that returns text.
fn keep_text(s: &str) -> *const c_char {
    let s = CString::new(s.replace('\0', " ")).unwrap_or_default();
    TEXT.with(|t| {
        *t.borrow_mut() = s;
        t.borrow().as_ptr()
    })
}

/// The negative `errno` of `e`.
fn errno(e: &Error) -> c_int {
    -match e {
        Error::Filter(_) | Error::InvalidArgument(_) => libc::EINVAL,
        Error::Unsupported(_) => libc::EOPNOTSUPP,
        Error::Shutdown => libc::ESHUTDOWN,
        Error::Timeout => libc::EAGAIN,
        Error::BufferTooSmall { .. } => libc::ENOBUFS,
        Error::Io(io) => io.raw_os_error().unwrap_or(libc::EIO),
        _ => libc::EIO,
    }
}

const EINVAL: c_int = -libc::EINVAL;

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
fn layer(n: c_int) -> Option<Layer> {
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
        unsafe { p.write_unaligned(v) };
    }
}

/// `struct ebpfdivert_open_opts`.
#[repr(C)]
pub struct ebpfdivert_open_opts {
    /// `sizeof(struct ebpfdivert_open_opts)`.
    pub sz: usize,
    /// The interfaces to capture on, NULL-terminated; NULL for all of them.
    pub ifnames: *const *const c_char,
    /// The kernel ring buffer's size. Accepted, and ignored: avulse sizes its own.
    pub ring_bytes: u32,
}

/// An open handle: the avulse handle, and the calls in progress, which `close` waits for.
pub struct ebpfdivert_handle {
    handle: Handle,
    calls: Mutex<Calls>,
    idle: Condvar,
}

#[derive(Default)]
struct Calls {
    inflight: usize,
    closing: bool,
}

impl ebpfdivert_handle {
    fn calls(&self) -> MutexGuard<'_, Calls> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Runs `f` on the handle, unless it is NULL or being closed, and counts it as in progress.
///
/// # Safety
///
/// `h` is NULL or a handle `ebpfdivert_open` returned that `ebpfdivert_close` has not freed.
unsafe fn guarded(h: *mut ebpfdivert_handle, f: impl FnOnce(&Handle) -> c_int) -> c_int {
    if h.is_null() {
        return EINVAL;
    }
    // SAFETY: the caller's contract.
    let h = unsafe { &*h };
    {
        let mut c = h.calls();
        if c.closing {
            return -libc::EBADF;
        }
        c.inflight += 1;
    }
    let r = f(&h.handle);
    let mut c = h.calls();
    c.inflight -= 1;
    if c.inflight == 0 {
        h.idle.notify_all();
    }
    r
}

/// The library's version.
#[unsafe(no_mangle)]
pub extern "C" fn ebpfdivert_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Sets a log callback. avulse does not log, so it is never called.
#[unsafe(no_mangle)]
pub extern "C" fn ebpfdivert_set_print(_print: *const c_void) {}

/// Opens a handle with a WinDivert filter. Returns NULL and sets `errno` on failure.
///
/// # Safety
///
/// `filter` is a NUL-terminated string; `opts` is NULL or valid, with `ifnames` NULL or a
/// NULL-terminated array of NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ebpfdivert_open(
    filter: *const c_char,
    layer: c_int,
    priority: i16,
    flags: u64,
    opts: *const ebpfdivert_open_opts,
) -> *mut ebpfdivert_handle {
    // SAFETY: the caller's contract.
    match unsafe { open(filter, layer, priority, flags, opts) } {
        Ok(h) => Box::into_raw(Box::new(h)),
        Err(e) => {
            // SAFETY: the thread's errno.
            unsafe { *libc::__errno_location() = -e };
            std::ptr::null_mut()
        }
    }
}

/// Opens a handle, for FFIs that cannot read `errno`: returns 0 and stores the handle in `*out`,
/// or a negative `errno`.
///
/// # Safety
///
/// As [`ebpfdivert_open`], and `out` is valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ebpfdivert_open_ex(
    filter: *const c_char,
    layer: c_int,
    priority: i16,
    flags: u64,
    opts: *const ebpfdivert_open_opts,
    out: *mut *mut ebpfdivert_handle,
) -> c_int {
    if out.is_null() {
        return EINVAL;
    }
    // SAFETY: the caller's contract.
    match unsafe { open(filter, layer, priority, flags, opts) } {
        Ok(h) => {
            // SAFETY: valid for a write, per the contract.
            unsafe { *out = Box::into_raw(Box::new(h)) };
            0
        }
        Err(e) => {
            // SAFETY: valid for a write, per the contract.
            unsafe { *out = std::ptr::null_mut() };
            e
        }
    }
}

/// # Safety
///
/// As [`ebpfdivert_open`].
unsafe fn open(
    filter: *const c_char,
    layer: c_int,
    priority: i16,
    flags: u64,
    opts: *const ebpfdivert_open_opts,
) -> Result<ebpfdivert_handle, c_int> {
    // SAFETY: the caller's contract.
    let src = unsafe { text(filter) }.ok_or(EINVAL)?;
    let layer = self::layer(layer).ok_or(EINVAL)?;
    let flags = Flags::from_bits(flags).ok_or(EINVAL)?;
    let mut names = Vec::new();
    // SAFETY: valid or NULL, per the contract.
    if let Some(o) = unsafe { opts.as_ref() }
        && o.sz >= std::mem::offset_of!(ebpfdivert_open_opts, ring_bytes)
        && !o.ifnames.is_null()
    {
        for i in 0.. {
            // SAFETY: a NULL-terminated array, per the contract.
            let name = unsafe { *o.ifnames.add(i) };
            if name.is_null() {
                break;
            }
            // SAFETY: a NUL-terminated string, per the contract.
            names.push(unsafe { text(name) }.ok_or(EINVAL)?.to_owned());
        }
    }
    let mut options = OpenOptions::new();
    options
        .priority(priority)
        .flags(flags)
        .syntax(Syntax::WinDivert);
    if !names.is_empty() {
        options.interfaces(names);
    }
    let handle = options.open(src, layer).map_err(|e| errno(&e))?;
    Ok(ebpfdivert_handle {
        handle,
        calls: Mutex::new(Calls::default()),
        idle: Condvar::new(),
    })
}

/// A negative timeout blocks, 0 polls.
fn timeout(ms: c_int) -> Option<Duration> {
    u64::try_from(ms).ok().map(Duration::from_millis)
}

/// Runs `f` on `buf` when the caller wants packet data (`wants_data`), or on a scratch buffer of
/// the largest packet when `pkt` was NULL (the caller wants the length and the address only).
fn with_buffer<R>(buf: &mut [u8], wants_data: bool, f: impl FnOnce(&mut [u8]) -> R) -> R {
    if wants_data {
        return f(buf);
    }
    SCRATCH.with(|s| {
        let mut s = s.borrow_mut();
        s.resize(MAX_PACKET_LEN, 0);
        f(&mut s)
    })
}

/// Receives one packet or event. A negative timeout blocks, 0 polls. With `pkt` NULL, only the
/// length and the address are returned.
///
/// # Safety
///
/// `h` is an open handle; `pkt` is NULL or valid for `pkt_len` bytes; `recv_len` and `addr` are
/// NULL or valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ebpfdivert_recv(
    h: *mut ebpfdivert_handle,
    pkt: *mut c_void,
    pkt_len: u32,
    recv_len: *mut u32,
    addr: *mut WdAddress,
    timeout_ms: c_int,
) -> c_int {
    // SAFETY: the caller's contract.
    unsafe {
        guarded(h, |h| {
            if h.flags().contains(Flags::SEND_ONLY) {
                return -libc::EPERM;
            }
            let buf = bytes_mut(pkt, pkt_len);
            let wants_data = !pkt.is_null();
            let r = if h.layer() == Layer::Reflect {
                recv_reflect(h, buf, wants_data, timeout(timeout_ms))
            } else {
                with_buffer(buf, wants_data, |buf| match timeout(timeout_ms) {
                    Some(t) => h.recv_timeout(buf, t),
                    None => h.recv(buf),
                })
            };
            match r {
                Ok((n, a)) => {
                    put(recv_len, n as u32);
                    put(addr, WdAddress::from_avulse(&a));
                    0
                }
                Err(Error::BufferTooSmall { needed }) if wants_data => {
                    put(recv_len, needed as u32);
                    -libc::ENOBUFS
                }
                Err(e) => errno(&e),
            }
        })
    }
}

/// A REFLECT event with WinDivert's data: a filter written in WinDivert's syntax becomes
/// WinDivert's serialized filter object, with its NUL, as WinDivert reports it. A native filter
/// stays as it is: WinDivert has no object for it.
fn recv_reflect(
    h: &Handle,
    buf: &mut [u8],
    wants_data: bool,
    timeout: Option<Duration>,
) -> avulse::Result<(usize, Address)> {
    let (data, a) = with_buffer(&mut [], false, |scratch| {
        let (n, a) = match timeout {
            Some(t) => h.recv_timeout(scratch, t),
            None => h.recv(scratch),
        }?;
        let raw = &scratch[..n];
        let object = match (a.reflect.syntax, std::str::from_utf8(raw)) {
            (Syntax::WinDivert, Ok(src)) => Filter::windivert_object(src, a.reflect.layer).ok(),
            _ => None,
        };
        let data = match object {
            Some(o) => {
                let mut o = o.into_bytes();
                o.push(0);
                o
            }
            None => raw.to_vec(),
        };
        Ok::<_, Error>((data, a))
    })?;
    // As for packets, one that does not fit is dropped; no buffer asks for the length only.
    if wants_data {
        buf.get_mut(..data.len())
            .ok_or(Error::BufferTooSmall { needed: data.len() })?
            .copy_from_slice(&data);
    }
    Ok((data.len(), a))
}

/// Receives up to `*addr_len` packets back to back into `pkt`. Waits only for the first. On
/// return `*addr_len` is how many, and `*recv_len` their total length.
///
/// # Safety
///
/// `h` is an open handle; `pkt` is NULL or valid for `pkt_len` bytes; `addr_len` is valid;
/// `addrs` is NULL or valid for `*addr_len` addresses; `recv_len` is NULL or valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ebpfdivert_recv_ex(
    h: *mut ebpfdivert_handle,
    pkt: *mut c_void,
    pkt_len: u32,
    recv_len: *mut u32,
    addrs: *mut WdAddress,
    addr_len: *mut u32,
    timeout_ms: c_int,
) -> c_int {
    if addr_len.is_null() {
        return EINVAL;
    }
    // SAFETY: not NULL, per the check above.
    let max = unsafe { addr_len.read_unaligned() };
    if max == 0 {
        return EINVAL;
    }
    // SAFETY: the caller's contract.
    unsafe {
        guarded(h, |h| {
            if h.flags().contains(Flags::SEND_ONLY) {
                return -libc::EPERM;
            }
            let max = max as usize;
            let mut got = vec![Address::default(); max];
            let mut lens = vec![0; max];
            let buf = bytes_mut(pkt, pkt_len);
            let wants_data = !pkt.is_null();
            // REFLECT events one at a time: their data changes length on the way.
            let r = if h.layer() == Layer::Reflect {
                recv_reflect(h, buf, wants_data, timeout(timeout_ms)).map(|(n, a)| {
                    (got[0], lens[0]) = (a, n);
                    1
                })
            } else {
                with_buffer(buf, wants_data, |buf| {
                    h.recv_batch(buf, &mut got, &mut lens, timeout(timeout_ms))
                })
            };
            match r {
                Ok(k) => {
                    for (i, a) in got[..k].iter().enumerate() {
                        if !addrs.is_null() {
                            put(addrs.add(i), WdAddress::from_avulse(a));
                        }
                    }
                    put(addr_len, k as u32);
                    put(recv_len, lens[..k].iter().sum::<usize>() as u32);
                    0
                }
                Err(Error::BufferTooSmall { needed }) if wants_data => {
                    put(addr_len, 0);
                    put(recv_len, needed as u32);
                    -libc::ENOBUFS
                }
                Err(e) => errno(&e),
            }
        })
    }
}

/// The packet `pkt` was received with `addr` goes on, or a new one goes where `addr` says.
fn send_one(h: &Handle, pkt: &[u8], addr: &WdAddress) -> c_int {
    if h.flags().contains(Flags::RECV_ONLY) {
        return -libc::EPERM;
    }
    if !matches!(h.layer(), Layer::Network | Layer::NetworkForward) {
        return EINVAL;
    }
    if pkt.len() > MTU_MAX as usize {
        return -libc::EMSGSIZE;
    }
    let Ok(addr) = addr.to_avulse() else {
        return EINVAL;
    };
    match h.send(pkt, &addr) {
        Ok(_) => 0,
        Err(e) => errno(&e),
    }
}

/// Sends (or reinjects) a packet. The address decides the direction and the interface.
///
/// # Safety
///
/// `h` is an open handle; `pkt` is valid for `pkt_len` bytes; `addr` is valid; `send_len` is
/// NULL or valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ebpfdivert_send(
    h: *mut ebpfdivert_handle,
    pkt: *const c_void,
    pkt_len: u32,
    send_len: *mut u32,
    addr: *const WdAddress,
) -> c_int {
    if pkt.is_null() || addr.is_null() {
        return EINVAL;
    }
    // SAFETY: the caller's contract.
    unsafe {
        guarded(h, |h| {
            let r = send_one(h, bytes(pkt, pkt_len), &addr.read_unaligned());
            if r == 0 {
                put(send_len, pkt_len);
            }
            r
        })
    }
}

/// Sends `addr_len` packets that are back to back in `pkt`, each as long as its IP header says.
/// Returns an error only if the first one fails; `*send_len` is the bytes sent.
///
/// # Safety
///
/// `h` is an open handle; `pkt` is valid for `pkt_len` bytes; `addrs` is valid for `addr_len`
/// addresses; `send_len` is NULL or valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ebpfdivert_send_ex(
    h: *mut ebpfdivert_handle,
    pkt: *const c_void,
    pkt_len: u32,
    send_len: *mut u32,
    addrs: *const WdAddress,
    addr_len: u32,
) -> c_int {
    if pkt.is_null() || addrs.is_null() || addr_len == 0 {
        return EINVAL;
    }
    // SAFETY: the caller's contract.
    unsafe {
        guarded(h, |h| {
            let all = bytes(pkt, pkt_len);
            let (mut off, mut sent, mut r) = (0, 0u32, 0);
            for i in 0..addr_len as usize {
                if off >= all.len() {
                    break;
                }
                let p = &all[off..];
                let (len, min) = match p.first().map(|b| b >> 4) {
                    Some(4) if p.len() >= 20 => (usize::from(u16::from_be_bytes([p[2], p[3]])), 20),
                    Some(6) if p.len() >= 40 => {
                        (40 + usize::from(u16::from_be_bytes([p[4], p[5]])), 40)
                    }
                    _ if i > 0 => break,
                    _ => return EINVAL,
                };
                if len < min || len > p.len() {
                    if i > 0 {
                        break;
                    }
                    return EINVAL;
                }
                r = send_one(h, &p[..len], &addrs.add(i).read_unaligned());
                if r != 0 {
                    break;
                }
                off += len;
                sent += len as u32;
            }
            put(send_len, sent);
            if sent == 0 && r != 0 { r } else { 0 }
        })
    }
}

/// Stops receiving (1), sending (2) or both (3). Packets already queued are still received.
///
/// # Safety
///
/// `h` is an open handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ebpfdivert_shutdown(h: *mut ebpfdivert_handle, how: c_int) -> c_int {
    let how = match how {
        1 => Shutdown::Recv,
        2 => Shutdown::Send,
        3 => Shutdown::Both,
        _ => return EINVAL,
    };
    // SAFETY: the caller's contract.
    unsafe { guarded(h, |h| h.shutdown(how).map_or_else(|e| errno(&e), |()| 0)) }
}

/// Closes a handle: shuts it down, waits for the calls in progress on other threads, then frees
/// it.
///
/// # Safety
///
/// `h` is an open handle, not used again after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ebpfdivert_close(h: *mut ebpfdivert_handle) -> c_int {
    if h.is_null() {
        return EINVAL;
    }
    {
        // SAFETY: open, per the contract.
        let handle = unsafe { &*h };
        let mut c = handle.calls();
        if c.closing {
            return -libc::EBADF;
        }
        c.closing = true;
        drop(c);
        // Wakes the receivers that are waiting.
        let _ = handle.handle.shutdown(Shutdown::Both);
        let mut c = handle.calls();
        while c.inflight > 0 {
            c = handle.idle.wait(c).unwrap_or_else(|e| e.into_inner());
        }
    }
    // SAFETY: it came from `Box::into_raw`, and no call is using it any more.
    let h = unsafe { Box::from_raw(h) };
    h.handle.close().map_or_else(|e| errno(&e), |()| 0)
}

fn param(n: c_int) -> Option<Param> {
    match n {
        0 => Some(Param::QueueLength),
        1 => Some(Param::QueueTime),
        2 => Some(Param::QueueSize),
        _ => None,
    }
}

/// Sets a queue parameter.
///
/// # Safety
///
/// `h` is an open handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ebpfdivert_set_param(
    h: *mut ebpfdivert_handle,
    param: c_int,
    value: u64,
) -> c_int {
    let Some(p) = self::param(param) else {
        return EINVAL;
    };
    // SAFETY: the caller's contract.
    unsafe {
        guarded(h, |h| {
            h.set_param(p, value).map_or_else(|e| errno(&e), |()| 0)
        })
    }
}

/// Reads a queue parameter, or the WinDivert API version (2.2).
///
/// # Safety
///
/// `h` is an open handle; `value` is valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ebpfdivert_get_param(
    h: *mut ebpfdivert_handle,
    param: c_int,
    value: *mut u64,
) -> c_int {
    if value.is_null() {
        return EINVAL;
    }
    // SAFETY: the caller's contract.
    unsafe {
        guarded(h, |h| {
            let v = match param {
                PARAM_VERSION_MAJOR | PARAM_VERSION_MINOR => 2,
                p => match self::param(p) {
                    Some(p) => h.param(p),
                    None => return EINVAL,
                },
            };
            put(value, v);
            0
        })
    }
}

/// A descriptor that is readable when `ebpfdivert_recv` would not block. The handle owns it.
///
/// # Safety
///
/// `h` is an open handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ebpfdivert_get_event_fd(h: *mut ebpfdivert_handle) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { guarded(h, |h| h.as_fd().as_raw_fd()) }
}

/// The handle's counters, in libebpfdivert's `STAT_*` order. Returns how many it wrote.
///
/// # Safety
///
/// `h` is an open handle; `stats` is valid for `stats_len` values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ebpfdivert_get_handle_stats(
    h: *mut ebpfdivert_handle,
    stats: *mut u64,
    stats_len: c_int,
) -> c_int {
    if stats.is_null() || stats_len <= 0 {
        return EINVAL;
    }
    // SAFETY: the caller's contract.
    unsafe {
        guarded(h, |h| {
            let s = match h.stats() {
                Ok(s) => s,
                Err(e) => return errno(&e),
            };
            let values: [u64; STATS] = [
                s.diverted,
                s.dropped,
                s.sniffed,
                s.load_errors,
                s.ring_full,
                s.queue_drops,
                s.too_big,
                s.owner_gone,
            ];
            let n = (stats_len as usize).min(STATS);
            for (i, &v) in values[..n].iter().enumerate() {
                stats.add(i).write_unaligned(v);
            }
            n as c_int
        })
    }
}

/// Removes what handles of processes that died left behind.
#[unsafe(no_mangle)]
pub extern "C" fn ebpfdivert_unregister() -> c_int {
    avulse::cleanup().map_or_else(|e| errno(&e), |_| 0)
}

/// The description of a positive or negative `errno` value, kept for the calling thread.
#[unsafe(no_mangle)]
pub extern "C" fn ebpfdivert_strerror(err: c_int) -> *const c_char {
    let err = err.checked_abs().unwrap_or(0);
    let mut buf = [0 as c_char; 128];
    // SAFETY: `buf` is valid for its length.
    let r = unsafe { libc::strerror_r(err, buf.as_mut_ptr(), buf.len()) };
    let s = if r == 0 {
        // SAFETY: `strerror_r` wrote a NUL-terminated string.
        unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    } else {
        format!("Unknown error {err}")
    };
    keep_text(&s)
}

/// Checks a WinDivert filter for `layer`. On error returns `-EINVAL`, with the description in
/// `*err_str` (kept for the calling thread) and the offset of the error in `*err_pos`.
///
/// # Safety
///
/// `filter` is a NUL-terminated string; `err_str` and `err_pos` are NULL or valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ebpfdivert_helper_compile_filter(
    filter: *const c_char,
    layer: c_int,
    err_str: *mut *const c_char,
    err_pos: *mut u32,
) -> c_int {
    // SAFETY: valid or NULL, per the contract.
    unsafe {
        put(err_str, std::ptr::null());
        put(err_pos, 0);
    }
    // SAFETY: the caller's contract.
    let (Some(src), Some(layer)) = (unsafe { text(filter) }, self::layer(layer)) else {
        return EINVAL;
    };
    match helpers::check_filter(src, layer) {
        Ok(()) => 0,
        Err(d) => {
            // SAFETY: valid or NULL, per the contract.
            unsafe {
                put(err_str, keep_text(&d.message));
                put(err_pos, d.span.start as u32);
            }
            EINVAL
        }
    }
}

/// Whether a packet with its address matches a WinDivert filter (compiled at the address's
/// layer): 1, 0, or `-EINVAL` for a bad filter, packet or address.
///
/// # Safety
///
/// `filter` is a NUL-terminated string; `pkt` is NULL or valid for `pkt_len` bytes; `addr` is
/// valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ebpfdivert_helper_eval_filter(
    filter: *const c_char,
    pkt: *const c_void,
    pkt_len: u32,
    addr: *const WdAddress,
) -> c_int {
    if addr.is_null() {
        return EINVAL;
    }
    // SAFETY: the caller's contract.
    let (Some(src), addr) = (unsafe { text(filter) }, unsafe { addr.read_unaligned() }) else {
        return EINVAL;
    };
    let Ok(addr) = addr.to_avulse() else {
        return EINVAL;
    };
    // SAFETY: the caller's contract.
    match helpers::eval_filter(src, unsafe { bytes(pkt, pkt_len) }, &addr) {
        Ok(m) => c_int::from(m),
        Err(Invalid::Filter(_) | Invalid::Argument(_)) => EINVAL,
    }
}

/// Writes a WinDivert filter in canonical form to `buf`. `-EINVAL` for a bad filter, `-ENOBUFS`
/// if it does not fit.
///
/// # Safety
///
/// `filter` is a NUL-terminated string; `buf` is valid for `buf_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ebpfdivert_helper_format_filter(
    filter: *const c_char,
    layer: c_int,
    buf: *mut c_char,
    buf_len: u32,
) -> c_int {
    // SAFETY: the caller's contract.
    let (Some(src), Some(layer)) = (unsafe { text(filter) }, self::layer(layer)) else {
        return EINVAL;
    };
    if buf.is_null() {
        return EINVAL;
    }
    let Ok(out) = helpers::format_filter(src, layer) else {
        return EINVAL;
    };
    if out.len() >= buf_len as usize {
        return -libc::ENOBUFS;
    }
    // SAFETY: `buf` has room for the text and its NUL.
    unsafe {
        std::ptr::copy_nonoverlapping(out.as_ptr(), buf.cast(), out.len());
        *buf.add(out.len()) = 0;
    }
    0
}

/// Recomputes the checksums of a packet in place, except those `flags` excludes
/// (`WINDIVERT_HELPER_NO_*`), and sets the address's checksum bits for those it computed.
/// `-EINVAL` where WinDivert fails.
///
/// # Safety
///
/// `pkt` is valid for `pkt_len` bytes; `addr` is NULL or valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ebpfdivert_helper_calc_checksums(
    pkt: *mut c_void,
    pkt_len: u32,
    addr: *mut WdAddress,
    flags: u64,
) -> c_int {
    if pkt.is_null() {
        return EINVAL;
    }
    // SAFETY: the caller's contract.
    let (ok, set) = helpers::calc_checksums(unsafe { bytes_mut(pkt, pkt_len) }, flags);
    if !addr.is_null() {
        // SAFETY: valid, per the contract.
        let mut a = unsafe { addr.read_unaligned() };
        a.set_checksums(set.ip, set.tcp, set.udp);
        // SAFETY: valid, per the contract.
        unsafe { addr.write_unaligned(a) };
    }
    if ok { 0 } else { EINVAL }
}

/// WinDivert's hash of a packet's headers, seeded; 0 for a packet it cannot parse.
///
/// # Safety
///
/// `pkt` is NULL or valid for `pkt_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ebpfdivert_helper_hash_packet(
    pkt: *const c_void,
    pkt_len: u32,
    seed: u64,
) -> u64 {
    // SAFETY: the caller's contract.
    helpers::hash_packet(unsafe { bytes(pkt, pkt_len) }, seed)
}
