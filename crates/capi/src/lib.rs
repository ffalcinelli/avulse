//! The C ABI of libavulse, as `include/avulse.h` declares it.
//!
//! Every function returns `AVULSE_OK` or a negative `AVULSE_E_*` status, and keeps the error's
//! description for `avulse_last_error` (per thread). The address crosses the boundary as
//! [`avulse_address`], which has the layout of [`avulse_rs::Address`] but integers where Rust
//! has `bool`s and enums: it is converted field by field and checked, so no value C passes is
//! undefined behaviour here. A panic aborts the process (`extern "C"`); the code avoids them.

#![allow(non_camel_case_types)]

use std::cell::{Cell, RefCell};
use std::ffi::{CStr, CString, c_char, c_int};
use std::time::Duration;

use avulse_filter::{Event, Filter, Layer};
use avulse_proto::{Link, Packet};
use avulse_rs::{Address, Context, Error, Flags, Handle, OpenOptions, Param, Shutdown, Syntax};

/// Success.
pub const AVULSE_OK: c_int = 0;
/// The filter does not compile.
pub const AVULSE_E_FILTER: c_int = -1;
/// An argument is out of range or does not apply.
pub const AVULSE_E_INVALID: c_int = -2;
/// This platform's backend cannot do it.
pub const AVULSE_E_UNSUPPORTED: c_int = -3;
/// The handle was shut down in this direction.
pub const AVULSE_E_SHUTDOWN: c_int = -4;
/// Nothing arrived in time.
pub const AVULSE_E_TIMEOUT: c_int = -5;
/// The packet does not fit the buffer.
pub const AVULSE_E_BUFFER: c_int = -6;
/// The system refused.
pub const AVULSE_E_IO: c_int = -7;

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
    static LAST_OS_ERROR: Cell<c_int> = const { Cell::new(0) };
}

fn set_error(message: String, os: c_int) {
    let message = CString::new(message.replace('\0', " ")).unwrap_or_default();
    LAST_ERROR.with(|e| *e.borrow_mut() = message);
    LAST_OS_ERROR.with(|e| e.set(os));
}

/// The status of `e`, keeping its description; `src` is the filter, for diagnostics.
fn fail(e: Error, src: &str) -> c_int {
    let (status, os) = match &e {
        Error::Filter(_) => (AVULSE_E_FILTER, 0),
        Error::InvalidArgument(_) => (AVULSE_E_INVALID, 0),
        Error::Unsupported(_) => (AVULSE_E_UNSUPPORTED, 0),
        Error::Shutdown => (AVULSE_E_SHUTDOWN, 0),
        Error::Timeout => (AVULSE_E_TIMEOUT, 0),
        Error::BufferTooSmall { .. } => (AVULSE_E_BUFFER, 0),
        Error::Io(io) => (AVULSE_E_IO, io.raw_os_error().unwrap_or(0)),
        _ => (AVULSE_E_IO, 0),
    };
    let message = match &e {
        Error::Filter(d) => d.render(src),
        e => e.to_string(),
    };
    set_error(message, os);
    status
}

fn invalid(what: &str) -> c_int {
    set_error(format!("invalid argument: {what}"), 0);
    AVULSE_E_INVALID
}

/// A C string as UTF-8.
///
/// # Safety
///
/// `s` is NULL or a NUL-terminated string.
unsafe fn text<'a>(s: *const c_char, what: &str) -> Result<&'a str, c_int> {
    if s.is_null() {
        return Err(invalid(&format!("{what} is NULL")));
    }
    // SAFETY: the caller's contract.
    unsafe { CStr::from_ptr(s) }
        .to_str()
        .map_err(|_| invalid(&format!("{what} is not UTF-8")))
}

fn layer(n: u8) -> Result<Layer, c_int> {
    Layer::try_from(n).map_err(|_| invalid("unknown layer"))
}

/// `struct avulse_flow`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct avulse_flow {
    /// The endpoint (socket) ID.
    pub endpoint_id: u64,
    /// The parent endpoint ID.
    pub parent_endpoint_id: u64,
    /// The process ID.
    pub process_id: u32,
    /// The local port.
    pub local_port: u16,
    /// The remote port.
    pub remote_port: u16,
    /// The local address, IPv4-mapped for IPv4.
    pub local_addr: [u8; 16],
    /// The remote address.
    pub remote_addr: [u8; 16],
    /// The IP protocol.
    pub protocol: u8,
    /// Zero.
    pub reserved: [u8; 7],
    /// The process name, UTF-8, NUL-padded.
    pub process_name: [u8; 32],
}

/// `struct avulse_reflect`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct avulse_reflect {
    /// When the handle was opened.
    pub timestamp: i64,
    /// Its flags.
    pub flags: u64,
    /// Its process.
    pub process_id: u32,
    /// Its priority.
    pub priority: i16,
    /// Its layer.
    pub layer: u8,
    /// `AVULSE_SYNTAX_*` of its filter, the event's data.
    pub syntax: u8,
}

/// `struct avulse_address`: [`Address`]'s layout, with integers for its `bool`s and enums.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct avulse_address {
    /// Nanoseconds of the monotonic clock.
    pub timestamp: i64,
    /// `AVULSE_ADDRESS_VERSION`.
    pub version: u16,
    /// The layer.
    pub layer: u8,
    /// The event.
    pub event: u8,
    /// Direction.
    pub outbound: u8,
    /// On a loopback interface.
    pub loopback: u8,
    /// Injected by another handle.
    pub impostor: u8,
    /// Received as a copy.
    pub sniffed: u8,
    /// IPv6.
    pub ipv6: u8,
    /// The IPv4 header checksum is valid.
    pub ip_checksum: u8,
    /// The TCP checksum is valid.
    pub tcp_checksum: u8,
    /// The UDP checksum is valid.
    pub udp_checksum: u8,
    /// The interface.
    pub if_idx: u32,
    /// The sub-interface.
    pub sub_if_idx: u32,
    /// The outer VLAN tag.
    pub vlan_tci: u16,
    /// Whether there was a VLAN tag.
    pub vlan: u8,
    /// Zero.
    pub reserved: u8,
    /// FLOW and SOCKET events.
    pub flow: avulse_flow,
    /// REFLECT events.
    pub reflect: avulse_reflect,
    /// The reinjection context.
    pub context: [u8; 64],
}

impl From<&Address> for avulse_address {
    fn from(a: &Address) -> Self {
        let f = &a.flow;
        let mut name = [0u8; 32];
        if let Some(n) = f.process_name() {
            name[..n.len()].copy_from_slice(n.as_bytes());
        }
        let r = &a.reflect;
        avulse_address {
            timestamp: a.timestamp,
            version: a.version(),
            layer: a.layer as u8,
            event: a.event as u8,
            outbound: a.outbound.into(),
            loopback: a.loopback.into(),
            impostor: a.impostor.into(),
            sniffed: a.sniffed.into(),
            ipv6: a.ipv6.into(),
            ip_checksum: a.ip_checksum.into(),
            tcp_checksum: a.tcp_checksum.into(),
            udp_checksum: a.udp_checksum.into(),
            if_idx: a.if_idx,
            sub_if_idx: a.sub_if_idx,
            vlan_tci: a.vlan_tci,
            vlan: a.vlan.into(),
            reserved: 0,
            flow: avulse_flow {
                endpoint_id: f.endpoint_id,
                parent_endpoint_id: f.parent_endpoint_id,
                process_id: f.process_id,
                local_port: f.local_port,
                remote_port: f.remote_port,
                local_addr: f.local_addr,
                remote_addr: f.remote_addr,
                protocol: f.protocol,
                reserved: [0; 7],
                process_name: name,
            },
            reflect: avulse_reflect {
                timestamp: r.timestamp,
                flags: r.flags.bits(),
                process_id: r.process_id,
                priority: r.priority,
                layer: r.layer as u8,
                syntax: r.syntax as u8,
            },
            context: *a.context.as_bytes(),
        }
    }
}

impl TryFrom<&avulse_address> for Address {
    type Error = &'static str;

    fn try_from(c: &avulse_address) -> Result<Address, &'static str> {
        let mut a = Address::new(Layer::try_from(c.layer).map_err(|_| "unknown layer")?);
        a.timestamp = c.timestamp;
        a.event = Event::try_from(c.event).map_err(|_| "unknown event")?;
        a.outbound = c.outbound != 0;
        a.loopback = c.loopback != 0;
        a.impostor = c.impostor != 0;
        a.sniffed = c.sniffed != 0;
        a.ipv6 = c.ipv6 != 0;
        a.ip_checksum = c.ip_checksum != 0;
        a.tcp_checksum = c.tcp_checksum != 0;
        a.udp_checksum = c.udp_checksum != 0;
        a.if_idx = c.if_idx;
        a.sub_if_idx = c.sub_if_idx;
        a.vlan_tci = c.vlan_tci;
        a.vlan = c.vlan != 0;
        let (f, cf) = (&mut a.flow, &c.flow);
        f.endpoint_id = cf.endpoint_id;
        f.parent_endpoint_id = cf.parent_endpoint_id;
        f.process_id = cf.process_id;
        f.local_port = cf.local_port;
        f.remote_port = cf.remote_port;
        f.local_addr = cf.local_addr;
        f.remote_addr = cf.remote_addr;
        f.protocol = cf.protocol;
        let n = cf.process_name.iter().position(|&b| b == 0).unwrap_or(32);
        if let Ok(name) = std::str::from_utf8(&cf.process_name[..n]) {
            f.set_process_name(name);
        }
        let (r, cr) = (&mut a.reflect, &c.reflect);
        r.timestamp = cr.timestamp;
        r.flags = Flags::from_bits(cr.flags).ok_or("unknown flags in reflect")?;
        r.process_id = cr.process_id;
        r.priority = cr.priority;
        r.layer = Layer::try_from(cr.layer).map_err(|_| "unknown layer in reflect")?;
        r.syntax = Syntax::try_from(cr.syntax).map_err(|_| "unknown syntax in reflect")?;
        a.context = Context::from_bytes(c.context);
        Ok(a)
    }
}

/// `struct avulse_stats`: [`avulse_rs::Stats`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct avulse_stats {
    /// Diverted to the handle.
    pub diverted: u64,
    /// Copied to the handle and passed on.
    pub sniffed: u64,
    /// Dropped.
    pub dropped: u64,
    /// Passed on: the kernel's buffer to the handle was full.
    pub ring_full: u64,
    /// Passed on: the owner stopped answering.
    pub owner_gone: u64,
    /// Passed on: too large to divert whole.
    pub too_big: u64,
    /// Passed on: the kernel could not copy them.
    pub load_errors: u64,
    /// Lost in user space: the queue was full, or they waited too long.
    pub queue_drops: u64,
}

/// `struct avulse_open_options`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct avulse_open_options {
    /// `sizeof(struct avulse_open_options)`.
    pub size: u32,
    /// The priority.
    pub priority: i16,
    /// `AVULSE_SYNTAX_*`.
    pub syntax: u8,
    /// `AVULSE_FLAG_*`.
    pub flags: u64,
    /// Interface names, or NULL for all.
    pub interfaces: *const *const c_char,
    /// How many.
    pub interface_count: usize,
}

/// An open handle.
pub struct avulse_handle {
    handle: Handle,
}

/// The library's version, as a static NUL-terminated string.
#[unsafe(no_mangle)]
pub extern "C" fn avulse_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// What the last failed call on this thread said; valid until the next call on the thread.
#[unsafe(no_mangle)]
pub extern "C" fn avulse_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().as_ptr())
}

/// The system's error number behind the last `AVULSE_E_IO` on this thread.
#[unsafe(no_mangle)]
pub extern "C" fn avulse_last_os_error() -> c_int {
    LAST_OS_ERROR.with(Cell::get)
}

fn syntax(n: u8) -> Result<Syntax, c_int> {
    match n {
        0 => Ok(Syntax::Native),
        1 => Ok(Syntax::WinDivert),
        _ => Err(invalid("unknown syntax")),
    }
}

/// Opens a handle with a native filter.
///
/// # Safety
///
/// `filter` is a NUL-terminated string; `handle` is valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_open(
    filter: *const c_char,
    layer: u8,
    priority: i16,
    flags: u64,
    handle: *mut *mut avulse_handle,
) -> c_int {
    let options = avulse_open_options {
        size: size_of::<avulse_open_options>() as u32,
        priority,
        syntax: 0,
        flags,
        interfaces: std::ptr::null(),
        interface_count: 0,
    };
    // SAFETY: the caller's contract, and `options` is valid.
    unsafe { avulse_open_ex(filter, layer, &options, handle) }
}

/// Opens a handle with options.
///
/// # Safety
///
/// `filter` is a NUL-terminated string; `options` is valid, with `interface_count` strings at
/// `interfaces` when it is not NULL; `handle` is valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_open_ex(
    filter: *const c_char,
    layer: u8,
    options: *const avulse_open_options,
    handle: *mut *mut avulse_handle,
) -> c_int {
    // SAFETY: the caller's contract.
    let src = match unsafe { text(filter, "the filter") } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if handle.is_null() || options.is_null() {
        return invalid("a pointer is NULL");
    }
    // SAFETY: not NULL, and valid per the contract.
    let o = unsafe { &*options };
    if (o.size as usize) < size_of::<avulse_open_options>() {
        return invalid("avulse_open_options.size is too small");
    }
    let layer = match self::layer(layer) {
        Ok(l) => l,
        Err(e) => return e,
    };
    let Some(flags) = Flags::from_bits(o.flags) else {
        return invalid("unknown flags");
    };
    let syntax = match syntax(o.syntax) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let mut names = Vec::new();
    if !o.interfaces.is_null() {
        for i in 0..o.interface_count {
            // SAFETY: `interface_count` strings at `interfaces`, per the contract.
            match unsafe { text(*o.interfaces.add(i), "an interface name") } {
                Ok(s) => names.push(s.to_owned()),
                Err(e) => return e,
            }
        }
    }
    let mut opts = OpenOptions::new();
    opts.priority(o.priority).flags(flags).syntax(syntax);
    if !names.is_empty() {
        opts.interfaces(names);
    }
    match opts.open(src, layer) {
        Ok(h) => {
            // SAFETY: valid for a write, per the contract.
            unsafe { *handle = Box::into_raw(Box::new(avulse_handle { handle: h })) };
            AVULSE_OK
        }
        Err(e) => fail(e, src),
    }
}

fn timeout(ms: i64) -> Option<Duration> {
    u64::try_from(ms).ok().map(Duration::from_millis)
}

/// Receives a packet or event.
///
/// # Safety
///
/// `handle` is open; `buf` is valid for `buf_len` bytes; `len` and `addr` are valid for a
/// write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_recv(
    handle: *mut avulse_handle,
    buf: *mut u8,
    buf_len: usize,
    len: *mut usize,
    addr: *mut avulse_address,
    timeout_ms: i64,
) -> c_int {
    if handle.is_null() || len.is_null() || addr.is_null() || (buf.is_null() && buf_len > 0) {
        return invalid("a pointer is NULL");
    }
    // SAFETY: valid per the contract.
    let (h, buf) = unsafe { (&(*handle).handle, slice_mut(buf, buf_len)) };
    let r = match timeout(timeout_ms) {
        Some(t) => h.recv_timeout(buf, t),
        None => h.recv(buf),
    };
    match r {
        Ok((n, a)) => {
            // SAFETY: valid for a write, per the contract.
            unsafe {
                *len = n;
                *addr = (&a).into();
            }
            AVULSE_OK
        }
        Err(e) => {
            if let Error::BufferTooSmall { needed } = e {
                // SAFETY: valid for a write, per the contract.
                unsafe { *len = needed };
            }
            fail(e, "")
        }
    }
}

/// A slice of `len` bytes at `p`, which may be NULL when `len` is 0.
///
/// # Safety
///
/// `p` is valid for `len` bytes.
unsafe fn slice_mut<'a>(p: *mut u8, len: usize) -> &'a mut [u8] {
    if len == 0 {
        return &mut [];
    }
    // SAFETY: the caller's contract.
    unsafe { std::slice::from_raw_parts_mut(p, len) }
}

/// Receives several packets or events.
///
/// # Safety
///
/// `handle` is open; `buf` is valid for `buf_len` bytes; `addrs` and `lens` for `n` writes;
/// `count` for one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_recv_batch(
    handle: *mut avulse_handle,
    buf: *mut u8,
    buf_len: usize,
    addrs: *mut avulse_address,
    lens: *mut usize,
    n: usize,
    count: *mut usize,
    timeout_ms: i64,
) -> c_int {
    if handle.is_null() || addrs.is_null() || lens.is_null() || count.is_null() || n == 0 {
        return invalid("a pointer is NULL, or n is 0");
    }
    if buf.is_null() && buf_len > 0 {
        return invalid("the buffer is NULL");
    }
    // SAFETY: valid per the contract.
    let (h, buf) = unsafe { (&(*handle).handle, slice_mut(buf, buf_len)) };
    let mut got = vec![Address::default(); n];
    // SAFETY: `lens` is valid for `n` writes.
    let lens = unsafe { std::slice::from_raw_parts_mut(lens, n) };
    match h.recv_batch(buf, &mut got, lens, timeout(timeout_ms)) {
        Ok(k) => {
            for (i, a) in got[..k].iter().enumerate() {
                // SAFETY: `addrs` is valid for `n` writes, and `i < k <= n`.
                unsafe { *addrs.add(i) = a.into() };
            }
            // SAFETY: valid for a write, per the contract.
            unsafe { *count = k };
            AVULSE_OK
        }
        Err(e) => fail(e, ""),
    }
}

/// Sends a packet.
///
/// # Safety
///
/// `handle` is open; `packet` is valid for `len` bytes; `addr` is valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_send(
    handle: *mut avulse_handle,
    packet: *const u8,
    len: usize,
    addr: *const avulse_address,
) -> c_int {
    if handle.is_null() || packet.is_null() || addr.is_null() {
        return invalid("a pointer is NULL");
    }
    // SAFETY: valid per the contract.
    let (h, packet, addr) = unsafe {
        (
            &(*handle).handle,
            std::slice::from_raw_parts(packet, len),
            &*addr,
        )
    };
    let addr = match Address::try_from(addr) {
        Ok(a) => a,
        Err(what) => return invalid(what),
    };
    match h.send(packet, &addr) {
        Ok(_) => AVULSE_OK,
        Err(e) => fail(e, ""),
    }
}

/// Sends several packets.
///
/// # Safety
///
/// `handle` is open; `packets`, `lens` and `addrs` are valid for `n` reads, and packet `i` for
/// `lens[i]` bytes; `sent` is valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_send_batch(
    handle: *mut avulse_handle,
    packets: *const *const u8,
    lens: *const usize,
    addrs: *const avulse_address,
    n: usize,
    sent: *mut usize,
) -> c_int {
    if handle.is_null() || packets.is_null() || lens.is_null() || addrs.is_null() {
        return invalid("a pointer is NULL");
    }
    if sent.is_null() || n == 0 {
        return invalid("sent is NULL, or n is 0");
    }
    let mut ps = Vec::with_capacity(n);
    let mut as_ = Vec::with_capacity(n);
    for i in 0..n {
        // SAFETY: valid for `n` reads, per the contract.
        let (p, len, a) = unsafe { (*packets.add(i), *lens.add(i), &*addrs.add(i)) };
        if p.is_null() {
            return invalid("a packet is NULL");
        }
        // SAFETY: packet `i` is valid for `lens[i]` bytes.
        ps.push(unsafe { std::slice::from_raw_parts(p, len) });
        match Address::try_from(a) {
            Ok(a) => as_.push(a),
            Err(what) => return invalid(what),
        }
    }
    // SAFETY: open, per the contract.
    let h = unsafe { &(*handle).handle };
    match h.send_batch(&ps, &as_) {
        Ok(k) => {
            // SAFETY: valid for a write, per the contract.
            unsafe { *sent = k };
            AVULSE_OK
        }
        Err(e) => fail(e, ""),
    }
}

/// Stops receiving, sending, or both.
///
/// # Safety
///
/// `handle` is open.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_shutdown(handle: *mut avulse_handle, how: c_int) -> c_int {
    let how = match how {
        1 => Shutdown::Recv,
        2 => Shutdown::Send,
        3 => Shutdown::Both,
        _ => return invalid("unknown shutdown direction"),
    };
    if handle.is_null() {
        return invalid("the handle is NULL");
    }
    // SAFETY: open, per the contract.
    match unsafe { &(*handle).handle }.shutdown(how) {
        Ok(()) => AVULSE_OK,
        Err(e) => fail(e, ""),
    }
}

fn param(n: c_int) -> Result<Param, c_int> {
    match n {
        0 => Ok(Param::QueueLength),
        1 => Ok(Param::QueueTime),
        2 => Ok(Param::QueueSize),
        _ => Err(invalid("unknown parameter")),
    }
}

/// Sets a queue parameter.
///
/// # Safety
///
/// `handle` is open.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_set_param(
    handle: *mut avulse_handle,
    param: c_int,
    value: u64,
) -> c_int {
    let p = match self::param(param) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if handle.is_null() {
        return invalid("the handle is NULL");
    }
    // SAFETY: open, per the contract.
    match unsafe { &(*handle).handle }.set_param(p, value) {
        Ok(()) => AVULSE_OK,
        Err(e) => fail(e, ""),
    }
}

/// Reads a queue parameter.
///
/// # Safety
///
/// `handle` is open; `value` is valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_get_param(
    handle: *const avulse_handle,
    param: c_int,
    value: *mut u64,
) -> c_int {
    let p = match self::param(param) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if handle.is_null() || value.is_null() {
        return invalid("a pointer is NULL");
    }
    // SAFETY: valid per the contract.
    unsafe { *value = (*handle).handle.param(p) };
    AVULSE_OK
}

/// The handle's counters.
///
/// # Safety
///
/// `handle` is open; `stats` is valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_stats(
    handle: *const avulse_handle,
    stats: *mut avulse_stats,
) -> c_int {
    if handle.is_null() || stats.is_null() {
        return invalid("a pointer is NULL");
    }
    // SAFETY: open, per the contract.
    match unsafe { &(*handle).handle }.stats() {
        Ok(s) => {
            // SAFETY: valid for a write, per the contract.
            unsafe {
                *stats = avulse_stats {
                    diverted: s.diverted,
                    sniffed: s.sniffed,
                    dropped: s.dropped,
                    ring_full: s.ring_full,
                    owner_gone: s.owner_gone,
                    too_big: s.too_big,
                    load_errors: s.load_errors,
                    queue_drops: s.queue_drops,
                }
            };
            AVULSE_OK
        }
        Err(e) => fail(e, ""),
    }
}

/// The handle's pollable file descriptor, or -1.
///
/// # Safety
///
/// `handle` is open.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_fd(handle: *const avulse_handle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    #[cfg(unix)]
    {
        use std::os::fd::{AsFd, AsRawFd};
        // SAFETY: open, per the contract.
        unsafe { (*handle).handle.as_fd().as_raw_fd() }
    }
    #[cfg(not(unix))]
    -1
}

/// Closes and frees a handle.
///
/// # Safety
///
/// `handle` is NULL, or open and not in use; it is invalid afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_close(handle: *mut avulse_handle) -> c_int {
    if handle.is_null() {
        return AVULSE_OK;
    }
    // SAFETY: it came from `Box::into_raw`, and is no longer in use, per the contract.
    let h = unsafe { Box::from_raw(handle) };
    match h.handle.close() {
        Ok(()) => AVULSE_OK,
        Err(e) => fail(e, ""),
    }
}

/// An empty address at `layer` (NETWORK for an unknown layer).
///
/// # Safety
///
/// `addr` is valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_address_init(addr: *mut avulse_address, layer: u8) {
    if addr.is_null() {
        return;
    }
    let a = Address::new(Layer::try_from(layer).unwrap_or_default());
    // SAFETY: valid for a write, per the contract.
    unsafe { *addr = (&a).into() };
}

/// Removes what dead processes left behind.
///
/// # Safety
///
/// `count` is NULL or valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_cleanup(count: *mut usize) -> c_int {
    match avulse_rs::cleanup() {
        Ok(n) => {
            if !count.is_null() {
                // SAFETY: valid for a write, per the contract.
                unsafe { *count = n };
            }
            AVULSE_OK
        }
        Err(e) => fail(e, ""),
    }
}

fn compile(src: &str, syntax: u8, layer: u8) -> Result<Filter, c_int> {
    let filter = match self::syntax(syntax)? {
        Syntax::WinDivert => Filter::compile_windivert(src, self::layer(layer)?),
        _ => Filter::compile(src),
    };
    filter.map_err(|d| fail(Error::Filter(d), src))
}

/// Whether a filter compiles.
///
/// # Safety
///
/// `filter` is a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_filter_check(
    filter: *const c_char,
    syntax: c_int,
    layer: u8,
) -> c_int {
    // SAFETY: the caller's contract.
    let src = match unsafe { text(filter, "the filter") } {
        Ok(s) => s,
        Err(e) => return e,
    };
    let Ok(syntax) = u8::try_from(syntax) else {
        return invalid("unknown syntax");
    };
    match compile(src, syntax, layer) {
        Ok(_) => AVULSE_OK,
        Err(e) => e,
    }
}

/// Writes `s` as a C string to `out`, with the size it needs in `needed`.
///
/// # Safety
///
/// `out` is valid for `out_len` bytes (or NULL with 0); `needed` is NULL or valid for a write.
unsafe fn write_str(s: &str, out: *mut c_char, out_len: usize, needed: *mut usize) -> c_int {
    let n = s.len() + 1;
    if !needed.is_null() {
        // SAFETY: valid for a write, per the contract.
        unsafe { *needed = n };
    }
    if out.is_null() || out_len < n {
        set_error(format!("the output needs {n} bytes"), 0);
        return AVULSE_E_BUFFER;
    }
    // SAFETY: `out` has room for `n` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(s.as_ptr(), out.cast(), s.len());
        *out.add(s.len()) = 0;
    }
    AVULSE_OK
}

/// The canonical form of a native filter.
///
/// # Safety
///
/// `filter` is a NUL-terminated string; `out` is valid for `out_len` bytes; `needed` is NULL or
/// valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_filter_format(
    filter: *const c_char,
    out: *mut c_char,
    out_len: usize,
    needed: *mut usize,
) -> c_int {
    // SAFETY: the caller's contract.
    let src = match unsafe { text(filter, "the filter") } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match avulse_filter::parse(src) {
        // SAFETY: the caller's contract.
        Ok(ast) => unsafe { write_str(&ast.to_string(), out, out_len, needed) },
        Err(d) => fail(Error::Filter(d), src),
    }
}

/// The native equivalent of a WinDivert filter at `layer`.
///
/// # Safety
///
/// As [`avulse_filter_format`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_filter_convert(
    windivert: *const c_char,
    layer: u8,
    out: *mut c_char,
    out_len: usize,
    needed: *mut usize,
) -> c_int {
    // SAFETY: the caller's contract.
    let src = match unsafe { text(windivert, "the filter") } {
        Ok(s) => s,
        Err(e) => return e,
    };
    match compile(src, 1, layer) {
        // SAFETY: the caller's contract.
        Ok(f) => unsafe { write_str(&f.ir().native().to_string(), out, out_len, needed) },
        Err(e) => e,
    }
}

/// Evaluates a native filter on a packet: 1 if it matches, 0 if not, or a negative status.
///
/// # Safety
///
/// `filter` is a NUL-terminated string; `packet` is valid for `len` bytes; `addr` is NULL or
/// valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_filter_eval(
    filter: *const c_char,
    packet: *const u8,
    len: usize,
    ethernet: bool,
    addr: *const avulse_address,
) -> c_int {
    // SAFETY: the caller's contract.
    let src = match unsafe { text(filter, "the filter") } {
        Ok(s) => s,
        Err(e) => return e,
    };
    if packet.is_null() && len > 0 {
        return invalid("the packet is NULL");
    }
    let filter = match compile(src, 0, 0) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let addr = if addr.is_null() {
        Address::default()
    } else {
        // SAFETY: valid per the contract.
        match Address::try_from(unsafe { &*addr }) {
            Ok(a) => a,
            Err(what) => return invalid(what),
        }
    };
    let bytes: &[u8] = if len == 0 {
        &[]
    } else {
        // SAFETY: valid for `len` bytes, per the contract.
        unsafe { std::slice::from_raw_parts(packet, len) }
    };
    let link = if ethernet { Link::Ethernet } else { Link::Ip };
    filter.matches(&Packet::parse(bytes, link), &addr.meta()) as c_int
}

#[cfg(test)]
mod tests;
