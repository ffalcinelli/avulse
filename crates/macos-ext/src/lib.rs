//! The logic of avulse's macOS system extension (Phase 6, Steps 33 and 34), linked into the
//! Swift shim of `drivers/macos` as a static library.
//!
//! The shim does what needs Apple's frameworks: the `NEFilterPacketProvider` hands each packet to
//! [`avulse_ext_packet`], and holds the ones it says to delay; the `NEFilterDataProvider` hands
//! each new flow to [`avulse_ext_flow_new`], and its end to [`avulse_ext_flow_end`]; an XPC
//! listener on
//! [`MACH_SERVICE`](avulse_abi::macos::MACH_SERVICE) hands each request to
//! [`avulse_ext_request`], and each connection's end to [`avulse_ext_disconnect`]. Everything
//! else is here, in portable Rust that the host's tests cover:
//!
//! - the handles, opened by root clients with `avulse_abi::macos`'s protocol, each with its
//!   queue, in priority order;
//! - the packet path: each handle's filter, with the reference evaluator (this is user space),
//!   then sniff (a copy), drop, or divert (the provider holds the packet, the handle gets a
//!   copy that names it);
//! - what becomes of a held packet: sent back unchanged, it goes on to the next handles, then out;
//!   modified, it is dropped and the client injects the new bytes, which the handles at its
//!   priority and above skip; never sent back, it is dropped after [`HOLD_MAX`];
//! - a client's death: its handles close, and what they held goes on past them;
//! - the FLOW layer (flows established and deleted), the SOCKET layer (connects and accepts,
//!   which a handle without SNIFF refuses, and closes), and REFLECT (the extension's handles
//!   opening and closing).
//!
//! The include file for the shim is `drivers/macos/Shared/avulse_ext.h`.

mod ext;
#[cfg(test)]
mod tests;

use std::ffi::{CStr, c_char};
use std::net::IpAddr;
use std::sync::OnceLock;

pub use ext::{Extension, FlowStart, HOLD_MAX, Release, Seen, Verdict, hash, link_of};

static EXTENSION: OnceLock<Extension> = OnceLock::new();

/// Sets up the extension. `release(token, allow)` tells the shim what becomes of a packet it
/// holds: let it go on (`allow`), or drop it. `test_mode` serves `TestPacket` requests, for
/// running without the packet provider. Returns false if it was set up already.
#[unsafe(no_mangle)]
pub extern "C" fn avulse_ext_init(release: extern "C" fn(u64, bool), test_mode: bool) -> bool {
    EXTENSION
        .set(Extension::new(
            Box::new(move |token, allow| release(token, allow)),
            test_mode,
        ))
        .is_ok()
}

/// The packet path: the [`Verdict`] for a packet of `len` bytes at `data` (a frame or an IP
/// packet), on interface `ifindex` named `ifname`. For [`Verdict::Delay`], `*token` is what to
/// hold it under, until the release callback names it. Without [`avulse_ext_init`], every packet
/// is allowed.
///
/// # Safety
///
/// `data` must be valid for reads of `len` bytes, `ifname` must be null or a NUL-terminated
/// string, and `token` must be valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_ext_packet(
    ifindex: u32,
    ifname: *const c_char,
    outbound: bool,
    loopback: bool,
    data: *const u8,
    len: usize,
    token: *mut u64,
) -> i32 {
    let Some(ext) = EXTENSION.get() else {
        return Verdict::Allow as i32;
    };
    if data.is_null() || token.is_null() {
        return Verdict::Allow as i32;
    }
    // SAFETY: the caller guarantees `len` readable bytes at `data`.
    let data = unsafe { std::slice::from_raw_parts(data, len) };
    let ifname = if ifname.is_null() {
        ""
    } else {
        // SAFETY: the caller guarantees a NUL-terminated string.
        unsafe { CStr::from_ptr(ifname) }.to_str().unwrap_or("")
    };
    let (v, t) = ext.packet(&Seen {
        ifindex,
        ifname,
        outbound,
        loopback,
        data,
    });
    // SAFETY: the caller guarantees `token` is writable.
    unsafe { token.write(t) };
    v as i32
}

/// Serves a request of `len` bytes from client connection `conn`, whose effective user is
/// `euid` and process `pid`. It returns the response, `*out_len` bytes to free with [`avulse_ext_free`]. A `Recv`
/// request waits, so call it off the connection's queue.
///
/// # Safety
///
/// `req` must be valid for reads of `len` bytes, and `out_len` for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_ext_request(
    conn: u64,
    euid: u32,
    pid: u32,
    req: *const u8,
    len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    let req = if req.is_null() {
        &[][..]
    } else {
        // SAFETY: the caller guarantees `len` readable bytes at `req`.
        unsafe { std::slice::from_raw_parts(req, len) }
    };
    let resp = match EXTENSION.get() {
        Some(ext) => ext.request(conn, euid, pid, req),
        None => avulse_abi::macos::encode_response(avulse_abi::macos::Status::Unsupported, &[]),
    };
    let resp = resp.into_boxed_slice();
    // SAFETY: the caller guarantees `out_len` is writable.
    unsafe { out_len.write(resp.len()) };
    Box::into_raw(resp).cast()
}

/// Frees a response of [`avulse_ext_request`].
///
/// # Safety
///
/// `p` and `len` must be what `avulse_ext_request` returned, freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_ext_free(p: *mut u8, len: usize) {
    if !p.is_null() {
        // SAFETY: from `Box::into_raw` of a boxed slice of `len` bytes.
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(p, len)) });
    }
}

/// Client connection `conn` went away: its handles close.
#[unsafe(no_mangle)]
pub extern "C" fn avulse_ext_disconnect(conn: u64) {
    if let Some(ext) = EXTENSION.get() {
        ext.disconnect(conn);
    }
}

/// Whether the data provider runs: the FLOW and SOCKET layers need it.
#[unsafe(no_mangle)]
pub extern "C" fn avulse_ext_flows(on: bool) {
    if let Some(ext) = EXTENSION.get() {
        ext.set_flows(on);
    }
}

/// The address in `host` (a numeric IPv4 or IPv6 address, maybe with a `%scope`), or the
/// unspecified address.
fn host(p: *const c_char) -> IpAddr {
    if p.is_null() {
        return IpAddr::from([0u8; 4]);
    }
    // SAFETY: the callers guarantee a NUL-terminated string.
    let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("");
    let s = s.split('%').next().unwrap_or("");
    s.parse().unwrap_or(IpAddr::from([0u8; 4]))
}

/// The process of an audit token (`audit_token_t`: eight `u32`s, the PID at index 5), and its
/// name.
fn process(token: *const u8) -> (u32, Option<String>) {
    if token.is_null() {
        return (0, None);
    }
    let mut b = [0u8; 4];
    // SAFETY: the callers guarantee 32 readable bytes at `token`.
    unsafe { std::ptr::copy_nonoverlapping(token.add(20), b.as_mut_ptr(), 4) };
    let pid = u32::from_ne_bytes(b);
    (pid, process_name(pid))
}

#[cfg(target_os = "macos")]
fn process_name(pid: u32) -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` has room for the size given.
    let n = unsafe { libc::proc_name(pid as i32, buf.as_mut_ptr().cast(), buf.len() as u32) };
    (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

#[cfg(not(target_os = "macos"))]
fn process_name(_: u32) -> Option<String> {
    None
}

/// A new flow, as the data provider sees it: whether the local side opened it, its IP
/// protocol, its local and remote addresses (numeric strings) and ports, and the audit token
/// of its process (32 bytes, or null). Returns [`Verdict::Allow`] or [`Verdict::Drop`] (a
/// SOCKET handle refused it); `*id` names the flow, and `*watch` says whether its end is wanted.
///
/// # Safety
///
/// The strings must be null or NUL-terminated, `audit_token` null or valid for 32 bytes, and
/// `id` and `watch` valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_ext_flow_new(
    outbound: bool,
    protocol: u8,
    local_host: *const c_char,
    local_port: u16,
    remote_host: *const c_char,
    remote_port: u16,
    audit_token: *const u8,
    id: *mut u64,
    watch: *mut bool,
) -> i32 {
    let Some(ext) = EXTENSION.get() else {
        return Verdict::Allow as i32;
    };
    if id.is_null() || watch.is_null() {
        return Verdict::Allow as i32;
    }
    let (pid, process_name) = process(audit_token);
    let (v, i, w) = ext.flow_start(&FlowStart {
        outbound,
        protocol,
        pid,
        process_name,
        local: host(local_host),
        local_port,
        remote: host(remote_host),
        remote_port,
    });
    // SAFETY: the caller guarantees both are writable.
    unsafe {
        id.write(i);
        watch.write(w);
    }
    v as i32
}

/// Flow `id`, whose end [`avulse_ext_flow_new`] wanted, ended.
#[unsafe(no_mangle)]
pub extern "C" fn avulse_ext_flow_end(id: u64) {
    if let Some(ext) = EXTENSION.get() {
        ext.flow_end(id);
    }
}
