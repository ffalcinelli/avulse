//! The logic of avulse's macOS system extension (Phase 6, Steps 33 and 34), linked into the
//! Swift shim of `drivers/macos` as a static library.
//!
//! The shim does what needs Apple's frameworks: the `NEFilterPacketProvider` hands each packet to
//! [`avulse_ext_packet`], and holds the ones it says to delay; an XPC listener on
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
//! - a client's death: its handles close, and what they held goes on past them.
//!
//! The include file for the shim is `drivers/macos/Shared/avulse_ext.h`.

mod ext;
#[cfg(test)]
mod tests;

use std::ffi::{CStr, c_char};
use std::sync::OnceLock;

pub use ext::{Extension, HOLD_MAX, Release, Seen, Verdict, hash, link_of};

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
/// `euid`. It returns the response, `*out_len` bytes to free with [`avulse_ext_free`]. A `Recv`
/// request waits, so call it off the connection's queue.
///
/// # Safety
///
/// `req` must be valid for reads of `len` bytes, and `out_len` for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_ext_request(
    conn: u64,
    euid: u32,
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
        Some(ext) => ext.request(conn, euid, req),
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
