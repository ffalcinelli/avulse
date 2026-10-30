//! A client connection to the avulse system extension's XPC Mach service, through libxpc (part
//! of libSystem). Requests go synchronously: each thread waits for its own reply.

use std::ffi::{CString, c_char, c_int, c_ulong, c_void};
use std::io;
use std::sync::OnceLock;

use avulse_abi::macos::{MACH_SERVICE, Request, Status, decode_response};

use crate::{Error, Result};

#[allow(non_camel_case_types)]
type xpc_object_t = *mut c_void;

/// An opaque libSystem symbol, used for its address.
#[repr(C)]
struct Opaque {
    _p: [u8; 0],
}

/// `XPC_CONNECTION_MACH_SERVICE_PRIVILEGED`: the service is a system (root) one.
const MACH_SERVICE_PRIVILEGED: u64 = 1 << 1;

unsafe extern "C" {
    fn xpc_connection_create_mach_service(
        name: *const c_char,
        targetq: *mut c_void,
        flags: u64,
    ) -> xpc_object_t;
    fn xpc_connection_set_event_handler(conn: xpc_object_t, handler: *const c_void);
    fn xpc_connection_resume(conn: xpc_object_t);
    fn xpc_connection_cancel(conn: xpc_object_t);
    fn xpc_connection_send_message_with_reply_sync(
        conn: xpc_object_t,
        msg: xpc_object_t,
    ) -> xpc_object_t;
    fn xpc_dictionary_create(
        keys: *const *const c_char,
        values: *const xpc_object_t,
        count: usize,
    ) -> xpc_object_t;
    fn xpc_dictionary_set_data(
        d: xpc_object_t,
        key: *const c_char,
        bytes: *const c_void,
        len: usize,
    );
    fn xpc_dictionary_get_data(
        d: xpc_object_t,
        key: *const c_char,
        len: *mut usize,
    ) -> *const c_void;
    fn xpc_get_type(o: xpc_object_t) -> *const Opaque;
    fn xpc_release(o: xpc_object_t);
    static _xpc_type_dictionary: Opaque;
    static _NSConcreteGlobalBlock: Opaque;
}

/// The key of the one value in every message.
const KEY: &[u8] = b"d\0";

/// A block's layout (the blocks ABI), for the connection's event handler, which libxpc requires
/// before the connection resumes. Ours captures nothing, so it is a global block.
#[repr(C)]
struct Block {
    isa: *const Opaque,
    flags: c_int,
    reserved: c_int,
    invoke: unsafe extern "C" fn(*const Block, xpc_object_t),
    descriptor: *const BlockDescriptor,
}

#[repr(C)]
struct BlockDescriptor {
    reserved: c_ulong,
    size: c_ulong,
}

const BLOCK_IS_GLOBAL: c_int = 1 << 28;

static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
    reserved: 0,
    size: size_of::<Block>() as c_ulong,
};

/// Errors come back as replies to the requests, so events need no handling.
unsafe extern "C" fn ignore(_: *const Block, _: xpc_object_t) {}

/// The event handler's address: one global block for the process.
fn handler() -> *const c_void {
    static BLOCK: OnceLock<usize> = OnceLock::new();
    *BLOCK.get_or_init(|| {
        let block = Box::leak(Box::new(Block {
            isa: &raw const _NSConcreteGlobalBlock,
            flags: BLOCK_IS_GLOBAL,
            reserved: 0,
            invoke: ignore,
            descriptor: &DESCRIPTOR,
        }));
        block as *const Block as usize
    }) as *const c_void
}

/// The service's name: `AVULSE_MACH_SERVICE` if set (the tests' daemon), else
/// [`MACH_SERVICE`].
fn service_name() -> String {
    std::env::var("AVULSE_MACH_SERVICE").unwrap_or_else(|_| MACH_SERVICE.to_string())
}

/// A connection to the extension.
pub struct Connection(xpc_object_t);

// SAFETY: XPC connections may be used from any thread.
unsafe impl Send for Connection {}
// SAFETY: as above; each request waits for its own reply.
unsafe impl Sync for Connection {}

impl Connection {
    /// A connection to the service. Nothing is sent yet, so this succeeds even when the
    /// extension is not there; the first request says.
    pub fn open() -> Result<Connection> {
        let name = CString::new(service_name())
            .map_err(|_| Error::InvalidArgument("AVULSE_MACH_SERVICE"))?;
        // SAFETY: a NUL-terminated name; the default target queue.
        let conn = unsafe {
            xpc_connection_create_mach_service(
                name.as_ptr(),
                std::ptr::null_mut(),
                MACH_SERVICE_PRIVILEGED,
            )
        };
        if conn.is_null() {
            return Err(Error::Io(io::Error::other(
                "xpc_connection_create_mach_service",
            )));
        }
        // SAFETY: a fresh connection, and a block that lives for the process.
        unsafe {
            xpc_connection_set_event_handler(conn, handler());
            xpc_connection_resume(conn);
        }
        Ok(Connection(conn))
    }

    /// Sends `req` and waits for the reply's status and payload. A connection error (the
    /// extension is not running, or went away) is `ErrorKind::NotConnected`.
    pub fn call(&self, req: &Request<'_>) -> Result<(Status, Vec<u8>)> {
        let bytes = req.encode();
        // SAFETY: a fresh dictionary, released below; `bytes` is copied in.
        let reply = unsafe {
            let msg = xpc_dictionary_create(std::ptr::null(), std::ptr::null(), 0);
            xpc_dictionary_set_data(msg, KEY.as_ptr().cast(), bytes.as_ptr().cast(), bytes.len());
            let reply = xpc_connection_send_message_with_reply_sync(self.0, msg);
            xpc_release(msg);
            reply
        };
        let not_running = || {
            Error::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                "the avulse system extension is not running",
            ))
        };
        if reply.is_null() {
            return Err(not_running());
        }
        // SAFETY: `reply` is a live object, released below.
        let out = unsafe {
            if xpc_get_type(reply) != &raw const _xpc_type_dictionary {
                None
            } else {
                let mut len = 0;
                let p = xpc_dictionary_get_data(reply, KEY.as_ptr().cast(), &mut len);
                (!p.is_null()).then(|| std::slice::from_raw_parts(p.cast::<u8>(), len).to_vec())
            }
        };
        // SAFETY: the reply, ours to release.
        unsafe { xpc_release(reply) };
        let out = out.ok_or_else(not_running)?;
        let (status, payload) = decode_response(&out)
            .map_err(|_| Error::Io(io::Error::other("a malformed reply from the extension")))?;
        Ok((status, payload.to_vec()))
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // SAFETY: the connection, ours; cancelling makes the service see us go.
        unsafe {
            xpc_connection_cancel(self.0);
            xpc_release(self.0);
        }
    }
}
