//! A handle: one file object of the control device, opened by [`ioctl::OPEN`] with a verified
//! program, and closed when the file is cleaned up (closed, or its process exits).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use avulse_abi::ioctl::{self, OpenRequest};
use avulse_abi::{Flags, Param, Stats, Syntax};
use avulse_filter::Layer;
use avulse_filter::bytecode::{self, VerifiedProgram};

use crate::lock::SpinLock;
use crate::rx::Rx;
use crate::sys;

/// What a file object holds (`FsContext`).
pub struct File {
    pub state: SpinLock<State>,
    /// The queue and the waiting `RECV` requests, which live as long as the file.
    pub rx: SpinLock<Rx>,
}

impl File {
    pub fn new() -> File {
        File {
            state: SpinLock::new(State::New),
            rx: SpinLock::new(Rx::default()),
        }
    }
}

pub enum State {
    /// Created, not opened yet.
    New,
    Open(Arc<Open>),
    /// Cleaned up: the file is going away.
    Closed,
}

/// An open handle. The flags, filter text and interfaces serve the packet hooks and REFLECT, from
/// Step 25.
#[allow(dead_code)]
pub struct Open {
    pub layer: Layer,
    pub priority: i16,
    pub flags: Flags,
    pub syntax: Syntax,
    /// The filter as written, for REFLECT.
    pub filter: String,
    /// The interfaces to capture on; empty for all of them.
    pub interfaces: Vec<u32>,
    /// The program, borrowing `code`, which it is freed with.
    program: VerifiedProgram<'static>,
    code: *mut [u8],
    pub mutable: SpinLock<Mutable>,
}

// SAFETY: `code` is owned, and only freed when the last reference goes.
unsafe impl Send for Open {}
// SAFETY: as above; the rest is read-only or behind a lock.
unsafe impl Sync for Open {}

/// What changes while the handle is open.
pub struct Mutable {
    pub params: [u64; 3],
    pub stats: Stats,
    pub shut_send: bool,
}

impl Open {
    /// The handle a request describes, with its program verified.
    pub fn new(req: &OpenRequest<'_>) -> Result<Open, sys::NTSTATUS> {
        if !(-30_000..=30_000).contains(&req.priority) {
            return Err(sys::STATUS_INVALID_PARAMETER);
        }
        let code: Box<[u8]> = req.program.into();
        let code = Box::into_raw(code);
        // SAFETY: `code` stays allocated until `Drop`, after the program's last use.
        let bytes: &'static [u8] = unsafe { &*code };
        let program = match bytecode::verify(bytes) {
            Ok(p) => p,
            Err(_) => {
                // SAFETY: from `Box::into_raw` just above, unused.
                drop(unsafe { Box::from_raw(code) });
                return Err(sys::STATUS_INVALID_PARAMETER);
            }
        };
        Ok(Open {
            layer: req.layer,
            priority: req.priority,
            flags: req.flags,
            syntax: req.syntax,
            filter: req.filter.into(),
            interfaces: req.interfaces.clone(),
            program,
            code,
            mutable: SpinLock::new(Mutable {
                params: Param::ALL.map(Param::default_value),
                stats: Stats::default(),
                shut_send: false,
            }),
        })
    }

    pub fn program(&self) -> &VerifiedProgram<'_> {
        &self.program
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        // SAFETY: from `Box::into_raw` in `new`; the program borrowing it goes with `self`.
        drop(unsafe { Box::from_raw(self.code) });
    }
}

/// Decodes and opens: what [`ioctl::OPEN`] does to a new file.
pub fn open(file: &File, input: &[u8]) -> Result<(), sys::NTSTATUS> {
    let req = OpenRequest::decode(input).map_err(|e| match e {
        ioctl::Malformed::Version => sys::STATUS_REVISION_MISMATCH,
        _ => sys::STATUS_INVALID_PARAMETER,
    })?;
    // Verify before taking the lock: it is linear in the program's size.
    let open = Arc::new(Open::new(&req)?);
    let mut state = file.state.lock();
    match *state {
        State::New => {
            *state = State::Open(open);
            Ok(())
        }
        _ => Err(sys::STATUS_INVALID_DEVICE_STATE),
    }
}

/// The open handle of `file`, if it is open.
pub fn get(file: &File) -> Result<Arc<Open>, sys::NTSTATUS> {
    match &*file.state.lock() {
        State::Open(o) => Ok(o.clone()),
        _ => Err(sys::STATUS_INVALID_DEVICE_STATE),
    }
}
