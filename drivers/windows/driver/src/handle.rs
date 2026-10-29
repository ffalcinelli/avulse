//! A handle: one file object of the control device, opened by [`ioctl::OPEN`] with a verified
//! program, and closed when the file is cleaned up (closed, or its process exits).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use avulse_abi::ioctl::{self, OpenRequest};
use avulse_abi::{Address, Flags, Param, Stats, Syntax};
use avulse_filter::Layer;
use avulse_filter::bytecode::{self, VerifiedProgram};

use core::sync::atomic::AtomicU64;

use crate::lock::SpinLock;
use crate::rx::{self, Entry, Rx};
use crate::sys;
use crate::{lwf, reflect, wfp};

/// What a file object holds (`FsContext`).
pub struct File {
    pub state: SpinLock<State>,
    /// The queue and the waiting `RECV` requests. The open handle shares it with the packet
    /// hooks, which may still run briefly after the file is cleaned up.
    pub rx: Arc<SpinLock<Rx>>,
}

impl File {
    pub fn new() -> File {
        File {
            state: SpinLock::new(State::New),
            rx: Arc::new(SpinLock::new(Rx::default())),
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

/// An open handle.
pub struct Open {
    pub layer: Layer,
    pub priority: i16,
    pub flags: Flags,
    pub syntax: Syntax,
    /// The filter as written, for REFLECT.
    pub filter: String,
    /// The interfaces to capture on; empty for all of them.
    pub interfaces: Vec<u32>,
    /// The process that opened it, and when, for REFLECT.
    pub process_id: u32,
    pub opened: i64,
    /// Its data in a WinDivert REFLECT receive (WinDivert's filter object), if it has one.
    pub windivert_object: Option<Arc<[u8]>>,
    /// The program, borrowing `code`, which it is freed with.
    program: VerifiedProgram<'static>,
    code: *mut [u8],
    pub mutable: SpinLock<Mutable>,
    /// The file's queue, which the packet hooks fill.
    pub rx: Arc<SpinLock<Rx>>,
    /// The id the WFP filters carry as their context (0 before `wfp::attach`).
    pub id: AtomicU64,
    /// The handle's WFP filters.
    pub filters: SpinLock<Vec<u64>>,
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
    pub fn new(req: &OpenRequest<'_>, rx: Arc<SpinLock<Rx>>) -> Result<Open, sys::NTSTATUS> {
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
            // SAFETY: a plain query, in the context of the process that opens the handle.
            process_id: unsafe { sys::PsGetCurrentProcessId() } as usize as u32,
            opened: wfp::now_ns(),
            windivert_object: (!req.windivert_object.is_empty())
                .then(|| Arc::from(req.windivert_object)),
            program,
            code,
            mutable: SpinLock::new(Mutable {
                params: Param::ALL.map(Param::default_value),
                stats: Stats::default(),
                shut_send: false,
            }),
            rx,
            id: AtomicU64::new(0),
            filters: SpinLock::new(Vec::new()),
        })
    }

    pub fn program(&self) -> &VerifiedProgram<'_> {
        &self.program
    }

    /// Whether the handle captures on the interface `if_idx`: all of them when it was given
    /// none.
    pub fn captures_on(&self, if_idx: u32) -> bool {
        self.interfaces.is_empty() || self.interfaces.contains(&if_idx)
    }

    /// Whether the packet hooks pass the handle by: shut down for receiving, or SEND_ONLY.
    pub fn idle(&self) -> bool {
        self.flags.contains(Flags::SEND_ONLY) || self.rx.lock().shut
    }

    /// Queues a packet the handle matched (a copy if `addr.sniffed`), within its queue
    /// parameters, and counts it.
    pub fn deliver(&self, addr: Address, data: Vec<u8>) {
        self.queue(Entry {
            addr,
            data,
            windivert: None,
        });
    }

    /// [`deliver`](Self::deliver), for an entry of its own.
    pub fn queue(&self, e: Entry) {
        let sniff = e.addr.sniffed;
        let (max_len, max_bytes) = {
            let m = self.mutable.lock();
            (m.params[0] as usize, m.params[2] as usize)
        };
        let queued = rx::push(&self.rx, e, max_len, max_bytes);
        let mut m = self.mutable.lock();
        match (queued, sniff) {
            (false, _) => m.stats.queue_drops += 1,
            (true, true) => m.stats.sniffed += 1,
            (true, false) => m.stats.diverted += 1,
        }
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
    if !matches!(*file.state.lock(), State::New) {
        return Err(sys::STATUS_INVALID_DEVICE_STATE);
    }
    // Verify outside the lock: it is linear in the program's size.
    let open = Arc::new(Open::new(&req, file.rx.clone())?);
    // A SEND_ONLY handle captures nothing: it needs no WFP filter, and no place among the
    // lightweight filter's handles.
    let capture = !open.flags.contains(Flags::SEND_ONLY);
    match open.layer {
        Layer::Network | Layer::NetworkForward | Layer::Flow | Layer::Socket if capture => {
            // SAFETY: at PASSIVE_LEVEL, in the dispatch routine.
            unsafe { wfp::attach(&open)? };
        }
        Layer::Ethernet if !lwf::available() => return Err(sys::STATUS_NOT_SUPPORTED),
        Layer::Ethernet if capture => lwf::attach(&open),
        _ => {}
    }
    let mut state = file.state.lock();
    if !matches!(*state, State::New) {
        drop(state);
        // SAFETY: as above.
        unsafe { wfp::detach(&open) };
        lwf::detach(&open);
        return Err(sys::STATUS_INVALID_DEVICE_STATE);
    }
    *state = State::Open(open.clone());
    drop(state);
    reflect::opened(&open);
    Ok(())
}

/// Closes the handle of `file`, if it is open: what `IRP_MJ_CLEANUP` does.
///
/// # Safety
///
/// At PASSIVE_LEVEL.
pub unsafe fn close(file: &File) {
    let old = core::mem::replace(&mut *file.state.lock(), State::Closed);
    if let State::Open(open) = &old {
        reflect::closed(open);
        // SAFETY: the caller's contract.
        unsafe { wfp::detach(open) };
        lwf::detach(open);
    }
    drop(old);
}

/// The open handle of `file`, if it is open.
pub fn get(file: &File) -> Result<Arc<Open>, sys::NTSTATUS> {
    match &*file.state.lock() {
        State::Open(o) => Ok(o.clone()),
        _ => Err(sys::STATUS_INVALID_DEVICE_STATE),
    }
}
