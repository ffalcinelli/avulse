//! Handles served by the avulse system extension (Steps 33 and 34): the extension's packet
//! provider diverts, drops and sniffs, and this side talks to it over XPC
//! ([`avulse_abi::macos`]'s protocol).
//!
//! A thread per handle waits on `Recv` requests and moves what comes to the handle's `Rx`, so
//! the handle is pollable and receives as the bpf tier does. A packet sent back unchanged is
//! the extension's to let go on; a modified or new one, the extension notes, and [`Tx`] sends it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use avulse_abi::ioctl::{self, OpenRequest, Record};
use avulse_abi::macos::{
    Op, Request, SendResult, Status, decode_capabilities, encode_recv, support,
};
use avulse_filter::Layer;

use super::record::Entry;
use super::send::Tx;
use super::xpc::Connection;
use super::{Rx, lock};
use crate::backend::{Capabilities, LayerSupport, Spec};
use crate::{Address, Error, Param, Result, Shutdown, Stats};

/// How long one `Recv` waits, so that the thread notices a close.
const RECV_WAIT_MS: u32 = 250;
/// How many bytes of records one `Recv` brings at most.
const RECV_BYTES: u32 = 1 << 20;

/// What the extension supports, or `None` if it is not there (or `AVULSE_NO_EXTENSION` is set).
pub fn capabilities() -> Option<Capabilities> {
    if std::env::var_os("AVULSE_NO_EXTENSION").is_some() {
        return None;
    }
    let conn = Connection::open().ok()?;
    let (status, payload) = conn
        .call(&Request {
            op: Op::Capabilities,
            handle: 0,
            payload: &[],
        })
        .ok()?;
    let layers = (status == Status::Ok)
        .then(|| decode_capabilities(&payload).ok())
        .flatten()?;
    let mut c = Capabilities::NONE;
    for (i, bits) in layers.into_iter().enumerate() {
        c.layers[i] = LayerSupport {
            open: bits & support::OPEN != 0,
            divert: bits & support::DIVERT != 0,
            drop: bits & support::DROP != 0,
            inject: bits & support::INJECT != 0,
            modify: bits & support::MODIFY != 0,
        };
    }
    Some(c)
}

/// The error for a status the extension answered.
fn status_error(s: Status) -> Error {
    match s {
        Status::Ok => Error::Io(std::io::Error::other("no error")),
        Status::Denied => Error::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        Status::Invalid => Error::InvalidArgument("refused by the avulse system extension"),
        Status::Unsupported => Error::Unsupported("refused by the avulse system extension"),
        Status::Shutdown => Error::Shutdown,
        Status::Timeout => Error::Timeout,
        Status::NoHandle | Status::NoMemory => {
            Error::Io(std::io::Error::from_raw_os_error(-(s as i32)))
        }
    }
}

/// What the handle and its receiving thread share.
struct Shared {
    conn: Connection,
    id: u64,
    rx: Rx,
    /// Set when the handle closes: the thread stops.
    closing: AtomicBool,
}

impl Shared {
    fn call(&self, op: Op, payload: &[u8]) -> Result<Vec<u8>> {
        match self.conn.call(&Request {
            op,
            handle: self.id,
            payload,
        })? {
            (Status::Ok, p) => Ok(p),
            (s, _) => Err(status_error(s)),
        }
    }

    /// The receiving thread: `Recv` after `Recv`, into the queue, until the handle shuts down
    /// or closes.
    fn receive(&self) {
        let req = encode_recv(RECV_WAIT_MS, RECV_BYTES);
        while !self.closing.load(Ordering::Acquire) {
            match self.call(Op::Recv, &req) {
                Ok(records) => {
                    let entries = Record::decode_all(&records)
                        .map_while(|r| r.ok())
                        .map(|r| Entry {
                            addr: r.addr,
                            data: r.data.to_vec(),
                        })
                        .collect();
                    self.rx.push(entries);
                }
                Err(Error::Timeout) => {}
                // Shut down, closed, or the extension went away.
                Err(_) => break,
            }
        }
        self.rx.shut();
    }
}

/// A handle the extension serves.
pub struct ExtHandle {
    shared: Arc<Shared>,
    layer: Layer,
    tx: Tx,
    shut_send: AtomicBool,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl ExtHandle {
    pub fn open(spec: &Spec<'_>) -> Result<ExtHandle> {
        let conn = Connection::open()?;
        let interfaces = spec
            .interfaces
            .iter()
            .map(|n| super::send::if_index(n))
            .collect::<Result<Vec<_>>>()?;
        // The extension compiles the filter's text itself: it runs in user space, where the
        // reference evaluator is the faster one.
        let req = OpenRequest {
            layer: spec.layer,
            priority: spec.priority,
            flags: spec.flags,
            program: &[],
            interfaces,
            filter: spec.source,
            syntax: spec.syntax,
            windivert_object: &[],
        };
        let id = match conn.call(&Request {
            op: Op::Open,
            handle: 0,
            payload: &req.encode(),
        })? {
            (Status::Ok, p) => u64::from_le_bytes(
                p.try_into()
                    .map_err(|_| Error::Io(std::io::Error::other("a malformed open reply")))?,
            ),
            (s, _) => return Err(status_error(s)),
        };
        let shared = Arc::new(Shared {
            conn,
            id,
            rx: Rx::new(spec.params)?,
            closing: AtomicBool::new(false),
        });
        for p in Param::ALL {
            if spec.params[p.index()] != p.default_value() {
                shared.call(
                    Op::SetParam,
                    &ioctl::encode_set_param(p, spec.params[p.index()]),
                )?;
            }
        }
        let thread = if spec.flags.contains(crate::Flags::SEND_ONLY) {
            shared.rx.shut();
            None
        } else {
            let s = shared.clone();
            Some(
                std::thread::Builder::new()
                    .name("avulse-recv".into())
                    .spawn(move || s.receive())
                    .map_err(Error::Io)?,
            )
        };
        Ok(ExtHandle {
            shared,
            layer: spec.layer,
            tx: Tx::new(),
            shut_send: AtomicBool::new(false),
            thread: Mutex::new(thread),
        })
    }
}

impl super::Opened for ExtHandle {
    fn recv(&self, buf: &mut [u8], timeout: Option<Duration>) -> Result<(usize, Address)> {
        self.shared.rx.recv(buf, timeout, || 0)
    }

    fn recv_ready(&self, buf: &mut [u8]) -> Result<Option<(usize, Address)>> {
        self.shared.rx.ready(buf, || 0)
    }

    fn send(&self, packet: &[u8], addr: &Address) -> Result<usize> {
        if self.shut_send.load(Ordering::Acquire) {
            return Err(Error::Shutdown);
        }
        let mut b = Vec::with_capacity(Record::encoded_len(packet.len()));
        Record {
            addr: *addr,
            data: packet,
        }
        .encode_into(&mut b);
        let results = self.shared.call(Op::Send, &b)?;
        match results.first().map(|&r| SendResult::try_from(r)) {
            Some(Ok(SendResult::Sent)) => {}
            Some(Ok(SendResult::Inject)) => self.tx.send(packet, addr, self.layer)?,
            _ => return Err(Error::Io(std::io::Error::other("a malformed send reply"))),
        }
        Ok(packet.len())
    }

    fn shutdown(&self, how: Shutdown) -> Result<()> {
        let code: u32 = match how {
            Shutdown::Recv => 1,
            Shutdown::Send => 2,
            Shutdown::Both => 3,
        };
        // The receiving thread delivers what is queued, then sees the shutdown.
        self.shared.call(Op::Shutdown, &code.to_le_bytes())?;
        if matches!(how, Shutdown::Send | Shutdown::Both) {
            self.shut_send.store(true, Ordering::Release);
        }
        Ok(())
    }

    fn set_param(&self, param: Param, value: u64) -> Result<()> {
        self.shared
            .call(Op::SetParam, &ioctl::encode_set_param(param, value))?;
        lock(&self.shared.rx.queue).queue.set(param, value);
        Ok(())
    }

    fn stats(&self) -> Result<Stats> {
        let b = self.shared.call(Op::Stats, &[])?;
        let mut s = ioctl::decode_stats(&b)
            .map_err(|_| Error::Io(std::io::Error::other("a malformed stats reply")))?;
        s.queue_drops += lock(&self.shared.rx.queue).queue.drops;
        Ok(s)
    }

    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self.shared.rx.kqueue.as_fd()
    }

    fn close(self: Box<Self>) -> Result<()> {
        drop(self);
        Ok(())
    }
}

impl Drop for ExtHandle {
    fn drop(&mut self) {
        self.shared.closing.store(true, Ordering::Release);
        // Closing answers the thread's pending `Recv`; the packets the handle holds go on.
        let _ = self.shared.call(Op::Close, &[]);
        if let Some(t) = lock(&self.thread).take() {
            let _ = t.join();
        }
    }
}
