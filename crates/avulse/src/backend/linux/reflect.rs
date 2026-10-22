//! The REFLECT layer: the handles of every process, as the registry lists them. A REFLECT
//! handle compares the registry with what it last saw every [`PERIOD`], and reports each handle
//! that appeared (OPEN, all of them at first, itself included) or went away or lost its owner
//! (CLOSE). The data of an event is the handle's filter, in native syntax.

use std::collections::HashMap;
use std::os::fd::{AsFd, BorrowedFd};
use std::time::Duration;

use avulse_filter::{Event, Filter, Layer};
use avulse_proto::{Link, Packet};

use super::record::Entry;
use super::registry::{self, Registry};
use super::{Rx, lock, sys};
use crate::backend::{Opened, Spec};
use crate::{Address, Error, Flags, Param, Result, Shutdown};

/// How often the registry is read.
const PERIOD: Duration = Duration::from_millis(100);

pub(super) struct ReflectHandle {
    filter: Filter,
    rx: Rx<Seen>,
    registered: Option<u64>,
}

/// What a handle has seen of the registry: the timer of its reads, and the live entries.
struct Seen {
    timer: sys::Timer,
    handles: HashMap<u64, registry::Entry>,
}

/// The REFLECT event of the handle registered as `e`, and its data: the filter.
pub(super) fn event(e: &registry::Entry, event: Event, now: i64) -> Option<Entry> {
    let mut addr = Address::new(Layer::Reflect);
    addr.timestamp = now;
    addr.event = event;
    addr.sniffed = true;
    let r = &mut addr.reflect;
    r.timestamp = e.timestamp;
    r.flags = Flags::from_bits(e.flags)?;
    r.process_id = e.pid;
    r.priority = e.priority;
    r.layer = Layer::try_from(e.layer).ok()?;
    Some(Entry {
        addr,
        data: e.filter.as_bytes().to_vec(),
    })
}

/// The events between what was seen, `seen`, and the live handles now, `now`: CLOSE for those
/// gone, then OPEN for the new ones. `seen` becomes `now`.
pub(super) fn diff(
    seen: &mut HashMap<u64, registry::Entry>,
    now: HashMap<u64, registry::Entry>,
    at: i64,
) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut gone: Vec<_> = seen
        .keys()
        .filter(|k| !now.contains_key(k))
        .copied()
        .collect();
    gone.sort_by_key(|k| seen[k].timestamp);
    for k in gone {
        out.extend(event(&seen[&k], Event::ReflectClose, at));
        seen.remove(&k);
    }
    let mut new: Vec<_> = now
        .into_iter()
        .filter(|(k, _)| !seen.contains_key(k))
        .collect();
    new.sort_by_key(|(_, e)| e.timestamp);
    for (k, e) in new {
        out.extend(event(&e, Event::ReflectOpen, at));
        seen.insert(k, e);
    }
    out
}

impl ReflectHandle {
    pub(super) fn open(spec: &Spec<'_>) -> Result<ReflectHandle> {
        let rx = Rx::new(spec.params)?;
        let timer = sys::Timer::periodic(PERIOD)?;
        rx.epoll.add(timer.as_fd())?;
        *lock(&rx.ring) = Some(Seen {
            timer,
            handles: HashMap::new(),
        });
        let mut handle = ReflectHandle {
            filter: spec.filter.clone(),
            rx,
            registered: None,
        };
        let registry = Registry::lock()?;
        let _ = registry.reap();
        handle.registered = registry.add(&registry::Entry {
            pid: sys::pid(),
            start_time: sys::start_time(sys::pid()).unwrap_or(0),
            tc_priority: 0,
            timestamp: sys::now_ns(),
            flags: spec.flags.bits(),
            layer: spec.layer as u8,
            priority: spec.priority,
            attachments: Vec::new(),
            filter: spec.filter.ir().native().to_string(),
        })?;
        Ok(handle)
    }

    /// Reads the registry when the timer says so, and queues what changed. Returns how many
    /// events that was.
    fn drain(&self) -> usize {
        let mut guard = lock(&self.rx.ring);
        let Some(seen) = guard.as_mut() else {
            return 0;
        };
        if !seen.timer.expired() {
            return 0;
        }
        let now = match Registry::lock_existing() {
            Ok(Some(registry)) => registry.entries().unwrap_or_default(),
            _ => Vec::new(),
        };
        let live = now.into_iter().filter(|(_, e)| e.alive()).collect();
        let mut events = diff(&mut seen.handles, live, sys::now_ns());
        drop(guard);
        events.retain(|e| {
            self.filter
                .matches(&Packet::parse(&[], Link::Ip), &e.addr.meta())
        });
        let n = events.len();
        self.rx.push(events);
        n
    }
}

impl Opened for ReflectHandle {
    fn recv(&self, buf: &mut [u8], timeout: Option<Duration>) -> Result<(usize, Address)> {
        self.rx.recv(buf, timeout, || self.drain())
    }

    fn recv_ready(&self, buf: &mut [u8]) -> Result<Option<(usize, Address)>> {
        self.rx.ready(buf, || self.drain())
    }

    fn send(&self, _: &[u8], _: &Address) -> Result<usize> {
        // `Handle` refuses it first: the layer needs RECV_ONLY.
        Err(Error::Unsupported("sending at the REFLECT layer"))
    }

    fn shutdown(&self, how: Shutdown) -> Result<()> {
        if matches!(how, Shutdown::Recv | Shutdown::Both) {
            self.rx.shut();
        }
        Ok(())
    }

    fn set_param(&self, param: Param, value: u64) -> Result<()> {
        lock(&self.rx.queue).queue.set(param, value);
        Ok(())
    }

    fn as_fd(&self) -> BorrowedFd<'_> {
        self.rx.epoll.as_fd()
    }

    fn close(self: Box<Self>) -> Result<()> {
        drop(self);
        Ok(())
    }
}

impl Drop for ReflectHandle {
    fn drop(&mut self) {
        if let Some(key) = self.registered
            && let Ok(registry) = Registry::lock()
        {
            let _ = registry.remove(key);
        }
    }
}
