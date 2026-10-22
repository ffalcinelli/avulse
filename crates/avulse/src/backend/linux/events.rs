//! The FLOW layer: the event programs (`avulse_ebpf::loader::Events`) report what sockets do,
//! and user space turns their records into addresses, ends the flows of the UDP sockets that go
//! away, and evaluates the filter. Events have no packet: the filter sees an empty one, so
//! protocol fields such as `ip` and `tcp` are false (WinDivert's rule), and it filters on
//! `event`, `local.*`, `remote.*`, `protocol` and `process.*`.

use std::collections::HashMap;
use std::io;
use std::net::Ipv6Addr;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::Arc;
use std::time::Duration;

use avulse_ebpf::abi::{self, Config, EV_OUTBOUND, EV_RELEASED, EventRecord};
use avulse_ebpf::loader::{self, Events};
use avulse_filter::{Event, Filter, Layer};
use avulse_proto::{Link, Packet};

use super::heartbeat::{self, Beat};
use super::record::{self, Entry};
use super::registry::{self, Registry};
use super::{Rx, io_error, lock, sys};
use crate::backend::{Opened, Spec};
use crate::{Address, Error, Flags, Param, Result, Shutdown};

/// The size of an event handle's ring buffer: 1 MiB, about 11,000 events.
const RING_BYTES: u32 = 1 << 20;
/// The UDP flows a handle remembers, to report their end when their socket goes away. Past it,
/// flows end without a DELETED event.
const MAX_UDP_FLOWS: usize = 65_536;

/// An open FLOW handle.
pub(super) struct EventHandle {
    layer: Layer,
    priority: i16,
    filter: Filter,
    sniff: bool,
    rx: Rx<EventRing>,
    beat: Arc<Beat>,
    /// The programs and their links, detached when dropped.
    events: Option<Events>,
    registered: Option<u64>,
}

/// The ring buffer, and the UDP flows of the sockets.
struct EventRing {
    buf: loader::Ring,
    udp: UdpFlows,
}

/// The UDP flows each socket established, by endpoint: the kernel reports the end of a socket,
/// once, and each of its flows ends with it.
#[derive(Default)]
pub(super) struct UdpFlows {
    flows: HashMap<u64, Vec<EventRecord>>,
    count: usize,
}

impl UdpFlows {
    /// The events record `r` stands for at the FLOW layer: itself, or, for the release of a UDP
    /// socket, a DELETED event for each flow it established.
    pub(super) fn events(&mut self, r: EventRecord) -> Vec<EventRecord> {
        if r.flags & EV_RELEASED != 0 {
            let flows = self.flows.remove(&r.endpoint).unwrap_or_default();
            self.count -= flows.len();
            return flows
                .into_iter()
                .map(|mut f| {
                    f.event = Event::FlowDeleted as u8;
                    f.flags &= !EV_RELEASED;
                    f.timestamp = r.timestamp;
                    f
                })
                .collect();
        }
        if r.protocol == 17 && r.event == Event::FlowEstablished as u8 && self.count < MAX_UDP_FLOWS
        {
            self.flows.entry(r.endpoint).or_default().push(r);
            self.count += 1;
        }
        vec![r]
    }
}

impl EventHandle {
    pub(super) fn open(spec: &Spec<'_>) -> Result<EventHandle> {
        let mut events = Events::load_with_ring(RING_BYTES).map_err(io_error)?;
        let ring = events
            .take_ring()
            .ok_or_else(|| Error::Io(io::Error::other("the event programs have no ring buffer")))?;
        let rx = Rx::new(spec.params)?;
        rx.epoll.add(ring.as_fd())?;
        *lock(&rx.ring) = Some(EventRing {
            buf: ring,
            udp: UdpFlows::default(),
        });
        let mut flags = 0;
        let sniff = spec.flags.contains(Flags::SNIFF);
        if sniff {
            flags |= abi::CFG_SNIFF;
        }
        let config = Config {
            flags,
            layer: spec.layer as u8,
            ..Config::default()
        };
        let beat = Arc::new(Beat::new(config, events.config_writer().map_err(io_error)?));
        // The configuration goes first, with a fresh heartbeat.
        beat.update(|_| {}).map_err(io_error)?;
        events.attach(spec.layer).map_err(|e| match e {
            loader::Error::Sys("cgroup2", _) => {
                Error::Unsupported("the event layers without a cgroup v2 hierarchy")
            }
            e => io_error(e),
        })?;
        let mut handle = EventHandle {
            layer: spec.layer,
            priority: spec.priority,
            filter: spec.filter.clone(),
            sniff,
            rx,
            beat,
            events: Some(events),
            registered: None,
        };
        // Registered for `cleanup` and REFLECT; the links go with the process, so there is
        // nothing to detach.
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
        drop(registry);
        heartbeat::add(&handle.beat);
        Ok(handle)
    }

    /// Moves the ring buffer's events to the queue, and returns how many records it read.
    fn drain(&self) -> usize {
        let mut guard = lock(&self.rx.ring);
        let Some(ring) = guard.as_mut() else {
            return 0;
        };
        let mut n = 0;
        let mut records = Vec::new();
        while let Some(item) = ring.buf.next() {
            n += 1;
            if let Some(r) = EventRecord::parse(&item) {
                records.push(r);
            }
        }
        let mut entries = Vec::new();
        for r in records {
            for e in ring.udp.events(r) {
                entries.extend(self.entry(&e));
            }
        }
        drop(guard);
        self.rx.push(entries);
        n
    }

    /// The event of `r`, if the filter matches it.
    fn entry(&self, r: &EventRecord) -> Option<Entry> {
        let addr = address(r, self.layer, self.sniff)?;
        let mut meta = addr.meta();
        meta.process_name = r.comm();
        meta.priority = self.priority;
        meta.hash = record::hash(&r.endpoint.to_ne_bytes());
        self.filter
            .matches(&Packet::parse(&[], Link::Ip), &meta)
            .then_some(Entry {
                addr,
                data: Vec::new(),
            })
    }
}

/// The event of number `n`.
fn event(n: u8) -> Option<Event> {
    Some(match n {
        1 => Event::FlowEstablished,
        2 => Event::FlowDeleted,
        3 => Event::SocketBind,
        4 => Event::SocketConnect,
        5 => Event::SocketListen,
        6 => Event::SocketAccept,
        7 => Event::SocketClose,
        _ => return None,
    })
}

fn is_loopback(a: &[u8; 16]) -> bool {
    Ipv6Addr::from(*a).to_canonical().is_loopback()
}

/// The address of an event record at `layer`; `None` if the record is inconsistent.
pub(super) fn address(r: &EventRecord, layer: Layer, sniffed: bool) -> Option<Address> {
    let mut addr = Address::new(layer);
    addr.timestamp = r.timestamp as i64;
    addr.event = event(r.event)?;
    addr.outbound = r.flags & EV_OUTBOUND != 0;
    addr.loopback = is_loopback(&r.local_addr) || is_loopback(&r.remote_addr);
    addr.ipv6 = r.family == 6;
    addr.sniffed = sniffed;
    let f = &mut addr.flow;
    f.endpoint_id = r.endpoint;
    f.parent_endpoint_id = r.parent_endpoint;
    f.process_id = r.pid;
    f.local_port = r.local_port;
    f.remote_port = r.remote_port;
    f.local_addr = r.local_addr;
    f.remote_addr = r.remote_addr;
    f.protocol = r.protocol;
    Some(addr)
}

impl Opened for EventHandle {
    fn recv(&self, buf: &mut [u8], timeout: Option<Duration>) -> Result<(usize, Address)> {
        self.rx.recv(buf, timeout, || self.drain())
    }

    fn send(&self, _: &[u8], _: &Address) -> Result<usize> {
        // `Handle` refuses it first: these layers need RECV_ONLY.
        Err(Error::Unsupported("sending at the event layers"))
    }

    fn shutdown(&self, how: Shutdown) -> Result<()> {
        if matches!(how, Shutdown::Recv | Shutdown::Both) {
            self.beat
                .update(|c| c.flags |= abi::CFG_SHUTDOWN)
                .map_err(io_error)?;
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

impl Drop for EventHandle {
    fn drop(&mut self) {
        let _ = self.beat.update(|c| c.flags |= abi::CFG_SHUTDOWN);
        self.events = None;
        if let Some(key) = self.registered
            && let Ok(registry) = Registry::lock()
        {
            let _ = registry.remove(key);
        }
    }
}
