//! The Linux backend: eBPF programs on the TC hooks of each interface (`avulse-ebpf`).
//!
//! Each handle loads its own instance of the static programs, with its own maps, and its filter
//! compiled to an eBPF matcher. When the code generator cannot compile the filter, or the
//! verifier rejects it, the matcher takes every packet of the layer and user space evaluates the
//! filter on each record, reinjecting what does not match. The programs are attached as classic
//! cls_bpf filters at TC priority `30001 - priority`, on the selected interfaces and on `lo`:
//! Ethernet devices, and at the NETWORK layers devices without a link-layer header too (tun,
//! WireGuard, IP tunnels), which get the programs that read packets from the IP header.
//! Matching packets go to a ring buffer, which `recv` drains into a queue; `send` injects
//! packets through raw and `AF_PACKET` sockets (`send.rs`).

mod events;
mod heartbeat;
mod queue;
mod record;
mod reflect;
mod registry;
mod send;
mod sys;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use avulse_ebpf::abi::{self, Config, Record};
use avulse_ebpf::codegen::{self, Env};
use avulse_ebpf::loader::{self, Classifier, Hook};
use avulse_filter::{Filter, Layer};
use avulse_proto::{Link, Packet};

use self::heartbeat::Beat;
use self::queue::Queue;
use self::record::Entry;
use self::registry::Registry;
use self::send::Tx;
use super::{Backend, Capabilities, LayerSupport, Opened, Spec};
use crate::{Address, Error, Flags, Param, Result, Shutdown, Stats};

/// TC priority of a handle of priority 0 when no other handle is open, and the base of
/// `30001 - priority`.
const TC_PRIORITY_BASE: u32 = 30_001;

pub(crate) struct Linux;

impl Backend for Linux {
    fn capabilities(&self) -> Capabilities {
        let packets = LayerSupport {
            open: true,
            divert: true,
            drop: true,
            inject: true,
            modify: true,
        };
        let mut c = Capabilities::NONE;
        for layer in [Layer::Network, Layer::NetworkForward, Layer::Ethernet] {
            c.layers[layer as usize] = packets;
        }
        // Flows are reported, never held; binds and connects can be refused.
        c.layers[Layer::Flow as usize] = LayerSupport {
            open: true,
            ..LayerSupport::default()
        };
        c.layers[Layer::Socket as usize] = LayerSupport {
            open: true,
            divert: true,
            drop: true,
            ..LayerSupport::default()
        };
        c.layers[Layer::Reflect as usize] = LayerSupport {
            open: true,
            ..LayerSupport::default()
        };
        c
    }

    fn open(&self, spec: &Spec<'_>) -> Result<Box<dyn Opened>> {
        match spec.layer {
            Layer::Network | Layer::NetworkForward | Layer::Ethernet => {
                Ok(Box::new(Handle::open(spec)?))
            }
            Layer::Flow | Layer::Socket => Ok(Box::new(events::EventHandle::open(spec)?)),
            Layer::Reflect => Ok(Box::new(reflect::ReflectHandle::open(spec)?)),
        }
    }

    fn cleanup(&self) -> Result<usize> {
        match Registry::lock_existing()? {
            Some(registry) => Ok(registry.reap()?),
            None => Ok(0),
        }
    }
}

/// An I/O error, keeping the kind of the system error under it (such as `PermissionDenied`).
fn io_error(e: loader::Error) -> Error {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&e);
    while let Some(s) = source {
        if let Some(io) = s.downcast_ref::<io::Error>() {
            return Error::Io(io::Error::new(io.kind(), e.to_string()));
        }
        source = s.source();
    }
    Error::Io(io::Error::other(e.to_string()))
}

/// The TC priorities of this process's open handles, for when the registry is unavailable.
static LOCAL_TC_PRIORITIES: Mutex<Vec<u16>> = Mutex::new(Vec::new());

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// An open handle.
struct Handle {
    layer: Layer,
    priority: i16,
    /// The filter, when user space must evaluate it (the kernel matcher is not exact).
    filter: Option<Filter>,
    /// User space drops what `filter` matches (`DROP` with an inexact matcher).
    drop: bool,
    rx: Rx<Ring>,
    tx: Tx,
    shut_send: AtomicBool,
    /// The heartbeat and configuration. `SEND_ONLY` handles capture nothing (their programs are
    /// shut down, on `lo`'s ingress only, for the redirect of inbound packets) and need no
    /// heartbeat.
    beat: Option<Arc<Beat>>,
    /// The programs and their TC filters, detached when dropped.
    classifier: Option<Classifier>,
    /// The registry key.
    registered: Option<u64>,
    /// The TC priority, while it is in [`LOCAL_TC_PRIORITIES`]; its packets carry it in their mark.
    tc_priority: Option<u16>,
}

/// The receive side: `R` is the ring buffer, with what draining it needs.
struct Rx<R> {
    /// The ring buffer. Its lock serializes the readers.
    ring: Mutex<Option<R>>,
    queue: Mutex<QueueState>,
    /// Set while `recv` would not block: the queue has packets, or the handle is shut down.
    ready: sys::Flag,
    /// Readable when `ready` is, or the ring buffer has records.
    epoll: sys::Epoll,
}

struct Ring {
    buf: loader::Ring,
    /// Interface names by index, for filters on `iface`.
    names: HashMap<u32, String>,
}

struct QueueState {
    queue: Queue,
    shut: bool,
    ready: bool,
}

impl Handle {
    fn open(spec: &Spec<'_>) -> Result<Handle> {
        let lo = sys::interfaces()?
            .into_iter()
            .find(|i| i.kind == sys::ARPHRD_LOOPBACK)
            .map_or(1, |i| i.index);
        let send_only = spec.flags.contains(Flags::SEND_ONLY);
        let rx = Rx::new(spec.params)?;
        let mut handle = Handle {
            layer: spec.layer,
            priority: spec.priority,
            filter: None,
            drop: false,
            rx,
            tx: Tx::new(lo),
            shut_send: AtomicBool::new(false),
            beat: None,
            classifier: None,
            registered: None,
            tc_priority: None,
        };
        // A SEND_ONLY handle attaches to lo's ingress only, which redirects the inbound packets it
        // injects; it receives nothing.
        let (targets, ring_bytes) = if send_only {
            let lo = sys::interfaces()?
                .into_iter()
                .filter(|i| i.kind == sys::ARPHRD_LOOPBACK)
                .map(|i| (i, Link::Ethernet))
                .collect();
            let page = u32::try_from(sys::page_size()).unwrap_or(4096);
            (
                Targets {
                    list: lo,
                    lo_selected: false,
                },
                page,
            )
        } else {
            (
                targets(sys::interfaces()?, spec.interfaces, spec.layer)?,
                loader::DEFAULT_RING_BYTES,
            )
        };

        let mut classifier = Classifier::load_with_ring(ring_bytes).map_err(io_error)?;
        let mut flags = 0;
        if send_only {
            flags |= abi::CFG_SHUTDOWN;
        } else {
            let (exact, options) = set_matcher(&mut classifier, spec)?;
            if options {
                flags |= abi::CFG_TCP_OPTIONS;
            }
            if !exact {
                // The kernel diverts (or copies) every packet of the layer; user space reinjects
                // (or ignores) what the filter does not match, and drops what it matches.
                handle.filter = Some(spec.filter.clone());
                handle.drop = spec.flags.contains(Flags::DROP);
            }
            let ring = classifier
                .take_ring()
                .ok_or_else(|| Error::Io(io::Error::other("the classifier has no ring buffer")))?;
            handle.rx.epoll.add(ring.as_fd())?;
            *lock(&handle.rx.ring) = Some(Ring {
                buf: ring,
                names: HashMap::new(),
            });
            if spec.flags.contains(Flags::SNIFF) {
                flags |= abi::CFG_SNIFF;
            }
            if spec.flags.contains(Flags::DROP) && exact {
                flags |= abi::CFG_DROP;
            }
            if spec.flags.contains(Flags::FRAGMENTS) {
                flags |= abi::CFG_FRAGMENTS;
            }
            if sys::sysctl_on("net/ipv4/ip_forward")
                || sys::sysctl_on("net/ipv6/conf/all/forwarding")
            {
                flags |= abi::CFG_FWD_CHECK;
            }
            if !targets.lo_selected {
                flags |= abi::CFG_SKIP_LO;
            }
        }

        // Under the lock: the TC priority depends on the other handles, and must be registered
        // before another process picks one.
        let registry = Registry::lock()?;
        let _ = registry.reap();
        let tc_priority = tc_priority(spec.priority, &registry)?;
        let config = Config {
            flags,
            priority: tc_priority as u32,
            lo_ifindex: lo,
            layer: spec.layer as u8,
            ..Config::default()
        };
        // The configuration goes first: a program attached with the zero configuration would
        // divert at the NETWORK layer, with no heartbeat check.
        let beat = Arc::new(Beat::new(
            config,
            classifier.config_writer().map_err(io_error)?,
        ));
        beat.update(|_| {}).map_err(io_error)?;
        let hooks: &[Hook] = if send_only {
            &[Hook::Ingress]
        } else {
            &[Hook::Ingress, Hook::Egress]
        };
        let mut attachments = Vec::new();
        for (iface, link) in &targets.list {
            for &hook in hooks {
                // Dropping the classifier detaches what is attached so far.
                attachments.push(
                    classifier
                        .attach(&iface.name, hook, *link, tc_priority)
                        .map_err(io_error)?,
                );
            }
        }
        handle.classifier = Some(classifier);
        handle.registered = registry.add(&registry::Entry {
            pid: sys::pid(),
            start_time: sys::start_time(sys::pid()).unwrap_or(0),
            tc_priority,
            timestamp: sys::now_ns(),
            flags: spec.flags.bits(),
            layer: spec.layer as u8,
            priority: spec.priority,
            attachments,
            filter: spec.source.to_owned(),
            syntax: spec.syntax as u8,
        })?;
        lock(&LOCAL_TC_PRIORITIES).push(tc_priority);
        handle.tc_priority = Some(tc_priority);
        drop(registry);
        if !send_only {
            heartbeat::add(&beat);
        }
        handle.beat = Some(beat);
        Ok(handle)
    }

    /// The TC priority its packets carry in their mark.
    fn mark_priority(&self) -> u16 {
        self.tc_priority.unwrap_or(TC_PRIORITY_BASE as u16)
    }
}

/// Generates the matcher: the filter exactly, or else a superset of it (unsupported tests
/// widened), or else every packet of the layer, when the code generator cannot compile it or
/// the verifier rejects it. Returns whether the kernel matcher is exact (when it is not, user
/// space filters what it diverts), and whether it reads TCP options.
fn set_matcher(classifier: &mut Classifier, spec: &Spec<'_>) -> Result<(bool, bool)> {
    let resolve = |name: &str| loader::if_index(name).ok();
    let env = Env {
        layer: spec.layer,
        priority: spec.priority,
        ifindex: &resolve,
        event: None,
    };
    let ir = spec.filter.ir();
    let candidates = [
        codegen::compile_superset(ir, &env),
        codegen::everything(&env),
    ];
    for m in candidates.into_iter().flatten() {
        match classifier.set_matcher(&m) {
            Ok(_) => return Ok((m.exact(), m.reads_tcp_options())),
            Err(loader::Error::Rejected { .. }) => {}
            Err(e) => return Err(io_error(e)),
        }
    }
    Err(Error::Io(io::Error::other(
        "the verifier rejects every matcher",
    )))
}

/// The TC priority of a handle: `30001 - priority`, or after every open handle for priority 0.
fn tc_priority(priority: i16, registry: &Registry) -> Result<u16> {
    if priority != 0 {
        return Ok((TC_PRIORITY_BASE as i32 - priority as i32) as u16);
    }
    let local = lock(&LOCAL_TC_PRIORITIES).iter().copied().max();
    Ok(after(registry.max_tc_priority()?.max(local.unwrap_or(0))))
}

/// The TC priority after `max`, the highest in use: at least that of priority 0.
fn after(max: u16) -> u16 {
    if (max as u32) < TC_PRIORITY_BASE {
        TC_PRIORITY_BASE as u16
    } else {
        max.saturating_add(1)
    }
}

/// The interfaces to attach to, with the header their packets start with.
struct Targets {
    list: Vec<(sys::Interface, Link)>,
    /// Whether the application selected `lo` (it is attached anyway).
    lo_selected: bool,
}

/// Of the interfaces `all`, those to attach to at `layer`: the selected ones (every one when
/// `names` is empty) the programs support at the layer, plus the loopback device. Devices
/// without a link-layer header serve the NETWORK layers only: they carry no frames.
fn targets(all: Vec<sys::Interface>, names: &[String], layer: Layer) -> Result<Targets> {
    let supported = |i: &sys::Interface| match i.link() {
        Some(Link::Ip) if layer == Layer::Ethernet => None,
        link => link,
    };
    for name in names {
        match all.iter().find(|i| &i.name == name) {
            None => {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no interface {name}"),
                )));
            }
            Some(i) if i.link() == Some(Link::Ip) && supported(i).is_none() => {
                return Err(Error::Unsupported(
                    "the ETHERNET layer on interfaces without an Ethernet header (tun, \
                     WireGuard, IP tunnels)",
                ));
            }
            Some(i) if supported(i).is_none() => {
                return Err(Error::Unsupported(
                    "interfaces other than Ethernet, loopback, tun, PPP and IP-in-IP tunnels",
                ));
            }
            Some(_) => {}
        }
    }
    let selected = |i: &sys::Interface| names.is_empty() || names.contains(&i.name);
    let lo_selected = all
        .iter()
        .any(|i| i.kind == sys::ARPHRD_LOOPBACK && selected(i));
    let list = all
        .into_iter()
        .filter_map(|i| {
            let link = supported(&i)?;
            (i.kind == sys::ARPHRD_LOOPBACK || selected(&i)).then_some((i, link))
        })
        .collect();
    Ok(Targets { list, lo_selected })
}

impl<R> Rx<R> {
    /// The handle's counters: the kernel's (indexed by [`abi::stat`]) and the queue's drops.
    fn stats(&self, kernel: [u64; abi::stat::COUNT]) -> Stats {
        use abi::stat;
        let mut s = Stats::default();
        s.diverted = kernel[stat::DIVERTED];
        s.sniffed = kernel[stat::SNIFFED];
        s.dropped = kernel[stat::DROPPED];
        s.ring_full = kernel[stat::RING_FULL];
        s.owner_gone = kernel[stat::OWNER_GONE];
        s.too_big = kernel[stat::TOO_BIG];
        s.load_errors = kernel[stat::LOAD_ERR];
        s.queue_drops = lock(&self.queue).queue.drops;
        s
    }

    fn new(params: [u64; 3]) -> io::Result<Rx<R>> {
        let ready = sys::Flag::new()?;
        let epoll = sys::Epoll::new()?;
        epoll.add(ready.as_fd())?;
        Ok(Rx {
            ring: Mutex::new(None),
            queue: Mutex::new(QueueState {
                queue: Queue::new(params),
                shut: false,
                ready: false,
            }),
            ready,
            epoll,
        })
    }

    /// Queues what `drain` took from the ring, and wakes the readers.
    fn push(&self, entries: Vec<Entry>) {
        if entries.is_empty() {
            return;
        }
        let mut q = lock(&self.queue);
        for e in entries {
            q.queue.push(e);
        }
        self.update(&mut q);
    }

    /// After a shutdown of the receive side: what is queued or in the ring is delivered, then
    /// `recv` fails with [`Error::Shutdown`].
    fn shut(&self) {
        let mut q = lock(&self.queue);
        q.shut = true;
        self.update(&mut q);
    }

    /// Waits for a packet or an event, at most `timeout`. `drain` moves the ring's records to
    /// the queue ([`push`](Rx::push)) and returns how many it read.
    fn recv(
        &self,
        buf: &mut [u8],
        timeout: Option<Duration>,
        drain: impl Fn() -> usize,
    ) -> Result<(usize, Address)> {
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            let shut = {
                let mut q = lock(&self.queue);
                let e = q.queue.pop(sys::now_ns());
                self.update(&mut q);
                if let Some(e) = e {
                    drop(q);
                    let n = e.data.len();
                    let dst = buf
                        .get_mut(..n)
                        .ok_or(Error::BufferTooSmall { needed: n })?;
                    dst.copy_from_slice(&e.data);
                    return Ok((n, e.addr));
                }
                q.shut
            };
            // After a shutdown, what the ring still holds is delivered first.
            if drain() > 0 {
                continue;
            }
            if shut {
                return Err(Error::Shutdown);
            }
            let wait = match deadline {
                None => -1,
                Some(d) => {
                    let left = d.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(Error::Timeout);
                    }
                    left.as_millis().clamp(1, i32::MAX as u128) as i32
                }
            };
            self.epoll.wait(wait)?;
        }
    }

    /// A packet or event that is already there (queued, or in the ring: `drain` moves it to the
    /// queue) and fits `buf`; `None` otherwise, and one that does not fit stays first in line.
    fn ready(&self, buf: &mut [u8], drain: impl Fn() -> usize) -> Result<Option<(usize, Address)>> {
        for first in [true, false] {
            {
                let mut q = lock(&self.queue);
                let e = q.queue.pop(sys::now_ns());
                let got = e.and_then(|e| match buf.get_mut(..e.data.len()) {
                    Some(dst) => {
                        dst.copy_from_slice(&e.data);
                        Some((e.data.len(), e.addr))
                    }
                    None => {
                        q.queue.unpop(e);
                        None
                    }
                });
                let empty = q.queue.is_empty();
                self.update(&mut q);
                if got.is_some() || !empty {
                    return Ok(got);
                }
            }
            if !first || drain() == 0 {
                break;
            }
        }
        Ok(None)
    }

    /// Makes `ready` say whether `recv` would return at once.
    fn update(&self, q: &mut QueueState) {
        let want = q.shut || !q.queue.is_empty();
        if want != q.ready {
            if want {
                self.ready.set();
            } else {
                self.ready.clear();
            }
            q.ready = want;
        }
    }
}

impl Handle {
    /// Moves the ring buffer's records to the queue. Returns how many it read.
    fn drain(&self) -> usize {
        let mut ring = lock(&self.rx.ring);
        let Some(ring) = ring.as_mut() else {
            return 0;
        };
        let mut n = 0;
        let mut entries = Vec::new();
        while let Some(item) = ring.buf.next() {
            n += 1;
            let Some(e) = Record::parse(&item).and_then(|r| record::entry(&r, self.layer)) else {
                continue;
            };
            drop(item);
            if let Some(filter) = &self.filter {
                if !self.matches(filter, &e, &mut ring.names) {
                    // Not for this handle: a copy is ignored, a diverted packet goes back. A
                    // failure loses the packet, as a full queue does.
                    if !e.addr.sniffed {
                        let _ =
                            self.tx
                                .send(&e.data, &e.addr, self.layer, self.mark_priority(), false);
                    }
                    continue;
                }
                if self.drop {
                    continue;
                }
            }
            entries.push(e);
        }
        self.rx.push(entries);
        n
    }

    fn matches(&self, filter: &Filter, e: &Entry, names: &mut HashMap<u32, String>) -> bool {
        let link = if self.layer == Layer::Ethernet {
            Link::Ethernet
        } else {
            Link::Ip
        };
        let name = names
            .entry(e.addr.if_idx)
            .or_insert_with(|| loader::if_name(e.addr.if_idx).unwrap_or_default());
        let mut meta = e.addr.meta();
        meta.iface = Some(name);
        meta.priority = self.priority;
        meta.hash = record::hash(&e.data);
        filter.matches(&Packet::parse(&e.data, link), &meta)
    }
}

impl Opened for Handle {
    fn recv(&self, buf: &mut [u8], timeout: Option<Duration>) -> Result<(usize, Address)> {
        self.rx.recv(buf, timeout, || self.drain())
    }

    fn recv_ready(&self, buf: &mut [u8]) -> Result<Option<(usize, Address)>> {
        self.rx.ready(buf, || self.drain())
    }

    fn send(&self, packet: &[u8], addr: &Address) -> Result<usize> {
        if self.shut_send.load(Ordering::Acquire) {
            return Err(Error::Shutdown);
        }
        self.tx
            .send(packet, addr, self.layer, self.mark_priority(), true)?;
        Ok(packet.len())
    }

    fn shutdown(&self, how: Shutdown) -> Result<()> {
        if matches!(how, Shutdown::Recv | Shutdown::Both) {
            if let Some(beat) = &self.beat {
                beat.update(|c| c.flags |= abi::CFG_SHUTDOWN)
                    .map_err(io_error)?;
            }
            self.rx.shut();
        }
        if matches!(how, Shutdown::Send | Shutdown::Both) {
            self.shut_send.store(true, Ordering::Release);
        }
        Ok(())
    }

    fn set_param(&self, param: Param, value: u64) -> Result<()> {
        lock(&self.rx.queue).queue.set(param, value);
        Ok(())
    }

    fn stats(&self) -> Result<Stats> {
        let kernel = match &self.classifier {
            Some(c) => c.stats().map_err(io_error)?,
            None => [0; abi::stat::COUNT],
        };
        Ok(self.rx.stats(kernel))
    }

    fn as_fd(&self) -> BorrowedFd<'_> {
        self.rx.epoll.as_fd()
    }

    fn close(self: Box<Self>) -> Result<()> {
        drop(self);
        Ok(())
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // Stop the heartbeat first: if detaching fails, the filters left behind fail open.
        if let Some(beat) = self.beat.take() {
            let _ = beat.update(|c| c.flags |= abi::CFG_SHUTDOWN);
        }
        // Detach and unregister under the lock, so that no other handle takes the TC priority
        // before the filters are gone.
        let registry = self.registered.and_then(|_| Registry::lock().ok());
        self.classifier = None;
        if let (Some(registry), Some(key)) = (&registry, self.registered) {
            let _ = registry.remove(key);
        }
        if let Some(p) = self.tc_priority {
            let mut local = lock(&LOCAL_TC_PRIORITIES);
            if let Some(i) = local.iter().position(|&q| q == p) {
                local.swap_remove(i);
            }
        }
    }
}
