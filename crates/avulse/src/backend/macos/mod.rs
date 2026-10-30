//! The macOS backend. Where the avulse system extension runs, its packet provider serves the
//! handles ([`extension`], Steps 33 and 34): they divert, drop, sniff and send. Without it (Step
//! 31), `/dev/bpf` copies the packets of the selected interfaces, and the filter runs here, in
//! user space: handles sniff and send, at the NETWORK and ETHERNET layers only.
//! [`capabilities`](Backend::capabilities) says which, per layer.
//!
//! The rest of this module is the bpf tier.
//! Each interface gets two bpf devices, one per direction (`BIOCSDIRECTION`), which is how a
//! packet's direction is known; a loopback interface gets the outbound one only, which sees each
//! of its packets once. Where the ioctl is missing, one device sees both, and a packet is
//! outbound when it comes from the interface's own address. `recv` reads the devices that a
//! `kqueue` says are readable into a queue, through the filter. Sending is in [`send`].
//!
//! Interfaces: all that are up, running and have an address that is not link-local (plus the
//! loopback interface), or the ones the handle names. The ETHERNET layer takes Ethernet
//! interfaces only. Interfaces that appear after the handle opens are not captured.

mod extension;
mod record;
mod send;
mod sys;
#[cfg(test)]
mod tests;
mod xpc;

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use avulse_filter::Layer;
use avulse_proto::{Link, Packet};

use self::record::{Entry, Source};
use self::send::Tx;
use self::sys::{Bpf, DLT_EN10MB, DLT_NULL};
use super::queue::Queue;
use super::{Backend, Capabilities, LayerSupport, Opened, Spec};
use crate::{Address, Error, Filter, Flags, Param, Result, Shutdown, Stats};

/// How many reads of one device a drain takes at most, so that a busy interface does not keep
/// `recv` from the others.
const READS_PER_DRAIN: usize = 8;

pub(crate) struct MacOs;

/// What the bpf tier supports.
fn bpf_capabilities() -> Capabilities {
    let mut c = Capabilities::NONE;
    for layer in [Layer::Network, Layer::Ethernet] {
        c.layers[layer as usize] = LayerSupport {
            open: true,
            inject: true,
            ..LayerSupport::default()
        };
    }
    c
}

impl Backend for MacOs {
    /// The extension's, layer by layer, where it serves the layer; the bpf tier's elsewhere.
    fn capabilities(&self) -> Capabilities {
        let mut c = bpf_capabilities();
        if let Some(ext) = extension::capabilities() {
            for (i, l) in ext.layers.iter().enumerate() {
                if l.open {
                    c.layers[i] = *l;
                }
            }
        }
        c
    }

    fn open(&self, spec: &Spec<'_>) -> Result<Box<dyn Opened>> {
        if let Some(res) = extension::ExtHandle::open_if_supported(spec) {
            return res.map(|h| Box::new(h) as Box<dyn Opened>);
        }
        if !matches!(spec.layer, Layer::Network | Layer::Ethernet) {
            return Err(Error::Unsupported(
                "the NETWORK_FORWARD, FLOW, SOCKET and REFLECT layers on macOS",
            ));
        }
        Ok(Box::new(Handle::open(spec)?))
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A bpf device and the interface it captures.
struct Device {
    bpf: Bpf,
    src: Source,
    name: String,
}

/// An open handle.
struct Handle {
    layer: Layer,
    priority: i16,
    filter: Filter,
    /// Whether inbound IP fragments are delivered ([`Flags::FRAGMENTS`]). Without it they are
    /// not, and neither is the packet they make: bpf sees packets before reassembly.
    fragments: bool,
    rx: Rx,
    tx: Tx,
    shut_send: AtomicBool,
}

/// The receive side.
struct Rx {
    /// The devices, and the buffer they are read into. Its lock serializes the readers. Empty
    /// after a shutdown.
    devices: Mutex<Devices>,
    queue: Mutex<QueueState>,
    /// Set while `recv` would not block: the queue has packets, or the handle is shut down.
    ready: sys::Flag,
    /// Readable when `ready` is, or a device has packets.
    kqueue: sys::Kqueue,
    /// Packets queued, and dropped by the devices whose buffers were full (counted at
    /// shutdown, for the devices it closes).
    sniffed: AtomicU64,
    closed_drops: AtomicU64,
}

#[derive(Default)]
struct Devices {
    list: Vec<Device>,
    buf: Vec<u8>,
}

struct QueueState {
    queue: Queue,
    shut: bool,
    ready: bool,
}

impl Handle {
    fn open(spec: &Spec<'_>) -> Result<Handle> {
        let rx = Rx::new(spec.params)?;
        if !spec.flags.contains(Flags::SEND_ONLY) {
            let list = devices(sys::interfaces()?, spec.interfaces, spec.layer)?;
            for d in &list {
                rx.kqueue.add(d.bpf.as_fd())?;
            }
            lock(&rx.devices).list = list;
        }
        Ok(Handle {
            layer: spec.layer,
            priority: spec.priority,
            filter: spec.filter.clone(),
            fragments: spec.flags.contains(Flags::FRAGMENTS),
            rx,
            tx: Tx::new(),
            shut_send: AtomicBool::new(false),
        })
    }

    /// Moves what the devices captured to the queue, through the filter. Returns how many
    /// packets it read.
    fn drain(&self) -> usize {
        let mut devs = lock(&self.rx.devices);
        let Devices { list, buf } = &mut *devs;
        let offset = sys::now_ns() - sys::wall_ns();
        let mut n = 0;
        let mut entries = Vec::new();
        for d in list.iter() {
            if buf.len() < d.bpf.blen {
                buf.resize(d.bpf.blen, 0);
            }
            for _ in 0..READS_PER_DRAIN {
                // A device that fails to read is skipped; the others go on.
                let got = d.bpf.read(&mut buf[..d.bpf.blen]).unwrap_or(0);
                if got == 0 {
                    break;
                }
                for f in record::frames(&buf[..got]) {
                    n += 1;
                    let Some(e) = record::entry(&f, &d.src, self.layer, offset) else {
                        continue;
                    };
                    if self.wanted(&e, &d.name) {
                        entries.push(e);
                    }
                }
            }
        }
        drop(devs);
        self.rx.push(entries);
        n
    }

    /// Whether the handle receives `e`, captured on interface `name`: not a packet it sent
    /// itself, not an inbound fragment unless it asked for them, and a match of its filter.
    fn wanted(&self, e: &Entry, name: &str) -> bool {
        let link = if self.layer == Layer::Ethernet {
            Link::Ethernet
        } else {
            Link::Ip
        };
        let packet = Packet::parse(&e.data, link);
        if self.layer != Layer::Ethernet
            && !self.fragments
            && !e.addr.outbound
            && packet.fragment().is_some()
        {
            return false;
        }
        if self.tx.sent(&e.data) {
            return false;
        }
        let mut meta = e.addr.meta();
        meta.iface = Some(name);
        meta.priority = self.priority;
        meta.hash = record::hash(&e.data);
        self.filter.matches(&packet, &meta)
    }
}

/// The devices of a handle at `layer`, on the interfaces in `names` (all suitable ones when it
/// is empty).
fn devices(all: Vec<sys::Interface>, names: &[String], layer: Layer) -> Result<Vec<Device>> {
    for name in names {
        if !all.iter().any(|i| &i.name == name) {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no interface {name}"),
            )));
        }
    }
    let chosen = |i: &sys::Interface| {
        if !names.is_empty() {
            return names.contains(&i.name);
        }
        let routable = |a: &IpAddr| match a {
            IpAddr::V4(a) => !a.is_link_local(),
            IpAddr::V6(a) => !a.is_unicast_link_local(),
        };
        i.up && i.running
            && match layer {
                Layer::Ethernet => !i.loopback && i.mac.is_some(),
                _ => i.loopback || i.addrs.iter().any(routable),
            }
    };
    let mut list = Vec::new();
    for i in all.into_iter().filter(chosen) {
        let named = !names.is_empty();
        // A loopback interface's packets are outbound only: an inbound device sees none of them.
        let first = !i.loopback;
        let mut pair = match Bpf::open(&i.name, Some(!first)) {
            Ok(dev) if i.loopback => vec![(dev, Some(true))],
            Ok(inbound) => {
                let outbound = Bpf::open(&i.name, Some(true))?;
                vec![(inbound, Some(false)), (outbound, Some(true))]
            }
            Err(e) if e.kind() == io::ErrorKind::Unsupported => {
                vec![(Bpf::open(&i.name, None)?, None)]
            }
            // Some interfaces have no bpf attachment; skip them unless the handle named them.
            Err(_) if !named => continue,
            Err(e) => return Err(Error::Io(e)),
        };
        let dlt = pair[0].0.dlt;
        let suits = match dlt {
            DLT_EN10MB => true,
            DLT_NULL => layer != Layer::Ethernet,
            _ => false,
        };
        if !suits {
            if !named {
                continue;
            }
            return Err(Error::Unsupported(if dlt == DLT_NULL {
                "the ETHERNET layer on interfaces without an Ethernet header (lo0, utun)"
            } else {
                "interfaces other than Ethernet, loopback and utun"
            }));
        }
        for (bpf, outbound) in pair.drain(..) {
            list.push(Device {
                bpf,
                src: Source {
                    outbound,
                    ifindex: i.index,
                    dlt,
                    loopback: i.loopback,
                    mac: i.mac,
                    addrs: i.addrs.clone(),
                },
                name: i.name.clone(),
            });
        }
    }
    Ok(list)
}

impl Rx {
    fn new(params: [u64; 3]) -> io::Result<Rx> {
        let ready = sys::Flag::new()?;
        let kqueue = sys::Kqueue::new()?;
        kqueue.add(ready.as_fd())?;
        Ok(Rx {
            devices: Mutex::new(Devices::default()),
            queue: Mutex::new(QueueState {
                queue: Queue::new(params),
                shut: false,
                ready: false,
            }),
            ready,
            kqueue,
            sniffed: AtomicU64::new(0),
            closed_drops: AtomicU64::new(0),
        })
    }

    /// Queues what `drain` read, and wakes the readers.
    fn push(&self, entries: Vec<Entry>) {
        if entries.is_empty() {
            return;
        }
        self.sniffed
            .fetch_add(entries.len() as u64, Ordering::Relaxed);
        let mut q = lock(&self.queue);
        for e in entries {
            q.queue.push(e);
        }
        self.update(&mut q);
    }

    /// After a shutdown of the receive side, `drain` (called first) has queued what the devices
    /// held; they close, what is queued is delivered, then `recv` fails with
    /// [`Error::Shutdown`].
    fn shut(&self) {
        let list = std::mem::take(&mut lock(&self.devices).list);
        let drops: u64 = list.iter().map(|d| d.bpf.drops()).sum();
        self.closed_drops.fetch_add(drops, Ordering::Relaxed);
        drop(list);
        let mut q = lock(&self.queue);
        q.shut = true;
        self.update(&mut q);
    }

    /// Waits for a packet, at most `timeout`. `drain` moves the devices' packets to the queue
    /// ([`push`](Rx::push)) and returns how many it read.
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
            if shut {
                return Err(Error::Shutdown);
            }
            if drain() > 0 {
                continue;
            }
            let wait = match deadline {
                None => -1,
                Some(d) => {
                    let left = d.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(Error::Timeout);
                    }
                    left.as_millis().clamp(1, i64::MAX as u128) as i64
                }
            };
            self.kqueue.wait(wait)?;
        }
    }

    /// A packet that is already there (queued, or in a device: `drain` moves it to the queue)
    /// and fits `buf`; `None` otherwise, and one that does not fit stays first in line.
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
        self.tx.send(packet, addr, self.layer)?;
        Ok(packet.len())
    }

    fn shutdown(&self, how: Shutdown) -> Result<()> {
        if matches!(how, Shutdown::Recv | Shutdown::Both) {
            self.drain();
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
        let mut s = Stats::default();
        s.sniffed = self.rx.sniffed.load(Ordering::Relaxed);
        s.ring_full = self.rx.closed_drops.load(Ordering::Relaxed)
            + lock(&self.rx.devices)
                .list
                .iter()
                .map(|d| d.bpf.drops())
                .sum::<u64>();
        s.queue_drops = lock(&self.rx.queue).queue.drops;
        Ok(s)
    }

    fn as_fd(&self) -> BorrowedFd<'_> {
        self.rx.kqueue.as_fd()
    }

    fn close(self: Box<Self>) -> Result<()> {
        drop(self);
        Ok(())
    }
}
