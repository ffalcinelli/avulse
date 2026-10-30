//! The extension's state: the handles, sorted by priority; the packets they hold; the notes of
//! what their clients inject; and the requests that change them.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use avulse_abi::ioctl::{self, OpenRequest, Record};
use avulse_abi::macos::{
    self, MacContext, Op, Request, SendResult, Status, TestFlow, decode_recv, decode_test_packet,
    encode_response, support,
};
use avulse_abi::{Address, Flags, Flow, Param, Shutdown, Stats, Syntax};
use avulse_filter::{Event, Filter, Layer};
use avulse_proto::{Link, Packet, checksum};

/// How long a diverted packet a client received may wait to be sent back before it is dropped,
/// as WinDivert drops a diverted packet that is never reinjected.
pub const HOLD_MAX: Duration = Duration::from_secs(10);
/// How long a note of an injected packet waits for the packet.
const NOTE_TTL: Duration = Duration::from_secs(2);
/// How many notes are kept at most.
const NOTES_MAX: usize = 1024;
/// How many packets are held at most, all handles together.
const HELD_MAX: usize = 65_536;
/// How many flows are watched for their end at most.
const FLOWS_MAX: usize = 65_536;

/// What the provider does with a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Verdict {
    /// Let it go on.
    Allow = 0,
    /// Drop it.
    Drop = 1,
    /// Hold it (`delayCurrentPacket`) under the token the packet path returns, until the
    /// release callback says what becomes of it.
    Delay = 2,
}

/// A packet as the provider gets it.
#[derive(Clone, Copy, Debug)]
pub struct Seen<'a> {
    /// The interface's index.
    pub ifindex: u32,
    /// The interface's name, for filters on `iface`.
    pub ifname: &'a str,
    /// Whether the packet is outbound.
    pub outbound: bool,
    /// Whether the interface is a loopback one.
    pub loopback: bool,
    /// A frame, or an IP packet: [`link_of`] tells.
    pub data: &'a [u8],
}

/// A flow the data provider sees start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowStart {
    /// Whether the local side opened it (a connect), rather than accepted it.
    pub outbound: bool,
    /// The IP protocol.
    pub protocol: u8,
    /// The process that owns the socket, and its name when known.
    pub pid: u32,
    /// The process's name, when known.
    pub process_name: Option<String>,
    /// The local address and port.
    pub local: IpAddr,
    /// The local port.
    pub local_port: u16,
    /// The remote address.
    pub remote: IpAddr,
    /// The remote port.
    pub remote_port: u16,
}

/// What becomes of a held packet: the provider's `allowPacket:` (`true`) or its release, which
/// drops it (`false`).
pub type Release = Box<dyn Fn(u64, bool) + Send + Sync>;

/// The extension.
pub struct Extension {
    state: Mutex<State>,
    /// Signalled when a queue gets a packet, or a handle shuts down or closes.
    wake: Condvar,
    release: Release,
    /// Whether `TestPacket` requests are served: only without the provider.
    test_mode: bool,
}

#[derive(Default)]
struct State {
    handles: BTreeMap<u64, Handle>,
    /// The handles' keys, in the order packets visit them.
    order: Vec<Key>,
    next_id: u64,
    next_token: u64,
    held: HashMap<u64, Held>,
    notes: Vec<Note>,
    /// Whether the provider's packets start with a link-layer header, from the first one seen.
    frames: Option<bool>,
    /// Whether the data provider runs: the FLOW and SOCKET layers need it.
    flows_on: bool,
    /// The flows whose end is wanted, by id.
    flows: HashMap<u64, Flow>,
    next_flow: u64,
    last_sweep: Option<Instant>,
}

/// Where a handle stands in the chain: higher priorities first, then the older handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    priority: Reverse<i16>,
    id: u64,
}

struct Handle {
    key: Key,
    conn: u64,
    /// What REFLECT reports: the process that opened it, when, and the filter as written.
    pid: u32,
    opened: i64,
    source: String,
    syntax: Syntax,
    layer: Layer,
    flags: Flags,
    filter: Filter,
    interfaces: Vec<u32>,
    queue: VecDeque<Queued>,
    bytes: u64,
    params: [u64; 3],
    shut_recv: bool,
    shut_send: bool,
    stats: Stats,
}

struct Queued {
    addr: Address,
    data: Vec<u8>,
    /// When it was queued, for `QUEUE_TIME`.
    at: Instant,
}

/// A packet the provider holds for a handle.
struct Held {
    data: Vec<u8>,
    ifindex: u32,
    ifname: String,
    outbound: bool,
    loopback: bool,
    /// The handle it was diverted to.
    holder: Key,
    /// When the client received it; `None` while it is queued.
    received: Option<Instant>,
}

/// A packet a client is about to inject: handles at `priority` and above skip it, lower ones
/// see an impostor.
struct Note {
    hash: u64,
    priority: i16,
    at: Instant,
}

/// What the chain decided for a packet.
enum Outcome {
    Allow,
    Drop,
    /// Diverted to the handle with this id, under this address.
    Divert(u64, Box<Address>, Vec<u8>),
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Whether `data` is a frame (`Link::Ethernet`) or an IP packet: an IP packet's version and
/// length agree with its size.
pub fn link_of(data: &[u8]) -> Link {
    let ip_len = match data.first().map(|b| b >> 4) {
        Some(4) if data.len() >= 20 => usize::from(u16::from_be_bytes([data[2], data[3]])),
        Some(6) if data.len() >= 40 => 40 + usize::from(u16::from_be_bytes([data[4], data[5]])),
        _ => return Link::Ethernet,
    };
    if ip_len == data.len() {
        Link::Ip
    } else {
        Link::Ethernet
    }
}

/// The link-layer header and the IP packet of `data` (`None` for a frame that carries no IP).
fn split(data: &[u8], link: Link) -> (&[u8], Option<&[u8]>) {
    if link == Link::Ip {
        return (&[], Some(data));
    }
    let p = Packet::parse(data, Link::Ethernet);
    match p.l3_offset() {
        Some(at) if p.ipv4().is_some() || p.ipv6().is_some() => (&data[..at], Some(&data[at..])),
        _ => (data, None),
    }
}

/// What a handle at `layer` sees of `data`: the IP packet at NETWORK, the frame at ETHERNET.
fn view(data: &[u8], link: Link, layer: Layer) -> Option<&[u8]> {
    match layer {
        Layer::Ethernet => (link == Link::Ethernet).then_some(data),
        Layer::Network => split(data, link).1,
        // The event layers get no packets.
        _ => None,
    }
}

/// A hash of a packet's bytes (64-bit FNV-1a), for the notes and the `random*` fields.
pub fn hash(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ b as u64).wrapping_mul(0x0100_0000_01b3)
    })
}

/// What notes and the packet path hash: the IP packet when there is one.
fn note_hash(data: &[u8], link: Link) -> u64 {
    hash(split(data, link).1.unwrap_or(data))
}

/// Nanoseconds of the monotonic clock, which the backend's queue shares.
#[cfg(unix)]
fn now_ns() -> i64 {
    // SAFETY: an all-zero timespec is valid, and clock_gettime fills it.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as i64 * 1_000_000_000 + ts.tv_nsec as i64
}

/// Elsewhere (the tests on Windows), nanoseconds since the first call.
#[cfg(not(unix))]
fn now_ns() -> i64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as i64
}

fn response(status: Status) -> Vec<u8> {
    encode_response(status, &[])
}

impl Extension {
    /// An extension that tells the provider what becomes of held packets through `release`.
    pub fn new(release: Release, test_mode: bool) -> Extension {
        Extension {
            state: Mutex::new(State {
                next_id: 1,
                next_token: 1,
                next_flow: 1,
                flows_on: test_mode,
                ..State::default()
            }),
            wake: Condvar::new(),
            release,
            test_mode,
        }
    }

    fn fire(&self, releases: Vec<(u64, bool)>) {
        for (token, allow) in releases {
            (self.release)(token, allow);
        }
    }

    /// The packet path: what the provider does with `p`, and the token to hold it under when it
    /// is [`Verdict::Delay`].
    pub fn packet(&self, p: &Seen<'_>) -> (Verdict, u64) {
        let mut releases = Vec::new();
        let r = {
            let mut st = lock(&self.state);
            st.sweep(&mut releases);
            let link = link_of(p.data);
            st.frames.get_or_insert(link == Link::Ethernet);
            if st.order.is_empty() {
                (Verdict::Allow, 0)
            } else {
                let note = st.take_note(note_hash(p.data, link));
                let r = match st.chain(p, link, None, note) {
                    Outcome::Allow => (Verdict::Allow, 0),
                    Outcome::Drop => (Verdict::Drop, 0),
                    Outcome::Divert(id, addr, data) => {
                        let token = st.next_token;
                        st.next_token += 1;
                        st.hold(token, p, id, *addr, data);
                        (Verdict::Delay, token)
                    }
                };
                // Sniffing handles may have got copies too.
                self.wake.notify_all();
                r
            }
        };
        self.fire(releases);
        r
    }

    /// Serves a request from client connection `conn`, whose effective user is `euid` and
    /// process `pid`, and returns the response's bytes.
    pub fn request(&self, conn: u64, euid: u32, pid: u32, bytes: &[u8]) -> Vec<u8> {
        let Ok(req) = Request::decode(bytes) else {
            return response(Status::Invalid);
        };
        if euid != 0 {
            return response(Status::Denied);
        }
        let mut releases = Vec::new();
        let r = self.serve(conn, pid, &req, &mut releases);
        self.fire(releases);
        r
    }

    fn serve(
        &self,
        conn: u64,
        pid: u32,
        req: &Request<'_>,
        releases: &mut Vec<(u64, bool)>,
    ) -> Vec<u8> {
        if req.op == Op::Recv {
            return self.recv(conn, req, releases);
        }
        let mut st = lock(&self.state);
        st.sweep(releases);
        match req.op {
            Op::Open => {
                let r = st.open(conn, pid, req.payload);
                self.wake.notify_all();
                r
            }
            Op::Capabilities => {
                let mut layers = [0u8; 6];
                let all = support::OPEN
                    | support::DIVERT
                    | support::DROP
                    | support::INJECT
                    | support::MODIFY;
                layers[Layer::Network as usize] = all;
                if st.frames == Some(true) {
                    layers[Layer::Ethernet as usize] = all;
                }
                if st.flows_on {
                    layers[Layer::Flow as usize] = support::OPEN;
                    // Connects and accepts can be refused.
                    layers[Layer::Socket as usize] =
                        support::OPEN | support::DIVERT | support::DROP;
                }
                layers[Layer::Reflect as usize] = support::OPEN;
                encode_response(Status::Ok, &macos::encode_capabilities(layers))
            }
            Op::TestPacket => {
                if !self.test_mode {
                    return response(Status::Unsupported);
                }
                let Ok(t) = decode_test_packet(req.payload) else {
                    return response(Status::Invalid);
                };
                drop(st);
                let ifname = format!("if{}", t.ifindex);
                let (v, token) = self.packet(&Seen {
                    ifindex: t.ifindex,
                    ifname: &ifname,
                    outbound: t.outbound,
                    loopback: t.loopback,
                    data: t.data,
                });
                let mut b = (v as u32).to_le_bytes().to_vec();
                b.extend_from_slice(&token.to_le_bytes());
                encode_response(Status::Ok, &b)
            }
            Op::TestFlow => {
                if !self.test_mode {
                    return response(Status::Unsupported);
                }
                let Ok(t) = TestFlow::decode(req.payload) else {
                    return response(Status::Invalid);
                };
                drop(st);
                let (v, id, watch) = if t.end {
                    self.flow_end(t.id);
                    (Verdict::Allow, t.id, false)
                } else {
                    self.flow_start(&FlowStart {
                        outbound: t.outbound,
                        protocol: t.protocol,
                        pid: t.pid,
                        process_name: None,
                        local: Ipv6Addr::from(t.local_addr).to_canonical(),
                        local_port: t.local_port,
                        remote: Ipv6Addr::from(t.remote_addr).to_canonical(),
                        remote_port: t.remote_port,
                    })
                };
                let mut b = (v as u32).to_le_bytes().to_vec();
                b.extend_from_slice(&[0; 4]);
                b.extend_from_slice(&id.to_le_bytes());
                b.push(u8::from(watch));
                b.extend_from_slice(&[0; 7]);
                encode_response(Status::Ok, &b)
            }
            _ => {
                if !st.handles.get(&req.handle).is_some_and(|h| h.conn == conn) {
                    return response(Status::NoHandle);
                }
                match req.op {
                    Op::Close => {
                        st.close(req.handle, releases);
                        self.wake.notify_all();
                        return response(Status::Ok);
                    }
                    Op::Send => {
                        // A packet sent back may go to the next handles' queues.
                        let r = st.send(req.handle, req.payload, releases);
                        self.wake.notify_all();
                        return r;
                    }
                    _ => {}
                }
                let Some(h) = st.handles.get_mut(&req.handle) else {
                    return response(Status::NoHandle);
                };
                match req.op {
                    Op::Shutdown => {
                        let how = match req.payload {
                            [1, 0, 0, 0] => Shutdown::Recv,
                            [2, 0, 0, 0] => Shutdown::Send,
                            [3, 0, 0, 0] => Shutdown::Both,
                            _ => return response(Status::Invalid),
                        };
                        if matches!(how, Shutdown::Recv | Shutdown::Both) {
                            h.shut_recv = true;
                        }
                        if matches!(how, Shutdown::Send | Shutdown::Both) {
                            h.shut_send = true;
                        }
                        self.wake.notify_all();
                        response(Status::Ok)
                    }
                    Op::SetParam => match ioctl::decode_param(req.payload) {
                        Ok((p, Some(v))) if p.range().contains(&v) => {
                            h.params[p.index()] = v;
                            response(Status::Ok)
                        }
                        _ => response(Status::Invalid),
                    },
                    Op::Stats => encode_response(Status::Ok, &ioctl::encode_stats(&h.stats)),
                    _ => response(Status::Invalid),
                }
            }
        }
    }

    /// `Recv`: waits for the handle's queue, a shutdown, or the timeout.
    fn recv(&self, conn: u64, req: &Request<'_>, releases: &mut Vec<(u64, bool)>) -> Vec<u8> {
        let Ok((timeout_ms, max)) = decode_recv(req.payload) else {
            return response(Status::Invalid);
        };
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
        let mut st = lock(&self.state);
        loop {
            st.sweep(releases);
            let Some(h) = st.handles.get_mut(&req.handle).filter(|h| h.conn == conn) else {
                return response(Status::NoHandle);
            };
            let max_wait = Duration::from_millis(h.params[Param::QueueTime.index()]);
            let mut out = Vec::new();
            let mut taken = Vec::new();
            let now = Instant::now();
            while let Some(q) = h.queue.pop_front() {
                if now.duration_since(q.at) > max_wait {
                    h.bytes -= q.data.len() as u64;
                    h.stats.queue_drops += 1;
                    taken.push((q.addr, false));
                    continue;
                }
                let len = Record::encoded_len(q.data.len());
                if !out.is_empty() && out.len() + len > max as usize {
                    h.queue.push_front(q);
                    break;
                }
                h.bytes -= q.data.len() as u64;
                Record {
                    addr: q.addr,
                    data: &q.data,
                }
                .encode_into(&mut out);
                taken.push((q.addr, true));
            }
            let shut = h.shut_recv;
            for (addr, delivered) in taken {
                let Some(token) = MacContext::decode(&addr.context).map(|c| c.token) else {
                    continue;
                };
                if token == 0 {
                    continue;
                }
                if delivered {
                    if let Some(held) = st.held.get_mut(&token) {
                        held.received = Some(now);
                    }
                } else if st.held.remove(&token).is_some() {
                    // Waited past QUEUE_TIME: dropped, as WinDivert drops it.
                    releases.push((token, false));
                }
            }
            if !out.is_empty() {
                return encode_response(Status::Ok, &out);
            }
            if shut {
                return response(Status::Shutdown);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return response(Status::Timeout);
            }
            st = self
                .wake
                .wait_timeout(st, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// Tells the extension whether the data provider runs, which the FLOW and SOCKET layers
    /// need.
    pub fn set_flows(&self, on: bool) {
        lock(&self.state).flows_on = on;
    }

    /// A new flow, as the data provider sees it: the SOCKET handles get its connect (outbound)
    /// or accept (inbound), and may refuse it ([`Verdict::Drop`]); the FLOW handles get its
    /// establishment. Returns the verdict, the flow's id, and whether its end is wanted
    /// ([`flow_end`](Self::flow_end)).
    pub fn flow_start(&self, f: &FlowStart) -> (Verdict, u64, bool) {
        let mut st = lock(&self.state);
        let wanted = st
            .handles
            .values()
            .any(|h| matches!(h.layer, Layer::Flow | Layer::Socket));
        if !wanted {
            return (Verdict::Allow, 0, false);
        }
        let id = st.next_flow;
        st.next_flow += 1;
        let mut flow = Address::new(Layer::Flow).flow;
        flow.endpoint_id = id;
        flow.process_id = f.pid;
        flow.protocol = f.protocol;
        flow.set_local_addr(f.local);
        flow.local_port = f.local_port;
        flow.set_remote_addr(f.remote);
        flow.remote_port = f.remote_port;
        if let Some(name) = &f.process_name {
            flow.set_process_name(name);
        }
        let event = if f.outbound {
            Event::SocketConnect
        } else {
            Event::SocketAccept
        };
        let refused = st.flow_event(&flow, Layer::Socket, event, f.outbound, true);
        if !refused {
            st.flow_event(
                &flow,
                Layer::Flow,
                Event::FlowEstablished,
                f.outbound,
                false,
            );
        }
        let watch = !refused && st.flows.len() < FLOWS_MAX;
        if watch {
            st.flows.insert(id, flow);
        }
        self.wake.notify_all();
        let v = if refused {
            Verdict::Drop
        } else {
            Verdict::Allow
        };
        (v, id, watch)
    }

    /// The end of flow `id`: the SOCKET handles get its close, the FLOW handles its deletion.
    pub fn flow_end(&self, id: u64) {
        let mut st = lock(&self.state);
        let Some(flow) = st.flows.remove(&id) else {
            return;
        };
        st.flow_event(&flow, Layer::Socket, Event::SocketClose, false, false);
        st.flow_event(&flow, Layer::Flow, Event::FlowDeleted, false, false);
        self.wake.notify_all();
    }

    /// Closes every handle client connection `conn` opened: it went away.
    pub fn disconnect(&self, conn: u64) {
        let mut releases = Vec::new();
        {
            let mut st = lock(&self.state);
            let ids: Vec<u64> = st
                .handles
                .iter()
                .filter(|(_, h)| h.conn == conn)
                .map(|(&id, _)| id)
                .collect();
            for id in ids {
                st.close(id, &mut releases);
            }
            self.wake.notify_all();
        }
        self.fire(releases);
    }
}

impl State {
    /// Drops what clients received and never sent back within [`HOLD_MAX`], and forgets stale
    /// notes; at most once a second.
    fn sweep(&mut self, releases: &mut Vec<(u64, bool)>) {
        let now = Instant::now();
        if self
            .last_sweep
            .is_some_and(|t| now.duration_since(t) < Duration::from_secs(1))
        {
            return;
        }
        self.last_sweep = Some(now);
        self.held.retain(|&token, h| {
            let stale = h.received.is_some_and(|t| now.duration_since(t) > HOLD_MAX);
            if stale {
                releases.push((token, false));
            }
            !stale
        });
        self.notes.retain(|n| now.duration_since(n.at) < NOTE_TTL);
    }

    /// The priority of the note for a packet with this hash, which the note was for.
    fn take_note(&mut self, h: u64) -> Option<i16> {
        let i = self.notes.iter().position(|n| n.hash == h)?;
        Some(self.notes.remove(i).priority)
    }

    fn note(&mut self, hash: u64, priority: i16) {
        if self.notes.len() >= NOTES_MAX {
            self.notes.remove(0);
        }
        self.notes.push(Note {
            hash,
            priority,
            at: Instant::now(),
        });
    }

    /// Runs `p` through the handles after `after` (all of them for `None`). A packet a client
    /// injected at priority `note` is skipped by the handles at that priority and above, and is
    /// an impostor to the others. Sniffing handles get their copies here.
    fn chain(
        &mut self,
        p: &Seen<'_>,
        link: Link,
        after: Option<Key>,
        note: Option<i16>,
    ) -> Outcome {
        struct Parsed<'a> {
            data: &'a [u8],
            packet: Packet<'a>,
            valid: checksum::Updated,
            vlan: Option<u16>,
            hash: u64,
        }

        let (l2, ip) = split(p.data, link);
        let ipv6 = ip.and_then(|ip| ip.first()).is_some_and(|v| v >> 4 == 6);
        let now = now_ns();
        let mut parsed: [Option<Parsed<'_>>; 2] = [None, None];
        let held_full = self.held.len() >= HELD_MAX;
        for i in 0..self.order.len() {
            let key = self.order[i];
            if after.is_some_and(|a| key <= a) {
                continue;
            }
            if note.is_some_and(|n| key.priority.0 >= n) {
                continue;
            }
            let Some(h) = self.handles.get_mut(&key.id) else {
                continue;
            };
            if h.shut_recv || (!h.interfaces.is_empty() && !h.interfaces.contains(&p.ifindex)) {
                continue;
            }
            let eth_layer = h.layer == Layer::Ethernet;
            let slot = usize::from(eth_layer);
            let info = match &parsed[slot] {
                Some(info) => info,
                None => {
                    let Some(data) = view(p.data, link, h.layer) else {
                        continue;
                    };
                    let packet_link = if eth_layer { Link::Ethernet } else { Link::Ip };
                    let header = if eth_layer { data } else { l2 };
                    let vlan = match header.get(12..16) {
                        Some(t) if matches!(t[..2], [0x81, 0x00] | [0x88, 0xa8] | [0x91, 0x00]) => {
                            Some(u16::from_be_bytes([t[2], t[3]]))
                        }
                        _ => None,
                    };
                    parsed[slot].insert(Parsed {
                        data,
                        packet: Packet::parse(data, packet_link),
                        valid: checksum::verify(data, packet_link),
                        vlan,
                        hash: hash(data),
                    })
                }
            };
            let sniff = h.flags.contains(Flags::SNIFF);
            let drop = h.flags.contains(Flags::DROP);
            let mut addr = Address::new(h.layer);
            addr.timestamp = now;
            addr.event = Event::Packet;
            addr.outbound = p.outbound;
            addr.loopback = p.loopback;
            addr.impostor = note.is_some();
            addr.sniffed = sniff;
            addr.ipv6 = ipv6;
            addr.ip_checksum = info.valid.ipv4;
            addr.tcp_checksum = info.valid.tcp;
            addr.udp_checksum = info.valid.udp;
            addr.if_idx = p.ifindex;
            addr.vlan = info.vlan.is_some();
            addr.vlan_tci = info.vlan.unwrap_or(0);
            let l2_kept = if eth_layer { &[][..] } else { l2 };
            if let Some(c) = MacContext::new(p.ifindex, l2_kept, 0) {
                addr.context = c.encode();
            }
            let mut meta = addr.meta();
            meta.iface = Some(p.ifname);
            meta.priority = key.priority.0;
            meta.hash = info.hash;
            if !h.filter.matches(&info.packet, &meta) {
                continue;
            }
            if drop {
                h.stats.dropped += 1;
                return Outcome::Drop;
            }
            if !h.fits(info.data.len()) || (!sniff && held_full) {
                // A full queue lets the packet go on, as a full ring buffer does on Linux.
                h.stats.ring_full += 1;
                continue;
            }
            if sniff {
                h.stats.sniffed += 1;
                h.push(addr, info.data.to_vec());
                continue;
            }
            h.stats.diverted += 1;
            return Outcome::Divert(key.id, Box::new(addr), info.data.to_vec());
        }
        Outcome::Allow
    }

    /// Holds `p` under `token` for the handle `id`, and queues its copy there.
    fn hold(&mut self, token: u64, p: &Seen<'_>, id: u64, mut addr: Address, data: Vec<u8>) {
        let Some(h) = self.handles.get_mut(&id) else {
            return;
        };
        if let Some(mut c) = MacContext::decode(&addr.context) {
            c.token = token;
            addr.context = c.encode();
        }
        let holder = h.key;
        h.push(addr, data);
        self.held.insert(
            token,
            Held {
                data: p.data.to_vec(),
                ifindex: p.ifindex,
                ifname: p.ifname.to_string(),
                outbound: p.outbound,
                loopback: p.loopback,
                holder,
                received: None,
            },
        );
    }

    /// Lets the packet held under `token` go on past its holder: to the next handles, which may
    /// divert it again (it stays held), or out. Returns what to release.
    fn resume(&mut self, token: u64, releases: &mut Vec<(u64, bool)>) {
        let Some(held) = self.held.remove(&token) else {
            return;
        };
        let p = Seen {
            ifindex: held.ifindex,
            ifname: &held.ifname,
            outbound: held.outbound,
            loopback: held.loopback,
            data: &held.data,
        };
        let link = link_of(p.data);
        match self.chain(&p, link, Some(held.holder), None) {
            Outcome::Allow => releases.push((token, true)),
            Outcome::Drop => releases.push((token, false)),
            Outcome::Divert(id, addr, data) => self.hold(token, &p, id, *addr, data),
        }
    }

    fn open(&mut self, conn: u64, pid: u32, payload: &[u8]) -> Vec<u8> {
        let Ok(req) = OpenRequest::decode(payload) else {
            return response(Status::Invalid);
        };
        match req.layer {
            Layer::Network => {}
            Layer::Ethernet if self.frames != Some(false) => {}
            Layer::Flow | Layer::Socket if self.flows_on => {}
            Layer::Reflect => {}
            _ => return response(Status::Unsupported),
        }
        if !(-30_000..=30_000).contains(&req.priority)
            || req.flags.contains(Flags::SNIFF | Flags::DROP)
        {
            return response(Status::Invalid);
        }
        let filter = match req.syntax {
            Syntax::WinDivert => Filter::compile_windivert(req.filter, req.layer),
            _ => Filter::compile(req.filter),
        };
        let Ok(filter) = filter else {
            return response(Status::Invalid);
        };
        let id = self.next_id;
        self.next_id += 1;
        let key = Key {
            priority: Reverse(req.priority),
            id,
        };
        let mut params = [0; 3];
        for p in Param::ALL {
            params[p.index()] = p.default_value();
        }
        let send_only = req.flags.contains(Flags::SEND_ONLY);
        self.handles.insert(
            id,
            Handle {
                key,
                conn,
                pid,
                opened: now_ns(),
                source: req.filter.to_string(),
                syntax: req.syntax,
                layer: req.layer,
                flags: req.flags,
                filter,
                interfaces: req.interfaces,
                queue: VecDeque::new(),
                bytes: 0,
                params,
                shut_recv: send_only,
                shut_send: req.flags.contains(Flags::RECV_ONLY),
                stats: Stats::default(),
            },
        );
        let at = self.order.partition_point(|k| *k < key);
        self.order.insert(at, key);
        // REFLECT: the other REFLECT handles hear of this one; a new REFLECT handle hears of
        // every handle, itself included.
        let now = now_ns();
        let new = [self.handles[&id].reflect(Event::ReflectOpen, now)];
        self.tell_reflect(&new, Some(id));
        if req.layer == Layer::Reflect {
            let all: Vec<(Address, Vec<u8>)> = self
                .handles
                .values()
                .map(|h| h.reflect(Event::ReflectOpen, now))
                .collect();
            if let Some(r) = self.handles.get_mut(&id) {
                for (addr, data) in all {
                    r.report(addr, data);
                }
            }
        }
        encode_response(Status::Ok, &id.to_le_bytes())
    }

    /// Closes handle `id`. The packets it holds, queued or received, go on past it.
    fn close(&mut self, id: u64, releases: &mut Vec<(u64, bool)>) {
        let Some(h) = self.handles.remove(&id) else {
            return;
        };
        self.order.retain(|k| *k != h.key);
        self.tell_reflect(&[h.reflect(Event::ReflectClose, now_ns())], None);
        let tokens: Vec<u64> = self
            .held
            .iter()
            .filter(|(_, held)| held.holder == h.key)
            .map(|(&t, _)| t)
            .collect();
        for t in tokens {
            self.resume(t, releases);
        }
    }

    /// Reports `events` to the REFLECT handles (but `except`) whose filters match them.
    fn tell_reflect(&mut self, events: &[(Address, Vec<u8>)], except: Option<u64>) {
        for (id, h) in self.handles.iter_mut() {
            if h.layer != Layer::Reflect || Some(*id) == except {
                continue;
            }
            for (addr, data) in events {
                h.report(*addr, data.clone());
            }
        }
    }

    /// Reports a flow's event to the handles at `layer`, in priority order. When `refusable`,
    /// the first handle without SNIFF whose filter matches refuses it: it gets the event, the
    /// handles after it do not, and this returns true.
    fn flow_event(
        &mut self,
        flow: &Flow,
        layer: Layer,
        event: Event,
        outbound: bool,
        refusable: bool,
    ) -> bool {
        let now = now_ns();
        let ipv6 = !flow.local_addr().is_ipv4() || !flow.remote_addr().is_ipv4();
        let loopback = flow.local_addr().is_loopback() || flow.remote_addr().is_loopback();
        let flow_hash = hash(&flow.endpoint_id.to_ne_bytes());
        for i in 0..self.order.len() {
            let key = self.order[i];
            let Some(h) = self.handles.get_mut(&key.id) else {
                continue;
            };
            if h.layer != layer || h.shut_recv {
                continue;
            }
            let sniff = h.flags.contains(Flags::SNIFF) || !refusable;
            let mut addr = Address::new(layer);
            addr.timestamp = now;
            addr.event = event;
            addr.outbound = outbound;
            addr.loopback = loopback;
            addr.sniffed = sniff;
            addr.ipv6 = ipv6;
            addr.flow = *flow;
            let mut meta = addr.meta();
            meta.priority = key.priority.0;
            meta.hash = flow_hash;
            if !h.filter.matches(&Packet::parse(&[], Link::Ip), &meta) {
                continue;
            }
            if !h.fits(0) {
                h.stats.ring_full += 1;
                continue;
            }
            h.push(addr, Vec::new());
            if sniff {
                h.stats.sniffed += 1;
                continue;
            }
            h.stats.dropped += 1;
            return true;
        }
        false
    }

    /// `Send`: each record is either the original its handle holds, unchanged, which goes on,
    /// or a packet the client injects, which is noted.
    fn send(&mut self, id: u64, payload: &[u8], releases: &mut Vec<(u64, bool)>) -> Vec<u8> {
        let mut records = Vec::new();
        for r in Record::decode_all(payload) {
            match r {
                Ok(r) => records.push((r.addr, r.data.to_vec())),
                Err(_) => return response(Status::Invalid),
            }
        }
        let Some(h) = self.handles.get(&id) else {
            return response(Status::NoHandle);
        };
        if h.shut_send {
            return response(Status::Shutdown);
        }
        let (key, layer) = (h.key, h.layer);
        let mut out = Vec::with_capacity(records.len());
        for (addr, data) in records {
            let token = MacContext::decode(&addr.context)
                .map(|c| c.token)
                .filter(|&t| t != 0 && self.held.get(&t).is_some_and(|h| h.holder == key));
            if let Some(token) = token {
                let held = &self.held[&token];
                let link = link_of(&held.data);
                let same = view(&held.data, link, layer) == Some(&data[..])
                    && held.outbound == addr.outbound;
                if same {
                    self.resume(token, releases);
                    out.push(SendResult::Sent as u8);
                    continue;
                }
                // Modified: the original goes, the client injects the new one.
                self.held.remove(&token);
                releases.push((token, false));
            }
            let link = if layer == Layer::Ethernet {
                Link::Ethernet
            } else {
                Link::Ip
            };
            self.note(note_hash(&data, link), key.priority.0);
            out.push(SendResult::Inject as u8);
        }
        encode_response(Status::Ok, &out)
    }
}

impl Handle {
    /// The REFLECT event about this handle, and its data: the filter as written.
    fn reflect(&self, event: Event, now: i64) -> (Address, Vec<u8>) {
        let mut addr = Address::new(Layer::Reflect);
        addr.timestamp = now;
        addr.event = event;
        addr.sniffed = true;
        let r = &mut addr.reflect;
        r.timestamp = self.opened;
        r.flags = self.flags;
        r.process_id = self.pid;
        r.priority = self.key.priority.0;
        r.layer = self.layer;
        r.syntax = self.syntax;
        (addr, self.source.as_bytes().to_vec())
    }

    /// Queues an event of a REFLECT handle, if its filter matches and it has room.
    fn report(&mut self, addr: Address, data: Vec<u8>) {
        if self.shut_recv {
            return;
        }
        let meta = addr.meta();
        if !self.filter.matches(&Packet::parse(&[], Link::Ip), &meta) {
            return;
        }
        if !self.fits(data.len()) {
            self.stats.ring_full += 1;
            return;
        }
        self.stats.sniffed += 1;
        self.push(addr, data);
    }

    /// Whether a packet of `len` bytes fits the queue (`QUEUE_LENGTH`, `QUEUE_SIZE`).
    fn fits(&self, len: usize) -> bool {
        (self.queue.len() as u64) < self.params[Param::QueueLength.index()]
            && self.bytes + len as u64 <= self.params[Param::QueueSize.index()]
    }

    fn push(&mut self, addr: Address, data: Vec<u8>) {
        self.bytes += data.len() as u64;
        self.queue.push_back(Queued {
            addr,
            data,
            at: Instant::now(),
        });
    }
}
