//! What the Linux backend does without privileges: records to addresses, the queue's limits, the
//! registry's entries, and the TC priorities. `tests/capture.rs` runs the rest, as root, in a VM.

use avulse_ebpf::abi::{RECORD_HEADER, Record};
use avulse_ebpf::facts::{
    F_ETH, F_ICMP, F_IPV4, F_IPV6, M_IMPOSTOR, M_OUTBOUND, M_SNIFFED, M_VLAN,
};
use avulse_ebpf::loader::{Attachment, Hook};
use avulse_filter::Layer;
use avulse_proto::{Link, checksum};

use super::queue::Queue;
use super::record::{self, Ctx, Entry};
use super::registry;
use super::{after, sys, targets};
use crate::{Address, Context, Error, Param};

const MAC: [u8; 12] = [2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2];

/// An ICMP echo request from 10.0.0.1 to 10.0.0.2, checksums right.
fn ping() -> Vec<u8> {
    let mut p = vec![
        0x45, 0, 0, 32, 0, 1, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, //
        8, 0, 0, 0, 0x12, 0x34, 0, 1, b'a', b'b', b'c', b'd',
    ];
    checksum::recalculate(&mut p, Link::Ip);
    p
}

fn frame(tags: &[[u8; 4]], ethertype: [u8; 2], payload: &[u8]) -> Vec<u8> {
    let mut f = MAC.to_vec();
    for t in tags {
        f.extend(t);
    }
    f.extend(ethertype);
    f.extend(payload);
    f
}

/// A ring buffer record of `data`, as `avulse_act` writes it.
fn record(data: &[u8], l3: u16, meta: u8, flags: u16, vlan_tci: u16) -> Vec<u8> {
    let mut b = vec![0u8; RECORD_HEADER];
    b[0..8].copy_from_slice(&123_456u64.to_ne_bytes());
    b[8..12].copy_from_slice(&(data.len() as u32).to_ne_bytes());
    b[12..16].copy_from_slice(&(data.len() as u32).to_ne_bytes());
    b[16..20].copy_from_slice(&7u32.to_ne_bytes());
    b[24..26].copy_from_slice(&1448u16.to_ne_bytes());
    b[26..28].copy_from_slice(&3u16.to_ne_bytes());
    b[28..30].copy_from_slice(&vlan_tci.to_ne_bytes());
    b[30..32].copy_from_slice(&l3.to_ne_bytes());
    b[32] = meta;
    b[34..36].copy_from_slice(&flags.to_ne_bytes());
    b.extend(data);
    b
}

fn entry(rec: &[u8], layer: Layer) -> Option<Entry> {
    record::entry(&Record::parse(rec).unwrap(), layer)
}

#[test]
fn network_records() {
    let eth = frame(&[], [8, 0], &ping());
    let flags = (F_ETH | F_IPV4 | F_ICMP) as u16;
    let e = entry(&record(&eth, 14, M_OUTBOUND, flags, 0), Layer::Network).unwrap();
    assert_eq!(e.data, ping());
    let a = e.addr;
    assert_eq!(
        (a.layer, a.timestamp, a.if_idx),
        (Layer::Network, 123_456, 7)
    );
    assert!(a.outbound && !a.loopback && !a.impostor && !a.sniffed && !a.ipv6);
    assert!(a.ip_checksum && !a.tcp_checksum && !a.udp_checksum);
    assert!(!a.vlan);
    let ctx = Ctx::decode(&a.context).unwrap();
    assert_eq!(ctx.l2(), &eth[..14]);
    assert_eq!((ctx.ifindex, ctx.gso_size, ctx.gso_segs), (7, 1448, 3));
    assert_eq!(ctx.encode(), a.context);

    // A wrong checksum, inbound, sniffed, from an impostor.
    let mut bad = eth.clone();
    *bad.last_mut().unwrap() ^= 1;
    let e = entry(
        &record(&bad, 14, M_SNIFFED | M_IMPOSTOR, flags, 0),
        Layer::NetworkForward,
    )
    .unwrap();
    assert!(e.addr.ip_checksum && !e.addr.outbound && e.addr.sniffed && e.addr.impostor);
    assert_eq!(e.addr.layer, Layer::NetworkForward);
    assert_eq!(record::hash(&e.data), record::hash(&bad[14..]));
    assert_ne!(record::hash(&e.data), record::hash(&ping()));

    let e = entry(
        &record(&eth, 14, 0, (F_ETH | F_IPV6) as u16, 0),
        Layer::Network,
    )
    .unwrap();
    assert!(e.addr.ipv6);
}

#[test]
fn vlan_tags() {
    // In the data: the NETWORK layers keep it in the context.
    let tagged = frame(&[[0x81, 0, 0x20, 5]], [8, 0], &ping());
    let e = entry(&record(&tagged, 18, 0, 0, 0), Layer::Network).unwrap();
    assert_eq!(e.data, ping());
    assert!(e.addr.vlan);
    assert_eq!(e.addr.vlan_tci, 0x2005);
    assert_eq!(Ctx::decode(&e.addr.context).unwrap().l2(), &tagged[..18]);

    // Offloaded: it goes back where it was on the wire.
    let untagged = frame(&[], [8, 0], &ping());
    let e = entry(&record(&untagged, 14, M_VLAN, 0, 0x2005), Layer::Ethernet).unwrap();
    assert_eq!(e.data, tagged);
    assert!(e.addr.vlan && e.addr.vlan_tci == 0x2005);
    assert!(Ctx::decode(&e.addr.context).unwrap().l2().is_empty());
    let e = entry(&record(&untagged, 14, M_VLAN, 0, 0x2005), Layer::Network).unwrap();
    assert_eq!(e.data, ping());
    assert_eq!(Ctx::decode(&e.addr.context).unwrap().l2(), &tagged[..18]);

    // QinQ, with the outer tag offloaded: three tags.
    let inner = frame(&[[0x81, 0, 0, 1], [0x81, 0, 0, 2]], [8, 0], &ping());
    let e = entry(&record(&inner, 22, M_VLAN, 0, 9), Layer::Network).unwrap();
    assert_eq!(e.data, ping());
    assert_eq!(e.addr.vlan_tci, 9);
    assert_eq!(Ctx::decode(&e.addr.context).unwrap().l2().len(), 26);
}

#[test]
fn bad_records() {
    let eth = frame(&[], [8, 0], &ping());
    assert_eq!(entry(&record(&eth, 200, 0, 0, 0), Layer::Network), None);
    assert_eq!(entry(&record(&eth, 40, 0, 0, 0), Layer::Network), None);
    // The ETHERNET layer keeps the frame whole, whatever the offset.
    assert!(entry(&record(&eth, 200, 0, 0, 0), Layer::Ethernet).is_some());
}

#[test]
fn contexts() {
    assert_eq!(Ctx::decode(&Context::EMPTY), None);
    let mut b = [0u8; 64];
    b[0] = 0x5a;
    assert_eq!(Ctx::decode(&Context::from_bytes(b)), None);
    b[0] = 0xa1;
    b[1] = 31;
    assert_eq!(Ctx::decode(&Context::from_bytes(b)), None);
}

fn queued(timestamp: i64, len: usize) -> Entry {
    let mut addr = Address::new(Layer::Network);
    addr.timestamp = timestamp;
    Entry {
        addr,
        data: vec![0; len],
    }
}

fn params(length: u64, time_ms: u64, size: u64) -> [u64; 3] {
    let mut p = [0; 3];
    p[Param::QueueLength.index()] = length;
    p[Param::QueueTime.index()] = time_ms;
    p[Param::QueueSize.index()] = size;
    p
}

#[test]
fn queue_limits() {
    let ms = 1_000_000;
    // Length.
    let mut q = Queue::new(params(2, 100, 1000));
    for t in 0..3 {
        q.push(queued(t, 10));
    }
    assert_eq!(q.drops, 1);
    assert_eq!(q.pop(0).unwrap().addr.timestamp, 0);
    assert_eq!(q.pop(0).unwrap().addr.timestamp, 1);
    assert!(q.pop(0).is_none() && q.is_empty());

    // Size: the bytes of the packets.
    let mut q = Queue::new(params(10, 100, 25));
    for t in 0..3 {
        q.push(queued(t, 10));
    }
    assert_eq!(q.drops, 1);
    q.pop(0);
    q.push(queued(3, 15));
    assert_eq!(q.drops, 1);
    q.push(queued(4, 1));
    assert_eq!(q.drops, 2);

    // Time: packets older than QUEUE_TIME at the pop are dropped.
    let mut q = Queue::new(params(10, 100, 1000));
    q.push(queued(0, 1));
    q.push(queued(50 * ms, 1));
    q.push(queued(120 * ms, 1));
    let e = q.pop(140 * ms).unwrap();
    assert_eq!((e.addr.timestamp, q.drops), (50 * ms, 1));
    q.set(Param::QueueTime, 10);
    assert!(q.pop(140 * ms).is_none());
    assert_eq!(q.drops, 2);

    // A new limit applies to the next packets.
    let mut q = Queue::new(params(1, 100, 1000));
    q.push(queued(0, 1));
    q.set(Param::QueueLength, 2);
    q.push(queued(0, 1));
    assert_eq!(q.drops, 0);
}

#[test]
fn registry_entries() {
    let e = registry::Entry {
        pid: 42,
        start_time: 1234,
        tc_priority: 30_001,
        timestamp: -5,
        flags: 0x21,
        layer: 5,
        priority: -300,
        attachments: vec![
            Attachment {
                ifindex: 1,
                hook: Hook::Ingress,
                priority: 30_001,
                handle: 0x8000_0001,
            },
            Attachment {
                ifindex: 3,
                hook: Hook::Egress,
                priority: 30_001,
                handle: 7,
            },
        ],
        filter: "icmp".into(),
    };
    let b = e.encode();
    assert_eq!(registry::Entry::decode(&b), Some(e.clone()));
    assert_eq!(registry::Entry::decode(&b[1..]), None);

    // Too many filters, and a long filter cut at a character boundary.
    let mut big = e;
    big.attachments = vec![big.attachments[0]; registry::MAX_ATTACH + 5];
    big.filter = "é".repeat(1500);
    let back = registry::Entry::decode(&big.encode()).unwrap();
    assert_eq!(back.attachments.len(), registry::MAX_ATTACH);
    assert_eq!(back.filter, "é".repeat(1024));
}

#[test]
fn processes() {
    let start = sys::start_time(sys::pid()).unwrap();
    assert!(sys::alive(sys::pid(), start));
    assert!(!sys::alive(sys::pid(), start + 1));
    assert_eq!(sys::start_time(u32::MAX), None);
}

#[test]
fn tc_priorities() {
    assert_eq!(after(0), 30_001);
    assert_eq!(after(100), 30_001);
    assert_eq!(after(30_001), 30_002);
    assert_eq!(after(60_001), 60_002);
    assert_eq!(after(u16::MAX), u16::MAX);
}

#[test]
fn interfaces() {
    let all = sys::interfaces().unwrap();
    let lo = all.iter().find(|i| i.kind == sys::ARPHRD_LOOPBACK);
    let Some(lo) = lo else {
        // A network namespace with nothing in it.
        return;
    };
    let t = targets(std::slice::from_ref(&lo.name)).unwrap();
    assert!(t.lo_selected);
    assert!(t.list.iter().all(|i| i.kind == sys::ARPHRD_LOOPBACK));
    let t = targets(&[]).unwrap();
    assert!(t.lo_selected);
    assert!(
        t.list
            .iter()
            .all(|i| matches!(i.kind, sys::ARPHRD_ETHER | sys::ARPHRD_LOOPBACK))
    );
    match targets(&["no-such-if0".into()]) {
        Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
        r => panic!("{:?}", r.map(|t| t.list)),
    }
}
