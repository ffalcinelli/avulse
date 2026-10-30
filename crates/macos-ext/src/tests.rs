//! The extension against a fake provider, which records what becomes of the packets it holds,
//! and fake clients, which speak `avulse_abi::macos`'s protocol as the backend does.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use avulse_abi::ioctl::{self, OpenRequest, Record};
use avulse_abi::macos::{
    self, MacContext, Op, Request, SendResult, Status, TestPacket, decode_response, encode_recv,
    support,
};
use avulse_abi::{Address, Flags, Param, Stats, Syntax};
use avulse_filter::Layer;
use avulse_proto::{Link, checksum};

use crate::{Extension, Seen, Verdict, link_of};

const ROOT: u32 = 0;
const MAC_A: [u8; 6] = [2, 0, 0, 0, 0, 1];
const MAC_B: [u8; 6] = [2, 0, 0, 0, 0, 2];

/// What the fake provider was told: `(token, allowed)`.
type Released = Arc<Mutex<Vec<(u64, bool)>>>;

/// The extension, and what it released.
fn extension(test_mode: bool) -> (Extension, Released) {
    let released = Arc::new(Mutex::new(Vec::new()));
    let r = released.clone();
    let ext = Extension::new(
        Box::new(move |token, allow| r.lock().unwrap().push((token, allow))),
        test_mode,
    );
    (ext, released)
}

fn call(ext: &Extension, conn: u64, op: Op, handle: u64, payload: &[u8]) -> (Status, Vec<u8>) {
    let b = ext.request(
        conn,
        ROOT,
        100 + conn as u32,
        &Request {
            op,
            handle,
            payload,
        }
        .encode(),
    );
    let (s, p) = decode_response(&b).unwrap();
    (s, p.to_vec())
}

fn try_open(
    ext: &Extension,
    conn: u64,
    filter: &str,
    layer: Layer,
    priority: i16,
    flags: Flags,
) -> Result<u64, Status> {
    let req = OpenRequest {
        layer,
        priority,
        flags,
        program: &[],
        interfaces: Vec::new(),
        filter,
        syntax: Syntax::Native,
        windivert_object: &[],
    };
    match call(ext, conn, Op::Open, 0, &req.encode()) {
        (Status::Ok, p) => Ok(u64::from_le_bytes(p.try_into().unwrap())),
        (s, _) => Err(s),
    }
}

fn open(ext: &Extension, conn: u64, filter: &str, priority: i16, flags: Flags) -> u64 {
    try_open(ext, conn, filter, Layer::Network, priority, flags).unwrap()
}

fn recv(
    ext: &Extension,
    conn: u64,
    h: u64,
    timeout_ms: u32,
) -> Result<Vec<(Address, Vec<u8>)>, Status> {
    match call(ext, conn, Op::Recv, h, &encode_recv(timeout_ms, 1 << 20)) {
        (Status::Ok, p) => Ok(Record::decode_all(&p)
            .map(|r| {
                let r = r.unwrap();
                (r.addr, r.data.to_vec())
            })
            .collect()),
        (s, _) => Err(s),
    }
}

fn recv_one(ext: &Extension, conn: u64, h: u64) -> (Address, Vec<u8>) {
    let mut v = recv(ext, conn, h, 0).unwrap();
    assert_eq!(v.len(), 1);
    v.remove(0)
}

fn send(ext: &Extension, conn: u64, h: u64, records: &[(Address, &[u8])]) -> Vec<SendResult> {
    let mut b = Vec::new();
    for (addr, data) in records {
        Record { addr: *addr, data }.encode_into(&mut b);
    }
    let (s, p) = call(ext, conn, Op::Send, h, &b);
    assert_eq!(s, Status::Ok);
    p.into_iter()
        .map(|b| SendResult::try_from(b).unwrap())
        .collect()
}

fn stats(ext: &Extension, conn: u64, h: u64) -> Stats {
    let (s, p) = call(ext, conn, Op::Stats, h, &[]);
    assert_eq!(s, Status::Ok);
    ioctl::decode_stats(&p).unwrap()
}

/// A UDP datagram from 10.0.0.1 to 10.0.0.2 with destination `port`, checksums right.
fn udp(port: u16, payload: &[u8]) -> Vec<u8> {
    let len = 28 + payload.len();
    let mut p = vec![
        0x45, 0, 0, 0, 0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, //
        0x9c, 0x40, 0, 0, 0, 0, 0, 0,
    ];
    p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    p[22..24].copy_from_slice(&port.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(payload);
    checksum::recalculate(&mut p, Link::Ip);
    p
}

fn frame(ip: &[u8]) -> Vec<u8> {
    let mut f = MAC_B.to_vec();
    f.extend_from_slice(&MAC_A);
    f.extend_from_slice(&[0x08, 0]);
    f.extend_from_slice(ip);
    f
}

fn seen(data: &[u8]) -> Seen<'_> {
    Seen {
        ifindex: 4,
        ifname: "en0",
        outbound: true,
        loopback: false,
        data,
    }
}

fn token(addr: &Address) -> u64 {
    MacContext::decode(&addr.context).unwrap().token
}

#[test]
fn links() {
    let ip = udp(53, b"x");
    assert_eq!(link_of(&ip), Link::Ip);
    assert_eq!(link_of(&frame(&ip)), Link::Ethernet);
    // A frame whose first byte looks like IPv4 is told apart by the length.
    let mut f = frame(&ip);
    f[0] = 0x45;
    assert_eq!(link_of(&f), Link::Ethernet);
    assert_eq!(link_of(&[]), Link::Ethernet);
}

#[test]
fn requests_are_checked() {
    let (ext, _) = extension(false);
    // Malformed, and not root.
    assert_eq!(
        decode_response(&ext.request(1, ROOT, 1, &[1, 2]))
            .unwrap()
            .0,
        Status::Invalid
    );
    let req = Request {
        op: Op::Capabilities,
        handle: 0,
        payload: &[],
    }
    .encode();
    assert_eq!(
        decode_response(&ext.request(1, 501, 1, &req)).unwrap().0,
        Status::Denied
    );
    // Layers, flags and filters.
    let f = Flags::NONE;
    assert_eq!(
        try_open(&ext, 1, "udp", Layer::Flow, 0, f),
        Err(Status::Unsupported)
    );
    assert_eq!(
        try_open(&ext, 1, "udp.nosuch == 1", Layer::Network, 0, f),
        Err(Status::Invalid)
    );
    assert_eq!(
        try_open(
            &ext,
            1,
            "udp",
            Layer::Network,
            0,
            Flags::SNIFF | Flags::DROP
        ),
        Err(Status::Invalid)
    );
    // A handle belongs to the connection that opened it.
    let h = open(&ext, 1, "udp", 0, Flags::SNIFF);
    assert_eq!(call(&ext, 2, Op::Stats, h, &[]).0, Status::NoHandle);
    assert_eq!(call(&ext, 1, Op::Stats, h + 1, &[]).0, Status::NoHandle);
    // Parameters in range only.
    let (s, _) = call(
        &ext,
        1,
        Op::SetParam,
        h,
        &ioctl::encode_set_param(Param::QueueLength, 1),
    );
    assert_eq!(s, Status::Invalid);
    let (s, _) = call(
        &ext,
        1,
        Op::SetParam,
        h,
        &ioctl::encode_set_param(Param::QueueLength, 64),
    );
    assert_eq!(s, Status::Ok);
    // TestPacket only in test mode.
    let t = macos::encode_test_packet(&TestPacket {
        ifindex: 1,
        outbound: false,
        loopback: false,
        data: &udp(1, b""),
    });
    assert_eq!(call(&ext, 1, Op::TestPacket, 0, &t).0, Status::Unsupported);
}

#[test]
fn capabilities_follow_what_the_provider_gives() {
    let (ext, _) = extension(false);
    let caps = |ext: &Extension| {
        let (s, p) = call(ext, 1, Op::Capabilities, 0, &[]);
        assert_eq!(s, Status::Ok);
        macos::decode_capabilities(&p).unwrap()
    };
    let all = support::OPEN | support::DIVERT | support::DROP | support::INJECT | support::MODIFY;
    let c = caps(&ext);
    assert_eq!(c[Layer::Network as usize], all);
    // ETHERNET opens until the provider shows it gives IP packets only.
    assert_eq!(c[Layer::Ethernet as usize], 0);
    assert!(try_open(&ext, 1, "true", Layer::Ethernet, 0, Flags::SNIFF).is_ok());
    ext.packet(&seen(&udp(1, b"")));
    assert_eq!(
        try_open(&ext, 1, "true", Layer::Ethernet, 0, Flags::SNIFF),
        Err(Status::Unsupported)
    );

    let (ext, _) = extension(false);
    ext.packet(&seen(&frame(&udp(1, b""))));
    assert_eq!(caps(&ext)[Layer::Ethernet as usize], all);
}

#[test]
fn sniff_and_drop() {
    let (ext, released) = extension(false);
    let sniffer = open(&ext, 1, "udp.dstport == 53", 0, Flags::SNIFF);
    let dropper = open(
        &ext,
        1,
        "udp.dstport == 53 and udp.payload contains \"bad\"",
        -5,
        Flags::DROP,
    );
    let ok = udp(53, b"good");
    assert_eq!(ext.packet(&seen(&ok)), (Verdict::Allow, 0));
    assert_eq!(ext.packet(&seen(&udp(80, b"bad"))), (Verdict::Allow, 0));
    // The sniffer sees it before the dropper, which has a lower priority.
    assert_eq!(ext.packet(&seen(&udp(53, b"bad"))).0, Verdict::Drop);
    let got = recv(&ext, 1, sniffer, 0).unwrap();
    assert_eq!(got.len(), 2);
    let (addr, data) = &got[0];
    assert_eq!(data, &ok);
    assert!(addr.sniffed && addr.outbound && !addr.impostor && addr.ip_checksum);
    assert_eq!(addr.if_idx, 4);
    assert_eq!(stats(&ext, 1, sniffer).sniffed, 2);
    assert_eq!(stats(&ext, 1, dropper).dropped, 1);
    assert_eq!(recv(&ext, 1, sniffer, 0), Err(Status::Timeout));
    assert!(released.lock().unwrap().is_empty());
}

#[test]
fn filters_see_the_interface() {
    let (ext, _) = extension(false);
    let h = open(&ext, 1, r#"iface == "en0" and udp"#, 0, Flags::SNIFF);
    ext.packet(&seen(&udp(1, b"")));
    ext.packet(&Seen {
        ifname: "en1",
        ..seen(&udp(1, b""))
    });
    assert_eq!(recv(&ext, 1, h, 0).unwrap().len(), 1);
}

#[test]
fn divert_and_send_back_unchanged() {
    let (ext, released) = extension(false);
    let h = open(&ext, 1, "udp.dstport == 53", 0, Flags::NONE);
    let pkt = udp(53, b"q");
    let (v, t) = ext.packet(&seen(&pkt));
    assert_eq!(v, Verdict::Delay);
    let (addr, data) = recv_one(&ext, 1, h);
    assert!(!addr.sniffed);
    assert_eq!(token(&addr), t);
    assert_eq!(send(&ext, 1, h, &[(addr, &data)]), [SendResult::Sent]);
    assert_eq!(*released.lock().unwrap(), [(t, true)]);
    assert_eq!(stats(&ext, 1, h).diverted, 1);
    // Sent again, it is a new packet: the client injects it.
    assert_eq!(send(&ext, 1, h, &[(addr, &data)]), [SendResult::Inject]);
}

#[test]
fn a_packet_sent_back_goes_on_to_the_next_handles() {
    let (ext, released) = extension(false);
    let high = open(&ext, 1, "udp", 10, Flags::NONE);
    let low = open(&ext, 2, "udp", 5, Flags::NONE);
    let sniffer = open(&ext, 2, "udp", 0, Flags::SNIFF);
    let (_, t) = ext.packet(&seen(&udp(9, b"")));
    assert_eq!(recv(&ext, 2, low, 0), Err(Status::Timeout));
    let (addr, data) = recv_one(&ext, 1, high);
    send(&ext, 1, high, &[(addr, &data)]);
    // Still held, now by the lower handle, under the same token.
    assert!(released.lock().unwrap().is_empty());
    let (addr, data) = recv_one(&ext, 2, low);
    assert_eq!(token(&addr), t);
    send(&ext, 2, low, &[(addr, &data)]);
    assert_eq!(*released.lock().unwrap(), [(t, true)]);
    // The sniffer, last, saw it once.
    assert_eq!(recv(&ext, 2, sniffer, 0).unwrap().len(), 1);
}

#[test]
fn modified_packets_are_injected_by_the_client() {
    let (ext, released) = extension(false);
    let high = open(&ext, 1, "udp", 10, Flags::NONE);
    let low = open(&ext, 2, "udp", 5, Flags::SNIFF);
    let (_, t) = ext.packet(&seen(&udp(9, b"a")));
    let (addr, _) = recv_one(&ext, 1, high);
    let changed = udp(9, b"b");
    assert_eq!(
        send(&ext, 1, high, &[(addr, &changed)]),
        [SendResult::Inject]
    );
    // The original is dropped.
    assert_eq!(*released.lock().unwrap(), [(t, false)]);
    // The client's copy comes through: the sender skips it, the lower handle sees an impostor.
    assert_eq!(ext.packet(&seen(&changed)), (Verdict::Allow, 0));
    assert_eq!(recv(&ext, 1, high, 0), Err(Status::Timeout));
    let (addr, data) = recv_one(&ext, 2, low);
    assert_eq!(data, changed);
    assert!(addr.impostor);
    // The note is used once.
    assert_eq!(ext.packet(&seen(&changed)).0, Verdict::Delay);
}

#[test]
fn closing_lets_held_packets_go_on() {
    let (ext, released) = extension(false);
    let h = open(&ext, 7, "udp", 0, Flags::NONE);
    let (_, queued) = ext.packet(&seen(&udp(1, b"")));
    let (_, received) = ext.packet(&seen(&udp(2, b"")));
    let other = open(&ext, 8, "udp.dstport == 2", -1, Flags::NONE);
    let _ = recv(&ext, 7, h, 0).unwrap();
    ext.disconnect(7);
    let r = released.lock().unwrap().clone();
    assert!(r.contains(&(queued, true)), "{r:?}");
    // The one the next handle wants is held for it now.
    assert!(!r.iter().any(|&(t, _)| t == received));
    let (addr, _) = recv_one(&ext, 8, other);
    assert_eq!(token(&addr), received);
    assert_eq!(call(&ext, 7, Op::Stats, h, &[]).0, Status::NoHandle);
}

#[test]
fn queue_limits() {
    let (ext, released) = extension(false);
    let h = open(&ext, 1, "udp", 0, Flags::NONE);
    call(
        &ext,
        1,
        Op::SetParam,
        h,
        &ioctl::encode_set_param(Param::QueueLength, 32),
    );
    for i in 0..32 {
        assert_eq!(ext.packet(&seen(&udp(i, b""))).0, Verdict::Delay);
    }
    // Full: the packet goes on.
    assert_eq!(ext.packet(&seen(&udp(99, b""))), (Verdict::Allow, 0));
    assert_eq!(stats(&ext, 1, h).ring_full, 1);
    // QUEUE_TIME: packets that waited too long are dropped at the receive.
    call(
        &ext,
        1,
        Op::SetParam,
        h,
        &ioctl::encode_set_param(Param::QueueTime, 100),
    );
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(recv(&ext, 1, h, 0), Err(Status::Timeout));
    assert_eq!(stats(&ext, 1, h).queue_drops, 32);
    let r = released.lock().unwrap();
    assert_eq!(r.len(), 32);
    assert!(r.iter().all(|&(_, allow)| !allow));
}

#[test]
fn receive_waits_and_shutdown_ends_it() {
    let (ext, _) = extension(false);
    let ext = Arc::new(ext);
    let h = open(&ext, 1, "udp", 0, Flags::SNIFF);
    let e = ext.clone();
    let waiter = std::thread::spawn(move || recv(&e, 1, h, 5_000));
    std::thread::sleep(Duration::from_millis(100));
    ext.packet(&seen(&udp(1, b"")));
    assert_eq!(waiter.join().unwrap().unwrap().len(), 1);

    let e = ext.clone();
    let waiter = std::thread::spawn(move || recv(&e, 1, h, 5_000));
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        call(&ext, 1, Op::Shutdown, h, &1u32.to_le_bytes()).0,
        Status::Ok
    );
    assert_eq!(waiter.join().unwrap(), Err(Status::Shutdown));
    // Shut down, it takes nothing more.
    ext.packet(&seen(&udp(1, b"")));
    assert_eq!(recv(&ext, 1, h, 0), Err(Status::Shutdown));
    // Sending, shut down too.
    call(&ext, 1, Op::Shutdown, h, &2u32.to_le_bytes());
    let mut b = Vec::new();
    Record {
        addr: Address::new(Layer::Network),
        data: &udp(1, b""),
    }
    .encode_into(&mut b);
    assert_eq!(call(&ext, 1, Op::Send, h, &b).0, Status::Shutdown);
}

#[test]
fn frames_at_both_layers() {
    let (ext, _) = extension(false);
    let net = open(&ext, 1, "udp", 0, Flags::SNIFF);
    let eth = try_open(
        &ext,
        1,
        "eth.src == 02:00:00:00:00:01",
        Layer::Ethernet,
        0,
        Flags::SNIFF,
    )
    .unwrap();
    let ip = udp(1, b"");
    let f = frame(&ip);
    ext.packet(&seen(&f));
    let (addr, data) = recv_one(&ext, 1, net);
    assert_eq!(data, ip);
    assert_eq!(MacContext::decode(&addr.context).unwrap().l2(), &f[..14]);
    let (addr, data) = recv_one(&ext, 1, eth);
    assert_eq!(data, f);
    assert_eq!(addr.layer, Layer::Ethernet);
}

#[test]
fn test_packets_in_test_mode() {
    let (ext, _) = extension(true);
    let h = open(&ext, 1, "udp", 0, Flags::NONE);
    let t = macos::encode_test_packet(&TestPacket {
        ifindex: 3,
        outbound: false,
        loopback: true,
        data: &udp(1, b""),
    });
    let (s, p) = call(&ext, 1, Op::TestPacket, 0, &t);
    assert_eq!(s, Status::Ok);
    assert_eq!(
        u32::from_le_bytes(p[..4].try_into().unwrap()),
        Verdict::Delay as u32
    );
    let (addr, _) = recv_one(&ext, 1, h);
    assert!(addr.loopback && !addr.outbound);
    assert_eq!(token(&addr), u64::from_le_bytes(p[4..].try_into().unwrap()));
}

fn start(ext: &Extension, outbound: bool, remote_port: u16) -> (Verdict, u64, bool) {
    ext.flow_start(&crate::FlowStart {
        outbound,
        protocol: 6,
        pid: 42,
        process_name: Some("curl".into()),
        local: "10.0.0.1".parse().unwrap(),
        local_port: 50000,
        remote: "93.184.216.34".parse().unwrap(),
        remote_port,
    })
}

#[test]
fn flows_need_the_data_provider() {
    let (ext, _) = extension(false);
    let flow = Flags::SNIFF | Flags::RECV_ONLY;
    assert_eq!(
        try_open(&ext, 1, "true", Layer::Flow, 0, flow),
        Err(Status::Unsupported)
    );
    let (_, p) = call(&ext, 1, Op::Capabilities, 0, &[]);
    let caps = macos::decode_capabilities(&p).unwrap();
    assert_eq!(caps[Layer::Flow as usize], 0);
    assert_eq!(caps[Layer::Reflect as usize], support::OPEN);
    ext.set_flows(true);
    let (_, p) = call(&ext, 1, Op::Capabilities, 0, &[]);
    let caps = macos::decode_capabilities(&p).unwrap();
    assert_eq!(caps[Layer::Flow as usize], support::OPEN);
    assert_eq!(
        caps[Layer::Socket as usize],
        support::OPEN | support::DIVERT | support::DROP
    );
    assert!(try_open(&ext, 1, "true", Layer::Flow, 0, flow).is_ok());
    // Without FLOW or SOCKET handles, flows are let by and not watched.
    let (ext, _) = extension(false);
    ext.set_flows(true);
    assert_eq!(start(&ext, true, 443), (Verdict::Allow, 0, false));
}

#[test]
fn sockets_refuse_and_flows_report() {
    let (ext, _) = extension(false);
    ext.set_flows(true);
    let recv_only = Flags::RECV_ONLY;
    let sniffer = try_open(
        &ext,
        1,
        "event == connect",
        Layer::Socket,
        10,
        Flags::SNIFF | recv_only,
    )
    .unwrap();
    let blocker = try_open(&ext, 1, "remote.port == 443", Layer::Socket, 0, recv_only).unwrap();
    let flows = try_open(&ext, 2, "true", Layer::Flow, 0, Flags::SNIFF | recv_only).unwrap();

    // Refused: both SOCKET handles see the connect, the FLOW handle nothing.
    let (v, _, watch) = start(&ext, true, 443);
    assert_eq!((v, watch), (Verdict::Drop, false));
    let (addr, data) = recv_one(&ext, 1, sniffer);
    assert!(data.is_empty() && addr.sniffed && addr.outbound);
    assert_eq!(addr.event, avulse_filter::Event::SocketConnect);
    assert_eq!(addr.flow.remote_port, 443);
    assert_eq!(addr.flow.remote_addr().to_string(), "93.184.216.34");
    let (addr, _) = recv_one(&ext, 1, blocker);
    assert!(!addr.sniffed);
    assert_eq!(stats(&ext, 1, blocker).dropped, 1);
    assert_eq!(recv(&ext, 2, flows, 0), Err(Status::Timeout));

    // Allowed: established, then deleted, with the process.
    let (v, id, watch) = start(&ext, true, 80);
    assert_eq!((v, watch), (Verdict::Allow, true));
    let (addr, _) = recv_one(&ext, 2, flows);
    assert_eq!(addr.event, avulse_filter::Event::FlowEstablished);
    assert_eq!(addr.flow.endpoint_id, id);
    assert_eq!(
        (addr.flow.process_id, addr.flow.process_name()),
        (42, Some("curl"))
    );
    assert_eq!(addr.layer, Layer::Flow);
    ext.flow_end(id);
    let (addr, _) = recv_one(&ext, 2, flows);
    assert_eq!(addr.event, avulse_filter::Event::FlowDeleted);
    // The connect sniffer saw the second connect, not the close; an accept it does not want.
    assert_eq!(recv(&ext, 1, sniffer, 0).unwrap().len(), 1);
    start(&ext, false, 80);
    assert_eq!(recv(&ext, 1, sniffer, 0), Err(Status::Timeout));
    // Ending twice, or an unknown flow, does nothing.
    ext.flow_end(id);
    assert_eq!(recv(&ext, 2, flows, 0).unwrap().len(), 1);
}

#[test]
fn event_layers_get_no_packets() {
    let (ext, _) = extension(false);
    ext.set_flows(true);
    try_open(&ext, 1, "true", Layer::Socket, 0, Flags::RECV_ONLY).unwrap();
    assert_eq!(ext.packet(&seen(&udp(1, b""))), (Verdict::Allow, 0));
}

#[test]
fn reflect_reports_the_handles() {
    let (ext, _) = extension(false);
    let net = open(&ext, 1, "tcp.port == 80", 5, Flags::SNIFF);
    let reflect = try_open(
        &ext,
        2,
        "true",
        Layer::Reflect,
        0,
        Flags::SNIFF | Flags::RECV_ONLY,
    )
    .unwrap();
    // On opening, every handle, itself included.
    let got = recv(&ext, 2, reflect, 0).unwrap();
    assert_eq!(got.len(), 2);
    let (addr, data) = &got[0];
    assert_eq!(addr.event, avulse_filter::Event::ReflectOpen);
    assert_eq!(data, b"tcp.port == 80");
    assert_eq!(
        (
            addr.reflect.layer,
            addr.reflect.priority,
            addr.reflect.process_id
        ),
        (Layer::Network, 5, 101)
    );
    assert_eq!(got[1].0.reflect.layer, Layer::Reflect);
    // Then each handle that opens or closes.
    let other = open(&ext, 3, "udp", 0, Flags::SNIFF);
    call(&ext, 1, Op::Close, net, &[]);
    let got = recv(&ext, 2, reflect, 0).unwrap();
    let events: Vec<_> = got
        .iter()
        .map(|(a, _)| (a.event, a.reflect.process_id))
        .collect();
    assert_eq!(
        events,
        [
            (avulse_filter::Event::ReflectOpen, 103),
            (avulse_filter::Event::ReflectClose, 101)
        ]
    );
    let _ = other;
}

#[test]
fn test_flows_in_test_mode() {
    let (ext, _) = extension(true);
    let h = try_open(
        &ext,
        1,
        "true",
        Layer::Flow,
        0,
        Flags::SNIFF | Flags::RECV_ONLY,
    )
    .unwrap();
    let f = macos::TestFlow {
        outbound: true,
        protocol: 17,
        pid: 7,
        local_port: 1,
        remote_port: 2,
        ..macos::TestFlow::default()
    };
    let (s, p) = call(&ext, 1, Op::TestFlow, 0, &f.encode());
    assert_eq!(s, Status::Ok);
    let id = u64::from_le_bytes(p[8..16].try_into().unwrap());
    assert_eq!(p[16], 1);
    let end = macos::TestFlow { end: true, id, ..f };
    call(&ext, 1, Op::TestFlow, 0, &end.encode());
    let got = recv(&ext, 1, h, 0).unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[1].0.event, avulse_filter::Event::FlowDeleted);
    let (ext, _) = extension(false);
    assert_eq!(
        call(&ext, 1, Op::TestFlow, 0, &f.encode()).0,
        Status::Unsupported
    );
}
