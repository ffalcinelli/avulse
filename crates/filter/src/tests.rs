use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr};

use avulse_proto::{Link, Packet, Tcp, ethertype, ip_proto};

use crate::ir::Test;
use crate::{Event, Filter, FlowTuple, Layer, Level, Meta};

const MAC_A: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const MAC_B: [u8; 6] = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

fn eth(et: u16, tags: &[u16], payload: &[u8]) -> Vec<u8> {
    let mut v = [MAC_B, MAC_A].concat();
    for (i, tci) in tags.iter().enumerate() {
        let tpid = if i == 0 && tags.len() > 1 {
            ethertype::QINQ
        } else {
            ethertype::VLAN
        };
        v.extend_from_slice(&tpid.to_be_bytes());
        v.extend_from_slice(&tci.to_be_bytes());
    }
    v.extend_from_slice(&et.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// 10.0.0.1 -> 192.168.1.2
fn ipv4(proto: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x45, 0x00];
    v.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    v.extend_from_slice(&[
        0x12, 0x34, 0x40, 0x00, 64, proto, 0, 0, 10, 0, 0, 1, 192, 168, 1, 2,
    ]);
    v.extend_from_slice(payload);
    v
}

/// fe80::1 -> 2001:db8::2
fn ipv6(next: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x60, 0, 0, 0];
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(&[
        next, 64, 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);
    v.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    v.extend_from_slice(payload);
    v
}

fn tcp(sport: u16, dport: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&sport.to_be_bytes());
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2]);
    v.extend_from_slice(&((5u16 << 12) | flags).to_be_bytes());
    v.extend_from_slice(&[0x10, 0x00, 0, 0, 0, 0]);
    v.extend_from_slice(payload);
    v
}

fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&sport.to_be_bytes());
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(payload);
    v
}

fn https_syn() -> Vec<u8> {
    eth(
        ethertype::IPV4,
        &[],
        &ipv4(ip_proto::TCP, &tcp(51000, 443, Tcp::SYN, b"")),
    )
}

fn http_get() -> Vec<u8> {
    eth(
        ethertype::IPV4,
        &[100],
        &ipv4(
            ip_proto::TCP,
            &tcp(51000, 80, Tcp::PSH | Tcp::ACK, b"GET / HTTP/1.1\r\n"),
        ),
    )
}

fn dns_query() -> Vec<u8> {
    eth(
        ethertype::IPV4,
        &[],
        &ipv4(ip_proto::UDP, &udp(5353, 53, b"\x12\x34\x01\x00")),
    )
}

fn arp_request() -> Vec<u8> {
    let mut a = vec![0, 1, 8, 0, 6, 4, 0, 1];
    a.extend_from_slice(&MAC_A);
    a.extend_from_slice(&[10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 2]);
    eth(ethertype::ARP, &[], &a)
}

fn v6_udp() -> Vec<u8> {
    eth(
        ethertype::IPV6,
        &[7, 0x1fff],
        &ipv6(ip_proto::UDP, &udp(546, 547, b"x")),
    )
}

fn compile(src: &str) -> Filter {
    Filter::compile(src).unwrap_or_else(|e| panic!("{}", e.render(src)))
}

fn check_with(src: &str, frame: &[u8], meta: &Meta<'_>) -> bool {
    compile(src).matches(&Packet::parse(frame, Link::Ethernet), meta)
}

fn check(src: &str, frame: &[u8]) -> bool {
    check_with(src, frame, &Meta::default())
}

fn error(src: &str) -> crate::Diagnostic {
    Filter::compile(src).expect_err(src)
}

#[test]
fn protocols_and_ports() {
    let f = https_syn();
    assert!(check("tcp", &f));
    assert!(check("ip and tcp and not udp", &f));
    assert!(check("tcp.port == 443", &f));
    assert!(check("tcp.dstport == 443 && tcp.srcport == 51000", &f));
    assert!(!check("udp.port == 443", &f));
    assert!(check("tcp xor udp", &f));
    assert!(check("frame.len == 54", &f));
    assert!(check(
        "eth.type == ipv4 and ip.proto == tcp and protocol == tcp",
        &f
    ));
}

#[test]
fn wireshark_quantifiers() {
    let f = https_syn();
    assert!(check("ip.addr == 192.168.1.2", &f));
    // `!=` is all_ne: false because the source is 10.0.0.1.
    assert!(!check("ip.addr != 10.0.0.1", &f));
    assert!(check("ip.addr != 1.1.1.1", &f));
    // `!==` / `~=` is any_ne.
    assert!(check("ip.addr ~= 10.0.0.1", &f));
    assert!(check("ip.addr !== 10.0.0.1", &f));
    assert!(!check("ip.addr === 10.0.0.1", &f));
    assert!(check("tcp.port > 50000", &f));
    assert!(check("tcp.port lt 1000", &f));
}

#[test]
fn absent_fields_are_false() {
    let f = dns_query();
    assert!(!check("tcp.port == 80", &f));
    assert!(!check("tcp.port != 80", &f));
    assert!(check("not tcp.port == 80", &f));
    assert!(!check("tcp.payload contains \"x\"", &f));
}

#[test]
fn addresses_sets_and_ranges() {
    let f = https_syn();
    assert!(check("ip.src == 10.0.0.0/8", &f));
    assert!(!check("ip.src == 10.0.0.0/16 and ip.dst == 10.0.0.0/8", &f));
    assert!(check("ip.dst in {172.16.0.0/12, 192.168.0.0/16}", &f));
    assert!(!check("ip.dst not in {192.168.0.0/16}", &f));
    assert!(check("tcp.dstport in {80, 400..500}", &f));
    assert!(check("tcp.dstport in {80 443}", &f));
    assert!(!check("tcp.dstport in {1..442, 444..65535}", &f));
    assert!(check("ip.dst in {192.168.1.1..192.168.1.9}", &f));
    assert!(check("ip.src < 10.0.0.2", &f));
    assert!(check("443 == tcp.dstport and 1000 < tcp.srcport", &f));
}

#[test]
fn tcp_flags() {
    let f = https_syn();
    assert!(check("tcp.flags & syn", &f));
    assert!(check("tcp.flags & (0x12) == 0x02", &f));
    assert!(check(
        "tcp.flags & (syn) == syn and not tcp.flags & ack",
        &f
    ));
    assert!(check("tcp.flags == syn", &f));
    assert!(check(
        "tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.flags.fin == false",
        &f
    ));
    assert!(!check("tcp.flags.ack == true", &f));
}

#[test]
fn bare_boolean_field_warns() {
    let f = compile("tcp.flags.ack");
    assert_eq!(f.warnings().len(), 1);
    assert_eq!(f.warnings()[0].level, Level::Warning);
    assert!(f.warnings()[0].help.as_ref().unwrap().contains("== 1"));
    // Wireshark semantics: presence, even though ACK is clear.
    assert!(f.matches(
        &Packet::parse(&https_syn(), Link::Ethernet),
        &Meta::default()
    ));
}

#[test]
fn slices_payloads_and_functions() {
    let f = http_get();
    assert!(check("eth.src[0:3] == 00:11:22", &f));
    assert!(check("eth.src[3-5] == 33:44:55", &f));
    assert!(check("eth.dst[-1] == bb", &f));
    assert!(check("ip.src[0] == 0a", &f));
    assert!(check("frame[12:2] == 81:00", &f));
    assert!(check("tcp.payload[0:3] == \"GET\"", &f));
    assert!(check("tcp.payload contains \"HTTP/1.1\"", &f));
    assert!(check("tcp contains 00:50", &f));
    assert!(check("len(tcp.payload) == 16 and tcp.len == 16", &f));
    assert!(check("tcp.payload[0] == 'G'", &f));
    assert!(!check("tcp.payload[100:2]", &f));
    assert!(check("udp.payload[2:2] == 01:00", &dns_query()));
}

#[test]
fn vlan_and_qinq() {
    assert!(check(
        "vlan.id == 100 and vlan.etype == ipv4 and eth.type == vlan",
        &http_get()
    ));
    let f = v6_udp();
    assert!(check("vlan.id == 7 and vlan.id == 4095", &f));
    assert!(check("count(vlan.id) == 2", &f));
    assert!(check("vlan.dei == 1", &f));
    assert!(!check("vlan", &https_syn()));
}

#[test]
fn arp_and_ipv6() {
    let f = arp_request();
    assert!(check("arp and eth.type == arp", &f));
    assert!(check(
        "arp.opcode == request and arp.dst.proto_ipv4 == 10.0.0.2",
        &f
    ));
    assert!(check(
        "arp.src.hw_mac == 00:11:22:33:44:55 and eth.addr == 66:77:88:99:aa:bb",
        &f
    ));
    assert!(!check("ip or ipv6", &f));

    let f = v6_udp();
    assert!(check("ipv6.addr == fe80::1 and ipv6.src == fe80::/10", &f));
    assert!(check(
        "ipv6.dst in {2001:db8::/32} and udp.dstport == 547",
        &f
    ));
    assert!(check("ipv6.nxt == udp and ipv6.hlim == 64", &f));
}

#[test]
fn metadata_fields() {
    let f = https_syn();
    let out = Meta {
        outbound: true,
        ifidx: 3,
        iface: Some("eth0"),
        ..Meta::default()
    };
    assert!(check_with("outbound and not inbound", &f, &out));
    assert!(check_with(
        "local.port == 51000 and remote.port == 443",
        &f,
        &out
    ));
    assert!(check_with(
        "local.addr == 10.0.0.1 and remote.addr == 192.168.1.0/24",
        &f,
        &out
    ));
    assert!(check_with(
        "iface == \"eth0\" and frame.interface_name == eth0 and ifidx == 3",
        &f,
        &out
    ));
    assert!(check_with("layer == network and event == packet", &f, &out));
    let inbound = Meta::default();
    assert!(check_with("inbound and local.port == 443", &f, &inbound));

    let flow = Meta {
        layer: Layer::Socket,
        event: Event::SocketConnect,
        process_id: Some(42),
        process_name: Some("curl"),
        flow: Some(FlowTuple {
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
            remote_addr: "2001:db8::1".parse().unwrap(),
            local_port: 40000,
            remote_port: 443,
            protocol: 6,
        }),
        ..Meta::default()
    };
    let none = Packet::parse(&[], Link::Ip);
    let f = compile(
        "layer == socket and event == connect and process.pid == 42 and process.name == \"curl\" \
         and protocol == tcp and remote.addr == 2001:db8::/32 and local.addr == 10.0.0.9 and remote.port == 443",
    );
    assert!(f.matches(&none, &flow));
    assert!(!compile("tcp").matches(&none, &flow));
}

#[test]
fn macros() {
    let src = "let lan = {10.0.0.0/8, 192.168.0.0/16}\nlet web = tcp.port in {80, 443}\nlet https = 443;\n\
               ip.src in $lan and $web and tcp.dstport == ${https}";
    assert!(check(src, &https_syn()));
    assert!(
        error("let a = $b\nlet b = $a\n$a")
            .message
            .contains("refers to itself")
    );
    assert!(error("$nope").message.contains("unknown macro"));
    assert!(error("let s = {1}\n$s").message.contains("is a set"));
    assert!(
        error("let a = tcp\nlet a = udp\n$a")
            .message
            .contains("twice")
    );
    let f = compile("let unused = tcp\nudp");
    assert!(f.warnings()[0].message.contains("never used"));
}

#[test]
fn ir_is_simplified() {
    assert_eq!(
        compile("true and (tcp and (udp or false))")
            .ir()
            .to_string_lossy(),
        "(and (exists tcp) (exists udp))"
    );
    assert_eq!(
        compile("not not tcp").ir().to_string_lossy(),
        "(exists tcp)"
    );
    assert_eq!(*compile("tcp or true").ir(), Test::Const(true));
    assert_eq!(
        compile("tcp.port != 80").ir().to_string_lossy(),
        "(all_ne tcp.port 80)"
    );
}

trait Lossy {
    fn to_string_lossy(&self) -> String;
}

impl Lossy for Test {
    fn to_string_lossy(&self) -> String {
        alloc::format!("{self}")
    }
}

#[test]
fn errors_explain_themselves() {
    let e = error("tcp.prot == 80");
    assert!(e.message.contains("unknown field `tcp.prot`"));
    assert_eq!(e.help.as_deref(), Some("did you mean `tcp.port`?"));
    assert_eq!((e.span.start, e.span.end), (0, 8));

    assert!(
        error("http.host == \"x\"")
            .message
            .contains("does not decode `http`")
    );
    assert!(error("tcp.seq == 1").help.unwrap().contains("tcp.seq_raw"));
    assert!(
        error("tcp.analysis.retransmission")
            .help
            .unwrap()
            .contains("stream")
    );
    assert!(error("ip.src == fe80::1").message.contains("IPv6 address"));
    assert!(
        error("ipv6.src == 1.2.3.4")
            .message
            .contains("IPv4 address")
    );
    assert!(error("tcp.port == 70000").message.contains("does not fit"));
    assert!(error("vlan.id == 4096").message.contains("12 bits"));
    assert!(
        error("tcp.port == foo")
            .message
            .contains("expected an unsigned integer")
    );
    assert!(error("80 == 80").message.contains("two values"));
    assert!(error("tcp == 1").message.contains("protocol"));
    assert!(error("tcp[13] & 0x18").help.unwrap().contains("tcp.flags"));
    assert!(error("80").message.contains("not a test"));
    assert!(error("len(tcp.payload)").help.unwrap().contains("> 0"));
    assert!(
        error("tcp.payload matches \"x\"")
            .message
            .contains("matches")
    );
    assert!(
        error("tcp.flags.syn > 0")
            .message
            .contains("cannot be ordered")
    );
    assert!(error("ip.src > 10.0.0.0/8").message.contains("ranges"));
    assert!(
        error("tcp.port[0:1] == 00")
            .message
            .contains("cannot slice")
    );
    assert!(
        error("tcp.port in {ip.ttl}")
            .message
            .contains("must be values")
    );
    assert!(error("tcp.port in {9..1}").message.contains("empty"));
    assert!(
        error("ip.src == ipv6.src")
            .message
            .contains("cannot compare")
    );
    assert!(
        error("upper(tcp.payload) == \"x\"")
            .message
            .contains("not supported")
    );
}

#[test]
fn bare_fields_are_presence_tests() {
    // A bare non-boolean field is a presence test in Wireshark, never an error.
    assert!(check("tcp.port", &https_syn()));
    assert!(!check("tcp.payload", &https_syn()));
}

#[test]
fn render_points_at_the_problem() {
    let src = "tcp.port == 80 and\nhttp.host == \"x\"";
    let r = error(src).render(src);
    assert!(r.contains("2 | http.host == \"x\""), "{r}");
    assert!(r.contains("  | ^^^^^^^^^"), "{r}");
    assert!(r.contains("= help:"), "{r}");
}
