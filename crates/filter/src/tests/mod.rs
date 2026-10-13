mod frames;
mod pcap;
mod tshark;

use alloc::string::String;
use core::net::{IpAddr, Ipv4Addr};

use avulse_proto::{Link, Packet, Tcp, ethertype, ip_proto};

use frames::*;

use crate::ir::Test;
use crate::{Event, Filter, FlowTuple, Layer, Level, Meta};

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
    // As in Wireshark, the outer 802.1ad tag is `ieee8021ad`, the inner 802.1Q tag `vlan`.
    assert!(check("ieee8021ad.id == 7 and vlan.id == 4095", &f));
    assert!(!check("vlan.id == 7", &f));
    assert!(check("count(vlan.id) == 1 and count(ieee8021ad) == 1", &f));
    assert!(check("vlan.dei == 1 and ieee8021ad.dei == 0", &f));
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

/// Behaviours settled against tshark 4.x (see `tshark.rs`), checked here without it.
#[test]
fn wireshark_conformance() {
    let syn = https_syn();
    // `not in`: present, and no value in the set.
    assert!(!check("ip.addr not in {10.0.0.0/8}", &syn));
    assert!(check("ip.addr not in {1.0.0.0/8}", &syn));
    assert!(!check("ipv6.addr not in {1::/16}", &syn));
    assert!(check("not ipv6.addr in {1::/16}", &syn));

    // An integer compared with bytes is one byte; `nn:` is hex.
    assert!(check(
        "tcp[13] == 2 and tcp[13] == 02 and tcp[13] == 02:",
        &syn
    ));
    assert!(check("ip[9] == 6 and ip[8] == 64 and ip[8] == 40:", &syn));
    assert!(!check("ip[8] == 40", &syn));
    // Wireshark before 4.6 read `18` as 0x18, so it gets a warning; `2` and `0x12` do not.
    assert_eq!(compile("tcp[13] == 18").warnings().len(), 1);
    assert!(
        compile("tcp[13] == 2 or tcp[13] == 0x12 or tcp[13] == 12:")
            .warnings()
            .is_empty()
    );
    assert!(error("ip[8] == 256").message.contains("too large"));
    assert!(error("tcp contains 80").message.contains("protocol"));

    // `ip.version` is also set for IPv6; `ipv6` spans the extension headers.
    let v6 = v6_udp();
    assert!(check("ip.version == 6 and not ip", &v6));
    let hbh = eth(
        ethertype::IPV6,
        &[],
        &ipv6(
            ip_proto::HOPOPT,
            &ipv6_hbh(ip_proto::TCP, &tcp(1, 2, Tcp::SYN, b"")),
        ),
    );
    assert!(check("len(ipv6) == 48 and ipv6.nxt == 0 and tcp", &hbh));

    // Fragments: no `tcp.len` without reassembly; `ipv6.fraghdr.*`.
    let frag = eth(
        ethertype::IPV4,
        &[],
        &ipv4_with(
            V4 {
                frag: 0x2000,
                ..V4::default()
            },
            ip_proto::TCP,
            &tcp(1, 2, Tcp::ACK, b"hello"),
        ),
    );
    assert!(check("tcp.payload and not tcp.len", &frag));
    let v6frag = eth(
        ethertype::IPV6,
        &[],
        &ipv6(
            ip_proto::IPV6_FRAG,
            &ipv6_frag(ip_proto::UDP, 5, true, b"zzzzzzzz"),
        ),
    );
    assert!(check(
        "ipv6.fraghdr.offset == 5 and ipv6.fraghdr.more and ipv6.fraghdr.ident == 0xcafef00d",
        &v6frag
    ));
}

#[test]
fn quantifiers_and_leading_dots() {
    let f = https_syn();
    assert!(check("all tcp.port > 400 and not all tcp.port > 500", &f));
    assert!(check("any tcp.port === 443 and all tcp.port !== 80", &f));
    assert!(!check("all tcp.port !== 443", &f));
    assert!(check(
        "all tcp.port in {443, 51000} and not all tcp.port in {443}",
        &f
    ));
    // `not in` negates the quantified membership, and needs the field.
    assert!(!check("any tcp.port not in {443}", &f));
    assert!(check("all tcp.port not in {443}", &f));
    assert!(!check("all udp.port not in {443}", &f));
    assert!(!check("all tcp.port == tcp.port", &f));
    assert!(!check("all udp.port > 0", &f));
    assert!(check(
        ".ip.src == 10.0.0.1 and ip.src == .ip.src and .tcp",
        &f
    ));
    assert_eq!(
        compile("all tcp.port in {80}").ir().to_string_lossy(),
        "(all_in tcp.port 80)"
    );
    assert_eq!(
        compile("any tcp.port != 80").ir().to_string_lossy(),
        "(any_ne tcp.port 80)"
    );
    assert!(error("all tcp").message.contains("needs a relation"));
    assert!(error(".tcp.prot == 1").message.contains("unknown field"));
    assert!(error("tcp.port == .80").message.contains("unknown field"));
}

#[test]
fn arithmetic() {
    let f = https_syn();
    assert!(check(
        "tcp.srcport + 1 == 51001 and tcp.dstport - 444 == -1",
        &f
    ));
    assert!(check("tcp.srcport -1 == 50999 and -tcp.dstport < 0", &f));
    assert!(check(
        "tcp.srcport + 1 * 2 == 51002 and {tcp.srcport + 1} * 2 == 102002",
        &f
    ));
    assert!(check("tcp.srcport & 0xff00 + 1 == 0xc700", &f));
    assert!(check(
        "tcp.port + tcp.port == 51443 and not tcp.port - tcp.port != 0",
        &f
    ));
    assert!(check(
        "tcp.port in {440 + 3, 1} and tcp.srcport == {1 + 2} * 17000",
        &f
    ));
    assert!(check(
        "max(tcp.port) == 51000 and min(tcp.port, udp.port) == 443",
        &f
    ));
    assert!(check(
        "abs(tcp.dstport - tcp.srcport) == 50557 and max(udp.port, 7) == 7",
        &f
    ));
    // Division by zero and overflow give no value.
    assert!(!check("tcp.srcport / 0 == 0 or tcp.srcport % 0", &f));
    assert!(!check("tcp.srcport * 9223372036854775807 > 0", &f));
    assert!(check(
        "tcp.srcport + 1 and not tcp.srcport - tcp.srcport",
        &f
    ));
    assert_eq!(
        compile("tcp.srcport == 2 * {3 + 4} - -1")
            .ir()
            .to_string_lossy(),
        "(any_eq tcp.srcport 15)"
    );
    assert!(
        error("tcp.srcport == 1 / 0")
            .message
            .contains("division by zero")
    );
    assert!(
        error("tcp.flags.syn + 1 == 1")
            .message
            .contains("needs integers")
    );
    assert!(error("ip.src + 1 == 1").message.contains("needs integers"));
    assert!(error("max(1, 2) == 2").message.contains("needs a field"));
    assert!(error("1 + 2").message.contains("not a test"));
    assert!(
        error("tcp.srcport-1 == 2")
            .help
            .unwrap()
            .contains("tcp.srcport - 1")
    );
}

#[test]
fn layers() {
    let tagged = eth_tpids(
        ethertype::IPV4,
        &[(ethertype::VLAN, 3), (ethertype::VLAN, 4)],
        &ipv4(ip_proto::UDP, &udp(1, 2, b"")),
    );
    assert!(check(
        "vlan.id#1 == 3 and vlan.id#2 == 4 and vlan.id #2 == 4",
        &tagged
    ));
    assert!(!check(
        "vlan.id#1 == 4 or vlan.id#0 == 3 or vlan#3",
        &tagged
    ));
    assert!(check(
        "vlan.id#[-1] == 4 and vlan.id#[-2] == 3 and vlan.id#[2:] == 4",
        &tagged
    ));
    assert!(check(
        "count(vlan.id#[1-2]) == 2 and count(vlan.id#[:2]) == 1",
        &tagged
    ));
    assert!(check(
        "ip#1 and ip.addr#[-1] == 10.0.0.1 and not ip#2 and udp.port#1 == 2",
        &tagged
    ));
    assert!(check("vlan.id#[1,2] == 4 and len(vlan#2) == 4", &tagged));
    // Absurd ranges select nothing instead of overflowing.
    assert!(!check("vlan.id#[5:9223372036854775807] == 4", &tagged));
    assert!(!check("frame[5:9223372036854775807] == 00", &tagged));
    assert_eq!(
        compile("vlan.id#[1-2,4:] == 3").ir().to_string_lossy(),
        "(any_eq vlan.id#[1-2,4:] 3)"
    );
    assert!(error("vlan.id#1#2 == 3").message.contains("expected `and`"));
    assert!(
        error("outbound#1")
            .message
            .contains("not part of a protocol layer")
    );
    assert!(
        error("vlan.id#[2-1] == 1")
            .message
            .contains("invalid layer range")
    );
    assert!(
        error("vlan.id#[-1-2] == 1")
            .message
            .contains("invalid layer range")
    );
}

#[test]
fn wireshark_labels() {
    let f = https_syn();
    assert!(check(
        "ip.proto == \"TCP\" and ip.proto == tcp and ip.proto == Tcp",
        &f
    ));
    assert!(check(
        "eth.type == IPv4 and ip.proto in {\"UDP\", \"TCP\"} and ip.proto > \"ICMP\"",
        &f
    ));
    assert!(check(
        "ip.flags.df == \"Set\" and ip.flags.mf == \"not set\" and tcp.flags.syn == Set",
        &f
    ));
    assert!(check("ip.dsfield.dscp == \"Default\"", &f));
    let e = error("ip.proto == \"Unassigned\"");
    assert!(e.message.contains("several values"), "{e:?}");
    assert!(error("ip.proto == \"6\"").message.contains("not a name"));
    assert!(
        error("tcp.port == \"80\"")
            .message
            .contains("expected an unsigned integer")
    );
    assert!(
        error("ip.proto == foo")
            .help
            .unwrap()
            .contains("known names")
    );
}

#[test]
fn bytes_and_case() {
    let f = dns_query();
    // `&` on bytes: as long as the shorter side; a bare one tests for a set bit.
    assert!(check(
        "udp.payload[2:2] & 80:00 == 00:00 and udp.payload[2:2] & 01:00",
        &f
    ));
    assert!(check(
        "udp.payload & ff:ff == 12:34 and len(udp.payload & ff:ff:ff:ff:ff) == 4",
        &f
    ));
    assert!(check(
        "udp.payload[0] & 0x10 == 0x10 and not udp.payload[0] & 0x10 == 10",
        &f
    ));
    assert!(check(
        "1 & udp.payload[1] == 00 and eth.src & 00:00:00:00:00:ff == 00:00:00:00:00:55",
        &f
    ));
    assert!(check(
        "ip.src & 255.0.0.0 == 10.0.0.0 and ip.dst & 255.255.0.0 == 192.168.0.0/16",
        &f
    ));
    assert!(!check("udp.payload[0:2] & udp.payload[2:2]", &f));
    // `upper`/`lower` fold ASCII case without copying.
    let meta = Meta {
        iface: Some("Eth0"),
        process_name: Some("Curl.EXE"),
        ..Meta::default()
    };
    assert!(check_with(
        "upper(iface) == \"ETH0\" and lower(iface) == \"eth0\"",
        &f,
        &meta
    ));
    assert!(check_with(
        "lower(process.name) contains \"curl.e\"",
        &f,
        &meta
    ));
    assert!(check_with(
        "upper(iface)[0:2] == \"ET\" and len(lower(iface)) == 4",
        &f,
        &meta
    ));
    assert!(check_with(
        "upper(iface) > \"EAAA\" and not iface == \"eth0\"",
        &f,
        &meta
    ));
    assert!(
        error("upper(tcp.payload) == \"X\"")
            .message
            .contains("string field")
    );
}

#[test]
fn multi_range_slices() {
    let f = dns_query();
    assert!(check(
        "udp.payload[0:2,3] == 12:34:00 and udp.payload[3,0:2] == 00:12:34",
        &f
    ));
    // Ranges that do not fit are skipped; none fitting gives no value.
    assert!(check(
        "udp.payload[0:2,10] == 12:34 and udp.payload[0:2,2:10] == 12:34",
        &f
    ));
    assert!(!check("udp.payload[10,20]", &f));
    assert!(check(
        "len(udp.payload[0:2,1:]) == 5 and udp.payload[0:2,3][1:2] == 34:00",
        &f
    ));
    assert!(check("ip.src[0,3] == 0a:01 and eth.src[0,5] == 00:55", &f));
    let meta = Meta {
        iface: Some("Eth0"),
        ..Meta::default()
    };
    assert!(check_with("upper(iface)[0,3] == \"E0\"", &f, &meta));
    // At most 32 bytes: too long a result gives no value, or an error when it is known early.
    assert!(check("frame[0:20,70:]", &long_frame()));
    assert!(!check("frame[0:20,40:]", &long_frame()));
    assert!(
        error("frame[0:20,20:20] == 00")
            .message
            .contains("more than 32 bytes")
    );
}

/// A frame long enough for 40-byte slices.
fn long_frame() -> alloc::vec::Vec<u8> {
    let mut f = https_syn();
    f.resize(80, 0);
    f
}

#[cfg(feature = "regex")]
#[test]
fn regular_expressions() {
    let f = http_get();
    // Case-insensitive by default, over bytes, as in Wireshark.
    assert!(check(
        "tcp.payload matches \"get\" and not tcp.payload matches \"(?-i)get\"",
        &f
    ));
    assert!(check(
        "tcp.payload ~ \"^GET /\" and frame matches \"HTTP/1\\\\.1\"",
        &f
    ));
    assert!(check(
        "all tcp.payload matches \"T\" and eth.src matches \"\\\\x00\\\\x11\"",
        &f
    ));
    let raw = eth(
        ethertype::IPV4,
        &[],
        &ipv4(ip_proto::UDP, &udp(1, 2, b"a\x81\xc3\xa9")),
    );
    assert!(check(
        "udp.payload matches \"\\x81\" and udp.payload matches \"[\\\\x80-\\\\xff]\"",
        &raw
    ));
    assert!(check("udp.payload matches \"\u{e9}$\"", &raw));
    let meta = Meta {
        iface: Some("Eth0"),
        ..Meta::default()
    };
    assert!(check_with("upper(iface) matches \"(?-i)^ETH\"", &f, &meta));
    let c = compile("tcp.payload matches \"x\"");
    assert!(c.user_space_only());
    assert!(!compile("tcp").user_space_only());
    assert!(
        error("tcp.payload matches \"(a)\\\\1\"")
            .message
            .contains("backreferences")
    );
    assert!(
        error("tcp.payload matches \"G(?=E)\"")
            .message
            .contains("look-around")
    );
    assert!(
        error("ip.src matches \"10\"")
            .message
            .contains("needs bytes")
    );
    assert!(
        error("tcp.payload matches 47:45")
            .message
            .contains("double-quoted")
    );
}

#[cfg(not(feature = "regex"))]
#[test]
fn regular_expressions_need_the_feature() {
    assert!(
        error("tcp.payload matches \"x\"")
            .message
            .contains("`regex` feature")
    );
}

#[test]
fn regex_patterns_escape_invalid_utf8() {
    assert_eq!(
        crate::regex::pattern(b"a\x81\xc3\xa9\\d"),
        "a\\x81\u{e9}\\d"
    );
}

#[test]
fn bitwise_and_chains_resolve_once() {
    // Resolving each side twice made a left-nested chain exponential.
    let chain = alloc::format!("tcp.flags{} == 0", " & 1".repeat(40));
    compile(&chain);
    assert_eq!(compile("frame[0] & 18 & 1 == 0").warnings().len(), 1);
}

#[test]
fn raw_field_bytes() {
    let f = https_syn();
    assert!(check(
        "@tcp.port == 01:bb and @tcp.srcport == c7:38 and @ip.src == 0a:00:00:01",
        &f
    ));
    // Bit fields cover the bytes they sit in; computed fields cover none.
    assert!(check(
        "@tcp.flags == 50:02 and @tcp.flags.syn == 02: and @ip.flags == 40:",
        &f
    ));
    assert!(check("len(@frame.len) == 0 and @tcp.flags[1] & 02:", &f));
    let tagged = eth_tpids(
        ethertype::IPV4,
        &[(ethertype::VLAN, 3), (ethertype::VLAN, 4)],
        &ipv4(ip_proto::UDP, &udp(1, 2, b"")),
    );
    assert!(check(
        "@vlan.id#2 == 00:04 and count(@vlan.id) == 2",
        &tagged
    ));
    assert!(!check("@tcp.port", &tagged));
    assert!(error("@outbound").message.contains("no bytes"));
    assert!(error("@(tcp)").message.contains("field name after `@`"));
    assert!(error("@1").message.contains("unknown field"));
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
    assert!(error("tcp & 0x18").message.contains("protocol"));
    assert!(error("iface & 1").message.contains("integers or bytes"));
    assert!(error("80").message.contains("not a test"));
    assert!(error("len(tcp.payload)").help.unwrap().contains("> 0"));
    assert!(
        error("tcp.payload matches {1}")
            .message
            .contains("double-quoted")
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
        error("string(tcp.port) == \"80\"")
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
