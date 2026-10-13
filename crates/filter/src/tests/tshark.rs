//! Differential test against Wireshark: every filter must select the same frames in `tshark` and
//! in Avulse. It runs only with `AVULSE_TSHARK=1`, since it needs `tshark` 4.6 or later on the
//! `PATH`:
//!
//! ```text
//! AVULSE_TSHARK=1 cargo test -p avulse-filter tshark -- --nocapture
//! ```

extern crate std;

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use std::io::Write;
use std::process::{Command, Stdio};
use std::{env, println, thread};

use avulse_proto::{Link, Packet, Tcp, ethertype as et, ip_proto as ipp};

use super::frames::*;
use super::pcap;
use crate::fields::{FIELDS, Origin};
use crate::{Filter, Meta};

type Corpus = Vec<(&'static str, Vec<u8>)>;

/// Ethernet frames covering every header the parser knows, plus truncations.
fn corpus() -> Corpus {
    let v4 = |proto: u8, l4: &[u8]| eth(et::IPV4, &[], &ipv4(proto, l4));
    let v6 = |next: u8, l4: &[u8]| eth(et::IPV6, &[], &ipv6(next, l4));
    let truncated = |mut f: Vec<u8>, len: usize| {
        f.truncate(len);
        f
    };
    let padded = {
        let mut f = v4(ipp::TCP, &tcp(1000, 2000, Tcp::PSH | Tcp::ACK, b"hello"));
        f.resize(64, 0);
        f
    };
    let hbh_tcp = v6(
        ipp::HOPOPT,
        &ipv6_hbh(ipp::TCP, &tcp(443, 51000, Tcp::SYN | Tcp::ACK, b"hi")),
    );
    vec![
        ("syn", https_syn()),
        ("http_vlan", http_get()),
        ("udp_dns", dns_query()),
        ("arp", arp_request()),
        ("v6_udp_qinq", v6_udp()),
        (
            "vlan_9100",
            eth_tpids(
                et::IPV4,
                &[(et::VLAN_9100, 0x2005), (et::VLAN, 0xe006)],
                &ipv4(ipp::UDP, &udp(1, 2, b"")),
            ),
        ),
        (
            "vlan_double",
            eth_tpids(
                et::IPV4,
                &[(et::VLAN, 0x0003), (et::VLAN, 0x0004)],
                &ipv4(ipp::UDP, &udp(1, 2, b"")),
            ),
        ),
        (
            "v4_frag_first",
            eth(
                et::IPV4,
                &[],
                &ipv4_with(
                    V4 {
                        frag: 0x2000,
                        ..V4::default()
                    },
                    ipp::TCP,
                    &tcp(1000, 2000, Tcp::PSH | Tcp::ACK, b"hello"),
                ),
            ),
        ),
        (
            "v4_frag_last",
            eth(
                et::IPV4,
                &[],
                &ipv4_with(
                    V4 {
                        frag: 0x0003,
                        ..V4::default()
                    },
                    ipp::TCP,
                    b"zzzzzzzz",
                ),
            ),
        ),
        (
            "v4_evil_bit",
            eth(
                et::IPV4,
                &[],
                &ipv4_with(
                    V4 {
                        frag: 0x8000,
                        ..V4::default()
                    },
                    ipp::UDP,
                    &udp(7, 7, b"e"),
                ),
            ),
        ),
        (
            "v6_frag_first",
            v6(
                ipp::IPV6_FRAG,
                &ipv6_frag(ipp::UDP, 0, true, &udp(1000, 2000, b"abcd")),
            ),
        ),
        (
            "v6_frag_last",
            v6(ipp::IPV6_FRAG, &ipv6_frag(ipp::UDP, 5, false, b"zzzzzzzz")),
        ),
        ("v6_hbh_tcp", hbh_tcp.clone()),
        ("echo", v4(ipp::ICMP, &icmp(8, 0, [0, 7, 0, 9], b"ping"))),
        ("echo_reply", v4(ipp::ICMP, &icmp(0, 0, [0, 7, 0, 9], b""))),
        (
            "timestamp",
            v4(ipp::ICMP, &icmp(13, 0, [0, 3, 0, 4], &[0; 12])),
        ),
        (
            "unreachable",
            v4(
                ipp::ICMP,
                &icmp(3, 3, [0; 4], &ipv4(ipp::UDP, &udp(1, 2, b""))),
            ),
        ),
        (
            "v6_echo",
            v6(ipp::ICMPV6, &icmp(128, 0, [0, 0x77, 0, 3], b"ping")),
        ),
        (
            "v6_ns",
            v6(
                ipp::ICMPV6,
                &icmp(
                    135,
                    0,
                    [0; 4],
                    &[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                ),
            ),
        ),
        ("padded", padded),
        (
            "ip_options",
            eth(
                et::IPV4,
                &[],
                &ipv4_with(
                    V4 {
                        options: &[1, 1, 1, 0],
                        ..V4::default()
                    },
                    ipp::UDP,
                    &udp(53, 53, b""),
                ),
            ),
        ),
        (
            "all_flags",
            eth(
                et::IPV4,
                &[],
                &ipv4_with(
                    V4 {
                        tos: 0xb9,
                        ..V4::default()
                    },
                    ipp::TCP,
                    &tcp_with(80, 80, 0x1ff, &[2, 4, 5, 0xb4], b""),
                ),
            ),
        ),
        (
            "tcp_reserved",
            v4(ipp::TCP, &tcp(1, 2, 0xe00 | Tcp::ACK, b"")),
        ),
        ("v6_udp_empty", v6(ipp::UDP, &udp(5000, 5001, b""))),
        (
            "lldp",
            eth(
                et::LLDP,
                &[],
                &[0x02, 0x07, 0x04, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0, 0],
            ),
        ),
        ("trunc_ip", truncated(https_syn(), 14 + 10)),
        ("trunc_tcp", truncated(https_syn(), 14 + 20 + 10)),
        ("trunc_v6_ext", truncated(hbh_tcp, 14 + 40 + 4)),
    ]
}

/// The untagged IP frames of the corpus without their Ethernet header.
fn raw_corpus(eth_corpus: &Corpus) -> Corpus {
    eth_corpus
        .iter()
        .filter(|(_, f)| matches!(f.get(12..14), Some([0x08, 0x00] | [0x86, 0xdd])))
        .map(|(n, f)| (*n, f[14..].to_vec()))
        .collect()
}

/// Frames where Avulse knowingly reads fewer headers than tshark, so the general tables skip them
/// and [`DIVERGENCES`] pins the difference:
///
/// - `unreachable`: tshark also dissects the IP datagram quoted by an ICMP error. Avulse matches
///   only the outermost headers, as WinDivert does.
/// - `trunc_*`: tshark sets the fields of a header that is cut short as far as the bytes go.
///   Avulse stops at the first incomplete header, so its fields are absent.
const SKIP: &[&str] = &["unreachable", "trunc_ip", "trunc_tcp", "trunc_v6_ext"];

/// Filters that must select the same frames in tshark and Avulse.
const AGREE: &[&str] = &[
    // Quantifiers and absent fields.
    "ip.addr == 192.168.1.2",
    "ip.addr != 10.0.0.1",
    "ip.addr != 1.1.1.1",
    "ip.addr !== 10.0.0.1",
    "ip.addr === 10.0.0.1",
    "ipv6.addr === fe80::1",
    "tcp.port != 80",
    "udp.port != 53",
    "tcp.port !== 80",
    "tcp.port === 80",
    "not tcp.port == 80",
    "tcp.port > 50000",
    "tcp.port lt 1000",
    "tcp.port ge 443 and tcp.port le 443",
    "vlan.id != 7",
    "eth.addr == 66:77:88:99:aa:bb",
    "eth.addr != 00:11:22:33:44:55",
    // Explicit quantifiers.
    "all tcp.port > 400",
    "all tcp.port > 500",
    "any tcp.port === 443",
    "all tcp.port !== 443",
    "all tcp.port != 80",
    "any tcp.port != 443",
    "any tcp.port == 80",
    "all tcp.port in {443, 51000}",
    "all tcp.port in {443}",
    "any tcp.port in {443}",
    "any tcp.port not in {443}",
    "all tcp.port not in {443}",
    "all tcp.port not in {1, 2}",
    "all udp.port > 0",
    "all tcp.port == tcp.port",
    "any tcp.port < tcp.port",
    "all tcp.port <= tcp.port",
    "not all tcp.port > 500",
    "all ip.addr == 10.0.0.0/8",
    "all ip.addr in {10.0.0.0/8, 192.168.0.0/16}",
    "any ip.addr == 10.0.0.1",
    "all vlan.id > 5",
    "all tcp.payload contains \"T\"",
    "all eth.addr contains 00:",
    "all len(tcp) > 20",
    "all 443 == tcp.port",
    "all ip.addr != 10.0.0.1 or arp",
    // Arithmetic and functions.
    "tcp.srcport + 1 == 51001",
    "tcp.srcport + 1 > 65535",
    "tcp.dstport - 2 < 0",
    "tcp.dstport - 2 == -1",
    "tcp.srcport -1 == 50999",
    "tcp.srcport - tcp.dstport == 50557",
    "tcp.dstport - tcp.srcport == -50557",
    "-tcp.dstport == -443",
    "-tcp.dstport < 0",
    "tcp.srcport * 2 > 100",
    "tcp.srcport / 2 == 25500",
    "tcp.srcport % 7 == 4",
    "tcp.srcport / 0 == 0",
    "tcp.srcport % 0",
    "tcp.srcport + 1 * 2 == 51002",
    "{tcp.srcport + 1} * 2 - 51001 == 51001",
    "tcp.srcport + 1",
    "tcp.srcport - tcp.srcport",
    "{tcp.flags & 2}",
    "tcp.srcport & 0xff00 + 1 == 0xc701",
    "tcp.srcport & 0xff00 == 0xc700",
    "tcp.port + 1 == 444",
    "tcp.port + tcp.port == 51443",
    "tcp.port - tcp.port == 0",
    "tcp.port - tcp.port != 0",
    "all tcp.port - tcp.port == 0",
    "tcp.srcport == 50999 + 1",
    "tcp.srcport == 51001 - 1",
    "tcp.srcport == {1 + 2} * 17000",
    "1 + 1 == tcp.srcport - 50998",
    "tcp.srcport + 'a' == 51097",
    "tcp.srcport == -1",
    "tcp.port in {440 + 3, 1}",
    "tcp.port in {440+3..444}",
    "tcp.port in {1 - 1 .. 2}",
    "len(tcp) + 1 == 21",
    "count(tcp.port) * 2 == 4",
    "tcp.len > tcp.hdr_len * 2",
    "ip.ttl * 2 == 128",
    "frame.len - 54 == 0",
    "vlan.id * 2 == 8",
    "tcp.seq_raw * tcp.seq_raw == 1",
    "max(tcp.port) == 51000",
    "min(tcp.port) == 443",
    "max(tcp.srcport, tcp.dstport) == 51000",
    "max(tcp.port, 60000) == 60000",
    "min(udp.port, tcp.port) == 1",
    "max(tcp.srcport, udp.srcport) > 1000",
    "min(vlan.id) == 3",
    "abs(-tcp.dstport) == 443",
    "abs(tcp.dstport - tcp.srcport) == 50557",
    "abs(tcp.dstport) == 443",
    // Layers.
    "vlan.id#1 == 3",
    "vlan.id#2 == 4",
    "vlan.id#1 == 4",
    "vlan.id #2 == 4",
    "vlan.id#0 == 3",
    "vlan#2",
    "vlan#[-1]",
    "vlan.id#[-1] == 4",
    "vlan.id#[-2] == 3",
    "vlan.id#[-2:] == 4",
    "vlan.id#[-1:2] == 6",
    "vlan.id#[0-1] == 3",
    "vlan.id#[:2] == 3",
    "vlan.id#[:2] == 4",
    "vlan.id#[1,2] == 4",
    "vlan.id#[2:] == 6",
    "vlan.id#[1-2] == 6",
    "count(vlan.id#[1-2]) == 2",
    "count(vlan.id#2) == 1",
    "len(vlan#1) == 4",
    "vlan.etype#2 == 0x800",
    "vlan.priority#1 == 1",
    "vlan.priority#2 == 7",
    "vlan.dei#1 == 1",
    "vlan.id#1 == 0xfff",
    "ieee8021ad.id#1 == 7",
    "ieee8021ad#2",
    "ip#1",
    "ip#2",
    "ip.addr#1 == 10.0.0.1",
    "ip.addr#[-1] == 192.168.1.2",
    "udp.port#1 == 53",
    "tcp.port#[-1] == 80",
    "eth.addr#1 == 66:77:88:99:aa:bb",
    "eth#2",
    "all vlan.id#[1-2] > 2",
    // Wireshark's value-string labels (more are generated by `label_filters`).
    "ip.proto == \"TCP\"",
    "ip.proto == \"tcp\"",
    "ip.proto == UDP",
    "icmp.type == \"Echo (ping) request\"",
    "icmp.type == \"echo (ping) reply\"",
    "eth.type == \"IPv4\"",
    "eth.type == IPv6",
    "vlan.etype == \"IPv4\"",
    "arp.opcode == \"REQUEST\"",
    "ip.proto in {\"TCP\", UDP}",
    "ip.proto > \"TCP\"",
    "ip.dsfield.dscp == \"Expedited Forwarding\"",
    "ip.dsfield.ecn == \"ECN-Capable Transport codepoint '01'\"",
    "vlan.priority == \"Background\"",
    "vlan.priority == \"Network Control\"",
    "ip.flags.df == \"Set\"",
    "ip.flags.mf == \"Not set\"",
    "ip.flags.df == Set",
    "tcp.flags.syn == \"Set\"",
    "ipv6.fraghdr.more == \"Yes\"",
    "vlan.dei == \"Eligible\"",
    "ipv6.nxt == \"UDP\"",
    "icmpv6.type == \"Echo (ping) request\"",
    "arp.hw.type == \"Ethernet\"",
    "arp.proto.type == \"IPv4\"",
    // `&` on bytes and addresses.
    "udp.payload[2:2] & 01:00",
    "udp.payload[2:2] & 01:00 == 01:00",
    "udp.payload[0] & 0x10",
    "udp.payload[0] & 0x10 == 10",
    "udp.payload[0] & 0x10 == 0x10",
    "udp.payload[0] & 0x10 == 10:",
    "udp.payload & ff:ff",
    "udp.payload & ff:ff == 12:34",
    "len(udp.payload & ff:ff:ff:ff:ff) == 4",
    "udp.payload[0:2] & udp.payload[2:2]",
    "udp.payload[0:2] & udp.payload[2:2] == 00:00",
    "eth.dst & 01:00:00:00:00:00",
    "eth.dst[0] & 1",
    "eth.dst[0] & 2",
    "eth.src & 00:00:00:00:00:01",
    "tcp.payload & 0x80",
    "tcp.payload[0] & 0x47 == 47:",
    "ip.src & 255.0.0.0 == 10.0.0.0",
    "ip.dst & 255.255.255.0 == 192.168.1.0",
    "ipv6.src & ffff:: == fe80::",
    "1 & udp.payload[0]",
    "tcp[13] & 0x12 == 0x12",
    "tcp[12:2] & 0f:ff == 00:02",
    "frame[12:2] & ff:00 == 08:00",
    // Multi-range slices.
    "udp.payload[0:2,3] == 12:34:00",
    "udp.payload[3,0:2] == 00:12:34",
    "udp.payload[0,0] == 12:12",
    "udp.payload[0:2,10] == 12:34",
    "udp.payload[0:2,10]",
    "udp.payload[10,20]",
    "udp.payload[0:2,2:10] == 12:34",
    "udp.payload[-1,0] == 00:12",
    "len(udp.payload[0:2,1:]) == 5",
    "udp.payload[0:2,1-2] == 12:34:34:01",
    "udp.payload[0:2,3][1:2] == 34:00",
    "udp.payload[ 0:2 , 3 ] == 12:34:00",
    "eth.src[0,5] == 00:55",
    "ip.src[0,3] == 0a:01",
    "ipv6.dst[0:2,15] == 20:01:02",
    "frame[0:6,6:6] == 66:77:88:99:aa:bb:00:11:22:33:44:55",
    "tcp.payload[0:3,4] contains \"T/\"",
    "frame[12:2,-1] & ff:00:00 == 08:00:00",
    // `upper`/`lower` (the only string field in a pcap is absent).
    "upper(frame.interface_name) == \"ETH0\"",
    "lower(frame.interface_name) contains \"eth\"",
    // `@field`: the bytes on the wire (every span is also checked by `tshark_raw_spans`).
    "@tcp.port == 01:bb",
    "@tcp.srcport == c7:38",
    "@tcp.flags == 50:02",
    "@tcp.flags.syn == 02:",
    "@tcp.flags & 00:02",
    "any @tcp.port == 00:50",
    "all @tcp.port == 00:50",
    "@ip.flags == 40:",
    "@ip.src == 0a:00:00:01",
    "len(@tcp.flags) == 2",
    "@vlan.id#1 == 00:03",
    "@vlan.id#2 == 00:04",
    "@vlan#2",
    "count(@vlan.id) == 2",
    "@frame.len",
    "len(@frame.len) == 0",
    "len(@tcp.len) == 0",
    "@eth.addr == 00:11:22:33:44:55",
    "@udp.payload[0:2] == 12:34",
    "@ieee8021ad.priority == 00:",
    "@ipv6.fraghdr.ident == ca:fe:f0:0d",
    // Leading dots force a field name.
    ".ip.src == 10.0.0.1",
    "ip.src == .ip.src",
    ".tcp",
    ".tcp.port == 80",
    // Precedence.
    "tcp or udp and ip",
    "tcp and udp or ip",
    "udp or tcp and ipv6",
    "not tcp and ip",
    "not tcp or udp",
    "tcp xor udp",
    "tcp ^^ udp or arp",
    "arp or tcp ^^ udp",
    "tcp ^^ ip and udp",
    "tcp && !udp || arp",
    // Sets, ranges and prefixes.
    "ip.addr in {10.0.0.0/8}",
    "ip.dst in {172.16.0.0/12, 192.168.0.0/16}",
    "ip.dst not in {192.168.0.0/16}",
    "ip.addr in {10.0.0.0 .. 10.0.0.5}",
    "ip.src == 10.0.0.0/8",
    "ip.src == 10.0.0.0/16 and ip.dst == 10.0.0.0/8",
    "ipv6.src == fe80::/10",
    "ipv6.addr in {2001:db8::/32}",
    "tcp.dstport in {80, 400..500}",
    "tcp.port in {80, 443}",
    "ip.addr not in {10.0.0.0/8}",
    "ip.addr not in {10.0.0.1, 192.168.1.2}",
    "ip.dst not in {192.168.0.0/16}",
    "not ip.dst in {192.168.0.0/16}",
    "tcp.port not in {80, 443}",
    "udp.port in {1..100}",
    "ip.src < 10.0.0.2",
    "ipv6.dst > fe80::",
    // Flags and masks.
    "ip.flags == 0x2",
    "ip.flags == 0x1",
    "ip.flags == 0x4",
    "ip.flags.df == 1",
    "ip.flags.mf == 1",
    "ip.flags.rb == 1",
    "ip.flags.df == 0",
    "ip.frag_offset == 0",
    "ip.frag_offset == 3",
    "ip.frag_offset == 24",
    "ipv6.fraghdr.offset == 5",
    "ipv6.fraghdr.offset == 40",
    "ipv6.fraghdr.more == 1",
    "ipv6.fraghdr.ident == 0xcafef00d",
    "ip.version == 6",
    "ip.version == 4 and ipv6",
    "tcp.flags.syn",
    "tcp.flags.syn == 1",
    "tcp.flags.syn == 0",
    "tcp.flags.syn == True",
    "tcp.flags.ack == false",
    "tcp.flags == 0x002",
    "tcp.flags == 0x1ff",
    "tcp.flags & 0x12 == 0x12",
    "tcp.flags & 0x02",
    "tcp.flags.res == 1",
    "tcp.flags.res",
    "tcp.flags.ae == 1",
    "tcp.flags.cwr == 1 and tcp.flags.ece == 1 and tcp.flags.urg == 1",
    "tcp.flags.push == 1 and tcp.flags.reset == 1 and tcp.flags.fin == 1",
    "ip.dsfield == 0xb9",
    "ip.dsfield.dscp == 46",
    "ip.dsfield.ecn == 1",
    "ip.hdr_len == 24",
    "ip.len == 40",
    "ip.ttl == 64 and ip.id == 0x1234",
    "ip.version == 4",
    "ip.proto == 6",
    "ip.checksum == 0",
    "ipv6.version == 6 and ipv6.hlim == 64",
    "ipv6.nxt == 0",
    "ipv6.nxt == 44",
    "ipv6.plen == 9",
    "ipv6.tclass == 0 and ipv6.flow == 0",
    "ipv6.tclass.dscp == 0 and ipv6.tclass.ecn == 0",
    // Lengths and payloads.
    "tcp.len == 0",
    "tcp.len == 5",
    "tcp.len > 0",
    "tcp.hdr_len == 24",
    "udp.length == 9",
    "udp.length == 8",
    "len(tcp.payload) == 16",
    "len(udp.payload) == 4",
    "frame.len == 64",
    "frame.cap_len == 54",
    // Protocol extents and slices.
    "len(eth) == 14",
    "len(vlan) == 4",
    "len(ip) == 20",
    "len(ip) == 24",
    "len(ipv6) == 40",
    "len(ipv6) == 48",
    "len(tcp) == 20",
    "len(tcp) == 24",
    "len(udp) == 8",
    "len(icmp) == 12",
    "len(icmp) == 8",
    "len(icmpv6) == 12",
    "len(arp) == 28",
    "len(frame) == 54",
    "tcp[0:2] == c7:38",
    "tcp[13] == 02",
    "tcp[13] == 2",
    "tcp[13] == 18",
    "tcp[13] == 24",
    "tcp[13] == 18:",
    "tcp[13] == 0x18",
    "ipv6[6] == 11",
    "ipv6[6] == 17",
    "ipv6[6] == 0b10001",
    "udp.payload == 120",
    "udp.payload == 78",
    "udp.payload == 78:",
    "tcp contains 50:",
    "ip[9] > 16",
    "tcp[-2:] == 00:00",
    "udp[0:2] == 14:e9",
    "udp[4:2] == 00:0c",
    "icmp[0] == 08",
    "icmp[8:4] == \"ping\"",
    "icmpv6[0] == 80",
    "ip[9] == 06",
    "ip[-4:] == c0:a8:01:02",
    "ipv6[6] == 11",
    "eth[12:2] == 81:00",
    "eth[-2:] == 08:00",
    "vlan[0:2] == 00:64",
    "arp[7] == 01",
    "frame[12:2] == 81:00",
    "frame[-1] == 00",
    "eth.src[0:3] == 00:11:22",
    "eth.src[3-5] == 33:44:55",
    "eth.dst[-1] == bb",
    "ip.src[0] == 0a",
    "ipv6.src[0:2] == fe:80",
    "tcp.payload[0:3] == \"GET\"",
    "tcp.payload[0] == 'G'",
    "tcp.payload[100:2]",
    "udp.payload[2:2] == 01:00",
    "tcp.payload contains \"HTTP/1.1\"",
    "tcp contains 00:50",
    "frame contains \"ping\"",
    "udp.payload contains 61:62",
    "count(vlan.id) == 2",
    "count(ip.addr) == 2",
    "count(tcp.port) == 2",
    // Ethernet and VLAN.
    "eth.type == 0x8100",
    "eth.type == 0x800",
    "eth.type == 0x88a8",
    "eth.type == 0x86dd",
    "eth.type == 0x88cc",
    "vlan.etype == 0x800",
    "vlan.etype == 0x8100",
    "vlan.id == 7 and vlan.id == 4095",
    "vlan.id == 100",
    "vlan.dei == 1",
    "vlan.priority == 0",
    "vlan.priority == 7",
    "vlan.id == 3 and vlan.id == 4",
    "vlan.id == 5",
    "count(vlan) == 2",
    "len(vlan) == 4",
    "ieee8021ad",
    "ieee8021ad.id == 7",
    "ieee8021ad.dei == 0 and ieee8021ad.priority == 0",
    "len(ieee8021ad) == 4",
    "ieee8021ad[2:2] == 81:00",
    "count(eth.type) == 1",
    // ARP.
    "arp.opcode == 1",
    "arp.hw.type == 1 and arp.proto.type == 0x0800",
    "arp.hw.size == 6 and arp.proto.size == 4",
    "arp.src.hw_mac == 00:11:22:33:44:55",
    "arp.dst.hw_mac == 00:00:00:00:00:00",
    "arp.src.proto_ipv4 == 10.0.0.1 and arp.dst.proto_ipv4 == 10.0.0.2",
    // ICMP.
    "icmp.type == 8",
    "icmp.type == 13",
    "icmp.ident == 7",
    "icmp.seq == 9",
    "icmp.ident == 3 and icmp.seq == 4",
    "icmp.code == 0",
    "icmp.checksum == 0",
    "icmpv6.type == 128",
    "icmpv6.code == 0 and icmpv6.checksum == 0",
    "icmpv6.echo.identifier == 0x77",
    "icmpv6.echo.sequence_number == 3",
    // TCP and UDP header fields.
    "tcp.srcport == 51000 and tcp.dstport == 443",
    "tcp.seq_raw == 1 and tcp.ack_raw == 2",
    "tcp.window_size_value == 4096",
    "tcp.checksum == 0",
    "tcp.urgent_pointer == 0",
    "udp.srcport == 5353 and udp.dstport == 53",
    "udp.checksum == 0",
    // Field against field, and functions on absent fields.
    "tcp.srcport == tcp.dstport",
    "tcp.srcport < tcp.dstport",
    "udp.srcport != udp.dstport",
    "ip.src == ip.dst",
    "eth.src != eth.dst",
    "count(tcp.port) == 0",
    "len(tcp.payload) == 0",
    "len(udp.payload) >= 1",
    // Symbolic constants that Wireshark also knows (from its value strings).
    "eth.type == ipv4",
    "arp.opcode == request",
];

/// Filters that read only headers both sides parse, so they must agree on the [`SKIP`] frames
/// too.
const OUTER: &[&str] = &[
    "icmp",
    "icmp.type == 3 and icmp.code == 3",
    "icmp.ident",
    "icmp.seq",
    "len(icmp) == 36",
    "icmp[8] == 45",
    "icmp contains 00:01:00:02",
    "eth.type == 0x800",
    "frame.len == 24",
    "eth",
];

/// Where Avulse knowingly differs from Wireshark: `(filter, frames only tshark selects, frames
/// only Avulse selects)`.
const DIVERGENCES: &[(&str, &[&str], &[&str])] = &[
    // The IPv4/UDP datagram quoted by an ICMP error: Wireshark dissects it, Avulse does not.
    ("udp.port == 2", &["unreachable"], &[]),
    ("udp and icmp", &["unreachable"], &[]),
    ("count(ip.addr) == 4", &["unreachable"], &[]),
    ("ip#2", &["unreachable"], &[]),
    ("udp.port#[-1] == 2", &["unreachable"], &[]),
    // A header cut short: tshark keeps the fields that fit, Avulse drops the header.
    ("ip", &["trunc_ip"], &[]),
    ("ip.ttl == 64 and ip.proto == 6", &["trunc_ip"], &[]),
    ("tcp.srcport == 51000", &["trunc_tcp"], &[]),
    ("len(ipv6) == 40", &[], &["trunc_v6_ext"]),
    // Wireshark converts a negative operand to the field's unsigned type; Avulse stays signed.
    ("tcp.srcport + -1 == 50999", &[], &["syn", "http_vlan"]),
];

/// Filters tshark accepts but Avulse rejects on purpose, because the literal cannot fit the field
/// and the test could never be true.
const STRICTER: &[&str] = &[
    "ip.flags == 8",
    "ip.dsfield.ecn == 4",
    "vlan.priority == 8",
    // A label of several values (or of another `vlan.priority` table): Wireshark compares the
    // displayed text instead of the number. None of these match the corpus.
    "ip.proto == \"Unassigned\"",
    "icmp.type == \"Reserved\"",
    "vlan.priority == \"Spare\"",
];

/// `matches` (with the `regex` feature): case-insensitive, over bytes, as in Wireshark.
#[cfg(feature = "regex")]
const MATCHES: &[&str] = &[
    "tcp.payload matches \"get\"",
    "tcp.payload matches \"(?-i)get\"",
    "tcp.payload ~ \"^GET /\"",
    "tcp.payload matches \"^get$\"",
    "tcp.payload matches \"HTTP/1\\\\.1\\r\\n$\"",
    "tcp.payload matches \"(?m)1$\"",
    "tcp.payload matches \"1.\\n?$\"",
    "tcp.payload matches \"(?s)1..$\"",
    "udp.payload matches \"\\x12\\x34\"",
    "udp.payload matches \"\\\\x12\\\\x34\"",
    "udp.payload matches \"[\\\\x80-\\\\xff]\"",
    "udp.payload matches \"^\\\\w{3,4}$\"",
    "udp.payload matches \"[a-z]\"",
    "frame matches \"GET\"",
    "udp matches \"\\\\x00\\\\x35\"",
    "eth.src matches \"\\\\x00\\\\x11\"",
    "all eth.addr matches \"\\\\x00\"",
    "all tcp.payload matches \"T\"",
    "tcp.payload[0:3] matches \"get\"",
    "upper(frame.interface_name) matches \"ETH\"",
];

/// Like [`DIVERGENCES`], for `matches`: PCRE2's `$` also matches before a final newline.
#[cfg(feature = "regex")]
const REGEX_DIVERGENCES: &[(&str, &[&str], &[&str])] =
    &[("tcp.payload matches \"1.$\"", &["http_vlan"], &[])];

#[cfg(not(feature = "regex"))]
const REGEX_DIVERGENCES: &[(&str, &[&str], &[&str])] = &[];

/// Filters tshark accepts and Avulse rejects: PCRE2 syntax that Rust's regex engine lacks.
#[cfg(feature = "regex")]
const PCRE_ONLY: &[&str] = &[
    "tcp.payload matches \"(G)\\\\1\"",
    "tcp.payload matches \"G(?=E)\"",
    "tcp.payload matches \"(?<!x)GET\"",
];

/// Avulse extensions that tshark rejects. They never change what a valid Wireshark filter means.
const EXTENSIONS: &[&str] = &[
    "tcp.port in {80 443}",
    "ip.addr ~= 10.0.0.1",
    "tcp // comment",
    "/* comment */ tcp",
    "# comment\ntcp",
    "let web = {80, 443}\ntcp.port in $web",
    "outbound or not loopback",
    // Wireshark checks a literal against the type of the field in the arithmetic, although the
    // result is signed and unbounded; Avulse only needs it to fit 64 bits.
    "tcp.srcport + 1 == 65536",
    // Symbolic constants Wireshark does not know. In Wireshark `tcp` here is the protocol field,
    // so `ip.proto == tcp` is a type error there.
    "ip.proto == tcp",
    "icmp.type == echo-request",
    "tcp.flags & syn",
    "tcp.flags == syn",
];

fn enabled() -> Option<String> {
    if env::var_os("AVULSE_TSHARK").is_none_or(|v| v != "1") {
        println!("skipped: set AVULSE_TSHARK=1 to compare with tshark");
        return None;
    }
    let out = Command::new("tshark")
        .arg("--version")
        .output()
        .expect("AVULSE_TSHARK=1 but tshark cannot be run");
    let version = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    // Wireshark 4.6 changed how `tcp[13] == 18` reads, among others; older versions disagree.
    let minor = version
        .strip_prefix("TShark (Wireshark) 4.")
        .and_then(|v| v.split('.').next())
        .and_then(|m| m.parse::<u32>().ok());
    assert!(
        minor.is_some_and(|m| m >= 6),
        "need tshark 4.6 or later, found {version:?}"
    );
    println!("comparing with {version}");
    Some(version)
}

/// Dissectors that would claim the corpus payloads by port or by heuristics.
const APP_PROTOCOLS: &[&str] = &["dns", "mdns", "http", "dhcpv6", "echo", "lldp"];

/// Frame numbers (1-based) that tshark selects, or its error message.
fn tshark(capture: &[u8], filter: &str) -> Result<Vec<usize>, String> {
    let out = run_tshark(
        capture,
        &["-Y", filter, "-T", "fields", "-e", "frame.number"],
    )?;
    Ok(out
        .lines()
        .map(|l| l.trim().parse().expect("frame number"))
        .collect())
}

/// Runs tshark over the capture with reassembly and application dissectors off; its standard
/// output, or its error message.
fn run_tshark(capture: &[u8], args: &[&str]) -> Result<String, String> {
    let mut child = Command::new("tshark")
        .args(["-r", "-", "-n"])
        .args(["-o", "ip.defragment:FALSE"])
        .args(["-o", "ipv6.defragment:FALSE"])
        .args(["-o", "tcp.desegment_tcp_streams:FALSE"])
        .args(APP_PROTOCOLS.iter().flat_map(|p| ["--disable-protocol", p]))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tshark");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(capture)
        .expect("write the capture to tshark");
    let out = child.wait_with_output().expect("wait for tshark");
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `(name, pos, size)` of every field and protocol tshark dissects, frame by frame, from its
/// PDML output.
fn pdml_fields(capture: &[u8]) -> Vec<Vec<(String, usize, usize)>> {
    let attr = |line: &str, key: &str| -> Option<String> {
        let start = line.find(&format!(" {key}=\""))? + key.len() + 3;
        let end = line[start..].find('"')? + start;
        Some(line[start..end].to_string())
    };
    let out = run_tshark(capture, &["-T", "pdml"]).expect("tshark -T pdml");
    let mut frames = Vec::new();
    for line in out.lines().map(str::trim) {
        if line.starts_with("<packet>") {
            frames.push(Vec::new());
        } else if (line.starts_with("<field ") || line.starts_with("<proto "))
            && let (Some(name), Some(pos), Some(size), Some(frame)) = (
                attr(line, "name"),
                attr(line, "pos"),
                attr(line, "size"),
                frames.last_mut(),
            )
        {
            frame.push((name, pos.parse().expect("pos"), size.parse().expect("size")));
        }
    }
    frames
}

fn avulse(frames: &Corpus, link: Link, filter: &str) -> Result<Vec<usize>, String> {
    let f = Filter::compile(filter).map_err(|e| e.render(filter))?;
    Ok(frames
        .iter()
        .enumerate()
        .filter(|(_, (_, bytes))| f.matches(&Packet::parse(bytes, link), &Meta::default()))
        .map(|(i, _)| i + 1)
        .collect())
}

/// Frame names, in corpus order.
fn names(frames: &Corpus, numbers: &[usize]) -> Vec<&'static str> {
    numbers.iter().map(|&n| frames[n - 1].0).collect()
}

struct Capture {
    link: Link,
    frames: Corpus,
    pcap: Vec<u8>,
}

fn captures() -> Vec<Capture> {
    let eth_frames = corpus();
    let raw_frames = raw_corpus(&eth_frames);
    [
        (Link::Ethernet, pcap::LINKTYPE_ETHERNET, eth_frames),
        (Link::Ip, pcap::LINKTYPE_RAW, raw_frames),
    ]
    .into_iter()
    .map(|(link, linktype, frames)| Capture {
        link,
        pcap: pcap::write(linktype, frames.iter().map(|(_, f)| f.as_slice())),
        frames,
    })
    .collect()
}

/// Runs `check` over every filter on a few threads (one tshark process per filter and capture),
/// and fails with every message it returns.
fn run<T: Sync>(items: &[T], check: impl Fn(&T) -> Vec<String> + Sync) {
    let workers = thread::available_parallelism().map_or(4, |n| n.get());
    let chunk = items.len().div_ceil(workers).max(1);
    let failures: Vec<String> = thread::scope(|s| {
        let handles: Vec<_> = items
            .chunks(chunk)
            .map(|c| s.spawn(|| c.iter().flat_map(&check).collect::<Vec<_>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("worker panicked"))
            .collect()
    });
    assert!(
        failures.is_empty(),
        "{} disagreement(s) with tshark:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

/// Compares one filter on every capture, ignoring the frames named in `skip`.
fn compare(caps: &[Capture], filter: &str, skip: &[&str]) -> Vec<String> {
    let mut failures = Vec::new();
    for cap in caps {
        let keep = |v: Vec<usize>| -> Vec<&str> {
            names(&cap.frames, &v)
                .into_iter()
                .filter(|n| !skip.contains(n))
                .collect()
        };
        match (
            tshark(&cap.pcap, filter),
            avulse(&cap.frames, cap.link, filter),
        ) {
            (Ok(t), Ok(a)) => {
                let (t, a) = (keep(t), keep(a));
                if t != a {
                    failures.push(format!(
                        "{filter:?} on {:?}:\n  tshark: {t:?}\n  avulse: {a:?}",
                        cap.link
                    ));
                }
            }
            (Err(e), _) => failures.push(format!("tshark rejects {filter:?}: {e}")),
            (_, Err(e)) => failures.push(format!("avulse rejects {filter:?}:\n{e}")),
        }
    }
    failures
}

/// `field == "label"` for the first, middle and last unambiguous label of every field that has
/// labels, which checks that `labels.rs` was generated from the right tables.
///
/// `labels.rs` merges several Wireshark versions, so with `known` (the `(field, label)` pairs of
/// the tshark at hand, from [`tshark_labels`]) only labels that this tshark has are picked.
fn label_filters(known: Option<&BTreeSet<(String, String)>>) -> Vec<String> {
    let mut out = Vec::new();
    for d in FIELDS {
        let table = crate::labels::labels(d.field);
        let unique: Vec<&str> = table
            .iter()
            .filter(|(l, v)| {
                table
                    .iter()
                    .all(|(m, w)| !m.eq_ignore_ascii_case(l) || w == v)
            })
            .map(|(l, _)| *l)
            .filter(|l| known.is_none_or(|k| k.contains(&(d.name.to_string(), l.to_string()))))
            .collect();
        let mut picks = [0, unique.len() / 2, unique.len().saturating_sub(1)]
            .into_iter()
            .filter_map(|i| unique.get(i))
            .collect::<Vec<_>>();
        picks.dedup();
        for l in picks {
            out.push(format!("{} == \"{}\"", d.name, l.replace('"', "\\\"")));
        }
    }
    out
}

/// The `(field, label)` pairs of the tshark at hand, from `tshark -G values`.
fn tshark_labels() -> BTreeSet<(String, String)> {
    let out = Command::new("tshark")
        .args(["-G", "values"])
        .output()
        .expect("tshark -G values");
    let mut known = BTreeSet::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        match cols.as_slice() {
            ["V" | "V64", field, _, label] => {
                known.insert((field.to_string(), label.to_string()));
            }
            ["T", field, yes, no] => {
                known.insert((field.to_string(), yes.to_string()));
                known.insert((field.to_string(), no.to_string()));
            }
            _ => {}
        }
    }
    known
}

/// A bare presence test for every Wireshark field, so that new fields are covered too.
fn presence_filters() -> Vec<&'static str> {
    FIELDS
        .iter()
        .filter(|d| d.origin == Origin::Wireshark && d.name != "frame.interface_name")
        .map(|d| d.name)
        .collect()
}

/// `filter fmt` must print every table filter in a form that compiles to the same IR, and
/// printing it again must not change it. This needs no tshark.
#[test]
fn fmt_round_trips() {
    let mut filters: Vec<String> = AGREE.iter().chain(OUTER).map(|f| f.to_string()).collect();
    filters.extend(label_filters(None));
    #[cfg(feature = "regex")]
    filters.extend(MATCHES.iter().map(|f| f.to_string()));
    let mut failures = Vec::new();
    for f in &filters {
        let printed = format!("{}", crate::parse(f).expect("table filters parse"));
        let again = crate::parse(&printed).map(|p| format!("{p}"));
        let same_ir = Filter::compile(&printed).map(|c| c.ir().clone()).ok()
            == Filter::compile(f).map(|c| c.ir().clone()).ok();
        if again.as_deref() != Ok(printed.as_str()) || !same_ir {
            failures.push(format!(
                "{f:?} prints as {printed:?}, which reprints as {again:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn tshark_agrees() {
    if enabled().is_none() {
        return;
    }
    let caps = captures();
    let mut filters = presence_filters();
    filters.extend_from_slice(AGREE);
    run(&filters, |f| compare(&caps, f, SKIP));
    let labels = label_filters(Some(&tshark_labels()));
    run(&labels, |f| compare(&caps, f, SKIP));
    #[cfg(feature = "regex")]
    run(MATCHES, |f| compare(&caps, f, SKIP));
    run(OUTER, |f| compare(&caps, f, &[]));
}

#[cfg(feature = "regex")]
#[test]
fn tshark_has_pcre() {
    if enabled().is_none() {
        return;
    }
    let caps = captures();
    run(PCRE_ONLY, |&filter| {
        let mut failures = Vec::new();
        if let Err(e) = tshark(&caps[0].pcap, filter) {
            failures.push(format!("tshark rejects {filter:?}: {e}"));
        }
        if Filter::compile(filter).is_ok() {
            failures.push(format!("avulse accepts {filter:?}"));
        }
        failures
    });
}

/// `@field` reads the bytes Wireshark says a field covers: compare `raw_spans` with the positions
/// and sizes in tshark's PDML output, for every field of every frame.
#[test]
fn tshark_raw_spans() {
    if enabled().is_none() {
        return;
    }
    let mut failures = Vec::new();
    for cap in captures() {
        let dissected = pdml_fields(&cap.pcap);
        for (i, (frame, bytes)) in cap.frames.iter().enumerate() {
            if SKIP.contains(frame) {
                continue;
            }
            let pkt = Packet::parse(bytes, cap.link);
            for d in FIELDS.iter().filter(|d| d.origin == Origin::Wireshark) {
                if d.name == "frame.interface_name" {
                    continue;
                }
                let mut want: Vec<(usize, usize)> = dissected[i]
                    .iter()
                    .filter(|(n, ..)| n == d.name)
                    .map(|&(_, pos, size)| (pos, size))
                    .collect();
                let mut got: Vec<(usize, usize)> =
                    crate::eval::raw_spans(d.field, &pkt, &Meta::default())
                        .as_slice()
                        .iter()
                        .map(|&(_, start, len)| (start, len))
                        .collect();
                want.sort();
                got.sort();
                if want != got {
                    failures.push(format!(
                        "@{} in {frame} ({:?}): tshark {want:?}, avulse {got:?}",
                        d.name, cap.link
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} raw span(s) differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn tshark_divergences() {
    if enabled().is_none() {
        return;
    }
    let caps = captures();
    let eth = &caps[0];
    let rows: Vec<_> = DIVERGENCES
        .iter()
        .chain(REGEX_DIVERGENCES)
        .copied()
        .collect();
    run(&rows, |&(filter, want_t, want_a)| {
        let (t, a) = match (
            tshark(&eth.pcap, filter),
            avulse(&eth.frames, eth.link, filter),
        ) {
            (Ok(t), Ok(a)) => (t, a),
            (t, a) => return vec![format!("{filter:?}: tshark {t:?}, avulse {a:?}")],
        };
        let only = |x: &[usize], y: &[usize]| {
            let v: Vec<usize> = x.iter().copied().filter(|n| !y.contains(n)).collect();
            names(&eth.frames, &v)
        };
        let (only_t, only_a) = (only(&t, &a), only(&a, &t));
        if (only_t.as_slice(), only_a.as_slice()) == (want_t, want_a) {
            Vec::new()
        } else {
            vec![format!(
                "{filter:?}: expected only-tshark {want_t:?} and only-avulse {want_a:?}\n  \
                 only tshark: {only_t:?}\n  only avulse: {only_a:?}"
            )]
        }
    });
}

#[test]
fn tshark_rejects_extensions() {
    if enabled().is_none() {
        return;
    }
    let caps = captures();
    run(EXTENSIONS, |&filter| {
        let mut failures = Vec::new();
        if tshark(&caps[0].pcap, filter).is_ok() {
            failures.push(format!(
                "tshark accepts {filter:?}: move it to AGREE and drop it from EXTENSIONS"
            ));
        }
        if let Err(e) = Filter::compile(filter) {
            failures.push(format!("avulse rejects {filter:?}:\n{}", e.render(filter)));
        }
        failures
    });
}

#[test]
fn tshark_is_less_strict() {
    if enabled().is_none() {
        return;
    }
    let caps = captures();
    run(STRICTER, |&filter| {
        let mut failures = Vec::new();
        match tshark(&caps[0].pcap, filter) {
            Ok(v) if v.is_empty() => {}
            other => failures.push(format!("tshark on {filter:?}: {other:?}")),
        }
        if Filter::compile(filter).is_ok() {
            failures.push(format!("avulse accepts {filter:?}"));
        }
        failures
    });
}
