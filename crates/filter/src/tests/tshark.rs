//! Differential test against Wireshark: every filter must select the same frames in `tshark` and
//! in Avulse. It runs only with `AVULSE_TSHARK=1`, since it needs `tshark` 4.6 or later on the
//! `PATH`:
//!
//! ```text
//! AVULSE_TSHARK=1 cargo test -p avulse-filter tshark -- --nocapture
//! ```

extern crate std;

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
    // A header cut short: tshark keeps the fields that fit, Avulse drops the header.
    ("ip", &["trunc_ip"], &[]),
    ("ip.ttl == 64 and ip.proto == 6", &["trunc_ip"], &[]),
    ("tcp.srcport == 51000", &["trunc_tcp"], &[]),
    ("len(ipv6) == 40", &[], &["trunc_v6_ext"]),
];

/// Filters tshark accepts but Avulse rejects on purpose, because the literal cannot fit the field
/// and the test could never be true.
const STRICTER: &[&str] = &["ip.flags == 8", "ip.dsfield.ecn == 4", "vlan.priority == 8"];

/// Avulse extensions that tshark rejects. They never change what a valid Wireshark filter means.
const EXTENSIONS: &[&str] = &[
    "tcp.port in {80 443}",
    "ip.addr ~= 10.0.0.1",
    "tcp // comment",
    "/* comment */ tcp",
    "# comment\ntcp",
    "let web = {80, 443}\ntcp.port in $web",
    "outbound or not loopback",
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
    let mut child = Command::new("tshark")
        .args(["-r", "-", "-n"])
        .args(["-o", "ip.defragment:FALSE"])
        .args(["-o", "ipv6.defragment:FALSE"])
        .args(["-o", "tcp.desegment_tcp_streams:FALSE"])
        .args(APP_PROTOCOLS.iter().flat_map(|p| ["--disable-protocol", p]))
        .args(["-Y", filter, "-T", "fields", "-e", "frame.number"])
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
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().parse().expect("frame number"))
        .collect())
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

/// A bare presence test for every Wireshark field, so that new fields are covered too.
fn presence_filters() -> Vec<&'static str> {
    FIELDS
        .iter()
        .filter(|d| d.origin == Origin::Wireshark && d.name != "frame.interface_name")
        .map(|d| d.name)
        .collect()
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
    run(OUTER, |f| compare(&caps, f, &[]));
}

#[test]
fn tshark_divergences() {
    if enabled().is_none() {
        return;
    }
    let caps = captures();
    let eth = &caps[0];
    run(DIVERGENCES, |&(filter, want_t, want_a)| {
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
