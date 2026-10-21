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

pub(super) type Corpus = Vec<(&'static str, Vec<u8>)>;

/// Ethernet frames covering every header the parser knows, plus truncations.
pub(super) fn corpus() -> Corpus {
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
        // An atomic fragment (RFC 6946): a whole datagram, so `tcp.len` is set.
        (
            "v6_atomic_tcp",
            v6(
                ipp::IPV6_FRAG,
                &ipv6_frag(ipp::TCP, 0, false, &tcp(1000, 80, Tcp::ACK, b"abc")),
            ),
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
        // TCP options: a typical SYN, and the edge cases of Wireshark's option walk.
        (
            "syn_opts",
            v4(
                ipp::TCP,
                &tcp_with(
                    41000,
                    443,
                    Tcp::SYN,
                    &[
                        2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 1, 3, 3, 7,
                    ],
                    b"",
                ),
            ),
        ),
        (
            "opt_odd",
            v4(
                ipp::TCP,
                // MSS of length 3, then a NOP, then an unknown kind, then window scale 15.
                &tcp_with(1, 2, Tcp::ACK, &[2, 3, 5, 1, 99, 4, 1, 2, 3, 3, 15, 0], b""),
            ),
        ),
        (
            "opt_overflow",
            v4(ipp::TCP, &tcp_with(1, 2, Tcp::ACK, &[1, 3, 10, 7], b"")),
        ),
        (
            "opt_after_eol",
            v4(
                ipp::TCP,
                &tcp_with(1, 2, Tcp::ACK, &[1, 0, 0, 0, 2, 4, 5, 0xb4], b""),
            ),
        ),
        (
            "dup_mss",
            v4(
                ipp::TCP,
                &tcp_with(1, 2, Tcp::SYN, &[2, 4, 0x05, 0xb4, 2, 4, 0x02, 0x18], b""),
            ),
        ),
        ("trunc_ip", truncated(https_syn(), 14 + 10)),
        ("trunc_tcp", truncated(https_syn(), 14 + 20 + 10)),
        ("trunc_v6_ext", truncated(hbh_tcp, 14 + 40 + 4)),
    ]
}

/// The untagged IP frames of the corpus without their Ethernet header.
pub(super) fn raw_corpus(eth_corpus: &Corpus) -> Corpus {
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
/// - `dup_mss`: two MSS options. tshark reads both; Avulse reads the first option of each kind.
pub(super) use super::filters::{AGREE, EXTENSIONS, OUTER};

const SKIP: &[&str] = &[
    "unreachable",
    "trunc_ip",
    "trunc_tcp",
    "trunc_v6_ext",
    "dup_mss",
];

/// Where Avulse knowingly differs from Wireshark: `(filter, frames only tshark selects, frames
/// only Avulse selects)`.
pub(super) const DIVERGENCES: &[(&str, &[&str], &[&str])] = &[
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
    // Two MSS options: tshark reads both, Avulse the first.
    ("tcp.options.mss_val == 536", &["dup_mss"], &[]),
    ("count(tcp.options.mss_val) == 2", &["dup_mss"], &[]),
    ("all tcp.options.mss_val == 1460", &[], &["dup_mss"]),
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

/// Filters tshark accepts but Avulse rejects, because the result could exceed the evaluator's
/// fixed buffers (no allocation, for the kernels): [`value::MAX`] occurrences and [`value::OWNED`]
/// computed bytes.
///
/// [`value::MAX`]: crate::value::MAX
/// [`value::OWNED`]: crate::value::OWNED
const LIMITS: &[&str] = &[
    "tcp.port + tcp.port + tcp.port == 6",
    "tcp.port & tcp.port & tcp.port == 0",
    "tcp.payload[0:1,1:] contains \"GET\"",
    "len(udp.payload[0:2,1:]) == 5",
    "tcp.payload & tcp.payload == tcp.payload",
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
    // An escaped byte that is not UTF-8 is that byte.
    "frame matches \"\\\\\\xff\"",
    "frame matches \"\\\\\\xff\\\\\\xff\\\\\\xff\"",
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
pub(super) fn presence_filters() -> Vec<&'static str> {
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
                    crate::value::raw_spans(d.field, &pkt, &Meta::default())
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
fn tshark_exceeds_the_evaluator() {
    if enabled().is_none() {
        return;
    }
    let caps = captures();
    run(LIMITS, |&filter| {
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
