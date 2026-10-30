//! How fast the filter engine runs here: the IR evaluator (`Filter::matches`) and the bytecode
//! interpreter (`VerifiedProgram::matches`, what a system extension or a driver runs), in ns per
//! packet over a small mixed corpus.

use std::hint::black_box;
use std::time::Instant;

use avulse_filter::bytecode::verify;
use avulse_filter::{Filter, Layer, Meta};
use avulse_proto::{Link, Packet};
use avulse_spike_macos::{eth, finish, icmp_echo, ipv4, ipv6, tcp, udp};

use crate::report::Report;

const MAC_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0xa];
const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0xb];
const V6_A: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const V6_MC: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// IP packets: a mix of TCP (SYN with options, HTTP request, bulk), UDP (DNS, QUIC), ICMP and
/// IPv6.
fn corpus() -> Vec<Vec<u8>> {
    let mss = [2, 4, 0x05, 0xb4, 4, 2, 1, 3, 3, 7];
    let bulk = vec![0x5a; 1400];
    [
        ipv4(
            [10, 0, 0, 1],
            [93, 184, 216, 34],
            6,
            &tcp(51000, 443, 0x02, &mss, &[]),
        ),
        ipv4(
            [10, 0, 0, 1],
            [93, 184, 216, 34],
            6,
            &tcp(51001, 80, 0x18, &[], b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        ),
        ipv4(
            [93, 184, 216, 34],
            [10, 0, 0, 1],
            6,
            &tcp(443, 51000, 0x10, &[], &bulk),
        ),
        ipv4(
            [10, 0, 0, 1],
            [8, 8, 8, 8],
            17,
            &udp(53000, 53, &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
        ),
        ipv4(
            [192, 168, 1, 7],
            [142, 250, 1, 1],
            17,
            &udp(60000, 443, &bulk[..1200]),
        ),
        ipv4([10, 0, 0, 1], [10, 0, 0, 2], 1, &icmp_echo(7, 1, &[0; 56])),
        ipv6(V6_A, V6_MC, 17, &udp(546, 547, &[1, 2, 3, 4])),
        ipv6(V6_A, V6_A, 6, &tcp(40000, 22, 0x02, &mss, &[])),
    ]
    .into_iter()
    .map(|p| finish(p, Link::Ip))
    .collect()
}

fn time(iters: u32, mut f: impl FnMut() -> usize) -> (f64, usize) {
    let mut hits = 0;
    let start = Instant::now();
    for _ in 0..iters {
        hits += f();
    }
    (start.elapsed().as_nanos() as f64 / f64::from(iters), hits)
}

pub fn run(r: &mut Report) {
    let ip = corpus();
    let frames: Vec<Vec<u8>> = ip
        .iter()
        .map(|p| {
            let et = if p[0] >> 4 == 6 { 0x86dd } else { 0x0800 };
            eth(MAC_B, MAC_A, et, p)
        })
        .collect();
    let set = (1000..1050)
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let native = [
        "tcp.port == 443".to_string(),
        "ip.src in {10.0.0.0/8 192.168.0.0/16} and tcp.flags.syn == 1".into(),
        format!("udp.dstport in {{53 {set}}}"),
        "tcp.payload contains \"GET \"".into(),
        "ipv6.dst == ff02::1 or (tcp.options.mss_val < 1400 and tcp.dstport != 22)".into(),
        "eth.type == 0x0800 and not icmp and len(frame) > 100".into(),
    ];
    let windivert = "outbound and tcp.DstPort == 80 and ip.DstAddr >= 93.0.0.0 and ip.DstAddr <= 93.255.255.255";
    let iters: u32 = std::env::var("AVULSE_BENCH_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(400_000);
    let meta = Meta {
        outbound: true,
        ..Meta::default()
    };
    let mut cases: Vec<(String, Filter, &Vec<Vec<u8>>, Link)> = native
        .iter()
        .map(|s| {
            (
                s.clone(),
                Filter::compile(s).expect(s),
                &frames,
                Link::Ethernet,
            )
        })
        .collect();
    let wd = Filter::compile_windivert(windivert, Layer::Network).expect("windivert filter");
    cases.push((format!("windivert: {windivert}"), wd, &ip, Link::Ip));

    for (src, filter, packets, link) in &cases {
        let parsed: Vec<Packet<'_>> = packets.iter().map(|p| Packet::parse(p, *link)).collect();
        let bytes = filter.program().expect("bytecode").to_bytes();
        let program = verify(&bytes).expect("verified");
        let n = parsed.len();
        let mut i = 0;
        let (ir_ns, ir_hits) = time(iters, || {
            i = (i + 1) % n;
            usize::from(filter.matches(black_box(&parsed[i]), &meta))
        });
        let mut i = 0;
        let (bc_ns, bc_hits) = time(iters, || {
            i = (i + 1) % n;
            usize::from(program.matches(black_box(&parsed[i]), &meta))
        });
        let mut i = 0;
        let (parse_ns, _) = time(iters, || {
            i = (i + 1) % n;
            let p = Packet::parse(black_box(&packets[i]), *link);
            usize::from(p.tcp().is_some())
        });
        r.check(
            src,
            ir_hits == bc_hits && ir_hits > 0 && ir_hits < iters as usize,
            format!(
                "parse {parse_ns:.1} ns, eval {ir_ns:.1} ns, bytecode {bc_ns:.1} ns per packet; \
                 {} bytes of bytecode; {ir_hits}/{iters} matched",
                bytes.len()
            ),
        );
        r.num(&format!("{src} | bytecode_ns"), bc_ns);
    }
}
