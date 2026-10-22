//! What the host and kernel tests share: a corpus of frames, the filters, metadata variants,
//! and a random filter generator.

#![allow(dead_code)]

pub mod emu;

use avulse_ebpf::codegen::Env;
use avulse_ebpf::facts::{M_IMPOSTOR, M_LOOPBACK, M_OUTBOUND};
use avulse_filter::{Layer, Meta};

/// The interfaces the tests name: index and name.
pub const IFACES: &[(u32, &str)] = &[(1, "lo"), (2, "eth0"), (3, "veth3"), (7, "wlan0")];

pub fn ifindex(name: &str) -> Option<u32> {
    IFACES.iter().find(|(_, n)| *n == name).map(|(i, _)| *i)
}

/// What the generator knows of a test handle at `layer`.
pub fn env(layer: Layer) -> Env<'static> {
    Env {
        layer,
        priority: 0,
        ifindex: &ifindex,
        event: None,
    }
}

/// The metadata of the `i`th frame of a run: `M_*` bits and interface index.
pub fn variant(i: usize) -> (u8, u32) {
    [
        (0, 2),
        (M_OUTBOUND, 2),
        (M_OUTBOUND | M_LOOPBACK, 1),
        (M_IMPOSTOR, 3),
        (M_OUTBOUND | M_IMPOSTOR, 7),
    ][i % 5]
}

/// The metadata user space gives the filter for those facts.
pub fn meta(layer: Layer, bits: u8, ifindex: u32) -> Meta<'static> {
    Meta {
        layer,
        outbound: bits & M_OUTBOUND != 0,
        loopback: bits & M_LOOPBACK != 0,
        impostor: bits & M_IMPOSTOR != 0,
        ifidx: ifindex,
        // The backend names every interface, with "" when the name is unknown.
        iface: Some(
            IFACES
                .iter()
                .find(|(i, _)| *i == ifindex)
                .map_or("", |(_, n)| *n),
        ),
        ..Meta::default()
    }
}

/// A small deterministic generator (xorshift64*), so that failures reproduce.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    pub fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
}

pub fn eth(vlans: &[(u16, u16)], et: u16, body: &[u8]) -> Vec<u8> {
    let mut f = vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 1];
    for &(tpid, tci) in vlans {
        f.extend(tpid.to_be_bytes());
        f.extend(tci.to_be_bytes());
    }
    f.extend(et.to_be_bytes());
    f.extend(body);
    f
}

pub struct Ip4 {
    pub proto: u8,
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub ttl: u8,
    pub tos: u8,
    /// Flags and fragment offset.
    pub frag: u16,
    /// Option words.
    pub opts: usize,
}

impl Default for Ip4 {
    fn default() -> Self {
        Ip4 {
            proto: 6,
            src: [10, 0, 0, 1],
            dst: [192, 168, 1, 1],
            ttl: 64,
            tos: 0,
            frag: 0x4000,
            opts: 0,
        }
    }
}

pub fn ipv4(h: &Ip4, body: &[u8]) -> Vec<u8> {
    let hl = 20 + 4 * h.opts;
    let total = (hl + body.len()) as u16;
    let mut f = vec![0x40 | (hl / 4) as u8, h.tos];
    f.extend(total.to_be_bytes());
    f.extend([0x12, 0x34]);
    f.extend(h.frag.to_be_bytes());
    f.extend([h.ttl, h.proto, 0xab, 0xcd]);
    f.extend(h.src);
    f.extend(h.dst);
    f.extend(std::iter::repeat_n(1, 4 * h.opts));
    f.extend(body);
    f
}

/// An IPv6 packet with extension headers `(type, length in bytes)`; `nh` is the protocol after
/// them.
pub fn ipv6(nh: u8, exts: &[(u8, usize)], tclass: u8, body: &[u8]) -> Vec<u8> {
    let mut ext = Vec::new();
    let mut first = nh;
    for (i, &(t, len)) in exts.iter().enumerate().rev() {
        let next = first;
        first = t;
        let mut h = vec![next, 0];
        h[1] = match t {
            51 => (len / 4 - 2) as u8,
            44 => 0,
            _ => (len / 8 - 1) as u8,
        };
        h.resize(len, 0);
        if t == 44 {
            // Offset and M flag from the position: the first fragment header is a first
            // fragment with more to come, the others are later ones.
            let field: u16 = if i == 0 { 1 } else { (8 << 3) | 1 };
            h[2..4].copy_from_slice(&field.to_be_bytes());
            h[4..8].copy_from_slice(&0xdead_beef_u32.to_be_bytes());
        }
        ext.splice(0..0, h);
    }
    let plen = (ext.len() + body.len()) as u16;
    let mut f = vec![0x60 | tclass >> 4, tclass << 4 | 0x0a, 0xbc, 0xde];
    f.extend(plen.to_be_bytes());
    f.extend([first, 64]);
    f.extend([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    f.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    f.extend(ext);
    f.extend(body);
    f
}

/// A TCP header with `opts` words of options: none, an MSS, or a NOP, a window scale and
/// SACK permitted.
pub fn tcp(sport: u16, dport: u16, flags: u16, opts: usize, payload: &[u8]) -> Vec<u8> {
    let o: &[u8] = match opts {
        0 => &[],
        1 => &[2, 4, 5, 0xb4],
        _ => &[1, 3, 3, 7, 4, 2, 1, 1],
    };
    tcp_opts(sport, dport, flags, o, payload)
}

/// A TCP header with these option bytes, padded with zeros to a word.
pub fn tcp_opts(sport: u16, dport: u16, flags: u16, opts: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut o = opts.to_vec();
    o.resize(opts.len().div_ceil(4) * 4, 0);
    let mut f = Vec::new();
    f.extend(sport.to_be_bytes());
    f.extend(dport.to_be_bytes());
    f.extend(0x0102_0304_u32.to_be_bytes());
    f.extend(0x0506_0708_u32.to_be_bytes());
    let doff = (5 + o.len() / 4) as u16;
    f.extend((doff << 12 | flags).to_be_bytes());
    f.extend([0x10, 0x00, 0xaa, 0xbb, 0, 0]);
    f.extend(o);
    f.extend(payload);
    f
}

/// Option lists that exercise the walk: timestamps, a known option of the wrong length, the
/// end of the list, a length below 2 or past the header, unknown kinds, a second MSS, a large
/// window scale.
const OPTIONS: &[&[u8]] = &[
    &[1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0],
    &[8, 10, 1, 2, 3, 4, 5, 6, 7, 8, 1, 0],
    &[2, 3, 5, 0],
    &[1, 1, 1, 0, 2, 4, 5, 0xb4],
    &[3, 3, 15, 1],
    &[5, 1, 2, 4, 5, 0xb4],
    &[2, 4, 5, 0xb4, 2, 4, 1, 0],
    &[254, 6, 0, 0, 0, 0, 4, 2],
    &[2, 44, 5, 0xb4],
    &[3, 3, 0, 4, 2, 2, 4, 1, 0x40, 1, 1],
];

pub fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend(sport.to_be_bytes());
    f.extend(dport.to_be_bytes());
    f.extend(((8 + payload.len()) as u16).to_be_bytes());
    f.extend([0x12, 0x34]);
    f.extend(payload);
    f
}

pub fn icmp(ty: u8, code: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![ty, code, 0xf7, 0xff, 0, 1, 0, 2];
    f.extend(payload);
    f
}

pub fn arp() -> Vec<u8> {
    let mut f = vec![0, 1, 8, 0, 6, 4, 0, 1];
    f.extend([2, 0, 0, 0, 0, 1, 10, 0, 0, 1]);
    f.extend([0, 0, 0, 0, 0, 0, 10, 0, 0, 2]);
    f
}

/// An ARP reply, and ARP packets with other address sizes.
pub fn arps() -> Vec<Vec<u8>> {
    let mut reply = vec![0, 1, 8, 0, 6, 4, 0, 2];
    reply.extend([2, 0, 0, 0, 0, 2, 10, 0, 0, 2]);
    reply.extend([2, 0, 0, 0, 0, 1, 10, 0, 0, 1]);
    // 8-byte hardware addresses, IPv4.
    let mut long_hw = vec![0, 6, 8, 0, 8, 4, 0, 1];
    long_hw.extend([1, 2, 3, 4, 5, 6, 7, 8, 10, 0, 0, 3]);
    long_hw.extend([0; 8]);
    long_hw.extend([10, 0, 0, 4]);
    // Ethernet, but a 16-byte protocol address.
    let mut v6 = vec![0, 1, 0x86, 0xdd, 6, 16, 0, 1];
    v6.extend([2, 0, 0, 0, 0, 3]);
    v6.extend([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    v6.extend([0; 6]);
    v6.extend([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    vec![reply, long_hw, v6]
}

const PAYLOADS: &[&[u8]] = &[
    b"",
    b"GET / HTTP/1.1\r\n\r\n",
    &[1, 2, 3],
    &[0x16, 3, 1, 0, 0xa5, 1],
    b"0123456789abcdefghijklmnopqrstuvwxyz0123456789",
];

/// Whether `BPF_PROG_TEST_RUN` takes `frame` as input. Since Linux 7.0 it refuses (`EINVAL`)
/// a frame whose EtherType is IPv4 or IPv6 when the IP header after the 14-byte Ethernet header
/// is shorter than the minimum (`bpf_prog_test_run_skb` reads it to fill the socket). The
/// programs see such frames in real traffic too, but a test run cannot give them.
pub fn test_runnable(frame: &[u8]) -> bool {
    let ip = frame.len().saturating_sub(14);
    match frame.get(12..14) {
        Some([0x08, 0x00]) => ip >= 20,
        Some([0x86, 0xdd]) => ip >= 40,
        _ => frame.len() >= 14,
    }
}

/// Well-formed frames of every kind the filters read, then the same frames cut short, with
/// padding, and with random bytes changed. Every frame is at least 14 bytes long when
/// `min_len` is 14 (what `BPF_PROG_TEST_RUN` accepts).
pub fn corpus(seed: u64, mutants: usize, min_len: usize) -> Vec<Vec<u8>> {
    let mut base = Vec::new();
    let ports: &[(u16, u16)] = &[(40000, 80), (443, 51000), (53, 53), (22, 8080), (8050, 1)];
    for (i, payload) in PAYLOADS.iter().enumerate() {
        let (sp, dp) = ports[i % ports.len()];
        let flags = [0x002, 0x012, 0x010, 0x018, 0xfff][i % 5];
        let t = tcp(sp, dp, flags, i % 3, payload);
        let u = udp(sp, dp, payload);
        let ic = icmp([8, 0, 3, 11, 128][i], i as u8, payload);
        let h = Ip4 {
            src: [
                [10, 1, 2, 3],
                [172, 16, 0, 9],
                [192, 168, 1, 1],
                [8, 8, 8, 8],
                [200, 0, 0, 1],
            ][i],
            ttl: [1, 64, 128, 255, 63][i],
            tos: [0, 0xb8, 1, 3, 0x2e][i],
            opts: i % 2,
            ..Ip4::default()
        };
        base.push(eth(&[], 0x0800, &ipv4(&h, &t)));
        base.push(eth(&[], 0x0800, &ipv4(&Ip4 { proto: 17, ..h }, &u)));
        base.push(eth(&[], 0x0800, &ipv4(&Ip4 { proto: 1, ..h }, &ic)));
        base.push(eth(&[(0x8100, 10)], 0x0800, &ipv4(&h, &t)));
        base.push(eth(&[(0x88a8, 20), (0x8100, 10)], 0x0800, &ipv4(&h, &t)));
        // Fragments: first with more to come, a later one, the last one.
        for frag in [0x2000, 0x2010, 0x0010] {
            base.push(eth(&[], 0x0800, &ipv4(&Ip4 { frag, ..h }, &t)));
        }
        base.push(eth(&[], 0x86dd, &ipv6(6, &[], 0, &t)));
        base.push(eth(&[], 0x86dd, &ipv6(17, &[(0, 8), (60, 16)], 0xb8, &u)));
        base.push(eth(&[], 0x86dd, &ipv6(58, &[(43, 24)], 0, &ic)));
        base.push(eth(&[], 0x86dd, &ipv6(6, &[(44, 8)], 0, &t)));
        base.push(eth(
            &[],
            0x86dd,
            &ipv6(6, &[(51, 12), (44, 8), (44, 8)], 0, &t),
        ));
    }
    for (i, o) in OPTIONS.iter().enumerate() {
        let t = tcp_opts(
            443,
            40000 + i as u16,
            0x012,
            o,
            PAYLOADS[i % PAYLOADS.len()],
        );
        base.push(eth(&[], 0x0800, &ipv4(&Ip4::default(), &t)));
        base.push(eth(&[], 0x86dd, &ipv6(6, &[], 0, &t)));
    }
    base.push(eth(&[], 0x0806, &arp()));
    for a in arps() {
        base.push(eth(&[], 0x0806, &a));
    }
    base.push(eth(&[(0x8100, 30)], 0x0806, &arp()));
    base.push(eth(
        &[(0x88a8, 0x2028)],
        0x0800,
        &ipv4(&Ip4::default(), &udp(53, 53, b"x")),
    ));
    base.push(eth(&[], 0x88cc, &[1, 2, 3, 4]));
    base.push(eth(
        &[(0x8100, 1), (0x8100, 2), (0x8100, 3)],
        0x0800,
        &[0x45],
    ));
    let mut out = base.clone();
    // Ethernet padding, and a bogus IPv4 total length.
    for f in &base {
        let mut g = f.clone();
        g.extend([0; 7]);
        out.push(g);
    }
    let mut rng = Rng::new(seed);
    for f in &base {
        for _ in 0..3 {
            let cut = min_len.max(rng.below(f.len() + 1));
            out.push(f[..cut.min(f.len())].to_vec());
        }
    }
    for _ in 0..mutants {
        let mut g = rng.pick(&base).clone();
        for _ in 0..1 + rng.below(3) {
            // Mostly in the headers, where it changes the parse.
            let at = rng.below(g.len().min(80));
            g[at] = match rng.below(4) {
                0 => 0,
                1 => 0xff,
                _ => rng.next() as u8,
            };
        }
        if rng.below(4) == 0 {
            let cut = min_len.max(rng.below(g.len() + 1));
            g.truncate(cut);
        }
        out.push(g);
    }
    out.retain(|f| f.len() >= min_len);
    out
}

/// Filters the generator supports, one feature or field at a time.
pub const SUPPORTED: &[&str] = &[
    "frame",
    "eth",
    "ip",
    "ipv6",
    "arp",
    "tcp",
    "udp",
    "icmp",
    "icmpv6",
    "true",
    "false",
    "tcp.port == 80",
    "tcp.port != 80",
    "tcp.port !== 80",
    "tcp.port === 53",
    "tcp.dstport >= 1024",
    "tcp.srcport < 1024",
    "tcp.srcport <= 443",
    "tcp.dstport > 8000",
    "tcp.port in {80 443 8000..8100}",
    "tcp.port not in {22 80}",
    "all tcp.port in {1..1023}",
    "all tcp.port not in {1..1023}",
    "any tcp.port == 443",
    "all tcp.port > 1000",
    "udp.port == 53",
    "udp.length > 20",
    "udp.dstport in {53 67..68}",
    "udp.srcport == 8050",
    "udp.checksum == 0x1234",
    "ip.src == 10.0.0.0/8",
    "ip.addr == 192.168.1.1",
    "ip.dst != 10.0.0.0/8",
    "ip.addr in {10.0.0.0/8 172.16.0.0/12}",
    "ip.src in {10.0.0.0..10.255.255.255}",
    "ip.src > 128.0.0.0",
    "ip.src <= 10.1.2.3",
    "ip.addr == 0.0.0.0/0",
    "ip.ttl < 64",
    "ip.proto == 6",
    "ip.proto == UDP",
    "ip.flags.df == 1",
    "ip.flags.df == 0",
    "ip.flags.mf",
    "ip.flags.mf == 1",
    "ip.flags.rb != 0",
    "ip.flags == 2",
    "ip.frag_offset > 0",
    "ip.hdr_len > 20",
    "ip.len < 100",
    "ip.version == 4",
    "ip.version == 6",
    "ip.dsfield.dscp == 46",
    "ip.dsfield.ecn == 3",
    "ip.dsfield == 0",
    "ip.id == 0x1234",
    "ip.checksum == 0xabcd",
    "ipv6.nxt == 6",
    "ipv6.hlim == 64",
    "ipv6.plen > 30",
    "ipv6.flow == 0xabcde",
    "ipv6.tclass == 0xb8",
    "ipv6.tclass.dscp == 46",
    "ipv6.tclass.ecn == 0",
    "ipv6.version == 6",
    "tcp.flags.syn == 1",
    "tcp.flags.ack == 0",
    "tcp.flags.syn == 1 and tcp.flags.ack == 0",
    "tcp.flags == 0x012",
    "tcp.flags.res == 1",
    "tcp.flags.ae == 1",
    "tcp.flags.fin == 1 or tcp.flags.reset == 1",
    "tcp.flags.push == 1 and tcp.flags.urg == 1 and tcp.flags.ece == 1 and tcp.flags.cwr == 1",
    "tcp.hdr_len > 20",
    "tcp.window_size_value < 5000",
    "tcp.len > 0",
    "tcp.len == 0",
    "tcp.len",
    "tcp.seq_raw == 0x01020304",
    "tcp.ack_raw != 0",
    "tcp.checksum == 0xaabb",
    "tcp.urgent_pointer == 0",
    "tcp.payload",
    "tcp.payload[0:4] == \"GET \"",
    "tcp.payload[-2:] == 0d:0a",
    "tcp.payload[-4--1] == 0d:0a:0d:0a",
    "tcp.payload == 01:02:03",
    "tcp.payload != 01:02:03",
    "tcp.payload[1:2] == 02:03",
    "tcp.payload[2-4] == 01:00:a5",
    "tcp.payload[0] == 0x16",
    "tcp.payload[0:46] == \"0123456789abcdefghijklmnopqrstuvwxyz0123456789\"",
    "tcp.payload[10:] == \"abcdefghijklmnopqrstuvwxyz0123456789\"",
    "tcp.payload[40:]",
    "tcp[13] == 0x12",
    "tcp[12:2] == 50:02",
    "tcp[-2:] == 00:00",
    "udp.payload[0] == 0x01",
    "udp.payload[1:] == 02:03",
    "udp.payload",
    "udp[4:2] == 00:0b",
    "frame[12:2] == 08:00",
    "frame[-1] == 00",
    "frame[0:6] == ff:ff:ff:ff:ff:ff",
    "frame[14] == 0x45",
    "frame[100:]",
    "eth.dst == ff:ff:ff:ff:ff:ff",
    "eth.src == 02:00:00:00:00:01",
    "eth.src != 02:00:00:00:00:01",
    "eth.type == 0x0800",
    "eth.type == 0x8100",
    "ip[0] == 0x45",
    "ip[0] == 0x46",
    "ip[20:4] == 01:01:01:01",
    "icmp.type == 8",
    "icmp.code == 0",
    "icmp[0:2] == 08:00",
    "icmpv6.type == 128",
    "icmpv6.code > 0",
    "icmpv6[4:]",
    "frame.len > 100",
    "frame.len <= 60",
    "frame.cap_len == 64",
    "not tcp",
    "tcp xor udp",
    "not (tcp or udp) and ip",
    "tcp.port == 80 xor ip.ttl < 64",
    "(tcp.port == 80 or udp.port == 53) and not ip.flags.mf",
    "ip.src == 172.16.0.0/12 and tcp.srcport in {80 443} and tcp.payload[0:3] == \"GET\"",
    "tcp.srcport > -1",
    "tcp.srcport < -1",
    "tcp.srcport <= -5",
    "tcp.port in {1..80}",
    "tcp.dstport in {80..443}",
    "tcp.payload[-4:]",
    "tcp.payload[2:2]",
    "udp.payload[0:4]",
    "frame[-1000:]",
    "frame[-60:]",
    // Metadata.
    "outbound",
    "inbound",
    "loopback",
    "impostor",
    "outbound and not impostor",
    "fragment",
    "ifidx == 2",
    "ifidx > 2",
    "iface == \"eth0\"",
    "iface != \"wlan0\"",
    "iface in {\"lo\" \"veth3\"}",
    "iface not in {\"lo\" \"nonexistent\"}",
    "protocol == 17",
    "protocol in {1 58}",
    "local.port == 80",
    "remote.port in {80 443}",
    "local.port != 53",
    "local.addr == 10.0.0.0/8",
    "remote.addr == 192.168.1.1",
    "local.addr != 10.1.2.3",
    "remote.addr == 2001:db8::2",
    "local.addr in {172.16.0.0/12 fe80::/10}",
    "remote.addr not in {192.168.1.1 2001:db8::2}",
    "local.addr and remote.port == 443",
    "remote.port",
    // IPv6 addresses.
    "ipv6.src == fe80::1",
    "ipv6.dst == 2001:db8::/32",
    "ipv6.addr == 2001:db8::2",
    "ipv6.addr != fe80::1",
    "ipv6.addr !== fe80::1",
    "ipv6.src > fe00::",
    "ipv6.dst < 2001:db8::2",
    "ipv6.dst <= 2001:db8::2",
    "ipv6.dst in {2001:db8::1..2001:db8::ff}",
    "ipv6.addr in {fe80::/10 ::1}",
    "ipv6.src[0:2] == fe:80",
    // Link layer.
    "eth.addr == ff:ff:ff:ff:ff:ff",
    "eth.addr != 02:00:00:00:00:01",
    "eth.src > 01:00:00:00:00:00",
    "eth.dst in {ff:ff:ff:ff:ff:ff 01:00:5e:00:00:01}",
    "vlan",
    "vlan.id == 10",
    "vlan.id != 10",
    "all vlan.id > 1",
    "vlan.priority == 0",
    "vlan.dei",
    "vlan.etype == 0x0800",
    "vlan[0:2] == 00:0a",
    "ieee8021ad",
    "ieee8021ad.id == 20",
    "ieee8021ad.dei == 0",
    "ieee8021ad.priority < 4",
    // TCP options.
    "tcp.options",
    "tcp.options.mss",
    "tcp.options.mss_val == 1460",
    "tcp.options.mss_val < 1200",
    "tcp.options.wscale",
    "tcp.options.wscale.shift == 7",
    "tcp.options.wscale.multiplier == 128",
    "tcp.options.wscale.multiplier > 1000",
    "tcp.options.sack_perm",
    "tcp.options.timestamp",
    "tcp.options.timestamp.tsval > 1",
    "tcp.options.timestamp.tsecr == 0",
    "tcp.options[0] == 2",
    "tcp.options.mss[0:2] == 02:04",
    // Lengths, counts, header contents.
    "len(tcp.payload) > 3",
    "len(udp.payload) == 3",
    "len(ip.src) == 4",
    "len(tcp.options) > 4",
    "len(frame) > 70",
    "count(ip.addr) == 2",
    "count(vlan.id) == 1",
    "count(tcp.payload) == 1",
    "tcp contains 05:b4",
    "ip contains 0a:01",
    "udp contains 00:35",
    "tcp.options contains 03:03",
    "all eth.addr contains 00",
    // Arithmetic and comparisons of fields.
    "tcp.port + 1 == 81",
    "tcp.srcport - tcp.dstport > 0",
    "tcp.dstport * 2 > 1000",
    "tcp.dstport / 100 == 80",
    "tcp.srcport % 1000 == 0",
    "tcp.srcport / (tcp.dstport + 1) > 2",
    "-tcp.srcport < -1000",
    "abs(tcp.srcport - tcp.dstport) < 1000",
    "max(tcp.srcport, tcp.dstport) > 1024",
    "min(tcp.port) < 100",
    "max(tcp.srcport, udp.srcport) > 1000",
    "tcp.flags & 0x12 == 0x12",
    "tcp.srcport == tcp.dstport",
    "ip.ttl > ip.dsfield",
    "udp.srcport != udp.dstport",
    "all tcp.port > tcp.hdr_len",
    "tcp.flags.syn == tcp.flags.ack",
    "ip.src == ip.dst",
    // ARP.
    "arp.opcode == 1",
    "arp.opcode == reply",
    "arp.hw.type == 1",
    "arp.proto.type == 0x0800",
    "arp.hw.size == 6",
    "arp.proto.size != 4",
    "arp.src.hw_mac == 02:00:00:00:00:01",
    "arp.dst.hw_mac == 02:00:00:00:00:01",
    "arp.src.proto_ipv4 == 10.0.0.1",
    "arp.dst.proto_ipv4 in {10.0.0.0/30}",
    "arp[7] == 1",
    "len(arp) == 28",
    // Large sets: trees of jumps.
    "tcp.port in {1 3 5 7 9 11 13 22 25 53 80 110 143 443 993 8000..8100}",
    "ip.addr in {10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 8.8.8.8 1.1.1.1 9.9.9.9}",
    "tcp.dstport not in {1 2 3 4 5 6 7 8 9 10 11 12 80 81 82}",
    "udp.payload in {01:02:03 \"GET\"}",
];

/// Filters it must refuse, so that the backend filters them in user space.
pub const UNSUPPORTED: &[&str] = &[
    "tcp.payload contains \"GET\"",
    "frame contains 00:00",
    "tcp.payload > 01:02",
    "@tcp.port == 00:50",
    "tcp.port#1 == 80",
    "lower(iface) == \"eth0\"",
    "iface contains \"eth\"",
    "tcp.payload[0:2,4:2] == 01:02:03:04",
    "ipv6[0] == 0x60",
    "random8 < 128",
    "timestamp > 0",
    "icmp.ident == 1",
    "arp contains 0a:00:00:02",
    "tcp.srcport * tcp.dstport * tcp.seq_raw > 0",
    "tcp.dstport / (tcp.srcport - 53) > 0",
    "ip.src[0] == 10",
    "eth.dst & ff:00:00:00:00:00 == ff:00:00:00:00:00",
];

/// A random filter built from `pool` with `and`, `or`, `not` and `xor`.
pub fn random_filter(rng: &mut Rng, pool: &[&str], depth: usize) -> String {
    if depth == 0 || rng.below(3) == 0 {
        return format!("({})", rng.pick(pool));
    }
    let a = random_filter(rng, pool, depth - 1);
    match rng.below(4) {
        0 => format!("not {a}"),
        1 => format!("({a} and {})", random_filter(rng, pool, depth - 1)),
        2 => format!("({a} or {})", random_filter(rng, pool, depth - 1)),
        _ => format!("({a} xor {})", random_filter(rng, pool, depth - 1)),
    }
}

/// SOCKET-layer filters the generator compiles exactly, for the events of `connect` and `bind`.
pub const EVENT_FILTERS: &[&str] = &[
    "remote.port == 443",
    "local.port in {80 443 1000..2000}",
    "local.port == 0",
    "protocol == 6",
    "protocol in {17}",
    "process.pid == 1234",
    "process.pid != 1234",
    "outbound",
    "inbound and not loopback",
    "loopback",
    "remote.addr == 10.0.0.1",
    "remote.addr in {10.0.0.0/8 fd00::/8}",
    "remote.addr not in {192.168.0.0/16}",
    "local.addr != 127.0.0.1",
    "local.addr == 0.0.0.0",
    "remote.addr == ::1",
    "remote.addr == 2001:db8::/32",
    "remote.addr != 2001:db8::1",
    "remote.addr > 10.0.0.0",
    "remote.addr in {fd00::1..fd00::ff}",
    "local.addr and remote.port == 443",
    "event == connect",
    "event == bind and local.port < 1024",
    "event in {bind accept}",
    "layer == socket and priority == 0 and remote.port == 53",
    "remote.port > local.port",
    "remote.port + 1 == 444",
    "remote.port % 2 == 0 and protocol == 6",
    "max(remote.port, local.port) >= 1000",
    "(remote.port == 443 xor protocol == 17) or process.pid == 0",
    "ifidx == 0 and subifidx == 0 and not impostor and protocol == 6",
    "not fragment and protocol == 17",
    "tcp or ip or udp.port == 53 or remote.port == 53",
    "not tcp and remote.port == 53",
    "frame.len > 0 or remote.port == 22",
    "iface == \"lo\" or remote.port == 22",
    "process.name == \"curl\"",
    "process.name in {\"curl\" \"wget\"}",
    "process.name != \"curl\"",
    "process.name",
    "not process.name",
    "event == connect and process.name == \"test\" and remote.port == 443",
];

/// SOCKET-layer filters it does not compile: a blocking handle refuses them.
pub const EVENT_UNSUPPORTED: &[&str] = &[
    "endpoint.id == 5",
    "process.name contains \"ur\"",
    "upper(process.name) == \"CURL\"",
    "process.name > \"a\"",
    "timestamp > 0",
    "random8 < 10",
    "len(remote.addr) == 4",
];

/// Events of `connect` and `bind`, over both families, loopback and unknown endpoints.
pub fn event_records() -> Vec<avulse_ebpf::abi::EventRecord> {
    use avulse_ebpf::abi::{EV_OUTBOUND, EventRecord};
    use std::net::{Ipv4Addr, Ipv6Addr};
    let v4 = |a: [u8; 4]| Ipv4Addr::from(a).to_ipv6_mapped().octets();
    let v6 = |s: &str| s.parse::<Ipv6Addr>().unwrap().octets();
    let addrs = [
        v4([10, 0, 0, 1]),
        v4([127, 0, 0, 1]),
        v4([192, 168, 1, 5]),
        v4([0, 0, 0, 0]),
        v6("::1"),
        v6("fd00::7"),
        v6("2001:db8::1"),
        v6("::"),
    ];
    let mut out = Vec::new();
    for (i, &remote) in addrs.iter().enumerate() {
        for (j, &(local_port, remote_port)) in [(0, 443), (50000, 53), (80, 22), (1500, 1500)]
            .iter()
            .enumerate()
        {
            for event in [4u8, 3] {
                let mut r = EventRecord {
                    event,
                    protocol: [6, 17][(i + j) % 2],
                    family: if remote[..12] == v4([0; 4])[..12] {
                        4
                    } else {
                        6
                    },
                    pid: [0, 1234, 99][(i + j) % 3],
                    flags: if event == 4 { EV_OUTBOUND } else { 0 },
                    local_port,
                    remote_port,
                    endpoint: (i * 8 + j) as u64,
                    comm: [
                        *b"test\0\0\0\0\0\0\0\0\0\0\0\0",
                        *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
                        [0; 16],
                        *b"0123456789abcdef",
                    ][(i + 2 * j) % 4],
                    ..EventRecord::default()
                };
                // A bind has a local address only; a connect has the bound one, if any.
                if event == 3 {
                    r.local_addr = remote;
                    r.remote_addr = if r.family == 4 { v4([0; 4]) } else { v6("::") };
                } else {
                    r.remote_addr = remote;
                    r.local_addr = addrs[(i + j) % addrs.len()];
                }
                out.push(r);
            }
        }
    }
    out
}

/// What a SOCKET handle's filter sees of `r`, as the backend builds it.
pub fn event_meta(r: &avulse_ebpf::abi::EventRecord) -> Meta<'_> {
    use avulse_ebpf::abi::EV_OUTBOUND;
    use avulse_ebpf::facts::ev::is_loopback;
    use avulse_filter::{Event, FlowTuple};
    use std::net::Ipv6Addr;
    let event = match r.event {
        3 => Event::SocketBind,
        _ => Event::SocketConnect,
    };
    Meta {
        layer: Layer::Socket,
        event,
        outbound: r.flags & EV_OUTBOUND != 0,
        loopback: is_loopback(&r.local_addr) || is_loopback(&r.remote_addr),
        process_id: Some(r.pid),
        process_name: r.comm(),
        endpoint_id: Some(r.endpoint),
        parent_endpoint_id: Some(r.parent_endpoint),
        flow: Some(FlowTuple {
            local_addr: Ipv6Addr::from(r.local_addr).to_canonical(),
            remote_addr: Ipv6Addr::from(r.remote_addr).to_canonical(),
            local_port: r.local_port,
            remote_port: r.remote_port,
            protocol: r.protocol,
        }),
        timestamp: r.timestamp as i64,
        ..Meta::default()
    }
}
