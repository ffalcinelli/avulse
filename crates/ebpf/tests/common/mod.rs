//! What the host and kernel tests share: a corpus of frames, the filters, and a random filter
//! generator.

#![allow(dead_code)]

pub mod emu;

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

pub fn tcp(sport: u16, dport: u16, flags: u16, opts: usize, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend(sport.to_be_bytes());
    f.extend(dport.to_be_bytes());
    f.extend(0x0102_0304_u32.to_be_bytes());
    f.extend(0x0506_0708_u32.to_be_bytes());
    let doff = (5 + opts) as u16;
    f.extend((doff << 12 | flags).to_be_bytes());
    f.extend([0x10, 0x00, 0xaa, 0xbb, 0, 0]);
    for _ in 0..opts {
        f.extend([2, 4, 5, 0xb4]);
    }
    f.extend(payload);
    f
}

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

const PAYLOADS: &[&[u8]] = &[
    b"",
    b"GET / HTTP/1.1\r\n\r\n",
    &[1, 2, 3],
    &[0x16, 3, 1, 0, 0xa5, 1],
    b"0123456789abcdefghijklmnopqrstuvwxyz0123456789",
];

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
    base.push(eth(&[], 0x0806, &arp()));
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
];

/// Filters it must refuse, so that the backend filters them in user space.
pub const UNSUPPORTED: &[&str] = &[
    "tcp.payload contains \"GET\"",
    "len(tcp.payload) > 3",
    "tcp.flags & 0x12 == 0x12",
    "ipv6.src == ::1",
    "eth.addr == ff:ff:ff:ff:ff:ff",
    "vlan.id == 10",
    "tcp.options.mss_val < 1200",
    "outbound",
    "tcp.srcport == tcp.dstport",
    "tcp.payload > 01:02",
    "@tcp.port == 00:50",
    "tcp.port#1 == 80",
    "count(ip.addr) == 2",
    "lower(iface) == \"eth0\"",
    "tcp.port + 1 == 81",
    "max(tcp.srcport, tcp.dstport) > 1024",
    "tcp.payload[0:2,4:2] == 01:02:03:04",
    "ipv6[0] == 0x60",
    "udp.payload in {01:02 03:04}",
];

/// A random filter built from [`SUPPORTED`] with `and`, `or`, `not` and `xor`.
pub fn random_filter(rng: &mut Rng, depth: usize) -> String {
    if depth == 0 || rng.below(3) == 0 {
        return format!("({})", rng.pick(SUPPORTED));
    }
    let a = random_filter(rng, depth - 1);
    match rng.below(4) {
        0 => format!("not {a}"),
        1 => format!("({a} and {})", random_filter(rng, depth - 1)),
        2 => format!("({a} or {})", random_filter(rng, depth - 1)),
        _ => format!("({a} xor {})", random_filter(rng, depth - 1)),
    }
}
