//! Spike C helpers: frame builders for the probes, and the C entry point that the system
//! extension's packet handler calls (`sysext/`).

use avulse_filter::Meta;
use avulse_filter::bytecode::verify;
use avulse_proto::{Link, Packet, checksum};

/// An Ethernet header in front of `payload`.
pub fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(14 + payload.len());
    v.extend_from_slice(&dst);
    v.extend_from_slice(&src);
    v.extend_from_slice(&ethertype.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// An IPv4 packet (no options, DF set), checksums left to [`finish`].
pub fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
    let len = (20 + payload.len()) as u16;
    let mut v = vec![0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, proto, 0, 0];
    v[2..4].copy_from_slice(&len.to_be_bytes());
    v.extend_from_slice(&src);
    v.extend_from_slice(&dst);
    v.extend_from_slice(payload);
    v
}

/// An IPv6 packet, checksums left to [`finish`].
pub fn ipv6(src: [u8; 16], dst: [u8; 16], next: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x60, 0, 0, 0];
    v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    v.extend_from_slice(&[next, 64]);
    v.extend_from_slice(&src);
    v.extend_from_slice(&dst);
    v.extend_from_slice(payload);
    v
}

/// A UDP header in front of `payload`.
pub fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + payload.len());
    v.extend_from_slice(&sport.to_be_bytes());
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(payload);
    v
}

/// A TCP header (20 bytes plus `options`, padded) with `flags`, in front of `payload`.
pub fn tcp(sport: u16, dport: u16, flags: u8, options: &[u8], payload: &[u8]) -> Vec<u8> {
    let olen = options.len().div_ceil(4) * 4;
    let mut v = Vec::with_capacity(20 + olen + payload.len());
    v.extend_from_slice(&sport.to_be_bytes());
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&1000u32.to_be_bytes());
    v.extend_from_slice(&0u32.to_be_bytes());
    v.push((((20 + olen) / 4) as u8) << 4);
    v.push(flags);
    v.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
    v.extend_from_slice(options);
    v.resize(20 + olen, 0);
    v.extend_from_slice(payload);
    v
}

/// An ICMP echo request.
pub fn icmp_echo(ident: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![8, 0, 0, 0];
    v.extend_from_slice(&ident.to_be_bytes());
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Computes every checksum of `buf`.
pub fn finish(mut buf: Vec<u8>, link: Link) -> Vec<u8> {
    checksum::recalculate(&mut buf, link);
    // ICMP is not part of `recalculate`: WinDivert sends it as it is.
    let p = Packet::parse(&buf, link);
    if let (avulse_proto::Network::Ipv4(ip), avulse_proto::Transport::Icmp(_)) =
        (p.network(), p.transport())
    {
        let start = p.l4_offset().unwrap_or(0);
        let end = start + usize::from(ip.total_len()).saturating_sub(ip.header_len());
        let end = end.min(buf.len());
        buf[start + 2..start + 4].fill(0);
        let sum = checksum::finish(checksum::sum(&buf[start..end], 0));
        buf[start + 2..start + 4].copy_from_slice(&sum.to_be_bytes());
    }
    buf
}

/// Runs the verified bytecode `prog` on a packet, as the system extension's packet handler does.
/// `link` is 0 for an Ethernet frame and 1 for an IP packet. Returns 1 on a match, 0 on a miss,
/// and -1 if the program does not verify.
///
/// # Safety
///
/// `prog` and `pkt` must be valid for reads of `prog_len` and `pkt_len` bytes (or null with a
/// zero length).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_spike_matches(
    prog: *const u8,
    prog_len: usize,
    pkt: *const u8,
    pkt_len: usize,
    link: u32,
    outbound: bool,
) -> i32 {
    let slice = |p: *const u8, n: usize| {
        if p.is_null() || n == 0 {
            &[][..]
        } else {
            // SAFETY: the caller guarantees `n` readable bytes at `p`.
            unsafe { core::slice::from_raw_parts(p, n) }
        }
    };
    let Ok(program) = verify(slice(prog, prog_len)) else {
        return -1;
    };
    let link = if link == 0 { Link::Ethernet } else { Link::Ip };
    let packet = Packet::parse(slice(pkt, pkt_len), link);
    let meta = Meta {
        outbound,
        ..Meta::default()
    };
    i32::from(program.matches(&packet, &meta))
}

/// Compiles the native filter `src` (`src_len` bytes of UTF-8) to bytecode in `out`. Returns the
/// program's length, -1 if the filter does not compile, or -2 if `out` is too small.
///
/// # Safety
///
/// `src` must be valid for reads of `src_len` bytes and `out` for writes of `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn avulse_spike_compile(
    src: *const u8,
    src_len: usize,
    out: *mut u8,
    cap: usize,
) -> isize {
    if src.is_null() || out.is_null() {
        return -1;
    }
    // SAFETY: the caller guarantees `src_len` readable bytes at `src`.
    let src = unsafe { core::slice::from_raw_parts(src, src_len) };
    let Ok(src) = core::str::from_utf8(src) else {
        return -1;
    };
    let Some(bytes) = avulse_filter::Filter::compile(src)
        .ok()
        .and_then(|f| f.program().ok())
        .map(|p| p.to_bytes())
    else {
        return -1;
    };
    if bytes.len() > cap {
        return -2;
    }
    // SAFETY: the caller guarantees `cap` writable bytes at `out`.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
    bytes.len() as isize
}
