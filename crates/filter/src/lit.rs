//! Literal syntax. Words are parsed according to the type expected by the other operand.

use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

/// Decimal, `0x` hex, `0b` binary, or leading-zero octal (as in Wireshark).
pub(crate) fn parse_uint(s: &str) -> Option<u64> {
    let (digits, radix) = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        (h, 16)
    } else if let Some(b) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
        (b, 2)
    } else if s.len() > 1 && s.starts_with('0') {
        (&s[1..], 8)
    } else {
        (s, 10)
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

pub(crate) fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "true" | "True" | "TRUE" => Some(true),
        "0" | "false" | "False" | "FALSE" => Some(false),
        _ => None,
    }
}

fn split_prefix(s: &str, max: u8) -> Option<(&str, u8)> {
    match s.split_once('/') {
        None => Some((s, max)),
        Some((a, p)) => {
            if p.is_empty() || !p.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            Some((a, p.parse().ok().filter(|p| *p <= max)?))
        }
    }
}

/// `a.b.c.d` with an optional `/prefix`.
pub(crate) fn parse_ipv4(s: &str) -> Option<([u8; 4], u8)> {
    let (a, p) = split_prefix(s, 32)?;
    Some((a.parse::<Ipv4Addr>().ok()?.octets(), p))
}

/// An IPv6 address with an optional `/prefix`.
pub(crate) fn parse_ipv6(s: &str) -> Option<([u8; 16], u8)> {
    let (a, p) = split_prefix(s, 128)?;
    Some((a.parse::<Ipv6Addr>().ok()?.octets(), p))
}

/// Byte strings: `aa:bb:cc`, `aa-bb-cc`, `aa.bb.cc`, `aabb.ccdd.eeff` (Cisco style), a single
/// byte `aa`, or a single byte with a trailing colon `aa:` (which keeps `12:` from reading as
/// the integer 12).
pub(crate) fn parse_bytes(s: &str) -> Option<Vec<u8>> {
    if let Some(b) = s.strip_suffix(':').filter(|b| (1..=2).contains(&b.len())) {
        return u8::from_str_radix(b, 16)
            .ok()
            .filter(|_| b.bytes().all(|c| c.is_ascii_hexdigit()))
            .map(|x| alloc::vec![x]);
    }
    let hex = |g: &str| {
        u8::from_str_radix(g, 16)
            .ok()
            .filter(|_| g.bytes().all(|c| c.is_ascii_hexdigit()))
    };
    let sep = s.bytes().find(|c| matches!(c, b':' | b'-' | b'.'));
    let Some(sep) = sep else {
        return (s.len() == 2)
            .then(|| hex(s))
            .flatten()
            .map(|b| alloc::vec![b]);
    };
    let groups: Vec<&str> = s.split(sep as char).collect();
    if sep == b'.' && groups.len() == 3 && groups.iter().all(|g| g.len() == 4) {
        let mut out = Vec::with_capacity(6);
        for g in groups {
            out.push(hex(&g[..2])?);
            out.push(hex(&g[2..])?);
        }
        return Some(out);
    }
    groups
        .iter()
        .map(|g| {
            if (1..=2).contains(&g.len()) {
                hex(g)
            } else {
                None
            }
        })
        .collect()
}

pub(crate) fn parse_mac(s: &str) -> Option<[u8; 6]> {
    parse_bytes(s)?.try_into().ok()
}

/// Whether a word reads as a value rather than a field name.
pub(crate) fn looks_like_literal(s: &str) -> bool {
    parse_uint(s).is_some()
        || parse_ipv4(s).is_some()
        || parse_ipv6(s).is_some()
        || parse_bytes(s).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers() {
        assert_eq!(parse_uint("80"), Some(80));
        assert_eq!(parse_uint("0x1F"), Some(31));
        assert_eq!(parse_uint("0b101"), Some(5));
        assert_eq!(parse_uint("010"), Some(8));
        assert_eq!(parse_uint("0"), Some(0));
        assert_eq!(parse_uint("08"), None);
        assert_eq!(parse_uint("+1"), None);
        assert_eq!(parse_uint("0x"), None);
    }

    #[test]
    fn addresses() {
        assert_eq!(parse_ipv4("10.0.0.0/8"), Some(([10, 0, 0, 0], 8)));
        assert_eq!(parse_ipv4("1.2.3.4"), Some(([1, 2, 3, 4], 32)));
        assert_eq!(parse_ipv4("1.2.3.4/33"), None);
        assert_eq!(parse_ipv4("1.2.3"), None);
        assert_eq!(parse_ipv6("fe80::1/64").map(|(_, p)| p), Some(64));
        assert_eq!(
            parse_ipv6("::ffff:1.2.3.4").map(|(a, _)| a[12..].to_vec()),
            Some(alloc::vec![1, 2, 3, 4])
        );
    }

    #[test]
    fn bytes() {
        assert_eq!(parse_bytes("00:11:22"), Some(alloc::vec![0, 0x11, 0x22]));
        assert_eq!(parse_bytes("de-ad"), Some(alloc::vec![0xde, 0xad]));
        assert_eq!(
            parse_bytes("0011.2233.4455"),
            Some(alloc::vec![0, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(parse_bytes("ff"), Some(alloc::vec![0xff]));
        assert_eq!(parse_bytes("12:"), Some(alloc::vec![0x12]));
        assert_eq!(parse_bytes(":"), None);
        assert_eq!(parse_bytes("a:b"), Some(alloc::vec![0xa, 0xb]));
        assert_eq!(parse_bytes("00:11-22"), None);
        assert_eq!(parse_bytes("ip.src"), None);
        assert_eq!(
            parse_mac("00:11:22:33:44:55"),
            Some([0, 0x11, 0x22, 0x33, 0x44, 0x55])
        );
        assert_eq!(parse_mac("00:11:22"), None);
    }

    #[test]
    fn literal_detection() {
        for w in ["80", "1.2.3.4", "fe80::1", "aa:bb", "10.0.0.0/8"] {
            assert!(looks_like_literal(w), "{w}");
        }
        for w in ["tcp", "tcp.port", "http.host", "ip"] {
            assert!(!looks_like_literal(w), "{w}");
        }
    }
}
