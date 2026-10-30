//! What the programs share with user space, as laid out in `bpf/abi.h`: the handle's
//! configuration, the ring buffer records (packets, and the events of the FLOW and SOCKET
//! layers), the statistics and the packet marks.

/// Copy matching packets to the ring; they go on.
pub const CFG_SNIFF: u32 = 1 << 0;
/// Drop matching packets, and copy nothing.
pub const CFG_DROP: u32 = 1 << 1;
/// Also take inbound IP fragments.
pub const CFG_FRAGMENTS: u32 = 1 << 2;
/// Pass everything (the receive side is shut down).
pub const CFG_SHUTDOWN: u32 = 1 << 3;
/// IP forwarding is on: at the NETWORK layer, ingress skips the packets the host forwards.
pub const CFG_FWD_CHECK: u32 = 1 << 4;
/// The loopback device is attached for injection only.
pub const CFG_SKIP_LO: u32 = 1 << 5;
/// The matcher reads TCP options ([`Matcher::reads_tcp_options`]): find them
/// (`avulse_options`) before it runs.
///
/// [`Matcher::reads_tcp_options`]: crate::codegen::Matcher::reads_tcp_options
pub const CFG_TCP_OPTIONS: u32 = 1 << 6;

/// `struct avulse_config`: the one entry of the `avulse_config` array.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
    /// `bpf_ktime_get_ns()` (`CLOCK_MONOTONIC`) of the last heartbeat.
    pub heartbeat_ns: u64,
    /// Pass everything once the heartbeat is older than this; 0 disables the check.
    pub heartbeat_timeout_ns: u64,
    /// `CFG_*` bits.
    pub flags: u32,
    /// The handle's TC priority (lower runs first).
    pub priority: u32,
    /// The loopback device's index.
    pub lo_ifindex: u32,
    /// With [`CFG_SNIFF`], copy at most this many bytes; 0 copies everything.
    pub snaplen: u32,
    /// The layer (`avulse_filter::Layer` as a number): NETWORK, NETWORK_FORWARD or ETHERNET for
    /// the TC programs, FLOW or SOCKET for the event programs.
    pub layer: u8,
    /// Padding.
    pub pad: [u8; 7],
}

/// The largest packet a record holds.
pub const MAX_RECORD_DATA: usize = 65_536;

/// Size of a record's header.
pub const RECORD_HEADER: usize = 40;

/// A ring buffer record: a packet the handle diverted or copied, as `struct avulse_record`
/// describes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    /// `bpf_ktime_get_ns()` when it was copied.
    pub timestamp: u64,
    /// The packet's length (`skb->len`); more than `data.len()` when a sniffed copy is cut.
    pub len: u32,
    /// The device it was seen on.
    pub ifindex: u32,
    /// `skb->ingress_ifindex`: 0 for locally generated packets.
    pub ingress_ifindex: u32,
    /// `skb->gso_size`: the segment size of a GSO packet, 0 otherwise.
    pub gso_size: u16,
    /// `skb->gso_segs`.
    pub gso_segs: u16,
    /// The offloaded outer VLAN tag, when `meta` has [`M_VLAN`](crate::facts::M_VLAN).
    pub vlan_tci: u16,
    /// Offset of the IP or ARP header in `data`: the link-layer header's length.
    pub l3: u16,
    /// `M_*` bits ([`facts`](crate::facts)).
    pub meta: u8,
    /// The handle's layer.
    pub layer: u8,
    /// The `F_*` presence bits of the facts.
    pub flags: u16,
    /// The packet from its first byte, link-layer header included.
    pub data: &'a [u8],
}

impl<'a> Record<'a> {
    /// Reads a record from the ring buffer's bytes; `None` if it is malformed.
    pub fn parse(b: &'a [u8]) -> Option<Record<'a>> {
        let u16_at = |at: usize| Some(u16::from_ne_bytes(b.get(at..at + 2)?.try_into().ok()?));
        let u32_at = |at: usize| Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?));
        let timestamp = u64::from_ne_bytes(b.get(0..8)?.try_into().ok()?);
        let cap_len = u32_at(12)? as usize;
        Some(Record {
            timestamp,
            len: u32_at(8)?,
            ifindex: u32_at(16)?,
            ingress_ifindex: u32_at(20)?,
            gso_size: u16_at(24)?,
            gso_segs: u16_at(26)?,
            vlan_tci: u16_at(28)?,
            l3: u16_at(30)?,
            meta: *b.get(32)?,
            layer: *b.get(33)?,
            flags: u16_at(34)?,
            data: b.get(RECORD_HEADER..RECORD_HEADER.checked_add(cap_len)?)?,
        })
    }
}

/// The local end opened it: a connect, an active TCP flow, a UDP flow it sent first.
pub const EV_OUTBOUND: u8 = 1 << 0;
/// The call was refused.
pub const EV_BLOCKED: u8 = 1 << 1;
/// FLOW: a UDP socket went away, so each of its flows is deleted. Not an event of its own.
pub const EV_RELEASED: u8 = 1 << 2;

/// Size of an event record.
pub const EVENT_RECORD: usize = 88;

/// An event record of the FLOW and SOCKET layers, as `struct avulse_event` describes it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EventRecord {
    /// `bpf_ktime_get_ns()` when it happened.
    pub timestamp: u64,
    /// The socket's cookie.
    pub endpoint: u64,
    /// The socket it came from; always 0 on Linux.
    pub parent_endpoint: u64,
    /// The process (thread group) that made the socket; 0 when unknown.
    pub pid: u32,
    /// The event (`avulse_filter::Event` as a number).
    pub event: u8,
    /// The IP protocol.
    pub protocol: u8,
    /// 4 or 6.
    pub family: u8,
    /// `EV_*` bits.
    pub flags: u8,
    /// The local port.
    pub local_port: u16,
    /// The remote port.
    pub remote_port: u16,
    /// The local address, IPv4 as `::ffff:a.b.c.d`.
    pub local_addr: [u8; 16],
    /// The remote address, IPv4 as `::ffff:a.b.c.d`.
    pub remote_addr: [u8; 16],
    /// The process's name (its `comm`), NUL-padded; empty when unknown.
    pub comm: [u8; 16],
}

impl EventRecord {
    /// Reads an event record from the ring buffer's bytes; `None` if it is too short.
    pub fn parse(b: &[u8]) -> Option<EventRecord> {
        let b: &[u8; EVENT_RECORD] = b.get(..EVENT_RECORD)?.try_into().ok()?;
        let u16_at = |at: usize| u16::from_ne_bytes([b[at], b[at + 1]]);
        let u32_at = |at: usize| u32::from_ne_bytes(b[at..at + 4].try_into().unwrap());
        let u64_at = |at: usize| u64::from_ne_bytes(b[at..at + 8].try_into().unwrap());
        let bytes16 = |at: usize| -> [u8; 16] { b[at..at + 16].try_into().unwrap() };
        Some(EventRecord {
            timestamp: u64_at(0),
            endpoint: u64_at(8),
            parent_endpoint: u64_at(16),
            pid: u32_at(24),
            event: b[28],
            protocol: b[29],
            family: b[30],
            flags: b[31],
            local_port: u16_at(32),
            remote_port: u16_at(34),
            local_addr: bytes16(36),
            remote_addr: bytes16(52),
            comm: bytes16(68),
        })
    }

    /// The process's name, if the kernel told it.
    pub fn comm(&self) -> Option<&str> {
        let n = self.comm.iter().position(|&c| c == 0).unwrap_or(16);
        std::str::from_utf8(&self.comm[..n])
            .ok()
            .filter(|s| !s.is_empty())
    }
}

/// Indexes of the per-CPU statistics in `avulse_stats`.
pub mod stat {
    /// Stolen and copied to the ring.
    pub const DIVERTED: usize = 0;
    /// Copied, and passed on.
    pub const SNIFFED: usize = 1;
    /// Dropped.
    pub const DROPPED: usize = 2;
    /// Matched, but the ring was full: passed.
    pub const RING_FULL: usize = 3;
    /// The heartbeat was stale: passed.
    pub const OWNER_GONE: usize = 4;
    /// Matched, but too large to divert whole: passed.
    pub const TOO_BIG: usize = 5;
    /// The copy to the ring failed: passed.
    pub const LOAD_ERR: usize = 6;
    /// The matcher slot was empty: passed.
    pub const NO_MATCHER: usize = 7;
    /// Seen with the mark of a higher-priority handle.
    pub const IMPOSTOR: usize = 8;
    /// How many there are.
    pub const COUNT: usize = 9;
}

/// The upper half of a mark, which says what it is.
pub const MARK_MASK: u32 = 0xffff_0000;
/// `MARK_INJECTED | tc_priority` marks an injected packet. Handles of the same or a higher
/// priority skip it; lower ones see an impostor.
pub const MARK_INJECTED: u32 = 0x4156_0000;
/// `MARK_REDIRECT | ifindex` marks an inbound packet sent through `lo`, with `skb->priority` set
/// to [`PRIO_INJECTED`]` | tc_priority`. Every handle skips it on `lo`'s egress; on `lo`'s ingress,
/// the first handle's program marks it `MARK_INJECTED | tc_priority` and redirects it to the
/// ingress of interface `ifindex`.
pub const MARK_REDIRECT: u32 = 0x4157_0000;
/// The upper half of `skb->priority` of an inbound packet sent through `lo` ([`MARK_REDIRECT`]);
/// the lower half is the TC priority of the handle that sent it.
pub const PRIO_INJECTED: u32 = 0x4158_0000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_parse() {
        let mut b = vec![0u8; RECORD_HEADER];
        b[0..8].copy_from_slice(&7u64.to_ne_bytes());
        b[8..12].copy_from_slice(&100u32.to_ne_bytes());
        b[12..16].copy_from_slice(&3u32.to_ne_bytes());
        b[30..32].copy_from_slice(&14u16.to_ne_bytes());
        b[32] = 5;
        b.extend([1, 2, 3, 4]);
        let r = Record::parse(&b).unwrap();
        assert_eq!((r.timestamp, r.len, r.l3, r.meta), (7, 100, 14, 5));
        assert_eq!(r.data, [1, 2, 3]);
        assert_eq!(Record::parse(&b[..RECORD_HEADER + 2]), None);
        assert_eq!(Record::parse(&b[..10]), None);
    }

    #[test]
    fn event_records_parse() {
        let mut b = vec![0u8; EVENT_RECORD];
        b[0..8].copy_from_slice(&9u64.to_ne_bytes());
        b[8..16].copy_from_slice(&0x1234u64.to_ne_bytes());
        b[24..28].copy_from_slice(&42u32.to_ne_bytes());
        b[28..32].copy_from_slice(&[4, 6, 4, EV_OUTBOUND]);
        b[32..34].copy_from_slice(&5000u16.to_ne_bytes());
        b[34..36].copy_from_slice(&80u16.to_ne_bytes());
        b[36 + 15] = 1;
        b[52 + 15] = 2;
        b[68..72].copy_from_slice(b"curl");
        let e = EventRecord::parse(&b).unwrap();
        assert_eq!((e.timestamp, e.endpoint, e.pid), (9, 0x1234, 42));
        assert_eq!(
            (e.event, e.protocol, e.family, e.flags),
            (4, 6, 4, EV_OUTBOUND)
        );
        assert_eq!((e.local_port, e.remote_port), (5000, 80));
        assert_eq!((e.local_addr[15], e.remote_addr[15]), (1, 2));
        assert_eq!(e.comm(), Some("curl"));
        assert_eq!(EventRecord::parse(&b[..EVENT_RECORD - 1]), None);
        assert_eq!(EventRecord::default().comm(), None);
    }

    #[test]
    fn config_is_40_bytes() {
        assert_eq!(size_of::<Config>(), 40);
    }
}
