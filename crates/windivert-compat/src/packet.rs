//! WinDivert's view of an IP packet (`WinDivertHelperParsePacket`), which its helpers compute
//! checksums and hashes on. It differs from [`avulse_proto`] where WinDivert does (for example, a
//! TCP header whose options are cut short is kept, shortened), so the helpers give WinDivert's
//! results byte for byte.

/// Where the transport header is, and what it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Transport {
    /// TCP, with its header length (at most what the packet holds).
    Tcp(usize),
    Udp,
    Icmp,
    Icmpv6,
}

/// The headers WinDivert finds in a packet, as offsets into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct View {
    /// IPv6 rather than IPv4. The IP header is at offset 0.
    pub ipv6: bool,
    /// The last next-header or IPv4 protocol.
    pub protocol: u8,
    /// A fragment: MF set or a non-zero offset.
    pub fragment: bool,
    /// More fragments follow.
    pub mf: bool,
    /// The fragment offset, as WinDivert reads it (non-zero for every fragment but the first).
    pub frag_off: u16,
    /// The IP length is longer than the packet.
    pub truncated: bool,
    /// The transport header and its offset.
    pub transport: Option<(Transport, usize)>,
    /// Where the payload starts, after the headers WinDivert parsed.
    pub payload: usize,
    /// The payload's length, within the IP length.
    pub payload_len: usize,
}

fn be16(p: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([p[at], p[at + 1]])
}

/// Parses `p` as WinDivert does (`WinDivertHelperParsePacketEx`). `None` where WinDivert fails:
/// shorter than 20 bytes, neither IPv4 nor IPv6, or an IP header longer than the packet or than
/// its own length.
pub(crate) fn parse(p: &[u8]) -> Option<View> {
    if p.len() < 20 {
        return None;
    }
    let ipv6;
    let mut protocol;
    let total_len;
    let packet_len;
    let mut data;
    let mut frag_off = 0;
    let mut mf = false;
    let mut fragment = false;
    match p[0] >> 4 {
        4 => {
            ipv6 = false;
            let header_len = usize::from(p[0] & 0xf) * 4;
            total_len = usize::from(be16(p, 2));
            if header_len < 20 || total_len < header_len || p.len() < header_len {
                return None;
            }
            protocol = p[9];
            frag_off = u16::from_be_bytes([p[6] & 0x1f, p[7]]);
            mf = p[6] & 0x20 != 0;
            fragment = mf || frag_off != 0;
            packet_len = total_len.min(p.len());
            data = header_len;
        }
        6 => {
            ipv6 = true;
            if p.len() < 40 {
                return None;
            }
            protocol = p[6];
            total_len = usize::from(be16(p, 4)) + 40;
            packet_len = total_len.min(p.len());
            data = 40;
            while frag_off == 0 && packet_len - data >= 2 {
                let left = packet_len - data;
                let len = match protocol {
                    // Fragment: only the first one counts.
                    44 if !fragment && left >= 8 => {
                        frag_off = u16::from_be_bytes([p[data + 2], p[data + 3] & 0xf8]);
                        mf = p[data + 3] & 0x01 != 0;
                        fragment = true;
                        8
                    }
                    // Authentication header: in 32-bit words, minus 2.
                    51 => (usize::from(p[data + 1]) + 2) * 4,
                    // Hop-by-hop, destination options, routing, mobility: in 8-byte units, minus 1.
                    0 | 60 | 43 | 135 => (usize::from(p[data + 1]) + 1) * 8,
                    _ => break,
                };
                if left < len {
                    break;
                }
                protocol = p[data];
                data += len;
            }
        }
        _ => return None,
    }
    let mut view = View {
        ipv6,
        protocol,
        fragment,
        mf,
        frag_off,
        truncated: total_len > p.len(),
        transport: None,
        payload: data,
        payload_len: packet_len - data,
    };
    if frag_off != 0 {
        return Some(view);
    }
    let left = packet_len - data;
    let (transport, len) = match protocol {
        6 if left >= 20 && p[data + 12] >> 4 >= 5 => {
            let len = (usize::from(p[data + 12] >> 4) * 4).min(left);
            (Transport::Tcp(len), len)
        }
        17 if left >= 8 => (Transport::Udp, 8),
        1 if !ipv6 && left >= 8 => (Transport::Icmp, 8),
        58 if ipv6 && left >= 8 => (Transport::Icmpv6, 8),
        _ => return Some(view),
    };
    view.transport = Some((transport, data));
    view.payload = data + len;
    view.payload_len = left - len;
    Some(view)
}
