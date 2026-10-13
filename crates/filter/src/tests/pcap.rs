//! A minimal pcap writer, for feeding test frames to tshark.

use alloc::vec::Vec;

pub(super) const LINKTYPE_ETHERNET: u32 = 1;
pub(super) const LINKTYPE_RAW: u32 = 101;

/// A classic pcap file (microsecond timestamps, little-endian) holding `frames` in order.
pub(super) fn write<'a>(linktype: u32, frames: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    for word in [0u32, 0, 65535, linktype] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    for (i, f) in frames.into_iter().enumerate() {
        let len = f.len() as u32;
        for word in [i as u32, 0, len, len] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.extend_from_slice(f);
    }
    out
}
