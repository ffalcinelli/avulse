//! The registry of open handles, shared by every process through a map pinned on the BPF
//! filesystem, and changed under a file lock.
//!
//! An entry records who opened a handle (process ID and start time), its TC priority and its TC
//! filters. The filters of a process that dies without closing its handles stay attached, and pass
//! every packet once its heartbeat stops; [`Registry::reap`] removes them and their entries. It
//! runs at every open, and in `avulse cleanup`.
//!
//! Without a BPF filesystem at `/sys/fs/bpf`, handles still open, but nothing is shared: priority
//! 0 orders handles within the process only, and nothing reaps.

use std::collections::HashSet;
use std::ffi::CStr;
use std::io;
use std::path::Path;

use avulse_ebpf::loader::{self, Attachment, HashMap, Hook};

use super::sys;

/// The registry's directory and map. The map's name carries the version of the entry layout.
const DIR: &str = "/sys/fs/bpf/avulse";
const PIN: &str = "/sys/fs/bpf/avulse/registry-1";
const LOCK: &CStr = c"/run/avulse.lock";
const MAX_ENTRIES: u32 = 1024;
/// The most TC filters an entry records: two per interface.
pub const MAX_ATTACH: usize = 128;
/// The most bytes of the filter an entry keeps (for display only).
const FILTER_MAX: usize = 2048;

const ATTACH_AT: usize = 48;
const ATTACH_LEN: usize = 12;
const FILTER_AT: usize = ATTACH_AT + MAX_ATTACH * ATTACH_LEN;
const VALUE_SIZE: usize = FILTER_AT + FILTER_MAX;

/// An entry of the registry. Its layout, in host byte order:
///
/// | Offset | Size | |
/// | --- | --- | --- |
/// | 0 | 4 | process ID |
/// | 4 | 4 | TC priority |
/// | 8 | 8 | process start time (`/proc/<pid>/stat`) |
/// | 16 | 8 | when it opened (`CLOCK_MONOTONIC`, ns) |
/// | 24 | 8 | flags |
/// | 32 | 1 | layer |
/// | 34 | 2 | priority |
/// | 36 | 4 | number of TC filters |
/// | 40 | 4 | length of the filter text |
/// | 48 | 128 × 12 | TC filters: ifindex (4), hook (1: 0 ingress, 1 egress), 0 (1), TC priority (2), handle (4) |
/// | 1584 | 2048 | the filter, as text (cut) |
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    pub pid: u32,
    pub start_time: u64,
    pub tc_priority: u16,
    pub timestamp: i64,
    pub flags: u64,
    pub layer: u8,
    pub priority: i16,
    pub attachments: Vec<Attachment>,
    pub filter: String,
}

impl Entry {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; VALUE_SIZE];
        let n = self.attachments.len().min(MAX_ATTACH);
        let mut filter_len = self.filter.len().min(FILTER_MAX);
        while !self.filter.is_char_boundary(filter_len) {
            filter_len -= 1;
        }
        b[0..4].copy_from_slice(&self.pid.to_ne_bytes());
        b[4..8].copy_from_slice(&(self.tc_priority as u32).to_ne_bytes());
        b[8..16].copy_from_slice(&self.start_time.to_ne_bytes());
        b[16..24].copy_from_slice(&self.timestamp.to_ne_bytes());
        b[24..32].copy_from_slice(&self.flags.to_ne_bytes());
        b[32] = self.layer;
        b[34..36].copy_from_slice(&self.priority.to_ne_bytes());
        b[36..40].copy_from_slice(&(n as u32).to_ne_bytes());
        b[40..44].copy_from_slice(&(filter_len as u32).to_ne_bytes());
        for (i, a) in self.attachments.iter().take(n).enumerate() {
            let at = ATTACH_AT + i * ATTACH_LEN;
            b[at..at + 4].copy_from_slice(&a.ifindex.to_ne_bytes());
            b[at + 4] = (a.hook == Hook::Egress) as u8;
            b[at + 6..at + 8].copy_from_slice(&a.priority.to_ne_bytes());
            b[at + 8..at + 12].copy_from_slice(&a.handle.to_ne_bytes());
        }
        b[FILTER_AT..FILTER_AT + filter_len].copy_from_slice(&self.filter.as_bytes()[..filter_len]);
        b
    }

    pub fn decode(b: &[u8]) -> Option<Entry> {
        if b.len() != VALUE_SIZE {
            return None;
        }
        let u16_at = |at: usize| u16::from_ne_bytes([b[at], b[at + 1]]);
        let u32_at = |at: usize| u32::from_ne_bytes(b[at..at + 4].try_into().unwrap());
        let u64_at = |at: usize| u64::from_ne_bytes(b[at..at + 8].try_into().unwrap());
        let n = (u32_at(36) as usize).min(MAX_ATTACH);
        let filter_len = (u32_at(40) as usize).min(FILTER_MAX);
        let attachments = (0..n)
            .map(|i| {
                let at = ATTACH_AT + i * ATTACH_LEN;
                Attachment {
                    ifindex: u32_at(at),
                    hook: if b[at + 4] == 0 {
                        Hook::Ingress
                    } else {
                        Hook::Egress
                    },
                    priority: u16_at(at + 6),
                    handle: u32_at(at + 8),
                }
            })
            .collect();
        Some(Entry {
            pid: u32_at(0),
            tc_priority: u32_at(4) as u16,
            start_time: u64_at(8),
            timestamp: u64_at(16) as i64,
            flags: u64_at(24),
            layer: b[32],
            priority: u16_at(34) as i16,
            attachments,
            filter: String::from_utf8_lossy(&b[FILTER_AT..FILTER_AT + filter_len]).into_owned(),
        })
    }

    pub fn alive(&self) -> bool {
        sys::alive(self.pid, self.start_time)
    }
}

/// The registry, locked: other processes wait to open or close handles until it is dropped.
pub struct Registry {
    map: Option<HashMap>,
    _lock: sys::FileLock,
}

fn io_error(e: loader::Error) -> io::Error {
    match e {
        loader::Error::Sys(call, e) => io::Error::new(e.kind(), format!("{call}: {e}")),
        e => io::Error::other(e.to_string()),
    }
}

fn not_found(e: &loader::Error) -> bool {
    matches!(e, loader::Error::Sys(_, e) if e.kind() == io::ErrorKind::NotFound)
}

impl Registry {
    /// Locks the registry, creating it if needed. Without a BPF filesystem (or the rights to
    /// create the map), it works with no map: nothing is shared.
    pub fn lock() -> io::Result<Registry> {
        let lock = sys::FileLock::acquire(LOCK)?;
        Ok(Registry {
            map: Self::open_map(true).ok(),
            _lock: lock,
        })
    }

    /// Locks the registry if it exists, without creating it.
    pub fn lock_existing() -> io::Result<Option<Registry>> {
        let lock = sys::FileLock::acquire(LOCK)?;
        match Self::open_map(false) {
            Ok(map) => Ok(Some(Registry {
                map: Some(map),
                _lock: lock,
            })),
            Err(e) if not_found(&e) => Ok(None),
            Err(e) => Err(io_error(e)),
        }
    }

    fn open_map(create: bool) -> Result<HashMap, loader::Error> {
        let pin = Path::new(PIN);
        match HashMap::open_pinned(pin, 8, VALUE_SIZE) {
            Err(e) if create && not_found(&e) => {
                let _ = std::fs::create_dir(DIR);
                let map = HashMap::create("avulse_reg", 8, VALUE_SIZE, MAX_ENTRIES)?;
                match map.pin(pin) {
                    Ok(()) => Ok(map),
                    // Another process pinned one first (it does not hold the lock to create).
                    Err(_) => HashMap::open_pinned(pin, 8, VALUE_SIZE),
                }
            }
            r => r,
        }
    }

    /// Every entry, with its key.
    pub fn entries(&self) -> io::Result<Vec<(u64, Entry)>> {
        let Some(map) = &self.map else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for key in map.keys().map_err(io_error)? {
            if let Some(value) = map.get(&key).map_err(io_error)?
                && let Some(entry) = Entry::decode(&value)
            {
                out.push((u64::from_ne_bytes(key.try_into().unwrap()), entry));
            }
        }
        Ok(out)
    }

    /// Removes the entries of dead processes and detaches their TC filters, except those a live
    /// entry also lists (the kernel reused the handle). Returns how many it removed.
    pub fn reap(&self) -> io::Result<usize> {
        let Some(map) = &self.map else {
            return Ok(0);
        };
        let entries = self.entries()?;
        let live: HashSet<Attachment> = entries
            .iter()
            .filter(|(_, e)| e.alive())
            .flat_map(|(_, e)| e.attachments.iter().copied())
            .collect();
        let mut reaped = 0;
        for (key, entry) in entries.iter().filter(|(_, e)| !e.alive()) {
            for a in entry.attachments.iter().filter(|a| !live.contains(a)) {
                // Already gone if its interface went, or someone removed it.
                let _ = a.detach();
            }
            map.remove(&key.to_ne_bytes()).map_err(io_error)?;
            reaped += 1;
        }
        Ok(reaped)
    }

    /// The highest TC priority of a live handle, 0 if there is none.
    pub fn max_tc_priority(&self) -> io::Result<u16> {
        Ok(self
            .entries()?
            .iter()
            .filter(|(_, e)| e.alive())
            .map(|(_, e)| e.tc_priority)
            .max()
            .unwrap_or(0))
    }

    /// Adds an entry, and returns its key; `None` without a registry.
    pub fn add(&self, entry: &Entry) -> io::Result<Option<u64>> {
        let Some(map) = &self.map else {
            return Ok(None);
        };
        let value = entry.encode();
        loop {
            let key = sys::random_u64()?;
            match map.insert(&key.to_ne_bytes(), &value) {
                Ok(()) => return Ok(Some(key)),
                Err(loader::Error::Sys(_, e)) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(io_error(e)),
            }
        }
    }

    pub fn remove(&self, key: u64) -> io::Result<()> {
        match &self.map {
            Some(map) => map.remove(&key.to_ne_bytes()).map_err(io_error),
            None => Ok(()),
        }
    }
}
