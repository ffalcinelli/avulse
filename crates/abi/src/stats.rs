//! A handle's counters.

/// What happened to the packets or events a handle's filter matched, since it opened
/// (`avulse::Handle::stats`). The kernel counts most of them; counters a backend
/// does not keep stay 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    /// Diverted to the handle.
    pub diverted: u64,
    /// Copied to the handle and passed on (`SNIFF`).
    pub sniffed: u64,
    /// Dropped (`DROP`).
    pub dropped: u64,
    /// Passed on because the kernel's buffer to the handle was full.
    pub ring_full: u64,
    /// Passed on because the owner stopped answering (the handle fails open).
    pub owner_gone: u64,
    /// Passed on because they were too large to divert whole.
    pub too_big: u64,
    /// Passed on because the kernel could not copy them.
    pub load_errors: u64,
    /// Lost in user space: the receive queue was full, or they waited longer than `QUEUE_TIME`.
    pub queue_drops: u64,
}
