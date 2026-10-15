//! The receive queue: packets wait here between the ring buffer and `recv`, within the limits of
//! the queue parameters.

use std::collections::VecDeque;

use super::record::Entry;
use crate::Param;

pub struct Queue {
    entries: VecDeque<Entry>,
    bytes: u64,
    /// The parameters, indexed by [`Param::index`].
    params: [u64; 3],
    /// Packets dropped: the queue was full, or they waited too long.
    pub drops: u64,
}

impl Queue {
    pub fn new(params: [u64; 3]) -> Queue {
        Queue {
            entries: VecDeque::new(),
            bytes: 0,
            params,
            drops: 0,
        }
    }

    pub fn set(&mut self, param: Param, value: u64) {
        self.params[param.index()] = value;
    }

    fn param(&self, param: Param) -> u64 {
        self.params[param.index()]
    }

    /// Queues `e`, or drops it if the queue is full (`QUEUE_LENGTH` packets or `QUEUE_SIZE`
    /// bytes).
    pub fn push(&mut self, e: Entry) {
        let len = e.data.len() as u64;
        if self.entries.len() as u64 >= self.param(Param::QueueLength)
            || self.bytes + len > self.param(Param::QueueSize)
        {
            self.drops += 1;
            return;
        }
        self.bytes += len;
        self.entries.push_back(e);
    }

    /// The oldest packet that has waited at most `QUEUE_TIME` at `now` (nanoseconds of the
    /// timestamps' clock). Older ones are dropped.
    pub fn pop(&mut self, now: i64) -> Option<Entry> {
        let max_wait = self.param(Param::QueueTime) as i64 * 1_000_000;
        while let Some(e) = self.entries.pop_front() {
            self.bytes -= e.data.len() as u64;
            if now - e.addr.timestamp <= max_wait {
                return Some(e);
            }
            self.drops += 1;
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
