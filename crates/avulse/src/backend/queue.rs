//! The receive queue: packets wait here between what the platform captured and `recv`, within the
//! limits of the queue parameters.

use std::collections::VecDeque;

use crate::{Address, Param};

/// A packet waiting in a handle's queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub addr: Address,
    /// From the IP header at the NETWORK layers, from the Ethernet header at ETHERNET.
    pub data: Vec<u8>,
}

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

    /// Puts back a packet [`pop`](Queue::pop) took, first in line.
    pub fn unpop(&mut self, e: Entry) {
        self.bytes += e.data.len() as u64;
        self.entries.push_front(e);
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use avulse_filter::Layer;

    use super::*;

    fn queued(timestamp: i64, len: usize) -> Entry {
        let mut addr = Address::new(Layer::Network);
        addr.timestamp = timestamp;
        Entry {
            addr,
            data: vec![0; len],
        }
    }

    fn params(length: u64, time_ms: u64, size: u64) -> [u64; 3] {
        let mut p = [0; 3];
        p[Param::QueueLength.index()] = length;
        p[Param::QueueTime.index()] = time_ms;
        p[Param::QueueSize.index()] = size;
        p
    }

    #[test]
    fn queue_limits() {
        let ms = 1_000_000;
        // Length.
        let mut q = Queue::new(params(2, 100, 1000));
        for t in 0..3 {
            q.push(queued(t, 10));
        }
        assert_eq!(q.drops, 1);
        assert_eq!(q.pop(0).unwrap().addr.timestamp, 0);
        assert_eq!(q.pop(0).unwrap().addr.timestamp, 1);
        assert!(q.pop(0).is_none() && q.is_empty());

        // Size: the bytes of the packets.
        let mut q = Queue::new(params(10, 100, 25));
        for t in 0..3 {
            q.push(queued(t, 10));
        }
        assert_eq!(q.drops, 1);
        q.pop(0);
        q.push(queued(3, 15));
        assert_eq!(q.drops, 1);
        q.push(queued(4, 1));
        assert_eq!(q.drops, 2);

        // Time: packets older than QUEUE_TIME at the pop are dropped.
        let mut q = Queue::new(params(10, 100, 1000));
        q.push(queued(0, 1));
        q.push(queued(50 * ms, 1));
        q.push(queued(120 * ms, 1));
        let e = q.pop(140 * ms).unwrap();
        assert_eq!((e.addr.timestamp, q.drops), (50 * ms, 1));
        q.set(Param::QueueTime, 10);
        assert!(q.pop(140 * ms).is_none());
        assert_eq!(q.drops, 2);

        // A new limit applies to the next packets.
        let mut q = Queue::new(params(1, 100, 1000));
        q.push(queued(0, 1));
        q.set(Param::QueueLength, 2);
        q.push(queued(0, 1));
        assert_eq!(q.drops, 0);
    }
}
