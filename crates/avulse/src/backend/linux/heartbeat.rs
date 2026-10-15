//! The owner's heartbeat. One thread per process rewrites the configuration of every open handle
//! every [`PERIOD`], with the time. The programs pass every packet once it is older than
//! [`TIMEOUT`], so a process that dies without closing its handles stops diverting (and dropping)
//! traffic within seconds; the registry then reaps its filters.

use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::Duration;

use avulse_ebpf::abi::Config;
use avulse_ebpf::loader::ConfigWriter;

use super::sys;

pub const PERIOD: Duration = Duration::from_millis(500);
pub const TIMEOUT: Duration = Duration::from_secs(3);

/// A handle's configuration, and the map it goes to.
pub struct Beat {
    config: Mutex<Config>,
    writer: ConfigWriter,
}

impl Beat {
    pub fn new(config: Config, writer: ConfigWriter) -> Beat {
        Beat {
            config: Mutex::new(config),
            writer,
        }
    }

    /// Changes the configuration and writes it, with a fresh heartbeat.
    pub fn update(
        &self,
        change: impl FnOnce(&mut Config),
    ) -> Result<(), avulse_ebpf::loader::Error> {
        let mut config = self.config.lock().unwrap_or_else(|e| e.into_inner());
        change(&mut config);
        config.heartbeat_ns = sys::now_ns() as u64;
        config.heartbeat_timeout_ns = TIMEOUT.as_nanos() as u64;
        self.writer.set(&config)
    }
}

struct Beats {
    list: Mutex<Vec<Weak<Beat>>>,
    wake: Condvar,
}

fn beats() -> &'static Beats {
    static BEATS: OnceLock<Beats> = OnceLock::new();
    BEATS.get_or_init(|| {
        std::thread::Builder::new()
            .name("avulse-heartbeat".into())
            .spawn(run)
            .expect("spawning the heartbeat thread");
        Beats {
            list: Mutex::new(Vec::new()),
            wake: Condvar::new(),
        }
    })
}

/// Keeps `beat` alive until it is dropped.
pub fn add(beat: &Arc<Beat>) {
    let beats = beats();
    beats
        .list
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(Arc::downgrade(beat));
    beats.wake.notify_one();
}

fn run() {
    let beats = beats();
    let mut list = beats.list.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        list.retain(|w| w.strong_count() > 0);
        if list.is_empty() {
            list = beats.wake.wait(list).unwrap_or_else(|e| e.into_inner());
            continue;
        }
        for beat in list.iter().filter_map(Weak::upgrade) {
            // A failure leaves the heartbeat to go stale: the handle then fails open.
            let _ = beat.update(|_| {});
        }
        list = beats
            .wake
            .wait_timeout(list, PERIOD)
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
}
