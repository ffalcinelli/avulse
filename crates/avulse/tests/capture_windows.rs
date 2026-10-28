//! The Windows backend against the driver, `avulse.sys`, in the `windows` VM. It needs
//! Administrator rights and the driver, so it runs only with `AVULSE_DRIVER` set to the path of
//! `avulse.sys`; the backend installs and starts the service from there
//! (drivers/windows/scripts/test.ps1 does all of it):
//!
//! ```text
//! $env:AVULSE_DRIVER = "C:\build\avulse\drivers\windows\driver\target\release\avulse_package\avulse.sys"
//! cargo test -p avulse --test capture_windows -- --test-threads=1
//! ```

#![cfg(target_os = "windows")]

use std::time::{Duration, Instant};

use avulse::{Error, Flags, Handle, Layer, MAX_PACKET_LEN, OpenOptions, Param, Shutdown};

fn enabled() -> bool {
    if std::env::var_os("AVULSE_DRIVER").is_some() {
        return true;
    }
    eprintln!("skipped: set AVULSE_DRIVER to avulse.sys and run as Administrator (in the VM)");
    false
}

fn sniff(filter: &str) -> Handle {
    Handle::open(filter, Layer::Network, 0, Flags::SNIFF)
        .unwrap_or_else(|e| panic!("opening `{filter}`: {e}"))
}

/// A receive times out, after about its timeout, also with a zero timeout.
#[test]
fn receive_times_out() {
    if !enabled() {
        return;
    }
    let h = sniff("udp.dstport == 9");
    let mut buf = vec![0; MAX_PACKET_LEN];
    let start = Instant::now();
    let r = h.recv_timeout(&mut buf, Duration::from_millis(200));
    assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
    assert!(
        start.elapsed() >= Duration::from_millis(150),
        "{:?}",
        start.elapsed()
    );
    let r = h.recv_timeout(&mut buf, Duration::ZERO);
    assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
    h.close().unwrap();
}

/// Shutting down wakes a receiver waiting in another thread, and later receives fail too.
#[test]
fn shutdown_ends_receives() {
    if !enabled() {
        return;
    }
    let h = sniff("udp.dstport == 9");
    std::thread::scope(|s| {
        let t = s.spawn(|| {
            let mut buf = vec![0; MAX_PACKET_LEN];
            h.recv(&mut buf).map(|(n, _)| n)
        });
        std::thread::sleep(Duration::from_millis(300));
        h.shutdown(Shutdown::Recv).unwrap();
        let r = t.join().unwrap();
        assert!(matches!(r, Err(Error::Shutdown)), "{r:?}");
    });
    let mut buf = vec![0; MAX_PACKET_LEN];
    let r = h.recv_timeout(&mut buf, Duration::from_secs(1));
    assert!(matches!(r, Err(Error::Shutdown)), "{r:?}");
}

/// Parameters reach the driver, counters come back, and what the driver cannot do yet is refused
/// as unsupported.
#[test]
fn parameters_counters_and_limits() {
    if !enabled() {
        return;
    }
    let h = OpenOptions::new()
        .flags(Flags::SNIFF)
        .open("tcp", Layer::Network)
        .unwrap();
    h.set_param(Param::QueueLength, 64).unwrap();
    assert_eq!(h.param(Param::QueueLength), 64);
    let s = h.stats().unwrap();
    assert_eq!((s.diverted, s.sniffed, s.queue_drops), (0, 0, 0));
    let r = h.send(&[0x45; 20], &avulse::Address::new(Layer::Network));
    assert!(matches!(r, Err(Error::Unsupported(_))), "{r:?}");

    // Diverting needs the packet hooks.
    let r = Handle::open("tcp", Layer::Network, 0, Flags::NONE);
    assert!(matches!(r, Err(Error::Unsupported(_))), "{r:?}");
    // The installed driver is used as it is.
    let h2 = Handle::open(
        "udp",
        Layer::NetworkForward,
        5,
        Flags::SNIFF | Flags::NO_INSTALL,
    );
    assert!(h2.is_ok(), "{:?}", h2.err());
}

/// Interfaces by index, and an unknown name.
#[test]
fn interfaces() {
    if !enabled() {
        return;
    }
    let h = OpenOptions::new()
        .flags(Flags::SNIFF)
        .interfaces(["1"])
        .open("ip", Layer::Network);
    assert!(h.is_ok(), "{:?}", h.err());
    let r = OpenOptions::new()
        .flags(Flags::SNIFF)
        .interfaces(["no such interface"])
        .open("ip", Layer::Network);
    assert!(matches!(r, Err(Error::InvalidArgument(_))), "{r:?}");
}

/// Many handles opened and closed in turn: each close releases the driver's side.
#[test]
fn many_handles() {
    if !enabled() {
        return;
    }
    for i in 0..200 {
        let h = sniff(&format!("tcp.dstport == {i}"));
        if i % 2 == 0 {
            h.close().unwrap();
        }
    }
}
