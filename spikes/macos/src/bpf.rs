//! `/dev/bpf` as a capture and injection path: device settings, frames written on one end of the
//! `feth` pair reaching the stack on the other, `lo0`, a self-addressed frame on the default
//! interface, and write and capture rates.

use std::time::{Duration, Instant};

use avulse_proto::{Link, Packet};
use avulse_spike_macos::{eth, finish, icmp_echo, ipv4, udp};

use crate::net::*;
use crate::report::Report;

const SEC: Duration = Duration::from_secs(1);

pub fn run(r: &mut Report) {
    let (host_mac, _) = if_addrs(HOST);
    let Some(host_mac) = host_mac else {
        return r.fail(
            "setup",
            format!("{HOST} has no MAC address: is the feth pair up?"),
        );
    };
    r.info("host_mac", mac_str(&host_mac));
    settings(r);
    feth_icmp(r, host_mac);
    feth_udp(r, host_mac);
    loopback(r);
    self_addressed(r);
    rates(r, host_mac);
}

fn settings(r: &mut Report) {
    for (name, want) in [("blen_2m", 2 << 20), ("blen_16m", 16 << 20)] {
        match Bpf::open(WIRE, want, true) {
            Ok(b) => r.info(
                name,
                format!("asked {want}, got {} (dlt {})", b.blen, b.dlt),
            ),
            Err(e) => r.fail(name, e.to_string()),
        }
    }
    match Bpf::open("lo0", 1 << 20, true) {
        Ok(b) => r.info("lo0_dlt", format!("{} (0 = DLT_NULL, 12 = DLT_RAW)", b.dlt)),
        Err(e) => r.fail("lo0_dlt", e.to_string()),
    }
    match Bpf::open(WIRE, 1 << 20, true) {
        Ok(b) => {
            let before = b.get(BIOCGHDRCMPLT);
            let set = b.set(BIOCSHDRCMPLT, 1);
            r.check(
                "hdrcmplt",
                set.is_ok(),
                format!("default {before:?}, set 1: {set:?}"),
            );
        }
        Err(e) => r.fail("hdrcmplt", e.to_string()),
    }
}

/// An echo request from a made-up peer, written on `feth0` with a spoofed source MAC: the stack
/// on `feth1` must answer, and its reply arrives back on `feth0`.
fn feth_icmp(r: &mut Report, host_mac: [u8; 6]) {
    let res = (|| -> std::io::Result<String> {
        let wire = Bpf::open(WIRE, 1 << 20, true)?;
        wire.set(BIOCSHDRCMPLT, 1)?;
        let mirror = Bpf::open(WIRE, 1 << 20, true)?;
        let host = Bpf::open(HOST, 1 << 20, true)?;
        let pkt = finish(
            ipv4(PEER_IP, HOST_IP, 1, &icmp_echo(0x4156, 1, b"avulse")),
            Link::Ip,
        );
        let frame = eth(host_mac, PEER_MAC, 0x0800, &pkt);
        wire.flush();
        let sent = Instant::now();
        let n = wire.write(&frame)?;
        let is_reply = |rec: &Record| {
            let p = Packet::parse(&rec.data, Link::Ethernet);
            p.icmp().is_some_and(|i| i.icmp_type() == 0)
                && p.ipv4().is_some_and(|ip| ip.dst().octets() == PEER_IP)
        };
        let reply = wire.wait_for(2 * SEC, is_reply)?;
        let rtt = sent.elapsed();
        let own = mirror.wait_for(SEC / 2, |rec| rec.data == frame)?;
        let at_host = host.wait_for(SEC / 2, |rec| rec.data == frame)?;
        Ok(format!(
            "wrote {n} bytes; reply on {WIRE}: {} (dst MAC {}, after {rtt:?}); our frame seen by \
             another bpf on {WIRE}: {}; seen on {HOST}: {}",
            reply.is_some(),
            reply
                .as_ref()
                .map(|r| mac_str(&r.data[..6]))
                .unwrap_or_default(),
            own.is_some(),
            at_host
                .as_ref()
                .map(|r| format!(
                    "yes, caplen {} datalen {} hdrlen {} ts {:?}",
                    r.caplen, r.datalen, r.hdrlen, r.ts
                ))
                .unwrap_or("no".into()),
        ))
    })();
    match res {
        Ok(s) => r.check("feth_icmp_inbound", s.contains("reply on feth0: true"), s),
        Err(e) => r.fail("feth_icmp_inbound", e.to_string()),
    }
}

/// A UDP datagram written on `feth0` reaches a socket bound on `feth1`'s address, which sees
/// `feth1` as the interface: inbound injection through the peer.
fn feth_udp(r: &mut Report, host_mac: [u8; 6]) {
    let res = (|| -> std::io::Result<(bool, String)> {
        let rx = UdpRx::bind(HOST_IP, 47001)?;
        let wire = Bpf::open(WIRE, 1 << 20, false)?;
        wire.set(BIOCSHDRCMPLT, 1)?;
        let pkt = finish(
            ipv4(PEER_IP, HOST_IP, 17, &udp(47000, 47001, b"hello")),
            Link::Ip,
        );
        wire.write(&eth(host_mac, PEER_MAC, 0x0800, &pkt))?;
        let got = rx.recv(2 * SEC)?;
        let want = ifindex(HOST);
        Ok(match got {
            Some(d) => (
                d.ifindex == Some(want),
                format!(
                    "received {} bytes from {}, ifindex {:?} ({HOST} is {want})",
                    d.len,
                    ip_str(d.src),
                    d.ifindex
                ),
            ),
            None => (false, "nothing received".into()),
        })
    })();
    match res {
        Ok((ok, s)) => r.check("feth_udp_inbound", ok, s),
        Err(e) => r.fail("feth_udp_inbound", e.to_string()),
    }
}

/// A datagram written to `lo0` (DLT_NULL: a 4-byte address family in host order).
fn loopback(r: &mut Report) {
    let res = (|| -> std::io::Result<(bool, String)> {
        let rx = UdpRx::bind([127, 0, 0, 1], 47002)?;
        let lo = Bpf::open("lo0", 1 << 20, true)?;
        let pkt = finish(
            ipv4(
                [127, 0, 0, 1],
                [127, 0, 0, 1],
                17,
                &udp(47000, 47002, b"lo"),
            ),
            Link::Ip,
        );
        let mut frame = (libc::AF_INET as u32).to_ne_bytes().to_vec();
        frame.extend_from_slice(&pkt);
        let w = lo.write(&frame);
        let got = rx.recv(2 * SEC)?;
        Ok((
            got.is_some(),
            format!(
                "write: {:?}; received: {}",
                w.map_err(|e| e.to_string()),
                got.map(|d| format!("{} bytes, ifindex {:?}", d.len, d.ifindex))
                    .unwrap_or("no".into())
            ),
        ))
    })();
    match res {
        Ok((ok, s)) => r.check("lo0_inject", ok, s),
        Err(e) => r.fail("lo0_inject", e.to_string()),
    }
}

/// A frame addressed to the default interface's own MAC and IP, written on that interface: does
/// bpf loop it back into the stack? (Inbound reinjection on a real NIC needs that.)
fn self_addressed(r: &mut Report) {
    let res = (|| -> std::io::Result<(bool, String)> {
        let Some(ifname) = default_iface() else {
            return Ok((false, "no default route".into()));
        };
        let (Some(mac), Some(ip)) = if_addrs(&ifname) else {
            return Ok((false, format!("{ifname} has no MAC or IPv4 address")));
        };
        let rx = UdpRx::bind([0, 0, 0, 0], 47003)?;
        let b = Bpf::open(&ifname, 1 << 20, true)?;
        b.set(BIOCSHDRCMPLT, 1)?;
        let src = [ip[0], ip[1], ip[2], ip[3].wrapping_add(1)];
        let pkt = finish(ipv4(src, ip, 17, &udp(47000, 47003, b"self")), Link::Ip);
        let w = b.write(&eth(mac, PEER_MAC, 0x0800, &pkt));
        let got = rx.recv(2 * SEC)?;
        Ok((
            got.is_some(),
            format!(
                "{ifname} {} {}: write {:?}; received: {}",
                mac_str(&mac),
                ip_str(ip),
                w.map_err(|e| e.to_string()),
                got.map(|d| format!("{} bytes, ifindex {:?}", d.len, d.ifindex))
                    .unwrap_or("no".into())
            ),
        ))
    })();
    // A miss is an answer, not a failure of the probe.
    match res {
        Ok((ok, s)) => r.info("default_iface_self_inject", format!("delivered: {ok}; {s}")),
        Err(e) => r.fail("default_iface_self_inject", e.to_string()),
    }
}

/// Write rate on `feth0`, and how many frames a bpf reader on `feth1` and the socket see.
fn rates(r: &mut Report, host_mac: [u8; 6]) {
    let res = (|| -> std::io::Result<String> {
        let rx = UdpRx::bind(HOST_IP, 47004)?;
        let wire = Bpf::open(WIRE, 1 << 20, false)?;
        wire.set(BIOCSHDRCMPLT, 1)?;
        let reader = Bpf::open(HOST, 16 << 20, false)?;
        let count: u32 = 50_000;
        let frames: Vec<Vec<u8>> = [64usize, 1400]
            .iter()
            .map(|&size| {
                let pkt = finish(
                    ipv4(PEER_IP, HOST_IP, 17, &udp(47000, 47004, &vec![0x41; size])),
                    Link::Ip,
                );
                eth(host_mac, PEER_MAC, 0x0800, &pkt)
            })
            .collect();
        let mut out = String::new();
        for frame in &frames {
            reader.flush();
            let before = reader.stats()?;
            let t = Instant::now();
            let mut errors = 0;
            for _ in 0..count {
                if wire.write(frame).is_err() {
                    errors += 1;
                }
            }
            let dt = t.elapsed();
            let mut captured = 0;
            while let Ok(recs) = reader.read(SEC / 4) {
                if recs.is_empty() {
                    break;
                }
                captured += recs.len();
            }
            let after = reader.stats()?;
            let delivered = rx.drain(SEC / 4);
            out.push_str(&format!(
                "{} bytes: {:.0} writes/s ({errors} errors); bpf on {HOST} read {captured}, \
                 stats recv {} drop {}; socket got {delivered} of {count}\n",
                frame.len(),
                f64::from(count) / dt.as_secs_f64(),
                after.0.wrapping_sub(before.0),
                after.1.wrapping_sub(before.1),
            ));
        }
        Ok(out)
    })();
    match res {
        Ok(s) => r.info("rates", s),
        Err(e) => r.fail("rates", e.to_string()),
    }
}
