//! What Phase 6's bpf backend needs to know (Step 31a): how to tell a captured packet's
//! direction (`BIOCSDIRECTION`, or the extended header's flags, with the sending process), what
//! `utun` captures look like, and which paths can send IPv6 packets inbound.
//!
//! The ioctl numbers are XNU's (`bsd/net/bpf.h`); the `env` probe dumps the SDK's header, which
//! says which of them are public.

use std::io;
use std::mem::size_of;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::time::Duration;

use avulse_proto::{Link, Packet};
use avulse_spike_macos::{eth, finish, ipv4, ipv6, udp};

use crate::inject::{UTUN_LOCAL, UTUN_PEER, open_utun};
use crate::net::*;
use crate::report::Report;

const SEC: Duration = Duration::from_secs(1);

const IOC_OUT: u32 = 0x4000_0000;
const IOC_IN: u32 = 0x8000_0000;

const fn ioc(dir: u32, n: u32) -> libc::c_ulong {
    (dir | (4 << 16) | ((b'B' as u32) << 8) | n) as libc::c_ulong
}

/// `_IOW('B', 122, u_int)`: records start with a `struct bpf_hdr_ext`.
const BIOCSEXTHDR: libc::c_ulong = ioc(IOC_IN, 122);
/// `_IOR('B', 138, int)` and `_IOW('B', 139, int)`: `BPF_D_NONE`, `_IN`, `_OUT`, `_INOUT` (0 to
/// 3).
const BIOCGDIRECTION: libc::c_ulong = ioc(IOC_OUT, 138);
const BIOCSDIRECTION: libc::c_ulong = ioc(IOC_IN, 139);

/// feth1's IPv6 address and the peer's, which the workflow sets up (`ndp -s` for the peer).
const HOST_IP6: [u8; 16] = [0xfd, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const PEER_IP6: [u8; 16] = [0xfd, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

pub fn run(r: &mut Report) {
    let Some(host_mac) = if_addrs(HOST).0 else {
        return r.fail(
            "setup",
            format!("{HOST} has no MAC address: is the feth pair up?"),
        );
    };
    direction(r, host_mac);
    ext_header(r, host_mac, HOST);
    ext_header(r, host_mac, "lo0");
    utun_capture(r);
    ipv6_inbound(r);
}

/// Sends one datagram out of `feth1` (to the static-ARP peer, port 47100) and writes one in from
/// `feth0` (port 47101).
fn both_ways(host_mac: [u8; 6]) -> io::Result<()> {
    let s = UdpSocket::bind(SocketAddr::from((HOST_IP, 0)))?;
    s.send_to(b"out", SocketAddr::from((PEER_IP, 47100)))?;
    let wire = Bpf::open(WIRE, 1 << 20, false)?;
    wire.set(BIOCSHDRCMPLT, 1)?;
    let pkt = finish(
        ipv4(PEER_IP, HOST_IP, 17, &udp(47000, 47101, b"in")),
        Link::Ip,
    );
    wire.write(&eth(host_mac, PEER_MAC, 0x0800, &pkt))?;
    Ok(())
}

/// The UDP destination port of a captured frame, at the link type `dlt`.
fn udp_port(rec: &Record, dlt: u32) -> Option<u16> {
    let (data, link) = match dlt {
        1 => (&rec.data[..], Link::Ethernet),
        _ => (rec.data.get(4..)?, Link::Ip),
    };
    let p = Packet::parse(data, link);
    p.udp().map(|u| u.dst_port())
}

/// Everything a bpf device reads within `timeout`.
fn drain(b: &Bpf, timeout: Duration) -> io::Result<Vec<Record>> {
    let mut all = Vec::new();
    loop {
        let recs = b.read(timeout)?;
        if recs.is_empty() {
            return Ok(all);
        }
        all.extend(recs);
    }
}

fn direction(r: &mut Report, host_mac: [u8; 6]) {
    let res = (|| -> io::Result<String> {
        let mut out = String::new();
        for want in [1u32, 2, 3] {
            let b = Bpf::open(HOST, 1 << 20, true)?;
            let before = b.get(BIOCGDIRECTION);
            let set = b.set(BIOCSDIRECTION, want);
            let after = b.get(BIOCGDIRECTION);
            b.flush();
            both_ways(host_mac)?;
            let seen: Vec<u16> = drain(&b, SEC / 2)?
                .iter()
                .filter_map(|rec| udp_port(rec, b.dlt))
                .filter(|p| (47100..=47101).contains(p))
                .collect();
            out.push_str(&format!(
                "set {want}: default {before:?}, set {set:?}, now {after:?}; saw ports {seen:?}\n"
            ));
        }
        Ok(out)
    })();
    match res {
        // Port 47100 is the outbound datagram, 47101 the inbound one.
        Ok(s) => r.check(
            "direction_ioctl",
            s.contains("set 1: default Ok") && s.contains("saw ports [47101]"),
            s,
        ),
        Err(e) => r.fail("direction_ioctl", e.to_string()),
    }
}

/// `struct bpf_hdr_ext`: the flags (bit 0 = outbound) at 18, the PID at 20 and the command name
/// at 24, if the layout is the one XNU's header gives.
fn ext_header(r: &mut Report, host_mac: [u8; 6], ifname: &str) {
    let name = format!("ext_header_{ifname}");
    let res = (|| -> io::Result<String> {
        let b = Bpf::open(ifname, 1 << 20, true)?;
        let set = b.set(BIOCSEXTHDR, 1);
        b.flush();
        if ifname == "lo0" {
            let rx = UdpSocket::bind("127.0.0.1:47102")?;
            let s = UdpSocket::bind("127.0.0.1:0")?;
            s.send_to(b"lo", "127.0.0.1:47102")?;
            drop(rx);
        } else {
            both_ways(host_mac)?;
        }
        let mut out = format!("BIOCSEXTHDR: {set:?}; dlt {}\n", b.dlt);
        for rec in drain(&b, SEC / 2)? {
            let Some(port) = udp_port(&rec, b.dlt) else {
                continue;
            };
            if !(47100..=47102).contains(&port) {
                continue;
            }
            let h = &rec.hdr;
            let u16_at = |o: usize| h.get(o..o + 2).map(|s| u16::from_ne_bytes([s[0], s[1]]));
            let i32_at = |o: usize| {
                h.get(o..o + 4)
                    .map(|s| i32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
            };
            let comm = h.get(24..41).map(|s| {
                let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
                String::from_utf8_lossy(&s[..end]).into_owned()
            });
            out.push_str(&format!(
                "port {port}: hdrlen {}, flags {:?}, pid {:?}, comm {comm:?}, link head {}, hdr {}\n",
                h.len(),
                u16_at(18),
                i32_at(20),
                mac_str(&rec.data[..rec.data.len().min(16)]),
                mac_str(h),
            ));
        }
        Ok(out)
    })();
    match res {
        Ok(s) => r.check(&name, s.contains("hdrlen") && !s.contains("hdrlen 18,"), s),
        Err(e) => r.fail(&name, e.to_string()),
    }
}

/// What a bpf device on a `utun` captures, for a datagram the device's owner writes in.
fn utun_capture(r: &mut Report) {
    let res = (|| -> io::Result<String> {
        let (fd, ifname) = open_utun()?;
        Command::new("ifconfig")
            .args([
                &ifname,
                "inet",
                &ip_str(UTUN_LOCAL),
                &ip_str(UTUN_PEER),
                "up",
            ])
            .output()?;
        let b = Bpf::open(&ifname, 1 << 20, true)?;
        let rx = UdpSocket::bind(SocketAddr::from((UTUN_LOCAL, 47103)))?;
        let pkt = finish(
            ipv4(UTUN_PEER, UTUN_LOCAL, 17, &udp(47000, 47103, b"utun")),
            Link::Ip,
        );
        let mut frame = (libc::AF_INET as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&pkt);
        // SAFETY: `frame` is live for the call.
        unsafe { libc::write(fd.as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
        rx.set_read_timeout(Some(SEC))?;
        let got = rx.recv(&mut [0; 64]).is_ok();
        let recs = drain(&b, SEC / 2)?;
        let heads: Vec<String> = recs
            .iter()
            .map(|r| mac_str(&r.data[..r.data.len().min(8)]))
            .collect();
        Ok(format!(
            "{ifname}: dlt {} (0 = NULL, 12 = RAW); delivered {got}; records {heads:?}",
            b.dlt
        ))
    })();
    match res {
        Ok(s) => r.info("utun_capture", s),
        Err(e) => r.fail("utun_capture", e.to_string()),
    }
}

fn sockaddr_in6(ip: [u8; 16], port: u16) -> libc::sockaddr_in6 {
    // SAFETY: an all-zero sockaddr_in6 is valid.
    let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sa.sin6_len = size_of::<libc::sockaddr_in6>() as u8;
    sa.sin6_family = libc::AF_INET6 as u8;
    sa.sin6_port = port.to_be();
    sa.sin6_addr.s6_addr = ip;
    sa
}

/// Inbound IPv6 without a peer interface: a raw IPv6 socket given the whole packet (with and
/// without an `IPV6_HDRINCL`-style option), and a `utun` device.
fn ipv6_inbound(r: &mut Report) {
    let rx = match UdpSocket::bind(SocketAddr::from((HOST_IP6, 47110))) {
        Ok(s) => s,
        Err(e) => return r.fail("ipv6_setup", format!("bind [fd77::1]:47110: {e}")),
    };
    let _ = rx.set_read_timeout(Some(SEC));
    let received = |rx: &UdpSocket| {
        let mut buf = [0; 64];
        rx.recv_from(&mut buf)
            .map(|(n, from)| format!("{n} bytes from {from}"))
            .unwrap_or_else(|e| format!("nothing ({e})"))
    };
    let pkt = finish(
        ipv6(PEER_IP6, HOST_IP6, 17, &udp(47000, 47110, b"raw6")),
        Link::Ip,
    );
    // SAFETY: a socket call; the descriptor is owned below.
    let raw = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if raw < 0 {
        r.fail("ipv6_raw", io::Error::last_os_error().to_string());
    } else {
        // SAFETY: a fresh descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut out = String::new();
        // 36 is Linux's IPV6_HDRINCL; the env probe says whether the SDK has one.
        for opt in [None, Some(36)] {
            if let Some(opt) = opt {
                let one: libc::c_int = 1;
                // SAFETY: an int option.
                let rc = unsafe {
                    libc::setsockopt(
                        fd.as_raw_fd(),
                        libc::IPPROTO_IPV6,
                        opt,
                        (&one as *const libc::c_int).cast(),
                        size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                out.push_str(&format!(
                    "setsockopt {opt}: {}; ",
                    if rc < 0 {
                        io::Error::last_os_error().to_string()
                    } else {
                        "ok".into()
                    }
                ));
            }
            let sa = sockaddr_in6(HOST_IP6, 0);
            // SAFETY: `pkt` and `sa` are live for the call.
            let n = unsafe {
                libc::sendto(
                    fd.as_raw_fd(),
                    pkt.as_ptr().cast(),
                    pkt.len(),
                    0,
                    (&sa as *const libc::sockaddr_in6).cast(),
                    size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            };
            let sent = if n < 0 {
                io::Error::last_os_error().to_string()
            } else {
                format!("{n}")
            };
            out.push_str(&format!("sendto {sent}, received {}\n", received(&rx)));
        }
        r.check("ipv6_raw", out.contains("bytes from"), out);
    }
    let res = (|| -> io::Result<String> {
        let (fd, ifname) = open_utun()?;
        let up = Command::new("ifconfig").args([&ifname, "up"]).output()?;
        let mut frame = (libc::AF_INET6 as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&pkt);
        // SAFETY: `frame` is live for the call.
        let n = unsafe { libc::write(fd.as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
        Ok(format!(
            "{ifname} up: {}; write {n}; received {}",
            up.status.success(),
            received(&rx)
        ))
    })();
    match res {
        Ok(s) => r.check("ipv6_utun", s.contains("bytes from"), s),
        Err(e) => r.fail("ipv6_utun", e.to_string()),
    }
}
