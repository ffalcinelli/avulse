//! Inbound reinjection without a peer interface: a raw IP socket (`IP_HDRINCL`) and a `utun`
//! device. Each test sends a UDP datagram "from outside" to a local address and reports whether
//! a bound socket gets it, and on which interface.

use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::time::Duration;

use avulse_proto::Link;
use avulse_spike_macos::{finish, ipv4, udp};
use libc::c_void;

use crate::net::*;
use crate::report::Report;

const SEC: Duration = Duration::from_secs(1);
const UTUN_LOCAL: [u8; 4] = [10, 77, 9, 1];
const UTUN_PEER: [u8; 4] = [10, 77, 9, 2];
/// An address that is not on any local subnet (TEST-NET-3 would do too, but this one is routed).
const FAR: [u8; 4] = [93, 184, 216, 34];

pub fn run(r: &mut Report) {
    let default = default_iface().and_then(|i| if_addrs(&i).1.map(|ip| (i, ip)));
    raw_socket(r, &default);
    utun(r, &default);
}

fn describe(got: Option<Datagram>) -> (bool, String) {
    match got {
        Some(d) => (
            true,
            format!(
                "received {} bytes from {}, ifindex {:?}",
                d.len,
                ip_str(d.src),
                d.ifindex
            ),
        ),
        None => (false, "not received".into()),
    }
}

fn raw_socket(r: &mut Report, default: &Option<(String, [u8; 4])>) {
    // SAFETY: plain socket calls on a descriptor we own.
    let fd = unsafe {
        let raw = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
        if raw < 0 {
            return r.fail("raw_socket", io::Error::last_os_error().to_string());
        }
        OwnedFd::from_raw_fd(raw)
    };
    let one: libc::c_int = 1;
    // SAFETY: IP_HDRINCL takes an int.
    unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            (&one as *const libc::c_int).cast::<c_void>(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    let send = |pkt: &[u8], dst: [u8; 4]| -> io::Result<usize> {
        let sa = sockaddr_in(dst, 0);
        // SAFETY: `pkt` and `sa` are live for the call.
        let n = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                pkt.as_ptr().cast(),
                pkt.len(),
                0,
                (&sa as *const libc::sockaddr_in).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if n < 0 { err("sendto") } else { Ok(n as usize) }
    };
    // BSD raw sockets historically want `ip_len` and `ip_off` in host byte order.
    let host_order = |mut p: Vec<u8>| {
        let len = u16::from_be_bytes([p[2], p[3]]);
        let off = u16::from_be_bytes([p[6], p[7]]);
        p[2..4].copy_from_slice(&len.to_ne_bytes());
        p[6..8].copy_from_slice(&off.to_ne_bytes());
        p
    };
    let mut cases = vec![("raw_to_feth1", PEER_IP, HOST_IP, 47020u16)];
    if let Some((_, ip)) = default {
        cases.push(("raw_far_source_to_default", FAR, *ip, 47021));
    }
    for (name, src, dst, port) in cases {
        let res = (|| -> io::Result<(bool, String)> {
            let rx = UdpRx::bind(dst, port)?;
            let pkt = finish(ipv4(src, dst, 17, &udp(47000, port, b"raw")), Link::Ip);
            let mut out = String::new();
            let mut any = false;
            for (order, p) in [
                ("network order", pkt.clone()),
                ("host order", host_order(pkt)),
            ] {
                let w = send(&p, dst);
                let (ok, s) = describe(rx.recv(SEC)?);
                any |= ok;
                out.push_str(&format!(
                    "{order}: send {:?}, {s}; ",
                    w.map_err(|e| e.to_string())
                ));
            }
            Ok((any, format!("{} -> {}: {out}", ip_str(src), ip_str(dst))))
        })();
        match res {
            Ok((ok, s)) => r.check(name, ok, s),
            Err(e) => r.fail(name, e.to_string()),
        }
    }
}

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

const AF_SYSTEM: i32 = 32;
const AF_SYS_CONTROL: u16 = 2;
const SYSPROTO_CONTROL: i32 = 2;
const UTUN_OPT_IFNAME: i32 = 2;

/// Opens a new `utunN` and returns it with its name.
fn open_utun() -> io::Result<(OwnedFd, String)> {
    // SAFETY: kernel-control socket calls with correctly sized structs.
    unsafe {
        let raw = libc::socket(AF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL);
        if raw < 0 {
            return err("socket(PF_SYSTEM)");
        }
        let fd = OwnedFd::from_raw_fd(raw);
        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0; 96],
        };
        let name = b"com.apple.net.utun_control";
        info.ctl_name[..name.len()].copy_from_slice(name);
        if libc::ioctl(raw, CTLIOCGINFO, &mut info as *mut CtlInfo) < 0 {
            return err("CTLIOCGINFO");
        }
        let sa = SockaddrCtl {
            sc_len: size_of::<SockaddrCtl>() as u8,
            sc_family: AF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: info.ctl_id,
            sc_unit: 0,
            sc_reserved: [0; 5],
        };
        let len = size_of::<SockaddrCtl>() as libc::socklen_t;
        if libc::connect(raw, (&sa as *const SockaddrCtl).cast(), len) < 0 {
            return err("connect(utun)");
        }
        let mut buf = [0u8; 32];
        let mut blen = buf.len() as libc::socklen_t;
        let p = buf.as_mut_ptr().cast::<c_void>();
        if libc::getsockopt(raw, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, p, &mut blen) < 0 {
            return err("UTUN_OPT_IFNAME");
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Ok((fd, String::from_utf8_lossy(&buf[..end]).into_owned()))
    }
}

fn utun(r: &mut Report, default: &Option<(String, [u8; 4])>) {
    let (fd, name) = match open_utun() {
        Ok(x) => x,
        Err(e) => return r.fail("utun_open", e.to_string()),
    };
    let cfg = Command::new("ifconfig")
        .args([&name, "inet", &ip_str(UTUN_LOCAL), &ip_str(UTUN_PEER), "up"])
        .output();
    r.check(
        "utun_open",
        cfg.as_ref().is_ok_and(|o| o.status.success()),
        format!("{name} (ifindex {}), ifconfig: {cfg:?}", ifindex(&name)),
    );
    let mut cases = vec![
        ("utun_to_own_address", UTUN_PEER, UTUN_LOCAL, 47030u16),
        ("utun_to_feth1_address", UTUN_PEER, HOST_IP, 47031),
        ("utun_far_source_to_feth1", FAR, HOST_IP, 47032),
    ];
    if let Some((_, ip)) = default {
        cases.push(("utun_far_source_to_default", FAR, *ip, 47033));
    }
    for (case, src, dst, port) in cases {
        let res = (|| -> io::Result<(bool, String)> {
            let rx = UdpRx::bind(dst, port)?;
            let pkt = finish(ipv4(src, dst, 17, &udp(47000, port, b"utun")), Link::Ip);
            // utun frames start with the address family, in network byte order.
            let mut frame = (libc::AF_INET as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(&pkt);
            // SAFETY: `frame` is live for the call.
            let n = unsafe { libc::write(fd.as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
            let w = if n < 0 {
                io::Error::last_os_error().to_string()
            } else {
                format!("{n}")
            };
            let (ok, s) = describe(rx.recv(SEC)?);
            Ok((
                ok,
                format!(
                    "{} -> {}: write {w}, {s} ({name} is {})",
                    ip_str(src),
                    ip_str(dst),
                    ifindex(&name)
                ),
            ))
        })();
        match res {
            Ok((ok, s)) => r.check(case, ok, s),
            Err(e) => r.fail(case, e.to_string()),
        }
    }
}
