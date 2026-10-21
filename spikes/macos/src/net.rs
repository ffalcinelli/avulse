//! macOS plumbing for the probes: bpf devices, interface lookups, and a UDP receiver that
//! reports the interface a datagram arrived on.
//!
//! The network the workflow sets up: `feth0` and `feth1` are peers (a frame sent out of one is
//! received by the other). `feth1` has 10.77.1.1/24, and 10.77.1.2 is a static ARP entry for
//! [`PEER_MAC`], so the stack's answers go back out of `feth1` to `feth0`. `feth0` has no address:
//! it plays the wire.

use std::ffi::CString;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use libc::{c_int, c_ulong, c_void};

pub const WIRE: &str = "feth0";
pub const HOST: &str = "feth1";
pub const HOST_IP: [u8; 4] = [10, 77, 1, 1];
pub const PEER_IP: [u8; 4] = [10, 77, 1, 2];
pub const PEER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x99];

const IOC_VOID: u32 = 0x2000_0000;
const IOC_OUT: u32 = 0x4000_0000;
const IOC_IN: u32 = 0x8000_0000;

const fn ioc(dir: u32, group: u8, n: u32, size: usize) -> c_ulong {
    (dir | ((size as u32 & 0x1fff) << 16) | ((group as u32) << 8) | n) as c_ulong
}

pub const BIOCGBLEN: c_ulong = ioc(IOC_OUT, b'B', 102, 4);
pub const BIOCSBLEN: c_ulong = ioc(IOC_IN | IOC_OUT, b'B', 102, 4);
pub const BIOCFLUSH: c_ulong = ioc(IOC_VOID, b'B', 104, 0);
pub const BIOCGDLT: c_ulong = ioc(IOC_OUT, b'B', 106, 4);
pub const BIOCSETIF: c_ulong = ioc(IOC_IN, b'B', 108, 32);
pub const BIOCGSTATS: c_ulong = ioc(IOC_OUT, b'B', 111, 8);
pub const BIOCIMMEDIATE: c_ulong = ioc(IOC_IN, b'B', 112, 4);
pub const BIOCGHDRCMPLT: c_ulong = ioc(IOC_OUT, b'B', 116, 4);
pub const BIOCSHDRCMPLT: c_ulong = ioc(IOC_IN, b'B', 117, 4);
pub const BIOCSSEESENT: c_ulong = ioc(IOC_IN, b'B', 119, 4);
/// `_IOWR('N', 3, struct ctl_info)`.
pub const CTLIOCGINFO: c_ulong = ioc(IOC_IN | IOC_OUT, b'N', 3, 100);

pub fn err<T>(what: &str) -> io::Result<T> {
    let e = io::Error::last_os_error();
    Err(io::Error::new(e.kind(), format!("{what}: {e}")))
}

/// `ioctl` with a `u32` argument (in or out).
pub fn ioctl_u32(fd: c_int, req: c_ulong, v: &mut u32) -> io::Result<()> {
    // SAFETY: every request used with this takes a pointer to a `u_int`.
    if unsafe { libc::ioctl(fd, req, v as *mut u32) } < 0 {
        return err("ioctl");
    }
    Ok(())
}

/// A bpf device bound to an interface.
pub struct Bpf {
    pub fd: OwnedFd,
    pub blen: usize,
    pub dlt: u32,
}

/// One captured packet.
pub struct Record {
    pub ts: Duration,
    pub caplen: usize,
    pub datalen: usize,
    pub hdrlen: usize,
    pub data: Vec<u8>,
}

impl Bpf {
    /// Opens the first free `/dev/bpfN`, with the largest buffer it takes (up to `want`),
    /// immediate mode, `see_sent`, and binds it to `ifname`.
    pub fn open(ifname: &str, want: u32, see_sent: bool) -> io::Result<Bpf> {
        let mut fd = None;
        for n in 0..256 {
            let path = CString::new(format!("/dev/bpf{n}")).unwrap_or_default();
            // SAFETY: a NUL-terminated path.
            let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
            if raw >= 0 {
                // SAFETY: a fresh descriptor we own.
                fd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
                break;
            }
            if io::Error::last_os_error().raw_os_error() != Some(libc::EBUSY) {
                return err(&format!("open /dev/bpf{n}"));
            }
        }
        let Some(fd) = fd else {
            return err("no free bpf device");
        };
        let raw = fd.as_raw_fd();
        let mut blen = want;
        // The buffer size must be set before the interface.
        let _ = ioctl_u32(raw, BIOCSBLEN, &mut blen);
        let mut ifr = [0u8; 32];
        let name = ifname.as_bytes();
        ifr[..name.len().min(15)].copy_from_slice(&name[..name.len().min(15)]);
        // SAFETY: BIOCSETIF takes a `struct ifreq` (32 bytes), name first.
        if unsafe { libc::ioctl(raw, BIOCSETIF, ifr.as_mut_ptr()) } < 0 {
            return err(&format!("BIOCSETIF {ifname}"));
        }
        let mut one = 1;
        ioctl_u32(raw, BIOCIMMEDIATE, &mut one)?;
        let mut seesent = u32::from(see_sent);
        ioctl_u32(raw, BIOCSSEESENT, &mut seesent)?;
        let mut blen = 0;
        ioctl_u32(raw, BIOCGBLEN, &mut blen)?;
        let mut dlt = 0;
        ioctl_u32(raw, BIOCGDLT, &mut dlt)?;
        Ok(Bpf {
            fd,
            blen: blen as usize,
            dlt,
        })
    }

    pub fn set(&self, req: c_ulong, mut v: u32) -> io::Result<()> {
        ioctl_u32(self.fd.as_raw_fd(), req, &mut v)
    }

    pub fn get(&self, req: c_ulong) -> io::Result<u32> {
        let mut v = 0;
        ioctl_u32(self.fd.as_raw_fd(), req, &mut v)?;
        Ok(v)
    }

    /// `(received, dropped)`.
    pub fn stats(&self) -> io::Result<(u32, u32)> {
        let mut s = [0u32; 2];
        // SAFETY: BIOCGSTATS fills a `struct bpf_stat` (two `u_int`s).
        if unsafe { libc::ioctl(self.fd.as_raw_fd(), BIOCGSTATS, s.as_mut_ptr()) } < 0 {
            return err("BIOCGSTATS");
        }
        Ok((s[0], s[1]))
    }

    pub fn flush(&self) {
        // SAFETY: BIOCFLUSH takes no argument.
        unsafe { libc::ioctl(self.fd.as_raw_fd(), BIOCFLUSH) };
    }

    pub fn write(&self, frame: &[u8]) -> io::Result<usize> {
        // SAFETY: `frame` is valid for its length.
        let n = unsafe { libc::write(self.fd.as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
        if n < 0 {
            return err("write");
        }
        Ok(n as usize)
    }

    /// The records of one read, waiting up to `timeout`; empty on a timeout.
    pub fn read(&self, timeout: Duration) -> io::Result<Vec<Record>> {
        if !poll_in(self.fd.as_raw_fd(), timeout)? {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; self.blen];
        // SAFETY: `buf` is `blen` bytes, as bpf requires.
        let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return err("read");
        }
        Ok(parse_records(&buf[..n as usize]))
    }

    /// Reads until `want` matches a record or `timeout` passes.
    pub fn wait_for(
        &self,
        timeout: Duration,
        mut want: impl FnMut(&Record) -> bool,
    ) -> io::Result<Option<Record>> {
        let end = Instant::now() + timeout;
        while let Some(left) = end.checked_duration_since(Instant::now()) {
            for rec in self.read(left)? {
                if want(&rec) {
                    return Ok(Some(rec));
                }
            }
        }
        Ok(None)
    }
}

/// `struct bpf_hdr` as macOS lays it out for user space: a 32-bit `timeval32`, `caplen`,
/// `datalen`, `hdrlen`; records are aligned to 4 bytes (`BPF_WORDALIGN`).
pub fn parse_records(mut b: &[u8]) -> Vec<Record> {
    let mut out = Vec::new();
    while b.len() >= 18 {
        let u32_at = |o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let sec = u32_at(0);
        let usec = u32_at(4);
        let caplen = u32_at(8) as usize;
        let datalen = u32_at(12) as usize;
        let hdrlen = usize::from(u16::from_ne_bytes([b[16], b[17]]));
        if hdrlen < 18 || hdrlen + caplen > b.len() {
            break;
        }
        out.push(Record {
            ts: Duration::new(u64::from(sec), usec.saturating_mul(1000)),
            caplen,
            datalen,
            hdrlen,
            data: b[hdrlen..hdrlen + caplen].to_vec(),
        });
        let next = (hdrlen + caplen).div_ceil(4) * 4;
        if next >= b.len() {
            break;
        }
        b = &b[next..];
    }
    out
}

pub fn poll_in(fd: c_int, timeout: Duration) -> io::Result<bool> {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis().min(i32::MAX as u128) as c_int;
    // SAFETY: one valid pollfd.
    let n = unsafe { libc::poll(&mut p, 1, ms) };
    if n < 0 {
        return err("poll");
    }
    Ok(n > 0)
}

pub fn ifindex(name: &str) -> u32 {
    let c = CString::new(name).unwrap_or_default();
    // SAFETY: a NUL-terminated name.
    unsafe { libc::if_nametoindex(c.as_ptr()) }
}

/// The MAC address and the first IPv4 address of an interface.
pub fn if_addrs(name: &str) -> (Option<[u8; 6]>, Option<[u8; 4]>) {
    let (mut mac, mut ip) = (None, None);
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates the list, freed below.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return (None, None);
    }
    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: a node of the list getifaddrs returned.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        // SAFETY: `ifa_name` is a NUL-terminated string.
        let n = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
        if n.to_bytes() != name.as_bytes() || ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: `ifa_addr` points to a sockaddr of the family it names.
        let family = c_int::from(unsafe { (*ifa.ifa_addr).sa_family });
        if family == libc::AF_LINK {
            // SAFETY: an AF_LINK address is a `sockaddr_dl`.
            let dl = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_dl) };
            let (nlen, alen) = (usize::from(dl.sdl_nlen), usize::from(dl.sdl_alen));
            if alen == 6 {
                let data = dl.sdl_data.as_ptr() as *const u8;
                let mut m = [0u8; 6];
                // SAFETY: the address follows the name inside the sockaddr.
                unsafe { std::ptr::copy_nonoverlapping(data.add(nlen), m.as_mut_ptr(), 6) };
                mac = Some(m);
            }
        } else if family == libc::AF_INET && ip.is_none() {
            // SAFETY: an AF_INET address is a `sockaddr_in`.
            let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
            ip = Some(sin.sin_addr.s_addr.to_ne_bytes());
        }
    }
    // SAFETY: the list from getifaddrs.
    unsafe { libc::freeifaddrs(ifap) };
    (mac, ip)
}

/// The interface of the default route.
pub fn default_iface() -> Option<String> {
    let out = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface: ").map(str::to_string))
}

pub fn sockaddr_in(ip: [u8; 4], port: u16) -> libc::sockaddr_in {
    // SAFETY: an all-zero sockaddr_in is valid.
    let mut sa: libc::sockaddr_in = unsafe { zeroed() };
    sa.sin_len = size_of::<libc::sockaddr_in>() as u8;
    sa.sin_family = libc::AF_INET as u8;
    sa.sin_port = port.to_be();
    sa.sin_addr.s_addr = u32::from_ne_bytes(ip);
    sa
}

/// A UDP socket bound to `ip:port` that reports each datagram's interface (`IP_PKTINFO`).
pub struct UdpRx(OwnedFd);

/// A received datagram.
pub struct Datagram {
    pub len: usize,
    pub src: [u8; 4],
    pub ifindex: Option<u32>,
}

impl UdpRx {
    pub fn bind(ip: [u8; 4], port: u16) -> io::Result<UdpRx> {
        // SAFETY: plain socket calls on a descriptor we own.
        unsafe {
            let raw = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if raw < 0 {
                return err("socket");
            }
            let fd = OwnedFd::from_raw_fd(raw);
            let one: c_int = 1;
            let p = (&one as *const c_int).cast::<c_void>();
            let sz = size_of::<c_int>() as libc::socklen_t;
            libc::setsockopt(raw, libc::SOL_SOCKET, libc::SO_REUSEADDR, p, sz);
            libc::setsockopt(raw, libc::IPPROTO_IP, libc::IP_PKTINFO, p, sz);
            let big: c_int = 8 << 20;
            let pb = (&big as *const c_int).cast::<c_void>();
            libc::setsockopt(raw, libc::SOL_SOCKET, libc::SO_RCVBUF, pb, sz);
            let sa = sockaddr_in(ip, port);
            let len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
            if libc::bind(raw, (&sa as *const libc::sockaddr_in).cast(), len) < 0 {
                return err("bind");
            }
            Ok(UdpRx(fd))
        }
    }

    pub fn recv(&self, timeout: Duration) -> io::Result<Option<Datagram>> {
        if !poll_in(self.0.as_raw_fd(), timeout)? {
            return Ok(None);
        }
        let mut buf = [0u8; 65536];
        let mut cbuf = [0u64; 32];
        // SAFETY: all-zero is valid for these C structs.
        let mut from: libc::sockaddr_in = unsafe { zeroed() };
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: as above.
        let mut msg: libc::msghdr = unsafe { zeroed() };
        msg.msg_name = (&mut from as *mut libc::sockaddr_in).cast();
        msg.msg_namelen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = size_of::<[u64; 32]>() as libc::socklen_t;
        // SAFETY: `msg` points to live buffers.
        let n = unsafe { libc::recvmsg(self.0.as_raw_fd(), &mut msg, 0) };
        if n < 0 {
            return err("recvmsg");
        }
        let mut ifindex = None;
        // SAFETY: walking the control messages recvmsg filled in.
        unsafe {
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                if (*c).cmsg_level == libc::IPPROTO_IP && (*c).cmsg_type == libc::IP_PKTINFO {
                    let info = &*(libc::CMSG_DATA(c) as *const libc::in_pktinfo);
                    ifindex = Some(info.ipi_ifindex);
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
        }
        Ok(Some(Datagram {
            len: n as usize,
            src: from.sin_addr.s_addr.to_ne_bytes(),
            ifindex,
        }))
    }

    /// Counts the datagrams that arrive until none comes for `quiet`.
    pub fn drain(&self, quiet: Duration) -> usize {
        let mut n = 0;
        while let Ok(Some(_)) = self.recv(quiet) {
            n += 1;
        }
        n
    }
}

pub fn ip_str(ip: [u8; 4]) -> String {
    std::net::Ipv4Addr::from(ip).to_string()
}

pub fn mac_str(m: &[u8]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
