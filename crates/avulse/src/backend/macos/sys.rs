//! The system calls of the macOS backend: bpf devices, interfaces, `kqueue`, and raw IP
//! sockets.

use std::ffi::{CStr, CString};
use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::null_mut;

use libc::{c_int, c_ulong, c_void};

const IOC_OUT: u32 = 0x4000_0000;
const IOC_IN: u32 = 0x8000_0000;

const fn ioc(dir: u32, n: u32, size: usize) -> c_ulong {
    (dir | ((size as u32 & 0x1fff) << 16) | ((b'B' as u32) << 8) | n) as c_ulong
}

const BIOCGBLEN: c_ulong = ioc(IOC_OUT, 102, 4);
/// `_IOW('B', 103, struct bpf_program)`: a classic BPF filter.
const BIOCSETF: c_ulong = ioc(IOC_IN, 103, size_of::<BpfProgram>());
const BIOCSBLEN: c_ulong = ioc(IOC_IN | IOC_OUT, 102, 4);
const BIOCGDLT: c_ulong = ioc(IOC_OUT, 106, 4);
const BIOCSETIF: c_ulong = ioc(IOC_IN, 108, 32);
const BIOCGSTATS: c_ulong = ioc(IOC_OUT, 111, 8);
const BIOCIMMEDIATE: c_ulong = ioc(IOC_IN, 112, 4);
const BIOCSHDRCMPLT: c_ulong = ioc(IOC_IN, 117, 4);
const BIOCSSEESENT: c_ulong = ioc(IOC_IN, 119, 4);
/// The directions a device captures, `BPF_D_IN` (1) or `BPF_D_OUT` (2). XNU's, not in the SDK's
/// header; it works on macOS 15 and 26 (Spike C).
const BIOCSDIRECTION: c_ulong = ioc(IOC_IN, 139, 4);
const BPF_D_IN: u32 = 1;
const BPF_D_OUT: u32 = 2;

/// Ethernet (`DLT_EN10MB`).
pub const DLT_EN10MB: u32 = 1;
/// A 4-byte address family in host byte order (`DLT_NULL`): `lo0`, `utun`.
pub const DLT_NULL: u32 = 0;
/// The buffer each bpf device asks for. The kernel caps it at `debug.bpf_bufsize_cap`.
const BUFFER: u32 = 4 << 20;

fn ioctl_u32(fd: RawFd, req: c_ulong, v: &mut u32) -> io::Result<()> {
    // SAFETY: every request used with this takes a pointer to a `u_int`.
    if unsafe { libc::ioctl(fd, req, v as *mut u32) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `struct bpf_program`.
#[repr(C)]
struct BpfProgram {
    len: u32,
    insns: *const BpfInsn,
}

/// `struct bpf_insn`.
#[repr(C)]
struct BpfInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// A bpf device bound to an interface: it sees what the interface sends and receives.
pub struct Bpf {
    fd: OwnedFd,
    /// The size of every read, which bpf requires to be the buffer's.
    pub blen: usize,
    pub dlt: u32,
}

impl Bpf {
    /// Opens a free `/dev/bpfN` on `ifname`, in immediate mode, for the packets going one way
    /// (`Some(true)`: outbound) or both. Fails with `ErrorKind::Unsupported` where a direction
    /// cannot be chosen.
    pub fn open(ifname: &str, outbound: Option<bool>) -> io::Result<Bpf> {
        let fd = open_device()?;
        let raw = fd.as_raw_fd();
        // The buffer size is set before the interface, or it does not apply.
        let mut blen = BUFFER;
        let _ = ioctl_u32(raw, BIOCSBLEN, &mut blen);
        let mut ifr = [0u8; 32];
        let name = ifname.as_bytes();
        if name.len() >= 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name too long",
            ));
        }
        ifr[..name.len()].copy_from_slice(name);
        // SAFETY: BIOCSETIF takes a `struct ifreq` (32 bytes), the name first.
        if unsafe { libc::ioctl(raw, BIOCSETIF, ifr.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        ioctl_u32(raw, BIOCIMMEDIATE, &mut 1)?;
        ioctl_u32(raw, BIOCSSEESENT, &mut 1)?;
        ioctl_u32(raw, BIOCSHDRCMPLT, &mut 1)?;
        if let Some(out) = outbound {
            let mut d = if out { BPF_D_OUT } else { BPF_D_IN };
            ioctl_u32(raw, BIOCSDIRECTION, &mut d)
                .map_err(|e| io::Error::new(io::ErrorKind::Unsupported, e))?;
        }
        let mut blen = 0;
        ioctl_u32(raw, BIOCGBLEN, &mut blen)?;
        let mut dlt = 0;
        ioctl_u32(raw, BIOCGDLT, &mut dlt)?;
        set_nonblocking(raw)?;
        Ok(Bpf {
            fd,
            blen: blen as usize,
            dlt,
        })
    }

    /// A device that only sends on `ifname`: its filter takes no packet, so nothing piles up in
    /// its buffer.
    pub fn writer(ifname: &str) -> io::Result<Bpf> {
        let b = Bpf::open(ifname, None)?;
        // `ret #0` (`BPF_RET | BPF_K`).
        let insn = BpfInsn {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0,
        };
        let prog = BpfProgram {
            len: 1,
            insns: &insn,
        };
        // SAFETY: BIOCSETF takes a `struct bpf_program`, whose instructions live for the call.
        if unsafe { libc::ioctl(b.fd.as_raw_fd(), BIOCSETF, &prog) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(b)
    }

    /// Reads what is buffered into `buf` (`blen` bytes); 0 when nothing is.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `buf` is valid for its length, which is `blen`.
        let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = io::Error::last_os_error();
            return match e.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(0),
                _ => Err(e),
            };
        }
        Ok(n as usize)
    }

    /// Sends `frame` out of the interface, with its link-layer header as it is.
    pub fn write(&self, frame: &[u8]) -> io::Result<()> {
        // SAFETY: `frame` is valid for its length.
        let n = unsafe { libc::write(self.fd.as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The packets the device dropped because its buffer was full.
    pub fn drops(&self) -> u64 {
        let mut s = [0u32; 2];
        // SAFETY: BIOCGSTATS fills a `struct bpf_stat` (two `u_int`s).
        if unsafe { libc::ioctl(self.fd.as_raw_fd(), BIOCGSTATS, s.as_mut_ptr()) } < 0 {
            return 0;
        }
        u64::from(s[1])
    }
}

impl AsFd for Bpf {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

fn open_device() -> io::Result<OwnedFd> {
    // macOS clones a new device when all are busy, up to `debug.bpf_maxdevices`.
    for n in 0..256 {
        let path = CString::new(format!("/dev/bpf{n}")).unwrap_or_default();
        // SAFETY: a NUL-terminated path.
        let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if raw >= 0 {
            // SAFETY: a fresh descriptor, ours.
            return Ok(unsafe { OwnedFd::from_raw_fd(raw) });
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EBUSY) => continue,
            // Past the last device.
            Some(libc::ENOENT) if n > 0 => break,
            _ => return Err(e),
        }
    }
    Err(io::Error::other("no free bpf device"))
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor we own.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// A network interface.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Interface {
    pub index: u32,
    pub name: String,
    pub up: bool,
    pub running: bool,
    pub loopback: bool,
    pub mac: Option<[u8; 6]>,
    pub addrs: Vec<IpAddr>,
}

/// The interfaces, in index order.
pub fn interfaces() -> io::Result<Vec<Interface>> {
    let mut list: Vec<Interface> = Vec::new();
    let mut ifap: *mut libc::ifaddrs = null_mut();
    // SAFETY: getifaddrs allocates the list, freed below.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: a node of the list getifaddrs returned.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        // SAFETY: `ifa_name` is a NUL-terminated string.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        let i = match list.iter().position(|i| i.name == name) {
            Some(i) => i,
            None => {
                let c = CString::new(name.as_str()).unwrap_or_default();
                list.push(Interface {
                    // SAFETY: a NUL-terminated name.
                    index: unsafe { libc::if_nametoindex(c.as_ptr()) },
                    up: ifa.ifa_flags & libc::IFF_UP as u32 != 0,
                    running: ifa.ifa_flags & libc::IFF_RUNNING as u32 != 0,
                    loopback: ifa.ifa_flags & libc::IFF_LOOPBACK as u32 != 0,
                    name,
                    ..Interface::default()
                });
                list.len() - 1
            }
        };
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: `ifa_addr` points to a sockaddr of the family it names.
        match c_int::from(unsafe { (*ifa.ifa_addr).sa_family }) {
            libc::AF_LINK => {
                // SAFETY: an AF_LINK address is a `sockaddr_dl`.
                let dl = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_dl) };
                let (nlen, alen) = (usize::from(dl.sdl_nlen), usize::from(dl.sdl_alen));
                if alen == 6 {
                    let mut m = [0u8; 6];
                    let data = dl.sdl_data.as_ptr() as *const u8;
                    // SAFETY: the address follows the name in the sockaddr.
                    unsafe { std::ptr::copy_nonoverlapping(data.add(nlen), m.as_mut_ptr(), 6) };
                    list[i].mac = Some(m);
                }
            }
            libc::AF_INET => {
                // SAFETY: an AF_INET address is a `sockaddr_in`.
                let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                let a = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
                list[i].addrs.push(IpAddr::V4(a));
            }
            libc::AF_INET6 => {
                // SAFETY: an AF_INET6 address is a `sockaddr_in6`.
                let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                let a = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                list[i].addrs.push(IpAddr::V6(a));
            }
            _ => {}
        }
    }
    // SAFETY: the list getifaddrs returned.
    unsafe { libc::freeifaddrs(ifap) };
    list.sort_by_key(|i| i.index);
    Ok(list)
}

/// A pipe that is readable while it is set: what tells `kqueue` (and callers polling the
/// handle) that `recv` would not block.
pub struct Flag {
    rx: OwnedFd,
    tx: OwnedFd,
}

impl Flag {
    pub fn new() -> io::Result<Flag> {
        let mut fds = [0; 2];
        // SAFETY: `fds` has room for the two descriptors.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fresh descriptors, ours.
        let (rx, tx) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        for fd in [&rx, &tx] {
            set_nonblocking(fd.as_raw_fd())?;
            // SAFETY: fcntl on a descriptor we own.
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        Ok(Flag { rx, tx })
    }

    /// Sets the flag; the caller tracks whether it already is (one byte at most in the pipe).
    pub fn set(&self) {
        // SAFETY: one byte from a live buffer.
        unsafe { libc::write(self.tx.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
    }

    pub fn clear(&self) {
        let mut b = [0u8; 16];
        // SAFETY: reads into a live buffer; the pipe is non-blocking.
        while unsafe { libc::read(self.rx.as_raw_fd(), b.as_mut_ptr().cast(), b.len()) } > 0 {}
    }
}

impl AsFd for Flag {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.rx.as_fd()
    }
}

/// A `kqueue` that waits for descriptors to be readable. A `kqueue` is itself readable while
/// one of its events is pending, so callers can poll it.
pub struct Kqueue(OwnedFd);

impl Kqueue {
    pub fn new() -> io::Result<Kqueue> {
        // SAFETY: no arguments.
        let raw = unsafe { libc::kqueue() };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh descriptor, ours.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: fcntl on a descriptor we own.
        unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) };
        Ok(Kqueue(fd))
    }

    /// Watches `fd` for reading (level-triggered).
    pub fn add(&self, fd: BorrowedFd<'_>) -> io::Result<()> {
        // SAFETY: an all-zero kevent is valid.
        let mut ev: libc::kevent = unsafe { zeroed() };
        ev.ident = fd.as_raw_fd() as usize;
        ev.filter = libc::EVFILT_READ;
        ev.flags = libc::EV_ADD;
        // SAFETY: one change, no events out.
        let rc =
            unsafe { libc::kevent(self.0.as_raw_fd(), &ev, 1, null_mut(), 0, std::ptr::null()) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Waits until one of the descriptors is readable, at most `timeout_ms` (-1: forever).
    pub fn wait(&self, timeout_ms: i64) -> io::Result<()> {
        // SAFETY: an all-zero kevent is valid.
        let mut ev: libc::kevent = unsafe { zeroed() };
        let ts = (timeout_ms >= 0).then(|| libc::timespec {
            tv_sec: timeout_ms / 1000,
            tv_nsec: (timeout_ms % 1000) * 1_000_000,
        });
        let tsp = ts.as_ref().map_or(std::ptr::null(), |t| t as *const _);
        // SAFETY: room for one event; `tsp` is null or points to `ts`.
        let rc = unsafe { libc::kevent(self.0.as_raw_fd(), std::ptr::null(), 0, &mut ev, 1, tsp) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
        Ok(())
    }
}

impl AsFd for Kqueue {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// Nanoseconds of the monotonic clock: addresses' timestamps.
pub fn now_ns() -> i64 {
    // SAFETY: an all-zero timespec is valid, and clock_gettime fills it.
    let mut ts: libc::timespec = unsafe { zeroed() };
    // SAFETY: as above.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec * 1_000_000_000 + ts.tv_nsec
}

/// Nanoseconds since the Unix epoch: the clock of bpf's timestamps.
pub fn wall_ns() -> i64 {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)
}

/// A raw IPv4 socket that sends whole packets (`IP_HDRINCL`).
pub fn raw_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket calls on a descriptor we own.
    unsafe {
        let raw = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = OwnedFd::from_raw_fd(raw);
        libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC);
        let one: c_int = 1;
        if libc::setsockopt(
            raw,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            (&one as *const c_int).cast::<c_void>(),
            size_of::<c_int>() as libc::socklen_t,
        ) < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }
}

/// Sends the IPv4 packet `ip` to its destination through the raw socket `fd`. BSD's raw
/// sockets take `ip_len` and `ip_off` in host byte order, so they are swapped here.
pub fn send_ip4(fd: BorrowedFd<'_>, ip: &[u8]) -> io::Result<()> {
    let mut pkt = ip.to_vec();
    for at in [2, 6] {
        let v = u16::from_be_bytes([pkt[at], pkt[at + 1]]);
        pkt[at..at + 2].copy_from_slice(&v.to_ne_bytes());
    }
    // SAFETY: an all-zero sockaddr_in is valid.
    let mut sa: libc::sockaddr_in = unsafe { zeroed() };
    sa.sin_len = size_of::<libc::sockaddr_in>() as u8;
    sa.sin_family = libc::AF_INET as u8;
    sa.sin_addr.s_addr = u32::from_ne_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
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
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `_IOWR('N', 3, struct ctl_info)`.
const CTLIOCGINFO: c_ulong = (IOC_IN | IOC_OUT | (100 << 16) | ((b'N' as u32) << 8) | 3) as c_ulong;
/// `_IOWR('i', 17, struct ifreq)` and `_IOW('i', 16, struct ifreq)`.
const SIOCGIFFLAGS: c_ulong =
    (IOC_IN | IOC_OUT | (32 << 16) | ((b'i' as u32) << 8) | 17) as c_ulong;
const SIOCSIFFLAGS: c_ulong = (IOC_IN | (32 << 16) | ((b'i' as u32) << 8) | 16) as c_ulong;
/// `_IOW('i', 26, struct in6_aliasreq)`.
const SIOCAIFADDR_IN6: c_ulong = (IOC_IN | (128 << 16) | ((b'i' as u32) << 8) | 26) as c_ulong;
const AF_SYSTEM: c_int = 32;
const AF_SYS_CONTROL: u16 = 2;
const SYSPROTO_CONTROL: c_int = 2;
const UTUN_OPT_IFNAME: c_int = 2;

#[repr(C)]
struct CtlInfo {
    id: u32,
    name: [u8; 96],
}

#[repr(C)]
struct SockaddrCtl {
    len: u8,
    family: u8,
    sysaddr: u16,
    id: u32,
    unit: u32,
    reserved: [u32; 5],
}

/// A `utun` device of our own, with an IPv6 address (a utun without one drops IPv6 input): what
/// the handle writes to it is received by the stack, from that interface. It is how inbound
/// IPv6 packets get in (Spike C).
pub struct Utun {
    fd: OwnedFd,
    pub name: String,
}

impl Utun {
    pub fn open() -> io::Result<Utun> {
        // SAFETY: kernel-control socket calls with correctly sized structs, on a descriptor we
        // own.
        unsafe {
            let raw = libc::socket(AF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL);
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = OwnedFd::from_raw_fd(raw);
            libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC);
            let mut info = CtlInfo {
                id: 0,
                name: [0; 96],
            };
            let name = b"com.apple.net.utun_control";
            info.name[..name.len()].copy_from_slice(name);
            if libc::ioctl(raw, CTLIOCGINFO, &mut info) < 0 {
                return Err(io::Error::last_os_error());
            }
            let sa = SockaddrCtl {
                len: size_of::<SockaddrCtl>() as u8,
                family: AF_SYSTEM as u8,
                sysaddr: AF_SYS_CONTROL,
                id: info.id,
                // 0: the next free unit.
                unit: 0,
                reserved: [0; 5],
            };
            let len = size_of::<SockaddrCtl>() as libc::socklen_t;
            if libc::connect(raw, (&sa as *const SockaddrCtl).cast(), len) < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut buf = [0u8; 32];
            let mut blen = buf.len() as libc::socklen_t;
            let p = buf.as_mut_ptr().cast::<c_void>();
            if libc::getsockopt(raw, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, p, &mut blen) < 0 {
                return Err(io::Error::last_os_error());
            }
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            let name = String::from_utf8_lossy(&buf[..end]).into_owned();
            let utun = Utun { fd, name };
            utun.add_ipv6()?;
            Ok(utun)
        }
    }

    /// Gives the device a point-to-point address, `fd00:a7e1:5e:<unit>::1` to `…::2`, which
    /// turns IPv6 on, and brings it up.
    fn add_ipv6(&self) -> io::Result<()> {
        let unit: u16 = self.name.trim_start_matches("utun").parse().unwrap_or(0);
        let mut ip = [0u8; 16];
        ip[..6].copy_from_slice(&[0xfd, 0x00, 0xa7, 0xe1, 0x00, 0x5e]);
        ip[6..8].copy_from_slice(&unit.to_be_bytes());
        let sin6 = |last: u8, bytes: Option<[u8; 16]>| {
            // SAFETY: an all-zero sockaddr_in6 is valid.
            let mut sa: libc::sockaddr_in6 = unsafe { zeroed() };
            sa.sin6_len = size_of::<libc::sockaddr_in6>() as u8;
            sa.sin6_family = libc::AF_INET6 as u8;
            sa.sin6_addr.s6_addr = bytes.unwrap_or_else(|| {
                let mut a = ip;
                a[15] = last;
                a
            });
            sa
        };
        // `struct in6_aliasreq`: name, address, destination, prefix mask, flags, then the
        // lifetimes (two `time_t`s, then the valid and preferred lifetimes, infinite).
        let mut req = [0u8; 128];
        req[..self.name.len().min(15)]
            .copy_from_slice(&self.name.as_bytes()[..self.name.len().min(15)]);
        let sa_len = size_of::<libc::sockaddr_in6>();
        for (i, sa) in [sin6(1, None), sin6(2, None), sin6(0, Some([0xff; 16]))]
            .iter()
            .enumerate()
        {
            // SAFETY: a sockaddr_in6 is plain bytes.
            let bytes = unsafe {
                std::slice::from_raw_parts((sa as *const libc::sockaddr_in6).cast::<u8>(), sa_len)
            };
            req[16 + i * sa_len..16 + (i + 1) * sa_len].copy_from_slice(bytes);
        }
        req[120..128].fill(0xff);
        // SAFETY: plain socket calls; the request is the size the ioctl's number says.
        unsafe {
            let raw = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0);
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            let s = OwnedFd::from_raw_fd(raw);
            if libc::ioctl(s.as_raw_fd(), SIOCAIFADDR_IN6, req.as_mut_ptr()) < 0 {
                return Err(io::Error::last_os_error());
            }
            // `struct ifreq`: the name, then the flags (a short).
            let mut ifr = [0u8; 32];
            ifr[..16].copy_from_slice(&req[..16]);
            if libc::ioctl(s.as_raw_fd(), SIOCGIFFLAGS, ifr.as_mut_ptr()) < 0 {
                return Err(io::Error::last_os_error());
            }
            let flags = i16::from_ne_bytes([ifr[16], ifr[17]]) | libc::IFF_UP as i16;
            ifr[16..18].copy_from_slice(&flags.to_ne_bytes());
            if libc::ioctl(s.as_raw_fd(), SIOCSIFFLAGS, ifr.as_mut_ptr()) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Writes the IP packet `ip` to the device, for the stack to receive.
    pub fn write(&self, ip: &[u8]) -> io::Result<()> {
        let family = if ip[0] >> 4 == 6 {
            libc::AF_INET6
        } else {
            libc::AF_INET
        };
        // utun frames start with the address family, in network byte order.
        let mut frame = (family as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(ip);
        // SAFETY: `frame` is valid for its length.
        let n = unsafe { libc::write(self.fd.as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
