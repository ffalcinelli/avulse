//! The system calls the backend makes directly: the clock, `eventfd`, `epoll`, `flock`, and what
//! `/proc` and `/sys` say about processes and interfaces.

use std::ffi::CStr;
use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::Path;

fn check(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn owned(fd: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: a successful call returned a new file descriptor that nothing else owns.
    check(fd).map(|fd| unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `CLOCK_MONOTONIC` in nanoseconds: the clock of `bpf_ktime_get_ns`, and of record timestamps.
pub fn now_ns() -> i64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid timespec; CLOCK_MONOTONIC always exists.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    // `time_t` and `c_long` are 32 bits on some targets.
    #[allow(clippy::unnecessary_cast)]
    let ns = ts.tv_sec as i64 * 1_000_000_000 + ts.tv_nsec as i64;
    ns
}

/// An `eventfd` used as a flag: readable while it is set.
pub struct Flag(OwnedFd);

impl Flag {
    pub fn new() -> io::Result<Flag> {
        // SAFETY: no pointers.
        owned(unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) }).map(Flag)
    }

    pub fn set(&self) {
        let one = 1u64;
        // SAFETY: writes 8 bytes from a valid u64. It fails only if the counter would overflow.
        unsafe { libc::write(self.0.as_raw_fd(), (&one as *const u64).cast(), 8) };
    }

    pub fn clear(&self) {
        let mut v = 0u64;
        // SAFETY: reads 8 bytes into a valid u64. Non-blocking: it fails (EAGAIN) when clear.
        unsafe { libc::read(self.0.as_raw_fd(), (&mut v as *mut u64).cast(), 8) };
    }
}

impl AsFd for Flag {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// An epoll instance: readable when one of its descriptors is.
pub struct Epoll(OwnedFd);

impl Epoll {
    pub fn new() -> io::Result<Epoll> {
        // SAFETY: no pointers.
        owned(unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) }).map(Epoll)
    }

    /// Watches `fd` for input.
    pub fn add(&self, fd: BorrowedFd<'_>) -> io::Result<()> {
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: 0,
        };
        // SAFETY: `ev` is valid for the call; the kernel keeps no pointer to it.
        check(unsafe {
            libc::epoll_ctl(
                self.0.as_raw_fd(),
                libc::EPOLL_CTL_ADD,
                fd.as_raw_fd(),
                &mut ev,
            )
        })
        .map(drop)
    }

    /// Waits until a descriptor is readable, at most `timeout_ms` (-1: no limit). It may return
    /// early (a signal).
    pub fn wait(&self, timeout_ms: i32) -> io::Result<()> {
        let mut ev = [libc::epoll_event { events: 0, u64: 0 }; 2];
        // SAFETY: `ev` has room for the 2 events the call may write.
        match check(unsafe { libc::epoll_wait(self.0.as_raw_fd(), ev.as_mut_ptr(), 2, timeout_ms) })
        {
            Err(e) if e.kind() != io::ErrorKind::Interrupted => Err(e),
            _ => Ok(()),
        }
    }
}

impl AsFd for Epoll {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// An exclusive `flock` on a file, released when dropped.
pub struct FileLock {
    _fd: OwnedFd,
}

impl FileLock {
    /// Waits for the lock on `path`, creating the file if needed.
    pub fn acquire(path: &CStr) -> io::Result<FileLock> {
        // SAFETY: `path` is a valid C string.
        let fd = owned(unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC,
                0o600,
            )
        })
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.to_string_lossy())))?;
        loop {
            // SAFETY: no pointers.
            match check(unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX) }) {
                Ok(_) => return Ok(FileLock { _fd: fd }),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

/// Random bytes from the kernel.
pub fn random_u64() -> io::Result<u64> {
    let mut v = 0u64;
    // SAFETY: writes at most 8 bytes into a valid u64.
    let n = unsafe { libc::getrandom((&mut v as *mut u64).cast(), 8, 0) };
    if n == 8 {
        Ok(v)
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn pid() -> u32 {
    std::process::id()
}

/// When process `pid` started (field 22 of `/proc/<pid>/stat`, in clock ticks since boot), which
/// tells it from a later process with the same ID. `None` if there is no such process.
pub fn start_time(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name (field 2) is in parentheses and may hold spaces: skip it.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_ascii_whitespace().nth(19)?.parse().ok()
}

/// Whether process `pid`, started at `start`, still runs.
pub fn alive(pid: u32, start: u64) -> bool {
    start_time(pid) == Some(start)
}

/// Whether a sysctl under `/proc/sys` is set to a non-zero number.
pub fn sysctl_on(path: &str) -> bool {
    fs::read_to_string(Path::new("/proc/sys").join(path))
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .is_some_and(|v| v != 0)
}

/// `ARPHRD_ETHER`.
pub const ARPHRD_ETHER: u16 = 1;
/// `ARPHRD_LOOPBACK`.
pub const ARPHRD_LOOPBACK: u16 = 772;

/// A network interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub index: u32,
    pub name: String,
    /// The `ARPHRD_*` device type.
    pub kind: u16,
}

/// Every network interface.
pub fn interfaces() -> io::Result<Vec<Interface>> {
    // SAFETY: no arguments; the result is freed below.
    let list = unsafe { libc::if_nameindex() };
    if list.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut p = list;
    // SAFETY: the list ends with an entry whose index is 0; each name is a C string.
    unsafe {
        while (*p).if_index != 0 {
            let name = CStr::from_ptr((*p).if_name).to_string_lossy().into_owned();
            let kind = fs::read_to_string(format!("/sys/class/net/{name}/type"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            out.push(Interface {
                index: (*p).if_index,
                name,
                kind,
            });
            p = p.add(1);
        }
        libc::if_freenameindex(list);
    }
    Ok(out)
}
