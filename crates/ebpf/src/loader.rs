//! Loading (Linux only): the static TC programs with `aya`, the generated matcher with the
//! `bpf()` system call, which `aya` has no public interface for, and `BPF_PROG_TEST_RUN` for
//! tests. Every function here needs `CAP_BPF` (or root).

use std::ffi::CStr;
use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};

use aya::maps::{Map, MapData, PerCpuArray};
use aya::programs::SchedClassifier;
use aya::{Ebpf, EbpfError, Pod};

use crate::codegen::Matcher;
use crate::facts::{Facts, SLOT_ACTION, SLOT_MATCHER};

/// The static programs, built from `bpf/tc.bpf.c`.
pub static TC_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tc.bpf.o"));

// SAFETY: `Facts` is `repr(C)`, made of integers, with no padding (32 bytes, asserted in
// `bpf/facts.h`), so every bit pattern is valid.
unsafe impl Pod for Facts {}

const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;
const BPF_PROG_LOAD: libc::c_long = 5;
const BPF_PROG_TEST_RUN: libc::c_long = 10;
const BPF_PROG_TYPE_SCHED_CLS: u32 = 3;
/// `BPF_LOG_STATS`: only the verifier's statistics.
const LOG_STATS: u32 = 4;
const LOG_SIZE: usize = 1 << 24;

/// A loading error.
#[derive(Debug)]
pub enum Error {
    /// `aya` could not load the static object.
    Ebpf(Box<EbpfError>),
    /// `aya` could not load or reach one of its programs or maps.
    Aya(String),
    /// A system call failed.
    Sys(&'static str, io::Error),
    /// The verifier rejected the generated matcher; `log` is its report.
    Rejected {
        /// The error of `BPF_PROG_LOAD`.
        error: io::Error,
        /// The verifier log.
        log: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Ebpf(e) => write!(f, "loading the TC object: {e}"),
            Error::Aya(e) => f.write_str(e),
            Error::Sys(call, e) => write!(f, "{call}: {e}"),
            Error::Rejected { error, log } => {
                write!(f, "the verifier rejected the matcher ({error}):\n{log}")
            }
        }
    }
}

impl std::error::Error for Error {}

fn aya<E: fmt::Display>(what: &str) -> impl FnOnce(E) -> Error + '_ {
    move |e| Error::Aya(format!("{what}: {e}"))
}

/// The static TC program, its action, and a generated matcher in its program array.
pub struct Classifier {
    ebpf: Ebpf,
    matcher: Option<OwnedFd>,
}

/// What the verifier reported about a matcher it accepted.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    /// Instructions in the program.
    pub insns: usize,
    /// The verifier's statistics line (instructions processed, states).
    pub log: String,
}

impl Classifier {
    /// Loads the static programs and puts the action program in its slot. The program array
    /// has no matcher yet, so every packet passes.
    pub fn load() -> Result<Self, Error> {
        let mut ebpf = Ebpf::load(TC_OBJECT).map_err(|e| Error::Ebpf(Box::new(e)))?;
        for name in ["avulse_tc", "avulse_act"] {
            let prog: &mut SchedClassifier = ebpf
                .program_mut(name)
                .ok_or_else(|| Error::Aya(format!("no program {name}")))?
                .try_into()
                .map_err(aya(name))?;
            prog.load().map_err(aya(name))?;
        }
        let c = Classifier {
            ebpf,
            matcher: None,
        };
        let act = c.prog_fd("avulse_act")?;
        update(c.map_fd("avulse_progs")?, SLOT_ACTION, act)?;
        Ok(c)
    }

    fn prog_fd(&self, name: &str) -> Result<RawFd, Error> {
        let prog: &SchedClassifier = self
            .ebpf
            .program(name)
            .ok_or_else(|| Error::Aya(format!("no program {name}")))?
            .try_into()
            .map_err(aya(name))?;
        Ok(prog.fd().map_err(aya(name))?.as_fd().as_raw_fd())
    }

    fn map_data(&self, name: &str) -> Result<&MapData, Error> {
        match self.ebpf.map(name) {
            Some(Map::PerCpuArray(d) | Map::ProgramArray(d)) => Ok(d),
            _ => Err(Error::Aya(format!("no map {name}"))),
        }
    }

    fn map_fd(&self, name: &str) -> Result<RawFd, Error> {
        Ok(self.map_data(name)?.fd().as_fd().as_raw_fd())
    }

    /// Loads `m` and puts it in the matcher slot, replacing the previous one.
    pub fn set_matcher(&mut self, m: &Matcher) -> Result<Stats, Error> {
        let insns = m.with_fds(self.map_fd("avulse_facts")?, self.map_fd("avulse_progs")?);
        let (fd, log) = prog_load(&insns)?;
        update(self.map_fd("avulse_progs")?, SLOT_MATCHER, fd.as_raw_fd())?;
        self.matcher = Some(fd);
        Ok(Stats {
            insns: insns.len(),
            log,
        })
    }

    /// Runs the TC program on `frame` (an Ethernet frame of at least 14 bytes) with
    /// `BPF_PROG_TEST_RUN`, and returns its verdict: `TC_ACT_SHOT` (2) if the filter matches,
    /// `TC_ACT_UNSPEC` (-1) if not, `TC_ACT_OK` (0) without a matcher.
    pub fn run(&self, frame: &[u8]) -> Result<i32, Error> {
        Ok(test_run(self.prog_fd("avulse_tc")?, frame, 1)?.0)
    }

    /// Runs the TC program `repeat` times on `frame` and returns the verdict and the kernel's
    /// average time per run, in nanoseconds.
    pub fn time(&self, frame: &[u8], repeat: u32) -> Result<(i32, u32), Error> {
        test_run(self.prog_fd("avulse_tc")?, frame, repeat)
    }

    /// The facts the last run on CPU `cpu` left.
    pub fn facts(&self, cpu: usize) -> Result<Facts, Error> {
        let map = self.ebpf.map("avulse_facts");
        let map: PerCpuArray<&MapData, Facts> = map
            .ok_or_else(|| Error::Aya("no map avulse_facts".into()))?
            .try_into()
            .map_err(aya("avulse_facts"))?;
        let values = map.get(&0, 0).map_err(aya("avulse_facts"))?;
        values
            .get(cpu)
            .copied()
            .ok_or_else(|| Error::Aya(format!("no CPU {cpu}")))
    }
}

fn sys_bpf<T>(cmd: libc::c_long, attr: &mut T) -> io::Result<libc::c_long> {
    // SAFETY: `attr` is a `repr(C)` prefix of `union bpf_attr` for `cmd`, valid for its size;
    // the pointers inside it outlive the call.
    let r = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            attr as *mut T as *mut libc::c_void,
            size_of::<T>() as libc::c_uint,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

#[repr(C)]
#[derive(Default)]
struct ProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

/// Loads a matcher. On success the log holds the verifier's statistics; on failure the verifier
/// runs again with a full log.
fn prog_load(insns: &[crate::insn::Insn]) -> Result<(OwnedFd, String), Error> {
    let bytes: Vec<u8> = insns.iter().flat_map(|i| i.to_bytes()).collect();
    let license = c"GPL";
    let mut log = vec![0u8; LOG_SIZE];
    let mut name = [0u8; 16];
    name[..14].copy_from_slice(b"avulse_matcher");
    let mut attr = ProgLoadAttr {
        prog_type: BPF_PROG_TYPE_SCHED_CLS,
        insn_cnt: insns.len() as u32,
        insns: bytes.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: LOG_STATS,
        log_size: LOG_SIZE as u32,
        log_buf: log.as_mut_ptr() as u64,
        prog_name: name,
        ..Default::default()
    };
    let text = |log: &[u8]| {
        CStr::from_bytes_until_nul(log)
            .map(|s| s.to_string_lossy().trim().to_owned())
            .unwrap_or_default()
    };
    match sys_bpf(BPF_PROG_LOAD, &mut attr) {
        // SAFETY: the kernel returned a new file descriptor that nothing else owns.
        Ok(fd) => Ok((unsafe { OwnedFd::from_raw_fd(fd as RawFd) }, text(&log))),
        Err(error) => {
            log.fill(0);
            attr.log_level = 1;
            let _ = sys_bpf(BPF_PROG_LOAD, &mut attr);
            Err(Error::Rejected {
                error,
                log: text(&log),
            })
        }
    }
}

#[repr(C)]
struct MapElemAttr {
    map_fd: u32,
    pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

fn update(map: RawFd, key: u32, value: RawFd) -> Result<(), Error> {
    let value = value as u32;
    let mut attr = MapElemAttr {
        map_fd: map as u32,
        pad: 0,
        key: &key as *const u32 as u64,
        value: &value as *const u32 as u64,
        flags: 0,
    };
    sys_bpf(BPF_MAP_UPDATE_ELEM, &mut attr)
        .map(drop)
        .map_err(|e| Error::Sys("BPF_MAP_UPDATE_ELEM", e))
}

#[repr(C)]
#[derive(Default)]
struct TestRunAttr {
    prog_fd: u32,
    retval: u32,
    data_size_in: u32,
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    duration: u32,
    ctx_size_in: u32,
    ctx_size_out: u32,
    ctx_in: u64,
    ctx_out: u64,
    flags: u32,
    cpu: u32,
}

fn test_run(prog: RawFd, frame: &[u8], repeat: u32) -> Result<(i32, u32), Error> {
    let mut attr = TestRunAttr {
        prog_fd: prog as u32,
        data_size_in: frame.len() as u32,
        data_in: frame.as_ptr() as u64,
        repeat,
        ..Default::default()
    };
    sys_bpf(BPF_PROG_TEST_RUN, &mut attr).map_err(|e| Error::Sys("BPF_PROG_TEST_RUN", e))?;
    Ok((attr.retval as i32, attr.duration))
}
