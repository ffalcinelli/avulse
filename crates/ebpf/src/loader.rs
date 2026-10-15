//! Loading (Linux only): the static TC programs with `aya`, the generated matcher with the
//! `bpf()` system call, which `aya` has no public interface for, and `BPF_PROG_TEST_RUN` for
//! tests. Every function here needs `CAP_BPF` (or root).
//!
//! Attaching to interfaces is not here yet (Step 8). It must use `TcAttachOptions::Netlink`:
//! aya's `SchedClassifier::attach` picks TCX on 6.6 and later, which turns `TC_ACT_STOLEN` into
//! "next".

use std::ffi::CStr;
use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};

use aya::maps::{Array, Map, MapData, PerCpuArray, RingBuf};
use aya::programs::SchedClassifier;
use aya::{Ebpf, EbpfError, EbpfLoader, Pod};

use crate::abi::{self, Config};
use crate::codegen::Matcher;
use crate::facts::{Facts, SLOT_ACTION, SLOT_MATCHER};

/// The static programs, built from `bpf/tc.bpf.c`.
pub static TC_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tc.bpf.o"));

// SAFETY: `Facts` is `repr(C)`, made of integers, with no padding (32 bytes, asserted in
// `bpf/facts.h`), so every bit pattern is valid.
unsafe impl Pod for Facts {}

// SAFETY: as for `Facts`: integers and explicit padding, 40 bytes (asserted in `bpf/abi.h`).
unsafe impl Pod for Config {}

/// The ring buffer's size when none is given: 4 MiB.
pub const DEFAULT_RING_BYTES: u32 = 1 << 22;

const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;
const BPF_MAP_DELETE_ELEM: libc::c_long = 3;
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

/// The static TC programs of one handle, its maps, and a generated matcher in its program array.
pub struct Classifier {
    ebpf: Ebpf,
    ring: RingBuf<MapData>,
    matcher: Option<OwnedFd>,
}

/// Which entry program a test run goes through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hook {
    /// `avulse_ingress`: packets arriving.
    Ingress,
    /// `avulse_egress`: packets leaving.
    Egress,
}

impl Hook {
    fn program(self) -> &'static str {
        match self {
            Hook::Ingress => "avulse_ingress",
            Hook::Egress => "avulse_egress",
        }
    }
}

/// The `__sk_buff` fields a test run sets (the ones `BPF_PROG_TEST_RUN` accepts).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SkbCtx {
    /// `skb->mark`.
    pub mark: u32,
    /// `skb->ingress_ifindex`.
    pub ingress_ifindex: u32,
    /// The device: 0 or 1 is the loopback device.
    pub ifindex: u32,
    /// `skb->gso_segs`.
    pub gso_segs: u32,
    /// `skb->gso_size`.
    pub gso_size: u32,
}

impl SkbCtx {
    /// The context as `struct __sk_buff` (the 5.15 layout, which ends after `gso_size`).
    fn to_bytes(self) -> [u8; 184] {
        let mut b = [0; 184];
        for (at, v) in [
            (8, self.mark),
            (36, self.ingress_ifindex),
            (40, self.ifindex),
            (164, self.gso_segs),
            (176, self.gso_size),
        ] {
            b[at..at + 4].copy_from_slice(&v.to_ne_bytes());
        }
        b
    }
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
    /// Loads the static programs with a ring buffer of [`DEFAULT_RING_BYTES`]. See
    /// [`load_with_ring`](Classifier::load_with_ring).
    pub fn load() -> Result<Self, Error> {
        Self::load_with_ring(DEFAULT_RING_BYTES)
    }

    /// Loads the static programs and puts the action program in its slot. The configuration is
    /// all zeros (NETWORK layer, divert, no heartbeat) and there is no matcher, so every packet
    /// passes. `ring_bytes` must be a power of two and a multiple of the page size.
    pub fn load_with_ring(ring_bytes: u32) -> Result<Self, Error> {
        let mut ebpf = EbpfLoader::new()
            .map_max_entries("avulse_ring", ring_bytes)
            .load(TC_OBJECT)
            .map_err(|e| Error::Ebpf(Box::new(e)))?;
        for name in ["avulse_ingress", "avulse_egress", "avulse_act"] {
            let prog: &mut SchedClassifier = ebpf
                .program_mut(name)
                .ok_or_else(|| Error::Aya(format!("no program {name}")))?
                .try_into()
                .map_err(aya(name))?;
            prog.load().map_err(aya(name))?;
        }
        let ring = ebpf
            .take_map("avulse_ring")
            .ok_or_else(|| Error::Aya("no map avulse_ring".into()))?;
        let ring = RingBuf::try_from(ring).map_err(aya("avulse_ring"))?;
        let c = Classifier {
            ebpf,
            ring,
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
            Some(Map::PerCpuArray(d) | Map::ProgramArray(d) | Map::Array(d)) => Ok(d),
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

    /// Empties the matcher slot: every packet passes again.
    pub fn clear_matcher(&mut self) -> Result<(), Error> {
        let key = SLOT_MATCHER;
        let mut attr = MapElemAttr {
            map_fd: self.map_fd("avulse_progs")? as u32,
            pad: 0,
            key: &key as *const u32 as u64,
            value: 0,
            flags: 0,
        };
        sys_bpf(BPF_MAP_DELETE_ELEM, &mut attr)
            .map_err(|e| Error::Sys("BPF_MAP_DELETE_ELEM", e))?;
        self.matcher = None;
        Ok(())
    }

    /// Writes the handle's configuration.
    pub fn set_config(&mut self, config: &Config) -> Result<(), Error> {
        let map = self
            .ebpf
            .map_mut("avulse_config")
            .ok_or_else(|| Error::Aya("no map avulse_config".into()))?;
        let mut array: Array<&mut MapData, Config> =
            map.try_into().map_err(aya("avulse_config"))?;
        array.set(0, config, 0).map_err(aya("avulse_config"))
    }

    /// The statistics, summed over the CPUs, indexed by [`abi::stat`].
    pub fn stats(&self) -> Result<[u64; abi::stat::COUNT], Error> {
        let map = self
            .ebpf
            .map("avulse_stats")
            .ok_or_else(|| Error::Aya("no map avulse_stats".into()))?;
        let map: PerCpuArray<&MapData, u64> = map.try_into().map_err(aya("avulse_stats"))?;
        let mut out = [0; abi::stat::COUNT];
        for (i, total) in out.iter_mut().enumerate() {
            let values = map.get(&(i as u32), 0).map_err(aya("avulse_stats"))?;
            *total = values.iter().sum();
        }
        Ok(out)
    }

    /// Takes every record in the ring buffer (see [`abi::Record::parse`]).
    pub fn records(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(item) = self.ring.next() {
            out.push(item.to_vec());
        }
        out
    }

    /// Runs the ingress program on `frame` (an Ethernet frame of at least 14 bytes) with
    /// `BPF_PROG_TEST_RUN` and a default context, and returns its verdict.
    pub fn run(&self, frame: &[u8]) -> Result<i32, Error> {
        self.run_on(Hook::Ingress, frame, &SkbCtx::default())
    }

    /// Runs an entry program on `frame` with the context `ctx`, and returns its verdict:
    /// `TC_ACT_UNSPEC` (-1) when the packet passes, `TC_ACT_SHOT` (2) when it is dropped,
    /// `TC_ACT_STOLEN` (4) when it is diverted.
    pub fn run_on(&self, hook: Hook, frame: &[u8], ctx: &SkbCtx) -> Result<i32, Error> {
        Ok(test_run(self.prog_fd(hook.program())?, frame, Some(ctx), 1)?.0)
    }

    /// Runs the ingress program `repeat` times on `frame` and returns the verdict and the
    /// kernel's average time per run, in nanoseconds.
    pub fn time(&self, frame: &[u8], repeat: u32) -> Result<(i32, u32), Error> {
        test_run(self.prog_fd("avulse_ingress")?, frame, None, repeat)
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

fn test_run(
    prog: RawFd,
    frame: &[u8],
    ctx: Option<&SkbCtx>,
    repeat: u32,
) -> Result<(i32, u32), Error> {
    let ctx = ctx.map(|c| c.to_bytes());
    let mut attr = TestRunAttr {
        prog_fd: prog as u32,
        data_size_in: frame.len() as u32,
        data_in: frame.as_ptr() as u64,
        repeat,
        ctx_size_in: ctx.as_ref().map_or(0, |c| c.len() as u32),
        ctx_in: ctx.as_ref().map_or(0, |c| c.as_ptr() as u64),
        ..Default::default()
    };
    sys_bpf(BPF_PROG_TEST_RUN, &mut attr).map_err(|e| Error::Sys("BPF_PROG_TEST_RUN", e))?;
    Ok((attr.retval as i32, attr.duration))
}
