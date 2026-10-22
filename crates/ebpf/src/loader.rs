//! Loading (Linux only): the static TC programs with `aya`, the generated matcher with the
//! `bpf()` system call, which `aya` has no public interface for, and `BPF_PROG_TEST_RUN` for
//! tests. Every function here needs `CAP_BPF` and `CAP_NET_ADMIN` (or root).
//!
//! [`Classifier::attach`] attaches classic cls_bpf filters through Netlink
//! (`TcAttachOptions::Netlink`), never TCX: aya's `SchedClassifier::attach` picks TCX on 6.6 and
//! later, which turns `TC_ACT_STOLEN` into "next".

use std::ffi::{CStr, CString};
use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use avulse_proto::Link;
use aya::maps::{Array, Map, MapData, PerCpuArray, RingBuf};
use aya::programs::links::Link as _;
use aya::programs::tc::{self, NlOptions, SchedClassifierLink, TcAttachOptions, TcHandle};
use aya::programs::{SchedClassifier, TcAttachType};
use aya::{Ebpf, EbpfError, EbpfLoader, Pod};

use crate::abi::{self, Config};
use crate::codegen::Matcher;
use crate::facts::{Facts, SLOT_ACTION, SLOT_MATCHER, SLOT_OPTIONS};

mod events;

pub use events::{Events, cgroup_root};

/// The static programs, built from `bpf/tc.bpf.c`.
pub static TC_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tc.bpf.o"));

// SAFETY: `Facts` is `repr(C)`, made of integers, with no padding (32 bytes, asserted in
// `bpf/facts.h`), so every bit pattern is valid.
unsafe impl Pod for Facts {}

// SAFETY: as for `Facts`: integers and explicit padding, 40 bytes (asserted in `bpf/abi.h`).
unsafe impl Pod for Config {}

/// A classifier's ring buffer ([`Classifier::take_ring`]). Its items are records
/// ([`abi::Record::parse`]).
pub type Ring = RingBuf<MapData>;

/// The ring buffer's size when none is given: 4 MiB.
pub const DEFAULT_RING_BYTES: u32 = 1 << 22;

const BPF_MAP_CREATE: libc::c_long = 0;
const BPF_MAP_LOOKUP_ELEM: libc::c_long = 1;
const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;
const BPF_MAP_DELETE_ELEM: libc::c_long = 3;
const BPF_MAP_GET_NEXT_KEY: libc::c_long = 4;
const BPF_PROG_LOAD: libc::c_long = 5;
const BPF_OBJ_PIN: libc::c_long = 6;
const BPF_OBJ_GET: libc::c_long = 7;
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

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Ebpf(e) => Some(e.as_ref()),
            Error::Sys(_, e) | Error::Rejected { error: e, .. } => Some(e),
            Error::Aya(_) => None,
        }
    }
}

fn aya<E: fmt::Display>(what: &str) -> impl FnOnce(E) -> Error + '_ {
    move |e| Error::Aya(format!("{what}: {e}"))
}

/// The static TC programs of one handle, its maps, a generated matcher in its program array, and
/// the TC filters that run them. Dropping it detaches the filters.
pub struct Classifier {
    ebpf: Ebpf,
    /// `None` once [`take_ring`](Classifier::take_ring) took it.
    ring: Option<RingBuf<MapData>>,
    matcher: Option<OwnedFd>,
    /// Detached when dropped.
    links: Vec<SchedClassifierLink>,
}

/// An entry program: which hook of an interface it runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Hook {
    /// `avulse_ingress`: packets arriving.
    Ingress,
    /// `avulse_egress`: packets leaving.
    Egress,
}

impl Hook {
    /// The entry program for the hook, on a device whose packets start with `link`'s header:
    /// `avulse_ingress`/`avulse_egress` for Ethernet devices, `avulse_ingress_ip`/
    /// `avulse_egress_ip` for those without a link-layer header (tun, WireGuard, IP tunnels).
    fn program(self, link: Link) -> &'static str {
        match (self, link) {
            (Hook::Ingress, Link::Ethernet) => "avulse_ingress",
            (Hook::Egress, Link::Ethernet) => "avulse_egress",
            (Hook::Ingress, Link::Ip) => "avulse_ingress_ip",
            (Hook::Egress, Link::Ip) => "avulse_egress_ip",
        }
    }

    fn attach_type(self) -> TcAttachType {
        match self {
            Hook::Ingress => TcAttachType::Ingress,
            Hook::Egress => TcAttachType::Egress,
        }
    }
}

/// A TC filter that runs an entry program: what it takes to detach it, from any process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Attachment {
    /// The interface.
    pub ifindex: u32,
    /// Its ingress or egress hook.
    pub hook: Hook,
    /// The filter's TC priority.
    pub priority: u16,
    /// The filter's handle, which the kernel picked.
    pub handle: u32,
}

impl Attachment {
    /// Removes the filter, such as one a dead process left. It does nothing if the interface is
    /// gone (its filters went with it).
    pub fn detach(&self) -> Result<(), Error> {
        let Some(name) = if_name(self.ifindex) else {
            return Ok(());
        };
        let link = SchedClassifierLink::attached(
            &name,
            self.hook.attach_type(),
            self.priority,
            TcHandle::from(self.handle),
            None,
        )
        .map_err(|e| Error::Sys("if_nametoindex", e))?;
        link.detach().map_err(aya("detaching"))
    }
}

/// The name of interface `ifindex`, if it exists.
pub fn if_name(ifindex: u32) -> Option<String> {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    // SAFETY: `buf` has room for IF_NAMESIZE bytes, as `if_indextoname` requires.
    let p = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr().cast()) };
    if p.is_null() {
        return None;
    }
    let name = CStr::from_bytes_until_nul(&buf).ok()?;
    Some(name.to_string_lossy().into_owned())
}

/// Room for the context a test run returns: the kernel's `struct __sk_buff`, which grows with
/// its version (a smaller buffer fails with `ENOSPC`).
const CTX_OUT: usize = 512;

/// The `__sk_buff` fields a test run sets (the ones `BPF_PROG_TEST_RUN` accepts).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SkbCtx {
    /// `skb->mark`.
    pub mark: u32,
    /// `skb->priority`.
    pub priority: u32,
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
            (32, self.priority),
            (36, self.ingress_ifindex),
            (40, self.ifindex),
            (164, self.gso_segs),
            (176, self.gso_size),
        ] {
            b[at..at + 4].copy_from_slice(&v.to_ne_bytes());
        }
        b
    }

    fn from_bytes(b: &[u8; CTX_OUT]) -> SkbCtx {
        let at = |i: usize| u32::from_ne_bytes(b[i..i + 4].try_into().unwrap());
        SkbCtx {
            mark: at(8),
            priority: at(32),
            ingress_ifindex: at(36),
            ifindex: at(40),
            gso_segs: at(164),
            gso_size: at(176),
        }
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
        for name in [
            "avulse_ingress",
            "avulse_egress",
            "avulse_ingress_ip",
            "avulse_egress_ip",
            "avulse_act",
            "avulse_options",
        ] {
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
            ring: Some(ring),
            matcher: None,
            links: Vec::new(),
        };
        let progs = c.map_fd("avulse_progs")?;
        update(progs, SLOT_ACTION, c.prog_fd("avulse_act")?)?;
        update(progs, SLOT_OPTIONS, c.prog_fd("avulse_options")?)?;
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

    /// Attaches an entry program to interface `ifname` as a cls_bpf filter at TC priority
    /// `priority` (lower runs first), adding the `clsact` qdisc if it is missing. `link` is the
    /// header the device's packets start with: [`Link::Ethernet`], or [`Link::Ip`] for devices
    /// without a link-layer header (tun, WireGuard, IP tunnels), which serve the NETWORK layers
    /// only. The filter stays until the classifier is dropped, or until [`Attachment::detach`].
    pub fn attach(
        &mut self,
        ifname: &str,
        hook: Hook,
        link: Link,
        priority: u16,
    ) -> Result<Attachment, Error> {
        let ifindex = if_index(ifname)?;
        // It fails when the qdisc exists, which is fine; attaching reports any other problem.
        let _ = tc::qdisc_add_clsact(ifname);
        let name = hook.program(link);
        let prog: &mut SchedClassifier = self
            .ebpf
            .program_mut(name)
            .ok_or_else(|| Error::Aya(format!("no program {name}")))?
            .try_into()
            .map_err(aya(name))?;
        let options = TcAttachOptions::Netlink(NlOptions {
            priority,
            handle: TcHandle::AUTO_ASSIGN,
            classid: None,
        });
        let what = || format!("attaching to {ifname}");
        let id = prog
            .attach_with_options(ifname, hook.attach_type(), options)
            .map_err(|e| Error::Aya(format!("{}: {e}", what())))?;
        let link = prog
            .take_link(id)
            .map_err(|e| Error::Aya(format!("{}: {e}", what())))?;
        let attachment = Attachment {
            ifindex,
            hook,
            priority: link.priority().map_err(aya("TC priority"))?,
            handle: link.handle().map_err(aya("TC handle"))?.into(),
        };
        self.links.push(link);
        Ok(attachment)
    }

    /// Takes the ring buffer, for a reader of its own. [`records`](Classifier::records) is empty
    /// after.
    pub fn take_ring(&mut self) -> Option<Ring> {
        self.ring.take()
    }

    /// A writer of the configuration that does not borrow the classifier, for a heartbeat thread.
    pub fn config_writer(&self) -> Result<ConfigWriter, Error> {
        config_writer(&self.ebpf)
    }

    /// Writes the handle's configuration.
    pub fn set_config(&mut self, config: &Config) -> Result<(), Error> {
        set_config(&mut self.ebpf, config)
    }

    /// The statistics, summed over the CPUs, indexed by [`abi::stat`].
    pub fn stats(&self) -> Result<[u64; abi::stat::COUNT], Error> {
        stats(&self.ebpf)
    }

    /// Takes every record in the ring buffer (see [`abi::Record::parse`]).
    pub fn records(&mut self) -> Vec<Vec<u8>> {
        drain(&mut self.ring)
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
        Ok(self.run_ctx(hook, frame, ctx)?.0)
    }

    /// [`run_on`](Classifier::run_on), which also returns the context as the program left it
    /// (the mark and priority it wrote). `TC_ACT_REDIRECT` (7) means the program redirected the
    /// packet; a test run does not deliver it.
    pub fn run_ctx(&self, hook: Hook, frame: &[u8], ctx: &SkbCtx) -> Result<(i32, SkbCtx), Error> {
        let mut out = [0u8; CTX_OUT];
        let (verdict, _) = test_run(
            self.prog_fd(hook.program(Link::Ethernet))?,
            frame,
            Some(ctx),
            Some(&mut out),
            1,
        )?;
        Ok((verdict, SkbCtx::from_bytes(&out)))
    }

    /// Runs the ingress program `repeat` times on `frame` and returns the verdict and the
    /// kernel's average time per run, in nanoseconds.
    pub fn time(&self, frame: &[u8], repeat: u32) -> Result<(i32, u32), Error> {
        test_run(self.prog_fd("avulse_ingress")?, frame, None, None, repeat)
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

/// A writer of the `avulse_config` map of `ebpf`.
fn config_writer(ebpf: &Ebpf) -> Result<ConfigWriter, Error> {
    let fd = match ebpf.map("avulse_config") {
        Some(Map::Array(d)) => d.fd().as_fd().try_clone_to_owned(),
        _ => return Err(Error::Aya("no map avulse_config".into())),
    };
    Ok(ConfigWriter(fd.map_err(|e| Error::Sys("dup", e))?))
}

fn set_config(ebpf: &mut Ebpf, config: &Config) -> Result<(), Error> {
    let map = ebpf
        .map_mut("avulse_config")
        .ok_or_else(|| Error::Aya("no map avulse_config".into()))?;
    let mut array: Array<&mut MapData, Config> = map.try_into().map_err(aya("avulse_config"))?;
    array.set(0, config, 0).map_err(aya("avulse_config"))
}

fn stats(ebpf: &Ebpf) -> Result<[u64; abi::stat::COUNT], Error> {
    let map = ebpf
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

/// Every record in the ring buffer, if it is still there.
fn drain(ring: &mut Option<Ring>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if let Some(ring) = ring {
        while let Some(item) = ring.next() {
            out.push(item.to_vec());
        }
    }
    out
}

/// The index of the interface named `ifname`.
pub fn if_index(ifname: &str) -> Result<u32, Error> {
    let name = CString::new(ifname)
        .map_err(|_| Error::Sys("if_nametoindex", io::ErrorKind::InvalidInput.into()))?;
    // SAFETY: `name` is a valid C string.
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => Err(Error::Sys("if_nametoindex", io::Error::last_os_error())),
        i => Ok(i),
    }
}

/// Writes a classifier's configuration ([`Classifier::config_writer`]).
pub struct ConfigWriter(OwnedFd);

impl ConfigWriter {
    /// Writes the configuration.
    pub fn set(&self, config: &Config) -> Result<(), Error> {
        let key = 0u32;
        let mut attr = MapElemAttr {
            map_fd: self.0.as_raw_fd() as u32,
            pad: 0,
            key: &key as *const u32 as u64,
            value: config as *const Config as u64,
            flags: 0,
        };
        sys_bpf(BPF_MAP_UPDATE_ELEM, &mut attr)
            .map(drop)
            .map_err(|e| Error::Sys("BPF_MAP_UPDATE_ELEM", e))
    }
}

/// A BPF hash map that is not part of the TC object, such as the pinned registry of handles, with
/// fixed-size keys and values as bytes.
pub struct HashMap {
    fd: OwnedFd,
    key_size: usize,
    value_size: usize,
}

#[repr(C)]
#[derive(Default)]
struct MapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
}

#[repr(C)]
#[derive(Default)]
struct ObjAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_F_NO_PREALLOC: u32 = 1;

impl HashMap {
    /// Creates a map (entries allocated as they are added). `name` is at most 15 bytes.
    pub fn create(
        name: &str,
        key_size: usize,
        value_size: usize,
        max_entries: u32,
    ) -> Result<Self, Error> {
        let mut map_name = [0u8; 16];
        let n = name.len().min(15);
        map_name[..n].copy_from_slice(&name.as_bytes()[..n]);
        let mut attr = MapCreateAttr {
            map_type: BPF_MAP_TYPE_HASH,
            key_size: key_size as u32,
            value_size: value_size as u32,
            max_entries,
            map_flags: BPF_F_NO_PREALLOC,
            map_name,
            ..Default::default()
        };
        let fd = sys_bpf(BPF_MAP_CREATE, &mut attr).map_err(|e| Error::Sys("BPF_MAP_CREATE", e))?;
        Ok(HashMap {
            // SAFETY: the kernel returned a new file descriptor that nothing else owns.
            fd: unsafe { OwnedFd::from_raw_fd(fd as RawFd) },
            key_size,
            value_size,
        })
    }

    /// Opens the map pinned at `path` (on a bpffs), which must have these key and value sizes.
    /// The error is `Sys` with `NotFound` when nothing is pinned there.
    pub fn open_pinned(path: &Path, key_size: usize, value_size: usize) -> Result<Self, Error> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| Error::Sys("BPF_OBJ_GET", io::ErrorKind::InvalidInput.into()))?;
        let mut attr = ObjAttr {
            pathname: path.as_ptr() as u64,
            ..Default::default()
        };
        let fd = sys_bpf(BPF_OBJ_GET, &mut attr).map_err(|e| Error::Sys("BPF_OBJ_GET", e))?;
        let map = HashMap {
            // SAFETY: the kernel returned a new file descriptor that nothing else owns.
            fd: unsafe { OwnedFd::from_raw_fd(fd as RawFd) },
            key_size,
            value_size,
        };
        // A lookup with the wrong sizes would read or write out of bounds: check them.
        let info = map.info()?;
        if (info.key_size as usize, info.value_size as usize) != (key_size, value_size) {
            return Err(Error::Sys(
                "BPF_OBJ_GET",
                io::Error::new(io::ErrorKind::InvalidData, "the pinned map has other sizes"),
            ));
        }
        Ok(map)
    }

    fn info(&self) -> Result<MapInfo, Error> {
        let mut info = MapInfo::default();
        let mut attr = InfoAttr {
            bpf_fd: self.fd.as_raw_fd() as u32,
            info_len: size_of::<MapInfo>() as u32,
            info: &mut info as *mut MapInfo as u64,
        };
        sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &mut attr)
            .map_err(|e| Error::Sys("BPF_OBJ_GET_INFO_BY_FD", e))?;
        Ok(info)
    }

    /// Pins the map at `path`. The error is `Sys` with `AlreadyExists` when something is pinned
    /// there.
    pub fn pin(&self, path: &Path) -> Result<(), Error> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| Error::Sys("BPF_OBJ_PIN", io::ErrorKind::InvalidInput.into()))?;
        let mut attr = ObjAttr {
            pathname: path.as_ptr() as u64,
            bpf_fd: self.fd.as_raw_fd() as u32,
            file_flags: 0,
        };
        sys_bpf(BPF_OBJ_PIN, &mut attr)
            .map(drop)
            .map_err(|e| Error::Sys("BPF_OBJ_PIN", e))
    }

    fn elem(&self, cmd: libc::c_long, key: &[u8], value: u64, flags: u64) -> io::Result<()> {
        assert_eq!(key.len(), self.key_size, "the map's key size");
        let mut attr = MapElemAttr {
            map_fd: self.fd.as_raw_fd() as u32,
            pad: 0,
            key: key.as_ptr() as u64,
            value,
            flags,
        };
        sys_bpf(cmd, &mut attr).map(drop)
    }

    /// The value of `key`, if there is one.
    ///
    /// # Panics
    ///
    /// If `key` is not of the map's key size.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let mut value = vec![0u8; self.value_size];
        match self.elem(BPF_MAP_LOOKUP_ELEM, key, value.as_mut_ptr() as u64, 0) {
            Ok(()) => Ok(Some(value)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Sys("BPF_MAP_LOOKUP_ELEM", e)),
        }
    }

    /// Adds `key`, which must not be in the map yet (`Sys` with `AlreadyExists` otherwise).
    ///
    /// # Panics
    ///
    /// If `key` or `value` is not of the map's size.
    pub fn insert(&self, key: &[u8], value: &[u8]) -> Result<(), Error> {
        assert_eq!(value.len(), self.value_size, "the map's value size");
        const BPF_NOEXIST: u64 = 1;
        self.elem(BPF_MAP_UPDATE_ELEM, key, value.as_ptr() as u64, BPF_NOEXIST)
            .map_err(|e| Error::Sys("BPF_MAP_UPDATE_ELEM", e))
    }

    /// Removes `key`; it is not an error if it is missing.
    ///
    /// # Panics
    ///
    /// If `key` is not of the map's key size.
    pub fn remove(&self, key: &[u8]) -> Result<(), Error> {
        match self.elem(BPF_MAP_DELETE_ELEM, key, 0, 0) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => {
                Err(Error::Sys("BPF_MAP_DELETE_ELEM", e))
            }
            _ => Ok(()),
        }
    }

    /// Every key, in the map's order.
    pub fn keys(&self) -> Result<Vec<Vec<u8>>, Error> {
        let mut keys: Vec<Vec<u8>> = Vec::new();
        loop {
            let mut next = vec![0u8; self.key_size];
            let mut attr = MapElemAttr {
                map_fd: self.fd.as_raw_fd() as u32,
                pad: 0,
                // No key (0) asks for the first one.
                key: keys.last().map_or(0, |k| k.as_ptr() as u64),
                value: next.as_mut_ptr() as u64,
                flags: 0,
            };
            match sys_bpf(BPF_MAP_GET_NEXT_KEY, &mut attr) {
                Ok(_) => keys.push(next),
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(keys),
                Err(e) => return Err(Error::Sys("BPF_MAP_GET_NEXT_KEY", e)),
            }
        }
    }
}

const BPF_OBJ_GET_INFO_BY_FD: libc::c_long = 15;

#[repr(C)]
struct InfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

/// The start of `struct bpf_map_info`.
#[repr(C)]
#[derive(Default)]
struct MapInfo {
    map_type: u32,
    id: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
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
    ctx_out: Option<&mut [u8; CTX_OUT]>,
    repeat: u32,
) -> Result<(i32, u32), Error> {
    let ctx = ctx.map(|c| c.to_bytes());
    let (ctx_size_out, ctx_out) =
        ctx_out.map_or((0, 0), |c| (c.len() as u32, c.as_mut_ptr() as u64));
    let mut attr = TestRunAttr {
        prog_fd: prog as u32,
        data_size_in: frame.len() as u32,
        data_in: frame.as_ptr() as u64,
        repeat,
        ctx_size_in: ctx.as_ref().map_or(0, |c| c.len() as u32),
        ctx_in: ctx.as_ref().map_or(0, |c| c.as_ptr() as u64),
        ctx_size_out,
        ctx_out,
        ..Default::default()
    };
    sys_bpf(BPF_PROG_TEST_RUN, &mut attr).map_err(|e| Error::Sys("BPF_PROG_TEST_RUN", e))?;
    Ok((attr.retval as i32, attr.duration))
}
