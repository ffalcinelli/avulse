//! The event programs of the FLOW and SOCKET layers (`bpf/events.bpf.c`), attached to the
//! cgroup v2 root through `bpf_link`s.

use std::fs::{self, File};
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;

use avulse_filter::{Event, Layer};
use aya::maps::{Map, RingBuf};
use aya::programs::{CgroupAttachMode, Program, ProgramError};
use aya::{Ebpf, EbpfLoader};

use super::{
    Error, Ring, Stats, aya, config_writer, drain, prog_load_as, set_config, stats, update,
};
use crate::abi::{self, Config};
use crate::codegen::Matcher;
use crate::facts::{SLOT_ACTION, SLOT_MATCHER};

/// The event programs, built from `bpf/events.bpf.c`.
pub static EVENTS_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/events.bpf.o"));

/// The programs, and the layers that attach them.
const PROGRAMS: &[(&str, &[Layer])] = &[
    ("avulse_ev_create", &[Layer::Flow, Layer::Socket]),
    ("avulse_ev_bind4", &[Layer::Socket]),
    ("avulse_ev_bind6", &[Layer::Socket]),
    ("avulse_ev_connect4", &[Layer::Socket]),
    ("avulse_ev_connect6", &[Layer::Socket]),
    ("avulse_ev_release", &[Layer::Flow, Layer::Socket]),
    ("avulse_ev_sockops", &[Layer::Flow, Layer::Socket]),
    ("avulse_ev_egress", &[Layer::Flow]),
    ("avulse_ev_ingress", &[Layer::Flow]),
    // Tail-called, never attached.
    ("avulse_ev_act_connect4", &[]),
    ("avulse_ev_act_connect6", &[]),
    ("avulse_ev_act_bind4", &[]),
    ("avulse_ev_act_bind6", &[]),
];

const BPF_PROG_TYPE_CGROUP_SOCK: u32 = 9;
const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;
const BPF_CGROUP_INET4_CONNECT: u32 = 10;
const BPF_CGROUP_INET6_CONNECT: u32 = 11;
const BPF_CGROUP_INET4_POST_BIND: u32 = 12;
const BPF_CGROUP_INET6_POST_BIND: u32 = 13;

/// A kind of event program that can refuse calls: each has its own matcher
/// ([`Events::set_matcher`]), generated for its [`event`](EventHook::event).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EventHook {
    /// `connect` on an IPv4 socket.
    Connect4,
    /// `connect` on an IPv6 socket.
    Connect6,
    /// `bind` of an IPv4 socket.
    Bind4,
    /// `bind` of an IPv6 socket.
    Bind6,
}

impl EventHook {
    /// Every kind.
    pub const ALL: [EventHook; 4] = [
        EventHook::Connect4,
        EventHook::Connect6,
        EventHook::Bind4,
        EventHook::Bind6,
    ];

    /// The event its matcher decides.
    pub fn event(self) -> Event {
        match self {
            EventHook::Connect4 | EventHook::Connect6 => Event::SocketConnect,
            EventHook::Bind4 | EventHook::Bind6 => Event::SocketBind,
        }
    }

    /// Its program array, its action program, and the program and attach types of its
    /// matcher.
    fn parts(self) -> (&'static str, &'static str, u32, u32) {
        match self {
            EventHook::Connect4 => (
                "avulse_progs_connect4",
                "avulse_ev_act_connect4",
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                BPF_CGROUP_INET4_CONNECT,
            ),
            EventHook::Connect6 => (
                "avulse_progs_connect6",
                "avulse_ev_act_connect6",
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                BPF_CGROUP_INET6_CONNECT,
            ),
            EventHook::Bind4 => (
                "avulse_progs_bind4",
                "avulse_ev_act_bind4",
                BPF_PROG_TYPE_CGROUP_SOCK,
                BPF_CGROUP_INET4_POST_BIND,
            ),
            EventHook::Bind6 => (
                "avulse_progs_bind6",
                "avulse_ev_act_bind6",
                BPF_PROG_TYPE_CGROUP_SOCK,
                BPF_CGROUP_INET6_POST_BIND,
            ),
        }
    }
}

/// The event programs of one handle, their maps and their links. Dropping it detaches the
/// programs; so does the end of the process, which closes the links.
pub struct Events {
    ebpf: Ebpf,
    /// `None` once [`take_ring`](Events::take_ring) took it.
    ring: Option<Ring>,
    have_task: bool,
    /// The matchers in the program arrays.
    matchers: Vec<OwnedFd>,
}

/// The mount point of the cgroup v2 hierarchy, where the programs attach.
pub fn cgroup_root() -> Result<PathBuf, Error> {
    let info = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|e| Error::Sys("/proc/self/mountinfo", e))?;
    // Fields: ID, parent, major:minor, root, mount point, options, optional fields, "-", type.
    info.lines()
        .find(|l| {
            l.split(" - ")
                .nth(1)
                .is_some_and(|t| t.starts_with("cgroup2 "))
        })
        .and_then(|l| l.split(' ').nth(4))
        .map(|p| PathBuf::from(p.replace("\\040", " ")))
        .ok_or_else(|| {
            Error::Sys(
                "cgroup2",
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "no cgroup v2 hierarchy is mounted",
                ),
            )
        })
}

fn load_program(p: &mut Program) -> Result<(), ProgramError> {
    match p {
        Program::CgroupSock(p) => p.load(),
        Program::CgroupSockAddr(p) => p.load(),
        Program::SockOps(p) => p.load(),
        Program::CgroupSkb(p) => p.load(),
        _ => Err(ProgramError::UnexpectedProgramType),
    }
}

/// Attaches `p` to the cgroup `cg` with a link. Links always allow other programs, and the
/// kernel refuses the attach flags with them, hence `Single` (its flags are 0).
fn attach_program(p: &mut Program, cg: &File) -> Result<(), ProgramError> {
    let mode = CgroupAttachMode::Single;
    match p {
        Program::CgroupSock(p) => p.attach(cg.as_fd(), mode).map(drop),
        Program::CgroupSockAddr(p) => p.attach(cg.as_fd(), mode).map(drop),
        Program::SockOps(p) => p.attach(cg.as_fd(), mode).map(drop),
        Program::CgroupSkb(p) => {
            let kind = p
                .expected_attach_type()
                .ok_or(ProgramError::UnexpectedProgramType)?;
            p.attach(cg.as_fd(), kind, mode).map(drop)
        }
        _ => Err(ProgramError::UnexpectedProgramType),
    }
}

impl Events {
    /// Loads the event programs with a ring buffer of `ring_bytes` (a power of two and a
    /// multiple of the page size). The configuration is all zeros: the layer is not FLOW or
    /// SOCKET, so nothing is reported until [`set_config`](Events::set_config) names one.
    ///
    /// Kernels that do not let cgroup socket programs ask for the current task get programs
    /// that leave the process ID and name to the socket's storage ([`have_task`]).
    ///
    /// [`have_task`]: Events::have_task
    pub fn load_with_ring(ring_bytes: u32) -> Result<Self, Error> {
        match Self::load_as(ring_bytes, true) {
            Err(Error::Aya(_)) => Self::load_as(ring_bytes, false),
            r => r,
        }
    }

    fn load_as(ring_bytes: u32, have_task: bool) -> Result<Self, Error> {
        let mut ebpf = EbpfLoader::new()
            .map_max_entries("avulse_ring", ring_bytes)
            .override_global("avulse_have_task", &u32::from(have_task), true)
            .load(EVENTS_OBJECT)
            .map_err(|e| Error::Ebpf(Box::new(e)))?;
        for (name, _) in PROGRAMS {
            let prog = ebpf
                .program_mut(name)
                .ok_or_else(|| Error::Aya(format!("no program {name}")))?;
            load_program(prog).map_err(aya(name))?;
        }
        let ring = ebpf
            .take_map("avulse_ring")
            .ok_or_else(|| Error::Aya("no map avulse_ring".into()))?;
        let ring = RingBuf::try_from(ring).map_err(aya("avulse_ring"))?;
        let events = Events {
            ebpf,
            ring: Some(ring),
            have_task,
            matchers: Vec::new(),
        };
        for hook in EventHook::ALL {
            let (progs, action, ..) = hook.parts();
            update(events.map_fd(progs)?, SLOT_ACTION, events.prog_fd(action)?)?;
        }
        Ok(events)
    }

    fn prog_fd(&self, name: &str) -> Result<RawFd, Error> {
        let prog = self
            .ebpf
            .program(name)
            .ok_or_else(|| Error::Aya(format!("no program {name}")))?;
        Ok(prog.fd().map_err(aya(name))?.as_fd().as_raw_fd())
    }

    fn map_fd(&self, name: &str) -> Result<RawFd, Error> {
        match self.ebpf.map(name) {
            Some(Map::ProgramArray(d) | Map::PerCpuArray(d)) => Ok(d.fd().as_fd().as_raw_fd()),
            _ => Err(Error::Aya(format!("no map {name}"))),
        }
    }

    /// Loads `m`, generated for [`hook.event()`](EventHook::event) at the SOCKET layer, as the
    /// matcher of `hook`'s programs. Until it is set, those programs let calls through. The
    /// error is [`Error::Rejected`] when the verifier refuses it.
    pub fn set_matcher(&mut self, hook: EventHook, m: &Matcher) -> Result<Stats, Error> {
        let (progs, _, prog_type, attach) = hook.parts();
        let progs = self.map_fd(progs)?;
        let insns = m.with_fds(self.map_fd("avulse_ev_state")?, progs);
        let (fd, log) = prog_load_as(&insns, prog_type, attach)?;
        update(progs, SLOT_MATCHER, fd.as_raw_fd())?;
        self.matchers.push(fd);
        Ok(Stats {
            insns: insns.len(),
            log,
        })
    }

    /// Whether the programs ask the current task for the process ID and name. Without, the
    /// socket's events report the process that made it only when the kernel tells (sockops and
    /// packets never do), and its name not at all.
    pub fn have_task(&self) -> bool {
        self.have_task
    }

    /// Attaches the programs `layer` needs (FLOW or SOCKET) to the cgroup v2 root, so that they
    /// see every socket of the system. Write the configuration first.
    pub fn attach(&mut self, layer: Layer) -> Result<(), Error> {
        let root = cgroup_root()?;
        let cg = File::open(&root).map_err(|e| Error::Sys("opening the cgroup root", e))?;
        for (name, layers) in PROGRAMS {
            if !layers.contains(&layer) {
                continue;
            }
            let prog = self
                .ebpf
                .program_mut(name)
                .ok_or_else(|| Error::Aya(format!("no program {name}")))?;
            attach_program(prog, &cg).map_err(aya(name))?;
        }
        Ok(())
    }

    /// Takes the ring buffer, for a reader of its own. [`records`](Events::records) is empty
    /// after.
    pub fn take_ring(&mut self) -> Option<Ring> {
        self.ring.take()
    }

    /// Takes every record in the ring buffer (see [`abi::EventRecord::parse`]).
    pub fn records(&mut self) -> Vec<Vec<u8>> {
        drain(&mut self.ring)
    }

    /// A writer of the configuration that does not borrow the programs, for a heartbeat thread.
    pub fn config_writer(&self) -> Result<super::ConfigWriter, Error> {
        config_writer(&self.ebpf)
    }

    /// Writes the handle's configuration: its layer, `CFG_SHUTDOWN`, `CFG_SNIFF` and the
    /// heartbeat.
    pub fn set_config(&mut self, config: &Config) -> Result<(), Error> {
        set_config(&mut self.ebpf, config)
    }

    /// The statistics, summed over the CPUs, indexed by [`abi::stat`] (the event programs count
    /// `RING_FULL` and `OWNER_GONE`).
    pub fn stats(&self) -> Result<[u64; abi::stat::COUNT], Error> {
        stats(&self.ebpf)
    }
}
