//! Filter IR to eBPF code generation and the static BPF programs of the Linux backend.
//!
//! A filter runs exactly in the kernel as eBPF generated at runtime (Spike A, Phase 0). The
//! pieces:
//!
//! - `bpf/tc.bpf.c`, the static TC (cls_bpf) programs in C. `avulse_ingress` and
//!   `avulse_egress` check the handle's configuration ([`abi::Config`]: layer, flags,
//!   heartbeat, marks), parse the headers as [`avulse_proto::Packet`] does into per-CPU
//!   [`facts`], and tail-call the matcher. The matcher tail-calls `avulse_act`, which diverts
//!   the packet to a ring buffer ([`abi::Record`]), copies it, or drops it;
//! - [`codegen`] turns a filter's IR into that matcher, with the assembler in [`insn`]; what it
//!   cannot compile it widens to a superset ([`codegen::compile_superset`]), which user space
//!   filters again;
//! - `bpf/events.bpf.c`, the event programs of the FLOW and SOCKET layers, on the cgroup v2
//!   root and `sockops`: they report what sockets do as [`abi::EventRecord`]s;
//! - `loader` (Linux only) loads the static objects with `aya` and the matcher with the `bpf()`
//!   system call, and runs them with `BPF_PROG_TEST_RUN`.
//!
//! See `docs/spikes/ebpf-codegen.md` for what the spike found.
//!
//! ```
//! use avulse_ebpf::codegen::{self, Env};
//! use avulse_filter::{Filter, Layer};
//!
//! let env = Env::new(Layer::Network);
//! let filter = Filter::compile("tcp.dstport == 80 and ip.src == 10.0.0.0/8").unwrap();
//! let matcher = codegen::compile(filter.ir(), &env).unwrap();
//! assert!(matcher.exact() && matcher.insns().len() < 100);
//!
//! // A search of the whole payload does not run in the kernel: the kernel takes what has a
//! // TCP payload, and user space looks for "GET" in it.
//! let get = Filter::compile(r#"tcp.dstport == 80 and tcp.payload contains "GET""#).unwrap();
//! assert!(codegen::compile(get.ir(), &env).is_err());
//! let superset = codegen::superset(get.ir(), &env);
//! assert_eq!(superset.test.native().to_string(), "tcp.dstport == 80");
//! assert!(!codegen::compile_superset(get.ir(), &env).unwrap().exact());
//! ```

pub mod abi;
pub mod codegen;
pub mod facts;
pub mod insn;
#[cfg(target_os = "linux")]
pub mod loader;
