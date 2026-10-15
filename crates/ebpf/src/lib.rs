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
//! - [`codegen`] turns a filter's IR into that matcher, with the assembler in [`insn`];
//! - `loader` (Linux only) loads the static object with `aya` and the matcher with the `bpf()`
//!   system call, and runs them with `BPF_PROG_TEST_RUN`.
//!
//! See `docs/spikes/ebpf-codegen.md` for what the spike found.
//!
//! ```
//! use avulse_filter::Filter;
//!
//! let filter = Filter::compile("tcp.dstport == 80 and ip.src == 10.0.0.0/8").unwrap();
//! let matcher = avulse_ebpf::codegen::compile(filter.ir()).unwrap();
//! assert!(matcher.insns().len() < 100);
//!
//! let regex = Filter::compile(r#"tcp.payload contains "GET""#).unwrap();
//! assert!(avulse_ebpf::codegen::compile(regex.ir()).is_err());
//! ```

pub mod abi;
pub mod codegen;
pub mod facts;
pub mod insn;
#[cfg(target_os = "linux")]
pub mod loader;
