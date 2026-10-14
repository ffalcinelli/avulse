//! Filter IR to eBPF code generation and the static BPF programs.
//!
//! **Spike A** (Phase 0): this crate checks that a filter can run exactly in the kernel as eBPF
//! generated at runtime. Its pieces:
//!
//! - `bpf/tc.bpf.c`, a static TC (cls_bpf) program in C, parses the headers as
//!   [`avulse_proto::Packet`] does and writes the result to per-CPU [`facts`], then tail-calls
//!   the matcher;
//! - [`codegen`] turns a filter's IR into that matcher, with the assembler in [`insn`];
//! - `loader` (Linux only) loads the static object with `aya` and the matcher with the `bpf()`
//!   system call, and runs both with `BPF_PROG_TEST_RUN`.
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

pub mod codegen;
pub mod facts;
pub mod insn;
#[cfg(target_os = "linux")]
pub mod loader;
