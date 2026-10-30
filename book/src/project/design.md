# Design and roadmap

This chapter summarizes the design. The full design document, with the reasoning behind each
decision, is [`docs/roadmap.md`](https://github.com/ffalcinelli/avulse/blob/main/docs/roadmap.md);
the current state of the work is in
[`docs/implementation-plan.md`](https://github.com/ffalcinelli/avulse/blob/main/docs/implementation-plan.md).

## Why a new project

WinDivert defines the API, the address structure and the filter language that its users, and the
[ebpfdivert](https://github.com/ffalcinelli/ebpfdivert) port to Linux, build on. That design has
limits: the filter language has no sets, CIDR, ranges or payload slices and fails silently on
type mismatches; there is no Ethernet layer, so non-IP traffic is never seen; and on Linux,
ebpfdivert can only check a superset of the filter in the kernel and must re-check every packet in
user space.

Avulse keeps the model, a superset of WinDivert, and fixes those limits, on Linux, Windows and
macOS.

## Architecture

```text
crates/proto            no_std: Ethernet, VLAN, ARP, IPv4/6, TCP, UDP, ICMP/v6; checksums
crates/filter           filter language: parser → checker → IR → evaluator, bytecode, WinDivert
crates/abi              no_std: Address, Flags, Param, Stats, Windows IOCTL & macOS XPC wire ABI
crates/ebpf             IR → eBPF code generation; static C programs (TC, cgroup)
drivers/windows         WDM driver (avulse.sys): WFP callouts + NDIS filter, runs proto+filter
crates/macos-ext        macOS system extension logic (packets, flows, sockets, reflect, XPC)
drivers/macos           macOS system extension bundle (Avulse.app: NE providers + XPC service)
crates/avulse           public API, capabilities; Linux, Windows and macOS backends
crates/capi             C ABI (libavulse, include/avulse.h)
crates/windivert-compat WinDivert ABI shim (libavulse_windivert.so, avulse_windivert.dll)
crates/cli              the avulse command
```

Rust everywhere except the static BPF programs, which stay in C. The decisive reason is that one
`no_std` crate can run inside the Windows driver, the macOS system extension and Linux user space:
one engine, one set of semantics, one fuzz target.

## The model

- **Layers:** WinDivert's `NETWORK`, `NETWORK_FORWARD`, `FLOW`, `SOCKET` and `REFLECT`, plus
  **`ETHERNET`**: every frame on the selected interfaces, non-IP traffic included.
- **Flags, parameters, priorities, batching and asynchronous I/O**, as in WinDivert.
- **A new address structure**, versioned and with explicit fields, instead of WinDivert's 80-byte
  union. Only the compatibility shim exposes the old layout.
- **`capabilities()`** reports what each backend supports, since the platforms differ (macOS, for
  example, cannot modify a packet in place).

## Where filters run

| Platform | Mechanism | Filter |
| --- | --- | --- |
| Linux | TC (classic `cls_bpf` on `clsact`) and cgroup eBPF programs | compiled to eBPF at runtime, exact in the kernel; a superset in the kernel plus user space as the fallback |
| Windows | own KMDF driver: WFP callouts, an NDIS lightweight filter for Ethernet | verified bytecode, run by the `no_std` interpreter in the driver |
| macOS | system extension: Network Extension providers, `/dev/bpf` | the same interpreter |

## Compiled programs

The Windows driver and the macOS system extension do not walk the IR that user space builds. User
space compiles each filter to a flat bytecode program (`Filter::program`), and the kernel side
verifies it once, when the handle opens, before running it on each packet:

- **Format.** A versioned header, fixed-width instructions over 16 value registers, and a
  constant pool of literals, ranges and sets. The format is specified in the
  [`bytecode` module documentation](../../api/rust/avulse_filter/bytecode/index.html).
- **Verifier.** It checks every opcode and operand, register and field indexes, and every
  constant an instruction refers to. Jumps only go forward, so every program terminates. Neither
  the verifier nor the interpreter allocates or panics.
- **One set of semantics.** The interpreter shares every operation on values with the IR
  evaluator, and tests check that the two agree on every `tshark` table filter and on random
  filters and packets. Fuzz targets feed arbitrary programs to the verifier and arbitrary filters
  to the whole pipeline.
- **User space only.** `matches` has no bytecode: a filter that uses it runs in user space.

`avulse filter explain --bytecode` prints the program.

## Roadmap

| Phase | Content | State |
| --- | --- | --- |
| 0 | Repository, CI, names; spikes: eBPF codegen, Rust Windows driver, macOS | done, except the macOS provider's measurements |
| 1 | `proto` and `filter`: parser, checker, IR, evaluator, bytecode, WinDivert front-end, `tshark` validation, CLI | done |
| 2 | Linux packet layers: NETWORK, NETWORK_FORWARD, ETHERNET | done |
| 3 | Linux event layers (FLOW, SOCKET, REFLECT); API 0.x and the C library | done |
| 4 | WinDivert compatibility shim on Linux; pydivert and jdivert suites as conformance tests | done |
| 5 | Windows driver (`avulse.sys`), `WinDivert.dll` shim, Driver Verifier & HVCI checks | done (attestation signing in v0.0.1) |
| 6 | macOS `/dev/bpf` backend and `Avulse.app` system extension | done, awaiting Developer ID signing to run the providers on macOS |
| 7 | Native Python and Java bindings; 1.0 | planned |

Versions stay 0.0.x while the project is experimental. The first release, 0.0.1, comes after the
Windows and macOS backends.
