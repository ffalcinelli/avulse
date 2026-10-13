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
crates/filter           filter language: parser → checker → IR → evaluator (bytecode planned)
crates/ebpf             IR → eBPF code generation; static C programs (TC, cgroup)    planned
crates/backend-linux    aya loader, TC attach, ring buffer, injection, registry      planned
driver/windows          KMDF driver: WFP callouts + NDIS filter, runs proto+filter    planned
macos/                  system extension (Network Extension) + XPC client             planned
crates/avulse           public Rust API, backend trait, capability query             planned
crates/capi             C ABI (libavulse)                                             planned
crates/windivert-compat WinDivert ABI shim                                            planned
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

## Roadmap

| Phase | Content | State |
| --- | --- | --- |
| 0 | Repository, CI, names; spikes: eBPF codegen, Rust Windows driver, macOS | setup done, spikes pending |
| 1 | `proto` and `filter`: parser, checker, IR, evaluator, `tshark` validation, CLI | in progress: bytecode and the WinDivert front-end remain |
| 2 | Linux packet layers: NETWORK, NETWORK_FORWARD, ETHERNET | planned |
| 3 | Linux event layers (FLOW, SOCKET, REFLECT); API v0.1 | planned |
| 4 | WinDivert compatibility shim; pydivert and jdivert suites as conformance tests | planned |
| 5 | Windows driver, signed | planned |
| 6 | macOS system extension, notarized | planned |
| 7 | Native Python and Java bindings; 1.0 | planned |
