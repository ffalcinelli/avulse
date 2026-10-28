# Avulse: a cross-platform packet-diverting library (roadmap)

## Context

Today the workspace builds on someone else's design. WinDivert (basil00) sets the API, the 80-byte address ABI and
the filter language. ebpfdivert reproduces that design on Linux, down to vendoring WinDivert's filter compiler, and
it inherits WinDivert's limits:

- **Filters.** The language is flat. It has no sets, no CIDR, no ranges and no payload slices. Its error messages
  are weak, and it fails silently on type mismatches.
- **Layers.** There is no Ethernet layer, so non-IP traffic is never captured.
- **Matching on Linux.** ebpfdivert can only lower filters to a *superset* in the kernel. It then re-checks every
  packet in user space and re-injects the ones that don't match.

The goal is a new project of our own. It covers every WinDivert feature on **Linux, Windows and macOS**, adds an
**ETHERNET layer**, and has a **new filter language**. It also ships a **WinDivert-compatible shim**, so pydivert and
jdivert can move over without a rewrite.

It will live in a new, fifth repo at `~/Workspace/divert/avulse/` (`github.com/ffalcinelli/avulse`), dual-licensed
LGPL-3.0-or-later / GPL-2.0-or-later like its siblings. The BPF programs must be GPL-compatible.

## Name: **Avulse**

In hydrology, an *avulsion* is a river suddenly leaving its channel for a new one. That is the act of diverting
traffic.

- The name is free on crates.io and PyPI, and no GitHub repo is using it (checked 2026-10-12).
- Artifacts would be named: crate `avulse`, library `libavulse.{so,dll,dylib}`, CLI `avulse`, Python `avulse`, Java
  `com.github.ffalcinelli:avulse` (the Maven groupId jdivert already uses).
- Runner-up: **Divortium**, from *divortium aquarum*, the watershed point where waters part. Also free on crates.io
  and PyPI.

## Language: **Rust** (C only for the static BPF programs)

| | Rust | Zig | C |
| --- | --- | --- | --- |
| Memory safety where it matters (parsing hostile packets and filters, kernel code) | ✅ | partial | ❌ (main source of CVEs) |
| Windows kernel driver | `windows-drivers-rs` (Microsoft, WDM/KMDF) | none in practice | WDK, mature |
| eBPF | `aya`: pure-Rust loader, no static libbpf/libelf/zlib/zstd bundle | weak | libbpf |
| macOS system extension | Swift shim + Rust static lib (fine) | possible | fine |
| Same filter engine in every kernel (`no_std`) | ✅ one crate | ✅ | ✅ but unsafe |
| C ABI for the bindings | `cbindgen` | native | native |
| Language stability | stable | pre-1.0 churn | stable |

The decisive point is that one `no_std` crate (packet parsing plus the filter bytecode interpreter and verifier) can
run inside the Windows driver, the macOS system extension and the Linux user-space fallback. One engine means one
set of semantics and one fuzz target.

- **BPF programs:** keep them in C with libbpf conventions, so we can reuse ebpfdivert's verifier-tuned code, and
  load them with `aya`. Porting them to `aya-ebpf` is optional later.
- **Windows driver fallback:** if the WFP/NDIS bindings in `wdk-sys` turn out to be incomplete, use a thin C shim
  for those calls only.

## Architecture

```
avulse/                    (Cargo workspace)
├─ crates/proto            no_std: Ethernet, 802.1Q/QinQ, ARP, IPv4/6 (+ext hdrs, frags), TCP, UDP, ICMP/v6; checksums
├─ crates/filter           parser (std) → typed AST → IR → optimizer → bytecode + verifier + interpreter (no_std)
│                          + `windivert` front-end (old syntax → same IR)
├─ crates/ebpf             IR → eBPF codegen; static C programs (TC parser/dispatch, cgroup/sockops events)
├─ driver/windows          KMDF driver (windows-drivers-rs): WFP callouts + NDIS LWF, uses proto+filter
├─ macos/                  system extension (Swift NE providers ↔ Rust staticlib) + XPC client backend
├─ crates/avulse           public Rust API, capability query, and the backends as modules:
│                            backend/linux (aya loader, TC clsact attach, ringbuf, injection,
│                            registry/heartbeat, events), backend/windows (IOCTL/overlapped I/O
│                            to the driver), backend/macos (XPC client)
├─ crates/capi             C ABI (cbindgen) → libavulse
├─ crates/windivert-compat WinDivert ABI shim (WinDivertOpen/Recv/Send…, 80-byte WINDIVERT_ADDRESS)
└─ crates/cli              capture / inject / `filter check|explain|fmt|test`
```

### Public model, a superset of WinDivert

- **Layers:**
  - from WinDivert: `NETWORK`, `NETWORK_FORWARD`, `FLOW`, `SOCKET`, `REFLECT`;
  - new: **`ETHERNET`**, meaning all frames on the selected interfaces, including non-IP traffic (ARP, LLDP, VLAN).
- **Flags:** `SNIFF`, `DROP`, `RECV_ONLY`, `SEND_ONLY`, `NO_INSTALL`, `FRAGMENTS`.
- **Parameters:** `QUEUE_LENGTH/TIME/SIZE`, version.
- **Shutdown:** `RECV`/`SEND`.
- **Priority:** −30000..30000.
- **Calls:** batch recv/send and async: a pollable fd on Linux, IOCP/overlapped on Windows, a kqueue-able fd on
  macOS.
- **Helpers:** parse, checksums, filter compile/format/eval.
- **Address:** a new versioned struct, no longer a squeezed union. It has explicit fields for timestamp, layer,
  event, ifindex/subifindex, direction, loopback/impostor/ipv6/checksum flags, VLAN/ethertype, flow/socket info
  (pid, endpoint, 5-tuple), and an explicit **opaque reinjection-context blob**. ebpfdivert currently hides the L2
  header and GSO size inside the union; the blob replaces that hack.
- **`capabilities()`:** reports per backend/layer what is supported (for example, macOS cannot modify in place), so
  applications can adapt.

## Filter language

Design goals: readable, typed, expressive enough for real rules, and still compilable to bounded kernel code.

### Wireshark compatibility (decision)

The native syntax **is** a Wireshark display-filter subset, plus extensions. We do not run a second parser for
Wireshark.

- **Accepted Wireshark syntax:**
  - Operators: `== != === !== < <= > >=`, `eq ne …`, `and or not xor` and `&& || ! ^^`, `in {…}` and
    `not in {…}` with `a..b` ranges, the `any`/`all` quantifiers, arithmetic `+ - * / %` with `{…}`
    grouping, `&` on integers and bytes, slices `[i:n]` / `[i-j]` and lists of them, the layer
    operator `#n` / `#[a-b]`, raw bytes `@field`, `contains`, `matches` / `~`, value-string labels
    (`ip.proto == "TCP"`), and functions `len()`, `count()`, `max()`, `min()`, `abs()`, `upper()`,
    `lower()`. Not supported: `string()`, `dec()`, `hex()`, `float()`, `vals()`, and `${field}`
    references to the packet selected in the Wireshark GUI.
  - Field names for the protocols we parse: `frame.len`, `frame.interface_name`, `eth.*`, `vlan.*`,
    `ieee8021ad.*`, `arp.*`, `ip.*`, `ipv6.*` (with `ipv6.fraghdr.*`), `tcp.*`, `udp.*`, `icmp.*`, `icmpv6.*`.
  - The usual idioms: `ip.addr`, `tcp.port`, `eth.addr`.
- **Semantics follow Wireshark 4.6 and later.** On multi-valued fields, `==` means *any* and `!=` means *all
  not*, and `!==` means *any not*. `not in` means the field is present and none of its values is in the set.
  A comparison with an absent field is false. A filter that copies and pastes from Wireshark and parses must mean
  the same thing. The differences are listed in the guide (`book/src/filters/wireshark.md`).
- **Compatibility rule.** A filter that compiles means what it means in Wireshark. Avulse may reject more (types,
  the evaluator's fixed buffers), with an error and a hint, but it never gives a different result silently.
  Each audience gets its own compatibility: people writing new filters get Wireshark's language, which they
  know and can test with `tshark`; existing WinDivert users get WinDivert's API, address struct and filter
  syntax, through the `windivert-compat` shim and its front-end. The native language does not imitate
  WinDivert's.
- **Clear rejections.** Fields that need dissector state are rejected with a clear message: `http.*`, `tls.*`, or
  anything that needs TCP reassembly. `matches` (PCRE) only runs in user space, through the fallback path, and
  `filter explain` says so.
- **Extensions that are not Wireshark:**
  - `let` definitions, used as `$name` / `${name}` (Wireshark macro style);
  - direction and layer fields: `inbound`, `outbound`, `loopback`, `impostor`, `ifidx`;
  - flow/socket fields: `event`, `process.pid`, `process.name`, `local.*`, `remote.*`;
  - symbolic constants that Wireshark does not know: `syn`, `echo-request`, `ip.proto == tcp`…
  - `#`, `//` and `/* */` comments, `~=` (Wireshark 3.6's spelling of `!==`), and space-separated sets.
- **Oracle.** Wireshark's own `dftest` and `tshark -Y` are a free oracle. `crates/filter/src/tests/tshark.rs` is a
  differential test: it runs `tshark -Y <filter>` and our evaluator over the same generated captures and asserts
  the same packet set (`AVULSE_TSHARK=1`, needs tshark 4.6+; a CI job installs it from the Wireshark stable
  PPA).
- **Front-ends.** Three front-ends compile to one IR: native/Wireshark, WinDivert (compat shim) and, optionally
  after 1.0, tcpdump/pcap syntax.

```text
# comments
let lan  = {10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fd00::/8}
let web  = tcp.port in {80, 443, 8000..8100}           # tcp.port = src OR dst

outbound and ip.dst not in $lan and $web
eth.type == arp and arp.opcode == request
vlan.id == 100 and eth.src == 00:11:22:33:44:55
tcp.flags & syn and not tcp.flags & ack               # symbolic constants
icmp.type == echo-request
udp.dstport == 53 and udp.payload[2:2] == 01:00         # payload slices
tcp.payload[0:4] == "GET " or tcp.payload contains "Host:"   # Wireshark-valid; contains is bounded
iface == "eth0" and not loopback
event == connect and process.pid == 1234 and remote.port == 443   # SOCKET layer
```

- **Sets, ranges, CIDR,** and MAC/IPv4/IPv6 literals. Direction-agnostic fields (`ip.addr`, `tcp.port`) and
  local/remote fields (`local.port`, `remote.addr`).
- **Strict typing.** A mismatch such as `ip.src == ::1` is a compile error, not a silent false. Errors carry source
  spans and suggestions (miette-style).
- **Clear absence semantics.** A predicate on a field that is absent is false, and `f != x` means
  `has(f) and not f == x`. This is documented once and fuzzed.
- **Tooling:**
  - `avulse filter explain` shows the IR and what runs in the kernel versus user space;
  - `filter fmt` is a canonical formatter;
  - `filter test` evaluates against a pcap.
- **WinDivert front-end.** The old syntax compiles to the same IR, so the compat shim stays exact and old filters
  can be translated mechanically (`avulse filter convert`).

### Where filters run

The pipeline is IR → bytecode (forward jumps only, so the verifier proves termination) → interpreter.

- **Linux.** The IR is code-generated into eBPF **at runtime**. A static C TC program parses the headers into a
  per-CPU "facts" struct, then calls `bpf_tail_call` into the handle's generated matcher. A tail call does not
  return, so the matcher writes its verdict into the facts and tail-calls a static action program, which diverts
  or passes the packet. This makes filtering **exact in the kernel**, which fixes ebpfdivert's main weakness.
  Spike A confirmed it on 5.15 and 6.8 (`docs/spikes/ebpf-codegen.md`).
- **Linux fallback.** If the verifier rejects the generated program (for example, an old kernel or a huge
  filter), fall back to ebpfdivert's approach: superset rules in the kernel, then the interpreter in user space
  with auto-reinjection.
- **Windows.** The driver runs the same `no_std` interpreter crate, verifying the bytecode at handle open.
- **macOS.** The system extension runs the same interpreter.

## Feature mapping per backend

| Feature | Linux | Windows (own driver) | macOS (system extension) |
| --- | --- | --- | --- |
| NETWORK | TC clsact cls_bpf (not TCX), `TC_ACT_STOLEN` | WFP `INBOUND/OUTBOUND_IPPACKET` callouts | `NEFilterPacketProvider` (allow, drop, delay then allow); modify = drop + reinject |
| NETWORK_FORWARD | TC with `ingress_ifindex` / `bpf_fib_lookup` (as ebpfdivert) | WFP `IPFORWARD` | limited: pf has no divert (`route-to`/`dup-to` only) + bpf device; documented gap |
| **ETHERNET** | TC sees L2; restore the offloaded VLAN tag (`skb->vlan_tci`) in captured frames | **NDIS Lightweight Filter** send/receive NBL hooks | `NEFilterPacketProvider` / `/dev/bpf` for L2 inject |
| FLOW | sockops + cgroup_skb (port `ebpfdivert_events.bpf.c`) | WFP `ALE_FLOW_ESTABLISHED` + flow-delete | `NEFilterDataProvider` flows |
| SOCKET (block bind/connect) | cgroup connect/bind hooks, `EPERM` | WFP `ALE_{BIND,CONNECT,LISTEN,ACCEPT}` | data provider (connect); bind/listen sniff-only |
| REFLECT | pinned registry diff (as ebpfdivert) | driver handle table | daemon registry |
| Reinjection | AF_PACKET + vnet GSO, raw IP, `lo` redirect | `FwpsInject*` / `NdisF{Send,Indicate}NetBufferLists` | outbound: `/dev/bpf` write (L2); inbound: raw IP socket (host-order `ip_len`/`ip_off`; bpf cannot inject inbound) |
| Priority, loop prevention | TC prio + `skb->mark` tagging | WFP sublayer weights + inject-context tagging | daemon-ordered handler chain |
| Crash safety | heartbeat, fail-open | handle cleanup on process exit | daemon watches XPC client death |

## Roadmap

The phases run in order. Each has an exit criterion.

### Phase 0: Spikes and project setup

1. Create the repo, Cargo workspace, CI (Linux, Windows, macOS runners), licenses, and claim the name on crates.io,
   PyPI and GitHub.
2. **Spike A, eBPF codegen.** Generate a trivial matcher at runtime, tail-call into it from a static TC program,
   and get it through the verifier on 5.15 and 6.8. Done: go (`docs/spikes/ebpf-codegen.md`).
3. **Spike B, Windows Rust driver.** Build a `windows-drivers-rs` KMDF driver that registers one WFP callout and
   one NDIS LWF, test-signed, loaded in a Windows VM. Decide whether pure Rust is viable or whether a thin C shim is
   needed. Done: go, pure Rust, with our own bindgen for NDIS and WFP (`docs/spikes/windows-driver.md`).
4. **Spike C, macOS.** Find out whether `NEFilterPacketProvider` exposes Ethernet frames, measure its throughput
   and delay semantics, and test reinjection through `/dev/bpf`. Partly done on GitHub's macOS runners
   (`docs/spikes/macos.md`): bpf injects outbound only; a raw socket (host-order `ip_len`) reinjects inbound on the
   right interface; pf has no divert; the system extension builds with the Rust library and stops at the user's
   approval, so the provider's frame level, throughput and delay are still to measure before Phase 6.

Exit: a written go/no-go note for each spike, and the capability matrix above confirmed or corrected.

### Phase 1: `proto` and `filter` crates (pure, host-testable)

1. Write the grammar, typechecker, IR, optimizer, bytecode, verifier, interpreter and WinDivert front-end.
2. Port WinDivert's filter test vectors from `ebpfdivert/tests/test_filter.c` as conformance tests for the
   front-end.
3. Add `cargo-fuzz` targets: parser, verifier (it must reject anything unsafe), and interpreter vs. AST evaluator
   (differential).
4. Add a Wireshark differential test: `tshark -Y` against our evaluator over a pcap corpus, for the supported field
   set.
5. Ship the CLI `filter check|explain|fmt|convert`.

Exit: the WinDivert vectors pass, the `tshark` differential tests agree, fuzzing finds nothing after a long run,
and the CLI is usable.

### Phase 2: Linux packet layers (NETWORK, NETWORK_FORWARD, ETHERNET)

1. Port the TC program and the injection paths from `ebpfdivert/src/ebpfdivert.bpf.c` and `ebpfdivert/src/handle.c`.
   This covers ringbuf size classes, GSO via `virtio_net_hdr`, `lo` redirect for inbound, mark-based loop
   prevention, the priority registry, the heartbeat (fail-open), queue limits and fragments.
2. Add the runtime eBPF codegen from the IR, with the superset fallback.
3. Add ETHERNET: non-IP frames, VLAN tag restore on capture and on reinjection.

Progress (steps in `docs/implementation-plan.md`): the kernel side of capture (Step 7), the backend's receive
side (Step 8: open, attach, registry, heartbeat, queue, `avulse cleanup`) and injection (Step 9: raw and
`AF_PACKET` sockets, the `lo` redirect, GSO, reinjection by user-space filters) and the matcher's coverage with the
superset fallback (Step 10: metadata, IPv6, VLAN, TCP options, arithmetic, set trees) and the ETHERNET layer
(Step 11: ARP, VLAN and QinQ with or without offload, non-IP injection) are done, and the privileged suite (Step 12)
passes on both VMs. **Phase 2 is done.** Devices without an Ethernet header (tun, WireGuard, PPP, IP tunnels) are
supported at the NETWORK layers since Step 13. Phase 3 comes next.

Exit: privileged tests pass on both Vagrant VMs, covering divert, inject, GSO, forward, ETHERNET/ARP/VLAN, crash
cleanup, and exact in-kernel match versus interpreter (`BPF_PROG_TEST_RUN`).

### Phase 3: Linux event layers and API 0.x

1. Port `ebpfdivert/src/ebpfdivert_events.bpf.c` for FLOW and SOCKET, add `process.name` (comm), and REFLECT.
2. Review the Rust API and the C ABI as 0.x (`libavulse.so`).

Progress (steps in `docs/implementation-plan.md`): the event programs (Step 14), the FLOW layer (Step 15) and the
SOCKET layer, which refuses binds and connects with eBPF matchers generated for the cgroup programs (Step 16), and
`process.name` with the REFLECT layer (Step 17) are done: every layer works on Linux. The API is reviewed for 0.x
(batch calls, `#[non_exhaustive]`) and the C ABI is `crates/capi` (Step 18). **Phase 3 is done.**

Exit: every layer on Linux, and the C ABI. The release first planned here waits for Phases 5 and 6 (see "Releases"
below).

### Phase 4: WinDivert compat shim on Linux and conformance

1. Build `libavulse-windivert.so`, which exports ebpfdivert's C API surface.
2. Run the **pydivert and jdivert test suites unchanged** against it, through the existing hooks:
   `PYDIVERT_EBPFDIVERT_LIB` and `-Debpfdivert.local`.

Progress (steps in `docs/implementation-plan.md`): `crates/windivert-compat` builds `libavulse_windivert.so`. It
exports libebpfdivert's API over avulse, and its helpers agree with WinDivert's own code (Steps 19 and 20). Left: the
binding suites (Step 21).

Exit: both suites pass. The binding suites become a free cross-language conformance suite.

### Phase 5: Windows driver

1. Build the KMDF driver: WFP callouts for every WinDivert layer, NDIS LWF for ETHERNET, the `no_std` interpreter,
   an IOCTL/overlapped I/O interface, sublayer priorities and inject-context loop tagging.
2. Make it clean under Driver Verifier and HVCI.
3. Set up the signing pipeline: EV certificate and attestation signing through Partner Center.
4. Ship the compat `WinDivert.dll` drop-in.

Exit: the pydivert and jdivert Windows suites pass against it, and the driver is attestation-signed.

### Phase 6: macOS system extension

1. Build the NE packet and data providers, the XPC daemon (registry, priority chain, client-death cleanup), and
   L2 reinjection through `/dev/bpf`.
2. Notarize, and document every gap through `capabilities()`.

Exit: a macOS test suite passes on real hardware, and the capability matrix is published.

### Releases

Versions stay 0.0.x while the project is experimental (owner decision, 2026-10-28). The first release, **v0.0.1**,
comes after Phases 5 and 6, so that it covers Linux, Windows and macOS: the crates on crates.io, and signed
`libavulse` tarballs (static, manylinux_2_28) with SBOMs. The plan is in `docs/implementation-plan.md`.

### Phase 7: Bindings and 1.0

1. Write native Python (PyO3/maturin, or ctypes over the C ABI) and Java (Panama, with JNA fallback) bindings.
   Migrate pydivert/jdivert, or retire them in favour of the native bindings.
2. Write docs and a filter language reference, benchmark pps/latency against WinDivert and ebpfdivert, get a
   security review of the driver and the verifier, and freeze the API.

### Post-1.0 candidates

- XDP fast path for sniff/drop-only handles
- AF_XDP zero-copy receive
- Tunnel-aware fields (GRE, VXLAN, GENEVE)
- Rate and connection-tracking predicates

## Reuse from this workspace

- `ebpfdivert/src/ebpfdivert.bpf.c` and `ebpfdivert/src/ebpfdivert_events.bpf.c`: verifier-tuned BPF code (global
  funcs for 5.15, inline-asm length bounds, `barrier_var`), ported as the static BPF programs.
- `ebpfdivert/src/handle.c`: injection-path table, registry/heartbeat, queue semantics, REFLECT diffing (logic
  reference for the Linux backend).
- `ebpfdivert/src/prefilter.c`: superset-lowering ideas for the verifier-rejection fallback.
- `ebpfdivert/tests/test_filter.c`, `test_bpf.c`, `tests/run_integration_tests.sh`: vectors and integration
  scenarios.
- `ebpfdivert/Vagrantfile` (5.15 + 6.8 VMs), pydivert/jdivert Vagrant Windows VMs, and the binding test suites as
  conformance tests.
- `windivert/sys/windivert.c`: reference for WFP layer and callout usage and injection edge cases. Read it only;
  do not copy it, because of the license and because the new driver is written in Rust.

## Signing and distribution

- **OSSign (ossign.org).** OSSign is a signing *tool*, built on Relic. Keys come from Azure Artifact (Trusted)
  Signing, Azure Key Vault or a local certificate. Use it in CI for every **user-mode** artifact:
  - `avulse.exe`, `avulse.dll` and the compat `WinDivert.dll`;
  - MSI, JAR and Python wheels.
- **Windows kernel driver.** OSSign is **not enough** here. On Windows with Secure Boot, a kernel driver loads
  only if Microsoft signs it, through **attestation signing in Partner Center** (Hardware Dev Center). Registering
  and submitting there still needs an **EV code-signing certificate**, and Azure Trusted Signing does not replace
  it for kernel mode.
  - Budget for one EV certificate on a hardware token or cloud HSM. It is used only to sign the driver CAB
    submissions.
  - OSSign/Trusted Signing covers everything else.
  - Phase 0 starts the EV purchase and Partner Center enrollment, because both have a lead time.
  - Until then, development uses test signing in the VM.
- **macOS.** An Apple Developer ID ($99/yr), the Network Extension entitlement for the system extension, and
  notarization through `notarytool`. OSSign does not cover this.
- **Linux.** Nothing to sign for loading. Sign the release tarballs (Sigstore/cosign) and publish SBOMs.

## Main risks

- **Rust in the Windows kernel.** `wdk-sys` lacks WFP/NDIS bindings; Spike B generated its own with bindgen, so no
  C shim is needed.
- **Kernel stack depth on Windows.** NDIS and WFP leave about 12 KiB of the 24 KiB kernel stack to a filter, and a
  debug build of the interpreter overflowed it. Mitigation: release builds, a stack check with
  `KeExpandKernelStackAndCalloutEx`, and a caller-provided register file for the interpreter (Spike B).
- **macOS fidelity.** There is no in-place modify and only a weak forward layer. Mitigation: the drop+reinject
  emulation, the `capabilities()` API, and setting expectations early.
- **Driver signing.** The EV certificate and Partner Center enrollment are unavoidable for the kernel driver, and
  OSSign covers user mode only. Start both in Phase 0.
- **Wireshark semantic drift.** Edge cases differ: absent fields, multi-occurrence fields, slices on short packets.
  Mitigation: the `tshark -Y` differential tests in Phase 1, pinned to a Wireshark 4.x version.
- **Verifier variance across kernels.** Mitigation: the superset fallback, plus the legacy VM in CI.

## Verification

- **Host, no root:**
  - `cargo test`, `cargo clippy -D warnings`;
  - `cargo fuzz` (parser, verifier, interpreter differential);
  - the WinDivert vector conformance tests;
  - the eBPF codegen tests through `BPF_PROG_TEST_RUN`. These need root, so they run on a VM.
- **Linux privileged.** Vagrant `default` (6.8) and `legacy` (5.15) VMs, one at a time, `vagrant destroy -f` right
  after. Run the integration scenarios from ebpfdivert, plus the ETHERNET/VLAN/ARP tests.
- **Conformance.** The pydivert and jdivert suites through the compat shim, on Linux (Phase 4) and Windows
  (Phase 5).
- **Windows.** VM in test-signing mode with Driver Verifier enabled. HLK before 1.0.
- **macOS.** Real Mac with `systemextensionsctl developer on`. Notarized build before release.
