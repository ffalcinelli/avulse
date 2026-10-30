# Spike B: a Windows driver in Rust

**Verdict: go, in pure Rust.** One `windows-drivers-rs` driver registers WFP callouts and an NDIS
lightweight filter. It runs avulse's bytecode verifier and interpreter, unchanged, on the packets
of both. It passed its test under Driver Verifier on Windows 11 24H2. No C shim is needed. The
one serious problem was kernel stack depth, which Phase 5 must design for (finding 2).

Date: 2026-10-15. Code: `spikes/windows-driver` (outside the workspace). Machine: the `windows`
Vagrant VM (Windows 11 24H2, build 26100, VirtualBox), test-signed.

## What was built

- **One WDM driver** (`avulse_spike.sys`), installed as an NDIS lightweight filter by
  `avulse_spike.inx`, with `netcfg -l … -c s -i avulse_spike`. The INF declares a modifying,
  optional filter on Ethernet adapters. The same `DriverEntry` also registers the WFP callouts.
- **Filters compiled at build time.** `build.rs` compiles three filters to avulse bytecode with
  `avulse-filter` on the build machine, and the driver embeds the bytes. `DriverEntry` runs
  `bytecode::verify` on them, and the hooks call `VerifiedProgram::matches`. `avulse-proto` and
  `avulse-filter` build for the kernel as they are (`no_std`, `alloc` through `wdk-alloc`).
- **WFP** (`src/wfp.rs`): callouts at `INBOUND_IPPACKET_V4` and `OUTBOUND_IPPACKET_V4`, with their
  sublayer and filters added in a dynamic `FwpmEngineOpen0` session. Closing the session removes
  all of them. The callouts block what `udp.dstport == 53` matches, so the test can see DNS
  fail.
- **NDIS** (`src/lwf.rs`): a pass-through filter that runs `tcp.port in {80 443} or arp` and
  `icmp.type == 8 and ip.dst == 10.0.2.2` on the first `NET_BUFFER` of every send and receive,
  and counts the matches.
- **Counters** (`src/stats.rs`) are written to `HKLM\SOFTWARE\AvulseSpike` at unload.
  `scripts/test.ps1` installs the driver, checks that DNS fails only while the driver is loaded,
  sends 5 pings, uninstalls the driver, and checks the counters.

## Results

Two runs of `test.ps1`, with Driver Verifier (standard flags, special pool) on `avulse_spike.sys`:

| Counter | Run 1 | Run 2 |
| --- | --- | --- |
| WFP packets seen, inbound / outbound | 70 / 65 | 68 / 69 |
| WFP matched and blocked (DNS) | 28 | 34 |
| DNS before / while loaded / after | ok / blocked / ok | ok / blocked / ok |
| LWF modules attached | 1 | 1 |
| LWF frames sent / received | 59 / 92 | 64 / 97 |
| LWF matched `tcp.port in {80 443} or arp` | 23 | 19 |
| LWF matched the echo-request filter (5 pings sent) | 5 | 5 |
| Evaluations that needed a copy (data not contiguous) | 112 | 132 |
| Packets that could not be read | 0 | 0 |
| Least stack left when a packet reached the interpreter | 11,736 B | 11,736 B |
| Evaluations moved to an expanded stack | 8 | 6 |
| Stack expansions that failed | 0 | 0 |

Driver Verifier reported 353 pool allocations, all from special pool, with no failures and no
violations, over three load/unload cycles. No crash dump was written.

## Findings

1. **Pure Rust works; `wdk-sys` is not enough on its own.** `wdk-sys` 0.5 has no NDIS or WFP
   bindings. `build.rs` generates them with bindgen 0.71, using `wdk-build`'s `wdk_default`
   settings and `ntifs.h`, `ndis.h`, `fwpsk.h` and `fwpmk.h` (`NDIS680`), in about 30 lines. Four
   quirks needed handling:
   - `NET_BUFFER` and `NET_BUFFER_LIST` contain `NET_BUFFER_DATA;` and `NET_BUFFER_LIST_DATA;`:
     anonymous members of a named type, a Microsoft extension. bindgen drops them and gets the
     union sizes wrong. The fix makes `_NET_BUFFER_HEADER` and `_NET_BUFFER_LIST_HEADER` opaque,
     and reads the same fields through the structs' own anonymous members (`src/sys.rs`).
   - The WFP layer GUIDs are `extern` (defined only under `INITGUID`), so they are Rust consts.
   - The macros bindgen skips are written by hand: `NDIS_STATUS_SUCCESS`,
     `NET_BUFFER_LIST_FIRST_NB`, `NET_BUFFER_LIST_NEXT_NBL` and `NET_BUFFER_DATA_LENGTH`.
     `IoGetRemainingStackSize` is inline, so it is rebuilt from `IoGetStackLimits`.
   - The generated file raises about 100 warnings (`unnecessary_transmutes`, `unused_imports`),
     which `sys.rs` allows.

   Everything else is ordinary `unsafe` FFI. Phase 5 should put the bindings in their own
   `-sys` crate and add safe wrappers for NBL chains and the classify output.
2. **The kernel stack is the hard constraint.** The first run of the debug build crashed the VM:
   a double fault at a stack page boundary, which is a kernel stack overflow. The x64 kernel
   stack is 24 KiB. NDIS and the WFP IP-packet classify call filters deep in the network stack:
   the release build saw as little as 10,744 bytes left on entry to the interpreter.
   - The debug build's frames (dumpbin) were `value::load` 6,728 B, `exec::run_in` 5,160 B,
     `value::raw_spans` 1,592 B, `Packet::parse_ipv6` 824 B, and many 500–650 B frames in
     `value.rs`. One evaluation needed more than 12 KiB.
   - In the release build (LTO, everything inlined), the largest frame is 4,008 B. The
     interpreter's register file alone is 16 `Vals` of about 170 B each (≈2.7 KiB), because
     `V::Owned` holds 32 bytes.
   - The spike checks the remaining stack before evaluating. Below 12 KiB, it calls the
     interpreter through `KeExpandKernelStackAndCalloutEx` (16 KiB, `Wait = FALSE`, which works at
     DISPATCH_LEVEL), and passes the packet if that fails (fail-open). That happened for 6–8
     packets per run, and never failed.

   **Requirements for Phase 5:**
   - Build the driver in release only.
   - Keep the stack check with `KeExpandKernelStackAndCalloutEx`.
   - Add an `avulse-filter` entry point that takes its register file from the caller (for example
     `VerifiedProgram::matches_in(&mut Scratch, …)`, from a per-processor buffer), so the
     interpreter's frame stays small.
   - Measure the release frames of `value.rs` in CI.
3. **Packet data is often split.** `NdisGetDataBuffer` without storage returns null unless the
   bytes are contiguous, and that was often not the case: Windows' sends put the headers in their
   own MDL. The spike then copies the frame into a pool allocation per evaluation. Phase 5 needs
   a preallocated per-processor buffer, or a `Packet` that reads across MDLs. It also needs to
   decide how much of a frame the filter may see (headers only, or the whole payload).
4. **The inbound IP layers start after the IP header.** At `INBOUND_IPPACKET_V4`, the
   `NET_BUFFER`'s data starts at the transport header. The callout retreats by
   `ipHeaderSize`, evaluates, and advances again, as WinDivert does.
5. **WFP objects in a dynamic session clean themselves up.** Closing the engine handle removes
   the sublayer, callouts and filters, and the callouts are unregistered after that. Unloading
   took no special care, even with traffic running. At boot, the base filtering engine may not be
   running yet. The spike tolerates this (`WfpStatus`); Phase 5 should register on
   `FwpmBfeStateSubscribeChanges0`.
6. **The toolchain works without Visual Studio's IDE.** `scripts/toolchain.ps1` installs
   everything on a fresh VM: Visual Studio 2022 Build Tools (MSVC, the Spectre libraries, the
   Windows 11 SDK 10.0.26100), WDK 10.0.26100 (10.1.26100.6584), LLVM 19.1.7 (libclang for
   bindgen), Rust 1.99 stable (MSVC host), and `cargo-wdk` 0.1.1. The driver crates were `wdk`
   0.4.1, `wdk-sys` 0.5.1 and `wdk-build` 0.5.1.
   - `cargo wdk build --profile release` builds, stamps the INF, makes the catalog, and
     test-signs both.
   - `wdk-build` needs `+crt-static` and the default target directory.
   - The build runs from a local copy of the repository (`robocopy`), because VirtualBox shared
     folders are slow and do not lock files.
   - The same script turns on test signing, Driver Verifier for the driver, and complete kernel
     memory dumps. All three need a reboot (`vagrant reload windows`).
7. **Debugging a crash.** The WDK's `kd` reads the dump:
   `kd -z C:\Windows\MEMORY.DMP -y "srv*C:\symbols*https://msdl.microsoft.com/download/symbols;<pdb dir>" -c "!analyze -v; kv; q"`.
   `dumpbin /disasm` gives each function's frame size (`sub rsp,…`, or the `mov eax,…` before
   `__chkstk`). The crash above left only a triage minidump with no driver frames, which is why
   provisioning now asks for kernel dumps.

## Left for Phase 5

- Injection: `FwpsInjectNetworkSendAsync0`/`ReceiveAsync0` at the NETWORK layers, and NBLs the
  filter allocates and sends at the ETHERNET layer, with loop prevention.
- Diverting packets to user space: a queue, an IOCTL interface, and pending or absorbing
  packets.
- IPv6 and the forward, ALE (FLOW, SOCKET) and REFLECT layers.
- Performance under load, arm64, HLK, and the EV signature (an owner action).
