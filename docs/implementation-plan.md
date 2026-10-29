# Avulse implementation plan

This is the hand-off document between sessions. `docs/roadmap.md` holds the design: why Rust, the layer
and backend matrix, the filter-language decisions, and the phases. This file holds where the
implementation stands and the next steps, specified well enough to start without re-deriving
anything. When a step lands, tick it here, update **Status**, and commit this file with the code.

## Status (2026-10-29, Phases 2 to 4 done: Steps 1 to 21 and Spikes A and B, Spike C partly done; Phase 5: Steps 22 to 28 done, next Step 29)

| Area | State |
| --- | --- |
| `crates/proto` (`avulse-proto`) | Done for Phase 1. Zero-copy `no_std` parsing: Ethernet, 2 VLAN tags, ARP, IPv4, IPv6 (8 extension headers, fragments), TCP (options: `Tcp::option_iter`, `option`), UDP, ICMP, ICMPv6. Checksum recalculation (all, or `checksum::recalculate_only`) and verification (`checksum::verify`). 15 tests, including all truncations and random input. |
| `crates/filter` (`avulse-filter`) | Front half of Phase 1 done: lexer, parser, `fmt`, checker, typed IR, `simplify`, allocation-free evaluator. Wireshark 4.6 syntax covered: quantifiers, arithmetic, layers, value labels, `@field`, `&` on bytes, multi-range slices, `upper`/`lower`, and `matches` (optional `regex` feature). Semantics validated against tshark 4.6/4.7 (`src/tests/tshark.rs`, including every field's byte span against PDML). Bytecode, verifier and `no_std` interpreter (`bytecode/`), sharing the value operations in `value.rs` with the IR evaluator; `VerifiedProgram::matches_in` takes the register file from the caller, and its frames are checked in CI (`scripts/stack-sizes.py`, Step 22). WinDivert 2.2 front-end (`windivert/`), passing WinDivert's 241 vectors through the IR, the bytecode and the native round trip; `ir::Test::native()` prints native syntax. Nesting is bounded (native 64 levels, 4 macro levels; WinDivert 341 parentheses). TCP options: `tcp.options`, `.mss`, `.mss_val`, `.wscale`, `.wscale.shift`, `.wscale.multiplier`, `.sack_perm`, `.timestamp`, `.tsval`, `.tsecr`. 76 unit tests, 9 tshark tests (opt-in) and doctests. |
| `crates/cli` (`avulse`) | `avulse filter check \| fmt \| explain [--bytecode] \| eval --hex … \| convert [--layer …] \| fields [--format markdown]`. Exit codes: 0 match, 1 no match, 2 error. `avulse cleanup` reaps the handles of dead processes (Linux, root). |
| `fuzz/` | cargo-fuzz targets `bytecode` (verifier and interpreter on arbitrary programs), `filter` (parser, `fmt` round trip, checker, evaluator, bytecode agreement) and `windivert` (front-end, bytecode and native agreement). Outside the workspace. |
| `crates/wasm` (`avulse-wasm`) | The filter engine for the website's playground (wasm-bindgen, `publish = false`). |
| Docs and website | README (front page), guide (`book/`, mdBook), `site/` with the playground, rustdoc and pdoc, built by `scripts/build-site.sh` and deployed by `pages.yml` to <https://ffalcinelli.github.io/avulse/>. Every public item is documented (`missing_docs`). |
| `crates/ebpf` (`avulse-ebpf`) | Step 10: the generator covers metadata (through `Env`: layer, priority, interface names), IPv6 and MAC addresses, VLAN fields, TCP options (`avulse_options`, behind `CFG_TCP_OPTIONS`), byte order and `contains` in headers, arithmetic, field-to-field comparisons, set trees, `xor` through a slot; `superset`/`compile_superset` widen the rest, and `Matcher::exact` says when user space filters again. Step 9: `avulse_ingress` redirects the inbound packets user space injects through `lo` (`MARK_REDIRECT`, `PRIO_INJECTED`); test runs return the context (`Classifier::run_ctx`). Step 8: the loader attaches through Netlink (`Classifier::attach`, `Attachment::detach`) and opens raw BPF hash maps (`HashMap`, for the registry). Step 7: the capture side of the static TC programs (`avulse_ingress`/`avulse_egress` → matcher → `avulse_act`): per-handle configuration, metadata facts, ring buffer records, divert/sniff/drop, marks, loopback, NETWORK/FORWARD/ETHERNET selection, fragments, the forwarding check, fail-open; `abi.rs` mirrors `bpf/abi.h`. Spike A (go, `docs/spikes/ebpf-codegen.md`): the static TC program `bpf/tc.bpf.c` (parser → per-CPU facts → tail call), `codegen` (IR subset → eBPF matcher; anything else is `Error::Unsupported`), `insn` (assembler, forward labels, dead-code removal), `loader` (Linux: `aya` plus raw `bpf()` for the matcher and `BPF_PROG_TEST_RUN`). `tests/emu.rs` runs the matchers in an eBPF interpreter against the evaluator; `tests/kernel.rs` (`AVULSE_BPF=1`, root, in the VMs) checks facts and verdicts in the kernel. Step 14: the event programs of the FLOW and SOCKET layers (`bpf/events.bpf.c`, `loader::Events`, records in `abi::EventRecord`). Needs clang on Linux. |
| `spikes/macos` | Spike C (partial, `docs/spikes/macos.md`): probes of bpf, raw-socket and `utun` injection, pf and the filter engine's speed, and a `NEFilterPacketProvider` system extension around a Rust static library; run on GitHub's macOS runners by `.github/workflows/macos-spike.yml` (on changes to the spike). Outside the workspace. |
| `spikes/windows-driver` | Spike B (go, pure Rust, `docs/spikes/windows-driver.md`): a WDM driver with WFP callouts (IPv4 packet layers) and an NDIS LWF running the bytecode interpreter, built with `cargo wdk` in the `windows` VM. Outside the workspace (`exclude`), not built by CI. |
| `crates/avulse` (`avulse`) | Step 6: the handle API. `Handle`/`OpenOptions` (WinDivert's argument rules, native or WinDivert syntax), `Flags`, `Param`, `Shutdown`, `Error`, `capabilities()`, `cleanup()`, and the 184-byte versioned `#[repr(C)]` `Address` with its opaque reinjection `Context`. The crate-private `Backend`/`Opened` traits; the backends are modules of this crate (owner decision: one crate to publish). 18 tests on a fake backend. Steps 8 and 9: the Linux backend (`src/backend/linux/`) receives at the NETWORK, NETWORK_FORWARD and ETHERNET layers (divert, sniff, drop) and sends (`send.rs`: raw IP and `AF_PACKET` sockets, the `lo` redirect, GSO); filters that run in user space reinject what they do not match. Steps 15 to 17: the FLOW, SOCKET and REFLECT layers (`events.rs`, `reflect.rs`), SOCKET refusing binds and connects in the kernel; `Address` version 2 (216 bytes) with the process name. Step 13: devices without a link-layer header (tun, WireGuard, PPP, ipip/ip6tnl/sit) at the NETWORK layers. 15 unit tests without privileges; `tests/capture.rs` (Step 12's privileged suite, 36 tests, `AVULSE_BPF=1`, root, in the VMs and in the `privileged` workflow) on veth pairs, VLAN devices, `lo` and routed namespaces. Other platforms: `Error::Unsupported`. |
| `crates/capi` (`avulse-capi`) | Step 18: the C ABI, `libavulse.so`/`.a`, header `include/avulse.h` (hand-written, layout pinned by asserts), 20 functions, tested from C (`tests/c.rs`, `tests/c/abi.c`). |
| `drivers/windows` | Step 23: `avulse.sys` (WDM, Rust, outside the workspace): the control device, handles opened with verified bytecode, parameters, statistics, shutdown, and `EVAL`, a test IOCTL that runs a handle's filter in the kernel. `test/` passes 243 checks in the `windows` VM under Driver Verifier, WinDivert's filter vectors included. Steps 25 and 26: WFP callouts divert, sniff, drop and inject at the NETWORK layers. Step 27: the NDIS lightweight filter (`lwf.rs`) gives the ETHERNET layer, with VLAN tags and large sends restored. Step 28: FLOW, SOCKET and REFLECT (`ale.rs`, `reflect.rs`). `capture_windows.rs` (27 tests) passes with the driver as a plain service and installed through `netcfg`. |
| `crates/abi` (`avulse-abi`) | Step 23: the types shared with the driver and the C ABI (`Address`, `Flags`, `Param`, `Shutdown`, `Stats`, `Syntax`), and `ioctl`, the driver protocol. `no_std`. |
| `crates/windivert-compat` | Steps 19 to 21: `libavulse_windivert.so`, libebpfdivert's C API over avulse (21 `ebpfdivert_*` exports, negative errno values, WinDivert's 80-byte address with avulse's reinjection context in its union). WinDivert's helpers (hash, checksums, `eval_filter` with `random*`) agree with WinDivert's own code on generated vectors (`scripts/gen_compat_vectors.py`). REFLECT's data is WinDivert's serialized filter object (`Filter::windivert_object`, matching WinDivert's compiler on 230 filters). 15 unit tests, the exported-symbol test, and `tests/capture.rs` (6, `AVULSE_BPF=1`) on 6.8 and 5.15. pydivert's suite (155) and jdivert's (334, JNA and Panama) pass against it unchanged. `publish = false`. |
| `bindings/python` | 0.0.0 placeholder, published to PyPI to reserve the name. |
| CI (`.github/workflows/ci.yml`) | fmt, clippy, tests on ubuntu/windows/macos, tshark comparison (tshark from `ppa:wireshark-dev/stable`), no_std build (`thumbv7em-none-eabihf`), docs (rustdoc `-D warnings`, wasm32 clippy, mdbook), fuzz (each target for 60 s on nightly). `pages.yml` deploys the website. |
| Release (`.github/workflows/release.yml`) | Builds and publishes the Python placeholder on `v*` tags. **No crates.io job yet.** |

### Accounts and registries (already set up)

- **GitHub:** `github.com/ffalcinelli/avulse` is public, with `main` and tag `v0.0.0`. Description and
  topics are set. The environments `pypi` and `crates-io` exist.
- **crates.io:** `avulse` 0.0.0 was published with a token. A trusted publisher is configured for repo
  `ffalcinelli/avulse`, workflow `release.yml`, environment `crates-io`. When adding the crates.io job,
  use `rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18 # v1.0.5` with
  `environment: crates-io` and `permissions: id-token: write`. That is the same pattern as the PRs in
  kaji, pinner, mcp-airlock and astroceleste-engine. Every published crate must have a trusted
  publisher; only `avulse` has one so far. On 2026-10-28, `avulse-proto`, `avulse-filter`,
  `avulse-ebpf`, `avulse-cli`, `avulse-capi` and `avulse-windivert-compat` were claimed with
  0.0.0 placeholders (a one-line `lib.rs` each, published with a token). Adding their trusted
  publishers is an owner action.
- **PyPI:** `avulse` 0.0.0 was published by `release.yml` through a trusted publisher (environment
  `pypi`).
- **Maven:** groupId `com.github.ffalcinelli`, already owned through jdivert. Nothing to claim.
- **Signing (not started, owner action):** the EV certificate and the Partner Center enrollment for
  the Windows driver; an Apple Developer ID and the Network Extension entitlement for macOS. OSSign
  covers user-mode Windows artifacts only. See the roadmap, "Signing and distribution".

### Environment quirks on this workstation

- No `rustup`. `rustc`/`cargo` 1.99 come from Arch. For a local no_std check, use the installed
  `wasm32v1-none` target: `cargo build -p avulse-proto -p avulse-filter --target wasm32v1-none`. CI
  uses `thumbv7em-none-eabihf`.
- **`tshark` 4.7.4 is installed** (with `dftest`, handy to see how Wireshark compiles a filter). Docker
  works without sudo: to run the tshark test against another Wireshark, build an image (e.g.
  `ubuntu:24.04` + `ppa:wireshark-dev/stable` gives 4.6) and put a `tshark` wrapper script that runs
  `docker run -i --rm <image> tshark "$@"` first on the `PATH`. That takes about 12 minutes instead
  of 50 s. `scripts/gen_labels.py` takes such commands too, to merge the label tables of 4.6 and
  4.7 (4.7 renamed many `ip.proto` labels).
- **Pushing:**
  - Push over SSH with `GIT_SSH_COMMAND='ssh -o BatchMode=yes' git push …`, wrapped in `timeout`.
    Plain SSH pushes have hung.
  - The `gh` token has no `workflow` scope, so HTTPS pushes that touch `.github/workflows/` are
    rejected.
  - `gh` is authenticated for API calls (runs, PRs, environments).
- **Privileged tests run only in Vagrant VMs.** Run one VM at a time and `vagrant destroy -f` it right
  after, even on failure. Never download big files into `/tmp` (a small tmpfs); use `~/.cache`.
  - `Vagrantfile` (repo root) has `default` (Ubuntu 24.04, 6.8) and `legacy` (22.04, 5.15), with
    nothing to provision. Build the test binaries on the host (`cargo test -p avulse-ebpf --test
    kernel --no-run`, `cargo test -p avulse --test capture --no-run`) and run them in the VM:
    `vagrant ssh default -c "sudo AVULSE_BPF=1 /vagrant/target/debug/deps/kernel-<hash>
    --nocapture --test-threads=1"`, and the same for `capture-<hash>` (`--test-threads=1` matters:
    the capture tests share one veth pair). On 22.04 they print a harmless warning about the weak
    `GLIBC_2.39` requirement.
  - The 24.04 box sometimes hangs at boot (guest RCU stalls, `vagrant up` times out waiting for
    SSH). Destroy it and run `vagrant up` again.
  - `windows` (Windows 11 24H2) builds and tests the Windows driver: `vagrant up windows && vagrant
    reload windows` (the provisioning, `spikes/windows-driver/scripts/toolchain.ps1`, downloads
    several GB and needs the reboot for test signing, Driver Verifier and kernel dumps), then
    `vagrant winrm windows -e -c "C:\avulse\spikes\windows-driver\scripts\build.ps1"` and
    `…\test.ps1`. After a crash, the reboot can leave `C:\avulse` unmounted: `vagrant reload
    windows` mounts it again. Read dumps with the WDK's `kd -z` and frame sizes with `dumpbin
    /disasm` (commands in the spike note). Give it 6 GB and nothing else running.
- **Fuzzing:** `cargo-fuzz` is installed in `~/.cargo/bin`. Without a nightly toolchain, run it
  with `RUSTC_BOOTSTRAP=1` (Arch's rustc ships the ASan runtime):
  `cd fuzz && RUSTC_BOOTSTRAP=1 cargo fuzz run filter -- -max_total_time=600`. Seed the `filter`
  corpus from the guide's filter blocks (source, a NUL byte, a flags byte, the packet) to get
  coverage faster; `fuzz/corpus` is gitignored.
- **Formatting:** rustfmt defaults (100 columns). Run `cargo fmt` twice if `--check` still complains;
  some long chains need a second pass.

## Done-criteria for every change

1. `cargo fmt --check`, `cargo clippy --workspace --all-targets` (no warnings) and
   `cargo test --workspace` all pass.
2. The no_std build passes for `avulse-proto` and `avulse-filter`.
3. `proto` and `filter` stay `#![no_std]`, `#![forbid(unsafe_code)]`, with no panicking paths in
   evaluation code (no `unwrap`, no unchecked indexing on packet data).
4. User-facing behaviour changes are reflected in the guide (`book/src/`), `docs/roadmap.md` and
   `CLAUDE.md`, and in `README.md` when they change its summary. `RUSTDOCFLAGS=-D warnings cargo doc
   --workspace --no-deps --all-features` is clean, and the docs test (`cargo test -p avulse-cli --test
   docs`) passes.
5. Commit messages use the imperative mood, with a body explaining why, and end with the
   `Co-Authored-By:` trailer the session asks for.

## Next steps, in order

### Step 1: Validate the Wireshark semantics against `tshark` (done)

**Outcome.** `crates/filter/src/tests/tshark.rs` builds an Ethernet and a raw-IP capture from the
frame builders (`src/tests/frames.rs`, pcap writer in `src/tests/pcap.rs`), and runs about 300 filters
through tshark and Avulse: a presence test for every Wireshark field in `FIELDS`, plus a hand-written
table. Separate tables pin the intentional divergences, the extensions tshark rejects, and the filters
Avulse rejects on purpose. It needs tshark 4.6+: 4.2 (Ubuntu 24.04) differs on byte literals, on
`len(ipv6)` of non-first fragments and on upper-case keywords. The answers:

- Confirmed: `ip.flags` is the 3-bit value; `ip.frag_offset` is in 8-byte units; `tcp`/`udp`/`ip`
  slices cover the header only and `icmp`/`icmpv6` the whole message; comparisons with an absent field
  are false; `and` binds tighter than `or` and mixing them is accepted; a bare boolean field tests
  presence; empty payloads are absent; `eth.type` is the outer TPID; `icmp.ident`/`seq` exist only for
  echo-like types; `in` accepts IP ranges.
- Fixed:
  - `not in` is "present and no value in the set" (it was `not (… in …)`, true on absent fields).
  - An integer compared with bytes is one byte (`tcp[13] == 18` is 0x12); `18:` is the hex byte; the
    ambiguous one- and two-digit forms warn. An integer against a protocol (`tcp contains 80`) is an
    error.
  - The outer 802.1ad tag (TPID 0x88a8) is `ieee8021ad.*` (new fields); `vlan.*` covers 0x8100 and
    0x9100 tags only.
  - `ip.version` is also set for IPv6; `ipv6` (and `len(ipv6)`) spans the extension headers.
  - `ipv6.fragment.*` were not Wireshark names: they are now `ipv6.fraghdr.offset/more/ident`.
  - `tcp.len` is absent on IP fragments.
- Documented divergences (README, "Differences from Wireshark"): only the outermost headers (no
  ICMP-quoted datagram, owner decision), no partial headers on truncated packets, and stricter literal
  ranges. Extensions tshark rejects: comments, `~=`, `let`, space-separated sets, symbolic constants
  Wireshark lacks (owner decision: keep them).

The original plan of the step follows.

**Why.** The filter claims that a filter pasted from Wireshark means the same thing in Avulse. Several
behaviours were implemented from memory of Wireshark 4.x and are unverified. Settle them before
anything else is built on the IR.

**How:**

1. Add a test-only pcap writer (global header + records, linktype 1 = Ethernet, 101 = raw IP) under
   `crates/filter/tests/` or a dev-only helper module.
2. Build a corpus from the existing frame builders (`eth/ipv4/ipv6/tcp/udp`, ARP, VLAN/QinQ,
   fragments, ICMP echo/unreachable, padding), plus truncated frames.
3. Add an integration test `tests/tshark.rs`, `#[ignore]` unless `AVULSE_TSHARK=1`. For each filter in
   a table, it:
   - runs `tshark -r corpus.pcap -Y '<filter>' -T fields -e frame.number` with reassembly and
     heuristics off: `-o ip.defragment:FALSE -o ipv6.defragment:FALSE -o tcp.desegment_tcp_streams:FALSE`,
     and `--disable-protocol` for app dissectors that would claim the payload;
   - compares the frame set with `Filter::matches` over the same frames.

   Record the tshark version in the test output, and pin to 4.x behaviour.
4. Optionally add a CI job installing `tshark` on ubuntu (`apt-get install -y tshark`, non-interactive)
   that runs the ignored test.

**Open questions to settle**, then fix the code or the docs:

- `ip.flags`: our value is the 3-bit field (DF = `0x2`). Wireshark may expose the byte (`0x40`).
- `ip.frag_offset`: we use raw 8-byte units. Wireshark may report bytes.
- Protocol slices: we take `ip`/`ipv6`/`tcp`/`udp`/`eth` as header bytes only, `arp`/`icmp`/`icmpv6` as
  the whole message, and `frame` as everything (`load()` in `eval.rs`). Check `tcp[…]`, `udp[…]` and
  `icmp[…]` extents.
- `!=` and `~=` on an absent field: we return false.
- Precedence: `not` > `and` > `xor` > `or`. Check `and`/`or` mixing without parentheses; Wireshark
  may reject it or warn.
- Bare boolean fields (`tcp.flags.syn`): we test presence and warn. Wireshark 4.2+ may have changed
  this.
- `tcp.payload`/`udp.payload` when empty: we treat them as absent. Check `tcp.len` on non-first
  fragments.
- `eth.type` on VLAN-tagged frames: we use the outer TPID. Check `vlan.etype` and the order of
  `eth.addr`.
- `icmp.ident`/`icmp.seq`: we expose them only for echo/timestamp/info types.
- Upper-case keywords (`AND`): we accept them. Also check `#` comments and Wireshark's `//`/`/* */`
  comment support, and `in` with IP ranges.

**Acceptance:** every behaviour above is either confirmed or fixed, the tshark test passes locally, and
any intentional divergence is documented in the README and in the comment on `ir::CmpOp`.

### Step 1b: Wireshark syntax coverage

**Why.** Step 1 made the meaning of supported filters match tshark, but a lot of Wireshark 4.6 syntax
was still rejected. Each item lands as its own commit, with tshark rows in `src/tests/tshark.rs`
and unit tests, before the bytecode freezes the IR. Out of scope: `string()`, `dec()`, `hex()`,
`float()` and `vals()` (they need formatting and allocation), and `${field}` references (they
refer to the packet selected in the Wireshark GUI).

1. [x] `any`/`all` quantifiers and leading-dot field names (`.ip.src`). The IR is now `CmpOp` plus
   `Quant` (`Test::Cmp`, `Test::Member`, `Test::Contains`). tshark confirmed that `any`/`all`
   override the operator's default quantifier, pairs are cartesian, and `[all] … not in` is
   "present and not ([all] … in)".
2. [x] Arithmetic (`+ - * / %`, unary `-`, `{…}` grouping, in sets too), `max`/`min`/`abs`: signed
   results, pairwise over occurrences, division by zero gives no value.
3. [x] Layer operator `#n` / `#[a-b]`: VLAN tags are layers, every other field is layer 1.
4. [x] Value-string labels (`ip.proto == "TCP"`), generated from `tshark -G values` by
   `scripts/gen_labels.py`.
5. [x] `&` on bytes, `upper()`/`lower()` on string fields.
6. [x] Multi-range slices (`frame[0:2,4]`), capped at 32 bytes.
7. [x] `matches` / `~` behind the `regex` feature (`regex-automata`, user space only).
8. [x] `@field` raw bytes, checked against the field positions in `tshark -T pdml`.

### Step 2: Bytecode, verifier and `no_std` interpreter (done)

**Outcome.** `crates/filter/src/bytecode/` (`mod.rs` documents the format), public through
`Filter::program()`, `Program::{compile, to_bytes, from_bytes}`, `bytecode::verify` and
`VerifiedProgram::matches`.

- **Format.** A 16-byte header (magic `AVBC`, version, flags, instruction count, pool length),
  8-byte instructions (`op, a, b, c, imm: u32`) over 16 value registers, 8 boolean registers for
  `xor` and an accumulator, then a tagged constant pool (literals, ranges, sets) referenced by
  offset. Programs are at most 64 KiB. `and`/`or` short-circuit with forward `jf`/`jt`. Field ids
  are indexes in `FIELDS`, so `VERSION` must change with the field table.
- **Verifier.** It checks the header, opcodes, that unused operands are zero, register, boolean
  register and field indexes, small operands, forward jumps, and that each referenced constant is
  in bounds, of the right kind and well formed (including address prefixes). It does not type
  registers: execution is total over every value combination, as in `eval`, and registers start
  empty. `verify.rs`, `exec.rs` and `value.rs` use no `alloc`.
- **One implementation of the semantics.** Field loads, comparisons, membership, `contains`,
  slices and value operations moved from `eval.rs` to `value.rs`; both interpreters call them.
- **Tests** (`src/tests/bytecode.rs`): a rejection per verifier rule, round trips, the
  disassembly, the encoder's errors (`matches`, nesting depth, size); every tshark table filter
  over the tshark corpus with three metadata variants (IR vs. bytecode); and a proptest of
  type-aware random filters (about two thirds compile) over random packets. 100 000 cases ran
  clean; planted bugs in the interpreter are caught.
- **Fuzzing** (`fuzz/`): `bytecode` ran 10 minutes (72 million programs) clean. `filter` found
  one panic in its first 10 minutes, outside the bytecode: an unknown escape before a multi-byte
  character gave a span inside the character and `Diagnostic::render` panicked (fixed, regression
  test `render_never_splits_a_character`). A second 10-minute run was clean.
- **Limits decision.** `OWNED` (32 computed bytes) and `MAX` (4 occurrences) stay; the bytecode
  has the same limits because it shares `value.rs`, and the `LIMITS` rows stay. Reading joined
  ranges in place, without a copy, remains possible later work.
- `avulse filter explain --bytecode` prints the disassembly.

The original plan of the step follows.


**Note from Step 1b.** The IR the bytecode must encode now has, besides fields, slices, `&`,
`len` and `count`: quantified comparisons, membership and `contains` (`CmpOp` plus `Quant`); signed
`Int` values with `Arith`, `Neg`, `Abs` and `Extreme` (`max`/`min`); `Layer` and `Raw` field reads;
multi-range slices; and `Case` (`upper`/`lower`). `Test::Matches` is user space only: the verifier
rejects it and the kernel backends pass such packets up (`Filter::user_space_only()`).

**Note on the evaluator's limits.** The checker rejects filters whose values could exceed the
evaluator's fixed buffers: 4 occurrences (`eval::MAX`, through arithmetic and `&`) and 32 computed
bytes (`eval::OWNED`, multi-range slices and `&` on bytes). Wireshark accepts these, so the
`LIMITS` table in `src/tests/tshark.rs` pins them. The bytecode interpreter has the same
constraints, so this is where to decide whether joined ranges and `&` results should be read in
place, without a copy, to lift the byte limit. Move each `LIMITS` row to `AGREE` once it works.

**Why.** The Windows driver and the macOS system extension must not walk a heap IR built by user
space. They get a flat, verified program. The IR evaluator stays the reference implementation.

**Where.** `crates/filter/src/bytecode/` (`mod.rs`, `encode.rs`, `verify.rs`, `exec.rs`). Public
surface: `ir::Test -> Program` (needs `alloc`), `Program::to_bytes()/from_bytes()`, `verify(&[u8]) ->
Result<VerifiedProgram<'_>, VerifyError>` and `VerifiedProgram::matches(&Packet, &Meta)`. Verify and
execute must use **no `alloc`**.

**Design constraints:**

- Versioned header: magic, version, instruction count, constant-pool length.
- Constant pool for byte strings, IPv6 addresses and sets.
- Fixed-width instructions.
- Execution:
  - Every jump is forward, so programs terminate.
  - Values live in a bounded register file; reuse the `V`/`Vals` model from `eval.rs`.
  - Field loads go through the same `load()` code. Factor it out of `eval.rs` so both interpreters
    share it.
- The verifier checks, before running anything:
  - every opcode and field id is known;
  - every jump target is in range and forward;
  - every constant reference is in bounds;
  - slice parameters are sane;
  - type consistency, such as `BitAnd` only on integers;
  - maximum program size, e.g. 64 KiB.
- `and`/`or` short-circuit via forward jumps; `xor` and `not` via flags.

**Tests:**

- Round-trip `Program` ↔ bytes.
- A verifier rejection test per rule, using hand-crafted bad programs.
- A **differential property test** over random filters and random packets: the IR evaluator and the
  bytecode interpreter must agree. Write a filter generator over the field registry; `proptest` is
  fine as a dev-dependency.
- A `cargo-fuzz` target that feeds arbitrary bytes to `verify`, then runs the program if it is
  accepted. It must never panic.

Add `avulse filter explain --bytecode` to dump the program.

**Acceptance:** differential and fuzz tests are clean (fuzz ≥ 10 min locally), the no_std build still
passes, and `exec` uses no `alloc`.

### Step 3: WinDivert front-end and conformance vectors (done)

**Outcome.** `crates/filter/src/windivert/` (`Filter::compile_windivert(src, layer)`), the
`avulse filter convert [--layer …]` command and the guide page `filters/windivert.md`.

- **Semantics, read from `windivert_helper.c`/`windivert_shared.c`** (no code copied). Names are
  **case-sensitive** (the step's note below was wrong). `not` flips the operator of one test, so a
  missing header still makes it false, and it cannot precede a parenthesis. Values are a sign and
  a 128-bit magnitude; IPv4 is `::ffff:a.b.c.d`; fields narrower than 64 bits compare only the low
  32 bits at run time. WinDivert's compiler replaces comparisons that a field's range decides by
  `protocol == result` (`ip.TOS < 0` is `not ip`), and the front-end reproduces it with the same
  range table. `localPort`/`remotePort` on ICMP are the type (sending side) or 0.
- **Lowering to existing IR**, so that `convert` works: `packet16[i]` is a 2-byte slice of `frame`
  compared with bytes, `ip.HdrLength` is `ip.hdr_len` times 4, `tcp.PayloadLength` is
  `len(tcp.payload)` or 0, `localAddr` splits by family. The planned `Value::Read` was not needed.
  New: `Test::If` for `(a? b: c)` (one node, so conditionals nested in conditions do not blow up;
  bytecode `jmp` opcode, version 2), the extension fields `timestamp`, `priority` and
  `random8/16/32` (`Meta::timestamp`, `priority`, `hash`), and `ir::Test::native()`/`native_tests()`.
- **Conformance:** `src/tests/windivert.rs` runs the 241 vectors (`scripts/gen_windivert_vectors.py`
  generates the table) through the IR, the bytecode and the converted native filter; the random
  ones only compile. Plus grammar, error, quirk and convert tests.
- **Stack safety, found on the way:** the native parser overflowed the stack on about 1000 nested
  parentheses (and `not`s, `+` chains, `-`s). It now bounds the expression tree to 64 levels, and
  the checker bounds macro nesting to 4; the WinDivert parser keeps `and`/`or` lists flat and
  allows 341 parentheses like WinDivert. The worst accepted filters need under 1 MiB of stack in
  release builds (about 3 MiB in debug), checked by `deep_filters_are_bounded` and
  `windivert_deepest_filters`.
- **Known differences** (guide): malformed packets that WinDivert's parser reads differently
  (UDP payload end, IPv6 mobility header, ICMP after IPv6, truncated TCP options); compiled
  `@` filter objects are not accepted; `convert` refuses output over 10,000 tests.
- **For Phase 4 (compat shim):** fill `Meta::hash` with WinDivert's packet hash, and at the REFLECT
  layer `Meta::layer`/`priority` with the reflected handle's. (Done: Step 17 and Step 19.)
- **Fuzzing:** the new `windivert` target (seeded with the vectors) ran 10 minutes, 6.9 million
  inputs, clean. `filter` ran another 10 minutes after the parser changes, with inputs up to
  4 KiB (1 million), clean.

The original plan of the step follows.

**Note from Step 2.** The IR extensions below must reach the bytecode too: put their semantics in
`value.rs`, add an opcode (or a field id) with its verifier rule, disassembly and rejection test,
bump `bytecode::VERSION`, and extend the proptest generator in `src/tests/bytecode.rs` so the
differential test covers them. Run the WinDivert vectors through both interpreters.

**Why.** The compat shim (Phase 4) must accept WinDivert filter strings exactly, and
`avulse filter convert` gives users a migration path.

**Where.** `crates/filter/src/windivert/` (a lexer and parser for WinDivert's grammar, lowered straight
to `ir::Test`). Public API: `Filter::compile_windivert(src, layer)`.

**Grammar** (reference: `../windivert/doc/windivert.html`, `../windivert/dll/windivert_helper.c`;
read them, do not copy code):

- Field names are case-insensitive: `ip.SrcAddr`, `tcp.DstPort`, `tcp.PayloadLength`, `ipv6.*`,
  `icmp.*`, `icmpv6.*`, `udp.*`.
- Direction and metadata: `inbound`, `outbound`, `loopback`, `impostor`, `fragment`, `ifIdx`,
  `subIfIdx`, `processId`, `localAddr`, `remoteAddr`, `localPort`, `remotePort`, `protocol`, `endpointId`,
  `parentEndpointId`, `layer`, `priority`, `event`, plus symbolic events (`PACKET`, `CONNECT`, …).
- Pseudo-fields: `zero`, `true`, `false`, `random8/16/32`, `timestamp`, `length`.
- Indexing: `packet[i]`, `packet16[i]`, `packet32[i]` (the `b` suffix means a byte offset; negative
  indexes count from the end), and `tcp.Payload[i]`, `tcp.Payload16[i]`, `udp.Payload32[i]` and so on.
- Operators:
  - comparison: `==`, `=`, `!=`, `<`, `<=`, `>`, `>=`;
  - logical: `and`/`&&`, `or`/`||`, `not`/`!`;
  - the ternary `a ? b : c`.
- Literals: decimal, hex, IPv4, IPv6. Note that `ip.HdrLength` counts 32-bit words, not bytes.
- **Semantics:** a test on a missing field is false. `!=` is a plain negation, with no Wireshark
  quantifiers. Confirm both against the vectors.

**IR extensions this needs** (keep them backend-neutral, and add support in `eval.rs` and the bytecode):

- `Value::Read { base: Frame|Payload, offset: i32, width: 1|2|4 }`: a big-endian integer read with
  negative offsets.
- Pseudo-fields `random*`, `timestamp`, `length`, `priority`. `Meta` gains `timestamp` and `priority`,
  and the random fields need a seed in `Meta` so evaluation stays deterministic.
- WinDivert-only header fields, such as `ip.HdrLength` in words, either as `Field` variants with
  `Origin::Extension` hidden from the Wireshark resolver, or as expressions over existing fields.

**Conformance:**

- Port the **241 vectors** in `../ebpfdivert/tests/wd_vectors.c`: 10 packets, which are IP-level, so
  use `Link::Ip` with `Meta { layer: Network, outbound: true, .. }`, exactly as
  `../ebpfdivert/tests/test_filter.c:run_vector` sets them.
- Skip filters containing `random`, as ebpfdivert does.
- The vector data is WinDivert's (LGPL/GPL, compatible with our dual license). Generate a Rust table,
  e.g. with a small script under `scripts/`, keeping the provenance header.

**CLI:** `avulse filter convert '<windivert filter>'` prints the native equivalent; this needs an
IR → native-syntax printer.

**Acceptance:** every non-random vector passes, and `convert` output re-compiles to an IR that is
equivalent on the vector packets.

### Step 4: Language gaps (done)

(`matches` and `&` on bytes moved to Step 1b and are done.)

- [x] **TCP options.** `avulse-proto` walks the options (`Tcp::option_iter`, `Tcp::option`,
  `TcpOption::{mss, wscale_shift, timestamps}`) the way Wireshark 4.6/4.7 does, checked with
  tshark on crafted headers: the walk ends after EOL, and at a length below 2 or past the header;
  unknown kinds are skipped by their length; a known option of the wrong length is present (its
  protocol item) but has no value. Fields: `tcp.options` (the option bytes),
  `tcp.options.mss`/`mss_val`, `tcp.options.wscale`/`wscale.shift`/`wscale.multiplier` (2 to the
  shift, at most 16384), `tcp.options.sack_perm`, `tcp.options.timestamp`/`timestamp.tsval`/`tsecr`,
  with their `@field` spans. **Not** `tcp.option_kind`/`option_len`/`options.nop`/`options.eol`:
  they repeat once per option, up to 40 times, and a value holds at most 4 occurrences, so they
  are rejected with a hint (as are SACK edges, which are relative sequence numbers). Each option
  field reads the first option of its kind; two MSS options are a documented divergence
  (`dup_mss` in `tests/tshark.rs`). The bytecode version is 3 (the field table changed).
  Unsupported-field errors now name the field as written. tshark 4.6.6 and 4.7.4 agree.
- [x] `cargo-fuzz` targets for the parser/checker (arbitrary UTF-8 must never panic) and for `eval` on
  arbitrary packets: the `filter` target in `fuzz/` (added with Step 2).

### Step 5: Phase 0 spikes (need VMs or hardware; see roadmap, Phase 0)

- [x] **Spike A: eBPF codegen.** Done 2026-10-14, verdict go; see `docs/spikes/ebpf-codegen.md`
  for the results and the findings that Phase 2 must take into account (the action program after
  the matcher, set lowering, `xor`, VLAN offload). In `crates/ebpf`, emit eBPF for a tiny IR subset
  (`tcp.dstport == N`) at runtime with a hand-rolled instruction encoder.
  1. A static C TC program (`crates/ebpf/bpf/tc.bpf.c`, clsact cls_bpf, reuse
     `../ebpfdivert/src/ebpfdivert.bpf.c` parsing) fills a per-CPU "facts" map and calls
     `bpf_tail_call` into a `PROG_ARRAY` slot.
  2. The generated matcher reads the facts, plus `bpf_skb_load_bytes` for slices, and returns the
     verdict. (It cannot return: a tail call does not. It writes the verdict to the facts and
     tail-calls a static action program.)
  3. Load everything with `aya`.
  4. Test with `BPF_PROG_TEST_RUN` in the Vagrant `default` (6.8) and `legacy` (5.15) VMs; reuse
     `../ebpfdivert/Vagrantfile`.

  Exit: the verifier accepts the program on both kernels. Write a go/no-go note in `docs/spikes/`.
- [x] **Spike B: Windows Rust driver.** Done 2026-10-15, verdict go in pure Rust; see
  `docs/spikes/windows-driver.md`. The kernel stack (24 KiB, about 12 KiB left when NDIS or WFP
  call the filter) is the constraint Phase 5 must design for: release builds, a stack check with
  `KeExpandKernelStackAndCalloutEx`, and a caller-provided register file for the interpreter. Use
  `windows-drivers-rs`: one WFP callout and one NDIS LWF, test-signed, loaded in a Windows Vagrant
  VM. Decide pure Rust or a thin C shim.
- [ ] **Spike C: macOS.** Partly done on GitHub's macOS runners, 2026-10-21 (no Mac; owner
  decision to use the runners): see `docs/spikes/macos.md`. Answered: `/dev/bpf` capture and
  outbound injection (not inbound), inbound reinjection through a raw socket (host-order
  `ip_len`/`ip_off`) or `utun`, no divert in pf, and the system extension's build (Rust static
  library in Swift, universal, ad hoc signed). The runners have SIP off; the extension reaches
  `activated_waiting_for_user` and nothing approves it headless. **Left:** the provider's frame
  level, throughput and delay semantics. Next try: script the approval on a runner
  (`osascript` in System Settings); else a Mac with SIP off, or a Developer ID (owner action).
  Do it before Phase 6. Also found: the bytecode interpreter is 2 to 7 times slower than the IR
  evaluator (it copies its operand registers every instruction); fix it in Phase 5.

### After that

Phases 2 to 5 are expanded below. Then follow the roadmap: 5 (Windows driver; read the Spike B
note's requirements first) → 6 (macOS, after Spike C) → the first release (v0.0.1, below) → 7
(bindings, 1.0). Before starting each phase, expand it into steps in this file, in the same
format as above.

**Versions and releases (owner decisions, 2026-10-28).**
- Versions stay **0.0.x** while the project is experimental. The first release is **v0.0.1**,
  not 0.1.
- Nothing is released before the Windows and macOS backends exist (Phases 5 and 6). The release
  step that closed Phase 3 moved to "Release v0.0.1" at the end of this file.

## Phase 2: Linux packet layers (NETWORK, NETWORK_FORWARD, ETHERNET)

**Goal** (roadmap, Phase 2): open a handle on Linux with a native or WinDivert filter, receive the
packets that match it, exactly, and send packets back, at the NETWORK, NETWORK_FORWARD and ETHERNET
layers. **Exit:** the privileged suite (Step 12) passes on both VMs.

**What to port.** The behaviour comes from ebpfdivert (`../ebpfdivert/docs/architecture.md`
explains it; `src/ebpfdivert.bpf.c` is the TC program, `src/handle.c` the user-space handle).
Port its logic, not its code layout. The kernel side keeps Spike A's split: the static parser
writes facts, tail-calls the generated matcher, and the matcher tail-calls the static action
program (`docs/spikes/ebpf-codegen.md`).

**Decisions made for this phase** (change them here, with a reason, if the work proves them
wrong):

- **One program instance per handle**, as in ebpfdivert. Each handle has its own maps (facts,
  program array, config, ring buffer), its own matcher, and its own TC filter on each interface.
  Handles share nothing but the registry.
- **Attach with classic cls_bpf on clsact, never TCX.** aya 0.14's `SchedClassifier::attach`
  picks TCX on kernels 6.6 and later (`programs/tc.rs`), so always call `attach_with_options` with
  `TcAttachOptions::Netlink(NlOptions { priority, handle })`. TCX turns `TC_ACT_STOLEN` into
  "next".
- **Priority and marks.** TC priority = `30001 - priority`. Priority 0 means after every existing
  handle. Use a mark prefix of our own (not ebpfdivert's `0x4D49…`), so the two never mistake
  each other's packets. Document it in the guide.
- **Fail-open everywhere.** A full ring, an empty program-array slot, a stale heartbeat, or a
  shut-down handle all pass the packet.
- **Kernel baseline:** 5.10 with BTF. Test on 6.8 (`default`) and 5.15 (`legacy`).
- **The backends are modules of the `avulse` crate** (`crates/avulse/src/backend/linux/…`), not
  crates: the facade must call them, and they implement its traits, so separate crates would
  depend on each other. One crate to publish (owner decision, 2026-10-15). The empty
  `backend-linux` stub was removed.
- **The NETWORK layers see IP packets** (`Link::Ip`). The matcher's `frame` base is the L3
  offset, and a captured NETWORK packet starts at the IP header. The L2 header goes in the
  address's reinjection blob.

### Step 6: The public API and the address, without a backend (done)

**Outcome.** `crates/avulse` (see the Status table and `CLAUDE.md`), and the guide page
`libraries/handles.md`. As planned, except:
- the trait is crate-private and split in two: `Backend` for the platform (`capabilities`, `open`)
  and `Opened` for an open handle;
- `Handle::send` also requires the address's layer to be the handle's;
- `MAX_PACKET_LEN` (65,600) sizes receive buffers;
- `OpenOptions::interfaces` selects the capture interfaces;
- the CLI binary is no longer documented by rustdoc (`doc = false`), because it collided with the
  library's `avulse` docs.

The original plan of the step follows.


**Why.** Every later step needs the types. They are not frozen until Phase 3, but should be close.

**Where.** `crates/avulse` (the facade, now a real crate): `Handle`, `Layer` (reuse
`avulse_filter::Layer`), `Flags` (`SNIFF`, `DROP`, `RECV_ONLY`, `SEND_ONLY`, `FRAGMENTS`),
`Param` (`QueueLength`, `QueueTime`, `QueueSize`), `Shutdown`, `Error`, `Address`, and a
`Backend` trait that `backend-linux` implements. `Handle::open(filter: &str, layer, priority,
flags)` takes a native filter; `Handle::open_windivert` takes a WinDivert one
(`Filter::compile_windivert`). Calls: `recv(&mut [u8]) -> (len, Address)`, `send(&[u8],
&Address)`, batch variants later, `shutdown`, `close` (on `Drop` too), and `AsFd` for
`poll`/`epoll`. Add `capabilities()` per layer.

**Address** (roadmap, "Public model"): a versioned, `#[repr(C)]` struct with explicit fields:
timestamp, layer, event, ifindex/subifindex, direction, loopback, impostor, IPv6, checksum-valid
flags, VLAN TCI and ethertype, and the flow/socket part (empty until Phase 3). It also has an
opaque, fixed-size reinjection blob (L2 header, GSO size and type, capture ifindex). Size the
blob for the ETHERNET layer: a 14-byte header plus two VLAN tags.

**Tests:** unit tests of the address layout (`size_of`, offsets, version) and of argument
checking (bad priority, flags that do not apply to the layer, a bad filter with its diagnostic).
Use a fake backend; nothing needs root.

**Acceptance:** done-criteria 1 and 4 hold; the guide gets an "API" page stub with the address
fields.

### Step 7: The kernel side of capture (done)

**Outcome.** `crates/ebpf/bpf/tc.bpf.c`, `bpf/abi.h` (mirrored by `src/abi.rs`), `bpf/facts.h`, and
the loader (`Classifier::{load_with_ring, set_config, stats, records, clear_matcher, run_on}`).
`tests/kernel.rs` passes on 6.8 and 5.15.

- **Two entry programs,** `avulse_ingress` and `avulse_egress`, run the checks in this order:
  configuration, shutdown, heartbeat, marks, loopback, layer. Then they parse, write the
  metadata facts, and tail-call the matcher.
- **`avulse_act` acts on the verdict.**
  - It drops with `CFG_DROP`.
  - Otherwise it copies the packet to the ring in three size classes (2, 16 and 64 KiB). It
    diverts (`TC_ACT_STOLEN`), or passes with `CFG_SNIFF`, cut to `snaplen`.
  - A packet over 64 KiB cannot be diverted whole, so it passes.
  - Every failure passes the packet (`TC_ACT_UNSPEC`, so the next classifier runs). This
    includes the generated matcher, which used to return `TC_ACT_OK` when the action slot was
    empty; `TC_ACT_OK` would have skipped lower-priority handles.
- **The facts grew to 48 bytes:** layer, `base`, ifindex, offloaded VLAN TCI, and `M_*` bits.
  - At the NETWORK layers the filter sees the IP packet: `F_ETH` is cleared, and `frame` and
    `frame.len` start at `base` (the IP header). `Facts::at_network` is the contract. The
    emulator and kernel tests check verdicts there against `Filter::matches` on the IP packet
    parsed alone (2.26 million runs agree on both kernels).
- **Records** (`struct avulse_record`, 40 bytes, then the whole frame) carry:
  - the timestamp (`CLOCK_MONOTONIC`), length, ifindex and ingress ifindex;
  - the GSO size and segment count, and the offloaded VLAN TCI;
  - the L3 offset, the `M_*` bits (outbound, loopback, impostor, VLAN, forward, sniffed), the
    layer, and the presence bits.
- **Marks:** `0x4156____` (injected, with the TC priority) and `0x4157____` (inbound redirect via
  `lo`, Step 9).
- **The license string is `"GPL"`:** the kernel does not count "Dual LGPL/GPL" as GPL-compatible,
  and `bpf_fib_lookup` is GPL-only.
- **Measured (VirtualBox):** parse and checks take 90 ns (6.8) or 190 ns (5.15), and diverting
  `tcp.dstport == 443` to the ring takes 265 or 372 ns.
- **Not testable through `BPF_PROG_TEST_RUN`,** so left to Steps 8 and 12 (real traffic):
  - offloaded VLAN tags (the context cannot set them);
  - the 64 KiB class and the over-64 KiB pass (test runs take about one page);
  - forwarded packets on 5.15, which refuses `ingress_ifindex` in the context;
  - a forwarding check that finds a route.

The original plan of the step follows.

**Where.** `crates/ebpf/bpf/tc.bpf.c` (plus `facts.h`/`facts.rs`), and maps declared there.

- **Per-handle config map:** layer, flags, TC priority, heartbeat timestamp, shutdown bits, and
  the capture-interface set.
- **Facts gain metadata** for the matcher: direction, ifindex, loopback, impostor, layer, VLAN TCI
  from `skb->vlan_tci` (offload), and the L3 base for the NETWORK layers.
- **The parser accounts for VLAN offload.** On a real hook, the outer tag is usually in
  `skb->vlan_tci`, not in the data. Spike A's `BPF_PROG_TEST_RUN` tests keep it in the data, so
  test both.
- **The action program diverts.** Copy the whole skb to a ring buffer in three size classes (2 KB,
  16 KB, 64 KB, as ebpfdivert), with a record header the address is built from. The verdict is
  `TC_ACT_STOLEN` to divert, the packet passes for `SNIFF`, and `TC_ACT_SHOT` for `DROP`.
  Statistics go to a per-CPU array (diverted, passed, ring full, owner gone, marked).
- **Layer selection:**
  - Loopback packets are seen once: egress on `lo`, reported outbound with loopback set.
  - NETWORK_FORWARD is egress with `skb->ingress_ifindex != 0`. When forwarding is on, ingress
    packets are checked with `bpf_fib_lookup`, so that NETWORK sees only local traffic.
  - Fragments are captured only with `FRAGMENTS`.
  - The NETWORK layers ignore non-IP frames.
- **Loop prevention:** skip packets marked at the same or a higher priority, and set impostor on
  lower ones.

Keep ebpfdivert's verifier tricks for 5.15: global functions for the large parts, the inline-asm
length bound before `bpf_skb_load_bytes` into the ring buffer, and `barrier_var` on context
arrays.

**Tests:** extend `tests/kernel.rs` (`BPF_PROG_TEST_RUN`): config and metadata in the facts,
verdicts for each flag, ring-buffer records (size class, header, bytes), marks and impostor,
fail-open on a stale heartbeat or an empty slot. Then run both VMs.

**Acceptance:** the program loads and passes `tests/kernel.rs` on 6.8 and 5.15, and the facts
still equal `Facts::from_packet` (extended with the metadata) on the whole corpus.

### Step 8: `backend-linux`: open, attach, receive (done)

**Outcome.** `crates/avulse/src/backend/linux/` (`mod.rs` the backend and the open handle,
`record.rs` records to addresses and the reinjection context, `queue.rs`, `registry.rs`,
`heartbeat.rs`, `sys.rs`), `avulse::cleanup()` and `avulse cleanup`, and in `avulse-ebpf`'s
loader: `Classifier::attach` (Netlink, `TcHandle::AUTO_ASSIGN`), `Attachment::detach` (for
reaping other processes' filters), `take_ring`, `config_writer`, and `HashMap` (a raw BPF hash map,
pinned or not, for the registry). `avulse-proto` gained `checksum::verify` for the address's
checksum flags. `tests/capture.rs` passes on 6.8 and 5.15: divert, sniff, drop, the user-space
fallback, shutdown, the pollable fd and timeouts, the ETHERNET layer, TC priorities, and a dead
owner (filters fail open after 3 s, `cleanup` removes them). `tests/kernel.rs` still passes on
both.

- **Open:** filter → `codegen::compile`; when it is unsupported or the verifier rejects it, the
  matcher is `Test::Const(true)` and user space runs `Filter::matches` on each record (with
  `iface` from the ifindex, the handle's priority, and an FNV-1a hash of the packet for
  `random*`). Such handles must `SNIFF` until Step 9; otherwise `Error::Unsupported`. Note that
  every filter with metadata fields (`outbound`, `loopback`, `iface`, …) takes this path until
  Step 10.
- **Order of operations:** load, matcher, then under the registry lock: reap, choose the TC
  priority, write the configuration (a fresh heartbeat), attach, register. The configuration goes
  before the attachment because the zero configuration means "divert at NETWORK, no heartbeat
  check". Closing writes `CFG_SHUTDOWN`, then detaches and unregisters under the lock.
- **Interfaces:** the selected ones (all by default) plus the loopback device, which is attached
  with `CFG_SKIP_LO` when not selected. Only `ARPHRD_ETHER` and `ARPHRD_LOOPBACK` devices: the
  programs expect an Ethernet header, so L3 devices (tun, WireGuard, IP tunnels) are skipped, or
  refused with `Error::Unsupported` when named. Interfaces that appear after the open are not
  captured.
- **Registry:** `/sys/fs/bpf/avulse/registry-1` (the suffix is the entry layout's version), a
  hash map of 1,024 entries keyed by a random u64, changed under `flock` on `/run/avulse.lock`.
  An entry holds the PID and its start time, the TC priority, flags, layer, priority, up to 128
  TC filters (ifindex, hook, TC priority, handle) and the filter's text. Reaping skips a TC filter
  that a live entry also lists. Without a bpffs, handles still open with nothing shared.
  Processes in other PID namespaces look dead to each other: run all users of one bpffs in one
  PID namespace.
- **Priority 0** goes after the highest TC priority of the live handles in the registry and of
  this process's open handles (a first version remembered closed handles too; the capture test
  caught it).
- **Heartbeat:** one thread per process (`avulse-heartbeat`) rewrites every open handle's
  configuration every 500 ms; the programs pass everything after 3 s.
- **Receive:** `recv` pops the queue, else drains the ring into it, else waits on the epoll fd
  (ring buffer + an eventfd set while the queue is non-empty or the handle is shut down). The
  queue applies `QUEUE_LENGTH`/`QUEUE_SIZE` at push and `QUEUE_TIME` at pop, against the record's
  `CLOCK_MONOTONIC` timestamp, so packets left in the ring expire too. After `shutdown(Recv)`,
  queued and ring packets are delivered, then `Error::Shutdown`. A packet larger than the buffer
  is consumed (`BufferTooSmall`). `close` needs no in-flight tracking: it takes the `Handle` by
  value, so no call can be in progress.
- **Address:** direction, loopback, impostor, sniffed and the layer from the record's `M_*`
  bits; `ipv6` from the facts; checksum flags from `checksum::verify` (outbound packets with
  offloaded checksums report `false`); the interface; the outer VLAN tag. An offloaded tag
  (`M_VLAN`) is put back into the frame after the MAC addresses with TPID 0x8100 (the record does
  not carry `vlan_proto`): into the packet at ETHERNET, into the saved L2 header at NETWORK.
- **Reinjection context** (64 bytes, host byte order): magic `0xa1`, L2 length, GSO size, capture
  ifindex, GSO segments, and up to 30 bytes of L2 header (Ethernet and four tags).
- **Errors** keep the kind of the system error under them (`PermissionDenied` without
  privileges), through `loader::Error::source`.
- **Publishing:** `avulse` now depends on `avulse-ebpf` on Linux, which is `publish = false` and
  needs clang at build time. Before the first crates.io release of the backend, publish
  `avulse-ebpf` (with a trusted publisher, owner action) and ship `tc.bpf.o` prebuilt in it, so
  that users do not need clang.

The original plan of the step follows.


**Where.** `crates/avulse/src/backend/linux/` (Linux only; `aya` and `libc` as Linux-only
dependencies of `avulse`), implementing Step 6's `Backend` and `Opened`, and returned by
`backend::platform()` on Linux.

- **Open:**
  - compile the filter;
  - generate the matcher with `codegen::compile`, or use the fallback (below) when it returns
    `Unsupported`, or when the verifier rejects it;
  - load an instance of the static programs and set the program-array slots;
  - attach to the selected interfaces plus `lo` (Netlink options, see the decisions);
  - register the handle.
- **Superset fallback, first version:** a matcher that matches everything at the layer. User space
  then runs `Filter::matches` on every record and reinjects what does not match (Step 9 adds
  sending; until then, such handles are `SNIFF` only). Step 10 makes the superset tight.
- **Registry:** a pinned hash map under `/sys/fs/bpf/avulse/`, updated under a `flock`. Each entry
  holds the PID with its start time, the TC priority, the attachments and the filter. Entries of
  dead processes are reaped, and their TC filters detached, at every open and by
  `avulse cleanup` (a CLI subcommand).
- **Heartbeat:** a thread refreshes the config map every 500 ms; the programs pass everything
  when it is over 3 s old.
- **Receive:** drain the ring into a queue bounded by `QUEUE_LENGTH`/`QUEUE_SIZE`, drop entries
  older than `QUEUE_TIME`, and count the drops. Build the `Address` from the record. The pollable
  fd is an epoll fd that is readable when `recv` would not block. After `shutdown(RECV)`, return
  what is queued, then an error. `close` waits for calls in progress.

**Tests:** unit tests that need no root (record decoding, queue limits with a fake clock); the
privileged part waits for Step 12, but add a `capture` smoke test now (veth pair in a netns, ping,
receive an echo request with the right address).

**Acceptance:** a handle with `icmp` diverts pings on a veth in both VMs (with no reply, since
nothing reinjects yet), and a `SNIFF` handle receives them while the pings still get replies.

### Step 9: Injection (done)

**Outcome.** `crates/avulse/src/backend/linux/send.rs` (the paths, GSO, the impostor rule), the
socket calls in `sys.rs`, and in `tc.bpf.c` the `lo` ingress redirect. `tests/capture.rs` passes
on 6.8 and 5.15 (18 tests), and `tests/kernel.rs` (13) too: reinjected pings both ways (each packet
seen once), the ETHERNET layer sending frames back, an outbound datagram sent to another port (the
peer answers from it), built packets injected inbound and outbound by a `SEND_ONLY` handle,
loopback over IPv4 and IPv6, an 8 MiB TCP transfer through a diverting handle (GSO packets go back
out as GSO), priority chaining with impostors, and a user-space filter that reinjects what it does
not match (and drops what it matches, with `DROP`).

- **Paths** (ebpfdivert's table): loopback → raw IP socket; outbound or forwarded with a context
  that names the same interface as `if_idx` → `AF_PACKET` out of it behind the saved L2 header
  (its last EtherType set for the packet's IP version); outbound without one → raw IP socket;
  inbound to no interface → raw IP socket; inbound → `AF_PACKET` on `lo` behind the saved header,
  or one to the interface's MAC address (from sysfs). ETHERNET: the frame out of `if_idx`, or in
  through `lo`; `if_idx` is required.
- **The `lo` redirect.** The `AF_PACKET` socket sets `SO_MARK = MARK_REDIRECT | ifindex` and
  `SO_PRIORITY = PRIO_INJECTED | tc_priority` (`0x4158____`). On `lo`'s egress every handle skips
  it; on `lo`'s ingress the first handle's program, before any configuration check, sets the mark
  to `MARK_INJECTED | tc_priority`, clears the priority and `bpf_redirect`s it to the target's
  ingress (`BPF_F_INGRESS`), where it is an injected packet like any other. ebpfdivert used an
  extra stage (`REDIRECTED_MARK`, then `bpf_skb_change_type(PACKET_HOST)` on the target) for L3
  targets; with Ethernet targets the redirect's `eth_type_trans` sets the packet type from the
  destination MAC, so one stage is enough. Revisit it with L3 devices (Step 11). Only interfaces
  with an index below 65536 can receive injected inbound packets.
- **`SEND_ONLY` handles** load the programs too, shut down (`CFG_SHUTDOWN`), on `lo`'s ingress
  only, so that inbound injection works when no other handle is attached to `lo`. They are
  registered (reaped like any other) but have no heartbeat. Their TC priority is chosen like any
  handle's, since their packets carry it.
- **Checksums** follow WinDivert's driver: those whose flag is clear (IPv4 header, TCP, UDP) are
  computed; ICMP and ICMPv6 checksums are sent as they are. Packets captured with partial
  (offloaded) checksums fail `verify`, so reinjecting them unchanged computes them. With GSO, the
  TCP/UDP checksum is left to the kernel (`VIRTIO_NET_HDR_F_NEEDS_CSUM` with the pseudo-header
  sum in the field).
- **GSO.** An IP packet larger than 576 bytes and than the target's MTU (sysfs, cached for 1 s)
  goes out with a `virtio_net_hdr` (`PACKET_VNET_HDR`, host byte order): TCPv4/TCPv6, or UDP_L4,
  which kernels before 6.2 refuse; the segment size is the captured one, or the MTU minus the
  headers. Fragments and other protocols get no header (and may then fail with `EMSGSIZE`).
- **Impostors** (WinDivert's rule): a packet the application sends with `impostor` set loses one
  TTL or hop limit (the IPv4 checksum updated incrementally), and fails with `HostUnreachable` at
  1. Packets the backend reinjects on its own are left alone.
- **User-space filters** no longer need `SNIFF`: non-matching records are reinjected at once
  (unless they were copies), and with `DROP` the kernel diverts and user space drops the matches.
  A failed reinjection loses the packet, as a full queue does.
- **Sockets** are made on first use and kept by the handle: one raw socket per IP version, one
  `AF_PACKET` socket per mark (the redirect mark names the target). Sending needs
  `CAP_NET_RAW` and `CAP_NET_ADMIN` (for `SO_MARK`).
- `BPF_PROG_TEST_RUN` fails with `ENOSPC` when `ctx_size_out` is smaller than the kernel's
  `__sk_buff`, which is larger on 6.8 than on 5.15: `run_ctx` passes 512 bytes.

The original plan of the step follows.

**Where.** `crates/avulse/src/backend/linux/` (`send`), plus the `lo` ingress redirect in the
static program.

Port ebpfdivert's path table:

| Packet | Path |
| --- | --- |
| Loopback | Raw IP socket (`IPPROTO_RAW`), so 127/8 and `::1` are not dropped as martians. |
| Outbound or forward, with its reinjection blob | `AF_PACKET` on the capture interface, with the saved L2 header. |
| Outbound, built by the user (no blob) | Raw IP socket: routed like any packet. |
| Inbound | `AF_PACKET` on `lo`, carrying a redirect mark and the target ifindex. The `lo` ingress hook `bpf_redirect`s it to the target's ingress. The redirect clears `skb->priority`, so use `SO_PRIORITY` and move the priority into the mark first. |

- **GSO.** Packets above the MTU go out with `PACKET_VNET_HDR` and a `virtio_net_hdr` that
  describes the segmentation.
- **Checksums.** Recalculate them with `avulse_proto::checksum` when the address flags ask for it.
  Captured packets often carry partial checksums from offload.
- **Marks.** Every injected packet carries the handle's mark (loop prevention).
- **Fallback handles** now reinject the non-matching records.

**Tests:** outbound modify (rewrite a port, the peer sees it), inbound inject on a veth, crafted
outbound, loopback (IPv4 and IPv6), GSO (a bulk TCP transfer through a diverting handle),
priority chaining (two handles, marks, impostor), and auto-reinjection by a fallback handle.

**Acceptance:** those scenarios pass on both VMs.

### Step 10: Matcher coverage and a tight superset (done)

**Outcome.** `crates/ebpf/src/codegen.rs` (`compile(test, &Env)`, `superset`,
`compile_superset`, `everything`, `Matcher::exact`), the facts' VLAN count and TCP option
offsets (`bpf/facts.h`, `tc.bpf.c`'s option walk), the backend's matcher chain, and `avulse filter
explain`'s `linux kernel:` line. In the emulator: 323 of the 463 tshark-table filters and 221 of
the 225 non-random WinDivert vectors compile exactly (the 4 others read `timestamp`); every one
of them, and 300 random mixes of supported and unsupported tests, runs as a sound superset.
In the kernel (`tests/kernel.rs`, 15 tests, on 6.8 and 5.15): 540 filters agree with the
evaluator over 3 million runs; all 463 tshark filters load at both layers; 221 of the 225
vectors are exact. `tests/capture.rs` (18) passes on both.

- **`Env`** carries the handle's constants: the layer, the priority, and an interface resolver.
  A pass over the IR before code generation (`lower`) decides `layer`, `event`, `priority` and
  `subifidx`, turns `iface` into `ifidx` (the index is resolved when the handle opens; a rename is
  not followed), and rewrites `local.*`/`remote.*` into conditionals on `outbound` over the source
  and destination fields, as `value::load` defines them at the packet layers. Against an address
  of the other family, `!=` and `not in` hold.
- **Metadata** from the facts: `inbound`/`outbound`, `loopback`, `impostor`, `fragment`, `ifidx`,
  `protocol`.
- **Occurrences** are general: each may be absent (VLAN tags, TCP options, division by zero), and
  a stack slot records whether any was present, so `all` and `not in` stay false on none.
- **Bytes:** IPv6 and MAC addresses as fixed-length ranges, with prefixes (masked word compares),
  ranges and lexicographic order (`value::ord`) for any byte value of fixed length (slices of a
  constant length included, which covers WinDivert's `packet[i]`); sets of bytes; `contains` in
  regions of at most 64 bytes (headers, options, tags), unrolled. `contains` on payloads and
  frames, and ordering of variable-length bytes, are widened.
- **Numbers:** `len()`, `count()` of fields, `+ - * / %`, unary `-`, `abs()`, `max()`/`min()`
  (absent arguments skipped) and `&`, in 64-bit registers, when a static range analysis shows that
  no intermediate overflows and that both sides of a division are non-negative (the BPF of 5.15
  has no signed division). Comparisons of two numeric fields (`tcp.srcport == tcp.dstport`), with
  the quantifiers over pairs; booleans are normalised first.
- **VLAN tags and TCP options:** the facts keep the number of in-band tags (`vlans`, the old
  padding byte) and the offsets of the first MSS, window scale, SACK permitted and timestamps
  options (`opts`, the old reserved word), so the facts stay 48 bytes. A tag's kind is read from
  its TPID. The option walk (`Tcp::option_iter`'s rules) is a static program of its own,
  `avulse_options` (slot `SLOT_OPTIONS`), which the parser tail-calls only with
  `CFG_TCP_OPTIONS`, set when the matcher reads options (`Matcher::reads_tcp_options`). It took
  three tries to get past the verifier (E2BIG on 6.8): a loop inlined in the parser multiplied
  with every path into it, and a loop alone still tracked the moving position exactly. What
  works: one unrolled step per byte position (constant stack offsets), with the walk's state
  (the next option's start, kept in `facts.verdict` until the matcher writes it, and the offsets
  found) in the facts map, read through `volatile`, which the verifier does not track. A BPF-to-
  BPF call was avoided: next to tail calls it needs arm64 JIT support that kernels before 6.0
  lack.
- **Offloaded tags** (ETHERNET only): the kernel sees the frame without its outer tag, so a filter
  that reads the link-layer layout (`eth.type`, `vlan.*`, `ieee8021ad.*`, `frame`) takes such
  frames to user space (a prologue on `M_VLAN`), and its matcher is inexact. Step 11 can make it
  exact with the TPID in the facts.
- **Sets** become sorted, merged ranges (IPv4 prefixes too) searched by a tree of jumps above 4
  ranges. **Decision:** no BPF maps for sets; a tree of 2000 single values is about 4000
  instructions, far under the limit, and maps would add per-handle map lifecycles.
- **5.15 quirk:** before a load of variable length into the stack (`contains`), the 5.15
  verifier wants the whole buffer initialized; the matcher zeroes it.
- **Measured** (VirtualBox, 6.8 / 5.15): parse 92 / 191 ns; `tcp.dstport == 443` 118 / 238 ns;
  `tcp.options.mss_val < 1400` on a SYN with four options, the walk included, 223 / 442 ns. Twelve
  nested `xor`s are the most verifier work (about 200,000 instructions processed, of the
  1,000,000 limit): the slots' constant values keep paths apart.
- **`xor`** keeps its left result in a stack slot: each side is compiled once.
- **Superset** (`superset`, `compile_superset`): each test `compile` refuses becomes `true`, or
  `false` under an odd number of `not`s; `xor` and conditionals are first written with
  `and`/`or`/`not`; then `ir::simplify`. The backend loads the exact matcher, else the superset,
  else one that takes everything (`everything`) when the verifier refuses; only inexact matchers
  make user space evaluate the filter (as before).
- **Tests:** the emulator test runs every filter at both layers with five metadata variants and
  the matching `Meta`; new tests for supersets (random mixes, the tshark tables, WinDivert's
  vectors), offloaded tags (frames stripped of their tag against the evaluator on the original),
  and folded constants. The tshark tables moved to `crates/filter/src/tests/filters.rs`, which
  `crates/ebpf/tests` include by path, like the vectors. `kernel.rs` runs the same in the kernel,
  plus the vectors and the tshark tables.
- **Left widened:** layer operators (`#n`), `@field`, `&` on bytes, multi-range slices,
  `contains`/`matches` on payloads, string functions, `timestamp`/`random*`, the ARP fields,
  `icmp.ident`/`seq`, `icmpv6.echo.*`, `ipv6.fraghdr.*`, and the `ipv6`/`arp` protocol bytes.

The original plan of the step follows.

**Why.** Spike A's code generator covers a subset. Everything else currently takes the
match-all fallback, which costs a trip to user space per packet.

**Where.** `crates/ebpf/src/codegen.rs`, with tests in `tests/emu.rs` and `tests/kernel.rs`.

1. **Coverage,** in this order, from the spike note's "Left for Phase 2":
   - metadata fields (direction, interface, loopback, impostor, layer);
   - IPv6 addresses;
   - `eth.addr`, VLAN fields, TCP option fields;
   - `len`/`count`, `contains`, arithmetic.
2. **Sets:** sorted ranges searched by a binary tree of jumps. Above a few dozen items, use a
   hash or LPM-trie map lookup.
3. **`xor`:** keep each operand's result in a stack slot instead of compiling it twice.
4. **Superset lowering:** `compile_superset(ir) -> (Matcher, exact: bool)`. It replaces each
   unsupported subtree by `true` or `false` depending on its polarity under `not`/`xor`, as
   ebpfdivert's `prefilter.c` widens rules. Use it when the exact matcher is unsupported,
   rejected or over the size limit. Only inexact handles evaluate in user space.
   `avulse filter explain` reports what runs in the kernel.

**Tests:**
- The emulator differential test covers every new feature (the `SUPPORTED` corpus must both match
  and miss).
- A proptest of superset soundness: the IR evaluator matches ⇒ the superset matches. The test
  also checks that `exact` implies equality.
- The kernel test runs on both VMs, with the largest programs on 5.15.

**Acceptance:**
- the WinDivert vectors and the tshark-table filters compile either exactly, or to a sound
  superset;
- `filter explain` shows which;
- the 241 WinDivert vectors run through the kernel matcher agree with the evaluator.

### Step 11: The ETHERNET layer (done, except devices without an Ethernet header)

**Outcome.** The ETHERNET layer captures and sends every frame, offloaded VLAN tags are exact
in the kernel, and the ARP fields compile. `tests/capture.rs` (23 tests) and `tests/kernel.rs`
(15) pass on 6.8 and 5.15.

- **The offloaded tag's TPID.** The kernel offloads only 802.1Q (0x8100) and 802.1ad (0x88a8)
  tags, so one metadata bit tells them apart: `M_VLAN_AD`, set from `skb->vlan_proto`. The
  records carry the `M_*` bits already, so their layout did not change. User space puts the tag
  back with its TPID (it always wrote 0x8100).
- **The parser parity.** With an offloaded tag, `tc.bpf.c` parses one in-band tag less, so the
  kernel's facts are those of the frame as user space restores it (Packet takes two tags). The
  contract is `Facts::offloaded(restored)`: the restored frame's facts, 4 bytes back, with
  `M_VLAN`, `M_VLAN_AD` and the TCI.
- **Exact matchers with an offloaded tag** (ETHERNET only): `vlan.*` and `ieee8021ad.*` see it as
  tag 0 and the tags in the frame after it; `eth.type` is its TPID; `frame.len` counts its 4
  bytes; `vlan`/`ieee8021ad` presence is that of the ID. Only filters that read link-layer bytes
  (`frame`, `eth`, the tags' bytes) keep the `M_VLAN` prologue and are inexact. The emulator test
  `offloaded_vlan_tags` strips the outer tag of every tagged corpus frame (both TPIDs) and checks
  every `SUPPORTED` filter against the evaluator on the original.
- **ARP fields:** `arp.hw.type`, `proto.type`, `hw.size`, `proto.size`, `opcode`,
  `src/dst.hw_mac` (when the hardware size is 6) and `src/dst.proto_ipv4` (when the protocol is
  IPv4 with 4-byte addresses), at offsets the packet's sizes give, and the `arp` bytes.
  `arp contains` stays widened: an ARP packet can be up to 1028 bytes long.
- **Injection** needed no change. Tagged frames go out through `AF_PACKET` with the tag in the
  frame, and come in through the `lo` redirect, whatever the offload setting (`vlan_tags`,
  `qinq`). Non-IP frames injected inbound (LLDP, ARP) reach the interface's ingress
  (`inject_inbound_frames`): the redirect happens at `lo`'s TC ingress, before any protocol
  handling, so no other mechanism was needed.
- **Capture tests** (VM): `arp_divert_and_reinject` (ARP diverted and sent back both ways; the
  peers still resolve each other); `vlan_tags` and `qinq` (802.1Q, and 802.1ad outside 802.1Q,
  over veth VLAN devices, with the offloads on and off: captured exactly in the kernel, tags in
  place with the right TPIDs, diverted and sent back); `modify_source_mac` (the host's ARP
  replies rewritten to another MAC, which the peer then believes); `inject_inbound_frames` (an
  LLDP frame and an ARP request injected inbound; the sniffing handle sees them as impostors and
  the host answers the ARP request).
- **Left for later (done in Step 13):** devices without an Ethernet header (tun, WireGuard, IP
  tunnels), which Step 8 skips. The programs would need to know, per packet, that the frame starts at the IP
  header, for instance from a per-interface set in the configuration. That is worth its own
  step after Phase 2 (VPN traffic is common), with the inbound redirect revisited for L3
  targets (Step 9's note).

The original plan of the step follows.

**Where.** `crates/ebpf/bpf/tc.bpf.c`, `crates/avulse/src/backend/linux/`.

- **Capture:** every frame on the selected interfaces, non-IP included (ARP, LLDP, VLAN-tagged).
  Step 8 already receives at ETHERNET and puts an offloaded VLAN tag back into the frame in user
  space (TPID 0x8100). Left: the kernel parser must see that tag too (Step 10's VLAN fields), the
  TPID (`skb->vlan_proto` in the record), and devices without an Ethernet header (tun,
  WireGuard), which Step 8 skips.
- **Injection:** Step 9 sends frames at ETHERNET: out of `if_idx` through `AF_PACKET`, and in
  through `lo`, whose TC ingress program redirects them before any protocol handling
  (`reinject_frames` covers IPv4 pings both ways). Left:
  - Outbound frames with tags: check that the kernel accepts in-band tags, or use
    `PACKET_AUXDATA`-style metadata.
  - Inbound non-IP frames (ARP): the redirect should carry them too, since it happens at `lo`'s
    TC ingress; check it in a VM. If it does not, the candidates are a
    `bpf_redirect(…, BPF_F_INGRESS)` from an egress hook on the target interface, or a tap
    device. Write the decision here.
- **Loop prevention and priorities** as for the NETWORK layers. ETHERNET and NETWORK handles on
  the same interface are ordered by TC priority like any two handles.

**Tests:** ARP request/reply diverted and reinjected (a ping across a veth still works), VLAN
capture with offload on and off (`ethtool -K … rxvlan off`), QinQ, modifying a frame's source
MAC, and LLDP sniffing.

**Acceptance:** those pass on both VMs. The guide documents the layer: what the filter sees
(`Link::Ethernet`), and how tags are restored.

### Step 12: The privileged suite (Phase 2 exit) (done)

**Outcome.** `crates/avulse/tests/capture.rs` is the suite (32 tests, plus `tests/kernel.rs`'s
15), and passes on 6.8 and 5.15. `.github/workflows/privileged.yml` runs both with `sudo` on a
GitHub Ubuntu runner, on pushes that touch the Linux crates and on pull requests. Added to Steps
8 to 11's tests:
- `loopback_single_sighting` (IPv4 and IPv6: held until sent back, seen once),
  `tcp_both_directions` (handshake, data and FINs each way), `inbound_udp` (held, then delivered
  through `lo`'s redirect), `auto_priority` (open order, the second handle sees an impostor),
  `queue_limits` (QUEUE_LENGTH, QUEUE_SIZE and QUEUE_TIME drops, the parameter range,
  `shutdown(Send)`), `shutdown_wakes_blocked_recv`, `bad_arguments` (an unknown interface, a tun
  device, the handle's checks through the real backend, nothing left behind), `forward_layer` (two
  namespaces routed through the host: diverted and sent on at NETWORK_FORWARD, unseen at
  NETWORK), and `kernel_agrees_with_evaluator` (20 filters, 17 exact, against a catch-all handle
  and `Filter::matches` on real traffic);
- `modify_outbound` now rewrites the payload too, and `bulk_tcp` checks 8 MiB each way byte for
  byte.

WinDivert's "close while receiving" becomes `shutdown_wakes_blocked_recv`: a Rust handle cannot be
closed while another thread borrows it. The widening got tighter on the way: an unsupported test
becomes the presence of the protocols it reads (`icmp.seq == 1` → `icmp`, a test of an absent field
being false) instead of `true`, so user space sees fewer packets.


**Where.** `crates/avulse/tests/` (root only, `AVULSE_BPF=1`, network namespaces and veth
pairs, like `../ebpfdivert/tests/test_integration.c`), run in the VMs like `tests/kernel.rs`.
Step 8's `tests/capture.rs` is the start: it covers crash cleanup, auto priority, sniff and drop,
shutdown, and the event fd.

Port the packet-layer scenarios of `test_integration.c`:

- loopback single sighting;
- `tcp.port` in both directions;
- inbound on a veth;
- outbound modify;
- send crafted;
- inexact filter auto-reinjection;
- priority chaining;
- auto priority;
- sniff and drop;
- queue parameters and shutdown;
- bulk TCP (GSO);
- the forward layer;
- crash cleanup (kill -9 a capturing child; traffic must flow within 3 s, and the next open
  reaps it);
- IPv6 loopback;
- the event fd;
- bad arguments;
- close while receiving.

Add Step 11's ETHERNET/ARP/VLAN cases, and the in-kernel versus interpreter agreement from Step
10.

Consider a CI job that runs the suite with `sudo` on a GitHub Ubuntu runner (passwordless sudo,
a 6.x kernel). It does not replace the 5.15 VM run.

**Acceptance (Phase 2 exit):** the whole suite passes on both VMs, run one at a time, and each VM
is destroyed afterwards. Then update `docs/roadmap.md` (Phase 2 done) and `CLAUDE.md` (what
what the `avulse` crate and its Linux backend now hold).

### Step 13: Devices without an Ethernet header (done)

**Outcome.** NETWORK and NETWORK_FORWARD handles capture, divert and send on devices whose packets
start at the IP header: `ARPHRD_NONE` (tun, WireGuard), `ARPHRD_RAWIP`, `ARPHRD_PPP`,
`ARPHRD_TUNNEL` (ipip), `ARPHRD_TUNNEL6` (ip6tnl) and `ARPHRD_SIT`. `tests/capture.rs` (36 tests)
and `tests/kernel.rs` (15) pass on 6.8 and 5.15.

- **Entry programs.** `avulse_ingress_ip` and `avulse_egress_ip` share the handle's maps and slots
  and call `classify(…, raw_ip)`: the parser starts at offset 0, with `parse_ipv4`/`parse_ipv6`
  chosen by `skb->protocol` (the header's version must agree), no `F_ETH`, no VLAN. The facts are
  then those of the NETWORK layers (`base = l3 = 0`), so `Facts::at_network` stays the contract
  and the code generator did not change. At ETHERNET they pass everything. There is no redirect
  branch: inbound injections arrive on `lo`.
- **Loader.** `Classifier::attach` takes the `Link` (`Ethernet` or `Ip`) to pick the program.
  `Hook` is still the attach point, so the registry's layout did not change.
- **Selection** (`targets`, now a pure function over the interface list, tested without
  privileges): `sys::Interface::link` maps each `ARPHRD_*` kind to `Link::Ethernet`, `Link::Ip` or
  unsupported. Raw-IP devices are attached at the NETWORK layers; the ETHERNET layer skips them,
  or refuses them when named (`Error::Unsupported`). Other kinds stay skipped, or refused when
  named.
- **GRE stays unsupported.** In NBMA mode (no remote address) a GRE device has `header_ops`, and
  TC sees the outer header first; sysfs does not tell the modes apart.
- **Sending.** A context with an empty L2 header (a packet captured on such a device) sends an
  outbound or forwarded packet out of the same device through `AF_PACKET`, as it is, with the
  protocol taken from the IP version; elsewhere it is routed. Inbound packets go through `lo`'s
  redirect, behind a made-up Ethernet header with a zero MAC address (`lo`'s). The redirect reaches
  an L3 device through `__bpf_redirect_no_mac` and the packet is delivered as `PACKET_HOST`.
  ebpfdivert's second stage (`bpf_skb_change_type`) was not needed, which settles Step 9's
  "revisit with L3 devices".
- **Tests.**
  - `tun_divert_and_reinject`, `tun_sniff_modify_inject` and `tun_kernel_agrees_with_evaluator`
    run on a tun device owned by the test, which plays the far end through the device's file.
    They cover:
    - divert and reinject over IPv4 and IPv6, each packet seen once;
    - sniff, an outbound reply rewritten on its way out, built packets injected inbound and
      outbound;
    - the ETHERNET layer seeing nothing;
    - 13 filters against the evaluator.
  - `ipip_tunnel`: an ipip tunnel to the namespace over the veth pair, with pings and 8 MiB of TCP
    each way through a diverting handle (GSO packets on the tunnel).
  - `bad_arguments`: tun at both layers, and GRE.
  - `BPF_PROG_TEST_RUN` always builds an Ethernet header (`eth_type_trans`), so `tests/kernel.rs`
    cannot drive the `_ip` programs; it still checks that the verifier loads them on both
    kernels.

## Phase 3: Linux event layers and API 0.x

**Goal** (roadmap, Phase 3): the FLOW, SOCKET and REFLECT layers on Linux, `process.name`, then the
Rust API and the C ABI reviewed as 0.x. **Exit:** every layer on Linux, and the C ABI. (The
release planned here moved after Phase 6; see "Versions and releases".) **Phase 3 is done.**

**What to port.** ebpfdivert's `src/ebpfdivert_events.bpf.c` (cgroup and sockops programs),
and the events, REFLECT and blocking parts of `src/handle.c`; its `docs/architecture.md` section 3
explains them. As in Phase 2, port the logic, not the layout.

**Decisions for this phase** (change them here, with a reason, if the work proves them wrong):

- **One instance per handle,** as at the packet layers. The event programs live in their own
  object (`crates/ebpf/bpf/events.bpf.c`), with their own configuration (heartbeat, shutdown,
  layer, flags) and ring buffer. They attach to the cgroup v2 root through `bpf_link`s, so they
  go with the process that owns them. The heartbeat and fail-open rules are the packet layers'
  (a stale or shut-down configuration lets every socket call through). Without a cgroup v2
  mount, opening at these layers is `Error::Unsupported`.
- **No packet.** Events reach user space as records of their own (event, protocol, family,
  local and remote address and port, PID, endpoint and parent endpoint, the process name, and a
  blocked bit). `Address::flow` is filled from them, and so is `Meta`'s flow tuple. A filter is
  evaluated against an empty packet (`Link::Ip`), so `ip`/`tcp`… are false: that is WinDivert's
  quirk, and `local.*`, `remote.*`, `protocol`, `event`, `process.*` and `endpoint.*` are what
  these layers filter on.
- **User space filters what it only reports.** Events are rare next to packets, so FLOW events,
  and SOCKET events with `SNIFF`, all go to user space, which runs `Filter::matches`. The code
  generator is only needed where the kernel has to decide.
- **Blocking needs the decision in the kernel.** A SOCKET handle without `SNIFF` refuses the
  BIND and CONNECT events its filter matches (`EPERM`), so the filter must be exact in the
  kernel. A superset would refuse too much, and a subset too little. `codegen` gains an event
  `Env`: the facts are the event's (a per-CPU map, as for packets), and `event` is decided per
  program. A program array holds programs of one type only, so each hook type has its own
  matcher, compiled from the same IR:
  - `cgroup/connect4`/`connect6` (`cgroup_sock_addr`);
  - `cgroup/post_bind4`/`post_bind6` (`cgroup_sock`).

  If the filter does not compile exactly, the open fails with `Error::Unsupported` and a hint to
  add `SNIFF`. Linux cannot refuse LISTEN and ACCEPT. A blocking filter that can match them (it
  does not fold to `false` with `event` set to them) is `Error::Unsupported` too, as in
  ebpfdivert.
- **REFLECT has no BPF program.** It diffs the registry (`registry.rs`) every 100 ms, as
  ebpfdivert does, and reports OPEN/CLOSE with `Address::reflect`. The data is the handle's
  filter text in native syntax, from the registry entry; the compat shim (Phase 4) serializes
  WinDivert's filter object instead.

### Step 14: The event programs and records (done)

**Outcome.** `crates/ebpf/bpf/events.bpf.c`, the event record in `bpf/abi.h` (`struct
avulse_event`, 88 bytes, mirrored by `abi::EventRecord`), and `loader::Events`
(`src/loader/events.rs`: `load_with_ring`, `attach(layer)`, `take_ring`, `records`,
`config_writer`, `set_config`, `stats`, and `cgroup_root`). `tests/kernel.rs` (19 tests) passes on
6.8 and 5.15.

- **One object, nine programs:** `sock_create`, `post_bind4/6`, `connect4/6`, `sock_release`,
  `sockops`, `cgroup_skb` egress/ingress. `attach` links the ones the layer needs to the cgroup
  v2 root (the mount from `/proc/self/mountinfo`). The links always allow other programs and the
  kernel refuses attach flags with them, so the mode is aya's `Single` (flags 0); every
  supported kernel (5.7 and later) takes the link path. The links go with the process.
- **The configuration is the TC programs' `struct avulse_config`** (layer FLOW or SOCKET,
  `CFG_SHUTDOWN`, the heartbeat; `CFG_SNIFF` for Step 16), so `Beat` and `ConfigWriter` serve both
  kinds of handle. `loader.rs`'s configuration, statistics and ring functions are shared. The
  event programs count `RING_FULL` and `OWNER_GONE`.
- **The record** carries the timestamp, the socket's cookie (the endpoint), the parent endpoint
  (always 0: Linux does not say which socket a socket came from), PID, event, protocol, family,
  flags (`EV_OUTBOUND`: a connect, an active TCP flow, a UDP flow sent first; `EV_BLOCKED` for
  Step 16; `EV_RELEASED`, a UDP socket's end at FLOW, which user space turns into DELETED for each
  of its flows), ports (host order), addresses (network order, IPv4 mapped) and the process's
  `comm`.
- **Socket storage** (`BPF_MAP_TYPE_SK_STORAGE`, cloned to accepted sockets) keeps the PID and
  name from `sock_create`, and the endpoints, which `sock_release` cannot read.
- **The task's PID and name** come from `bpf_get_current_pid_tgid`/`bpf_get_current_comm` behind
  a load-time constant (`avulse_have_task`). `load_with_ring` loads again without them when the
  kernel refuses them. Both 5.15 and 6.8 allow them in cgroup socket programs. `comm` is the
  thread's name.
- **Tests** (in the kernel, in this process):
  - SOCKET over IPv4 and IPv6: BIND, LISTEN, CONNECT, ACCEPT and CLOSE of a TCP listener and
    client, with their endpoints, PID, name, timestamps and directions; each socket closes
    once. UDP: bind, connect, close.
  - FLOW: a TCP connection established and deleted on both ends (active outbound, passive
    inbound); UDP flows once per 5-tuple and socket, and one release per socket.
  - Shut down or with a stale heartbeat, nothing is reported.
- **Also:** GitHub's runners moved to Linux 7.0, whose `BPF_PROG_TEST_RUN` refuses an IPv4 or
  IPv6 frame with a truncated IP header (`EINVAL`). The kernel tests now leave such frames out
  (`common::test_runnable`); the emulator keeps them. The privileged workflow passes on 7.0,
  the tun and ipip tests included.

The original plan of the step follows.

**Why.** FLOW and SOCKET share the programs, the records and the socket-local state.

**Where.**
- `crates/ebpf/bpf/events.bpf.c` and `bpf/events.h`, mirrored in `src/events.rs`:
  - the programs: `cgroup/sock_create`, `post_bind4/6`, `connect4/6`, `sock_release`, `sockops`
    and `cgroup_skb` ingress/egress;
  - `BPF_MAP_TYPE_SK_STORAGE` for each socket's PID, name and endpoints;
  - an LRU hash of the UDP 5-tuples already reported;
  - the configuration and the ring.
- `loader.rs`: `Events::load`/`attach`, through aya's cgroup program types with links.
- `ebpfdivert` probes whether `bpf_get_current_pid_tgid` is allowed in cgroup socket programs.
  Do the same with a load-time constant, and check what 5.15 allows.

**Tests.** `tests/kernel.rs` loads and attaches the programs on both VMs, with sockets created,
bound, connected and closed in a child process, and checks the records (endpoints, PID, cookie
as the endpoint ID, the order of events). The record layout is mirrored on both sides, which
assert its size.

**Acceptance.** The verifier accepts every program on 5.15 and 6.8, and the records of a TCP
connect, a TCP accept, a UDP exchange and a bind match what the test did.

### Step 15: The FLOW layer (done)

**Outcome.** `crates/avulse/src/backend/linux/events.rs`: FLOW handles open on Linux
(`capabilities()` reports `open` only: events are reported, never held). `tests/capture.rs` (40
tests) and `tests/kernel.rs` (19) pass on 6.8 and 5.15.

- **The handle** loads `Events`, writes the configuration (layer FLOW, a fresh heartbeat), links
  the programs to the cgroup root (`Error::Unsupported` without cgroup v2), registers in the
  registry (no TC filters: the links go with the process, so `cleanup` only removes the entry),
  and joins the heartbeat.
- **Receiving.** The receive side (`Rx<R>`: the queue, the readiness eventfd, epoll and the
  `recv` loop) is now generic over its ring and shared with the packet handle.
- **Addresses.** Each record becomes an address, with no packet: the event, `outbound`,
  `loopback` (either address), `ipv6`, `sniffed`, and `Address::flow`.
- **Filtering.** The filter runs in user space, on an empty packet, with `Meta::process_name` from
  the record's `comm`.
- **UDP flows** (`UdpFlows`): a handle remembers the UDP flows each socket established (at most
  65,536), and turns the socket's `EV_RELEASED` record into a DELETED event for each of them, with
  the release's timestamp.
- **The direction of a TCP flow** is kept in the socket's storage when it is established, so that
  its DELETED event says `outbound` too (the state callback cannot tell).
- **The process of a socket made before the handle opened is unknown (0).** That includes the
  sockets accepted from such a listener, since storage is cloned from the listener. The later
  callbacks (sockops, packets) run in softirq, not as the owner. Documented in the guide.
  `process.pid` filters miss those sockets.
- **Tests** (`tests/capture.rs`):
  - `flow_tcp`: outbound to the peer and inbound from the namespace (bash's `/dev/tcp`), with
    endpoints, ports, the PID and direction, and a `process.pid` filter;
  - `flow_udp`: established once over three exchanges, deleted when the socket closes;
  - `flow_loopback`: both ends over IPv4 and IPv6;
  - `flow_shutdown_and_dead_owner`: what is queued is delivered after `shutdown`, then
    `Error::Shutdown`; a killed owner's entry is reaped.
  - Unit tests: event records to addresses and filters, and `UdpFlows`.

The original plan of the step follows.

**Where.** `backend/linux/events.rs` (open, receive, close). The `Opened` handle for events
shares the queue (`queue.rs`), the heartbeat and the registry with the packet layers.
- TCP: ESTABLISHED from `sockops` (active and passive established, which then ask for state
  callbacks), DELETED when the state goes to CLOSE.
- UDP: ESTABLISHED on the first packet of a 5-tuple (`cgroup_skb`), DELETED for each of the
  socket's flows when it is released.
- `Address::flow` carries the endpoint, parent endpoint, PID, addresses, ports and protocol, and
  `outbound` says who opened the flow.
- FLOW requires `SNIFF` and `RECV_ONLY`, which `handle.rs` already checks.

**Tests** (`tests/capture.rs`): TCP to the peer server and back, both directions; UDP echo; a
filter on `remote.port` and `process.pid` (the test's own); loopback; a dead owner (the programs
fail open, the links go with the process).

**Acceptance.** Those pass on both VMs. The guide documents the layer and its fields.

### Step 16: The SOCKET layer, with blocking (done)

**Outcome.** SOCKET handles open on Linux (`capabilities()`: open, divert, drop). With `SNIFF`
they report. Without it they refuse the binds and connects their filter matches (`EPERM`) and
report them. With `DROP` they refuse silently. `tests/emu.rs` (event matchers), `tests/kernel.rs`
(20) and `tests/capture.rs` (44) pass on 6.8 and 5.15.

- **Kernel side.**
  - `bind` and `connect` write the event's facts (`struct avulse_ev_facts` in `facts.h`, 72
    bytes, mirrored by `facts::ev`) and its record to the per-CPU `avulse_ev_state`. Then they
    tail-call the matcher of their kind.
  - A program array holds one program type, so each of connect4, connect6, post_bind4 and
    post_bind6 has its own array (`avulse_progs_*`), action program (`avulse_ev_act_*`) and
    matcher (`loader::EventHook`, `Events::set_matcher`).
  - The action reports the event with `EV_BLOCKED` when the verdict is 1, and returns 0 to
    refuse.
  - Without a matcher, the call goes through.
- **The event facts** share only `flags` and `verdict` with the TC facts, which is what the
  generated prologue, presence tests and epilogue use. `EF_LOCAL4/6` and `EF_REMOTE4/6` say
  whether each address is IPv4-mapped. The meta byte has `M_OUTBOUND` and `M_LOOPBACK` (either
  address, as user space computes it).
- **The code generator's event mode** (`Env::event`, layers FLOW and SOCKET):
  - `lower_event` decides every leaf that reads no field of the event. It uses the bytecode
    interpreter on the empty packet with the handle's constants (`constant`), so `tcp` is false
    and `frame.len == 0` is true, exactly as the evaluator says.
  - `local.addr`/`remote.addr` become tests of stand-ins: `ip.src`/`ip.dst` for IPv4-mapped
    addresses (a big-endian word of the facts, `Scalar::FactBe`), `ipv6.src`/`ipv6.dst` for the
    others (`Region::Fact`). The other family gives `!=` and `not in`.
  - `operand(…, ev)` reads the event's ports, protocol, PID, direction and loopback from the
    facts.
  - `Gen::copy` copies bytes from the facts where packets use `bpf_skb_load_bytes`.
  - The matcher returns 1 (through) when it cannot reach the action.
  - `process.name`, `endpoint.id`, `timestamp` and `random*` are unsupported.
- **Opening a refusing handle.** `codegen::decide_for` must say that the filter never matches
  LISTEN or ACCEPT, which Linux cannot refuse. Each matcher must compile exactly and pass the
  verifier. Otherwise the open fails with `Error::Unsupported`, which suggests `SNIFF`. Both
  checks run before anything is loaded.
- **Tests.**
  - The emulator runs 36 SOCKET filters as connect and bind matchers on the facts of 64
    events (both families, loopback, unknown endpoints), against the evaluator on the same
    events, and refuses the unsupported ones.
  - In the kernel, all 36 load for the four kinds of program (at most 125 instructions
    processed).
  - Capture tests:
    - `socket_events`: bind, listen, connect, accept, three closes;
    - `socket_refuses_calls`: connect and bind refused over IPv4 and IPv6, others through,
      reported unsniffed, `DROP`;
    - `socket_filters_the_kernel_cannot_refuse`;
    - `socket_dead_owner`: refusing stops as soon as the owner is killed, since its links go
      with it.
- **Left:** `process.name` in the kernel (Step 17). A preemptible kernel could in principle run
  another task's bind or connect program on the same CPU between the facts and the action,
  since the state is per CPU and the programs run with migration disabled, not preemption.
  Ubuntu's kernels preempt voluntarily, which does not happen inside a BPF program. Revisit if
  it shows.

The original plan of the step follows.

**Where.** `codegen.rs` (the event `Env`: event facts, `event` decided per program, the fields of
these layers), `events.bpf.c` (tail calls into the per-type matchers, and the verdict: refuse
with `EPERM`, and report the event with the blocked bit), and the backend.
- BIND, CONNECT, LISTEN, ACCEPT and CLOSE.
- `connect` knows the local endpoint only when the socket was bound before (from the socket's
  storage). Document this.

**Tests.**
- The emulator tests the event matchers against the evaluator on generated events.
- In the VMs: a blocking handle refuses `connect` to one port and lets another through, refuses
  `bind` to a port, does not block what it does not match, and stops blocking once its owner
  dies (heartbeat).
- A `SNIFF` handle sees every event.
- Opening a blocking handle with a filter that is not exact, or that can match LISTEN/ACCEPT,
  fails.

**Acceptance.** Those pass on both VMs.

### Step 17: `process.name` and the REFLECT layer (done)

**Outcome.** Every layer works on Linux. `tests/emu.rs`, `tests/kernel.rs` (20) and
`tests/capture.rs` (46) pass on 6.8 and 5.15.

- **`process.name` in the kernel.** The SOCKET matchers read the event's `comm` (16 bytes in
  the facts) as `Region::FactStr`. Its length is the first NUL, found by an unrolled forward
  scan, and the name is absent when it is empty. `==`, `!=` and sets reuse the byte predicates.
  `contains`, ordering and `upper()`/`lower()` are unsupported. The emulator corpus varies the
  name (`test`, `curl`, empty, 16 bytes without a NUL), and six new table filters agree with
  the evaluator.
  - A name that is not UTF-8 is absent in user space, while the kernel compares its bytes.
    This is documented.
- **The address carries the name (decision).** `Flow` gains a 32-byte, NUL-padded process name
  (`Flow::process_name`, `set_process_name`, cut at a character boundary; `PROCESS_NAME_LEN`),
  after `reserved`. `Flow` is 96 bytes and `Address` 216. `ADDRESS_VERSION` is 2.
  - `Address::meta()` now sets `process_name`, so `Filter::matches` on a received address sees
    it; only `iface` is missing. The FLOW/SOCKET backend sets the name from the record.
  - 32 bytes rather than Linux's 16, for the other platforms' longer names.
  - At REFLECT, `meta()` gives the reflected handle's `layer`, besides its priority and
    process, as WinDivert does.
- **REFLECT** (`backend/linux/reflect.rs`).
  - The handle registers itself, then reads the registry every 100 ms, on a periodic
    `timerfd` in its epoll set (`sys::Timer`).
  - It compares the live entries (whose owners are alive) with what it saw (`reflect::diff`):
    CLOSE for those gone, then OPEN for the new ones, oldest first. At first it reports
    everything, itself included.
  - The data is the registered filter text.
  - Filters see an empty packet and the reflected handle's metadata.
- **Tests.**
  - Unit tests: `reflect_events` (the diff, the address, the metadata), the `Flow` name
    accessors, and the address layout.
  - Capture tests:
    - `process_names`: a connect from a thread named `avulse-deny` is refused by name, one
      from `avulse-allow` goes through, and FLOW reports its name;
    - `reflect_layer`: itself at first, a child's FLOW handle opening and its owner killed, and
      a filter on `layer`.

The original plan of the step follows.

**Where.**
- `process.name` is the task's `comm`, recorded at `sock_create` (`bpf_get_current_comm`) in the
  socket's storage, so it survives the process. It goes to the records, `Meta::process_name`
  and, for the SOCKET matcher, the event facts (16 bytes, compared as a string).
- `Address` has no room for the name. Decide whether to add it (`ADDRESS_VERSION` 2) or to leave
  it to filters. Leaning towards adding it, because WinDivert users ask for it through
  `/proc/<pid>/comm`, which races with the process's exit.
- REFLECT: `backend/linux/reflect.rs`, the registry diff, with `Address::reflect` (timestamp,
  flags, PID, priority, layer) and the filter text as the data.

**Tests.** Filters on `process.name` at FLOW and SOCKET (the test binary's name). REFLECT sees a
handle opened and closed by another process, and one that dies (CLOSE once it is reaped).

**Acceptance.** Those pass on both VMs. `capabilities()` reports FLOW, SOCKET and REFLECT on
Linux.

### Step 18: API 0.x and the C ABI (done)

**Outcome.** The API was reviewed for 0.1, and `crates/capi` is `libavulse`. Host tests,
`tests/kernel.rs` (20) and `tests/capture.rs` (46) pass on 6.8 and 5.15, and so does the C
program's capture part.

- **API review (decisions).**
  - `Handle::recv_batch(buf, addrs, lens, timeout)` waits for the first packet as `recv` does.
    Then it takes the packets already there, back to back in `buf`, and returns how many.
    Parallel slices, so the C call is the same shape.
    - What does not fit stays queued for the next call. To support that, the backends implement
      `Opened::recv_ready` (`Rx::ready`, `Queue::unpop`; the default returns nothing).
  - `Handle::send_batch(packets, addrs)` sends in order. It returns how many were sent, and the
    error only if the first one fails.
  - `#[non_exhaustive]` on `Param` (WinDivert also has version parameters) and `Syntax` (a
    tcpdump front-end may come). It was already on `Address`, `Flow`, `Reflect`, `LayerSupport`
    and `Error`. `Shutdown` and the flag set stay closed.
  - `Layer` and `Event` (`avulse-filter`) implement `TryFrom<u8>`, which replaces three
    hand-written mappings.
  - The `Error` variants stay as they are.
- **The C ABI** (`crates/capi`): a `cdylib` and a `staticlib` named `avulse`, without an
  `rlib`, which would collide with the facade's. The facade is the dependency `avulse-rs`.
  - 20 functions:
    - open (with `struct avulse_open_options`), recv and recv_batch (timeouts in milliseconds),
      send and send_batch, shutdown, the parameters, `avulse_fd`, close;
    - `avulse_address_init`, cleanup, version;
    - the filter helpers: check, format, convert, eval.
  - Statuses are `AVULSE_E_*`, not errno, because Windows lacks some errno values.
    `avulse_last_error` (the rendered diagnostic for a filter) and `avulse_last_os_error` are
    per thread.
  - `avulse_address` has `Address`'s layout, 216 bytes, but integers for its `bool`s and enums.
    It is converted field by field with checks, so no value from C is undefined behaviour.
  - **The header is written by hand, not by cbindgen (deviation).** cbindgen is not installed,
    and it handles types from other crates and their `#[repr]` poorly. Instead, the header's
    `_Static_assert`s and `src/tests.rs` pin the same offsets on `avulse_address` and
    `avulse::Address`, which is an exact check of the ABI.
- **Tests.**
  - Unit tests: layouts, address round trips and refusals, filter helpers, argument checks.
  - `tests/c.rs` builds the library (tests do not build a `cdylib`), compiles `tests/c/abi.c`
    with `-Wall -Wextra -Werror` into `target/<profile>/avulse-c-test` (rpath `$ORIGIN`), and
    runs it. In a VM, `sudo AVULSE_BPF=1 /vagrant/target/debug/avulse-c-test` also runs a
    handle on `lo`:
    - receive with a timeout, and readiness through `avulse_fd` and `poll`;
    - divert and send back;
    - three datagrams through `recv_batch` and `send_batch`;
    - `AVULSE_E_BUFFER` with the needed length;
    - shutdown.
  - The facade's `batches` test runs on the fake backend.
- **Guide:** `libraries/c.md`, whose example compiles.
- **Moved to Step 19:** building `libavulse.so` in the `manylinux_2_28` containers. It belongs
  with the release job that ships the tarballs.

The original plan of the step follows.

**Why.** The roadmap freezes the Rust API and the C ABI as 0.x before the release.

**Where.**
- `crates/avulse`: review the public surface before 0.1:
  - batch `recv`/`send`;
  - the `Error` variants;
  - `OpenOptions`;
  - `Address`, whose `ADDRESS_VERSION` and size are pinned by `tests.rs`;
  - `capabilities()`.

  Mark what may still change with `#[non_exhaustive]`.
- `crates/capi`: a `cdylib` and `staticlib` with a cbindgen header (`include/avulse.h`):
  - an opaque handle, with `avulse_open`, `avulse_recv`/`_ex` (batch), `avulse_send`/`_ex`,
    `avulse_shutdown`, `avulse_close`, `avulse_set_param`, `avulse_fd`;
  - `struct avulse_address` (the `#[repr(C)]` `Address`);
  - the filter helpers: compile and check with the diagnostic as text, `format`, `explain`,
    `eval` on a packet;
  - errors as negative errno values.
- `libavulse.so` built in `quay.io/pypa/manylinux_2_28_{x86_64,aarch64}`. aya is pure Rust, so
  the only dependency is glibc 2.28.

**Tests.**
- A C program under `crates/capi/tests/`, compiled with `cc` by an integration test, opens a
  handle with a bad filter (an error and its text), checks the address layout against the
  header, and runs the filter helpers.
- Its capture part (open, recv, send) runs in the VMs.

**Acceptance.**
- The header is generated and checked in, and CI fails when it is stale.
- The C test passes on the host, and in a VM for the capture part.
- The guide gets a C API page.

## Phase 4: WinDivert compat shim on Linux and conformance

**Goal** (roadmap, Phase 4): a library that exports ebpfdivert's C API (`../ebpfdivert/include/
ebpfdivert.h`) over avulse, so that the pydivert and jdivert test suites run against it
**unchanged**, through the hooks they already have (`PYDIVERT_EBPFDIVERT_LIB`,
`-Debpfdivert.local`). **Exit:** both suites pass. They then become the conformance suite that the
Windows driver (Phase 5) passes too, through the `WinDivert*` exports of the same crate. **Phase 4
is done** (Steps 19 to 21).

**Decisions for this phase** (change them here, with a reason, if the work proves them wrong):

- **One crate, `crates/windivert-compat`** (`avulse-windivert-compat`, `[lib] name =
  "avulse_windivert"`, `cdylib` and `rlib`): `libavulse_windivert.so`. Its core (the 80-byte
  address, the errno mapping, the helpers) is platform-neutral; the `ebpfdivert_*` exports are
  Linux only, and Phase 5 adds the `WinDivert*` ones beside them.
- **Only what the bindings call is exported**: the handle API (`open`, `open_ex`, `recv`,
  `recv_ex`, `send`, `send_ex`, `shutdown`, `close`, `set_param`, `get_param`, `get_event_fd`,
  `get_handle_stats`, `unregister`, `strerror`, `version`, `set_print`) and the helpers
  (`compile_filter`, `eval_filter`, `format_filter`, `calc_checksums`, `hash_packet`), each with
  the `ebpfdivert_` prefix. The pinned global mode (`load`, `rules_*`) belongs to
  `ebpfdivert-cli` and is left out.
- **The reinjection context goes in the union.** At NETWORK and NETWORK_FORWARD, bytes 8 to 63
  of WinDivert's 64-byte union (after `IfIdx` and `SubIfIdx`) carry the first 56 bytes of
  avulse's `Context`. A backend's context must therefore fit in 56 bytes (`address.rs` says so;
  Linux's `Ctx` uses 42). The bindings round-trip the union untouched, as they do for
  libebpfdivert.
- **Errors are negative errno values**, as in libebpfdivert: `Filter` and `InvalidArgument` →
  `EINVAL`, `Unsupported` → `EOPNOTSUPP`, `Shutdown` → `ESHUTDOWN`, `Timeout` → `EAGAIN`,
  `BufferTooSmall` → `ENOBUFS`, `Io` → its OS error (else `EIO`).
- **The bindings are never changed.** A failure of their suites is fixed in the shim or in
  avulse; an intended difference is listed under "Divergences from libebpfdivert" below and in
  the guide.

### Step 19: The shim's core: address, errors, helpers (done)

**Outcome.** `crates/windivert-compat`: `address.rs` (`WdAddress`), `packet.rs` (WinDivert's
packet parser), `helpers.rs`, and the helper exports. 14 unit tests pass.

- **Vectors from WinDivert's code.** `scripts/gen_compat_vectors.py` compiles a driver against
  ebpfdivert's vendored helpers. On 39 packets it records 117 hashes, 273 checksum runs and 148
  evaluations. The packets are WinDivert's own plus edge cases: truncated, fragments, IPv6
  extension headers, TCP options, a UDP checksum that comes out as 0. The evaluations cover
  `random*` at several timestamps, and the packet and address checks. All of them agree, and so
  do WinDivert's 241 filter vectors through `eval_filter`.
- **`random*`.** `eval_filter` fills `Meta::hash` with WinDivert's hash, seeded with the
  timestamp and made non-zero, as WinDivert's evaluator does.
- **`format_filter` (decision).** It returns a canonical WinDivert syntax of the parse tree:
  `Filter::format_windivert`, a `Display` for `windivert::parse::Expr`. It does not port
  WinDivert's decompiler. Every vector formats to a filter that compiles to the same IR, and
  formatting is stable. The bindings declare the function but never call it.
- **Deviation: no `catch_unwind`.** Panics abort, as in `crates/capi` (`extern "C"`).
- **A WinDivert bug left out of the vectors.** On a TCP data offset longer than the packet,
  WinDivert's checksum reads past the end of the packet. The shim checksums only the bytes that
  are there.

The original plan of the step follows.


**Where.** `crates/windivert-compat/src/`:
- `address.rs`: `WdAddress` (`#[repr(C)]`, 80 bytes), accessors for the bitfield word (layer bits
  0 to 7, event 8 to 15, then sniffed, outbound, loopback, impostor, ipv6, ip_checksum,
  tcp_checksum, udp_checksum) and the union (network: `if_idx` at 0, `sub_if_idx` at 4;
  flow/socket: endpoint 0, parent 8, PID 16, addresses 20 and 36 as host-order words with word 0
  least significant and IPv4 as `::ffff:a.b.c.d`, ports 52 and 54, protocol 56; reflect:
  timestamp 0, PID 8, layer 12, flags 16, priority 24). `to_avulse`/`from_avulse`.
- `errno.rs`: the mapping above.
- `helpers.rs`: `compile_filter` (`Filter::compile_windivert`, the diagnostic's message in a
  thread-local `CString`, its span's start as the position), `eval_filter` (the address's layer
  and `Address::meta()`, `Packet::parse(Link::Ip)`), `format_filter` (WinDivert syntax out: a
  printer of the WinDivert parse tree in `crates/filter/src/windivert/`), `calc_checksums`
  (`avulse_proto::checksum` with WinDivert's `NO_*` flags) and `hash_packet` (WinDivert's hash,
  reimplemented from `windivert/dll/windivert_helper.c`, which is LGPL user-mode code, not the
  driver).

**Tests.** The address layout byte by byte, round trips at every layer (the union survives at
NETWORK), the errno mapping, and vectors generated from libebpfdivert's helpers by
`scripts/gen_compat_vectors.py` (a C program against `../ebpfdivert/src/wd/`, no root) for
`hash_packet`, `calc_checksums` and `format_filter`. WinDivert's 241 filter vectors run through
`eval_filter` (included by path from `crates/filter/src/tests/windivert_vectors.rs`).

**Acceptance.** The helpers agree with libebpfdivert on every vector.

### Step 20: The handle exports, and `Handle::stats` (done)

**Outcome.** The 21 exports, `Handle::stats` (`avulse::Stats`), and `avulse_stats` in the C ABI.
`tests/capture.rs` of the shim (6 tests), avulse's `tests/capture.rs` (46) and `tests/kernel.rs`
(20), and `avulse-c-test` pass on 6.8 and 5.15.

- **Closing while another thread waits.** The handle counts the calls in progress, as
  libebpfdivert's `GUARDED` does. `close` marks the handle, shuts it down (which wakes waiting
  receivers), waits for the calls to finish, then frees it. Calls on a closing handle return
  `-EBADF`.
- **libebpfdivert's rules, checked in the shim:**
  - receiving on `SEND_ONLY` or sending on `RECV_ONLY` is `-EPERM`;
  - sending above the MTU is `-EMSGSIZE`;
  - `recv` with a NULL packet returns the length and the address (through a per-thread scratch
    buffer);
  - `send_ex` splits packets by their IP length.
- **`Stats`.** Most counters are the kernel's. `queue_drops` is the user-space queue's. REFLECT
  handles have only the queue's. The shim maps them to ebpfdivert's `STAT_*`, with
  `PARSING_ERR` ← `load_errors`.
- **REFLECT data.** Native filter text at first, as Step 17 decided; Step 21 changed it (below).
- **Linux's reinjection context fits in 56 bytes.** `record.rs` asserts it at compile time.

The original plan of the step follows.


**Where.**
- `crates/windivert-compat/src/ebpfdivert.rs` (Linux): the `#[unsafe(no_mangle)] unsafe extern
  "C"` exports, each body under `catch_unwind` as in `crates/capi`. The handle is a boxed
  `avulse::Handle`. `open` sets `errno` and returns NULL, `open_ex` returns the negative errno.
  `ifnames` → `OpenOptions::interfaces`; `ring_bytes` is accepted and ignored unless a suite
  needs it; a negative timeout blocks and 0 polls; `recv_ex`/`send_ex` → `recv_batch`/
  `send_batch`; `get_param` answers 2 and 2 for the version parameters; `get_event_fd` →
  `as_fd`; `unregister` → `avulse::cleanup`; `set_print` does nothing (avulse does not log).
- `crates/avulse`: `Handle::stats()` returning a `#[non_exhaustive]` `Stats` (diverted, sniffed,
  dropped, ring full, owner gone, too big, queue full), through `Opened::stats` (default
  `Unsupported`); the Linux handles read their programs' counters. The shim maps them onto
  ebpfdivert's `STAT_*` indexes. `crates/capi` gains `avulse_stats`.

**Tests.** `tests/symbols.rs` builds the library and checks the exported symbols (`nm -D`) are
exactly the list above. `tests/capture.rs` (`AVULSE_BPF=1`, root, in the VMs) drives the exports on
`lo`: a bad filter (`-EINVAL` and its position), a timeout (`-EAGAIN`), divert and send back,
`recv_ex`/`send_ex`, `-ENOBUFS`, the statistics, `-ESHUTDOWN`, and FLOW and SOCKET addresses.

**Acceptance.** Those pass on both VMs.

### Step 21: The binding suites (Phase 4 exit) (done)

**Outcome.** Both suites pass unchanged against `libavulse_windivert.so`. They ran in the
bindings' own Ubuntu 24.04 VMs, with the host-built library, which needs GLIBC 2.34 at most.
- pydivert: 155 passed, and 6 skipped, all Windows-only.
- jdivert: 334 run, 0 failures, and 14 skipped, all Windows-only. It ran on JDK 25 (Panama)
  and on JDK 8 (JNA), and the bundled library was checked to be the shim.

The first pydivert run had one failure, `test_reflect_layer`. It expects REFLECT's data to be
WinDivert's serialized filter object (`@WinDiv_…`).

- **Owner decision: REFLECT carries the filter as written.** This supersedes Step 17's native
  text.
  - The registry records the filter's `Syntax` in byte 33. That byte was free, and it reads as
    native in older entries, so the suffix stays.
  - `Reflect` gains `syntax` in its reserved byte. `ADDRESS_VERSION` is now 3, and the C ABI
    follows: `avulse_reflect.syntax`, `AVULSE_ADDRESS_VERSION` 3.
  - `Syntax` is `#[repr(u8)]` with `TryFrom<u8>`.
  - The backends register `Spec::source`.
- **`Filter::windivert_object`** (`crates/filter/src/windivert/object.rs`) ports WinDivert's
  compiler back end:
  - `WinDivertSimplifyTest` reuses `Range::decide`. WinDivert's table leaves `loopback` and
    `impostor` out, and so does the port.
  - `WinDivertFlattenExpr` processes flat `and`/`or` lists right to left, which gives
    WinDivert's labels.
  - Then `WinDivertEmitFilter`, and the serialization: base-32 digits, labels, the length as a
    byte.
  - On 230 filters at every layer, it matches WinDivert's `WinDivertHelperCompileFilter` (the
    `OBJECTS` vectors).
- **The shim** turns a REFLECT event of a WinDivert-syntax filter into that object, with its NUL,
  as WinDivert sends it. `recv_ex` takes REFLECT events one at a time.

The original plan of the step follows.


**Where.** No code of its own: the fixes the suites call for.
- Build `cargo build --release -p avulse-windivert-compat` on the host and copy the library into
  each binding's synced folder, untracked. The binding VMs are Ubuntu 24.04 (glibc 2.39); build
  in an `ubuntu:24.04` container if the host's library needs newer symbols.
- pydivert: `vagrant up linux`, then its suite as `scripts/run-tests-linux.sh` runs it, with
  `PYDIVERT_EBPFDIVERT_LIB` pointing at the library; `vagrant destroy -f linux`.
- jdivert: `vagrant up linux`, `sudo mvn clean verify -Debpfdivert.skipDownload=true
  -Debpfdivert.local=…` on JDK 25 (Panama) and JDK 8 (JNA); `vagrant destroy -f linux`.
- One VM at a time. Then avulse's own privileged suites on `default` and `legacy` again.

**Acceptance.** Both suites pass unchanged. The guide has a page on the shim
(`book/src/libraries/windivert-compat.md`) with the divergences.

### Divergences from libebpfdivert

Listed for users in `book/src/libraries/windivert-compat.md`.

- REFLECT data of a handle opened with a native filter is its text. There is no WinDivert object for it.
- `format_filter` is a canonical form of the source, not WinDivert's decompilation.
- The address loses the VLAN tag and the process name: WinDivert has no room for them.
- `compile_filter` reports avulse's messages, not WinDivert's fixed strings.
- `ring_bytes` and `set_print` are accepted and have no effect.
- On a TCP data offset longer than the packet, `calc_checksums` stays within the packet.
- At FLOW and SOCKET, `eval_filter` accepts a non-NULL packet of length 0.

## Phase 5: Windows driver

**Goal** (roadmap, Phase 5): a Rust driver that gives Windows every layer, with WFP callouts for
the WinDivert layers, an NDIS lightweight filter for ETHERNET, and the `no_std` bytecode
interpreter. Then the WinDivert-compatible `WinDivert.dll`. **Exit:** the pydivert and jdivert
Windows suites pass against it, under Driver Verifier. Attestation signing is an owner action
(EV certificate, Partner Center), tracked here but not blocking the code.

Read `docs/spikes/windows-driver.md` first. Its findings are requirements: release builds only,
the stack check with `KeExpandKernelStackAndCalloutEx`, a register file off the stack, a
preallocated buffer for split packets, retreating to the IP header at the inbound layers, and
registering when the base filtering engine starts. `windivert/sys/windivert.c` is reference
reading only, as everywhere in this project.

**Decisions for this phase** (change them here, with a reason, if the work proves them wrong):

- **Where the code lives.**
  - `drivers/windows/` is a Cargo workspace of its own, outside the main one (like the spikes),
    because it builds only with the WDK. It holds `avulse-wdk-sys` (the bindgen bindings of
    finding 1, with the hand-written macros and safe wrappers for NBL chains and classify
    output) and `avulse-driver` (`avulse.sys`, WDM, with the NDIS filter in the same binary,
    installed by an INF as in the spike).
  - The user-mode side is `crates/avulse/src/backend/windows/`, a module like Linux's.
- **One ABI crate for both sides.** `crates/abi` (`avulse-abi`) is `no_std` and
  `forbid(unsafe_code)`, in the main workspace so that host tests cover it. It holds:
  - the IOCTL codes, and the open request (layer, priority, flags, the bytecode, interface
    indexes, the filter text and its syntax for REFLECT);
  - the receive and send records;
  - the parameters and shutdown;
  - the address, which crosses the boundary as avulse's own `Address`: `Address`, `Flow`,
    `Reflect`, `Context` and `Flags` move into this crate, and `avulse` re-exports them (same
    layout, same `ADDRESS_VERSION`).
- **The kernel runs bytecode only.** User mode compiles the filter (`Filter::program`) and the
  driver verifies it at open (`bytecode::verify`). A filter the bytecode cannot express
  (`EncodeError::UserSpaceOnly`, i.e. `matches`) opens with a match-all program, and user space
  filters again and reinjects what does not match, as Linux does with an inexact matcher.
- **Evaluation.**
  - Per-processor scratch, allocated at load: the register file (`matches_in`) and a copy buffer
    for packets whose data is split across MDLs. No allocation per packet.
  - The stack check of the spike, failing open.
  - The kernel reads the whole packet. Large sends (LSO) are capped at the MTU WinDivert allows
    (`40 + 0xFFFF`).
- **Diverting** follows WinDivert's model.
  - At the WFP layers, a matched packet is copied to the handle's queue and the original is
    absorbed (`FWP_ACTION_BLOCK` with `FWPS_CLASSIFY_OUT_FLAG_ABSORB`).
  - `recv` completes pending `IOCTL_RECV` requests (the inverted-call model, a cancel-safe
    queue).
  - The queue applies the queue parameters, as Linux's `queue.rs` does.
- **Priorities and loops.** One sublayer, with a WFP filter per handle and layer whose weight
  follows the handle's priority. Each handle injects through its own injection handle, so
  `FwpsQueryPacketInjectionState0` tells its own packets (skipped) from other handles' (the
  impostor flag, and lower priorities only).
- **Lifetime.** A handle is a file object. `IRP_MJ_CLEANUP` closes it, which is the crash
  safety (no heartbeat is needed on Windows). The driver removes its WFP objects through a
  dynamic engine session. It (re)registers on `FwpmBfeStateSubscribeChanges0`.
- **Loading.** As WinDivert's DLL does: the first open installs and starts the `avulse` kernel
  service from `avulse.sys`. The file sits next to the executable, or at `AVULSE_DRIVER`, and
  the call needs Administrator. The ETHERNET layer also needs the filter bound to adapters
  (`netcfg` with the INF), so `capabilities()` reports ETHERNET only when it is.
- **Testing.**
  - Builds and tests run in the `windows` Vagrant VM: test signing, Driver Verifier, kernel
    dumps (`spikes/windows-driver/scripts/toolchain.ps1`, moved to `drivers/windows/scripts/`).
  - `crates/avulse/tests/capture_windows.rs` (`AVULSE_DRIVER=1`, Administrator) ports the Linux
    capture scenarios that apply.
  - The host checks the ABI crate, and the user-mode backend through `cargo check --target
    x86_64-pc-windows-msvc` in CI's Windows job.

### Step 22: The interpreter for the kernel (done)

**Outcome.** Spike B's and Spike C's interpreter findings are fixed in `avulse-filter`.

- **`VerifiedProgram::matches_in(&mut Registers, …)`.** The caller provides the register file
  (16 registers, about 2.7 KiB), so the interpreter's frame stays small. The driver keeps one
  per processor. `run` empties the registers it gets (16 length writes, not a 2.7 KiB clear), so
  a register a program reads before writing it is empty, as in a fresh file. `matches` uses a
  fresh file.
- **Operands are borrowed, not copied.** Copying two 170-byte registers per instruction was most
  of the cost (Spike C, finding 5). Interpreter time in ns per packet on this workstation, with
  the macOS spike's corpus; the last column reuses one register file:

  | Filter | Evaluator | Before | `matches` | `matches_in` |
  | --- | --- | --- | --- | --- |
  | `tcp.port == 443` | 37 | 198 | 108 | 75 |
  | addresses and a flag | 58 | 321 | 181 | 132 |
  | a 51-port set | 102 | 565 | 518 | 492 |
  | `tcp.payload contains "GET "` | 975 | 1133 | 1061 | 1017 |
  | IPv6 or TCP options | 86 | 419 | 211 | 168 |
  | `eth.type`, `not icmp`, `len(frame)` | 106 | 534 | 245 | 199 |
  | a WinDivert filter | 77 | 430 | 186 | 155 |

  Large sets stay slow: each test decodes every item from the constant pool. A sorted,
  fixed-width encoding of integer sets would fix it, at the cost of a `bytecode::VERSION` bump.
  Left for later.
- **Stack frames, measured in CI.** `scripts/stack-sizes.py` builds avulse-filter in release with
  `-Z emit-stack-sizes` and reads the frames with `llvm-readobj`. It fails over 1 KiB on the
  interpreter's path (`bytecode::exec`, `value`, `avulse_proto`). The largest are now
  `exec::run` and `value::load`, at 504 B each; Spike B's debug build had 6,728 B. CI's `stack`
  job runs it.
- **Tests:** `agree` compares a reused register file too, and a register left by an earlier run
  reads as empty.

### Step 23: The ABI crate, the bindings, and the driver's skeleton (done)

**Outcome.** `avulse.sys` loads and unloads under Driver Verifier in the `windows` VM.
`drivers/windows/test` passes 243 checks against it: handles, parameters, statistics, shutdown,
refused programs and requests, and WinDivert's filter vectors evaluated in the kernel.

- **`crates/abi`** (`avulse-abi`, `no_std`, `forbid(unsafe_code)`, in the `no_std` CI build)
  holds `Address`, `Flow`, `Reflect`, `Context`, `Flags`, `Param`, `Shutdown`, `Stats` and
  `Syntax`.
  - They moved from `avulse`, which re-exports them unchanged. `Param::index` is public.
  - Its layout tests moved with them.
- **`abi::ioctl`** is the driver protocol:
  - the device path, `PROTOCOL_VERSION` and the `CTL_CODE`s;
  - `OpenRequest`, `Record`s, the parameters and the statistics (all buffered but `RECV`,
    which is out-direct);
  - `EVAL`, a test IOCTL that runs a handle's filter on a packet from user mode, as the hooks
    will.

  Every decoder checks what it reads (`Malformed`), and the address is encoded field by field
  at its `repr(C)` offsets. 6 host tests.
- **`drivers/windows/driver`**: package `avulse`, outside the main workspace, built by
  `drivers/windows/scripts/build.ps1` (clippy `-D warnings`, then `cargo wdk build`).
  - The control device `\\.\Avulse` (`WdmlibIoCreateDeviceSecure`, the system and
    Administrators only).
  - Each file object is a handle: `CREATE`, `OPEN` (decode and verify), `CLEANUP` (close, also
    at process exit), `CLOSE` (free).
  - The program lives in an `Arc<Open>` that owns its bytes.
  - Per-processor scratch, each slot behind a spin lock that raises to DISPATCH_LEVEL
    (`KfRaiseIrql` is inline on x64), allocated zeroed (a 64 KiB struct literal would overflow
    the stack).
  - Registers written afresh for each evaluation, and the spike's stack check.
  - `RECV` and `SEND` answer `STATUS_NOT_IMPLEMENTED` for now.
- **Deviations.**
  - The bindings stay in the driver's `build.rs`, as in the spike, not in a `-sys` crate:
    `wdk-build` configures one package. Split them out if a second driver needs them.
  - The package is named `avulse`, because cargo-wdk derives the INF's name (`avulse.inx`) from
    it.
- **Found on the way.**
  - `IoCreateDeviceSecure` is a macro for `WdmlibIoCreateDeviceSecure`, in `wdmsec.lib`.
  - bindgen already defines `IRP`.
  - The toolchain script now adds clippy and rustfmt, and puts `avulse.sys` under Driver
    Verifier.
- **`drivers/windows/scripts/test.ps1`**:
  - loads the driver as a kernel service;
  - runs `avulse-driver-test.exe`, which leaves a handle open at exit, so stopping the driver
    checks that the handle's cleanup closed it;
  - fails on a crash dump.

The original plan of the step follows.

**Where.**
- `crates/abi`: the types above, with layout tests (`size_of`, offsets) and encode/decode
  tests of the requests. (Done.)
- Move `Address` and friends there, and re-export them from `avulse`. (Done.)
- `drivers/windows/avulse-wdk-sys`: the spike's `build.rs` and `sys.rs`, plus
  `IoCreateDevice`/symbolic link, IRP and cancel-safe queue functions, and the WFP injection
  calls.
- `drivers/windows/avulse-driver`:
  - `DriverEntry` and unload;
  - the control device `\\.\Avulse` (Administrator only, through its security descriptor);
  - `IRP_MJ_CREATE`/`CLEANUP`/`CLOSE`, and the IOCTLs open (verify the program), shutdown,
    set and get param, stats;
  - the per-processor scratch, and the evaluation with the stack check (from the spike's
    `stats.rs`);
  - no packet hook yet.

**Tests.** Host: the ABI crate. VM: the driver loads and unloads under Driver Verifier. A small
test program opens the device, opens a handle with a valid program and with a bad one (refused),
and closes it, also by exiting without closing.

### Step 24: The user-mode backend (done)

**Outcome.** `Handle::open` works on Windows at the NETWORK layers, with `SNIFF`. In the
`windows` VM, under Driver Verifier, `crates/avulse/tests/capture_windows.rs` (5 tests) and the
driver test (243) pass. No packet arrives yet: the hooks are Step 25.

- **`backend/windows/`.**
  - The service: it is installed from `avulse.sys` (`AVULSE_DRIVER`, else next to the
    executable) unless `NO_INSTALL` is set, and started. The service stays installed, on demand.
  - The device is opened with `FILE_FLAG_OVERLAPPED`. The open request carries the bytecode,
    and any non-default queue parameters follow.
  - `recv` keeps one `RECV` in flight, waits with `GetOverlappedResultEx`, and on a timeout
    cancels it (`CancelIoEx`) and waits for it to end. A zero timeout reports
    `ERROR_IO_INCOMPLETE`.
  - The records the driver returns beyond the first wait in a queue, which `recv_ready` serves.
  - `ERROR_NO_DATA` is `Error::Shutdown`.
  - Interfaces are numbers or `if_nametoindex` names.
  - Filters that need user space (`matches`) are `Unsupported` until injection (Step 26).
  - `capabilities()` reports NETWORK and NETWORK_FORWARD as open-only, so diverting and
    dropping are `Unsupported` until the hooks; `send` is too.
- **The driver's receive side** (`rx.rs`).
  - A `RECV` takes the queued records that fit (dropping a first one that does not, as WinDivert
    does), or waits with a cancel routine.
  - `IoSetCancelRoutine`, `IoMarkIrpPending` and `MmGetSystemAddressForMdlSafe` are macros or
    inlines, written by hand.
  - Shutdown completes the waiting requests with `STATUS_PIPE_EMPTY` once the queue is empty.
    Cleanup cancels them.
  - `rx::push`, with the queue limits, is ready for the hooks.
- **Deviation:** no readiness handle yet (`Opened::as_fd` stays Unix-only). The overlapped
  `RECV` would give one; it comes when something needs it, with the C ABI's counterpart of
  `avulse_fd`.
- **Tests.** `capture_windows.rs` (with `AVULSE_DRIVER`, as Administrator) covers:
  - timeouts, including zero;
  - shutdown waking a receiver in another thread;
  - parameters and counters;
  - what is refused (diverting, sending);
  - `NO_INSTALL` with the service installed;
  - interfaces;
  - 200 handles opened and closed.

  `drivers/windows/scripts/test.ps1` runs it after the driver test.

The original plan of the step follows.

**Where.** `crates/avulse/src/backend/windows/`:
- installing and starting the service, and opening the device;
- `Backend`/`Opened`, with overlapped `DeviceIoControl`;
- `recv` with a timeout (a pending `IOCTL_RECV`, cancelled with `CancelIoEx`);
- shutdown, params, stats and close.

`Opened::as_fd` is Unix-only, so add a Windows counterpart (`as_handle`, an event that is
signalled when `recv` would not block), and expose it as `Handle::as_handle` and in the C ABI
(`avulse_fd` returns -1 there; add `avulse_handle_event`). CI's Windows job checks it compiles.

**Acceptance.** In the VM, `Handle::open` at NETWORK loads the driver on first use, a receive
times out, and close and process exit release the handle.

### Step 25: NETWORK and NETWORK_FORWARD (done, without the FRAGMENTS flag and QUEUE_TIME)

**Outcome.** Handles divert, sniff and drop packets on Windows. In the `windows` VM, under Driver
Verifier, `capture_windows.rs` (9 tests) and the driver test (243) pass.

- **`drivers/windows/driver/src/wfp.rs`.**
  - At load: six callouts (inbound and outbound IP packets, v4 and v6, and the forward layers)
    with `FwpsCalloutRegister3`. A dynamic engine session holds the sublayer and the callouts;
    closing it at unload removes everything.
  - Per handle, at open: one WFP filter per layer of its own (`FWP_ACTION_CALLOUT_UNKNOWN`), with
    weight `priority + 30001` (higher runs first in the sublayer). The filter's `rawContext` is
    the handle's id in a table of open handles. Cleanup deletes the filters and the table entry.
  - Classify:
    - finds the handle by id (and holds a reference, so a classify racing a close is safe);
    - retreats to the IP header inbound;
    - reads the interface indexes and the loopback flag from the incoming values (their
      indexes differ between layers, and are taken from the generated bindings);
    - skips inbound loopback, so loopback is seen once, outbound, as in WinDivert;
    - evaluates (`eval::evaluate_nb`: in place, or through the processor's copy buffer), and
      copies the packet only when it matched and is kept.
  - A match: sniff (copy, `CONTINUE`), drop (`BLOCK`), or divert (copy, then `BLOCK` with
    `FWPS_CLASSIFY_OUT_FLAG_ABSORB`).
  - `QUEUE_LENGTH` and `QUEUE_SIZE` apply, and the counters follow.
  - Timestamps are `KeQueryPerformanceCounter` in nanoseconds.
- **The receive queue is shared** (`Arc`) between the file and the open handle, so the hooks
  never touch a freed file.
- **Found on the way.**
  - The layer GUIDs come from the WDK's `fwpmk.h`. `FWPM_LAYER_IPFORWARD_V6` is
    `7b964818-19c7-…`.
  - `FWPM_FILTER0`'s `rawContext` is in an anonymous union, and `FWP_UINT64` is in the
    `FWP_DATA_TYPE_` module of the bindings.
  - **Driver Verifier caught a leak at unload (bugcheck 0xC4/0x62):** an emptied `BTreeMap`
    keeps its root node allocated, so the static handle table is freed explicitly. Its crash
    dump read with `kd` gave the cause. After the reboot, `C:\avulse` was not mounted again
    until `vagrant reload`.
- **Left.**
  - The `FRAGMENTS` flag (every fragment is evaluated for now).
  - `QUEUE_TIME`.
  - Packets in NBL chains past the first NET_BUFFER (the IP layers indicate one per NBL in
    practice).
  - The impostor flag, which needs injection (Step 26).
- **Tests** (`capture_windows.rs`): loopback UDP over IPv4 and IPv6 is sniffed once, outbound,
  with its flags, and still delivered. A diverted datagram is held; a dropped one is gone; both
  come back once the handles close. A filter that misses sees nothing; two priorities both see a
  sniffed packet; shutdown delivers what is queued.

The original plan of the step follows.

**Where.** `avulse-driver`'s `wfp.rs`:
- callouts at `INBOUND`/`OUTBOUND_IPPACKET_V4`/`V6` and `IPFORWARD_V4`/`V6`;
- per handle and layer, WFP filters at its weight;
- classify:
  - retreat to the IP header inbound;
  - read the packet (in place or into the scratch copy);
  - fill `Meta` (direction, loopback, interface indexes, impostor, fragment);
  - evaluate;
  - divert (queue a copy, absorb the original), sniff (queue a copy, permit) or drop;
- the queue with the parameters, and `IOCTL_RECV` completion;
- the `FRAGMENTS` flag.

**Tests.** `capture_windows.rs`: divert, sniff and drop pings and loopback UDP, filters that
match and miss, priorities between two handles, queue limits, shutdown delivering what is
queued.

### Step 26: Injection (done; forward injection untested)

**Outcome.** Windows handles send packets: diverted packets go back unchanged or modified, and
built packets are injected. In the `windows` VM, under Driver Verifier, `capture_windows.rs`
(12 tests) and the driver test (243) pass.

- **`drivers/windows/driver/src/inject.rs`.**
  - One injection handle per address family. With `AF_UNSPEC` and forward injection,
    `FwpsInjectionHandleCreate0` fails with `0x80320035`.
  - A NET_BUFFER_LIST pool from an NDIS generic object.
  - `SEND` copies each packet into nonpaged memory with an MDL and injects it:
    - outbound with `FwpsInjectNetworkSendAsync0`;
    - inbound with `FwpsInjectNetworkReceiveAsync0`, on the address's interfaces;
    - forwarded with `FwpsInjectForwardAsync0`.

    The completion frees it. `SEND` became a buffered IOCTL, and returns how many records it
    sent; only a first failure is an error.
- **Loops and impostors.**
  - The injection context is the sender's priority. Classify queries it
    (`FwpsQueryPacketInjectionState0`):
    - handles of the same or a higher priority than the sender pass the packet by;
    - lower priorities see it with `impostor` set.

    This is Linux's mark rule.
  - `SEND_ONLY` handles get no WFP filter.
- **User mode** applies WinDivert's rules before `SEND`: an impostor loses a hop of TTL
  (`decrement_ttl` moved to `backend/mod.rs`, shared with Linux), and the checksums whose flags
  are clear are computed. `capabilities()` now reports inject and modify at the NETWORK layers.
- **Left.**
  - Filters that need user space (`matches`) are still `Unsupported`. They need the kernel to
    divert everything and user space to reinject what does not match, as Linux does.
  - Forward injection is written but untested (no routed setup in the VM yet).
- **Tests** (`capture_windows.rs`):
  - a diverted datagram sent back unchanged and modified arrives, and its handle does not see it
    again;
  - a built UDP packet from a `SEND_ONLY` handle arrives;
  - a high-priority handle diverts and reinjects, and the lower one sees the packet as an
    impostor;
  - a `RECV_ONLY` handle cannot send.

The original plan of the step follows.

**Where.**
- `IOCTL_SEND`: `FwpsInjectNetworkSendAsync0` (outbound), `ReceiveAsync0` (inbound, with the
  interface indexes) and `ForwardAsync0`.
- Each handle's injection handle, and the injection state for loops and `impostor` (an impostor
  loses a hop of TTL, as on Linux).
- WinDivert's checksum rules: compute the checksums whose address flag is clear.
- Batches.

**Tests.** Reinject diverted pings unchanged and modified, inject built packets both ways,
loopback, two handles at different priorities, and no loop.

### Step 27: The ETHERNET layer (done; offloaded VLAN tags untested)

**Outcome.** ETHERNET handles on Windows capture every frame of their adapters, and divert,
sniff, drop, reinject and inject frames both ways. In the `windows` VM, under Driver Verifier,
the driver test (243) and `capture_windows.rs` (20 tests) pass in two phases: first with the
driver as a plain service, where ETHERNET is refused, then installed with `netcfg` as a
lightweight filter, which also serves the WFP layers. Both phases passed twice in a row, with
`netcfg` installing and removing the filter each time and no crash dump.

- **`drivers/windows/driver/src/lwf.rs`.**
  - Registration happens in `DriverEntry`, after WFP. It fails without the INF install, which
    is not fatal: ETHERNET opens then get `STATUS_NOT_SUPPORTED` (`Error::Unsupported`), and
    the other layers work.
  - One module per adapter, with `if_idx = BaseMiniportIfIndex`, which is the index WFP and IP
    Helper use. Pause waits for the module's own sends and indications to come back.
  - A priority-sorted snapshot of the ETHERNET handles (`Arc<[Arc<Open>]>`, cloned per chain)
    runs on every NET_BUFFER (`process`). Handles of equal priority run in open order.
  - An NBL whose frames all pass goes on untouched. Otherwise it is completed (send) or
    returned (receive), and the frames that passed go on as copies.
  - With `NDIS_RECEIVE_FLAGS_RESOURCES`, the chain is never relinked: once a frame is taken,
    the passing frames go up as copies in an indication of the filter's own.
  - The filter's own NBLs come from a pool of its own, because WFP-injected NBLs reach the
    filter too. The completion handlers recognise them by `NdisPoolHandle` and free them,
    finding the copy through the MDL (`MappedSystemVa`, `ByteCount`).
- **Impostors.** The filter never sees its own sends and indications. `SEND` therefore runs an
  injected frame through the handles below the sender's priority first, as impostors, and they
  may take it. This is Linux's mark rule inside the module. Impostors are per layer: a
  NETWORK injection is not an impostor at ETHERNET, and the other way round.
- **Out-of-band info.** The `NetBufferListInfo` indexes are hard-coded in `sys.rs` (checksum
  0, LSO 2, 802.1Q 4).
  - An offloaded 802.1Q tag is put back into the frame the handles see (through the
    processor's copy buffer, now 4 bytes longer) and into `vlan`/`vlan_tci`.
  - `avulse_abi::ioctl::EthernetContext` (marker, flags, `if_idx`, LSO MSS) in the address's
    context takes the tag out of the frame again on reinjection to the same adapter.
  - Large sends (LSOv1 and v2) are captured whole. On reinjection they get their LSO request
    back, and `checksum::tcp_large_send` (new in `avulse-proto`) writes the partial TCP
    checksum.
  - An absorbed LSOv1 send reports its TCP payload in the completion.
  - Copies of passing frames keep the checksum, LSO and tag requests.
- **User mode.**
  - `capabilities()` lists ETHERNET when the filter's NetCfg key exists
    (`HKLM\SYSTEM\CurrentControlSet\Control\Network\{4D36E974-…}\{3C1D6E52-8B7A-4F19-A2D4-5E9B0C71F846}`,
    confirmed in the VM).
  - `recv` sets the checksum flags with `checksum::verify`, as Linux does, so a modified
    packet needs its flag cleared (the `reinject` test does that now).
  - `send` takes frames at ETHERNET, with `if_idx` required. `ip_offset` moved to
    `backend/mod.rs`, shared with Linux.
  - `Handle::open` never runs `netcfg`: binding a filter restarts every adapter.
- **Also:** the WFP hooks now honour the handle's interfaces (`Open::captures_on`), which they
  ignored before. `Open::deliver` is shared by both hooks.
- **Deviation:** there is no MTU check on injection. NDIS does not pass the MTU at attach
  (`NDIS_FILTER_ATTACH_PARAMETERS` has no `MtuSize`), and querying it takes an OID request, so
  the card drops an oversized frame.
- **Tests** (`capture_windows.rs`, `AVULSE_ETHERNET=1`; on the NAT adapter, with narrow
  filters, as WinRM shares it):
  - ETHERNET is refused without the filter;
  - pings to the gateway are sniffed both ways, and not on another interface;
  - outbound echo requests are dropped;
  - ARP is diverted and reinjected both ways, and the gateway still resolves;
  - a built ARP request goes out (a lower handle sees it as an impostor, then the gateway's
    reply);
  - an ARP request injected inbound is answered by Windows;
  - an in-band 802.1Q tag is seen with `vlan.id`/`vlan.priority`;
  - `lso_reinject` (`AVULSE_TCP_PEER`, `drivers/windows/scripts/tcp-sink.py` on the host): a
    4 MiB upload diverted and reinjected frame by frame arrives whole, with frames of up to
    46,774 bytes sent back as large sends.
- **Left.**
  - Offloaded VLAN tags: the VM's adapter does not offload them, so restoring and stripping the
    tag ran only on frames without one.
  - NBLs that mix taken and passing frames: tcpip did not send any in the tests.

The original plan of the step follows.

**Where.** `avulse-driver`'s `lwf.rs`:
- per handle, the frames of its adapters, from the send and receive NBL hooks;
- divert (complete the original NBL and queue a copy), sniff, drop;
- injection by allocating NBLs from a pool, sent with `NdisFSendNetBufferLists` or indicated
  with `NdisFIndicateReceiveNetBufferLists`, marked so the filter skips its own;
- VLAN tags from the NBL's 802.1Q info, the counterpart of Linux's offloaded tags.

The INF and its install (`netcfg`) are part of the backend's setup.

**Tests.** ARP and VLAN frames, divert and reinject, inject a frame both ways.

### Step 28: FLOW, SOCKET and REFLECT (done)

**Outcome.** Every layer opens on Windows. In the `windows` VM, under Driver Verifier, the
driver test (243) and `capture_windows.rs` (27 tests) pass, with the driver both as a plain
service and installed with `netcfg`. Three runs in a row, no crash dump.

- **`drivers/windows/driver/src/ale.rs`.**
  - Twelve callouts at the ALE layers, IPv4 and IPv6 (GUIDs checked against `fwpmk.h`). The
    field indexes come from the bindings' `FWPS_FIELDS_ALE_*_V4_` enums; the IPv6 layers
    number theirs the same way.
  - Event to layer: FLOW ESTABLISHED at `ALE_FLOW_ESTABLISHED`; BIND at
    `ALE_RESOURCE_ASSIGNMENT`; CONNECT at `ALE_AUTH_CONNECT`; LISTEN at `ALE_AUTH_LISTEN`;
    ACCEPT at `ALE_AUTH_RECV_ACCEPT`; CLOSE at `ALE_ENDPOINT_CLOSURE`.
  - FLOW handles and CLOSE get inspection filters. Reauthorizations
    (`FWP_CONDITION_FLAG_IS_REAUTHORIZE`) are skipped.
  - The address carries the endpoints (IPv4-mapped), ports, protocol (TCP at LISTEN), PID,
    image name (the last component of `processPath`), endpoint and parent endpoint handles,
    and `loopback` (the flag, or either address).
  - `outbound` is the flow's direction at FLOW, and CONNECT only at SOCKET, as on Linux.
  - The handle's bytecode runs in the kernel on an empty packet, with `random*` hashing the
    endpoint as Linux does. Fail open: an event that cannot be evaluated is not reported.
  - A SOCKET handle without SNIFF blocks what it matches (`FWP_ACTION_BLOCK`; the application
    gets `WSAEACCES`, i.e. `PermissionDenied`) and reports it unsniffed. With DROP, it
    reports nothing. Windows refuses listens and accepts too: every filter opens without
    SNIFF, unlike Linux.
- **FLOW DELETED.** Each flow a FLOW callout classifies gets a context
  (`FwpsFlowAssociateContext0`, the flow handle, kept in `FLOWS` with the ESTABLISHED
  address; at most 16,384). The callout's `flowDeleteFn` then reports DELETED to every FLOW
  handle whose filter matches it.
  - The contexts are removed when the last FLOW handle closes, and at unload, before the
    callouts are unregistered.
  - TCP flows on loopback were reported deleted within 2 s of the close: no TIME_WAIT delay.
- **REFLECT** (`reflect.rs`): a table of every open handle, oldest first, with the opener's
  PID (`PsGetCurrentProcessId` at OPEN) and the open time.
  - A REFLECT handle hears of every handle open (OPEN, itself included), then of each that
    opens or closes. A process's death closes its handles, so its CLOSE is immediate (no
    polling, unlike Linux's registry).
  - The events go out under the table's lock, in the handles' order.
- **`wfp.rs`.** One table of callouts (`callout(i)`: the packet layers, then `ale::HOOKS`),
  and `handle`/`handles_at` lookups. Filters of FLOW and SOCKET handles are added like the
  packet layers', with the same weights.
- **User mode.** `capabilities()` reports FLOW (open), SOCKET (open, divert, drop) and REFLECT
  (open). Events skip the checksum flags.
- **Differences from Linux.**
  - `process.name` is the image's file name (`curl.exe`), cut to the address's 32 bytes, where
    Linux has the task's `comm`.
  - A listening socket's close is not reported: `ALE_ENDPOINT_CLOSURE` covers connected
    sockets, so a loopback connection gives 2 CLOSE events (client and accepted socket) where
    Linux gives 3. `ALE_RESOURCE_RELEASE` would add it, at the cost of a duplicate for the
    client.
  - FLOW handles get DELETED only for flows established while one was open.
- **Tests** (`capture_windows.rs`):
  - `flow_loopback`: both ends over IPv4 and IPv6, established and deleted, two endpoints;
  - `flow_udp`: established once over three datagrams, deleted when the socket closes;
  - `socket_events`: one bind, listen, connect and accept, two closes, with directions and
    ports;
  - `socket_refuses_calls`: connect, bind, listen and accept refused over both families,
    others through, reported unsniffed; DROP refuses silently;
  - `process_names`: the FLOW event's name is the test binary's, cut to 32 bytes, and a
    connect is refused by name;
  - `reflect_layer`: itself at first, a child process's FLOW handle opening (with its flags,
    filter and syntax), and CLOSE when the child is killed.

The original plan of the step follows.

**Where.**
- FLOW: `ALE_FLOW_ESTABLISHED_V4`/`V6` and the flow-delete callback (`FwpsFlowAssociateContext0`).
- SOCKET: `ALE_RESOURCE_ASSIGNMENT` (bind), `ALE_AUTH_CONNECT` (connect), `ALE_AUTH_LISTEN`,
  `ALE_AUTH_RECV_ACCEPT` and the endpoint closure. Windows can refuse all four, unlike Linux.
- `process.name` from the process image.
- REFLECT from the driver's handle table: open and close events with the filter text.
- The FLOW/SOCKET fields of `Meta`, as Linux fills them.

**Tests.** The Linux event scenarios: connect, bind and accept, refusing by filter and by process
name, flows of TCP and UDP, and REFLECT of another process's handle.

### Step 29: `WinDivert.dll` and the binding suites (Phase 5 exit)

**Where.** `crates/windivert-compat` on Windows:
- the `WinDivert*` exports (Open, Recv/RecvEx, Send/SendEx, Shutdown, Close, Set/GetParam and
  the helpers) over the same core as the `ebpfdivert_*` exports, with `GetLastError` codes;
- built as `WinDivert.dll`, next to `avulse.sys`.

**Tests.** pydivert's and jdivert's Windows suites in their own `windows` VMs, with the DLL in
place of WinDivert's. Divergences are listed in the guide.

### Step 30: Hardening and distribution

**Where.**
- Driver Verifier (standard flags and special pool) on every suite, and HVCI compatibility (the
  Device Guard readiness tool).
- A CI job that builds the driver, if the WDK installs on a GitHub Windows runner in reasonable
  time; else the VM build stays the check.
- arm64.
- OSSign for the user-mode binaries.
- Owner actions: the EV certificate, Partner Center, attestation signing.

## Release v0.0.1 (after Phases 5 and 6)

The first release, once Windows and macOS have backends. The plan below was written for a
Linux-only release; extend it with the Windows and macOS artifacts (the signed driver, the
system extension) when Phases 5 and 6 are expanded.

**Where.** `.github/workflows/release.yml` and the crates' metadata.
- A crates.io job (`rust-lang/crates-io-auth-action`, environment `crates-io`, `id-token:
  write`). Publish in dependency order: `avulse-proto`, `avulse-filter`, `avulse-abi`, `avulse-ebpf`,
  `avulse`, then `avulse-cli`. (`avulse-abi` is new in Phase 5: claim the name and give it a
  trusted publisher.) `avulse-capi` ships in the tarballs only (owner decision), and keeps its
  0.0.0 placeholder on crates.io, as does `avulse-windivert-compat`.
- **Owner action:** a trusted publisher for every crate except `avulse`, which already has one.
- `avulse-ebpf` ships `tc.bpf.o` and `events.bpf.o` prebuilt in the package. `build.rs` uses
  them when clang is missing or `AVULSE_PREBUILT_BPF` is set, so users need no clang. CI checks
  that the shipped objects match a fresh build.
- Tarballs `avulse-v0.0.1-linux-{amd64,arm64}.tar.gz`, with `libavulse.so`, `avulse.h` and the
  `avulse` CLI. They are signed with cosign (keyless) and come with an SBOM.
  - Build them in `quay.io/pypa/manylinux_2_28_{x86_64,aarch64}` (moved here from Step 18), with
    Rust and clang installed in the container. aya is pure Rust, so glibc 2.28 is the only
    requirement.
  - Run `avulse-c-test` against the built library.
- Version 0.0.1 across the workspace, a CHANGELOG, and the tag `v0.0.1` (pre-release tags
  `v0.0.1-rc.N` build and dry-run without publishing). The Python placeholder
  job stays as it is.

**Acceptance.** A dry run (`cargo publish --dry-run` for each crate, and the workflow on a
pre-release tag) passes, then the v0.0.1 tag publishes. The guide and README say what 0.0.1 covers.

## Checklist

- [x] Phase 0.1: repo, workspace, CI, names claimed (GitHub, crates.io, PyPI), trusted publishers
- [x] Phase 1: `avulse-proto`
- [x] Phase 1: filter front half (parser, checker, IR, evaluator, CLI)
- [x] Step 1: tshark validation
- [x] Step 1b: Wireshark syntax coverage
- [x] Docs: README, guide, website with playground, Rust and Python API docs
- [x] Step 2: bytecode + verifier + interpreter
- [x] Step 3: WinDivert front-end + 241 vectors + `filter convert`
- [x] Step 4: TCP options, fuzz targets
- [x] Step 5: spikes A (go) and B (go, pure Rust); C partly done on GitHub's runners (the
  provider at work is left)
- [x] Step 6: public API and address (`crates/avulse`)
- [x] Step 7: kernel side of capture (config, metadata facts, ring buffer, verdicts)
- [x] Step 8: Linux backend: open, attach, registry, heartbeat, receive
- [x] Step 9: injection
- [x] Step 10: matcher coverage and superset fallback
- [x] Step 11: ETHERNET layer (devices without an Ethernet header left for later)
- [x] Step 12: privileged suite on both VMs (Phase 2 exit)
- [x] Step 13: devices without an Ethernet header (tun, WireGuard, PPP, IP tunnels) at the NETWORK
  layers
- [x] Step 14: event programs and records
- [x] Step 15: FLOW layer
- [x] Step 16: SOCKET layer, with blocking
- [x] Step 17: `process.name` and REFLECT
- [x] Step 18: API v0.1 and the C ABI (`libavulse.so`)
- [x] Step 19: compat shim core (address, errno, helpers)
- [x] Step 20: compat shim handle exports, `Handle::stats`
- [x] Step 21: pydivert and jdivert suites against the shim (Phase 4 exit)
- [x] Step 22: the interpreter for the kernel (`matches_in`, borrowed operands, frame sizes in CI)
- [x] Step 23: ABI crate (`avulse-abi`), driver skeleton (`avulse.sys`, device, handles, `EVAL`)
- [x] Step 24: user-mode Windows backend (service, device, overlapped `RECV`, timeouts, shutdown)
- [x] Step 25: NETWORK and NETWORK_FORWARD on Windows (divert, sniff, drop; WFP callouts)
- [x] Step 26: injection on Windows (send, reinject, impostors)
- [x] Step 27: ETHERNET on Windows (NDIS LWF; VLAN and LSO restored on reinjection)
- [x] Step 28: FLOW, SOCKET and REFLECT on Windows (ALE callouts, flow contexts, the handle table)
- [ ] Step 29: `WinDivert.dll` and the binding suites on Windows (Phase 5 exit)
- [ ] Step 30: hardening and distribution (Driver Verifier, HVCI, CI build, signing)
- [ ] Phase 6: macOS system extension
- [ ] Release v0.0.1 (crates.io, tarballs; after Phases 5 and 6)
- [ ] Owner: EV cert + Partner Center, Apple Developer ID + NE entitlement
