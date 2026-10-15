# Avulse implementation plan

This is the hand-off document between sessions. `docs/roadmap.md` holds the design: why Rust, the layer
and backend matrix, the filter-language decisions, and the phases. This file holds where the
implementation stands and the next steps, specified well enough to start without re-deriving
anything. When a step lands, tick it here, update **Status**, and commit this file with the code.

## Status (2026-10-15, Steps 1 to 6 and Spikes A and B done, Spike C deferred; next: Step 7)

| Area | State |
| --- | --- |
| `crates/proto` (`avulse-proto`) | Done for Phase 1. Zero-copy `no_std` parsing: Ethernet, 2 VLAN tags, ARP, IPv4, IPv6 (8 extension headers, fragments), TCP (options: `Tcp::option_iter`, `option`), UDP, ICMP, ICMPv6. Checksum recalculation. 13 tests, including all truncations and random input. |
| `crates/filter` (`avulse-filter`) | Front half of Phase 1 done: lexer, parser, `fmt`, checker, typed IR, `simplify`, allocation-free evaluator. Wireshark 4.6 syntax covered: quantifiers, arithmetic, layers, value labels, `@field`, `&` on bytes, multi-range slices, `upper`/`lower`, and `matches` (optional `regex` feature). Semantics validated against tshark 4.6/4.7 (`src/tests/tshark.rs`, including every field's byte span against PDML). Bytecode, verifier and `no_std` interpreter (`bytecode/`), sharing the value operations in `value.rs` with the IR evaluator. WinDivert 2.2 front-end (`windivert/`), passing WinDivert's 241 vectors through the IR, the bytecode and the native round trip; `ir::Test::native()` prints native syntax. Nesting is bounded (native 64 levels, 4 macro levels; WinDivert 341 parentheses). TCP options: `tcp.options`, `.mss`, `.mss_val`, `.wscale`, `.wscale.shift`, `.wscale.multiplier`, `.sack_perm`, `.timestamp`, `.tsval`, `.tsecr`. 76 unit tests, 9 tshark tests (opt-in) and doctests. |
| `crates/cli` (`avulse`) | `avulse filter check \| fmt \| explain [--bytecode] \| eval --hex … \| convert [--layer …] \| fields [--format markdown]`. Exit codes: 0 match, 1 no match, 2 error. |
| `fuzz/` | cargo-fuzz targets `bytecode` (verifier and interpreter on arbitrary programs), `filter` (parser, `fmt` round trip, checker, evaluator, bytecode agreement) and `windivert` (front-end, bytecode and native agreement). Outside the workspace. |
| `crates/wasm` (`avulse-wasm`) | The filter engine for the website's playground (wasm-bindgen, `publish = false`). |
| Docs and website | README (front page), guide (`book/`, mdBook), `site/` with the playground, rustdoc and pdoc, built by `scripts/build-site.sh` and deployed by `pages.yml` to <https://ffalcinelli.github.io/avulse/>. Every public item is documented (`missing_docs`). |
| `crates/ebpf` (`avulse-ebpf`) | Spike A (go, `docs/spikes/ebpf-codegen.md`): the static TC program `bpf/tc.bpf.c` (parser → per-CPU facts → tail call), `codegen` (IR subset → eBPF matcher; anything else is `Error::Unsupported`), `insn` (assembler, forward labels, dead-code removal), `loader` (Linux: `aya` plus raw `bpf()` for the matcher and `BPF_PROG_TEST_RUN`). `tests/emu.rs` runs the matchers in an eBPF interpreter against the evaluator; `tests/kernel.rs` (`AVULSE_BPF=1`, root, in the VMs) checks facts and verdicts in the kernel. Needs clang on Linux. |
| `spikes/windows-driver` | Spike B (go, pure Rust, `docs/spikes/windows-driver.md`): a WDM driver with WFP callouts (IPv4 packet layers) and an NDIS LWF running the bytecode interpreter, built with `cargo wdk` in the `windows` VM. Outside the workspace (`exclude`), not built by CI. |
| `crates/avulse` (`avulse`) | Step 6: the handle API with no backend yet. `Handle`/`OpenOptions` (WinDivert's argument rules, native or WinDivert syntax), `Flags`, `Param`, `Shutdown`, `Error`, `capabilities()`, and the 184-byte versioned `#[repr(C)]` `Address` with its opaque reinjection `Context`. The crate-private `Backend`/`Opened` traits; the backends will be modules of this crate (owner decision: one crate to publish). 18 tests on a fake backend. |
| `crates/{capi,windivert-compat}` | Empty stubs (one doc line each, `publish = false`). |
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
  publisher; only `avulse` has one so far.
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
    nothing to provision. Build the test binary on the host (`cargo test -p avulse-ebpf --test kernel
    --no-run`) and run it in the VM: `vagrant ssh default -c "sudo AVULSE_BPF=1
    /vagrant/target/debug/deps/kernel-<hash> --nocapture --test-threads=1"`. On 22.04 it prints a
    harmless warning about the weak `GLIBC_2.39` requirement.
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
  layer `Meta::layer`/`priority` with the reflected handle's.
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
- [ ] **Spike C: macOS.** Deferred: no Mac is available (owner decision, 2026-10-15). Check
  `NEFilterPacketProvider` frame level, throughput and delay semantics, and `/dev/bpf`
  reinjection. Do it before Phase 6.

### After that

Phase 2 is expanded below. Then follow the roadmap: Phase 3 (events, API v0.1, crates.io release
job) → 4 (compat shim + pydivert/jdivert suites) → 5 (Windows driver; read the Spike B note's
requirements first) → 6 (macOS, after Spike C) → 7 (bindings, 1.0). Before starting each phase,
expand it into steps in this file, in the same format as above.

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

### Step 7: The kernel side of capture

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

### Step 8: `backend-linux`: open, attach, receive

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

### Step 9: Injection

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

### Step 10: Matcher coverage and a tight superset

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

### Step 11: The ETHERNET layer

**Where.** `crates/ebpf/bpf/tc.bpf.c`, `crates/avulse/src/backend/linux/`.

- **Capture:** every frame on the selected interfaces, non-IP included (ARP, LLDP, VLAN-tagged).
  An offloaded VLAN tag is put back into the captured frame, so the bytes match what the filter
  saw.
- **Injection:**
  - Outbound frames go out through `AF_PACKET` on the interface, tags included. Check that the
    kernel accepts in-band tags, or use `PACKET_AUXDATA`-style metadata.
  - Inbound frames need a design: the `lo` redirect carries IP only, and a non-IP frame on `lo`
    is not delivered. Candidates are a `bpf_redirect(…, BPF_F_INGRESS)` from an egress hook on
    the target interface, or a tap device. Try them in a VM, and write the decision here.
- **Loop prevention and priorities** as for the NETWORK layers. ETHERNET and NETWORK handles on
  the same interface are ordered by TC priority like any two handles.

**Tests:** ARP request/reply diverted and reinjected (a ping across a veth still works), VLAN
capture with offload on and off (`ethtool -K … rxvlan off`), QinQ, modifying a frame's source
MAC, and LLDP sniffing.

**Acceptance:** those pass on both VMs. The guide documents the layer: what the filter sees
(`Link::Ethernet`), and how tags are restored.

### Step 12: The privileged suite (Phase 2 exit)

**Where.** `crates/avulse/tests/` (root only, `AVULSE_PRIV=1`, network namespaces and veth
pairs, like `../ebpfdivert/tests/test_integration.c`), run in the VMs like `tests/kernel.rs`.

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
- [x] Step 5: spikes A (go) and B (go, pure Rust); C deferred until a Mac is available
- [x] Step 6: public API and address (`crates/avulse`)
- [ ] Step 7: kernel side of capture (config, metadata facts, ring buffer, verdicts)
- [ ] Step 8: Linux backend: open, attach, registry, heartbeat, receive
- [ ] Step 9: injection
- [ ] Step 10: matcher coverage and superset fallback
- [ ] Step 11: ETHERNET layer
- [ ] Step 12: privileged suite on both VMs (Phase 2 exit)
- [ ] Owner: EV cert + Partner Center, Apple Developer ID + NE entitlement
