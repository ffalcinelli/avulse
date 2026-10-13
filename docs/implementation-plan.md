# Avulse implementation plan

This is the hand-off document between sessions. `docs/roadmap.md` holds the design: why Rust, the layer
and backend matrix, the filter-language decisions, and the phases. This file holds where the
implementation stands and the next steps, specified well enough to start without re-deriving
anything. When a step lands, tick it here, update **Status**, and commit this file with the code.

## Status (2026-10-13, Steps 1 and 1b done)

| Area | State |
| --- | --- |
| `crates/proto` (`avulse-proto`) | Done for Phase 1. Zero-copy `no_std` parsing: Ethernet, 2 VLAN tags, ARP, IPv4, IPv6 (8 extension headers, fragments), TCP, UDP, ICMP, ICMPv6. Checksum recalculation. 12 tests, including all truncations and random input. |
| `crates/filter` (`avulse-filter`) | Front half of Phase 1 done: lexer, parser, `fmt`, checker, typed IR, `simplify`, allocation-free evaluator. Wireshark 4.6 syntax covered: quantifiers, arithmetic, layers, value labels, `@field`, `&` on bytes, multi-range slices, `upper`/`lower`, and `matches` (optional `regex` feature). Semantics validated against tshark 4.6/4.7 (`src/tests/tshark.rs`, including every field's byte span against PDML). 55 unit tests, 7 tshark tests (opt-in) and a doctest. No bytecode and no WinDivert front-end yet. |
| `crates/cli` (`avulse`) | `avulse filter check \| fmt \| explain \| eval --hex … \| fields`. Exit codes: 0 match, 1 no match, 2 error. |
| `crates/{ebpf,backend-linux,avulse,capi,windivert-compat}` | Empty stubs (one doc line each, `publish = false`). |
| `bindings/python` | 0.0.0 placeholder, published to PyPI to reserve the name. |
| CI (`.github/workflows/ci.yml`) | fmt, clippy, tests on ubuntu/windows/macos, tshark comparison (tshark from `ppa:wireshark-dev/stable`), no_std build (`thumbv7em-none-eabihf`). |
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
- **Formatting:** rustfmt defaults (100 columns). Run `cargo fmt` twice if `--check` still complains;
  some long chains need a second pass.

## Done-criteria for every change

1. `cargo fmt --check`, `cargo clippy --workspace --all-targets` (no warnings) and
   `cargo test --workspace` all pass.
2. The no_std build passes for `avulse-proto` and `avulse-filter`.
3. `proto` and `filter` stay `#![no_std]`, `#![forbid(unsafe_code)]`, with no panicking paths in
   evaluation code (no `unwrap`, no unchecked indexing on packet data).
4. User-facing behaviour changes are reflected in `README.md`, `docs/roadmap.md` and `CLAUDE.md`.
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

### Step 2: Bytecode, verifier and `no_std` interpreter

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

### Step 3: WinDivert front-end and conformance vectors

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

### Step 4: Language gaps (small, independent)

(`matches` and `&` on bytes moved to Step 1b and are done.)

- **TCP options:** `tcp.options.mss_val`, `tcp.options.wscale.shift`, `tcp.options.sack_perm`,
  `tcp.option_kind`. Parse options in `proto` (bounded loop).
- `cargo-fuzz` targets for the parser/checker (arbitrary UTF-8 must never panic) and for `eval` on
  arbitrary packets.

### Step 5: Phase 0 spikes (need VMs or hardware; see roadmap, Phase 0)

- **Spike A: eBPF codegen.** In `crates/ebpf`, emit eBPF for a tiny IR subset (`tcp.dstport == N`)
  at runtime with a hand-rolled instruction encoder.
  1. A static C TC program (`crates/ebpf/bpf/tc.bpf.c`, clsact cls_bpf, reuse
     `../ebpfdivert/src/ebpfdivert.bpf.c` parsing) fills a per-CPU "facts" map and calls
     `bpf_tail_call` into a `PROG_ARRAY` slot.
  2. The generated matcher reads the facts, plus `bpf_skb_load_bytes` for slices, and returns the
     verdict.
  3. Load everything with `aya`.
  4. Test with `BPF_PROG_TEST_RUN` in the Vagrant `default` (6.8) and `legacy` (5.15) VMs; reuse
     `../ebpfdivert/Vagrantfile`.

  Exit: the verifier accepts the program on both kernels. Write a go/no-go note in `docs/spikes/`.
- **Spike B: Windows Rust driver.** Use `windows-drivers-rs`: one WFP callout and one NDIS LWF,
  test-signed, loaded in a Windows Vagrant VM (see pydivert's or jdivert's Vagrantfile). Decide pure
  Rust or a thin C shim.
- **Spike C: macOS.** Check `NEFilterPacketProvider` frame level, throughput and delay semantics,
  and `/dev/bpf` reinjection. This needs a real Mac, so ask the owner.

### After that

Follow the roadmap: Phase 2 (Linux packet layers) → 3 (events, API v0.1, crates.io release job) → 4
(compat shim + pydivert/jdivert suites) → 5 (Windows driver) → 6 (macOS) → 7 (bindings, 1.0). Before
starting each phase, expand it into steps in this file, in the same format as above.

## Checklist

- [x] Phase 0.1: repo, workspace, CI, names claimed (GitHub, crates.io, PyPI), trusted publishers
- [x] Phase 1: `avulse-proto`
- [x] Phase 1: filter front half (parser, checker, IR, evaluator, CLI)
- [x] Step 1: tshark validation
- [x] Step 1b: Wireshark syntax coverage
- [ ] Step 2: bytecode + verifier + interpreter
- [ ] Step 3: WinDivert front-end + 241 vectors + `filter convert`
- [ ] Step 4: TCP options, fuzz targets
- [ ] Step 5: spikes A, B, C
- [ ] Owner: EV cert + Partner Center, Apple Developer ID + NE entitlement
