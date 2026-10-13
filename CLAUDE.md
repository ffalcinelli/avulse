# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Avulse is a cross-platform (Linux, Windows, macOS) packet-diverting library. It aims to be a superset of WinDivert: it adds an ETHERNET layer, uses a Wireshark-compatible filter language, and will ship a WinDivert-compatible shim so that pydivert/jdivert can move onto it. It is the fifth repo in `~/Workspace/divert/` (see `../CLAUDE.md` for its siblings: windivert, ebpfdivert, pydivert, jdivert). It is dual-licensed LGPL-3.0-or-later / GPL-2.0-or-later, and BPF programs must be GPL-compatible.

**Status: pre-alpha.** Only `avulse-proto`, `avulse-filter`, the `avulse filter …` CLI and `avulse-wasm` (the website's filter playground) are implemented. `ebpf`, `backend-linux`, `capi`, `windivert-compat`, the `avulse` facade crate and `bindings/python` are empty placeholders that reserve names. `docs/roadmap.md` is the design document (phases, the layer/backend feature matrix, filter-language decisions, and what to reuse from ebpfdivert). Read it before starting work on a new phase.

**Start each session with `docs/implementation-plan.md`.** It holds the current status, the accounts and workstation quirks (pushing over SSH, no `tshark`, no `rustup`), the open Wireshark-semantics questions, and the ordered next steps with acceptance criteria. Tick steps there as they land, and commit it together with the code.

## Commands

```bash
cargo build --workspace
cargo test --workspace
cargo test -p avulse-filter wireshark_quantifiers   # single test (substring match on the test name)
cargo fmt --check
cargo clippy --workspace --all-targets             # CI sets RUSTFLAGS=-D warnings
cargo build -p avulse-proto -p avulse-filter --target thumbv7em-none-eabihf   # no_std check (CI job)
cargo run -p avulse-cli -- filter check 'tcp.port == 80'   # also: fmt | explain | eval --hex … [--link ip] | fields
AVULSE_TSHARK=1 cargo test -p avulse-filter --features regex tshark -- --nocapture   # compare with tshark 4.6+ (CI job `tshark`)
AVULSE_BLESS=1 cargo test -p avulse-cli --test docs   # regenerate book/src/reference/fields.md after changing FIELDS
scripts/build-site.sh && python3 -m http.server -d target/site   # whole website; needs mdbook, wasm-pack, uv (~/.cargo/bin here)
cargo test -p avulse-filter                       # without the `regex` feature (workspace builds turn it on via the CLI)
```

CI (`.github/workflows/ci.yml`) runs fmt and clippy, then `cargo test` on Linux, Windows and macOS, the tshark comparison (Wireshark stable PPA), and the `no_std` build. Edition 2024, resolver 3. Workspace lints: `unsafe_op_in_unsafe_fn = deny` and `clippy::all = warn`, which counts as an error in CI.

## Architecture

### `no_std` is a hard constraint

`crates/proto` and `crates/filter` are `#![no_std]` (filter uses `alloc`) and `#![forbid(unsafe_code)]`. The same code is meant to run inside the Windows KMDF driver and the macOS system extension, so one engine gives one set of semantics everywhere. Do not add `std` or dependencies that need it. The optional `regex` feature (`matches`, via `regex-automata` with `alloc` only) keeps `no_std` too, but it is user space only: it is the one evaluation path that may allocate. Use `core::net` for IP types. Tests opt in with `extern crate std`. The `thumbv7em-none-eabihf` CI build is what enforces this.

### `avulse-proto`

`Packet::parse(bytes, Link::{Ethernet, Ip})` does zero-copy parsing of Ethernet, up to 2 VLAN tags (QinQ), ARP, IPv4, IPv6 (walking up to 8 extension headers, plus fragments), TCP, UDP, ICMP and ICMPv6. Parsing **never fails, allocates or panics**: it stops at the first truncated or unknown header, and the rest of the buffer becomes the payload. `headers.rs` holds the per-header views, and `checksum.rs` handles recalculation.

### `avulse-filter`: the pipeline

`lexer` → `parser` (`ast`, `Display` = canonical `filter fmt` output) → `check` (name resolution of `let`/`$name` macros, strict typing, symbolic constants, lowering) → `ir::simplify` → `eval` (an allocation-free interpreter). `Filter::compile` / `Filter::matches(&Packet, &Meta)` is the public entry point.

- **`fields.rs` is the field registry.** The `fields!` macro generates both the `Field` enum and `FIELDS` (name, type, `Origin::{Wireshark, Extension, Flag}`, symbolic-constant table, description). To add a field, add a row there and the matching arm in `eval.rs` (which reads the value from `Packet`/`Meta`). `UNSUPPORTED` and `APPLICATION` list Wireshark fields that are rejected with a hint because they need stream state or dissectors.
- **`labels.rs` is generated** by `scripts/gen_labels.py` from `tshark -G values`: Wireshark's value-string labels (`ip.proto == "TCP"`) for every Wireshark field, merged across Wireshark versions (labels change between releases; a label that means different values is ambiguous and rejected). Rerun it after adding fields with every tshark at hand, e.g. `python3 scripts/gen_labels.py tshark "docker run --rm -i <4.6 image> tshark"`; multi-table fields need an entry in its `TABLE`.
- **`meta.rs` (`Meta`)** carries everything that is not in the packet bytes: layer, event, direction, loopback, iface, process, and the flow tuple for the FLOW/SOCKET layers. `Layer` and `Event` keep WinDivert's numbering (`Ethernet = 5` is new).
- **Semantics follow Wireshark 4.6+ and are the main correctness risk.** Fields can have several occurrences (`ip.addr`, `tcp.port`, `vlan.id`, at most 4 values; see `MAX` in `eval.rs`). `==` means some pair is equal, `!=` means no pair is equal, `!==` (`~=`) means some pair differs, `not in` means present and no value in the set, and any comparison with an absent field is false. An integer compared with bytes is one byte (`tcp[13] == 18` is 0x12). Type mismatches are compile errors, never a silent false. Diagnostics carry spans and "did you mean" help (`error.rs`).
- **`src/tests/tshark.rs` is the oracle.** It compares every Wireshark field and a table of filters with `tshark` over generated captures (`AVULSE_TSHARK=1 cargo test -p avulse-filter tshark`, needs tshark 4.6+). Add a row there whenever you add a field or change semantics; intentional differences go in its `DIVERGENCES`/`EXTENSIONS`/`STRICTER` tables and in the guide (`book/src/filters/wireshark.md`).
- The IR is the shared contract for future backends: runtime eBPF codegen on Linux with a superset-in-kernel fallback, and a bytecode verifier and interpreter in the Windows/macOS kernels. Keep it backend-neutral.

Tests sit in `src/tests.rs` (proto) and `src/tests/` (filter: `mod.rs`, frame builders in `frames.rs`, a pcap writer, `tshark.rs`). They build frames by hand with helpers such as `eth()`, `ipv4()`, `tcp()` and `udp()`.

## Documentation and website

Published to <https://ffalcinelli.github.io/avulse/> by `.github/workflows/pages.yml`, which runs `scripts/build-site.sh`: `site/` (hand-written landing page; `playground.js` loads `crates/wasm` built by wasm-pack into `/pkg/`), `book/` (mdBook guide, `/guide/`), rustdoc (`/api/rust/`) and pdoc of `bindings/python` (`/api/python/`).

- The guide is the language reference. The README stays a short front page that links to it.
- Every public item needs docs (`missing_docs` is a workspace lint, so CI fails without them). CI's `docs` job runs rustdoc with `-D warnings`, clippy for `wasm32-unknown-unknown` and `mdbook build`.
- `crates/cli/tests/docs.rs` compiles every ```` ```filter ```` block in `book/src` and `README.md` (```` ```filter,error ```` blocks must fail; a blank line separates filters, except after `let` lines), and checks that `book/src/reference/fields.md` matches `avulse filter fields --format markdown`.
- The Rust code in both READMEs runs as doctests (`cfg(doctest)` module in `crates/filter/src/lib.rs`). The guide `{{#include}}`s `crates/*/examples/`.
- `avulse-wasm` keeps `wasm-bindgen` behind `cfg(target_arch = "wasm32")`; its logic is plain Rust tested natively. When the language changes, update its samples' tests and, if useful, the playground's `EXAMPLES`.

## Planned work (from the roadmap; follow these decisions)

- **Linux backend.** Port the logic of ebpfdivert's `src/ebpfdivert.bpf.c`, `ebpfdivert_events.bpf.c` and `handle.c`. Keep the BPF programs in C with libbpf conventions and load them with `aya`. Attach with classic cls_bpf on clsact, **not TCX**. Keep mark-based loop prevention, the pinned registry and the heartbeat with fail-open. Privileged tests run only in the Vagrant VMs (6.8 `default`, 5.15 `legacy`), one at a time, destroyed right after the run, as in ebpfdivert.
- **Address struct.** It is a new versioned struct with explicit fields and an opaque reinjection-context blob. It replaces WinDivert's 80-byte union, which only the `windivert-compat` shim exposes.
- **`windivert/sys/windivert.c`** is reference reading only. Do not copy code from it.
