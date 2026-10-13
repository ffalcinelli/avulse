# Contributing

Thanks for your interest in Avulse. It is pre-alpha, so the design still moves: for anything
larger than a fix, open an issue first. [`docs/roadmap.md`](docs/roadmap.md) is the design, and
[`docs/implementation-plan.md`](docs/implementation-plan.md) the current status and next steps.

## Setup

You need a stable Rust toolchain (edition 2024). Optional tools:

- [`tshark`](https://www.wireshark.org/) 4.6 or later, to compare filters with Wireshark;
- [`mdbook`](https://rust-lang.github.io/mdBook/), [`wasm-pack`](https://drager.github.io/wasm-pack/)
  and [`uv`](https://docs.astral.sh/uv/), to build the documentation site.

## Checks

CI runs these on Linux, Windows and macOS. Run them before sending a change:

```console
$ cargo fmt --check
$ RUSTFLAGS=-D warnings cargo clippy --workspace --all-targets
$ cargo test --workspace
$ cargo build -p avulse-proto -p avulse-filter --target thumbv7em-none-eabihf   # no_std
$ RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --all-features
```

`avulse-proto` and `avulse-filter` must stay `#![no_std]` and `#![forbid(unsafe_code)]`, with no
panicking paths in evaluation code, and every public item documented.

Filter semantics follow Wireshark 4.6+. To compare with `tshark`:

```console
$ AVULSE_TSHARK=1 cargo test -p avulse-filter --features regex tshark -- --nocapture
```

## Documentation

- Language changes go in the guide (`book/src/filters/`). An intentional difference from
  Wireshark goes in `book/src/filters/wireshark.md` and in the matching table of
  `crates/filter/src/tests/tshark.rs`.
- The field reference (`book/src/reference/fields.md`) is generated from the field registry.
  After adding a field, regenerate it with `AVULSE_BLESS=1 cargo test -p avulse-cli --test docs`.
- Every ` ```filter ` block in the guide and the README must compile, and every
  ` ```filter,error ` block must fail; `cargo test` checks both. A blank line separates filters in
  one block.
- To build and preview the whole site (landing page, playground, guide, API docs):

  ```console
  $ scripts/build-site.sh
  $ python3 -m http.server -d target/site
  ```

## Commits

Write commit messages in the imperative mood, with a body that explains why. Keep unrelated
changes in separate commits.

## License

By contributing, you agree that your contributions are dual-licensed under LGPL-3.0-or-later or
GPL-2.0-or-later, at the user's option, like the rest of the project. BPF programs must be
GPL-compatible.
