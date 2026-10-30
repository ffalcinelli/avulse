#!/usr/bin/env bash
# Build the website into target/site (deployed by .github/workflows/pages.yml):
#   /              site/: the landing page and the filter playground
#   /pkg/          the playground's WebAssembly package (crates/wasm, wasm-pack --target web)
#   /guide/        the mdBook guide (book/)
#   /api/rust/     rustdoc for the workspace
#   /api/python/   pdoc for bindings/python
# Needs mdbook, wasm-pack, uv and the wasm32-unknown-unknown target. Preview locally with
#   python3 -m http.server -d target/site
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="$PWD/target/site"

rm -rf "$OUT"
mkdir -p "$OUT/api"
cp -R site/. "$OUT/"

wasm-pack build --release --target web --out-dir "$OUT/pkg" crates/wasm
# Only the module and its bindings are served.
find "$OUT/pkg" -type f ! -name '*.js' ! -name '*.wasm' -delete

mdbook build book --dest-dir "$OUT/guide"

# The CLI and the C ABI crate are left out: their docs are the guide and the C header.
cargo doc --workspace --no-deps --all-features --exclude avulse-cli --exclude avulse-capi --exclude avulse-wasm
cp -R target/doc "$OUT/api/rust"
cat >"$OUT/api/rust/index.html" <<'HTML'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rust API · Avulse</title>
  <meta name="color-scheme" content="dark light">
  <link rel="icon" href="../../favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="../../style.css">
</head>
<body>
  <main class="section">
    <div class="wrap">
      <p><a href="../../">← Avulse</a></p>
      <h1>Rust API</h1>
      <p class="section-lede">rustdoc for the Avulse workspace. The crates are not on crates.io
        yet; see <a href="../../guide/libraries/rust.html">Rust crates</a> in the guide to use
        them from Git.</p>
      <div class="cards docs">
        <a class="card link" href="avulse_proto/">
          <h3>avulse_proto</h3>
          <p>Zero-copy packet parsing (Ethernet, VLAN, ARP, IPv4/6, TCP, UDP, ICMP) and checksums.</p>
        </a>
        <a class="card link" href="avulse_filter/">
          <h3>avulse_filter</h3>
          <p>The filter language: parser, type checker, IR and evaluator.</p>
        </a>
        <a class="card link" href="avulse/">
          <h3>avulse</h3>
          <p>The handle API (preview): handles, flags, parameters and the packet address. No
            backend yet.</p>
        </a>
      </div>
      <p class="note"><code>avulse_ebpf</code> is a prototype of the Linux in-kernel filter;
        <code>avulse_windivert_compat</code> is a placeholder.</p>
    </div>
  </main>
</body>
</html>
HTML

uv run --quiet --project bindings/python --extra docs \
  pdoc avulse --favicon ../../favicon.svg --footer-text "Avulse $(git describe --tags --always 2>/dev/null || echo dev)" \
  -o "$OUT/api/python"

du -h "$OUT"/pkg/*.wasm
du -sh "$OUT"
