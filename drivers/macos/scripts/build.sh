#!/bin/bash
# Builds target/macos/Avulse.app: the host app and the avulse system extension, universal
# (arm64 and x86_64), with the extension's Rust logic (crates/macos-ext) linked in. Signs them
# with $AVULSE_SIGN_IDENTITY (a Developer ID Application identity, whose provisioning gives the
# restricted entitlements), or ad hoc.
#
# Also leaves target/macos/avulse-ext-test: the extension's executable signed ad hoc without
# entitlements, which `--test` runs as a plain daemon (scripts/test.sh). AMFI does not run ad-hoc
# signed binaries that carry restricted entitlements (docs/spikes/macos.md, finding 14).
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$here/../.." && pwd)
out=$root/target/macos
ext=com.github.ffalcinelli.avulse.extension
identity=${AVULSE_SIGN_IDENTITY:--}
rm -rf "$out" && mkdir -p "$out"

for t in aarch64-apple-darwin x86_64-apple-darwin; do
    cargo build --release -p avulse-macos-ext --target "$t" --manifest-path "$root/Cargo.toml"
done
lipo -create -output "$out/libavulse_macos_ext.a" \
    "$root"/target/{aarch64,x86_64}-apple-darwin/release/libavulse_macos_ext.a

swift_build() { # module, output, frameworks..., then the sources after --
    local name=$1 dst=$2; shift 2
    local fw=()
    while [ "$1" != "--" ]; do fw+=(-framework "$1"); shift; done; shift
    for arch in arm64 x86_64; do
        swiftc -O -target "$arch-apple-macos13.0" -module-name "$name" \
            -import-objc-header "$here/Shared/avulse_ext.h" "$@" \
            -L "$out" -lavulse_macos_ext "${fw[@]}" -o "$out/$name-$arch"
    done
    lipo -create -output "$dst" "$out/$name-arm64" "$out/$name-x86_64"
}

app=$out/Avulse.app
sx=$app/Contents/Library/SystemExtensions/$ext.systemextension
mkdir -p "$app/Contents/MacOS" "$sx/Contents/MacOS"
cp "$here/App/Info.plist" "$app/Contents/Info.plist"
cp "$here/Extension/Info.plist" "$sx/Contents/Info.plist"
swift_build AvulseExtension "$sx/Contents/MacOS/$ext" NetworkExtension Network -- \
    "$here"/Extension/*.swift
swift_build Avulse "$app/Contents/MacOS/Avulse" SystemExtensions NetworkExtension -- \
    "$here/App/main.swift"

cp "$sx/Contents/MacOS/$ext" "$out/avulse-ext-test"
codesign --force --sign - "$out/avulse-ext-test"
codesign --force --sign "$identity" --options runtime --entitlements "$here/Extension.entitlements" "$sx"
codesign --force --sign "$identity" --options runtime --entitlements "$here/App.entitlements" "$app"
codesign --verify --deep --strict --verbose=2 "$app"
lipo -info "$app/Contents/MacOS/Avulse" "$sx/Contents/MacOS/$ext"
