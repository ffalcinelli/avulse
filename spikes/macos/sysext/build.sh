#!/bin/bash
# Builds the Rust static library for both architectures, the system extension and its host
# app as universal binaries, and two ad-hoc signed bundles in target/sysext: AvulseSpike.app
# (with the restricted entitlements a real build needs) and AvulseSpikePlain.app (without).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
crate=$(dirname "$here")
out=$crate/target/sysext
ext=com.github.ffalcinelli.avulse.spike.filter
rm -rf "$out" && mkdir -p "$out"

for t in aarch64-apple-darwin x86_64-apple-darwin; do
    cargo build --release --lib --manifest-path "$crate/Cargo.toml" --target "$t"
done
lipo -create -output "$out/libavulse_spike_macos.a" \
    "$crate"/target/{aarch64,x86_64}-apple-darwin/release/libavulse_spike_macos.a
lipo -info "$out/libavulse_spike_macos.a"
cargo rustc --release --lib --manifest-path "$crate/Cargo.toml" --crate-type staticlib \
    -- --print native-static-libs 2>&1 | grep native-static-libs || true

swift_build() { # name, output, frameworks..., then the sources after --
    local name=$1 dst=$2; shift 2
    local fw=()
    while [ "$1" != "--" ]; do fw+=(-framework "$1"); shift; done; shift
    for arch in arm64 x86_64; do
        swiftc -O -target "$arch-apple-macos13.0" -module-name "$name" \
            -import-objc-header "$here/avulse_spike.h" "$@" \
            -L "$out" -lavulse_spike_macos "${fw[@]}" -o "$out/$name-$arch"
    done
    lipo -create -output "$dst" "$out/$name-arm64" "$out/$name-x86_64"
    lipo -info "$dst"
}

for variant in AvulseSpike AvulseSpikePlain; do
    app=$out/$variant.app
    sx=$app/Contents/Library/SystemExtensions/$ext.systemextension
    mkdir -p "$app/Contents/MacOS" "$sx/Contents/MacOS"
    cp "$here/App/Info.plist" "$app/Contents/Info.plist"
    cp "$here/Filter/Info.plist" "$sx/Contents/Info.plist"
    if [ "$variant" = AvulseSpike ]; then
        swift_build FilterExt "$sx/Contents/MacOS/$ext" NetworkExtension Network -- \
            "$here/Filter/FilterPacketProvider.swift" "$here/Filter/main.swift"
        swift_build AvulseSpike "$app/Contents/MacOS/AvulseSpike" SystemExtensions NetworkExtension -- \
            "$here/App/main.swift"
        # Without the restricted Network Extension entitlement (Step 32): launchd could not
        # execute the ad-hoc signed extension that had it (run 41032129926, EACCES), as AMFI
        # rejects ad-hoc signatures with restricted entitlements.
        codesign --force --sign - --options runtime --entitlements "$here/Filter.min.entitlements" "$sx"
        codesign --force --sign - --options runtime --entitlements "$here/App.entitlements" "$app"
    else
        cp "$out/AvulseSpike.app/Contents/MacOS/AvulseSpike" "$app/Contents/MacOS/"
        cp "$out/AvulseSpike.app/Contents/Library/SystemExtensions/$ext.systemextension/Contents/MacOS/$ext" \
            "$sx/Contents/MacOS/"
        codesign --force --sign - --options runtime "$sx"
        codesign --force --sign - --options runtime "$app"
    fi
    codesign --verify --deep --strict --verbose=2 "$app"
    codesign -d --entitlements - "$app" 2>&1 | tail -n +1
done
