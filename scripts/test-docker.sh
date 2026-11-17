#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
# Build Avulse's Linux privileged test binaries on the host and run them
# inside a privileged Docker container (uses the host Linux kernel).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE_NAME="${AVULSE_TEST_IMAGE:-avulse-test}"

cd "$REPO_DIR"

find_test_bin() {
    local pkg="$1"
    local test_name="$2"
    cargo test -p "$pkg" --test "$test_name" --no-run --message-format=json \
        | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        continue
    if msg.get("reason") == "compiler-artifact" and msg.get("profile", {}).get("test"):
        exe = msg.get("executable")
        if exe:
            print(exe)
' | tail -n 1
}

KERNEL_BIN="$(find_test_bin avulse-ebpf kernel)"
CAPTURE_BIN="$(find_test_bin avulse capture)"
COMPAT_BIN="$(find_test_bin avulse-windivert-compat capture)"
cargo build -p avulse-capi
C_BIN="$REPO_DIR/target/debug/avulse-c-test"
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -D_DEFAULT_SOURCE \
    -I"$REPO_DIR/crates/capi/include" \
    "$REPO_DIR/crates/capi/tests/c/abi.c" \
    -o "$C_BIN" \
    -L"$REPO_DIR/target/debug" -lavulse '-Wl,-rpath,$ORIGIN'

rel_path() {
    python3 -c 'import os, sys; print(os.path.relpath(sys.argv[1], sys.argv[2]))' "$1" "$REPO_DIR"
}

KERNEL_REL="$(rel_path "$KERNEL_BIN")"
CAPTURE_REL="$(rel_path "$CAPTURE_BIN")"
COMPAT_REL="$(rel_path "$COMPAT_BIN")"
C_REL="$(rel_path "$C_BIN")"

docker build -t "$IMAGE_NAME" -f "$REPO_DIR/Dockerfile.test" "$REPO_DIR"

exec docker run --rm --privileged --pid=host \
    -v "$REPO_DIR:/workspace:ro" \
    -e "KERNEL_REL=$KERNEL_REL" \
    -e "CAPTURE_REL=$CAPTURE_REL" \
    -e "COMPAT_REL=$COMPAT_REL" \
    -e "C_REL=$C_REL" \
    "$IMAGE_NAME" \
    bash -ceu '
        mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
        mountpoint -q /sys/fs/cgroup || mount -t cgroup2 none /sys/fs/cgroup
        iptables -P FORWARD ACCEPT || true
        echo "== BPF programs in the kernel ($KERNEL_REL)"
        AVULSE_BPF=1 "/workspace/$KERNEL_REL" --nocapture --test-threads=1
        echo "== The Linux backend on real traffic ($CAPTURE_REL)"
        AVULSE_BPF=1 "/workspace/$CAPTURE_REL" --nocapture --test-threads=1
        echo "== The WinDivert shim on real traffic ($COMPAT_REL)"
        AVULSE_BPF=1 "/workspace/$COMPAT_REL" --nocapture --test-threads=1
        echo "== C API capture test ($C_REL)"
        AVULSE_BPF=1 "/workspace/$C_REL"
    '
