#!/usr/bin/env python3
"""Check the stack frames of the bytecode interpreter in a release build.

The Windows driver runs `VerifiedProgram::matches_in` on a 24 KiB kernel stack, deep in the
network stack, where about 10 KiB may be left (docs/spikes/windows-driver.md). This builds
avulse-filter in release with rustc's `-Z emit-stack-sizes` (through RUSTC_BOOTSTRAP, so a stable
toolchain will do), reads the frames with `llvm-readobj --stack-sizes`, prints the largest ones of
the interpreter and the value operations, and fails if one is over the limit.

Usage: python3 scripts/stack-sizes.py [limit in bytes, default 1024]

Needs llvm-readobj (`LLVM_READOBJ` to pick another). `matches` is left out: it holds the
2.7 KiB register file, which the driver keeps elsewhere through `matches_in`.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "target" / "stack"
# Mangled (v0) path pieces of the code that runs per packet.
HOT = ("8bytecode4exec", "13avulse_filter5value", "12avulse_proto")


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 1024
    env = dict(os.environ, RUSTC_BOOTSTRAP="1", RUSTFLAGS="-Zemit-stack-sizes")
    subprocess.run(
        ["cargo", "build", "--release", "-p", "avulse-filter", "--target-dir", str(TARGET)],
        cwd=ROOT,
        env=env,
        check=True,
    )
    readobj = os.environ.get("LLVM_READOBJ", "llvm-readobj")
    rows = []
    for lib in ["libavulse_filter.rlib", "libavulse_proto.rlib"]:
        # It exits with 1 on the rlib's metadata members, which have no code; the output is whole.
        out = subprocess.run(
            [readobj, "--stack-sizes", str(TARGET / "release" / lib)],
            capture_output=True,
            text=True,
        ).stdout
        rows += [
            (int(size, 16), names.split(",")[0])
            for names, size in re.findall(r"Functions: \[([^\]]*)\]\s+Size: (0x[0-9A-Fa-f]+)", out)
        ]
    hot = sorted({r for r in rows if any(h in r[1] for h in HOT)}, reverse=True)
    if not hot:
        sys.exit("no frames found: did the build emit .stack_sizes?")
    print(f"largest frames on the interpreter's path (limit {limit} bytes):")
    for size, name in hot[:10]:
        print(f"{size:6}  {name[:110]}")
    over = [(s, n) for s, n in hot if s > limit]
    if over:
        sys.exit(f"{len(over)} frame(s) over {limit} bytes")


if __name__ == "__main__":
    main()
