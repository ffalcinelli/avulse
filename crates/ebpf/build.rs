//! Compiles the static BPF programs in `bpf/` with clang, for Linux targets only.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo::rerun-if-changed=bpf");
    println!("cargo::rerun-if-env-changed=CLANG");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    for name in ["tc", "events"] {
        compile(name);
    }
}

/// Compiles `bpf/{name}.bpf.c` to `{name}.bpf.o` in `OUT_DIR`.
fn compile(name: &str) {
    let src = format!("bpf/{name}.bpf.c");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join(format!("{name}.bpf.o"));
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".into());
    let mut cmd = Command::new(&clang);
    cmd.args(["-O2", "-g", "-target", "bpf", "-Wall", "-Werror", "-c"])
        .arg(&src)
        .arg("-o")
        .arg(&out);
    // Debian and Ubuntu keep `asm/types.h` in the multiarch directory, which `-target bpf` does
    // not search.
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let multiarch = format!("/usr/include/{arch}-linux-gnu");
    if Path::new(&multiarch).is_dir() {
        cmd.arg(format!("-I{multiarch}"));
    }
    match cmd.status() {
        Ok(s) if s.success() => {}
        Ok(s) => panic!("{clang} failed to compile {src}: {s}"),
        Err(e) => panic!(
            "cannot run {clang} ({e}): building avulse-ebpf on Linux needs clang with the BPF \
             target and the kernel UAPI headers (set CLANG to pick another compiler)"
        ),
    }
}
