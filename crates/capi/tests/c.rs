//! libavulse from C: compiles `tests/c/abi.c` against `include/avulse.h` and the shared
//! library, and runs it. Without privileges it checks the header's layout, the filter helpers
//! and the errors. The program is left next to the library as `avulse-c-test`, to run as root
//! in a VM with `AVULSE_BPF=1`, which also receives and sends packets through a handle.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The directory with the library: `target/<profile>`, above this test's `deps`.
fn target_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().to_path_buf()
}

#[test]
fn c_program() {
    if !cfg!(target_os = "linux") {
        return;
    }
    // Tests do not build the shared library (nothing links it): build it, in this profile.
    let dir = target_dir();
    let mut build = Command::new(env!("CARGO"));
    build.args(["build", "-p", "avulse-capi"]);
    if dir.ends_with("release") {
        build.arg("--release");
    }
    assert!(
        build.status().unwrap().success(),
        "cargo build -p avulse-capi"
    );
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let src = Path::new(env!("CARGO_MANIFEST_DIR"));
    let exe = dir.join("avulse-c-test");
    let status = Command::new(&cc)
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-D_DEFAULT_SOURCE",
        ])
        .arg("-I")
        .arg(src.join("include"))
        .arg(src.join("tests/c/abi.c"))
        .arg("-o")
        .arg(&exe)
        .arg("-L")
        .arg(&dir)
        .arg("-lavulse")
        .arg("-Wl,-rpath,$ORIGIN")
        .status()
        .unwrap_or_else(|e| panic!("running {cc}: {e}"));
    assert!(status.success(), "{cc} failed");
    let out = Command::new(&exe)
        .env_remove("AVULSE_BPF")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout) + String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{text}");
    assert_eq!(text.trim(), "ok");
}
