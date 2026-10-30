//! `libavulse_windivert.so` exports libebpfdivert's API, and nothing else: the symbols pydivert
//! and jdivert look up, plus `ebpfdivert_set_print`.

use std::path::PathBuf;
use std::process::Command;

/// What the library must export, and all it may.
const EXPORTS: &[&str] = &[
    "ebpfdivert_close",
    "ebpfdivert_get_event_fd",
    "ebpfdivert_get_handle_stats",
    "ebpfdivert_get_param",
    "ebpfdivert_helper_calc_checksums",
    "ebpfdivert_helper_compile_filter",
    "ebpfdivert_helper_eval_filter",
    "ebpfdivert_helper_format_filter",
    "ebpfdivert_helper_hash_packet",
    "ebpfdivert_open",
    "ebpfdivert_open_ex",
    "ebpfdivert_recv",
    "ebpfdivert_recv_ex",
    "ebpfdivert_send",
    "ebpfdivert_send_ex",
    "ebpfdivert_set_param",
    "ebpfdivert_set_print",
    "ebpfdivert_shutdown",
    "ebpfdivert_strerror",
    "ebpfdivert_unregister",
    "ebpfdivert_version",
];

/// `target/<profile>`, above this test's `deps`.
fn target_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().to_path_buf()
}

#[test]
fn exported_symbols() {
    if !cfg!(target_os = "linux") {
        return;
    }
    // Tests do not build the shared library: build it, in this profile.
    let dir = target_dir();
    let mut build = Command::new(env!("CARGO"));
    build.args(["build", "-p", "avulse-windivert-compat"]);
    if dir.ends_with("release") {
        build.arg("--release");
    }
    assert!(
        build.status().unwrap().success(),
        "cargo build -p avulse-windivert-compat"
    );
    let lib = dir.join("libavulse_windivert.so");
    let out = Command::new("nm")
        .args(["-D", "--defined-only", "--format=posix"])
        .arg(&lib)
        .output()
        .unwrap_or_else(|e| panic!("running nm: {e}"));
    assert!(out.status.success(), "nm {}", lib.display());
    let mut got: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.split(' ').nth(1).is_some_and(|t| t == "T"))
        .map(|l| l.split(' ').next().unwrap().to_owned())
        .collect();
    got.sort();
    assert_eq!(got, EXPORTS);
}
