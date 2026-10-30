//! The runner: OS, SIP, system extensions, bpf devices, what pf accepts, and the SDK's contract
//! for `NEFilterPacketProvider`.

use std::process::Command;

use crate::report::Report;

fn sh(cmd: &str) -> (bool, String) {
    match Command::new("/bin/sh").arg("-c").arg(cmd).output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), s.trim_end().to_string())
        }
        Err(e) => (false, e.to_string()),
    }
}

fn record(r: &mut Report, name: &str, cmd: &str) {
    let (_, out) = sh(cmd);
    r.info(name, out);
}

pub fn run(r: &mut Report) {
    record(r, "uname", "uname -a");
    if !cfg!(target_os = "macos") {
        return;
    }
    record(r, "sw_vers", "sw_vers");
    record(
        r,
        "cpu",
        "sysctl -n machdep.cpu.brand_string hw.ncpu hw.memsize",
    );
    record(r, "virtualized", "sysctl -n kern.hv_vmm_present");
    record(r, "csrutil", "csrutil status");
    record(r, "systemextensionsctl", "systemextensionsctl list");
    record(
        r,
        "developer_mode",
        "systemextensionsctl developer 2>&1; DevToolsSecurity -status",
    );
    record(r, "mdm", "profiles status -type enrollment 2>&1");
    record(r, "bpf_devices", "ls /dev | grep -c '^bpf'");
    record(
        r,
        "bpf_sysctl",
        "sysctl -a | grep -i '^debug.bpf\\|^net.bpf' ",
    );
    record(
        r,
        "divert_sysctl",
        "sysctl -a | grep -i 'divert\\|\\.fw\\.\\|ipfw\\|dummynet' | head -40",
    );
    record(
        r,
        "ifconfig",
        "ifconfig -l; route -n get default 2>&1 | grep interface",
    );
    record(r, "pf_info", "pfctl -s info 2>&1 | head -20");
    for (name, rule) in [
        (
            "pf_divert_to",
            "pass out on lo0 divert-to 127.0.0.1 port 700",
        ),
        ("pf_divert_packet", "pass out on lo0 divert-packet port 700"),
        (
            "pf_route_to",
            "pass out on en0 route-to (lo0 127.0.0.1) from any to 192.0.2.1",
        ),
        (
            "pf_dup_to",
            "pass out on en0 dup-to (lo0 127.0.0.1) from any to 192.0.2.1",
        ),
        (
            "pf_dummynet",
            "dummynet out on en0 from any to 192.0.2.1 pipe 1",
        ),
        (
            "pf_rdr",
            "rdr on en0 inet proto tcp to 192.0.2.1 port 80 -> 127.0.0.1 port 8080",
        ),
    ] {
        let path = std::env::temp_dir().join("avulse-pf.conf");
        let _ = std::fs::write(&path, format!("{rule}\n"));
        let (ok, out) = sh(&format!("pfctl -nf {} 2>&1", path.display()));
        r.check(
            name,
            ok && !out.contains("syntax error"),
            format!("{rule}\n{out}"),
        );
    }
    let sdk = sh("xcrun --show-sdk-path").1;
    record(
        r,
        "sdk",
        format!("echo {sdk}; xcrun --show-sdk-version; swiftc --version").as_str(),
    );
    record(
        r,
        "bpf_h",
        &format!(
            "grep -n 'BIOC\\|bpf_hdr_ext\\|BPF_HDR_EXT\\|BPF_D_\\|bh_\\|DLT_NULL\\|DLT_RAW\\|DLT_PKTAP' {sdk}/usr/include/net/bpf.h"
        ),
    );
    record(
        r,
        "ipv6_hdrincl",
        &format!("grep -rn 'HDRINCL' {sdk}/usr/include/netinet6 {sdk}/usr/include/netinet"),
    );
    let ne = format!("{sdk}/System/Library/Frameworks/NetworkExtension.framework/Headers");
    for h in [
        "NEFilterPacketProvider.h",
        "NEPacket.h",
        "NEFilterManager.h",
    ] {
        match std::fs::read_to_string(format!("{ne}/{h}")) {
            Ok(text) => r.info(h, text),
            Err(e) => r.fail(h, e.to_string()),
        }
    }
    record(
        r,
        "ne_provider_keys",
        &format!("grep -rho 'com.apple.networkextension.[a-z-]*' {ne} | sort -u"),
    );
}
