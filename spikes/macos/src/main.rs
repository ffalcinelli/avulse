//! `probe <report.jsonl> <env|bpf|inject|bench>...`: runs the Spike C probes and appends one JSON
//! object per result to the report. `bpf` and `inject` need root and the interfaces that
//! `.github/workflows/macos-spike.yml` sets up (see `net`).

mod bench;
#[cfg(target_os = "macos")]
mod bpf;
mod env;
#[cfg(target_os = "macos")]
mod inject;
#[cfg(target_os = "macos")]
mod net;
mod report;

use report::Report;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((path, probes)) = args.split_first() else {
        eprintln!("usage: probe <report.jsonl> <env|bpf|inject|bench>...");
        std::process::exit(2);
    };
    let mut r = Report::open(path);
    for p in probes {
        r.section(p);
        match p.as_str() {
            "env" => env::run(&mut r),
            #[cfg(target_os = "macos")]
            "bpf" => bpf::run(&mut r),
            #[cfg(target_os = "macos")]
            "inject" => inject::run(&mut r),
            "bench" => bench::run(&mut r),
            other => r.fail("probe", format!("unknown or unavailable probe `{other}`")),
        }
    }
}
