//! Links the driver like any WDK driver, generates bindings to the NDIS and WFP headers (which
//! `wdk-sys` does not cover), and compiles the spike's filters to avulse bytecode.

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use avulse_filter::Filter;
use wdk_build::{BuilderExt, Config};

/// What the WFP callout blocks: outbound DNS queries.
const WFP_FILTER: &str = "udp.dstport == 53";
/// What the NDIS filter counts, on Ethernet frames in both directions.
const LWF_FILTER: &str = "tcp.port in {80 443} or arp";
/// What the NDIS filter also counts, so that the test knows the exact number to expect.
const PING_FILTER: &str = "icmp.type == 8 and ip.dst == 10.0.2.2";

const HEADER: &str = r"
#include <ntifs.h>
#include <ntddk.h>
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
";

fn main() -> Result<(), Box<dyn Error>> {
    wdk_build::configure_wdk_binary_build()?;
    let out = PathBuf::from(env::var("OUT_DIR")?);

    for (name, src) in [
        ("wfp", WFP_FILTER),
        ("lwf", LWF_FILTER),
        ("ping", PING_FILTER),
    ] {
        let program = Filter::compile(src)
            .map_err(|e| format!("{src}: {}", e.message))?
            .program()
            .map_err(|e| format!("{src}: {e}"))?;
        fs::write(out.join(format!("{name}.avbc")), program.to_bytes())?;
    }

    let config = Config::from_env_auto()?;
    bindgen::Builder::wdk_default(config)?
        .header_contents("net.h", HEADER)
        // An NDIS 6.80 (Windows 10 1709) filter driver.
        .clang_arg("--define-macro=NDIS_WDM=1")
        .clang_arg("--define-macro=NDIS680=1")
        .allowlist_function("Ndis.*|Fwps.*|Fwpm.*")
        .allowlist_function(
            "IoCreateDevice|IoDeleteDevice|IoGetStackLimits|KeExpandKernelStackAndCalloutEx",
        )
        // These unions hold `NET_BUFFER_DATA;` and `NET_BUFFER_LIST_DATA;`, anonymous members of
        // a named type (a Microsoft extension), which bindgen drops, so it gets their size
        // wrong. The code reads the same fields through NET_BUFFER's and NET_BUFFER_LIST's own
        // anonymous structs instead.
        .opaque_type("_NET_BUFFER_HEADER|_NET_BUFFER_LIST_HEADER")
        .allowlist_function("ZwCreateKey|ZwSetValueKey|ZwClose|RtlInitUnicodeString|DbgPrint")
        .allowlist_type("NDIS_FILTER_.*|NDIS_OBJECT_.*|NET_BUFFER.*|FWPS_.*|FWPM_.*|FWP_.*")
        .allowlist_var("NDIS_.*|FWP.*|FILE_DEVICE_.*|REG_.*|KEY_.*|OBJ_.*|RPC_C_AUTHN_.*")
        .generate()?
        .write_to_file(out.join("sys.rs"))?;
    for lib in ["ndis", "fwpkclnt", "netio"] {
        println!("cargo::rustc-link-lib={lib}");
    }
    println!("cargo::rerun-if-changed=build.rs");
    Ok(())
}
