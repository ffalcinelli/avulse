//! Links the driver like any WDK driver, and generates bindings to the kernel, NDIS and WFP headers
//! that `wdk-sys` does not cover (docs/spikes/windows-driver.md, finding 1).

use std::env;
use std::error::Error;
use std::path::PathBuf;

use wdk_build::{BuilderExt, Config};

const HEADER: &str = r"
#include <ntifs.h>
#include <ntddk.h>
#include <wdmsec.h>
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
";

fn main() -> Result<(), Box<dyn Error>> {
    wdk_build::configure_wdk_binary_build()?;
    let out = PathBuf::from(env::var("OUT_DIR")?);
    let config = Config::from_env_auto()?;
    bindgen::Builder::wdk_default(config)?
        .header_contents("avulse.h", HEADER)
        // An NDIS 6.80 (Windows 10 1709) filter driver.
        .clang_arg("--define-macro=NDIS_WDM=1")
        .clang_arg("--define-macro=NDIS680=1")
        .allowlist_function("Ndis.*|Fwps.*|Fwpm.*")
        .allowlist_function(
            "IoCreateDevice|WdmlibIoCreateDeviceSecure|IoDeleteDevice|IoCreateSymbolicLink|\
             IoDeleteSymbolicLink|IofCompleteRequest|IoGetStackLimits|IoReleaseCancelSpinLock|\
             MmMapLockedPagesSpecifyCache|IoAllocateMdl|IoFreeMdl|MmBuildMdlForNonPagedPool|\
             KeExpandKernelStackAndCalloutEx|KeQueryMaximumProcessorCountEx|\
             KeGetCurrentProcessorNumberEx|\
             KeAcquireSpinLockRaiseToDpc|KeReleaseSpinLock|KeQueryPerformanceCounter|DbgPrint",
        )
        // These unions hold `NET_BUFFER_DATA;` and `NET_BUFFER_LIST_DATA;`, anonymous members of
        // a named type (a Microsoft extension), which bindgen drops, so it gets their size
        // wrong. The code reads the same fields through NET_BUFFER's and NET_BUFFER_LIST's own
        // anonymous structs instead.
        .opaque_type("_NET_BUFFER_HEADER|_NET_BUFFER_LIST_HEADER")
        .allowlist_type(
            "_IRP|_IO_STACK_LOCATION|_DRIVER_OBJECT|_DEVICE_OBJECT|_FILE_OBJECT|\
             NDIS_FILTER_.*|NDIS_OBJECT_.*|NET_BUFFER.*|FWPS_.*|FWPM_.*|FWP_.*",
        )
        .allowlist_var(
            "IRP_MJ_.*|NDIS_.*|FWP.*|FILE_DEVICE_.*|DO_.*|DISPATCH_LEVEL|AF_INET|AF_INET6|AF_UNSPEC|\
             NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1|\
             ALL_PROCESSOR_GROUPS|RPC_C_AUTHN_.*",
        )
        .generate()?
        .write_to_file(out.join("sys.rs"))?;
    for lib in ["ndis", "fwpkclnt", "netio", "wdmsec"] {
        println!("cargo::rustc-link-lib={lib}");
    }
    println!("cargo::rerun-if-changed=build.rs");
    Ok(())
}
