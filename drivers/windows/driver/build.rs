//! Links the driver like any WDK driver, generates bindings to the kernel, NDIS and WFP headers
//! that `wdk-sys` does not cover (docs/spikes/windows-driver.md, finding 1), and compiles
//! `src/user.c`, the one function that needs structured exception handling.

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
    // `src/user.c`, with the WDK's headers and definitions for the target, as a kernel-mode
    // object (`/kernel`, no buffer security checks, which would need the kernel's cookie).
    let mut c = cc::Build::new();
    c.file("src/user.c")
        .flag("/kernel")
        .flag("/GS-")
        .warnings_into_errors(true);
    for path in config.include_paths()? {
        c.include(path);
    }
    // `/kernel` defines _KERNEL_MODE itself, and defining it again is an error with -WX.
    for (name, value) in config.preprocessor_definitions() {
        if name != "_KERNEL_MODE" {
            c.define(&name, value.as_deref());
        }
    }
    c.compile("avulse_user");
    println!("cargo::rerun-if-changed=src/user.c");
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
             KeAcquireSpinLockRaiseToDpc|KeReleaseSpinLock|KeQueryPerformanceCounter|DbgPrint|\
             PsGetCurrentProcessId|MmUnlockPages|IoGetCurrentProcess|KeBugCheckEx",
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
