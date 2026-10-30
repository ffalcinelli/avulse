// The one piece of the driver in C: locking a buffer of the calling process, which
// MmProbeAndLockPages reports by raising an exception that only structured exception handling
// (__try/__except, MSVC's, on x64 and ARM64 alike) can catch. Rust cannot. Built by build.rs.

#include <ntddk.h>

// Probes and locks the pages `mdl` describes for `op` (IoReadAccess, IoWriteAccess), as a caller
// in `mode` may: STATUS_SUCCESS, or the exception's code (an invalid or protected buffer), with the
// pages left unlocked.
NTSTATUS avulse_probe_and_lock(PMDL mdl, KPROCESSOR_MODE mode, LOCK_OPERATION op)
{
    __try {
        MmProbeAndLockPages(mdl, mode, op);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}
