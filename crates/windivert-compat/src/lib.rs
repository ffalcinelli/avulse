//! WinDivert's API over avulse, so that programs written for WinDivert, and the bindings that
//! wrap it, run on avulse unchanged.
//!
//! On Linux the library is `libavulse_windivert.so` and exports libebpfdivert's C API
//! (`ebpfdivert_open`, `ebpfdivert_recv`, …, declared in ebpfdivert's `include/ebpfdivert.h`),
//! which is WinDivert 2.2's with Linux conventions: negative `errno` values, and the 80-byte
//! `WINDIVERT_ADDRESS`. pydivert and jdivert load it in place of libebpfdivert
//! (`PYDIVERT_EBPFDIVERT_LIB`, `-Debpfdivert.local`).
//!
//! The parts that do not depend on the platform are public, for the tests and for the Windows
//! exports to come: [`WdAddress`] and its conversion to [`avulse::Address`], and WinDivert's
//! helpers ([`helpers`]), which give WinDivert's results byte for byte.

mod address;
#[cfg(target_os = "linux")]
pub mod ebpfdivert;
pub mod helpers;
mod packet;
#[cfg(test)]
mod tests;

pub use address::{BadAddress, CONTEXT_KEPT, WdAddress};
