//! The types avulse shares with its kernel drivers and its C ABI.
//!
//! The [`Address`] of a packet or event, the open [`Flags`], the queue [`Param`]eters, the
//! [`Shutdown`] directions, a handle's [`Stats`] and the filter [`Syntax`]: the `avulse` crate
//! re-exports them all. They are `no_std`, so that the Windows driver uses the same definitions,
//! and the address is `#[repr(C)]` and versioned, so that it crosses the C ABI as it is.
//! [`ioctl`] is the protocol between the user-mode backend and the Windows driver, and
//! [`windivert`] WinDivert's own address, for the WinDivert shim and the driver.

#![no_std]
#![forbid(unsafe_code)]

mod address;
mod flags;
pub mod ioctl;
mod stats;
mod syntax;
#[cfg(test)]
mod tests;
pub mod windivert;

pub use address::{
    ADDRESS_VERSION, Address, CONTEXT_LEN, Context, Flow, PROCESS_NAME_LEN, Reflect,
};
pub use flags::{Flags, Param, Shutdown};
pub use stats::Stats;
pub use syntax::Syntax;
