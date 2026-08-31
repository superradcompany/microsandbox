//! Shared host-runtime contracts and the optional sandbox VM runner.
//!
//! The `client` feature exposes launch, IPC, control, logging, and maintenance
//! contracts used by SDKs. The `runner` feature adds the VM, relay, metrics,
//! console, and host-control implementation linked into the `msb` process.

#![warn(missing_docs)]

#[cfg(feature = "client")]
mod client;
mod error;
#[cfg(feature = "runner")]
mod runner;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "client")]
pub use client::{boot_error, control, ipc, launch, logging, maintenance};
#[cfg(feature = "runner")]
pub use runner::{console, cpu, exec_log, heartbeat, metrics, policy, relay, vm};
#[cfg(all(feature = "client", not(feature = "runner")))]
/// Backward-compatible access to the process-launch contract without the VM runner.
pub mod vm {
    pub use crate::launch::*;
}
#[cfg(all(feature = "runner", windows))]
pub(crate) use runner::bootstrap_fs;
#[cfg(feature = "runner")]
pub(crate) use runner::{clock, startup, writeback};

pub use error::*;
