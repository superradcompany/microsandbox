//! `microsandbox-runtime` provides the runtime library for the sandbox
//! process entry point. This crate contains the unified VM + relay logic
//! that runs inside the single sandbox process.

#![warn(missing_docs)]

#[cfg(windows)]
mod bootstrap_fs;
mod clock;
mod error;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod boot_error;
pub mod console;
pub mod control;
pub mod exec_log;
pub mod heartbeat;
pub mod launch;
pub mod logging;
pub mod maintenance;
pub mod metrics;
pub mod policy;
pub mod relay;
mod startup;
pub mod vm;

pub use error::*;
