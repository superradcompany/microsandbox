//! `microsandbox-runtime` provides the runtime library for the supervisor
//! and microVM entry points. This crate contains all logic that runs in the
//! supervisor and VM child processes.
//!
//! The supervisor monitors child processes, handles signals, manages the
//! drain lifecycle, and records termination data. The VM entry point
//! configures and enters the microVM via msb_krun.

#![warn(missing_docs)]

mod error;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub mod drain;
pub mod heartbeat;
pub mod logging;
pub mod monitor;
pub mod policy;
pub mod relay;
pub mod supervisor;
pub mod termination;
pub mod vm;

pub use error::*;
