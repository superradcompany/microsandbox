//! Standalone OCI runtime binary integration for Microsandbox.
#![cfg(all(target_os = "linux", feature = "runmsb"))]

mod console;
mod options;
mod process;
mod requests;
mod runtime;
mod sandbox;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use options::{CreateOptions, DeleteOptions, ExecOptions, KillOptions};
pub use runtime::MicrosandboxOciRuntime;
