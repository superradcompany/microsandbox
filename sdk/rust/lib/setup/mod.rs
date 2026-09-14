//! Setup and installation utilities for microsandbox runtime dependencies.

mod host;
mod runtime;
mod verify;
mod version;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use host::*;
pub use runtime::*;
pub use version::{Version, resolve_runtime_version};
#[cfg(windows)]
pub use windows::*;
