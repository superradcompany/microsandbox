//! Setup and installation utilities for microsandbox runtime dependencies.

mod host;
mod runtime;
mod verify;

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
#[cfg(windows)]
pub use windows::*;
