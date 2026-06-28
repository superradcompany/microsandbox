//! Setup and installation utilities for microsandbox runtime dependencies.

mod download;
mod host;
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

pub use download::*;
pub use host::*;
#[cfg(windows)]
pub use windows::*;
