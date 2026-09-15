//! Setup and installation utilities for microsandbox runtime dependencies.

mod bindings;
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

#[doc(hidden)]
pub use bindings::{binding_install_options, binding_runtime_config};
pub use host::*;
pub use runtime::*;
#[cfg(windows)]
pub use windows::*;
