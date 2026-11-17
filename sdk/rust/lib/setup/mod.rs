//! Setup and installation utilities for microsandbox runtime dependencies.

mod bindings;
mod host;
mod runtime;
#[cfg(feature = "local")]
mod storage;
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

#[cfg(feature = "local")]
#[doc(hidden)]
pub use bindings::binding_diagnose_storage;
#[doc(hidden)]
pub use bindings::{binding_install_options, binding_runtime_config};
pub use host::*;
pub use runtime::*;
#[cfg(feature = "local")]
pub use storage::*;
pub use version::{Version, resolve_runtime_version};
#[cfg(windows)]
pub use windows::*;
