//! Platform passthrough filesystem backends.
//!
//! The public passthrough API stays stable at this module path while the
//! implementation lives under platform-specific submodules. Shared helpers
//! such as quota accounting live beside the platform modules.

pub(crate) mod quota;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::{HostPermissions, PassthroughConfig, PassthroughFs, StatVirtualization};
