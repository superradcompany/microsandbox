//! Platform passthrough filesystem backends.
//!
//! The public passthrough API stays stable at this module path while the
//! implementation lives under platform-specific submodules.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

#[cfg(unix)]
pub(crate) use unix::inode;
#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::{HostPermissions, PassthroughConfig, PassthroughFs, StatVirtualization};
