//! Platform passthrough filesystem backends.
//!
//! The public passthrough API stays stable at this module path while the
//! implementation lives under platform-specific submodules. Shared helpers
//! such as quota accounting live beside the platform modules.

mod external;
mod owned;
pub(crate) mod quota;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use external::ExternalCheckpointOptions;
pub(crate) use external::ExternalSingleFileIndex;
pub use owned::{OwnedDirectoryCheckpoint, OwnedDirectoryPayload, OwnedDirectorySnapshot};
#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::{HostPermissions, PassthroughConfig, PassthroughFs, StatVirtualization};
