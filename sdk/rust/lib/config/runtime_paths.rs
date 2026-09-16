//! Package discovery is separate from explicit process-level runtime overrides.

use std::{path::PathBuf, sync::OnceLock};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

static SDK_PACKAGED_MSB_PATH: OnceLock<PathBuf> = OnceLock::new();

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Register an automatically discovered package executable as a home-first fallback.
///
/// The matching library is resolved beside the executable or under `../lib`.
/// Registration does not access the filesystem. Set-once: subsequent calls are ignored.
pub fn set_sdk_packaged_msb_path(path: impl Into<PathBuf>) {
    let _ = SDK_PACKAGED_MSB_PATH.set(path.into());
}

pub(crate) fn sdk_packaged_msb_path() -> Option<PathBuf> {
    SDK_PACKAGED_MSB_PATH.get().cloned()
}
