//! Verification of microsandbox runtime dependencies.

use std::path::Path;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Verify that all required runtime dependencies are present in the given lib directory.
pub(super) fn verify_installation(lib_dir: &Path) -> MicrosandboxResult<()> {
    let primary = microsandbox_utils::libkrunfw_filename(std::env::consts::OS);

    let path = lib_dir.join(&primary);
    if !path.exists() {
        return Err(MicrosandboxError::LibkrunfwNotFound(format!(
            "{} not found in {}",
            primary,
            lib_dir.display()
        )));
    }

    Ok(())
}
