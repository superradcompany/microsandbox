//! Verification of microsandbox runtime dependencies.

use std::path::Path;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Verify that all required runtime dependencies are present.
pub(super) fn verify_installation(bin_dir: &Path, lib_dir: &Path) -> MicrosandboxResult<()> {
    let msb_name = microsandbox_utils::msb_binary_filename(std::env::consts::OS);
    let libkrunfw_name = microsandbox_utils::libkrunfw_filename(std::env::consts::OS);

    for (name, dir) in [
        (msb_name.as_str(), bin_dir),
        (libkrunfw_name.as_str(), lib_dir),
    ] {
        let path = dir.join(name);
        if !path.exists() {
            return Err(MicrosandboxError::Custom(format!(
                "{name} not found in {}",
                dir.display()
            )));
        }
    }

    Ok(())
}
