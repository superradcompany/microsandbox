//! Utility functions for working with environment variables.

use std::path::PathBuf;

use crate::{DEFAULT_MICROSANDBOX_HOME, DEFAULT_OCI_REGISTRY};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Environment variable for the microsandbox home directory
pub const MICROSANDBOX_HOME_ENV_VAR: &str = "MICROSANDBOX_HOME";

/// Environment variable for the OCI registry domain
pub const OCI_REGISTRY_ENV_VAR: &str = "OCI_REGISTRY_DOMAIN";

/// Environment variable for the msbrun binary path
pub const MSBRUN_EXE_ENV_VAR: &str = "MSBRUN_EXE";

/// Environment variable for the msbserver binary path
pub const MSBSERVER_EXE_ENV_VAR: &str = "MSBSERVER_EXE";

/// Environment variable for the FEX-Emulator rootfs path
#[cfg(target_os = "macos")]
pub const FEX_EMU_PATH_ENV_VAR: &str = "FEX_EMU_PATH";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Returns the path to the microsandbox home directory.
/// If the MICROSANDBOX_HOME environment variable is set, returns that path.
/// Otherwise, returns the default microsandbox home path.
pub fn get_microsandbox_home_path() -> PathBuf {
    if let Ok(microsandbox_home) = std::env::var(MICROSANDBOX_HOME_ENV_VAR) {
        PathBuf::from(microsandbox_home)
    } else {
        DEFAULT_MICROSANDBOX_HOME.to_owned()
    }
}

/// Returns the domain for the OCI registry.
/// If the OCI_REGISTRY_DOMAIN environment variable is set, returns that value.
/// Otherwise, returns the default OCI registry domain.
pub fn get_oci_registry() -> String {
    if let Ok(oci_registry_domain) = std::env::var(OCI_REGISTRY_ENV_VAR) {
        oci_registry_domain
    } else {
        DEFAULT_OCI_REGISTRY.to_string()
    }
}

/// Returns the path to the FEX-Emu rootfs directory.
/// If the FEX_EMU_PATH environment variable is set, returns that path.
/// Otherwise, returns the default FEX-Emu path (~/.local/share/microsandbox/fex-emu).
#[cfg(target_os = "macos")]
pub fn get_fex_emulator_path() -> PathBuf {
    if let Ok(fex_emu_path) = std::env::var(FEX_EMU_PATH_ENV_VAR) {
        PathBuf::from(fex_emu_path)
    } else {
        crate::DEFAULT_FEX_EMU_PATH.to_owned()
    }
}
