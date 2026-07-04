//! Runtime gating for experimental SDK surfaces.

use std::ffi::OsStr;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Environment variable that enables the experimental sandbox modification surface: `modify`, `restart`, `touch`, `ping`, and boot-time max CPU/memory capacity.
pub const MODIFY_ENV: &str = "MSB_EXPERIMENTAL_MODIFY";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Whether the experimental modify/live-resize surface is enabled for this process.
///
/// The gate is read from [`MODIFY_ENV`] on every call so embedders and tests can toggle it without process restarts.
pub fn modify_enabled() -> bool {
    std::env::var_os(MODIFY_ENV).is_some_and(|value| env_enables(&value))
}

/// Fail with [`MicrosandboxError::Experimental`] unless the modify surface is enabled.
pub(crate) fn require_modify(feature: &str) -> MicrosandboxResult<()> {
    if modify_enabled() {
        return Ok(());
    }
    Err(MicrosandboxError::Experimental {
        feature: feature.to_string(),
        env: MODIFY_ENV,
    })
}

fn env_enables(value: &OsStr) -> bool {
    value.to_str().is_some_and(|value| {
        ["1", "true", "yes", "on"]
            .iter()
            .any(|enabled| value.eq_ignore_ascii_case(enabled))
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognized_values_enable_the_gate() {
        for value in ["1", "true", "TRUE", "yes", "on", "On"] {
            assert!(env_enables(OsStr::new(value)), "{value} should enable");
        }
    }

    #[test]
    fn unrecognized_values_leave_the_gate_off() {
        for value in ["", "0", "false", "no", "off", "2", "enable"] {
            assert!(!env_enables(OsStr::new(value)), "{value} should not enable");
        }
    }
}
