//! Sparse sandbox defaults captured from the launching host environment.
//!
//! Only ordinary default values are captured here. Ambient proxy endpoints,
//! `NO_PROXY` rules and URL credentials are never read SDK-side: they are
//! discovered by the runtime at each network-engine startup.

use std::ffi::OsStr;

use super::{GlobalConfigPatch, SandboxDefaultsPatch};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Host environment variable that supplies the ordinary ambient-proxy default.
pub(crate) const PROXY_FROM_ENV_VARIABLE: &str = "MSB_PROXY_FROM_ENV";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Interpret one `MSB_PROXY_FROM_ENV` value as a sparse ambient-proxy default.
///
/// Accepts trimmed, ASCII-case-insensitive `1,true,yes,on` and `0,false,no,off`.
/// Unset or empty is absent. Anything else, including a value that is not valid
/// Unicode, is an `InvalidConfig` error naming only the variable and its accepted
/// forms so a malformed value can never leak into an error or a log.
pub(crate) fn proxy_from_env_default(value: Option<&OsStr>) -> MicrosandboxResult<Option<bool>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(text) = value.to_str() else {
        return Err(invalid_toggle_error());
    };

    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    match trimmed.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => Err(invalid_toggle_error()),
    }
}

/// Capture the ordinary sandbox defaults supplied by the launching host environment.
pub(crate) fn capture_sandbox_defaults() -> MicrosandboxResult<GlobalConfigPatch> {
    let value = std::env::var_os(PROXY_FROM_ENV_VARIABLE);
    let enabled = proxy_from_env_default(value.as_deref())?;

    let mut defaults = SandboxDefaultsPatch::new();
    if let Some(enabled) = enabled {
        defaults.proxy_from_env_mut(enabled);
    }

    Ok(GlobalConfigPatch::new().sandbox_defaults(defaults))
}

fn invalid_toggle_error() -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!(
        "{PROXY_FROM_ENV_VARIABLE} must be one of 1, true, yes, on, 0, false, no, off"
    ))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{PROXY_FROM_ENV_VARIABLE, proxy_from_env_default};
    use crate::MicrosandboxError;

    #[test]
    fn proxy_from_env_values_are_parsed_sparsely() {
        for (raw, expected) in [
            ("1", Some(true)),
            ("true", Some(true)),
            ("TRUE", Some(true)),
            (" yes ", Some(true)),
            ("\ton\n", Some(true)),
            ("0", Some(false)),
            ("false", Some(false)),
            ("False", Some(false)),
            (" no ", Some(false)),
            ("OFF", Some(false)),
            ("", None),
            ("   ", None),
        ] {
            let value = OsString::from(raw);
            assert_eq!(
                proxy_from_env_default(Some(value.as_os_str())).unwrap(),
                expected,
                "raw value {raw:?}"
            );
        }

        assert_eq!(proxy_from_env_default(None).unwrap(), None);
    }

    #[test]
    fn proxy_from_env_rejects_unknown_values_without_echoing_them() {
        for raw in ["2", "maybe", "enabled", "definitely-not-a-toggle"] {
            let value = OsString::from(raw);
            let error = proxy_from_env_default(Some(value.as_os_str())).unwrap_err();
            let message = error.to_string();
            assert!(
                message.contains(PROXY_FROM_ENV_VARIABLE),
                "error must name the variable: {message}"
            );
            assert!(
                message.contains("1, true, yes, on"),
                "error must list accepted forms: {message}"
            );
            assert!(
                !message.contains(raw),
                "error must not echo the rejected value: {message}"
            );
            assert!(matches!(error, MicrosandboxError::InvalidConfig(_)));
        }
    }

    #[cfg(unix)]
    #[test]
    fn proxy_from_env_rejects_non_unicode_values() {
        use std::os::unix::ffi::OsStringExt;

        let value = OsString::from_vec(vec![b'1', 0xff]);
        let error = proxy_from_env_default(Some(value.as_os_str())).unwrap_err();
        assert!(matches!(error, MicrosandboxError::InvalidConfig(_)));
    }
}
