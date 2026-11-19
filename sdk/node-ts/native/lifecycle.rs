use microsandbox::sandbox::{DestroyOptions, RestartOptions};
use napi_derive::napi;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options for `restart`.
#[napi(object)]
pub struct SandboxRestartOptions {
    pub force: Option<bool>,
    pub timeout_ms: Option<u32>,
    pub detached: Option<bool>,
}

/// Options for `destroy`.
#[napi(object)]
pub struct SandboxDestroyOptions {
    pub force: Option<bool>,
    pub timeout_ms: Option<u32>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn restart_options(options: Option<SandboxRestartOptions>) -> RestartOptions {
    let mut result = RestartOptions::default();
    if let Some(options) = options {
        result.force = options.force.unwrap_or(result.force);
        result.detached = options.detached.unwrap_or(result.detached);
        if let Some(timeout_ms) = options.timeout_ms {
            result.timeout = std::time::Duration::from_millis(timeout_ms.into());
        }
    }
    result
}

pub(crate) fn destroy_options(options: Option<SandboxDestroyOptions>) -> DestroyOptions {
    let mut result = DestroyOptions::default();
    if let Some(options) = options {
        result.force = options.force.unwrap_or(result.force);
        if let Some(timeout_ms) = options.timeout_ms {
            result.timeout = std::time::Duration::from_millis(timeout_ms.into());
        }
    }
    result
}
