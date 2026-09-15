use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::to_napi_error;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve the existing runtime pair without installing host binaries.
#[napi]
pub fn resolve_runtime(config_json: String) -> Result<String> {
    let config =
        microsandbox::setup::binding_runtime_config(&config_json).map_err(to_napi_error)?;
    let runtime = microsandbox::setup::resolve_runtime(&config).map_err(to_napi_error)?;
    serialize_runtime(runtime)
}

/// Check whether a complete runtime pair resolves.
#[napi]
pub fn is_runtime_installed(config_json: String) -> bool {
    resolve_runtime(config_json).is_ok()
}

/// Explicitly install a runtime pair from the selected source.
#[napi]
pub async fn install_runtime(config_json: String, options_json: String) -> Result<String> {
    let config =
        microsandbox::setup::binding_runtime_config(&config_json).map_err(to_napi_error)?;
    let options =
        microsandbox::setup::binding_install_options(&options_json).map_err(to_napi_error)?;
    let runtime = microsandbox::setup::install_runtime(&config, options)
        .await
        .map_err(to_napi_error)?;
    serialize_runtime(runtime)
}

/// Reuse a resolved pair and install only when it is wholly absent.
#[napi]
pub async fn ensure_runtime(config_json: String, options_json: String) -> Result<String> {
    let config =
        microsandbox::setup::binding_runtime_config(&config_json).map_err(to_napi_error)?;
    let options =
        microsandbox::setup::binding_install_options(&options_json).map_err(to_napi_error)?;
    let runtime = microsandbox::setup::ensure_runtime(&config, options)
        .await
        .map_err(to_napi_error)?;
    serialize_runtime(runtime)
}

fn serialize_runtime(runtime: microsandbox::setup::ResolvedRuntime) -> Result<String> {
    serde_json::to_string(&runtime).map_err(|error| Error::from_reason(error.to_string()))
}
