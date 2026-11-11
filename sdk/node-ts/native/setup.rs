use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::error::to_napi_error;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Read an executable's embedded runtime version without starting it.
#[napi]
pub async fn resolve_runtime_version(executable: String) -> Result<Option<String>> {
    // File access can block on external storage; keep it off the async workers.
    tokio::task::spawn_blocking(move || {
        microsandbox::setup::resolve_runtime_version(executable)
            .map(|version| version.map(|version| version.to_string()))
            .map_err(to_napi_error)
    })
    .await
    .map_err(|error| Error::from_reason(format!("runtime version reader failed: {error}")))?
}

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

/// Inspect explicitly selected storage without initializing the normal backend.
#[napi]
pub async fn diagnose_storage(config_json: String, selection_json: String) -> Result<String> {
    let report = microsandbox::setup::binding_diagnose_storage(&config_json, &selection_json)
        .await
        .map_err(to_napi_error)?;
    // JSON numbers otherwise round u64 counters before the TypeScript wrapper sees them.
    // Only byte counters are decimal strings on this Node-specific wire boundary.
    let mut report: serde_json::Value =
        serde_json::from_str(&report).map_err(|error| Error::from_reason(error.to_string()))?;
    if let Some(sandboxes) = report["sandboxes"].as_array_mut() {
        for sandbox in sandboxes {
            let inspection = &mut sandbox["inspection"];
            stringify_counter(inspection, "estimated_bytes");
            if let Some(candidates) = inspection
                .get_mut("candidates")
                .and_then(serde_json::Value::as_array_mut)
            {
                for candidate in candidates {
                    stringify_counter(candidate, "estimated_bytes");
                    stringify_counter(candidate, "virtual_size");
                }
            }
        }
    }
    serde_json::to_string(&report).map_err(|error| Error::from_reason(error.to_string()))
}

fn stringify_counter(object: &mut serde_json::Value, key: &str) {
    if let Some(value) = object.get(key).and_then(serde_json::Value::as_u64) {
        object[key] = serde_json::Value::String(value.to_string());
    }
}
