//! Runtime setup uses the same paired resolver and installer as the Rust SDK.

use std::os::raw::{c_char, c_uchar};

use microsandbox::setup::{binding_install_options, binding_runtime_config};

use crate::{FfiError, cstr, run_c};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageRecoveryRequest {
    name: String,
    options: microsandbox::sandbox::StorageRecoveryOptions,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve, install, or ensure a runtime pair, returning its JSON description.
///
/// # Safety
/// Input strings must be NUL-terminated and the output buffer writable for `buf_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_runtime_setup(
    cancel_id: u64,
    operation: *const c_char,
    config_json: *const c_char,
    options_json: *const c_char,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let operation = unsafe { cstr(operation) }?;
        let config_json = unsafe { cstr(config_json) }?;
        let options_json = unsafe { cstr(options_json) }?;
        Ok(Box::pin(async move {
            if operation == "diagnose_storage" {
                return microsandbox::setup::binding_diagnose_storage(&config_json, &options_json)
                    .await
                    .map_err(FfiError::from);
            }
            if operation == "recover_storage" {
                // Existing optional ABI, new explicit operation; use the active SDK backend.
                let request: StorageRecoveryRequest = serde_json::from_str(&options_json)
                    .map_err(|error| FfiError::invalid_argument(error.to_string()))?;
                let result =
                    microsandbox::Sandbox::recover_storage(&request.name, request.options).await?;
                return serde_json::to_string(&result)
                    .map_err(|error| FfiError::internal(error.to_string()));
            }
            let config = binding_runtime_config(&config_json)?;
            let runtime = match operation.as_str() {
                "resolve" => microsandbox::setup::resolve_runtime(&config)?,
                "install" => {
                    microsandbox::setup::install_runtime(
                        &config,
                        binding_install_options(&options_json)?,
                    )
                    .await?
                }
                "ensure" => {
                    microsandbox::setup::ensure_runtime(
                        &config,
                        binding_install_options(&options_json)?,
                    )
                    .await?
                }
                _ => {
                    return Err(FfiError::invalid_argument(
                        "unknown runtime setup operation",
                    ));
                }
            };
            serde_json::to_string(&runtime).map_err(|error| FfiError::internal(error.to_string()))
        }))
    })
}
