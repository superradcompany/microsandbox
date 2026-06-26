use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use napi_derive::napi;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

static NEXT_BACKEND_SCOPE: AtomicU32 = AtomicU32::new(1);
static BACKEND_SCOPES: OnceLock<Mutex<HashMap<u32, Arc<dyn microsandbox::Backend>>>> =
    OnceLock::new();

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Set the `msb` binary path resolved by the JS SDK.
///
/// This avoids using `process.env` as an internal JS-to-native config channel.
#[napi(js_name = "setRuntimeMsbPath")]
pub fn set_runtime_msb_path(path: String) {
    microsandbox::config::set_sdk_msb_path(path);
}

/// Set the `libkrunfw` shared library path resolved by the JS SDK.
///
/// Process-level setter — one dylib per process address space, so this is the
/// natural granularity. User env (`MSB_LIBKRUNFW_PATH`) still wins as tier 1.
/// Mirrors `setRuntimeMsbPath` for libkrunfw.
#[napi(js_name = "setRuntimeLibkrunfwPath")]
pub fn set_runtime_libkrunfw_path(path: String) {
    microsandbox::config::set_sdk_libkrunfw_path(path);
}

/// Set the process-wide default backend.
///
/// `kind="local"` selects the local backend. `kind="cloud"` requires either
/// `url` + `api_key`, or `profile`.
#[napi(js_name = "setDefaultBackend")]
pub fn set_default_backend(
    kind: String,
    url: Option<String>,
    api_key: Option<String>,
    profile: Option<String>,
) -> napi::Result<()> {
    microsandbox::set_default_backend(build_backend(kind, url, api_key, profile)?);
    Ok(())
}

/// Temporarily replace the process-wide default backend and return a scope token.
///
/// The caller must pass the returned token to `popDefaultBackend`; concurrent
/// JavaScript work in the same process can observe the temporary backend.
#[napi(js_name = "pushDefaultBackend")]
pub fn push_default_backend(
    kind: String,
    url: Option<String>,
    api_key: Option<String>,
    profile: Option<String>,
) -> napi::Result<u32> {
    let previous = microsandbox::swap_default_backend(build_backend(kind, url, api_key, profile)?);
    let token = NEXT_BACKEND_SCOPE.fetch_add(1, Ordering::Relaxed);
    backend_scopes()
        .lock()
        .map_err(|_| napi::Error::from_reason("backend scope registry poisoned"))?
        .insert(token, previous);
    Ok(token)
}

/// Restore the backend saved by `pushDefaultBackend`.
#[napi(js_name = "popDefaultBackend")]
pub fn pop_default_backend(token: u32) -> napi::Result<()> {
    let previous = backend_scopes()
        .lock()
        .map_err(|_| napi::Error::from_reason("backend scope registry poisoned"))?
        .remove(&token)
        .ok_or_else(|| napi::Error::from_reason("unknown backend scope token"))?;
    microsandbox::set_default_backend(previous);
    Ok(())
}

/// Return the active default backend kind (`"local"` or `"cloud"`).
#[napi(js_name = "defaultBackendKind")]
pub fn default_backend_kind() -> &'static str {
    match microsandbox::default_backend().kind() {
        microsandbox::BackendKind::Local => "local",
        microsandbox::BackendKind::Cloud => "cloud",
    }
}

fn build_backend(
    kind: String,
    url: Option<String>,
    api_key: Option<String>,
    profile: Option<String>,
) -> napi::Result<Arc<dyn microsandbox::Backend>> {
    match kind.trim().to_ascii_lowercase().as_str() {
        "local" => Ok(Arc::new(microsandbox::LocalBackend::lazy())),
        "cloud" => {
            let cloud = if let Some(profile) = profile {
                microsandbox::CloudBackend::from_profile(&profile)
            } else {
                let url = url.ok_or_else(|| {
                    napi::Error::from_reason("cloud backend requires url + apiKey or profile")
                })?;
                let api_key = api_key.ok_or_else(|| {
                    napi::Error::from_reason("cloud backend requires url + apiKey or profile")
                })?;
                microsandbox::CloudBackend::new(url, api_key)
            }
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
            Ok(Arc::new(cloud))
        }
        other => Err(napi::Error::from_reason(format!(
            "backend kind must be 'local' or 'cloud', got {other:?}"
        ))),
    }
}

fn backend_scopes() -> &'static Mutex<HashMap<u32, Arc<dyn microsandbox::Backend>>> {
    BACKEND_SCOPES.get_or_init(|| Mutex::new(HashMap::new()))
}
