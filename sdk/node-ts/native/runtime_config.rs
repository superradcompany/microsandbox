use napi_derive::napi;

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
    match kind.trim().to_ascii_lowercase().as_str() {
        "local" => microsandbox::set_default_backend(microsandbox::LocalBackend::lazy()),
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
            microsandbox::set_default_backend(cloud);
        }
        other => {
            return Err(napi::Error::from_reason(format!(
                "backend kind must be 'local' or 'cloud', got {other:?}"
            )));
        }
    }
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
