use napi_derive::napi;

/// Register the platform package executable as a fallback after the runtime home.
#[napi(js_name = "setPackagedMsbPath")]
pub fn set_packaged_msb_path(path: String) {
    microsandbox::config::set_sdk_packaged_msb_path(path);
}

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
