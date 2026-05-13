use napi_derive::napi;

/// Set the `msb` binary path resolved by the JS SDK.
///
/// This avoids using `process.env` as an internal JS-to-native config channel.
#[napi(js_name = "setRuntimeMsbPath")]
pub fn set_runtime_msb_path(path: String) {
    microsandbox::config::set_sdk_msb_path(path);
}
