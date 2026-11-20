use napi_derive::napi;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Read selection before choosing a provider-specific native library.
#[napi]
pub fn configured_provider_kind() -> napi::Result<String> {
    microsandbox::context::configured_provider_kind()
        .map(|kind| kind.as_str().to_owned())
        .map_err(crate::error::to_napi_error)
}

/// Package loaders validate this before accepting any native objects.
#[napi]
pub fn provider_info() -> String {
    serde_json::json!({
        "abi": 1,
        "version": env!("CARGO_PKG_VERSION"),
        "local": cfg!(feature = "local"),
        "remote": cfg!(feature = "remote"),
    })
    .to_string()
}
