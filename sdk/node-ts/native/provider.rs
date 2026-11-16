use napi_derive::napi;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

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
