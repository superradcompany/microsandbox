use std::ffi::{CString, c_char};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Provider metadata is owned by this library and freed through msb_free_string.
#[unsafe(no_mangle)]
pub extern "C" fn msb_provider_info() -> *mut c_char {
    let json = serde_json::json!({
        "abi": 1,
        "version": env!("CARGO_PKG_VERSION"),
        "local": cfg!(feature = "local"),
        "remote": cfg!(feature = "remote"),
    });
    // JSON serialization escapes NUL bytes; the FFI receives one C string.
    CString::new(json.to_string())
        .expect("serialized provider metadata contains no NUL")
        .into_raw()
}
