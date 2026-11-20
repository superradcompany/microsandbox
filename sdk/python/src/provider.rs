use pyo3::prelude::*;

#[cfg(all(feature = "provider-package", feature = "local", feature = "remote"))]
compile_error!("provider-package requires exactly one of local or remote");
#[cfg(all(
    feature = "provider-package",
    not(any(feature = "local", feature = "remote"))
))]
compile_error!("provider-package requires local or remote");

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Shared enums and errors must come from the same public package as wrappers.
pub(crate) fn public_module(suffix: &str) -> String {
    let package = if cfg!(feature = "provider-package") {
        "microsandbox_core"
    } else {
        "microsandbox"
    };
    format!("{package}.{suffix}")
}

#[pyfunction]
pub(crate) fn configured_provider_kind() -> PyResult<&'static str> {
    microsandbox::context::configured_provider_kind()
        .map(|kind| kind.as_str())
        .map_err(crate::error::to_py_err)
}

#[pyfunction]
pub(crate) fn provider_info() -> String {
    serde_json::json!({
        "abi": 1,
        "version": env!("CARGO_PKG_VERSION"),
        "local": cfg!(feature = "local"),
        "remote": cfg!(feature = "remote"),
    })
    .to_string()
}

#[cfg(not(feature = "provider-package"))]
#[pymodule]
fn _microsandbox(module: &Bound<'_, PyModule>) -> PyResult<()> {
    crate::runtime::register(module)?;
    crate::register_native(module)
}

#[cfg(all(feature = "provider-package", feature = "local"))]
#[pymodule]
fn _microsandbox_local(module: &Bound<'_, PyModule>) -> PyResult<()> {
    crate::runtime::register(module)?;
    crate::register_native(module)
}

#[cfg(all(feature = "provider-package", feature = "remote"))]
#[pymodule]
fn _microsandbox_remote(module: &Bound<'_, PyModule>) -> PyResult<()> {
    crate::runtime::register(module)?;
    crate::register_native(module)
}
