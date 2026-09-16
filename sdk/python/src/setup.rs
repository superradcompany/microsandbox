use pyo3::prelude::*;

use crate::error::to_py_err;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve an existing runtime pair without installing host binaries.
#[pyfunction]
pub fn resolve_runtime(config_json: String) -> PyResult<String> {
    let config = microsandbox::setup::binding_runtime_config(&config_json).map_err(to_py_err)?;
    let runtime = microsandbox::setup::resolve_runtime(&config).map_err(to_py_err)?;
    serialize_runtime(runtime)
}

/// Check whether a complete runtime pair resolves.
#[pyfunction]
pub fn is_runtime_installed(config_json: String) -> bool {
    resolve_runtime(config_json).is_ok()
}

/// Install a runtime pair from the explicitly selected source.
#[pyfunction]
pub fn install_runtime<'py>(
    py: Python<'py>,
    config_json: String,
    options_json: String,
) -> PyResult<Bound<'py, PyAny>> {
    let config = microsandbox::setup::binding_runtime_config(&config_json).map_err(to_py_err)?;
    let options = microsandbox::setup::binding_install_options(&options_json).map_err(to_py_err)?;
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let runtime = microsandbox::setup::install_runtime(&config, options)
            .await
            .map_err(to_py_err)?;
        serialize_runtime(runtime)
    })
}

/// Reuse a resolved pair and install only when it is wholly absent.
#[pyfunction]
pub fn ensure_runtime<'py>(
    py: Python<'py>,
    config_json: String,
    options_json: String,
) -> PyResult<Bound<'py, PyAny>> {
    let config = microsandbox::setup::binding_runtime_config(&config_json).map_err(to_py_err)?;
    let options = microsandbox::setup::binding_install_options(&options_json).map_err(to_py_err)?;
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let runtime = microsandbox::setup::ensure_runtime(&config, options)
            .await
            .map_err(to_py_err)?;
        serialize_runtime(runtime)
    })
}

fn serialize_runtime(runtime: microsandbox::setup::ResolvedRuntime) -> PyResult<String> {
    serde_json::to_string(&runtime)
        .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))
}

/// Register the wheel executable as a fallback after the runtime home.
#[pyfunction]
pub fn set_packaged_msb_path(path: String) {
    microsandbox::config::set_sdk_packaged_msb_path(path);
}

/// Resolve the CLI runtime without depending on the selected local/cloud backend.
#[pyfunction]
pub fn resolved_cli_msb_path() -> PyResult<String> {
    let config = microsandbox::config::load_persisted_config_or_default().map_err(to_py_err)?;
    microsandbox::setup::resolve_runtime(&config)
        .map(|runtime| runtime.msb_path.to_string_lossy().into_owned())
        .map_err(to_py_err)
}
