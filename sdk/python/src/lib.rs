mod agent;
mod error;
mod exec;
mod fs;
mod helpers;
mod logs;
mod metrics;
mod sandbox;
mod sandbox_handle;
mod setup;
mod snapshot;
mod ssh;
mod volume;

use pyo3::prelude::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// The `_microsandbox` native extension module.
#[pymodule]
fn _microsandbox(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(setup::install, m)?)?;
    m.add_function(wrap_pyfunction!(setup::is_installed, m)?)?;
    m.add_function(wrap_pyfunction!(set_runtime_msb_path, m)?)?;
    m.add_function(wrap_pyfunction!(set_runtime_libkrunfw_path, m)?)?;
    m.add_function(wrap_pyfunction!(set_default_backend, m)?)?;
    m.add_function(wrap_pyfunction!(default_backend_kind, m)?)?;
    m.add_function(wrap_pyfunction!(resolved_msb_path, m)?)?;
    m.add_function(wrap_pyfunction!(metrics::all_sandbox_metrics, m)?)?;
    m.add_class::<sandbox::PySandbox>()?;
    m.add_class::<sandbox_handle::PySandboxHandle>()?;
    m.add_class::<exec::PyExecOutput>()?;
    m.add_class::<exec::PyExecHandle>()?;
    m.add_class::<exec::PyExecSink>()?;
    m.add_class::<agent::PyAgentClient>()?;
    m.add_class::<fs::PySandboxFs>()?;
    m.add_class::<fs::PyFsReadStream>()?;
    m.add_class::<fs::PyFsWriteSink>()?;
    m.add_class::<volume::PyVolume>()?;
    m.add_class::<volume::PyVolumeHandle>()?;
    m.add_class::<volume::PyVolumeFs>()?;
    m.add_class::<snapshot::PySnapshot>()?;
    m.add_class::<snapshot::PySnapshotHandle>()?;
    m.add_class::<metrics::PyMetricsStream>()?;
    m.add_class::<metrics::PySandboxMetrics>()?;
    m.add_class::<logs::PyLogEntry>()?;
    m.add_class::<logs::PyLogStream>()?;
    m.add_class::<sandbox::PyPullSession>()?;
    m.add_class::<ssh::PySandboxSsh>()?;
    m.add_class::<ssh::PySshOutput>()?;
    m.add_class::<ssh::PySshClient>()?;
    m.add_class::<ssh::PySftpClient>()?;
    m.add_class::<ssh::PySshServer>()?;
    m.add_class::<exec::PyExecEvent>()?;
    m.add_class::<fs::PyFsEntry>()?;
    m.add_class::<fs::PyFsMetadata>()?;
    Ok(())
}

/// Return the SDK version string.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Set the `msb` binary path resolved by the Python SDK.
#[pyfunction]
fn set_runtime_msb_path(path: String) {
    microsandbox::config::set_sdk_msb_path(path);
}

/// Set the `libkrunfw` shared library path resolved by the Python SDK.
///
/// Process-level setter — one dylib per process address space, so this is the
/// natural granularity. User env (`MSB_LIBKRUNFW_PATH`) still wins. Mirrors
/// `set_runtime_msb_path` for libkrunfw.
#[pyfunction]
fn set_runtime_libkrunfw_path(path: String) {
    microsandbox::config::set_sdk_libkrunfw_path(path);
}

/// Set the process-wide default backend.
///
/// `kind="local"` selects the local libkrun backend. `kind="cloud"` requires
/// either `url` + `api_key`, or `profile`.
#[pyfunction]
#[pyo3(signature = (kind, *, url=None, api_key=None, profile=None))]
fn set_default_backend(
    kind: String,
    url: Option<String>,
    api_key: Option<String>,
    profile: Option<String>,
) -> PyResult<()> {
    match kind.trim().to_ascii_lowercase().as_str() {
        "local" => microsandbox::set_default_backend(microsandbox::LocalBackend::lazy()),
        "cloud" => {
            let cloud = if let Some(profile) = profile {
                microsandbox::CloudBackend::from_profile(&profile)
            } else {
                let url = url.ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(
                        "cloud backend requires url + api_key or profile",
                    )
                })?;
                let api_key = api_key.ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(
                        "cloud backend requires url + api_key or profile",
                    )
                })?;
                microsandbox::CloudBackend::new(url, api_key)
            }
            .map_err(error::to_py_err)?;
            microsandbox::set_default_backend(cloud);
        }
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "backend kind must be 'local' or 'cloud', got {other:?}"
            )));
        }
    }
    Ok(())
}

/// Return the active default backend kind (`"local"` or `"cloud"`).
#[pyfunction]
fn default_backend_kind() -> &'static str {
    match microsandbox::default_backend().kind() {
        microsandbox::BackendKind::Local => "local",
        microsandbox::BackendKind::Cloud => "cloud",
    }
}

/// Return the `msb` binary path the native resolver would currently use.
///
/// Intended as a test/diagnostic hook for verifying the Python-to-native bridge.
#[pyfunction]
fn resolved_msb_path() -> PyResult<String> {
    let backend = microsandbox::backend::default_backend();
    let local = backend.as_local().ok_or_else(|| {
        error::to_py_err(microsandbox::MicrosandboxError::Unsupported {
            feature: "resolved_msb_path requires a local backend".into(),
            available_when: "with a local backend".into(),
        })
    })?;
    microsandbox::config::resolve_msb_path(local.config())
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(error::to_py_err)
}
