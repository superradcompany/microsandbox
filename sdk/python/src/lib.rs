mod agent;
mod error;
mod exec;
mod fs;
mod helpers;
mod image;
mod logs;
mod metrics;
mod sandbox;
mod sandbox_handle;
mod setup;
mod snapshot;
mod ssh;
mod volume;

use std::sync::Arc;

use pyo3::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Restorable process-wide backend scope.
#[pyclass(name = "BackendScope")]
struct PyBackendScope {
    previous: Option<Arc<dyn microsandbox::Backend>>,
}

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
    m.add_function(wrap_pyfunction!(backend_scope, m)?)?;
    m.add_function(wrap_pyfunction!(default_backend_kind, m)?)?;
    m.add_function(wrap_pyfunction!(resolved_msb_path, m)?)?;
    m.add_function(wrap_pyfunction!(metrics::all_sandbox_metrics, m)?)?;
    m.add_class::<sandbox::PySandbox>()?;
    m.add_class::<sandbox::PySandboxStopResult>()?;
    m.add_class::<sandbox::PySandboxPingResult>()?;
    m.add_class::<sandbox::PySandboxTouchResult>()?;
    m.add_class::<sandbox_handle::PySandboxHandle>()?;
    m.add_class::<exec::PyExecOutput>()?;
    m.add_class::<exec::PyExecHandle>()?;
    m.add_class::<exec::PyExecSink>()?;
    m.add_class::<agent::PyAgentClient>()?;
    m.add_class::<fs::PySandboxFsOps>()?;
    m.add_class::<fs::PyFsReadStream>()?;
    m.add_class::<fs::PyFsWriteSink>()?;
    m.add_class::<image::PyImage>()?;
    m.add_class::<image::PyImageHandle>()?;
    m.add_class::<image::PyImageDetail>()?;
    m.add_class::<image::PyImageConfigDetail>()?;
    m.add_class::<image::PyImageLayerDetail>()?;
    m.add_class::<image::PyImagePruneReport>()?;
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
    m.add_class::<ssh::PySandboxSshOps>()?;
    m.add_class::<ssh::PySshOutput>()?;
    m.add_class::<ssh::PySshClient>()?;
    m.add_class::<ssh::PySftpClient>()?;
    m.add_class::<ssh::PySshServer>()?;
    m.add_class::<exec::PyExecEvent>()?;
    m.add_class::<fs::PyFsEntry>()?;
    m.add_class::<fs::PyFsMetadata>()?;
    m.add_class::<PyBackendScope>()?;
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
    microsandbox::set_default_backend(build_backend(kind, url, api_key, profile)?);
    Ok(())
}

/// Temporarily replace the process-wide default backend.
///
/// Use as a regular context manager, including inside async functions:
///
/// ```python
/// with backend_scope("cloud", profile="dev"):
///     sandbox = await Sandbox.create("x", image="alpine:3.19")
/// ```
///
/// This is process-wide while active, not task-local. Concurrent work in the
/// same process can observe the temporary backend.
#[pyfunction]
#[pyo3(signature = (kind, *, url=None, api_key=None, profile=None))]
fn backend_scope(
    kind: String,
    url: Option<String>,
    api_key: Option<String>,
    profile: Option<String>,
) -> PyResult<PyBackendScope> {
    let previous = microsandbox::swap_default_backend(build_backend(kind, url, api_key, profile)?);
    Ok(PyBackendScope {
        previous: Some(previous),
    })
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
    local
        .config()
        .resolve_msb_path()
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(error::to_py_err)
}

fn build_backend(
    kind: String,
    url: Option<String>,
    api_key: Option<String>,
    profile: Option<String>,
) -> PyResult<Arc<dyn microsandbox::Backend>> {
    match kind.trim().to_ascii_lowercase().as_str() {
        "local" => Ok(Arc::new(microsandbox::LocalBackend::lazy())),
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
            Ok(Arc::new(cloud))
        }
        other => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "backend kind must be 'local' or 'cloud', got {other:?}"
        ))),
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PyBackendScope {
    fn __enter__(slf: PyRefMut<'_, Self>) -> PyRefMut<'_, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _exc_type: &Bound<'_, PyAny>,
        _exc_value: &Bound<'_, PyAny>,
        _traceback: &Bound<'_, PyAny>,
    ) -> bool {
        self.restore_inner();
        false
    }

    /// Restore the backend that was active before this scope was created.
    fn restore(&mut self) {
        self.restore_inner();
    }
}

impl PyBackendScope {
    fn restore_inner(&mut self) {
        if let Some(previous) = self.previous.take() {
            microsandbox::set_default_backend(previous);
        }
    }
}

impl Drop for PyBackendScope {
    fn drop(&mut self) {
        self.restore_inner();
    }
}
