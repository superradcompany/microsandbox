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
    m.add_function(wrap_pyfunction!(resolved_msb_path, m)?)?;
    m.add_function(wrap_pyfunction!(metrics::all_sandbox_metrics, m)?)?;
    m.add_class::<sandbox::PySandbox>()?;
    m.add_class::<sandbox_handle::PySandboxHandle>()?;
    m.add_class::<exec::PyExecOutput>()?;
    m.add_class::<exec::PyExecHandle>()?;
    m.add_class::<exec::PyExecSink>()?;
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
    m.add_class::<sandbox::PyPullSession>()?;
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

/// Return the `msb` binary path the native resolver would currently use.
///
/// Intended as a test/diagnostic hook for verifying the Python-to-native bridge.
#[pyfunction]
fn resolved_msb_path() -> PyResult<String> {
    microsandbox::config::resolve_msb_path()
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(error::to_py_err)
}
