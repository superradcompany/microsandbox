mod config;
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
