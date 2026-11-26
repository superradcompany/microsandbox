mod agent;
mod context;
mod conversion;
mod error;
mod exec;
mod fs;
mod helpers;
mod image;
mod jobs;
mod logs;
mod metrics;
mod provider;
mod resize;
mod runtime;
mod sandbox;
mod service;
mod setup;
mod snapshot;
mod snapshot_group;
mod ssh;
mod stdio;
mod storage;
mod volume;

use pyo3::prelude::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// The `_microsandbox` native extension module.
pub(crate) fn register_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(provider::configured_provider_kind, m)?)?;
    m.add_function(wrap_pyfunction!(provider::provider_info, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(setup::resolve_runtime, m)?)?;
    m.add_function(wrap_pyfunction!(setup::diagnose_storage, m)?)?;
    m.add_function(wrap_pyfunction!(setup::is_runtime_installed, m)?)?;
    m.add_function(wrap_pyfunction!(setup::install_runtime, m)?)?;
    m.add_function(wrap_pyfunction!(setup::ensure_runtime, m)?)?;
    m.add_function(wrap_pyfunction!(set_runtime_msb_path, m)?)?;
    m.add_function(wrap_pyfunction!(setup::set_packaged_msb_path, m)?)?;
    m.add_function(wrap_pyfunction!(set_runtime_libkrunfw_path, m)?)?;
    m.add_function(wrap_pyfunction!(resolved_msb_path, m)?)?;
    m.add_function(wrap_pyfunction!(setup::resolved_cli_msb_path, m)?)?;
    m.add_function(wrap_pyfunction!(metrics::all_sandbox_metrics, m)?)?;
    m.add_class::<context::PyContext>()?;
    m.add_function(wrap_pyfunction!(context::configured_context, m)?)?;
    m.add_class::<context::PySandboxes>()?;
    m.add_class::<context::PyVolumes>()?;
    m.add_class::<context::PySnapshots>()?;
    m.add_class::<context::PyCheckpoints>()?;
    m.add_class::<sandbox::PySandbox>()?;
    m.add_class::<sandbox::PyStorageRecovery>()?;
    m.add_class::<sandbox::PyForkOutcome>()?;
    // Preserve the old class identity for callers using isinstance on batch outcomes.
    m.add("BranchOutcome", m.getattr("ForkOutcome")?)?;
    m.add_class::<sandbox::PySandboxStopResult>()?;
    m.add_class::<sandbox::PySandboxPingResult>()?;
    m.add_class::<sandbox::PySandboxTouchResult>()?;
    m.add_class::<sandbox::PyExternalMountWarning>()?;
    m.add_class::<sandbox::PySandboxPage>()?;
    m.add_class::<jobs::PyJob>()?;
    m.add_class::<jobs::PyJobAttachment>()?;
    m.add_class::<jobs::PyJobLogStream>()?;
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
    m.add_class::<storage::PyStorage>()?;
    m.add_class::<storage::PyStorageUsage>()?;
    m.add_class::<storage::PyStorageCategoryUsage>()?;
    m.add_class::<storage::PyStorageItemUsage>()?;
    m.add_class::<storage::PyMemoryCacheEntry>()?;
    m.add_class::<storage::PyMemoryCacheReport>()?;
    m.add_class::<volume::PyVolume>()?;
    m.add_class::<volume::PyVolumeFs>()?;
    m.add_class::<service::PyService>()?;
    m.add_class::<service::PyServicePage>()?;
    m.add_class::<snapshot::PySnapshot>()?;
    m.add_class::<snapshot_group::PySnapshotGroup>()?;
    m.add_class::<snapshot_group::PySnapshotCreateResult>()?;
    m.add_class::<snapshot_group::PySnapshotImportResult>()?;
    m.add_class::<snapshot_group::PyCheckpointCaptureResult>()?;
    m.add_class::<snapshot::PySnapshotArchive>()?;
    m.add_class::<snapshot::PyCheckpointRemoveResult>()?;
    m.add_class::<snapshot_group::PySnapshotRemoveResult>()?;
    m.add_class::<snapshot::PySnapshotCopyBuilder>()?;
    m.add_class::<metrics::PyMetricsStream>()?;
    m.add_class::<metrics::PySandboxMetrics>()?;
    m.add_class::<logs::PyLogEntry>()?;
    m.add_class::<logs::PyLogStream>()?;
    m.add_class::<sandbox::PyPullSession>()?;
    m.add_class::<sandbox::PyPullProgressIter>()?;
    m.add_class::<sandbox::PyPullEvent>()?;
    m.add_class::<ssh::PySandboxSshOps>()?;
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

/// Return the `msb` binary path the native resolver would currently use.
///
/// Intended as a test/diagnostic hook for verifying the Python-to-native bridge.
#[pyfunction]
fn resolved_msb_path() -> PyResult<String> {
    #[cfg(not(feature = "local"))]
    {
        Err(error::local_only("resolved_msb_path"))
    }
    #[cfg(feature = "local")]
    {
        let backend = microsandbox::context::configured_context();
        let local = backend
            .as_local()
            .ok_or_else(|| error::local_only("resolved_msb_path"))?;
        microsandbox::setup::resolve_runtime(local.config())
            .map(|runtime| runtime.msb_path.to_string_lossy().into_owned())
            .map_err(error::to_py_err)
    }
}
