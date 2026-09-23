//! Structured storage observations and explicitly requested runtime-cache pruning.

use std::sync::Arc;
use std::time::Duration;

use microsandbox::storage::{
    MemoryCacheEntry, MemoryCacheKind, MemoryCacheReport, MemoryCacheState, MemoryPruneOptions,
};
use microsandbox::{Storage, StorageCategoryUsage, StorageItemUsage, StorageUsage};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyInt};

use crate::error::to_py_err;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Storage operations against the backend selected when the method is called.
#[pyclass(name = "Storage")]
pub struct PyStorage;

/// Storage totals and accounting limitations for the selected backend.
#[pyclass(name = "StorageUsage", get_all, frozen)]
#[derive(Clone)]
pub struct PyStorageUsage {
    images: PyStorageCategoryUsage,
    snapshots: PyStorageCategoryUsage,
    sandboxes: PyStorageCategoryUsage,
    volumes: PyStorageCategoryUsage,
    branch_memory: PyStorageCategoryUsage,
    snapshot_memory: PyStorageCategoryUsage,
    notes: Vec<String>,
}

/// Category observations; absent counts and byte values mean unknown, never zero.
#[pyclass(name = "StorageCategoryUsage", get_all, frozen)]
#[derive(Clone)]
pub struct PyStorageCategoryUsage {
    count: Option<u64>,
    in_use: Option<u64>,
    logical_bytes: Option<u64>,
    allocated_bytes: Option<u64>,
    reclaimable_logical_bytes: Option<u64>,
    items: Vec<PyStorageItemUsage>,
    notes: Vec<String>,
}

/// One object's storage, retention reasons, and ownership observations.
#[pyclass(name = "StorageItemUsage", get_all, frozen)]
#[derive(Clone)]
pub struct PyStorageItemUsage {
    name: String,
    path: String,
    logical_bytes: Option<u64>,
    allocated_bytes: Option<u64>,
    in_use: Option<bool>,
    reclaimable: Option<bool>,
    reasons: Vec<String>,
}

/// Per-file runtime-cache eligibility and any inspection error.
#[pyclass(name = "MemoryCacheEntry", get_all, frozen)]
#[derive(Clone)]
pub struct PyMemoryCacheEntry {
    path: String,
    kind: String,
    logical_bytes: Option<u64>,
    allocated_bytes: Option<u64>,
    state: String,
    error: Option<String>,
}

/// Runtime-cache prune results; removed logical bytes are not physical space reclaimed.
#[pyclass(name = "MemoryCacheReport", get_all, frozen)]
#[derive(Clone)]
pub struct PyMemoryCacheReport {
    dry_run: bool,
    entries: Vec<PyMemoryCacheEntry>,
    files_removed: u64,
    logical_bytes_removed: u64,
    physical_bytes_reclaimed: Option<u64>,
    truncated: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PyStorage {
    /// Observe backend storage without changing files; remote accounting is unsupported.
    #[staticmethod]
    fn usage<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        // Capture before scheduling: later backend_scope changes must not redirect this call.
        let backend = resolve_local(microsandbox::Operation::StorageUsage)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let local = backend.as_local().expect("validated local backend");
            let report = Storage::usage_local(local).await.map_err(to_py_err)?;
            Ok(PyStorageUsage::from_rust(report))
        })
    }

    /// Prune unused runtime RAM, or inspect candidates with dry_run=True.
    ///
    /// Durable snapshots, sandbox disks, named volumes, and stable locks are retained.
    /// older_than_seconds is a nonnegative integer; None applies no age filter.
    #[staticmethod]
    #[pyo3(signature = (*, dry_run = false, older_than_seconds = None))]
    fn prune<'py>(
        py: Python<'py>,
        dry_run: bool,
        older_than_seconds: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let options = MemoryPruneOptions {
            dry_run,
            older_than: parse_older_than(older_than_seconds.as_ref())?,
            ..Default::default()
        };
        let backend = resolve_local(microsandbox::Operation::StoragePrune)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let local = backend.as_local().expect("validated local backend");
            let report = Storage::prune_local(local, &options)
                .await
                .map_err(to_py_err)?;
            Ok(PyMemoryCacheReport::from_rust(report))
        })
    }
}

impl PyStorageUsage {
    fn from_rust(value: StorageUsage) -> Self {
        Self {
            images: PyStorageCategoryUsage::from_rust(value.images),
            snapshots: PyStorageCategoryUsage::from_rust(value.snapshots),
            sandboxes: PyStorageCategoryUsage::from_rust(value.sandboxes),
            volumes: PyStorageCategoryUsage::from_rust(value.volumes),
            branch_memory: PyStorageCategoryUsage::from_rust(value.branch_memory),
            snapshot_memory: PyStorageCategoryUsage::from_rust(value.snapshot_memory),
            notes: value.notes,
        }
    }
}

impl PyStorageCategoryUsage {
    fn from_rust(value: StorageCategoryUsage) -> Self {
        Self {
            count: value.count,
            in_use: value.in_use,
            logical_bytes: value.logical_bytes,
            allocated_bytes: value.allocated_bytes,
            reclaimable_logical_bytes: value.reclaimable_logical_bytes,
            items: value
                .items
                .into_iter()
                .map(PyStorageItemUsage::from_rust)
                .collect(),
            notes: value.notes,
        }
    }
}

impl PyStorageItemUsage {
    pub(crate) fn from_rust(value: StorageItemUsage) -> Self {
        Self {
            name: value.name,
            path: value.path.to_string_lossy().into_owned(),
            logical_bytes: value.logical_bytes,
            allocated_bytes: value.allocated_bytes,
            in_use: value.in_use,
            reclaimable: value.reclaimable,
            reasons: value.reasons,
        }
    }
}

impl PyMemoryCacheEntry {
    fn from_rust(value: MemoryCacheEntry) -> Self {
        Self {
            path: value.path.to_string_lossy().into_owned(),
            kind: match value.kind {
                MemoryCacheKind::BranchMemory => "branch_memory",
                MemoryCacheKind::SnapshotMemory => "snapshot_memory",
            }
            .into(),
            logical_bytes: value.logical_bytes,
            allocated_bytes: value.allocated_bytes,
            state: match value.state {
                MemoryCacheState::Reclaimable => "reclaimable",
                MemoryCacheState::InUse => "in_use",
                MemoryCacheState::PendingHandoff => "pending_handoff",
                MemoryCacheState::TooYoung => "too_young",
                MemoryCacheState::MissingHandoffLock => "missing_handoff_lock",
                MemoryCacheState::Changed => "changed",
                MemoryCacheState::Removed => "removed",
                MemoryCacheState::Error => "error",
            }
            .into(),
            error: value.error,
        }
    }
}

impl PyMemoryCacheReport {
    fn from_rust(value: MemoryCacheReport) -> Self {
        Self {
            dry_run: value.dry_run,
            entries: value
                .entries
                .into_iter()
                .map(PyMemoryCacheEntry::from_rust)
                .collect(),
            files_removed: value.files_removed,
            logical_bytes_removed: value.logical_bytes_removed,
            physical_bytes_reclaimed: value.physical_bytes_reclaimed,
            truncated: value.truncated,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn resolve_local(op: microsandbox::Operation) -> PyResult<Arc<dyn microsandbox::Backend>> {
    let backend = microsandbox::backend::default_backend();
    if backend.as_local().is_none() {
        return Err(to_py_err(microsandbox::MicrosandboxError::local_only(op)));
    }
    Ok(backend)
}

fn parse_older_than(value: Option<&Bound<'_, PyAny>>) -> PyResult<Duration> {
    let Some(value) = value else {
        return Ok(Duration::ZERO);
    };
    // Python bool subclasses int. Reject it explicitly so a flag never becomes an age policy.
    if value.is_instance_of::<PyBool>() || !value.is_instance_of::<PyInt>() {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "older_than_seconds must be an integer or None",
        ));
    }
    let seconds = value.extract::<u64>().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err(
            "older_than_seconds must be between 0 and 18446744073709551615",
        )
    })?;
    Ok(Duration::from_secs(seconds))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_preserve_unknowns_large_integer_bytes_and_partial_errors() {
        let usage = PyStorageUsage::from_rust(StorageUsage {
            branch_memory: StorageCategoryUsage {
                count: Some(1),
                logical_bytes: Some(u64::MAX),
                items: vec![StorageItemUsage {
                    name: "retained".into(),
                    in_use: Some(true),
                    reasons: vec!["pending handoff".into()],
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        });
        assert_eq!(usage.branch_memory.logical_bytes, Some(u64::MAX));
        assert_eq!(usage.branch_memory.allocated_bytes, None);
        assert_eq!(usage.branch_memory.items[0].reclaimable, None);
        assert_eq!(usage.branch_memory.items[0].reasons, ["pending handoff"]);
        assert_eq!(usage.images.count, None);
        let report = PyMemoryCacheReport::from_rust(MemoryCacheReport {
            files_removed: 1,
            logical_bytes_removed: u64::MAX,
            entries: vec![MemoryCacheEntry {
                path: "blocked.ram".into(),
                kind: MemoryCacheKind::SnapshotMemory,
                logical_bytes: None,
                allocated_bytes: None,
                state: MemoryCacheState::Error,
                error: Some("permission denied".into()),
            }],
            ..Default::default()
        });
        assert_eq!(report.entries[0].kind, "snapshot_memory");
        assert_eq!(report.entries[0].state, "error");
        assert_eq!(
            report.entries[0].error.as_deref(),
            Some("permission denied")
        );
        assert_eq!(report.logical_bytes_removed, u64::MAX);
        assert_eq!(report.physical_bytes_reclaimed, None);
    }
}
