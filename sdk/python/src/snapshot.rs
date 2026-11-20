use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use pyo3::prelude::*;
use pyo3::types::PyDict;

use microsandbox::snapshot::{LoadOpts as RustLoadOpts, SaveOpts as RustSaveOpts};
use microsandbox::{
    Checkpoint as RustSnapshot, SnapshotArchive as RustSnapshotArchive,
    SnapshotFormat as RustSnapshotFormat, SnapshotScope as RustSnapshotScope,
    UpperVerifyStatus as RustUpperVerifyStatus,
};

use crate::error::to_py_err;
use crate::helpers::str_enum_member;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A backend-neutral disk snapshot.
#[pyclass(name = "Snapshot")]
pub struct PySnapshot {
    inner: RustSnapshot,
}

/// Facts captured by one exact checkpoint removal, including its head decision.
#[pyclass(name = "CheckpointRemoveResult")]
pub struct PyCheckpointRemoveResult {
    pub(crate) inner: microsandbox::CheckpointRemoveResult,
}

/// Result of direct sandbox-to-archive capture.
#[pyclass(name = "SnapshotArchive")]
pub struct PySnapshotArchive {
    inner: RustSnapshotArchive,
}

/// Builder for copying a snapshot archive with replacement metadata.
#[pyclass(name = "SnapshotCopyBuilder")]
pub struct PySnapshotCopyBuilder {
    snapshot: RustSnapshot,
    output_archive_path: PathBuf,
    labels: BTreeMap<String, String>,
    record_integrity: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods: Snapshot
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PyCheckpointRemoveResult {
    #[getter]
    fn id(&self) -> String {
        self.inner.id.to_string()
    }

    #[getter]
    fn head_update(&self, py: Python<'_>) -> PyResult<Option<Py<PyDict>>> {
        self.inner
            .head_update
            .as_ref()
            .map(|head| head_update_to_py(py, head))
            .transpose()
    }

    #[getter]
    fn warnings(&self) -> Vec<String> {
        self.inner.warnings.clone()
    }
}

#[pymethods]
impl PySnapshot {
    /// Remove this retained checkpoint; force never bypasses an active reader.
    #[pyo3(signature = (*, force = false))]
    fn remove<'py>(&self, py: Python<'py>, force: bool) -> PyResult<Bound<'py, PyAny>> {
        let checkpoint = self.inner.clone();
        crate::runtime::future_into_py(py, async move {
            let inner = checkpoint
                .remove_with(|options| if force { options.force() } else { options })
                .await
                .map_err(to_py_err)?;
            Ok(PyCheckpointRemoveResult { inner })
        })
    }

    /// Capture a local destination without consulting remote selection variables.
    #[staticmethod]
    fn local() -> crate::context::PyCheckpoints {
        crate::context::PyCheckpoints {
            inner: microsandbox::context::default_local_context(),
        }
    }

    /// Capture remote environment settings before any deferred operation.
    #[staticmethod]
    fn remote() -> PyResult<crate::context::PyCheckpoints> {
        Ok(crate::context::PyCheckpoints {
            inner: microsandbox::context::remote_from_env().map_err(to_py_err)?,
        })
    }

    #[staticmethod]
    fn ctx(context: PyRef<'_, crate::context::PyContext>) -> crate::context::PyCheckpoints {
        crate::context::PyCheckpoints {
            inner: context.inner.clone(),
        }
    }

    #[getter]
    fn context(&self) -> PyResult<crate::context::PyContext> {
        Ok(crate::context::PyContext {
            inner: self.inner.context().clone_shared(),
        })
    }

    /// Observe artifact storage through this snapshot's captured backend.
    fn storage_usage<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let snapshot = self.inner.clone();
        crate::runtime::future_into_py(py, async move {
            let usage = snapshot.storage_usage().await.map_err(to_py_err)?;
            Ok(crate::storage::PyStorageItemUsage::from_rust(usage))
        })
    }

    /// Create a disk snapshot, or include memory and execution state with full=True.
    ///
    /// The artifact is installed in a snapshot group under the default snapshots
    /// directory or `dest_dir`. Omitted member names are generated; the group
    /// defaults to the source sandbox's name.
    /// The local backend uses its default artifact store; the cloud backend
    /// uses managed storage unless `dest_dir=` selects the host volume.
    // PyO3 kwargs map one-to-one onto function parameters; the count is the contract.
    #[allow(clippy::too_many_arguments)]
    #[staticmethod]
    #[pyo3(signature = (
        name = "".to_string(),
        *,
        from_sandbox,
        group = None,
        dest_dir = None,
        labels = None,
        force = false,
        record_integrity = false,
        full = false,
        guest_flush = None,
    ))]
    fn create<'py>(
        py: Python<'py>,
        name: String,
        from_sandbox: String,
        group: Option<String>,
        dest_dir: Option<PathBuf>,
        labels: Option<HashMap<String, String>>,
        force: bool,
        record_integrity: bool,
        full: bool,
        guest_flush: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        create_in(
            microsandbox::context::configured_context(),
            py,
            name,
            from_sandbox,
            group,
            dest_dir,
            labels,
            force,
            record_integrity,
            full,
            guest_flush,
        )
    }

    /// Capture a sandbox directly into an archive without installing a snapshot artifact.
    #[allow(clippy::too_many_arguments)]
    #[staticmethod]
    #[pyo3(signature = (
        name,
        archive,
        *,
        from_sandbox,
        group = None,
        labels = None,
        force = false,
        record_integrity = false,
        full = false,
        plain_tar = false,
        guest_flush = None,
    ))]
    fn create_archive<'py>(
        py: Python<'py>,
        name: String,
        archive: PathBuf,
        from_sandbox: String,
        group: Option<String>,
        labels: Option<HashMap<String, String>>,
        force: bool,
        record_integrity: bool,
        full: bool,
        plain_tar: bool,
        guest_flush: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        crate::runtime::future_into_py(py, async move {
            let mut builder = RustSnapshot::builder(name)
                .from_sandbox(from_sandbox)
                .guest_flush(guest_flush_policy(guest_flush)?);
            if let Some(group) = group {
                builder = builder.group(group);
            }
            if let Some(labels) = labels {
                for (key, value) in labels {
                    builder = builder.label(key, value);
                }
            }
            if force {
                builder = builder.force();
            }
            if record_integrity {
                builder = builder.record_integrity();
            }
            if full {
                builder = builder.full();
            }
            let archive = builder
                .create_archive(archive, plain_tar)
                .await
                .map_err(to_py_err)?;
            Ok(PySnapshotArchive { inner: archive })
        })
    }

    /// Open a snapshot by path, group head, or `group:member` selector.
    /// Cheap metadata validation only — does not read the upper file.
    #[staticmethod]
    fn open<'py>(py: Python<'py>, path_or_name: String) -> PyResult<Bound<'py, PyAny>> {
        crate::runtime::future_into_py(py, async move {
            let snap = RustSnapshot::open(&path_or_name).await.map_err(to_py_err)?;
            Ok(PySnapshot::from_rust(snap))
        })
    }

    /// Look up a snapshot using the active backend's public identifier.
    #[staticmethod]
    fn get<'py>(py: Python<'py>, name_or_digest: String) -> PyResult<Bound<'py, PyAny>> {
        crate::runtime::future_into_py(py, async move {
            let h = RustSnapshot::get(&name_or_digest)
                .await
                .map_err(to_py_err)?;
            Ok(PySnapshot::from_rust(h))
        })
    }

    /// List snapshots visible through the active backend.
    #[staticmethod]
    fn list<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        crate::runtime::future_into_py(py, async move {
            let handles = RustSnapshot::list().await.map_err(to_py_err)?;
            let py_handles: Vec<PySnapshot> =
                handles.into_iter().map(PySnapshot::from_rust).collect();
            Ok(py_handles)
        })
    }

    /// Remove a snapshot artifact and its index row.
    ///
    /// Refuses if the snapshot has indexed children unless
    /// `force=True`.
    #[staticmethod]
    #[pyo3(signature = (path_or_name, *, force = false))]
    fn remove_by_reference<'py>(
        py: Python<'py>,
        path_or_name: String,
        force: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        crate::runtime::future_into_py(py, async move {
            RustSnapshot::remove_by_reference(&path_or_name, force)
                .await
                .map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Bundle a snapshot into a `.tar.zst` archive.
    ///
    /// `since` omits disk layers and RAM objects supplied by the base; `last_layers` only
    /// selects disk layers. Dependent archives require a base when loaded or restored.
    ///
    /// The recorded manifest is archived as-is, so create the snapshot
    /// with `record_integrity=True` if receivers must verify content.
    // PyO3 kwargs map one-to-one onto function parameters; preserve the public keyword contract.
    #[allow(clippy::too_many_arguments)]
    #[staticmethod]
    #[pyo3(signature = (
        name_or_path,
        out,
        *,
        with_parents = false,
        with_image = false,
        plain_tar = false,
        since = None,
        last_layers = None,
        compatibility = "current".to_owned(),
    ))]
    fn save_by_reference<'py>(
        py: Python<'py>,
        name_or_path: String,
        out: PathBuf,
        with_parents: bool,
        with_image: bool,
        plain_tar: bool,
        since: Option<String>,
        last_layers: Option<usize>,
        compatibility: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        crate::runtime::future_into_py(py, async move {
            let opts = RustSaveOpts {
                compatibility: compatibility.parse().map_err(to_py_err)?,
                with_parents,
                with_image,
                plain_tar,
                since,
                last_layers,
            };
            RustSnapshot::save_by_reference(&name_or_path, &out, opts)
                .await
                .map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Unpack a snapshot archive (`.tar.zst` or `.tar`) into the
    /// snapshots directory, preserving recorded integrity for explicit
    /// verification.
    #[staticmethod]
    #[pyo3(signature = (archive, *, dest = None, base = None, group = None, set_head = false, maximum_disk_bytes = None))]
    fn load<'py>(
        py: Python<'py>,
        archive: PathBuf,
        dest: Option<PathBuf>,
        base: Option<String>,
        group: Option<String>,
        set_head: bool,
        maximum_disk_bytes: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let prepared = microsandbox::snapshot::PreparedSnapshotImport::new(
            vec![archive],
            RustLoadOpts {
                dest,
                base,
                group,
                set_head,
                maximum_disk_bytes,
            },
        );
        crate::runtime::future_into_py(py, async move {
            let handle = prepared
                .map_err(to_py_err)?
                .checkpoint()
                .await
                .map_err(to_py_err)?;
            Ok(PySnapshot::from_rust(handle))
        })
    }

    /// Import archives together, resolving dependencies within the batch and destination group.
    #[staticmethod]
    #[pyo3(signature = (archives, *, dest = None, base = None, group = None, set_head = false, maximum_disk_bytes = None))]
    fn load_many<'py>(
        py: Python<'py>,
        archives: Vec<PathBuf>,
        dest: Option<PathBuf>,
        base: Option<String>,
        group: Option<String>,
        set_head: bool,
        maximum_disk_bytes: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let prepared = microsandbox::snapshot::PreparedSnapshotImport::new(
            archives,
            RustLoadOpts {
                dest,
                base,
                group,
                set_head,
                maximum_disk_bytes,
            },
        );
        crate::runtime::future_into_py(py, async move {
            let handles = prepared
                .map_err(to_py_err)?
                .checkpoints()
                .await
                .map_err(to_py_err)?;
            Ok(handles
                .into_iter()
                .map(PySnapshot::from_rust)
                .collect::<Vec<_>>())
        })
    }

    #[staticmethod]
    fn group_head(py: Python<'_>, group: String) -> PyResult<Bound<'_, PyAny>> {
        group_head_in(microsandbox::context::configured_context(), py, group)
    }

    #[staticmethod]
    fn set_group_head(py: Python<'_>, group: String, id: String) -> PyResult<Bound<'_, PyAny>> {
        set_group_head_in(microsandbox::context::configured_context(), py, group, id)
    }

    /// Deprecated: use `reference`. Raises UnsupportedError for remote snapshots.
    #[getter]
    fn path(&self) -> PyResult<String> {
        self.inner
            .path()
            .map(|path| path.to_string_lossy().into_owned())
            .map_err(to_py_err)
    }

    /// Stable reference accepted by `Sandbox.restore(...)`.
    #[getter]
    fn reference(&self) -> String {
        self.inner.reference().value().to_owned()
    }

    #[getter]
    fn reference_kind(&self) -> &'static str {
        self.inner.reference().kind()
    }

    /// Outcome of the group head update performed by this import.
    #[getter]
    fn head_update(&self, py: Python<'_>) -> PyResult<Option<Py<PyDict>>> {
        self.inner
            .head_update()
            .map(|update| head_update_to_py(py, update))
            .transpose()
    }
    #[getter]
    fn id(&self) -> &str {
        self.inner.id()
    }

    #[getter]
    fn digest(&self) -> &str {
        self.inner.digest()
    }

    #[getter]
    fn size_bytes(&self) -> Option<u64> {
        self.inner.size_bytes()
    }

    #[getter]
    fn image_ref(&self) -> &str {
        self.inner.image_ref()
    }
    /// Fetch current metadata through this snapshot's retained context.
    fn image_manifest_digest<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let snapshot = self.inner.clone();
        crate::runtime::future_into_py(py, async move {
            Ok(snapshot
                .manifest()
                .await
                .map_err(to_py_err)?
                .image
                .manifest_digest)
        })
    }

    #[getter]
    fn state_kind(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        str_enum_member(py, "SnapshotStateKind", self.inner.state_kind().as_str())
    }

    #[getter]
    fn format(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        self.inner
            .format()
            .map(format_str)
            .map(|format| str_enum_member(py, "SnapshotFormat", format))
            .transpose()
    }

    #[getter]
    fn fstype(&self) -> Option<&str> {
        self.inner.fstype()
    }
    /// Fetch current metadata through this snapshot's retained context.
    fn checkpoint_id<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let snapshot = self.inner.clone();
        crate::runtime::future_into_py(py, async move {
            Ok(snapshot
                .manifest()
                .await
                .map_err(to_py_err)?
                .state
                .as_checkpoint()
                .map(|state| state.checkpoint_id.clone()))
        })
    }

    #[getter]
    fn checkpoint_manifest_digest(&self) -> Option<&str> {
        self.inner.checkpoint_manifest_digest()
    }
    #[getter]
    fn parent(&self) -> Option<&str> {
        self.inner.parent_digest()
    }

    #[getter]
    fn scope(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        str_enum_member(py, "SnapshotScope", format_scope(self.inner.scope()))
    }
    #[getter]
    fn created_at(&self) -> String {
        self.inner.created_at().and_utc().to_rfc3339()
    }

    /// Fetch current metadata through this snapshot's retained context.
    fn labels<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let snapshot = self.inner.clone();
        crate::runtime::future_into_py(
            py,
            async move { snapshot.labels().await.map_err(to_py_err) },
        )
    }

    /// Fetch current metadata through this snapshot's retained context.
    fn source_sandbox<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let snapshot = self.inner.clone();
        crate::runtime::future_into_py(py, async move {
            Ok(snapshot
                .manifest()
                .await
                .map_err(to_py_err)?
                .capture
                .source_lineage)
        })
    }

    /// Walk a backend-visible directory and parse each snapshot artifact.
    /// Raises `UnsupportedError` when artifact-file access is unavailable.
    #[staticmethod]
    fn list_dir<'py>(py: Python<'py>, dir: PathBuf) -> PyResult<Bound<'py, PyAny>> {
        crate::runtime::future_into_py(py, async move {
            let snapshots = RustSnapshot::list_dir(&dir).await.map_err(to_py_err)?;
            Ok(snapshots
                .into_iter()
                .map(PySnapshot::from_rust)
                .collect::<Vec<_>>())
        })
    }

    /// Rebuild the backend snapshot index from artifacts in `dir`.
    /// Raises `UnsupportedError` when the backend has no rebuildable index.
    #[staticmethod]
    #[pyo3(signature = (dir = None))]
    fn reindex<'py>(py: Python<'py>, dir: Option<PathBuf>) -> PyResult<Bound<'py, PyAny>> {
        crate::runtime::future_into_py(py, async move {
            match dir {
                Some(dir) => RustSnapshot::reindex(dir).await,
                None => RustSnapshot::reindex_default().await,
            }
            .map_err(to_py_err)
        })
    }

    /// Spawn this exact member on the backend retained by the handle.
    #[pyo3(signature = (*, name = None, **kwargs))]
    fn spawn_sandbox<'py>(
        &self,
        py: Python<'py>,
        name: Option<String>,
        kwargs: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let builder = crate::helpers::restore_builder_from_reference(
            self.inner.context().clone_shared(),
            self.inner.reference(),
            name.unwrap_or_default(),
            kwargs,
        )?;
        let inner = self.inner.clone();
        crate::runtime::future_into_py(py, async move {
            Ok(crate::sandbox::PySandbox::from_rust(
                inner
                    .spawn_sandbox_with(|_| builder)
                    .await
                    .map_err(to_py_err)?,
            ))
        })
    }

    #[pyo3(signature = (*, name = None, **kwargs))]
    fn spawn_sandbox_with_progress<'py>(
        &self,
        py: Python<'py>,
        name: Option<String>,
        kwargs: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let builder = crate::helpers::restore_builder_from_reference(
            self.inner.context().clone_shared(),
            self.inner.reference(),
            name.unwrap_or_default(),
            kwargs,
        )?;
        let inner = self.inner.clone();
        crate::runtime::future_into_py(py, async move {
            let (progress, task) = inner
                .spawn_sandbox_with_progress_with(|_| builder)
                .await
                .map_err(to_py_err)?;
            Ok(crate::sandbox::PyPullSession::new(progress, task))
        })
    }

    /// Raises `UnsupportedError` when artifact archives are unavailable.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        out,
        *,
        with_parents = false,
        with_image = false,
        plain_tar = false,
        since = None,
        last_layers = None,
        compatibility = "current".to_owned(),
    ))]
    fn save<'py>(
        &self,
        py: Python<'py>,
        out: PathBuf,
        with_parents: bool,
        with_image: bool,
        plain_tar: bool,
        since: Option<String>,
        last_layers: Option<usize>,
        compatibility: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let snapshot = self.inner.clone();
        crate::runtime::future_into_py(py, async move {
            snapshot
                .save_to(
                    &out,
                    RustSaveOpts {
                        compatibility: compatibility.parse().map_err(to_py_err)?,
                        with_parents,
                        with_image,
                        plain_tar,
                        since,
                        last_layers,
                    },
                )
                .await
                .map_err(to_py_err)
        })
    }

    /// Raises `UnsupportedError` when artifact archives are unavailable.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        out,
        *,
        with_parents = false,
        with_image = false,
        plain_tar = false,
        since = None,
        last_layers = None,
        compatibility = "current".to_owned(),
    ))]
    fn save_to<'py>(
        &self,
        py: Python<'py>,
        out: PathBuf,
        with_parents: bool,
        with_image: bool,
        plain_tar: bool,
        since: Option<String>,
        last_layers: Option<usize>,
        compatibility: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let snapshot = self.inner.clone();
        crate::runtime::future_into_py(py, async move {
            snapshot
                .save_to(
                    &out,
                    RustSaveOpts {
                        compatibility: compatibility.parse().map_err(to_py_err)?,
                        with_parents,
                        with_image,
                        plain_tar,
                        since,
                        last_layers,
                    },
                )
                .await
                .map_err(to_py_err)
        })
    }

    /// Configure a new archive containing this snapshot's disk data and
    /// replacement labels and integrity metadata.
    /// Raises `UnsupportedError` when artifact archives are unavailable.
    fn copy_to(&self, output_archive_path: PathBuf) -> PySnapshotCopyBuilder {
        PySnapshotCopyBuilder {
            snapshot: self.inner.clone(),
            output_archive_path,
            labels: BTreeMap::new(),
            record_integrity: false,
        }
    }

    /// Verify this snapshot's recorded payload integrity.
    /// Raises `UnsupportedError` when payload verification is unavailable.
    fn verify<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let snapshot = self.inner.clone();
        crate::runtime::future_into_py(py, async move {
            let report = snapshot.verify().await.map_err(to_py_err)?;
            Python::attach(|py| -> PyResult<Py<PyAny>> {
                let upper = PyDict::new(py);
                match report.upper {
                    RustUpperVerifyStatus::NotRecorded => {
                        upper.set_item("kind", "not_recorded")?;
                    }
                    RustUpperVerifyStatus::Verified { algorithm, digest } => {
                        upper.set_item("kind", "verified")?;
                        upper.set_item("algorithm", algorithm)?;
                        upper.set_item("digest", digest)?;
                    }
                }
                let out = PyDict::new(py);
                out.set_item("digest", report.digest)?;
                out.set_item("path", report.path.display().to_string())?;
                out.set_item("upper", upper)?;
                let coverage = PyDict::new(py);
                match report.coverage {
                    microsandbox::snapshot::SnapshotVerifyCoverage::Complete => {
                        coverage.set_item("kind", "complete")?;
                    }
                    microsandbox::snapshot::SnapshotVerifyCoverage::Incomplete { unrecorded } => {
                        coverage.set_item("kind", "incomplete")?;
                        coverage.set_item(
                            "unrecorded",
                            unrecorded
                                .into_iter()
                                .map(|path| path.display().to_string())
                                .collect::<Vec<_>>(),
                        )?;
                    }
                }
                out.set_item("coverage", coverage)?;
                if let Some(checkpoint) = report.checkpoint {
                    let checkpoint_out = PyDict::new(py);
                    checkpoint_out.set_item("kind", "verified")?;
                    checkpoint_out.set_item("root", checkpoint.root)?;
                    out.set_item("checkpoint", checkpoint_out)?;
                } else {
                    out.set_item("checkpoint", py.None())?;
                }
                Ok(out.into())
            })
        })
    }

    /// Local group containing this indexed snapshot.
    #[getter]
    fn group(&self) -> Option<&str> {
        self.inner.group()
    }

    #[getter]
    fn name(&self) -> Option<&str> {
        self.inner.name()
    }

    #[getter]
    fn parent_digest(&self) -> Option<&str> {
        self.inner.parent_digest()
    }

    #[getter]
    fn locality(&self) -> &str {
        self.inner.locality()
    }

    #[getter]
    fn availability(&self) -> &str {
        self.inner.availability()
    }

    #[getter]
    fn migration_state(&self) -> &str {
        self.inner.migration_state()
    }

    #[getter]
    fn migration_error_code(&self) -> Option<&str> {
        self.inner.migration_error_code()
    }
    /// Load and validate the captured identity, returning a detached observation.
    fn manifest<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let snapshot = self.inner.clone();
        crate::runtime::future_into_py(py, async move {
            let observed = snapshot.manifest().await.map_err(to_py_err)?;
            let json = serde_json::to_string(&observed)
                .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
            Python::attach(|py| Ok(py.import("json")?.call_method1("loads", (json,))?.unbind()))
        })
    }

    /// Load and validate the captured identity, returning a detached observation.
    fn state<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let snapshot = self.inner.clone();
        crate::runtime::future_into_py(py, async move {
            let observed = snapshot.state().await.map_err(to_py_err)?;
            let json = serde_json::to_string(&observed)
                .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
            Python::attach(|py| Ok(py.import("json")?.call_method1("loads", (json,))?.unbind()))
        })
    }

    /// Remove the artifact and its index row.
    #[pyo3(signature = (*, force = false))]
    fn destroy<'py>(&self, py: Python<'py>, force: bool) -> PyResult<Bound<'py, PyAny>> {
        let h = self.inner.clone();
        crate::runtime::future_into_py(py, async move {
            h.destroy(force).await.map_err(to_py_err)?;
            Ok(())
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SnapshotArchive
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PySnapshotArchive {
    #[getter]
    fn id(&self) -> &str {
        self.inner.id().as_str()
    }

    #[getter]
    fn descriptor_digest(&self) -> &str {
        self.inner.descriptor_digest()
    }

    #[getter]
    fn path(&self) -> String {
        self.inner.path().display().to_string()
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SnapshotCopyBuilder
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PySnapshotCopyBuilder {
    /// Replace the copied snapshot's labels.
    fn labels<'py>(
        mut slf: PyRefMut<'py, Self>,
        labels: HashMap<String, String>,
    ) -> PyRefMut<'py, Self> {
        slf.labels = labels.into_iter().collect();
        slf
    }

    /// Choose whether to calculate and record disk integrity in the copy.
    fn record_integrity<'py>(mut slf: PyRefMut<'py, Self>, enabled: bool) -> PyRefMut<'py, Self> {
        slf.record_integrity = enabled;
        slf
    }

    /// Write the configured snapshot archive.
    /// Raises `UnsupportedError` when artifact archives are unavailable.
    fn save<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let snapshot = self.snapshot.clone();
        let output_archive_path = self.output_archive_path.clone();
        let labels = self.labels.clone();
        let record_integrity = self.record_integrity;
        crate::runtime::future_into_py(py, async move {
            snapshot
                .copy_to(output_archive_path)
                .labels(labels)
                .record_integrity(record_integrity)
                .save()
                .await
                .map_err(to_py_err)?;
            Ok(())
        })
    }
}

impl PySnapshot {
    pub fn from_rust(inner: RustSnapshot) -> Self {
        Self { inner }
    }

    pub(crate) fn rust_reference(&self) -> microsandbox::SnapshotReference {
        self.inner.reference()
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Snapshot
//--------------------------------------------------------------------------------------------------

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

pub(crate) fn group_head_in(
    context: std::sync::Arc<dyn microsandbox::Context>,
    py: Python<'_>,
    group: String,
) -> PyResult<Bound<'_, PyAny>> {
    crate::runtime::future_into_py(py, async move {
        let head = context
            .checkpoints()
            .group_head(&group)
            .await
            .map_err(to_py_err)?;
        Ok(head.map(|id| id.to_string()))
    })
}

pub(crate) fn set_group_head_in(
    context: std::sync::Arc<dyn microsandbox::Context>,
    py: Python<'_>,
    group: String,
    id: String,
) -> PyResult<Bound<'_, PyAny>> {
    crate::runtime::future_into_py(py, async move {
        let id = microsandbox::snapshot::SnapshotId::new(id).map_err(|e| {
            to_py_err(microsandbox::MicrosandboxError::InvalidConfig(
                e.to_string(),
            ))
        })?;
        let update = context
            .checkpoints()
            .set_group_head(&group, &id)
            .await
            .map_err(to_py_err)?;
        Python::attach(|py| head_update_to_py(py, &update))
    })
}

pub(crate) fn head_update_to_py(
    py: Python<'_>,
    update: &microsandbox::snapshot::HeadUpdate,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("group", &update.group)?;
    result.set_item("previous", &update.previous)?;
    result.set_item("head", &update.head)?;
    // Preserve the stable reason spelling used by all serialized API surfaces.
    let reason = serde_json::to_value(update.reason)
        .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
    let reason = reason.as_str().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err("snapshot head reason is not a string")
    })?;
    result.set_item("reason", reason)?;
    result.set_item("changed", update.changed)?;
    Ok(result.unbind())
}

fn format_str(f: RustSnapshotFormat) -> &'static str {
    match f {
        RustSnapshotFormat::Raw => "raw",
        RustSnapshotFormat::Qcow2 => "qcow2",
    }
}

pub(crate) fn guest_flush_policy(
    value: Option<String>,
) -> PyResult<microsandbox::snapshot::GuestFlush> {
    value
        .as_deref()
        .unwrap_or("auto")
        .parse()
        .map_err(pyo3::exceptions::PyValueError::new_err)
}

fn format_scope(scope: RustSnapshotScope) -> &'static str {
    match scope {
        RustSnapshotScope::Disk => "disk",
        RustSnapshotScope::Full => "full",
    }
}

// Shared implementation for default and explicitly selected Python creation.
#[allow(clippy::too_many_arguments)]
pub(crate) fn create_in<'py>(
    context: std::sync::Arc<dyn microsandbox::Context>,
    py: Python<'py>,
    name: String,
    from_sandbox: String,
    group: Option<String>,
    dest_dir: Option<PathBuf>,
    labels: Option<HashMap<String, String>>,
    force: bool,
    record_integrity: bool,
    full: bool,
    guest_flush: Option<String>,
) -> PyResult<Bound<'py, PyAny>> {
    crate::runtime::future_into_py(py, async move {
        let mut builder = RustSnapshot::ctx(context.as_ref())
            .builder(name)
            .from_sandbox(&from_sandbox)
            .guest_flush(guest_flush_policy(guest_flush)?);
        if let Some(group) = group {
            builder = builder.group(group);
        }
        if let Some(dest_dir) = dest_dir {
            builder = builder.dest_dir(dest_dir);
        }
        if let Some(labels) = labels {
            for (k, v) in labels {
                builder = builder.label(k, v);
            }
        }
        if force {
            builder = builder.force();
        }
        if record_integrity {
            builder = builder.record_integrity();
        }
        if full {
            builder = builder.full();
        }
        let snap = builder.create().await.map_err(to_py_err)?;
        Ok(PySnapshot::from_rust(snap))
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox::{Context, LocalContext};
    use std::ffi::CString;

    #[tokio::test]
    async fn unified_snapshot_python_methods_load_after_context_drop() {
        let root = tempfile::tempdir().unwrap();
        let context = LocalContext::builder().home(root.path()).build().unwrap();
        let path = root.path().join("snapshots/fixture");
        std::fs::create_dir_all(&path).unwrap();
        let descriptor = serde_json::to_string(&serde_json::json!({
            "schema": 1, "artifact": "snapshot", "scope": "disk",
            "created_at": "2026-05-01T12:00:00Z", "parent": null,
            "image": {"ref": "alpine:3.21", "manifest_digest": format!("sha256:{}", "a".repeat(64))},
            "source_sandbox": "fixture", "labels": {},
            "state": {"kind": "file", "format": "raw", "fstype": "ext4",
                "upper": {"file": "disk.ext4", "size_bytes": 4, "integrity": null}},
            "extensions": {}, "requires": []
        })).unwrap();
        std::fs::write(path.join("snapshot.json"), &descriptor).unwrap();
        std::fs::write(path.join("disk.ext4"), b"data").unwrap();
        let opened = context
            .checkpoints()
            .open(path.to_string_lossy())
            .await
            .unwrap();
        let fetched = context.checkpoints().get(opened.id()).await.unwrap();
        let listed = context.checkpoints().list().await.unwrap().remove(0);
        drop(context);

        Python::initialize();
        Python::attach(|py| {
            let globals = PyDict::new(py);
            globals
                .set_item(
                    "resources",
                    vec![
                        Py::new(py, PySnapshot::from_rust(opened)).unwrap(),
                        Py::new(py, PySnapshot::from_rust(fetched)).unwrap(),
                        Py::new(py, PySnapshot::from_rust(listed)).unwrap(),
                    ],
                )
                .unwrap();
            globals
                .set_item("path", path.to_string_lossy().as_ref())
                .unwrap();
            globals.set_item("descriptor", descriptor).unwrap();
            let script = CString::new(
                r#"
import asyncio
from pathlib import Path
async def check():
    document = Path(path) / 'snapshot.json'
    document.unlink()
    for resource in resources:
        assert type(resource) is type(resources[0])
        assert isinstance(resource.id, str)
        assert resource.id == resources[0].id
        try:
            await resource.manifest()
        except Exception:
            pass
        else:
            raise AssertionError('missing descriptor returned cached metadata')
    document.write_text(descriptor)
    for resource in resources:
        assert (await resource.state())['kind'] == 'file'
        assert (await resource.manifest())['snapshot_id'] == resource.id
        assert await resource.labels() == {}
    await resources[-1].destroy()
    assert not Path(path).exists()
asyncio.run(check())
"#,
            )
            .unwrap();
            py.run(&script, Some(&globals), None).unwrap();
        });
    }
}
