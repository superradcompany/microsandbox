use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use pyo3::prelude::*;
use pyo3::types::PyDict;

use microsandbox::snapshot::{LoadOpts as RustLoadOpts, SaveOpts as RustSaveOpts};
use microsandbox::{
    Snapshot as RustSnapshot, SnapshotArchive as RustSnapshotArchive,
    SnapshotFormat as RustSnapshotFormat, SnapshotHandle as RustSnapshotHandle,
    SnapshotScope as RustSnapshotScope, UpperVerifyStatus as RustUpperVerifyStatus,
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

/// Lightweight snapshot handle returned by the active backend.
#[pyclass(name = "SnapshotHandle")]
pub struct PySnapshotHandle {
    inner: RustSnapshotHandle,
}

//--------------------------------------------------------------------------------------------------
// Methods: Snapshot
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PySnapshot {
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
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut builder = RustSnapshot::builder(name)
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
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
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
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let snap = RustSnapshot::open(&path_or_name).await.map_err(to_py_err)?;
            Ok(PySnapshot::from_rust(snap))
        })
    }

    /// Look up a snapshot using the active backend's public identifier.
    #[staticmethod]
    fn get<'py>(py: Python<'py>, name_or_digest: String) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let h = RustSnapshot::get(&name_or_digest)
                .await
                .map_err(to_py_err)?;
            Ok(PySnapshotHandle::from_rust(h))
        })
    }

    /// List snapshots visible through the active backend.
    #[staticmethod]
    fn list<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let handles = RustSnapshot::list().await.map_err(to_py_err)?;
            let py_handles: Vec<PySnapshotHandle> = handles
                .into_iter()
                .map(PySnapshotHandle::from_rust)
                .collect();
            Ok(py_handles)
        })
    }

    /// Remove a snapshot artifact and its index row.
    ///
    /// Refuses if the snapshot has indexed children unless
    /// `force=True`.
    #[staticmethod]
    #[pyo3(signature = (path_or_name, *, force = false))]
    fn remove<'py>(
        py: Python<'py>,
        path_or_name: String,
        force: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            RustSnapshot::remove(&path_or_name, force)
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
    ))]
    fn save<'py>(
        py: Python<'py>,
        name_or_path: String,
        out: PathBuf,
        with_parents: bool,
        with_image: bool,
        plain_tar: bool,
        since: Option<String>,
        last_layers: Option<usize>,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let opts = RustSaveOpts {
                with_parents,
                with_image,
                plain_tar,
                since,
                last_layers,
            };
            RustSnapshot::save(&name_or_path, &out, opts)
                .await
                .map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Unpack a snapshot archive (`.tar.zst` or `.tar`) into the
    /// snapshots directory, preserving recorded integrity for explicit
    /// verification.
    #[staticmethod]
    #[pyo3(signature = (archive, *, dest = None, base = None, group = None, set_head = false))]
    fn load<'py>(
        py: Python<'py>,
        archive: PathBuf,
        dest: Option<PathBuf>,
        base: Option<String>,
        group: Option<String>,
        set_head: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let h = RustSnapshot::load_with_options(
                &archive,
                RustLoadOpts {
                    dest,
                    base,
                    group,
                    set_head,
                },
            )
            .await
            .map_err(to_py_err)?;
            Ok(PySnapshotHandle::from_rust(h))
        })
    }

    /// Import archives together, resolving dependencies within the batch and destination group.
    #[staticmethod]
    #[pyo3(signature = (archives, *, dest = None, base = None, group = None, set_head = false))]
    fn load_many<'py>(
        py: Python<'py>,
        archives: Vec<PathBuf>,
        dest: Option<PathBuf>,
        base: Option<String>,
        group: Option<String>,
        set_head: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let handles = RustSnapshot::load_many(
                &archives,
                RustLoadOpts {
                    dest,
                    base,
                    group,
                    set_head,
                },
            )
            .await
            .map_err(to_py_err)?;
            Ok(handles
                .into_iter()
                .map(PySnapshotHandle::from_rust)
                .collect::<Vec<_>>())
        })
    }

    /// Read a group's head, or select `group:member` as its head.
    #[staticmethod]
    fn group_head<'py>(py: Python<'py>, selector: String) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let update = RustSnapshot::group_head(&selector)
                .await
                .map_err(to_py_err)?;
            Python::with_gil(|py| head_update_to_py(py, &update))
        })
    }

    //----------------------------------------------------------------------------------------------
    // Instance accessors
    //----------------------------------------------------------------------------------------------

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

    /// How the active backend resolves `reference`.
    #[getter]
    fn reference_kind(&self) -> &'static str {
        self.inner.reference().kind()
    }

    /// Outcome of the group head update performed by this capture.
    #[getter]
    fn head_update(&self, py: Python<'_>) -> PyResult<Option<Py<PyDict>>> {
        self.inner
            .head_update()
            .map(|update| head_update_to_py(py, update))
            .transpose()
    }

    /// Canonical content digest (`sha256:hex`). The snapshot's identity.
    #[getter]
    fn id(&self) -> &str {
        self.inner.id().as_str()
    }

    /// SHA-256 digest of the canonical descriptor.
    #[getter]
    fn digest(&self) -> &str {
        self.inner.digest()
    }

    /// Backend-reported stored payload size in bytes.
    #[getter]
    fn size_bytes(&self) -> Option<u64> {
        self.inner.size_bytes()
    }

    /// Image reference the snapshot was taken from.
    #[getter]
    fn image_ref(&self) -> &str {
        &self.inner.manifest().image.reference
    }

    /// OCI manifest digest of the pinned image.
    #[getter]
    fn image_manifest_digest(&self) -> &str {
        &self.inner.manifest().image.manifest_digest
    }

    /// Closed descriptor state kind (`"file"` or `"checkpoint"`).
    #[getter]
    fn state_kind(&self, py: Python<'_>) -> PyResult<PyObject> {
        str_enum_member(py, "SnapshotStateKind", self.inner.manifest().state.kind())
    }

    /// On-disk format for file state.
    #[getter]
    fn format(&self, py: Python<'_>) -> PyResult<Option<PyObject>> {
        self.inner
            .manifest()
            .state
            .as_file()
            .map(|state| format_str(state.disk_format))
            .map(|format| str_enum_member(py, "SnapshotFormat", format))
            .transpose()
    }

    /// Filesystem type inside the upper (e.g. `"ext4"`).
    #[getter]
    fn fstype(&self) -> Option<&str> {
        self.inner
            .manifest()
            .state
            .as_file()
            .map(|state| state.filesystem.as_str())
    }

    /// Checkpoint id for checkpoint state.
    #[getter]
    fn checkpoint_id(&self) -> Option<&str> {
        self.inner
            .manifest()
            .state
            .as_checkpoint()
            .map(|state| state.checkpoint_id.as_str())
    }

    /// Checkpoint manifest digest for checkpoint state.
    #[getter]
    fn checkpoint_manifest_digest(&self) -> Option<&str> {
        self.inner
            .manifest()
            .state
            .as_checkpoint()
            .map(|state| state.checkpoint_root.as_str())
    }

    /// Manifest digest of the parent snapshot, or `None` for a root.
    #[getter]
    fn parent(&self) -> Option<&str> {
        self.inner
            .manifest()
            .parent
            .as_ref()
            .map(|parent| parent.as_str())
    }

    /// Snapshot payload scope as a `SnapshotScope` member (`DISK` today).
    #[getter]
    fn scope(&self, py: Python<'_>) -> PyResult<PyObject> {
        str_enum_member(
            py,
            "SnapshotScope",
            format_scope(self.inner.manifest().scope),
        )
    }

    /// RFC 3339 timestamp when the snapshot was created.
    #[getter]
    fn created_at(&self) -> &str {
        &self.inner.manifest().capture.created_at
    }

    /// User-supplied labels.
    #[getter]
    fn labels(&self) -> HashMap<String, String> {
        self.inner
            .labels()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    /// Best-effort source-sandbox name, if recorded.
    #[getter]
    fn source_sandbox(&self) -> Option<&str> {
        self.inner.manifest().capture.source_lineage.as_deref()
    }

    /// Walk a backend-visible directory and parse each snapshot artifact.
    /// Raises `UnsupportedError` when artifact-file access is unavailable.
    #[staticmethod]
    fn list_dir<'py>(py: Python<'py>, dir: PathBuf) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
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
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            match dir {
                Some(dir) => RustSnapshot::reindex(dir).await,
                None => RustSnapshot::reindex_default().await,
            }
            .map_err(to_py_err)
        })
    }

    /// Bundle this snapshot into a `.tar.zst` archive.
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
    ) -> PyResult<Bound<'py, PyAny>> {
        let snapshot = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            snapshot
                .save_to(
                    &out,
                    RustSaveOpts {
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
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let report = snapshot.verify().await.map_err(to_py_err)?;
            Python::with_gil(|py| -> PyResult<PyObject> {
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
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
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
// Methods: SnapshotHandle
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PySnapshotHandle {
    /// Local group containing this indexed snapshot.
    #[getter]
    fn group(&self) -> Option<&str> {
        self.inner.group()
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
    fn name(&self) -> Option<&str> {
        self.inner.name()
    }

    #[getter]
    fn parent_digest(&self) -> Option<&str> {
        self.inner.parent_digest()
    }

    #[getter]
    fn scope(&self, py: Python<'_>) -> PyResult<PyObject> {
        str_enum_member(py, "SnapshotScope", format_scope(self.inner.scope()))
    }

    #[getter]
    fn image_ref(&self) -> &str {
        self.inner.image_ref()
    }

    #[getter]
    fn state_kind(&self, py: Python<'_>) -> PyResult<PyObject> {
        str_enum_member(py, "SnapshotStateKind", self.inner.state_kind())
    }

    #[getter]
    fn format(&self, py: Python<'_>) -> PyResult<Option<PyObject>> {
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

    #[getter]
    fn checkpoint_manifest_digest(&self) -> Option<&str> {
        self.inner.checkpoint_manifest_digest()
    }

    #[getter]
    fn size_bytes(&self) -> Option<u64> {
        self.inner.size_bytes()
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

    #[getter]
    fn created_at(&self) -> f64 {
        self.inner.created_at().and_utc().timestamp_millis() as f64
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

    /// Open and metadata-validate the underlying artifact.
    fn open<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let h = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let snap = h.open().await.map_err(to_py_err)?;
            Ok(PySnapshot::from_rust(snap))
        })
    }

    /// Remove the artifact and its index row.
    #[pyo3(signature = (*, force = false))]
    fn remove<'py>(&self, py: Python<'py>, force: bool) -> PyResult<Bound<'py, PyAny>> {
        let h = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            h.remove(force).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Bundle this snapshot into a `.tar.zst` archive.
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
    ) -> PyResult<Bound<'py, PyAny>> {
        let handle = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            handle
                .save_to(
                    &out,
                    RustSaveOpts {
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
}

impl PySnapshotHandle {
    pub fn from_rust(inner: RustSnapshotHandle) -> Self {
        Self { inner }
    }

    pub(crate) fn rust_reference(&self) -> microsandbox::SnapshotReference {
        self.inner.reference()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn head_update_to_py(
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
