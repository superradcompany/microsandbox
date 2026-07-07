use std::collections::HashMap;
use std::path::PathBuf;

use pyo3::prelude::*;
use pyo3::types::PyDict;

use microsandbox::snapshot::SaveOpts as RustSaveOpts;
use microsandbox::{
    Snapshot as RustSnapshot, SnapshotFormat as RustSnapshotFormat,
    SnapshotHandle as RustSnapshotHandle, SnapshotScope as RustSnapshotScope,
    UpperVerifyStatus as RustUpperVerifyStatus,
};

use crate::error::to_py_err;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A snapshot artifact on disk.
#[pyclass(name = "Snapshot")]
pub struct PySnapshot {
    inner: RustSnapshot,
}

/// Lightweight snapshot handle from the local index.
#[pyclass(name = "SnapshotHandle")]
pub struct PySnapshotHandle {
    inner: RustSnapshotHandle,
}

//--------------------------------------------------------------------------------------------------
// Methods: Snapshot
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PySnapshot {
    /// Create a snapshot named `name` from a stopped sandbox.
    ///
    /// The artifact is created under `~/.microsandbox/snapshots/<name>/`,
    /// or under `dest_dir=` when given; move artifacts with `save`/`load`.
    // PyO3 kwargs map one-to-one onto function parameters; the count is the contract.
    #[allow(clippy::too_many_arguments)]
    #[staticmethod]
    #[pyo3(signature = (
        name,
        *,
        from_sandbox,
        dest_dir = None,
        labels = None,
        force = false,
        record_integrity = false,
        resumable = false,
    ))]
    fn create<'py>(
        py: Python<'py>,
        name: String,
        from_sandbox: String,
        dest_dir: Option<PathBuf>,
        labels: Option<HashMap<String, String>>,
        force: bool,
        record_integrity: bool,
        resumable: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut builder = RustSnapshot::builder(name).from_sandbox(&from_sandbox);
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
            if resumable {
                builder = builder.resumable();
            }
            let snap = builder.create().await.map_err(to_py_err)?;
            Ok(PySnapshot::from_rust(snap))
        })
    }

    /// Open an existing snapshot artifact by path or bare name.
    /// Cheap metadata validation only — does not read the upper file.
    #[staticmethod]
    fn open<'py>(py: Python<'py>, path_or_name: String) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let snap = RustSnapshot::open(&path_or_name).await.map_err(to_py_err)?;
            Ok(PySnapshot::from_rust(snap))
        })
    }

    /// Look up an indexed snapshot by digest, name, or path.
    #[staticmethod]
    fn get<'py>(py: Python<'py>, name_or_digest: String) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let h = RustSnapshot::get(&name_or_digest)
                .await
                .map_err(to_py_err)?;
            Ok(PySnapshotHandle::from_rust(h))
        })
    }

    /// List indexed snapshots from the local DB cache.
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

    /// Walk `dir` and parse each subdirectory's `snapshot.json`. Does
    /// not touch the local index — useful for inspecting external
    /// snapshot collections (e.g. a mounted volume of artifacts that
    /// were never imported).
    #[staticmethod]
    fn list_dir<'py>(py: Python<'py>, dir: PathBuf) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let snapshots = RustSnapshot::list_dir(&dir).await.map_err(to_py_err)?;
            let py_snaps: Vec<PySnapshot> =
                snapshots.into_iter().map(PySnapshot::from_rust).collect();
            Ok(py_snaps)
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

    /// Walk the snapshots directory and rebuild the local index.
    /// Defaults to the configured snapshots directory.
    #[staticmethod]
    #[pyo3(signature = (dir = None))]
    fn reindex<'py>(py: Python<'py>, dir: Option<PathBuf>) -> PyResult<Bound<'py, PyAny>> {
        let dir = dir.unwrap_or_else(|| {
            microsandbox::backend::default_backend()
                .as_local()
                .map(|l| l.snapshots_dir())
                .unwrap_or_else(|| std::path::PathBuf::from("."))
        });
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let n = RustSnapshot::reindex(&dir).await.map_err(to_py_err)?;
            Ok(n)
        })
    }

    /// Bundle a snapshot into a `.tar.zst` archive.
    ///
    /// The recorded manifest is archived as-is, so create the snapshot
    /// with `record_integrity=True` if receivers must verify content.
    #[staticmethod]
    #[pyo3(signature = (
        name_or_path,
        out,
        *,
        with_parents = false,
        with_image = false,
        plain_tar = false,
    ))]
    fn save<'py>(
        py: Python<'py>,
        name_or_path: String,
        out: PathBuf,
        with_parents: bool,
        with_image: bool,
        plain_tar: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let opts = RustSaveOpts {
                with_parents,
                with_image,
                plain_tar,
            };
            RustSnapshot::save(&name_or_path, &out, opts)
                .await
                .map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Unpack a snapshot archive (`.tar.zst` or `.tar`) into the
    /// snapshots directory, verifying recorded integrity on the way
    /// in.
    #[staticmethod]
    #[pyo3(signature = (archive, *, dest = None))]
    fn load<'py>(
        py: Python<'py>,
        archive: PathBuf,
        dest: Option<PathBuf>,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let h = RustSnapshot::load(&archive, dest.as_deref())
                .await
                .map_err(to_py_err)?;
            Ok(PySnapshotHandle::from_rust(h))
        })
    }

    //----------------------------------------------------------------------------------------------
    // Instance accessors
    //----------------------------------------------------------------------------------------------

    /// Path to the artifact directory.
    #[getter]
    fn path(&self) -> String {
        self.inner.path().display().to_string()
    }

    /// Canonical content digest (`sha256:hex`). The snapshot's identity.
    #[getter]
    fn digest(&self) -> &str {
        self.inner.digest()
    }

    /// Apparent size of the captured upper layer in bytes.
    #[getter]
    fn size_bytes(&self) -> u64 {
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

    /// On-disk format of the upper layer (`"raw"` or `"qcow2"`).
    #[getter]
    fn format(&self) -> &'static str {
        format_str(self.inner.manifest().format)
    }

    /// Filesystem type inside the upper (e.g. `"ext4"`).
    #[getter]
    fn fstype(&self) -> &str {
        &self.inner.manifest().fstype
    }

    /// Manifest digest of the parent snapshot, or `None` for a root.
    #[getter]
    fn parent(&self) -> Option<&str> {
        self.inner.manifest().parent.as_deref()
    }

    /// Snapshot payload scope (`"disk"` today).
    #[getter]
    fn scope(&self) -> &'static str {
        format_scope(self.inner.manifest().scope)
    }

    /// RFC 3339 timestamp when the snapshot was created.
    #[getter]
    fn created_at(&self) -> &str {
        &self.inner.manifest().created_at
    }

    /// User-supplied labels.
    #[getter]
    fn labels(&self) -> HashMap<String, String> {
        self.inner
            .manifest()
            .labels
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Best-effort source-sandbox name, if recorded.
    #[getter]
    fn source_sandbox(&self) -> Option<&str> {
        self.inner.manifest().source_sandbox.as_deref()
    }

    /// Verify recorded content integrity.
    ///
    /// Returns a dict with `kind` (`"not_recorded"` or `"verified"`)
    /// and, when verified, `algorithm` and `digest`.
    fn verify<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let snap = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let report = snap.verify().await.map_err(to_py_err)?;
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
                Ok(out.into())
            })
        })
    }
}

impl PySnapshot {
    pub fn from_rust(inner: RustSnapshot) -> Self {
        Self { inner }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: SnapshotHandle
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PySnapshotHandle {
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
    fn scope(&self) -> &'static str {
        format_scope(self.inner.scope())
    }

    #[getter]
    fn image_ref(&self) -> &str {
        self.inner.image_ref()
    }

    #[getter]
    fn format(&self) -> &'static str {
        format_str(self.inner.format())
    }

    #[getter]
    fn size_bytes(&self) -> Option<u64> {
        self.inner.size_bytes()
    }

    #[getter]
    fn created_at(&self) -> f64 {
        self.inner.created_at().and_utc().timestamp_millis() as f64
    }

    #[getter]
    fn path(&self) -> String {
        self.inner.path().display().to_string()
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
}

impl PySnapshotHandle {
    pub fn from_rust(inner: RustSnapshotHandle) -> Self {
        Self { inner }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn format_str(f: RustSnapshotFormat) -> &'static str {
    match f {
        RustSnapshotFormat::Raw => "raw",
        RustSnapshotFormat::Qcow2 => "qcow2",
    }
}

fn format_scope(scope: RustSnapshotScope) -> &'static str {
    match scope {
        RustSnapshotScope::Disk => "disk",
        RustSnapshotScope::Resumable => "resumable",
    }
}
