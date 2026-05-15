use std::collections::HashMap;
use std::path::PathBuf;

use pyo3::prelude::*;
use pyo3::types::PyDict;

use microsandbox::snapshot::ExportOpts as RustExportOpts;
use microsandbox::{
    Snapshot as RustSnapshot, SnapshotDestination as RustSnapshotDestination,
    SnapshotFormat as RustSnapshotFormat, SnapshotHandle as RustSnapshotHandle,
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
    /// Create a snapshot from a stopped sandbox.
    ///
    /// Exactly one of `name=` (resolved under
    /// `~/.microsandbox/snapshots/<name>/`) or `path=` (explicit
    /// filesystem destination) must be provided.
    #[staticmethod]
    #[pyo3(signature = (
        source_sandbox,
        *,
        name = None,
        path = None,
        labels = None,
        force = false,
        record_integrity = false,
    ))]
    fn create<'py>(
        py: Python<'py>,
        source_sandbox: String,
        name: Option<String>,
        path: Option<PathBuf>,
        labels: Option<HashMap<String, String>>,
        force: bool,
        record_integrity: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let dest = match (name, path) {
            (Some(n), None) => RustSnapshotDestination::Name(n),
            (None, Some(p)) => RustSnapshotDestination::Path(p),
            (Some(_), Some(_)) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "Snapshot.create: pass either name= or path=, not both",
                ));
            }
            (None, None) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "Snapshot.create: name= or path= is required",
                ));
            }
        };
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut builder = RustSnapshot::builder(&source_sandbox).destination(dest);
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

    /// Walk `dir` and parse each subdirectory's `manifest.json`. Does
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
        let dir = dir.unwrap_or_else(|| microsandbox::config::config().snapshots_dir());
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let n = RustSnapshot::reindex(&dir).await.map_err(to_py_err)?;
            Ok(n)
        })
    }

    /// Bundle a snapshot into a `.tar.zst` archive.
    ///
    /// When the snapshot has no integrity hash yet, one is computed
    /// and embedded in the bundled manifest.
    #[staticmethod]
    #[pyo3(signature = (
        name_or_path,
        out,
        *,
        with_parents = false,
        with_image = false,
        plain_tar = false,
    ))]
    fn export<'py>(
        py: Python<'py>,
        name_or_path: String,
        out: PathBuf,
        with_parents: bool,
        with_image: bool,
        plain_tar: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let opts = RustExportOpts {
                with_parents,
                with_image,
                plain_tar,
            };
            RustSnapshot::export(&name_or_path, &out, opts)
                .await
                .map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Unpack a snapshot archive (`.tar.zst` or `.tar`) into the
    /// snapshots directory, verifying recorded integrity on the way
    /// in.
    ///
    /// Note: spelled `import_` because `import` is a Python keyword.
    #[staticmethod]
    #[pyo3(name = "import_", signature = (archive, *, dest = None))]
    fn import_method<'py>(
        py: Python<'py>,
        archive: PathBuf,
        dest: Option<PathBuf>,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let h = RustSnapshot::import(&archive, dest.as_deref())
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
