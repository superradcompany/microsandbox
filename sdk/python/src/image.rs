use std::io::Write;
use std::path::PathBuf;

use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyList, PyModule};

use microsandbox::ImageArchiveFormat;
use microsandbox::image::{
    Image as RustImage, ImageConfigDetail as RustImageConfigDetail, ImageDetail as RustImageDetail,
    ImageHandle as RustImageHandle, ImageLayerDetail as RustImageLayerDetail,
    ImagePruneReport as RustImagePruneReport,
};

use crate::error::to_py_err;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Static namespace for image source configuration and OCI image-cache management.
#[pyclass(name = "Image")]
pub struct PyImage;

/// One image reference or a sequence of them.
///
/// `One` must come first: an untagged extraction tries variants in order, and
/// a Python `str` is itself a sequence of 1-char strings, so trying
/// `Vec<String>` first would happily shred `"python:3.12"` into characters.
#[derive(FromPyObject)]
pub enum ReferenceArg {
    /// A single image reference.
    One(String),
    /// Multiple image references.
    Many(Vec<String>),
}

/// A lightweight handle to a cached OCI image.
#[pyclass(name = "ImageHandle")]
#[derive(Clone)]
pub struct PyImageHandle {
    reference: String,
    size_bytes: Option<i64>,
    manifest_digest: Option<String>,
    architecture: Option<String>,
    os: Option<String>,
    layer_count: usize,
    last_used_at: Option<f64>,
    created_at: Option<f64>,
}

/// Full detail for a cached OCI image.
#[pyclass(name = "ImageDetail")]
pub struct PyImageDetail {
    handle: PyImageHandle,
    config: Option<PyImageConfigDetail>,
    layers: Vec<PyImageLayerDetail>,
}

/// OCI image config fields extracted from the local cache.
#[pyclass(name = "ImageConfigDetail")]
#[derive(Clone)]
pub struct PyImageConfigDetail {
    digest: String,
    env: Vec<String>,
    cmd: Option<Vec<String>>,
    entrypoint: Option<Vec<String>>,
    working_dir: Option<String>,
    user: Option<String>,
    labels: Option<serde_json::Value>,
    stop_signal: Option<String>,
}

/// Metadata for a single image layer.
#[pyclass(name = "ImageLayerDetail")]
#[derive(Clone)]
pub struct PyImageLayerDetail {
    diff_id: String,
    blob_digest: String,
    media_type: Option<String>,
    compressed_size_bytes: Option<i64>,
    erofs_size_bytes: Option<i64>,
    position: i32,
}

/// Summary of cached image data removed by `Image.prune()`.
#[pyclass(name = "ImagePruneReport")]
#[derive(Clone)]
pub struct PyImagePruneReport {
    image_refs_removed: u32,
    manifests_removed: u32,
    layers_removed: u32,
    fsmeta_removed: u32,
    vmdk_removed: u32,
    bytes_reclaimed: Option<u64>,
}

//--------------------------------------------------------------------------------------------------
// Methods: Image
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PyImage {
    /// Create an OCI rootfs image source.
    ///
    /// `root_disk` accepts an int (MiB, managed sugar), a `RootDisk.*()`
    /// config, or an equivalent dict. `upper_size_mib` is a deprecated
    /// alias for a managed root disk of that size.
    #[staticmethod]
    #[pyo3(signature = (reference, *, root_disk = None, upper_size_mib = None))]
    fn oci(
        py: Python<'_>,
        reference: String,
        root_disk: Option<Bound<'_, PyAny>>,
        upper_size_mib: Option<u32>,
    ) -> PyResult<PyObject> {
        if root_disk.is_some() && upper_size_mib.is_some() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "pass either root_disk= or upper_size_mib=, not both",
            ));
        }
        let kwargs = PyDict::new(py);
        kwargs.set_item("_type", "oci")?;
        kwargs.set_item("_reference", reference)?;
        if let Some(root_disk) = root_disk {
            kwargs.set_item("_root_disk", root_disk)?;
        } else if let Some(upper_size_mib) = upper_size_mib {
            // Deprecated alias: normalize to a managed root disk dict.
            let managed = PyDict::new(py);
            managed.set_item("kind", "managed")?;
            managed.set_item("size_mib", upper_size_mib)?;
            kwargs.set_item("_root_disk", managed)?;
            kwargs.set_item("_upper_size_mib", upper_size_mib)?;
        }
        Ok(image_source_class(py)?.call((), Some(&kwargs))?.unbind())
    }

    /// Create a bind rootfs image source.
    #[staticmethod]
    fn bind(py: Python<'_>, path: String) -> PyResult<PyObject> {
        let kwargs = PyDict::new(py);
        kwargs.set_item("_type", "bind")?;
        kwargs.set_item("_path", path)?;
        Ok(image_source_class(py)?.call((), Some(&kwargs))?.unbind())
    }

    /// Create a disk-image rootfs source. Format is inferred from extension.
    #[staticmethod]
    #[pyo3(signature = (path, *, fstype = None))]
    fn disk(py: Python<'_>, path: String, fstype: Option<String>) -> PyResult<PyObject> {
        let kwargs = PyDict::new(py);
        kwargs.set_item("_type", "disk")?;
        kwargs.set_item("_path", path)?;
        if let Some(fstype) = fstype {
            kwargs.set_item("_fstype", fstype)?;
        }
        Ok(image_source_class(py)?.call((), Some(&kwargs))?.unbind())
    }

    /// Get a cached image by reference.
    #[staticmethod]
    fn get<'py>(py: Python<'py>, reference: String) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let backend = resolve_local().map_err(to_py_err)?;
            let local = backend.as_local().expect("checked above");
            let handle = RustImage::get_local(local, &reference)
                .await
                .map_err(to_py_err)?;
            Ok(PyImageHandle::from_rust(handle))
        })
    }

    /// List all cached images.
    #[staticmethod]
    fn list<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let backend = resolve_local().map_err(to_py_err)?;
            let local = backend.as_local().expect("checked above");
            let handles = RustImage::list_local(local).await.map_err(to_py_err)?;
            let py_handles: Vec<PyImageHandle> =
                handles.into_iter().map(PyImageHandle::from_rust).collect();
            Ok(py_handles)
        })
    }

    /// Get full image detail, including OCI config and layer metadata.
    #[staticmethod]
    fn inspect<'py>(py: Python<'py>, reference: String) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let backend = resolve_local().map_err(to_py_err)?;
            let local = backend.as_local().expect("checked above");
            let detail = RustImage::inspect_local(local, &reference)
                .await
                .map_err(to_py_err)?;
            Ok(PyImageDetail::from_rust(detail))
        })
    }

    /// Remove a cached image.
    #[staticmethod]
    #[pyo3(signature = (reference, *, force = false))]
    fn remove<'py>(py: Python<'py>, reference: String, force: bool) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let backend = resolve_local().map_err(to_py_err)?;
            let local = backend.as_local().expect("checked above");
            RustImage::remove_local(local, &reference, force)
                .await
                .map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Remove cached image data that is not used by any sandbox or indexed snapshot.
    #[staticmethod]
    fn prune<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let backend = resolve_local().map_err(to_py_err)?;
            let local = backend.as_local().expect("checked above");
            let report = RustImage::prune_local(local).await.map_err(to_py_err)?;
            Ok(PyImagePruneReport::from_rust(report))
        })
    }

    /// Load images from a local archive into the image cache.
    ///
    /// Accepts `docker save` tarballs and OCI Image Layout archives. Pass
    /// `input_path="-"` to read the archive from stdin. `tag` applies an
    /// extra reference to the first image in the archive.
    #[staticmethod]
    #[pyo3(signature = (input_path, *, tag = None))]
    fn load<'py>(
        py: Python<'py>,
        input_path: String,
        tag: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let backend = resolve_local().map_err(to_py_err)?;
            let local = backend.as_local().expect("checked above");
            let tags: Vec<String> = tag.into_iter().collect();

            let stdin_temp;
            let input = if input_path == "-" {
                stdin_temp = read_stdin_to_temp_file().await.map_err(to_py_err)?;
                stdin_temp.path().to_path_buf()
            } else {
                PathBuf::from(input_path)
            };

            let handles = RustImage::load_local(local, &input, tags)
                .await
                .map_err(to_py_err)?;
            let py_handles: Vec<PyImageHandle> =
                handles.into_iter().map(PyImageHandle::from_rust).collect();
            Ok(py_handles)
        })
    }

    /// Save one or more cached images to an archive file.
    ///
    /// `reference` accepts a single reference string or a sequence of them;
    /// every referenced image is written into the same archive. `format`
    /// selects the archive layout: `"docker"` (default, compatible with
    /// `docker load`) or `"oci"` (OCI Image Layout).
    #[staticmethod]
    #[pyo3(signature = (reference, *, output_path, format = None))]
    fn save<'py>(
        py: Python<'py>,
        reference: ReferenceArg,
        output_path: String,
        format: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let format = match format.as_deref().unwrap_or("docker") {
            "docker" => ImageArchiveFormat::Docker,
            "oci" => ImageArchiveFormat::Oci,
            other => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "invalid archive format '{other}': expected 'docker' or 'oci'"
                )));
            }
        };
        let references = match reference {
            ReferenceArg::One(reference) => vec![reference],
            ReferenceArg::Many(references) => references,
        };
        if references.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "at least one image reference is required",
            ));
        }

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let backend = resolve_local().map_err(to_py_err)?;
            let local = backend.as_local().expect("checked above");
            RustImage::save_local(
                local,
                &references,
                PathBuf::from(output_path).as_path(),
                format,
            )
            .await
            .map_err(to_py_err)?;
            Ok(())
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: ImageHandle
//--------------------------------------------------------------------------------------------------

impl PyImageHandle {
    pub fn from_rust(inner: RustImageHandle) -> Self {
        Self {
            reference: inner.reference().to_string(),
            size_bytes: inner.size_bytes(),
            manifest_digest: inner.manifest_digest().map(str::to_string),
            architecture: inner.architecture().map(str::to_string),
            os: inner.os().map(str::to_string),
            layer_count: inner.layer_count(),
            last_used_at: inner.last_used_at().map(|dt| dt.timestamp_millis() as f64),
            created_at: inner.created_at().map(|dt| dt.timestamp_millis() as f64),
        }
    }
}

#[pymethods]
impl PyImageHandle {
    #[getter]
    fn reference(&self) -> &str {
        &self.reference
    }

    #[getter]
    fn size_bytes(&self) -> Option<i64> {
        self.size_bytes
    }

    #[getter]
    fn manifest_digest(&self) -> Option<&str> {
        self.manifest_digest.as_deref()
    }

    #[getter]
    fn architecture(&self) -> Option<&str> {
        self.architecture.as_deref()
    }

    #[getter]
    fn os(&self) -> Option<&str> {
        self.os.as_deref()
    }

    #[getter]
    fn layer_count(&self) -> usize {
        self.layer_count
    }

    #[getter]
    fn last_used_at(&self) -> Option<f64> {
        self.last_used_at
    }

    #[getter]
    fn created_at(&self) -> Option<f64> {
        self.created_at
    }

    /// Inspect this cached image.
    fn inspect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let reference = self.reference.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let backend = resolve_local().map_err(to_py_err)?;
            let local = backend.as_local().expect("checked above");
            let detail = RustImage::inspect_local(local, &reference)
                .await
                .map_err(to_py_err)?;
            Ok(PyImageDetail::from_rust(detail))
        })
    }

    /// Remove this cached image.
    #[pyo3(signature = (*, force = false))]
    fn remove<'py>(&self, py: Python<'py>, force: bool) -> PyResult<Bound<'py, PyAny>> {
        let reference = self.reference.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let backend = resolve_local().map_err(to_py_err)?;
            let local = backend.as_local().expect("checked above");
            RustImage::remove_local(local, &reference, force)
                .await
                .map_err(to_py_err)?;
            Ok(())
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: ImageDetail
//--------------------------------------------------------------------------------------------------

impl PyImageDetail {
    fn from_rust(inner: RustImageDetail) -> Self {
        Self {
            handle: PyImageHandle::from_rust(inner.handle),
            config: inner.config.map(PyImageConfigDetail::from_rust),
            layers: inner
                .layers
                .into_iter()
                .map(PyImageLayerDetail::from_rust)
                .collect(),
        }
    }
}

#[pymethods]
impl PyImageDetail {
    #[getter]
    fn handle(&self) -> PyImageHandle {
        self.handle.clone()
    }

    #[getter]
    fn config(&self) -> Option<PyImageConfigDetail> {
        self.config.clone()
    }

    #[getter]
    fn layers(&self) -> Vec<PyImageLayerDetail> {
        self.layers.clone()
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: ImageConfigDetail
//--------------------------------------------------------------------------------------------------

impl PyImageConfigDetail {
    fn from_rust(inner: RustImageConfigDetail) -> Self {
        Self {
            digest: inner.digest,
            env: inner.env,
            cmd: inner.cmd,
            entrypoint: inner.entrypoint,
            working_dir: inner.working_dir,
            user: inner.user,
            labels: inner.labels,
            stop_signal: inner.stop_signal,
        }
    }
}

#[pymethods]
impl PyImageConfigDetail {
    #[getter]
    fn digest(&self) -> &str {
        &self.digest
    }

    #[getter]
    fn env(&self) -> Vec<String> {
        self.env.clone()
    }

    #[getter]
    fn cmd(&self) -> Option<Vec<String>> {
        self.cmd.clone()
    }

    #[getter]
    fn entrypoint(&self) -> Option<Vec<String>> {
        self.entrypoint.clone()
    }

    #[getter]
    fn working_dir(&self) -> Option<&str> {
        self.working_dir.as_deref()
    }

    #[getter]
    fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    #[getter]
    fn labels(&self, py: Python<'_>) -> PyResult<Option<PyObject>> {
        self.labels
            .clone()
            .map(|value| json_object_to_py(py, value))
            .transpose()
    }

    #[getter]
    fn stop_signal(&self) -> Option<&str> {
        self.stop_signal.as_deref()
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: ImageLayerDetail
//--------------------------------------------------------------------------------------------------

impl PyImageLayerDetail {
    fn from_rust(inner: RustImageLayerDetail) -> Self {
        Self {
            diff_id: inner.diff_id,
            blob_digest: inner.blob_digest,
            media_type: inner.media_type,
            compressed_size_bytes: inner.compressed_size_bytes,
            erofs_size_bytes: inner.erofs_size_bytes,
            position: inner.position,
        }
    }
}

#[pymethods]
impl PyImageLayerDetail {
    #[getter]
    fn diff_id(&self) -> &str {
        &self.diff_id
    }

    #[getter]
    fn blob_digest(&self) -> &str {
        &self.blob_digest
    }

    #[getter]
    fn media_type(&self) -> Option<&str> {
        self.media_type.as_deref()
    }

    #[getter]
    fn compressed_size_bytes(&self) -> Option<i64> {
        self.compressed_size_bytes
    }

    #[getter]
    fn erofs_size_bytes(&self) -> Option<i64> {
        self.erofs_size_bytes
    }

    #[getter]
    fn position(&self) -> i32 {
        self.position
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: ImagePruneReport
//--------------------------------------------------------------------------------------------------

impl PyImagePruneReport {
    fn from_rust(inner: RustImagePruneReport) -> Self {
        Self {
            image_refs_removed: inner.image_refs_removed,
            manifests_removed: inner.manifests_removed,
            layers_removed: inner.layers_removed,
            fsmeta_removed: inner.fsmeta_removed,
            vmdk_removed: inner.vmdk_removed,
            bytes_reclaimed: inner.bytes_reclaimed,
        }
    }
}

#[pymethods]
impl PyImagePruneReport {
    #[getter]
    fn image_refs_removed(&self) -> u32 {
        self.image_refs_removed
    }

    #[getter]
    fn manifests_removed(&self) -> u32 {
        self.manifests_removed
    }

    #[getter]
    fn layers_removed(&self) -> u32 {
        self.layers_removed
    }

    #[getter]
    fn fsmeta_removed(&self) -> u32 {
        self.fsmeta_removed
    }

    #[getter]
    fn vmdk_removed(&self) -> u32 {
        self.vmdk_removed
    }

    #[getter]
    fn bytes_reclaimed(&self) -> Option<u64> {
        self.bytes_reclaimed
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn image_source_class<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    let types = PyModule::import(py, "microsandbox.types")?;
    types.getattr("ImageSource")
}

fn resolve_local() -> microsandbox::MicrosandboxResult<std::sync::Arc<dyn microsandbox::Backend>> {
    let backend = microsandbox::backend::default_backend();
    if backend.as_local().is_none() {
        return Err(microsandbox::MicrosandboxError::Unsupported {
            feature: "image ops on cloud".into(),
            available_when: "with a local backend".into(),
        });
    }
    Ok(backend)
}

async fn read_stdin_to_temp_file() -> microsandbox::MicrosandboxResult<tempfile::NamedTempFile> {
    tokio::task::spawn_blocking(
        || -> microsandbox::MicrosandboxResult<tempfile::NamedTempFile> {
            let mut temp = tempfile::NamedTempFile::new()?;
            std::io::copy(&mut std::io::stdin().lock(), temp.as_file_mut())?;
            temp.as_file_mut().flush()?;
            Ok(temp)
        },
    )
    .await
    .map_err(|e| {
        microsandbox::MicrosandboxError::Custom(format!("stdin read task panicked: {e}"))
    })?
}

fn json_object_to_py(py: Python<'_>, value: serde_json::Value) -> PyResult<PyObject> {
    match value {
        serde_json::Value::Object(values) => {
            let dict = PyDict::new(py);
            for (key, value) in values {
                dict.set_item(key, json_value_to_py(py, value)?)?;
            }
            Ok(dict.unbind().into())
        }
        _ => Ok(PyDict::new(py).unbind().into()),
    }
}

fn json_value_to_py(py: Python<'_>, value: serde_json::Value) -> PyResult<PyObject> {
    match value {
        serde_json::Value::Null => Ok(py.None()),
        serde_json::Value::Bool(value) => Ok(PyBool::new(py, value).to_owned().unbind().into()),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Ok(value.into_pyobject(py)?.unbind().into())
            } else if let Some(value) = value.as_u64() {
                Ok(value.into_pyobject(py)?.unbind().into())
            } else if let Some(value) = value.as_f64() {
                Ok(value.into_pyobject(py)?.unbind().into())
            } else {
                Ok(py.None())
            }
        }
        serde_json::Value::String(value) => Ok(value.into_pyobject(py)?.unbind().into()),
        serde_json::Value::Array(values) => {
            let values = values
                .into_iter()
                .map(|value| json_value_to_py(py, value))
                .collect::<PyResult<Vec<_>>>()?;
            Ok(PyList::new(py, values)?.unbind().into())
        }
        serde_json::Value::Object(values) => {
            let dict = PyDict::new(py);
            for (key, value) in values {
                dict.set_item(key, json_value_to_py(py, value)?)?;
            }
            Ok(dict.unbind().into())
        }
    }
}
