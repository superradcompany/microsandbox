use std::collections::HashMap;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule};

use crate::error::to_py_err;
use crate::helpers::{extract_str_enum, str_enum_member};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A named persistent volume.
#[pyclass(name = "Volume")]
pub struct PyVolume {
    name: String,
    /// Local volumes expose a host path; cloud volumes deliberately do not.
    path: Option<String>,
}

/// A lightweight handle to a volume from the database.
#[pyclass(name = "VolumeHandle")]
pub struct PyVolumeHandle {
    inner: microsandbox::volume::VolumeHandle,
}

//--------------------------------------------------------------------------------------------------
// Methods: Volume
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PyVolume {
    /// Create a new named volume.
    #[staticmethod]
    #[pyo3(signature = (name, *, kind=None, size_mib=None, quota_mib=None, labels=None))]
    fn create<'py>(
        py: Python<'py>,
        name: String,
        kind: Option<Py<PyAny>>,
        size_mib: Option<u32>,
        quota_mib: Option<u32>,
        labels: Option<HashMap<String, String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let kind = kind
            .as_ref()
            .map(|value| extract_str_enum(value.bind(py), "VolumeKind"))
            .transpose()?
            .unwrap_or_else(|| "dir".to_string());
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut builder = microsandbox::Volume::builder(&name);
            match kind.as_str() {
                "dir" => {
                    builder = builder.directory();
                    if size_mib.is_some() {
                        return Err(to_py_err(microsandbox::MicrosandboxError::InvalidConfig(
                            "size_mib is only supported with kind='disk' until directory quotas are enforced".into(),
                        )));
                    }
                }
                "disk" => {
                    builder = builder.disk();
                    let size_mib = size_mib.ok_or_else(|| {
                        to_py_err(microsandbox::MicrosandboxError::InvalidConfig(
                            "size_mib is required with kind='disk'".into(),
                        ))
                    })?;
                    builder = builder.size(size_mib);
                }
                other => {
                    return Err(to_py_err(microsandbox::MicrosandboxError::InvalidConfig(
                        format!("unknown volume kind: {other}"),
                    )));
                }
            }
            if let Some(quota) = quota_mib {
                builder = builder.quota(quota);
            }
            if let Some(labels) = labels {
                for (k, v) in labels {
                    builder = builder.label(k, v);
                }
            }
            let vol = builder.create().await.map_err(to_py_err)?;
            // A cloud create is still a successful volume create even though
            // its bytes have no path on the SDK caller's machine.
            let path = match vol.path() {
                Ok(path) => Some(path.display().to_string()),
                Err(microsandbox::MicrosandboxError::Unsupported { .. }) => None,
                Err(error) => return Err(to_py_err(error)),
            };
            Ok(PyVolume {
                name: vol.name().to_string(),
                path,
            })
        })
    }

    /// Get a lightweight handle to an existing volume.
    #[staticmethod]
    fn get<'py>(py: Python<'py>, name: String) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let handle = microsandbox::Volume::get(&name).await.map_err(to_py_err)?;
            Ok(PyVolumeHandle { inner: handle })
        })
    }

    /// Get the cloud account's always-present default volume.
    #[staticmethod]
    fn get_default<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let handle = microsandbox::Volume::get_default()
                .await
                .map_err(to_py_err)?;
            Ok(PyVolumeHandle { inner: handle })
        })
    }

    /// List all volumes.
    #[staticmethod]
    fn list<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let handles = microsandbox::Volume::list().await.map_err(to_py_err)?;
            let py_handles: Vec<PyVolumeHandle> = handles
                .into_iter()
                .map(|h| PyVolumeHandle { inner: h })
                .collect();
            Ok(py_handles)
        })
    }

    /// Remove a volume.
    #[staticmethod]
    fn remove<'py>(py: Python<'py>, name: String) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            microsandbox::Volume::remove(&name)
                .await
                .map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Volume name.
    #[getter]
    fn name(&self) -> &str {
        &self.name
    }

    /// Host path of the volume.
    #[getter]
    fn path(&self) -> PyResult<&str> {
        self.path
            .as_deref()
            .ok_or_else(|| crate::error::local_only("volume.path"))
    }

    //----------------------------------------------------------------------------------------------
    // Static Factories (for mount configs)
    //----------------------------------------------------------------------------------------------

    /// Create a bind mount config.
    #[staticmethod]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (path, *, readonly = false, noexec = false, nosuid = false, nodev = false, stat_virtualization = None, host_permissions = None, uid = None, gid = None))]
    fn bind(
        py: Python<'_>,
        path: String,
        readonly: bool,
        noexec: bool,
        nosuid: bool,
        nodev: bool,
        stat_virtualization: Option<Py<PyAny>>,
        host_permissions: Option<Py<PyAny>>,
        uid: Option<Py<PyAny>>,
        gid: Option<Py<PyAny>>,
    ) -> PyResult<PyObject> {
        let kwargs = PyDict::new(py);
        kwargs.set_item("kind", mount_kind(py, "BIND")?)?;
        kwargs.set_item("bind", path)?;
        kwargs.set_item("readonly", readonly)?;
        kwargs.set_item("noexec", noexec)?;
        kwargs.set_item("nosuid", nosuid)?;
        kwargs.set_item("nodev", nodev)?;
        set_mount_metadata_options(py, &kwargs, stat_virtualization, host_permissions, uid, gid)?;
        Ok(mount_config_class(py)?.call((), Some(&kwargs))?.unbind())
    }

    /// Create a named volume mount config.
    #[staticmethod]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (name, *, mode = None, kind = None, size_mib = None, quota_mib = None, readonly = false, noexec = false, nosuid = false, nodev = false, stat_virtualization = None, host_permissions = None, uid = None, gid = None))]
    fn named(
        py: Python<'_>,
        name: String,
        mode: Option<Py<PyAny>>,
        kind: Option<Py<PyAny>>,
        size_mib: Option<u32>,
        quota_mib: Option<u32>,
        readonly: bool,
        noexec: bool,
        nosuid: bool,
        nodev: bool,
        stat_virtualization: Option<Py<PyAny>>,
        host_permissions: Option<Py<PyAny>>,
        uid: Option<Py<PyAny>>,
        gid: Option<Py<PyAny>>,
    ) -> PyResult<PyObject> {
        let kwargs = PyDict::new(py);
        kwargs.set_item("kind", mount_kind(py, "NAMED")?)?;
        kwargs.set_item("named", name)?;
        if let Some(mode) = mode {
            extract_str_enum(mode.bind(py), "NamedVolumeMode")?;
            kwargs.set_item("named_mode", mode)?;
        }
        if let Some(kind) = kind {
            extract_str_enum(kind.bind(py), "VolumeKind")?;
            kwargs.set_item("named_kind", kind)?;
        }
        if let Some(size_mib) = size_mib {
            kwargs.set_item("size_mib", size_mib)?;
        }
        if let Some(quota_mib) = quota_mib {
            kwargs.set_item("quota_mib", quota_mib)?;
        }
        kwargs.set_item("readonly", readonly)?;
        kwargs.set_item("noexec", noexec)?;
        kwargs.set_item("nosuid", nosuid)?;
        kwargs.set_item("nodev", nodev)?;
        set_mount_metadata_options(py, &kwargs, stat_virtualization, host_permissions, uid, gid)?;
        Ok(mount_config_class(py)?.call((), Some(&kwargs))?.unbind())
    }

    /// Create a tmpfs mount config.
    #[staticmethod]
    #[pyo3(signature = (*, size_mib = None, readonly = false, noexec = false, nosuid = false, nodev = false))]
    fn tmpfs(
        py: Python<'_>,
        size_mib: Option<u32>,
        readonly: bool,
        noexec: bool,
        nosuid: bool,
        nodev: bool,
    ) -> PyResult<PyObject> {
        let kwargs = PyDict::new(py);
        kwargs.set_item("kind", mount_kind(py, "TMPFS")?)?;
        if let Some(size) = size_mib {
            kwargs.set_item("size_mib", size)?;
        }
        kwargs.set_item("readonly", readonly)?;
        kwargs.set_item("noexec", noexec)?;
        kwargs.set_item("nosuid", nosuid)?;
        kwargs.set_item("nodev", nodev)?;
        Ok(mount_config_class(py)?.call((), Some(&kwargs))?.unbind())
    }

    /// Create a disk-image volume mount config.
    ///
    /// `format` is a `DiskImageFormat` member. When omitted it is inferred
    /// from the file extension. `fstype`
    /// (e.g. `"ext4"`) is the inner filesystem agentd will mount; if
    /// omitted, agentd probes `/proc/filesystems` to find a type that
    /// mounts cleanly.
    #[staticmethod]
    #[pyo3(signature = (path, *, format = None, fstype = None, readonly = false, noexec = false, nosuid = false, nodev = false))]
    fn disk(
        path: String,
        format: Option<Py<PyAny>>,
        fstype: Option<String>,
        readonly: bool,
        noexec: bool,
        nosuid: bool,
        nodev: bool,
    ) -> PyResult<PyObject> {
        Python::with_gil(|py| {
            let kwargs = PyDict::new(py);
            kwargs.set_item("kind", mount_kind(py, "DISK")?)?;
            kwargs.set_item("disk", path)?;
            if let Some(format) = format {
                extract_str_enum(format.bind(py), "DiskImageFormat")?;
                kwargs.set_item("format", format)?;
            }
            if let Some(fstype) = fstype {
                kwargs.set_item("fstype", fstype)?;
            }
            kwargs.set_item("readonly", readonly)?;
            kwargs.set_item("noexec", noexec)?;
            kwargs.set_item("nosuid", nosuid)?;
            kwargs.set_item("nodev", nodev)?;
            Ok(mount_config_class(py)?.call((), Some(&kwargs))?.unbind())
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: VolumeHandle
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PyVolumeHandle {
    #[getter]
    fn name(&self) -> &str {
        self.inner.name()
    }

    #[getter]
    fn is_default(&self) -> bool {
        self.inner.is_default()
    }

    #[getter]
    fn quota_mib(&self) -> Option<u32> {
        self.inner.quota_mib()
    }

    #[getter]
    fn kind(&self, py: Python<'_>) -> PyResult<PyObject> {
        str_enum_member(py, "VolumeKind", self.inner.kind().as_str())
    }

    #[getter]
    fn used_bytes(&self) -> u64 {
        self.inner.used_bytes()
    }

    #[getter]
    fn capacity_bytes(&self) -> Option<u64> {
        self.inner.capacity_bytes()
    }

    #[getter]
    fn disk_format(&self, py: Python<'_>) -> PyResult<Option<PyObject>> {
        self.inner
            .disk_format()
            .map(|format| str_enum_member(py, "DiskImageFormat", format))
            .transpose()
    }

    #[getter]
    fn disk_fstype(&self) -> Option<&str> {
        self.inner.disk_fstype()
    }

    #[getter]
    fn labels(&self) -> HashMap<String, String> {
        self.inner
            .labels()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    #[getter]
    fn created_at(&self) -> Option<f64> {
        self.inner
            .created_at()
            .map(|dt| dt.timestamp_millis() as f64)
    }

    /// Remove this volume.
    fn remove<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let handle = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            handle.remove().await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Host-side filesystem operations on this volume.
    #[getter]
    fn fs(&self) -> PyVolumeFs {
        PyVolumeFs {
            inner: self.inner.clone(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Types: VolumeFs
//--------------------------------------------------------------------------------------------------

/// Host-side filesystem operations on a volume (no running sandbox needed).
/// Holds a volume handle; constructs a [`VolumeFs`] per op.
#[pyclass(name = "VolumeFs")]
pub struct PyVolumeFs {
    inner: microsandbox::volume::VolumeHandle,
}

#[pymethods]
impl PyVolumeFs {
    fn read<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = handle.fs();
            let data = fs.read(&path).await.map_err(to_py_err)?;
            Ok(data.to_vec())
        })
    }

    fn read_text<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = handle.fs();
            let text = fs.read_to_string(&path).await.map_err(to_py_err)?;
            Ok(text)
        })
    }

    fn write<'py>(
        &self,
        py: Python<'py>,
        path: String,
        data: Vec<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let handle = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = handle.fs();
            fs.write(&path, &data).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    fn list<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = handle.fs();
            let entries = fs.list(&path).await.map_err(to_py_err)?;
            let py_entries: Vec<crate::fs::PyFsEntry> = entries
                .into_iter()
                .map(crate::fs::convert_fs_entry)
                .collect();
            Ok(py_entries)
        })
    }

    fn mkdir<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = handle.fs();
            fs.mkdir(&path).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    fn remove_file<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = handle.fs();
            fs.remove(&path).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    fn remove_dir<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            handle.fs().remove_dir(&path).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    fn copy<'py>(&self, py: Python<'py>, from_: String, to: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            handle.fs().copy(&from_, &to).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    fn rename<'py>(
        &self,
        py: Python<'py>,
        from_: String,
        to: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let handle = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            handle.fs().rename(&from_, &to).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    fn stat<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let metadata = handle.fs().stat(&path).await.map_err(to_py_err)?;
            Ok(crate::fs::convert_fs_metadata(&metadata))
        })
    }

    fn exists<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let handle = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = handle.fs();
            let exists = fs.exists(&path).await.map_err(to_py_err)?;
            Ok(exists)
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn mount_config_class<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    let types = PyModule::import(py, "microsandbox.types")?;
    types.getattr("MountConfig")
}

fn mount_kind<'py>(py: Python<'py>, variant: &str) -> PyResult<Bound<'py, PyAny>> {
    let types = PyModule::import(py, "microsandbox.types")?;
    types.getattr("MountKind")?.getattr(variant)
}

fn set_mount_metadata_options(
    py: Python<'_>,
    kwargs: &Bound<'_, PyDict>,
    stat_virtualization: Option<Py<PyAny>>,
    host_permissions: Option<Py<PyAny>>,
    uid: Option<Py<PyAny>>,
    gid: Option<Py<PyAny>>,
) -> PyResult<()> {
    if let Some(policy) = stat_virtualization {
        extract_str_enum(policy.bind(py), "StatVirtualization")?;
        kwargs.set_item("stat_virtualization", policy)?;
    }
    if let Some(policy) = host_permissions {
        extract_str_enum(policy.bind(py), "HostPermissions")?;
        kwargs.set_item("host_permissions", policy)?;
    }
    if uid.is_some() != gid.is_some() {
        return Err(PyValueError::new_err(
            "uid and gid must be specified together",
        ));
    }
    if let (Some(uid), Some(gid)) = (uid, gid) {
        // Keep the public names concise while preserving the author's internal
        // wire fields used by the shared MountOptions type.
        kwargs.set_item("override_uid", uid)?;
        kwargs.set_item("override_gid", gid)?;
    }
    Ok(())
}
