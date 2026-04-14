use std::collections::HashMap;
use std::sync::Arc;

use pyo3::prelude::*;

use crate::error::to_py_err;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A named persistent volume.
#[pyclass(name = "Volume")]
pub struct PyVolume {
    name: String,
    path: String,
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
    #[pyo3(signature = (name, *, quota_mib=None, labels=None))]
    fn create<'py>(
        py: Python<'py>,
        name: String,
        quota_mib: Option<u32>,
        labels: Option<HashMap<String, String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut builder = microsandbox::Volume::builder(&name);
            if let Some(quota) = quota_mib {
                builder = builder.quota(quota);
            }
            if let Some(labels) = labels {
                for (k, v) in labels {
                    builder = builder.label(k, v);
                }
            }
            let vol = builder.create().await.map_err(to_py_err)?;
            Ok(PyVolume {
                name: vol.name().to_string(),
                path: vol.path().display().to_string(),
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
    fn path(&self) -> &str {
        &self.path
    }

    //----------------------------------------------------------------------------------------------
    // Static Factories (for mount configs — return dicts)
    //----------------------------------------------------------------------------------------------

    /// Create a bind mount config.
    #[staticmethod]
    #[pyo3(signature = (path, *, readonly = false))]
    fn bind(py: Python<'_>, path: String, readonly: bool) -> PyResult<PyObject> {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("bind", path)?;
        dict.set_item("readonly", readonly)?;
        Ok(dict.into())
    }

    /// Create a named volume mount config.
    #[staticmethod]
    #[pyo3(signature = (name, *, readonly = false))]
    fn named(py: Python<'_>, name: String, readonly: bool) -> PyResult<PyObject> {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("named", name)?;
        dict.set_item("readonly", readonly)?;
        Ok(dict.into())
    }

    /// Create a tmpfs mount config.
    #[staticmethod]
    #[pyo3(signature = (*, size_mib = None, readonly = false))]
    fn tmpfs(py: Python<'_>, size_mib: Option<u32>, readonly: bool) -> PyResult<PyObject> {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("tmpfs", true)?;
        if let Some(size) = size_mib {
            dict.set_item("size_mib", size)?;
        }
        dict.set_item("readonly", readonly)?;
        Ok(dict.into())
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
    fn quota_mib(&self) -> Option<u32> {
        self.inner.quota_mib()
    }

    #[getter]
    fn used_bytes(&self) -> u64 {
        self.inner.used_bytes()
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
        let name = self.inner.name().to_string();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            microsandbox::Volume::remove(&name)
                .await
                .map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Host-side filesystem operations on this volume.
    #[getter]
    fn fs(&self) -> PyVolumeFs {
        let vol_dir = microsandbox::config::config()
            .volumes_dir()
            .join(self.inner.name());
        PyVolumeFs {
            vol_dir: vol_dir.to_string_lossy().into(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Types: VolumeFs
//--------------------------------------------------------------------------------------------------

/// Host-side filesystem operations on a volume (no running sandbox needed).
/// Path resolved once at construction — zero DB lookups per operation.
#[pyclass(name = "VolumeFs")]
pub struct PyVolumeFs {
    vol_dir: Arc<str>,
}

#[pymethods]
impl PyVolumeFs {
    fn read<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let dir = Arc::clone(&self.vol_dir);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::volume::VolumeFs::from_path((*dir).into());
            let data = fs.read(&path).await.map_err(to_py_err)?;
            Ok(data.to_vec())
        })
    }

    fn read_text<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let dir = Arc::clone(&self.vol_dir);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::volume::VolumeFs::from_path((*dir).into());
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
        let dir = Arc::clone(&self.vol_dir);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::volume::VolumeFs::from_path((*dir).into());
            fs.write(&path, &data).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    fn list<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let dir = Arc::clone(&self.vol_dir);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::volume::VolumeFs::from_path((*dir).into());
            let entries = fs.list(&path).await.map_err(to_py_err)?;
            let py_entries: Vec<crate::fs::PyFsEntry> = entries
                .into_iter()
                .map(crate::fs::convert_fs_entry)
                .collect();
            Ok(py_entries)
        })
    }

    fn mkdir<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let dir = Arc::clone(&self.vol_dir);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::volume::VolumeFs::from_path((*dir).into());
            fs.mkdir(&path).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    fn remove_file<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let dir = Arc::clone(&self.vol_dir);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::volume::VolumeFs::from_path((*dir).into());
            fs.remove(&path).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    fn exists<'py>(&self, py: Python<'py>, path: String) -> PyResult<Bound<'py, PyAny>> {
        let dir = Arc::clone(&self.vol_dir);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let fs = microsandbox::volume::VolumeFs::from_path((*dir).into());
            let exists = fs.exists(&path).await.map_err(to_py_err)?;
            Ok(exists)
        })
    }
}
