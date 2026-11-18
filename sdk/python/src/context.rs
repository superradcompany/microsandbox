//! Retained destinations and resource collections for Python.

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::{
    error::to_py_err,
    helpers::{sandbox_builder_with_context, str_enum_member},
    sandbox::{PySandbox, PySandboxPage},
    snapshot::PySnapshot,
    volume::PyVolume,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[pyclass(name = "Context", subclass)]
pub struct PyContext {
    pub(crate) inner: Arc<dyn microsandbox::Context>,
}

#[pyclass(name = "Sandboxes")]
pub struct PySandboxes {
    pub(crate) inner: Arc<dyn microsandbox::Context>,
}

#[pyclass(name = "Volumes")]
pub struct PyVolumes {
    pub(crate) inner: Arc<dyn microsandbox::Context>,
}

#[pyclass(name = "Snapshots")]
pub struct PySnapshots {
    pub(crate) inner: Arc<dyn microsandbox::Context>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PyContext {
    #[new]
    #[pyo3(signature = (options_json, base=None))]
    fn new(options_json: &str, base: Option<PyRef<'_, Self>>) -> PyResult<Self> {
        let inner = match base {
            Some(base) => microsandbox::context::derive_remote_from_options_json(
                base.inner.as_ref(),
                options_json,
            ),
            None => microsandbox::context::from_options_json(options_json),
        }
        .map_err(to_py_err)?;
        Ok(Self { inner })
    }
    #[getter]
    fn kind(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let kind = match self.inner.kind() {
            microsandbox::context::ContextKind::Local => "local",
            microsandbox::context::ContextKind::Remote => "remote",
        };
        str_enum_member(py, "ContextKind", kind)
    }
    #[getter]
    fn sandboxes(&self) -> PySandboxes {
        PySandboxes {
            inner: self.inner.clone(),
        }
    }
    #[getter]
    fn volumes(&self) -> PyVolumes {
        PyVolumes {
            inner: self.inner.clone(),
        }
    }
    #[getter]
    fn snapshots(&self) -> PySnapshots {
        PySnapshots {
            inner: self.inner.clone(),
        }
    }
}

#[pymethods]
impl PySandboxes {
    /// Restore on this destination, preserving explicit snapshot ID/path interpretation.
    #[pyo3(signature = (snapshot, *, name, **kwargs))]
    fn restore<'py>(
        &self,
        py: Python<'py>,
        snapshot: &Bound<'py, PyAny>,
        name: String,
        kwargs: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let builder = crate::helpers::restore_builder_with_context(
            self.inner.clone(),
            snapshot,
            name,
            kwargs,
        )?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            builder
                .restore()
                .await
                .map(PySandbox::from_rust)
                .map_err(to_py_err)
        })
    }

    #[pyo3(signature = (snapshot, *, name, **kwargs))]
    fn restore_with_progress<'py>(
        &self,
        snapshot: &Bound<'py, PyAny>,
        name: String,
        kwargs: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<crate::sandbox::PyPullSession> {
        let builder = crate::helpers::restore_builder_with_context(
            self.inner.clone(),
            snapshot,
            name,
            kwargs,
        )?;
        let _guard = pyo3_async_runtimes::tokio::get_runtime().enter();
        let (progress, task) = builder.restore_with_progress().map_err(to_py_err)?;
        Ok(crate::sandbox::PyPullSession::new(progress, task))
    }

    #[pyo3(signature = (name, **kwargs))]
    fn create_with_progress<'py>(
        &self,
        name: String,
        kwargs: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<crate::sandbox::PyPullSession> {
        let builder = sandbox_builder_with_context(self.inner.clone(), name, kwargs)?;
        let detached = kwargs
            .and_then(|kw| kw.get_item("detached").ok().flatten())
            .map(|value| value.extract::<bool>())
            .transpose()?
            .unwrap_or(false);
        let _guard = pyo3_async_runtimes::tokio::get_runtime().enter();
        let (progress, task) = if detached {
            builder.create_detached_with_progress()
        } else {
            builder.create_with_progress()
        }
        .map_err(to_py_err)?;
        Ok(crate::sandbox::PyPullSession::new(progress, task))
    }

    #[getter]
    fn context(&self) -> PyContext {
        PyContext {
            inner: self.inner.clone(),
        }
    }

    #[pyo3(signature = (name, **kwargs))]
    fn create<'py>(
        &self,
        py: Python<'py>,
        name: String,
        kwargs: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let builder = sandbox_builder_with_context(self.inner.clone(), name, kwargs)?;
        let detached = kwargs
            .and_then(|kw| kw.get_item("detached").ok().flatten())
            .map(|v| v.extract::<bool>())
            .transpose()?
            .unwrap_or(false);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = if detached {
                builder.create_detached().await
            } else {
                builder.create().await
            };
            sandbox.map(PySandbox::from_rust).map_err(to_py_err)
        })
    }

    #[pyo3(signature = (name, **kwargs))]
    fn connect_or_create<'py>(
        &self,
        py: Python<'py>,
        name: String,
        kwargs: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let builder = sandbox_builder_with_context(self.inner.clone(), name, kwargs)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            builder
                .connect_or_create()
                .await
                .map(PySandbox::from_rust)
                .map_err(to_py_err)
        })
    }

    fn get<'py>(&self, py: Python<'py>, name: String) -> PyResult<Bound<'py, PyAny>> {
        let collection = self.inner.sandboxes();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            collection
                .get(&name)
                .await
                .map(PySandbox::from_rust)
                .map_err(to_py_err)
        })
    }
    fn get_running<'py>(&self, py: Python<'py>, name: String) -> PyResult<Bound<'py, PyAny>> {
        let collection = self.inner.sandboxes();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            collection
                .get_running(&name)
                .await
                .map(PySandbox::from_rust)
                .map_err(to_py_err)
        })
    }
    #[pyo3(signature = (*, limit=None, cursor=None, labels=None))]
    fn list<'py>(
        &self,
        py: Python<'py>,
        limit: Option<u32>,
        cursor: Option<String>,
        labels: Option<HashMap<String, String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let collection = self.inner.sandboxes();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            collection
                .list_with(|mut query| {
                    if let Some(limit) = limit {
                        query = query.limit(limit);
                    }
                    if let Some(cursor) = cursor {
                        query = query.cursor(cursor);
                    }
                    if let Some(labels) = labels {
                        query = query.labels(labels);
                    }
                    query
                })
                .await
                .map(PySandboxPage::from_rust)
                .map_err(to_py_err)
        })
    }
    #[pyo3(signature = (name, *, detached=false))]
    fn start<'py>(
        &self,
        py: Python<'py>,
        name: String,
        detached: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let context = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let record = context
                .sandbox_ops()
                .get(context.clone(), &name)
                .await
                .map_err(to_py_err)?;
            let result = if detached {
                record.start_detached().await
            } else {
                record.start().await
            };
            result.map(PySandbox::from_rust).map_err(to_py_err)
        })
    }
    fn remove<'py>(&self, py: Python<'py>, name: String) -> PyResult<Bound<'py, PyAny>> {
        let context = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            context
                .sandbox_ops()
                .remove(context.clone(), &name)
                .await
                .map_err(to_py_err)?;
            Ok(Python::attach(|py| py.None()))
        })
    }
}

#[pymethods]
impl PyVolumes {
    #[getter]
    fn context(&self) -> PyContext {
        PyContext {
            inner: self.inner.clone(),
        }
    }
    #[pyo3(signature = (name, *, kind=None, size_mib=None, quota_mib=None, labels=None))]
    fn create<'py>(
        &self,
        py: Python<'py>,
        name: String,
        kind: Option<Py<PyAny>>,
        size_mib: Option<u32>,
        quota_mib: Option<u32>,
        labels: Option<HashMap<String, String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        crate::volume::create_in(
            self.inner.clone(),
            py,
            name,
            kind,
            size_mib,
            quota_mib,
            labels,
        )
    }
    fn get<'py>(&self, py: Python<'py>, name: String) -> PyResult<Bound<'py, PyAny>> {
        let collection = self.inner.volumes();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            collection
                .get(&name)
                .await
                .map(PyVolume::from_rust)
                .map_err(to_py_err)
        })
    }
    fn get_default<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let collection = self.inner.volumes();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            collection
                .get_default()
                .await
                .map(PyVolume::from_rust)
                .map_err(to_py_err)
        })
    }
    fn list<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let collection = self.inner.volumes();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            collection
                .list()
                .await
                .map(|values| {
                    values
                        .into_iter()
                        .map(PyVolume::from_rust)
                        .collect::<Vec<_>>()
                })
                .map_err(to_py_err)
        })
    }
    fn remove<'py>(&self, py: Python<'py>, name: String) -> PyResult<Bound<'py, PyAny>> {
        let collection = self.inner.volumes();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            collection.remove(&name).await.map_err(to_py_err)?;
            Ok(Python::attach(|py| py.None()))
        })
    }
}

#[pymethods]
impl PySnapshots {
    fn group_head<'py>(&self, py: Python<'py>, group: String) -> PyResult<Bound<'py, PyAny>> {
        crate::snapshot::group_head_in(self.inner.clone(), py, group)
    }
    fn set_group_head<'py>(
        &self,
        py: Python<'py>,
        group: String,
        id: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        crate::snapshot::set_group_head_in(self.inner.clone(), py, group, id)
    }

    #[getter]
    fn context(&self) -> PyContext {
        PyContext {
            inner: self.inner.clone(),
        }
    }
    // Python keyword arguments intentionally mirror the default creation surface.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (name="".to_string(), *, from_sandbox, group=None, dest_dir=None, labels=None, force=false, record_integrity=false, full=false, guest_flush=None))]
    fn create<'py>(
        &self,
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
        crate::snapshot::create_in(
            self.inner.clone(),
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
    fn get<'py>(&self, py: Python<'py>, reference: String) -> PyResult<Bound<'py, PyAny>> {
        let collection = self.inner.snapshots();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            collection
                .get(&reference)
                .await
                .map(PySnapshot::from_rust)
                .map_err(to_py_err)
        })
    }
    fn list<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let collection = self.inner.snapshots();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            collection
                .list()
                .await
                .map(|values| {
                    values
                        .into_iter()
                        .map(PySnapshot::from_rust)
                        .collect::<Vec<_>>()
                })
                .map_err(to_py_err)
        })
    }
    #[pyo3(signature = (reference, *, force=false))]
    fn remove<'py>(
        &self,
        py: Python<'py>,
        reference: String,
        force: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let collection = self.inner.snapshots();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            collection
                .remove(reference, force)
                .await
                .map_err(to_py_err)?;
            Ok(Python::attach(|py| py.None()))
        })
    }
}
