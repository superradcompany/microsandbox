//! Python bindings for the cloud `Service` resource.

use microsandbox::{Service, ServicePage, ServiceStatus, ServiceTarget};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::error::{to_py_change_err, to_py_err};
use crate::helpers::str_enum_member;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A public URL for one sandbox port. Services require a cloud backend.
#[pyclass(from_py_object, name = "Service", frozen)]
#[derive(Clone)]
pub struct PyService {
    inner: Service,
}

/// One page of Services.
#[pyclass(name = "ServicePage", get_all, frozen)]
pub struct PyServicePage {
    services: Vec<PyService>,
    next_cursor: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PyService {
    /// Create a Service for a running target without retrying.
    ///
    /// Get and check the Service if the task is cancelled after the request is sent.
    #[staticmethod]
    #[pyo3(signature = (slug, *, target))]
    fn create<'py>(
        py: Python<'py>,
        slug: String,
        target: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let target = extract_target(target)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut builder = Service::builder(slug);
            if let Some(target) = target {
                builder = builder.target(target.sandbox, target.port);
            }

            let inner = builder.create().await.map_err(to_py_change_err)?;
            Ok(PyService { inner })
        })
    }

    /// Get a Service by slug.
    #[staticmethod]
    fn get(py: Python<'_>, slug: String) -> PyResult<Bound<'_, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let inner = Service::get(&slug).await.map_err(to_py_err)?;
            Ok(PyService { inner })
        })
    }

    /// List the first page of the organization's Services.
    #[staticmethod]
    fn list(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let page = Service::list().await.map_err(to_py_err)?;
            Ok(PyServicePage::from_rust(page))
        })
    }

    /// List a configured page of the organization's Services.
    #[staticmethod]
    #[pyo3(signature = (*, sandbox = None, cursor = None, limit = None))]
    fn list_with(
        py: Python<'_>,
        sandbox: Option<String>,
        cursor: Option<String>,
        limit: Option<u32>,
    ) -> PyResult<Bound<'_, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let page = Service::list_with(|list| {
                let mut list = list;
                if let Some(sandbox) = sandbox {
                    list = list.sandbox(sandbox);
                }
                if let Some(cursor) = cursor {
                    list = list.cursor(cursor);
                }
                if let Some(limit) = limit {
                    list = list.limit(limit);
                }
                list
            })
            .await
            .map_err(to_py_err)?;
            Ok(PyServicePage::from_rust(page))
        })
    }

    /// The Service's globally unique slug.
    #[getter]
    fn slug(&self) -> &str {
        self.inner.slug()
    }

    /// The Service's public URL as returned by the backend.
    #[getter]
    fn url(&self) -> &str {
        self.inner.url()
    }

    /// Whether the Service routes requests, is disabled, or has no target, as of the read that
    /// returned this value. `refresh()` returns a current copy.
    #[getter]
    fn status(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        str_enum_member(py, "ServiceStatus", service_status(self.inner.status()))
    }

    /// The target, or `None` when the Service is detached.
    #[getter]
    fn target(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        self.inner
            .target()
            .map(|target| target_to_py(py, target))
            .transpose()
    }

    /// Creation timestamp (ms since epoch).
    #[getter]
    fn created_at(&self) -> f64 {
        self.inner.created_at().timestamp_millis() as f64
    }

    /// Last change timestamp (ms since epoch), including a detach.
    #[getter]
    fn updated_at(&self) -> f64 {
        self.inner.updated_at().timestamp_millis() as f64
    }

    /// Change the target without retrying. Setting a target also enables or reattaches the
    /// Service.
    ///
    /// Get and check the Service if the task is cancelled after the request is sent.
    #[pyo3(signature = (*, target))]
    fn update<'py>(
        &self,
        py: Python<'py>,
        target: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let target = extract_target(target)?;
        let service = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let inner = service
                .update(|update| {
                    let mut update = update;
                    if let Some(target) = target {
                        update = update.target(target.sandbox, target.port);
                    }
                    update
                })
                .await
                .map_err(to_py_change_err)?;
            Ok(PyService { inner })
        })
    }

    /// Enable the Service without retrying.
    fn enable<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let service = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let inner = service.enable().await.map_err(to_py_change_err)?;
            Ok(PyService { inner })
        })
    }

    /// Disable the Service without retrying while retaining its target.
    fn disable<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let service = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let inner = service.disable().await.map_err(to_py_change_err)?;
            Ok(PyService { inner })
        })
    }

    /// Remove the Service and release its slug without retrying.
    fn remove<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let service = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            service.remove().await.map_err(to_py_change_err)?;
            Ok(())
        })
    }

    /// Get the Service again and return its current state. This object is not changed.
    fn refresh<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let service = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let inner = service.refresh().await.map_err(to_py_err)?;
            Ok(PyService { inner })
        })
    }
}

impl PyServicePage {
    fn from_rust(page: ServicePage) -> Self {
        Self {
            services: page
                .services
                .into_iter()
                .map(|inner| PyService { inner })
                .collect(),
            next_cursor: page.next_cursor,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn extract_target(target: Option<Bound<'_, PyAny>>) -> PyResult<Option<ServiceTarget>> {
    target
        .map(|target| {
            Ok(ServiceTarget {
                sandbox: target.getattr("sandbox")?.extract()?,
                port: target.getattr("port")?.extract()?,
            })
        })
        .transpose()
}

fn target_to_py(py: Python<'_>, target: ServiceTarget) -> PyResult<Py<PyAny>> {
    let class = PyModule::import(py, "microsandbox.types")?.getattr("ServiceTarget")?;
    Ok(class.call1((target.sandbox, target.port))?.unbind())
}

fn service_status(status: ServiceStatus) -> &'static str {
    status.as_str()
}
