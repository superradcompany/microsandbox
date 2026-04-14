use std::sync::Arc;

use pyo3::prelude::*;
use tokio::sync::Mutex;

use crate::error::to_py_err;
use crate::metrics::convert_metrics;
use crate::sandbox::PySandbox;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A lightweight handle to a sandbox from the database.
#[pyclass(name = "SandboxHandle")]
pub struct PySandboxHandle {
    inner: Arc<Mutex<microsandbox::sandbox::SandboxHandle>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PySandboxHandle {
    pub fn from_rust(inner: microsandbox::sandbox::SandboxHandle) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

#[pymethods]
impl PySandboxHandle {
    /// Sandbox name.
    #[getter]
    fn name(&self) -> PyResult<String> {
        let guard = self
            .inner
            .try_lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("handle is busy"))?;
        Ok(guard.name().to_string())
    }

    /// Status: "running", "stopped", "crashed", "draining", or "paused".
    #[getter]
    fn status(&self) -> PyResult<String> {
        let guard = self
            .inner
            .try_lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("handle is busy"))?;
        Ok(format!("{:?}", guard.status()).to_lowercase())
    }

    /// Raw config JSON string.
    #[getter]
    fn config_json(&self) -> PyResult<String> {
        let guard = self
            .inner
            .try_lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("handle is busy"))?;
        Ok(guard.config_json().to_string())
    }

    /// Creation timestamp as ms since epoch.
    #[getter]
    fn created_at(&self) -> PyResult<Option<f64>> {
        let guard = self
            .inner
            .try_lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("handle is busy"))?;
        Ok(guard.created_at().map(|dt| dt.timestamp_millis() as f64))
    }

    /// Last update timestamp as ms since epoch.
    #[getter]
    fn updated_at(&self) -> PyResult<Option<f64>> {
        let guard = self
            .inner
            .try_lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("handle is busy"))?;
        Ok(guard.updated_at().map(|dt| dt.timestamp_millis() as f64))
    }

    /// Get point-in-time metrics.
    fn metrics<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let m = guard.metrics().await.map_err(to_py_err)?;
            Ok(convert_metrics(&m))
        })
    }

    /// Start the sandbox.
    #[pyo3(signature = (*, detached = false))]
    fn start<'py>(&self, py: Python<'py>, detached: bool) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sb = if detached {
                guard.start_detached().await.map_err(to_py_err)?
            } else {
                guard.start().await.map_err(to_py_err)?
            };
            Ok(PySandbox::from_rust(sb))
        })
    }

    /// Connect to an already-running sandbox (no lifecycle ownership).
    fn connect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sb = guard.connect().await.map_err(to_py_err)?;
            Ok(PySandbox::from_rust(sb))
        })
    }

    /// Stop the sandbox (SIGTERM).
    fn stop<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            guard.stop().await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Kill the sandbox (SIGKILL).
    fn kill<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            guard.kill().await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Remove the sandbox from the database.
    fn remove<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            guard.remove().await.map_err(to_py_err)?;
            Ok(())
        })
    }
}
