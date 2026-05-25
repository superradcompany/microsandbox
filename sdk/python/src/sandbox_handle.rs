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

    /// Read captured output from `exec.log`.
    ///
    /// Works without starting the sandbox. Defaults to `stdout +
    /// stderr` sources when `sources` is `None`.
    #[pyo3(signature = (tail = None, since_ms = None, until_ms = None, sources = None))]
    fn logs<'py>(
        &self,
        py: Python<'py>,
        tail: Option<usize>,
        since_ms: Option<f64>,
        until_ms: Option<f64>,
        sources: Option<Vec<String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let name = guard.name().to_string();
            drop(guard);
            let entries = tokio::task::spawn_blocking(move || {
                crate::logs::read_logs_blocking(&name, tail, since_ms, until_ms, sources)
            })
            .await
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))??;
            Ok(entries)
        })
    }

    /// Stream captured output as it appears, with optional follow.
    ///
    /// Works without starting the sandbox; with `follow=True`, the
    /// stream picks up new entries the moment they land in
    /// `exec.log`. `since_ms` and `from_cursor` are mutually
    /// exclusive.
    #[pyo3(signature = (
        sources = None,
        since_ms = None,
        from_cursor = None,
        until_ms = None,
        follow = false,
    ))]
    fn log_stream<'py>(
        &self,
        py: Python<'py>,
        sources: Option<Vec<String>>,
        since_ms: Option<f64>,
        from_cursor: Option<String>,
        until_ms: Option<f64>,
        follow: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let opts = crate::logs::parse_log_stream_options(
            sources,
            since_ms,
            from_cursor,
            until_ms,
            follow,
        )?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let name = guard.name().to_string();
            drop(guard);
            crate::logs::open_log_stream(&name, opts).await
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
    ///
    /// Returns a typed error if the sandbox doesn't respond within ten
    /// seconds. Use [`connect_with_timeout`](Self::connect_with_timeout)
    /// to override.
    fn connect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sb = guard.connect().await.map_err(to_py_err)?;
            Ok(PySandbox::from_rust(sb))
        })
    }

    /// Connect with an explicit timeout in seconds.
    ///
    /// If the sandbox doesn't respond within `timeout` seconds, the
    /// call returns a typed error instead of blocking.
    fn connect_with_timeout<'py>(
        &self,
        py: Python<'py>,
        timeout: f64,
    ) -> PyResult<Bound<'py, PyAny>> {
        if timeout < 0.0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "timeout must be non-negative",
            ));
        }
        let inner = self.inner.clone();
        let timeout = std::time::Duration::from_secs_f64(timeout);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sb = guard
                .connect_with_timeout(timeout)
                .await
                .map_err(to_py_err)?;
            Ok(PySandbox::from_rust(sb))
        })
    }

    /// Stop the sandbox gracefully.
    ///
    /// Lets the sandbox finish writing any pending data to disk before
    /// it exits, so files written inside the sandbox aren't lost across
    /// a later restart. Waits up to ten seconds for a clean exit; if
    /// the sandbox is still running after that, it is force-killed. Use
    /// [`stop_with_timeout`](Self::stop_with_timeout) to override the
    /// budget.
    fn stop<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            guard.stop().await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Stop gracefully with an explicit timeout in seconds.
    ///
    /// If the sandbox is still running after `timeout` seconds, it is
    /// force-killed. `timeout=0` force-kills immediately. The call
    /// returns successfully either way — it does not surface a timeout
    /// error.
    fn stop_with_timeout<'py>(&self, py: Python<'py>, timeout: f64) -> PyResult<Bound<'py, PyAny>> {
        if timeout < 0.0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "timeout must be non-negative",
            ));
        }
        let inner = self.inner.clone();
        let timeout = std::time::Duration::from_secs_f64(timeout);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            guard.stop_with_timeout(timeout).await.map_err(to_py_err)?;
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

    /// Snapshot this (stopped) sandbox under a bare name. Resolves
    /// under `~/.microsandbox/snapshots/<name>/`. For an explicit
    /// filesystem destination, see `snapshot_to`.
    fn snapshot<'py>(&self, py: Python<'py>, name: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let snap = guard.snapshot(&name).await.map_err(to_py_err)?;
            Ok(crate::snapshot::PySnapshot::from_rust(snap))
        })
    }

    /// Snapshot this (stopped) sandbox to an explicit filesystem path.
    fn snapshot_to<'py>(
        &self,
        py: Python<'py>,
        path: std::path::PathBuf,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let snap = guard.snapshot_to(path).await.map_err(to_py_err)?;
            Ok(crate::snapshot::PySnapshot::from_rust(snap))
        })
    }
}
