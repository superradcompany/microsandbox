use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyList};
use tokio::sync::Mutex;

use crate::error::to_py_err;
use crate::metrics::convert_metrics;
use crate::sandbox::{
    PySandbox, PySandboxPingResult, PySandboxStopResult, PySandboxTouchResult, optional_duration,
};

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
    /// Sandbox name. Names are limited to 128 UTF-8 bytes.
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
        Ok(format!("{:?}", guard.status_snapshot()).to_lowercase())
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

    /// Parsed sandbox configuration.
    fn config(&self, py: Python<'_>) -> PyResult<PyObject> {
        let guard = self
            .inner
            .try_lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("handle is busy"))?;
        let value: serde_json::Value =
            serde_json::from_str(guard.config_json()).map_err(|e| to_py_err(e.into()))?;
        json_value_to_py(py, value)
    }

    /// Return a fresh handle for the same sandbox.
    fn refresh<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let refreshed = guard.refresh().await.map_err(to_py_err)?;
            Ok(PySandboxHandle::from_rust(refreshed))
        })
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

    /// Check whether agentd is reachable without refreshing idle activity.
    ///
    /// Connects to an already-running sandbox; stopped sandboxes are not
    /// started implicitly.
    fn ping<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let result = guard.ping().await.map_err(to_py_err)?;
            Ok(PySandboxPingResult::from_rust(result))
        })
    }

    /// Explicitly refresh this sandbox's idle activity timer.
    ///
    /// Connects to an already-running sandbox; stopped sandboxes are not
    /// started implicitly.
    fn touch<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let result = guard.touch().await.map_err(to_py_err)?;
            Ok(PySandboxTouchResult::from_rust(result))
        })
    }

    /// Plan or apply a sandbox modification. Returns the plan as a dict.
    ///
    /// `memory` / `max_memory` are in MiB. `policy` is `"no_restart"`
    /// (default), `"next_start"`, or `"restart"`. With `dry_run=True` the
    /// plan is computed without applying anything.
    ///
    /// `secrets` maps secret names to spec dicts with at most one of
    /// `"env"` / `"value"` / `"store"`, plus optional `"placeholder"` and
    /// `"allowed_hosts"`. `secrets_rm` removes secrets by name.
    #[pyo3(signature = (
        *,
        cpus = None,
        max_cpus = None,
        memory = None,
        max_memory = None,
        env = None,
        env_rm = None,
        labels = None,
        labels_rm = None,
        workdir = None,
        secrets = None,
        secrets_rm = None,
        policy = None,
        dry_run = false,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn modify<'py>(
        &self,
        py: Python<'py>,
        cpus: Option<u8>,
        max_cpus: Option<u8>,
        memory: Option<u32>,
        max_memory: Option<u32>,
        env: Option<std::collections::HashMap<String, String>>,
        env_rm: Option<Vec<String>>,
        labels: Option<std::collections::HashMap<String, String>>,
        labels_rm: Option<Vec<String>>,
        workdir: Option<String>,
        secrets: Option<
            std::collections::HashMap<String, std::collections::HashMap<String, Py<PyAny>>>,
        >,
        secrets_rm: Option<Vec<String>>,
        policy: Option<String>,
        dry_run: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let secrets = crate::sandbox::build_secret_patches(py, secrets)?;
        let patch = crate::sandbox::build_modify_patch(
            cpus, max_cpus, memory, max_memory, env, env_rm, labels, labels_rm, workdir, secrets,
            secrets_rm,
        );
        let policy = crate::sandbox::parse_modify_policy(policy.as_deref())?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let builder =
                crate::sandbox::apply_modify_policy(guard.modify().with_patch(patch), policy);
            drop(guard);
            crate::sandbox::run_modify(builder, dry_run).await
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
        let opts = crate::logs::parse_log_options(tail, since_ms, until_ms, sources)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let entries = guard.logs(&opts).await.map_err(to_py_err)?;
            Ok(entries
                .into_iter()
                .map(crate::logs::convert_entry)
                .collect::<Vec<_>>())
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
            let stream = guard.log_stream(&opts).await.map_err(to_py_err)?;
            Ok(crate::logs::PyLogStream::new(stream))
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

    /// Connect to an already-running sandbox.
    #[pyo3(signature = (timeout = None))]
    fn connect<'py>(&self, py: Python<'py>, timeout: Option<f64>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let timeout = optional_duration(timeout)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sb = match timeout {
                Some(timeout) => guard
                    .connect_with_timeout(timeout)
                    .await
                    .map_err(to_py_err)?,
                None => guard.connect().await.map_err(to_py_err)?,
            };
            Ok(PySandbox::from_rust(sb))
        })
    }

    /// Stop the sandbox gracefully and wait until stopped.
    #[pyo3(signature = (timeout = None))]
    fn stop<'py>(&self, py: Python<'py>, timeout: Option<f64>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let timeout = optional_duration(timeout)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            match timeout {
                Some(timeout) => guard.stop_with_timeout(timeout).await.map_err(to_py_err)?,
                None => guard.stop().await.map_err(to_py_err)?,
            }
            Ok(())
        })
    }

    /// Request graceful shutdown without waiting.
    fn request_stop<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            guard.request_stop().await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Kill the sandbox (SIGKILL).
    #[pyo3(signature = (timeout = None))]
    fn kill<'py>(&self, py: Python<'py>, timeout: Option<f64>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let timeout = optional_duration(timeout)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            match timeout {
                Some(timeout) => guard.kill_with_timeout(timeout).await.map_err(to_py_err)?,
                None => guard.kill().await.map_err(to_py_err)?,
            }
            Ok(())
        })
    }

    /// Request force termination without waiting.
    fn request_kill<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            guard.request_kill().await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Request drain without waiting.
    fn request_drain<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            guard.request_drain().await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Wait until the sandbox is observed in a terminal non-running state.
    fn wait_until_stopped<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let result = guard.wait_until_stopped().await.map_err(to_py_err)?;
            Ok(PySandboxStopResult::from_rust(result))
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
    /// under `~/.microsandbox/snapshots/<name>/`. Move artifacts with
    /// `Snapshot.save`/`Snapshot.load`.
    fn snapshot<'py>(&self, py: Python<'py>, name: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let snap = guard.snapshot(&name).await.map_err(to_py_err)?;
            Ok(crate::snapshot::PySnapshot::from_rust(snap))
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn json_value_to_py(py: Python<'_>, value: serde_json::Value) -> PyResult<PyObject> {
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
