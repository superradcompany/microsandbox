use std::collections::HashMap;
use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use tokio::sync::Mutex;

use crate::error::to_py_err;
use crate::exec::{PyExecHandle, PyExecOutput};
use crate::fs::PySandboxFs;
use crate::helpers::sandbox_builder_from_args;
use crate::logs::read_logs_blocking;
use crate::metrics::PyMetricsStream;
use crate::metrics::convert_metrics;
use crate::sandbox_handle::PySandboxHandle;
use crate::ssh::PySandboxSsh;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A running sandbox instance.
///
/// Sandbox names are limited to 128 UTF-8 bytes.
#[pyclass(name = "Sandbox")]
pub struct PySandbox {
    inner: Arc<Mutex<Option<microsandbox::sandbox::Sandbox>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PySandbox {
    pub fn from_rust(inner: microsandbox::sandbox::Sandbox) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(inner))),
        }
    }

    async fn clone_sandbox(
        inner: &Arc<Mutex<Option<microsandbox::sandbox::Sandbox>>>,
    ) -> PyResult<microsandbox::sandbox::Sandbox> {
        let guard = inner.lock().await;
        let sb = guard.as_ref().ok_or_else(crate::error::consumed)?;
        Ok(sb.clone())
    }

    async fn with_sandbox<F, R>(
        inner: &Arc<Mutex<Option<microsandbox::sandbox::Sandbox>>>,
        f: F,
    ) -> PyResult<R>
    where
        F: FnOnce(&microsandbox::sandbox::Sandbox) -> R,
    {
        let guard = inner.lock().await;
        let sb = guard.as_ref().ok_or_else(crate::error::consumed)?;
        Ok(f(sb))
    }
}

#[pymethods]
impl PySandbox {
    //----------------------------------------------------------------------------------------------
    // Static Methods — Creation
    //----------------------------------------------------------------------------------------------

    /// Create a sandbox from a name and keyword-only configuration.
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
    #[staticmethod]
    #[pyo3(signature = (name, **kwargs))]
    fn create<'py>(
        py: Python<'py>,
        name: String,
        kwargs: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let builder = sandbox_builder_from_args(name, kwargs)?;
        let detached = kwargs
            .and_then(|kw| kw.get_item("detached").ok().flatten())
            .and_then(|v| v.extract::<bool>().ok())
            .unwrap_or(false);

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sb = builder
                .detached(detached)
                .create()
                .await
                .map_err(to_py_err)?;
            Ok(PySandbox::from_rust(sb))
        })
    }

    /// Start an existing stopped sandbox.
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
    #[staticmethod]
    #[pyo3(signature = (name, *, detached = false))]
    fn start<'py>(py: Python<'py>, name: String, detached: bool) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sb = if detached {
                microsandbox::sandbox::Sandbox::start_detached(&name)
                    .await
                    .map_err(to_py_err)?
            } else {
                microsandbox::sandbox::Sandbox::start(&name)
                    .await
                    .map_err(to_py_err)?
            };
            Ok(PySandbox::from_rust(sb))
        })
    }

    /// Create a sandbox with pull progress reporting.
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
    /// Returns a PullSession async context manager.
    #[staticmethod]
    #[pyo3(signature = (name, **kwargs))]
    fn create_with_progress<'py>(
        _py: Python<'py>,
        name: String,
        kwargs: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<PyPullSession> {
        let builder = sandbox_builder_from_args(name, kwargs)?;
        let detached = kwargs
            .and_then(|kw| kw.get_item("detached").ok().flatten())
            .and_then(|v| v.extract::<bool>().ok())
            .unwrap_or(false);

        // `create_with_progress()` is intentionally synchronous from Python, but
        // the Rust builder spawns the creation task immediately. Enter the
        // pyo3-owned Tokio runtime so that spawn has a reactor even before the
        // caller reaches `async with session`.
        let runtime = pyo3_async_runtimes::tokio::get_runtime();
        let _runtime_guard = runtime.enter();

        let (progress, task) = builder
            .detached(detached)
            .create_with_pull_progress()
            .map_err(to_py_err)?;

        Ok(PyPullSession::new(progress, task))
    }

    //----------------------------------------------------------------------------------------------
    // Static Methods — Lookup
    //----------------------------------------------------------------------------------------------

    /// Get a lightweight handle to an existing sandbox.
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
    #[staticmethod]
    fn get<'py>(py: Python<'py>, name: String) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let handle = microsandbox::sandbox::Sandbox::get(&name)
                .await
                .map_err(to_py_err)?;
            Ok(PySandboxHandle::from_rust(handle))
        })
    }

    /// List all sandboxes.
    #[staticmethod]
    fn list<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let handles = microsandbox::sandbox::Sandbox::list()
                .await
                .map_err(to_py_err)?;
            let py_handles: Vec<PySandboxHandle> = handles
                .into_iter()
                .map(PySandboxHandle::from_rust)
                .collect();
            Ok(py_handles)
        })
    }

    /// List sandboxes filtered to those carrying all of the given `labels`
    /// (AND-matched).
    #[staticmethod]
    #[pyo3(signature = (*, labels = None))]
    fn list_with<'py>(
        py: Python<'py>,
        labels: Option<HashMap<String, String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let filter =
                microsandbox::sandbox::SandboxFilter::new().labels(labels.unwrap_or_default());
            let handles = microsandbox::sandbox::Sandbox::list_with(filter)
                .await
                .map_err(to_py_err)?;
            let py_handles: Vec<PySandboxHandle> = handles
                .into_iter()
                .map(PySandboxHandle::from_rust)
                .collect();
            Ok(py_handles)
        })
    }

    /// Remove a stopped sandbox.
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
    #[staticmethod]
    fn remove<'py>(py: Python<'py>, name: String) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            microsandbox::sandbox::Sandbox::remove(&name)
                .await
                .map_err(to_py_err)?;
            Ok(())
        })
    }

    //----------------------------------------------------------------------------------------------
    // Properties
    //----------------------------------------------------------------------------------------------

    /// Sandbox name. Names are limited to 128 UTF-8 bytes.
    #[getter]
    fn name<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let name = Self::with_sandbox(&inner, |sb| sb.name().to_string()).await?;
            Ok(name)
        })
    }

    /// Whether this handle owns the sandbox lifecycle.
    #[getter]
    fn owns_lifecycle<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let owns = Self::with_sandbox(&inner, |sb| sb.owns_lifecycle()).await?;
            Ok(owns)
        })
    }

    /// Get a filesystem handle. Extracts the AgentClient Arc — no lock per FS op.
    #[getter]
    fn fs(&self) -> PyResult<PySandboxFs> {
        let guard = self
            .inner
            .try_lock()
            .map_err(|_| pyo3::exceptions::PyRuntimeError::new_err("sandbox is busy"))?;
        let sb = guard.as_ref().ok_or_else(crate::error::consumed)?;
        Ok(PySandboxFs::from_client(sb.client_arc()))
    }

    //----------------------------------------------------------------------------------------------
    // Execution
    //----------------------------------------------------------------------------------------------

    /// Execute a command and wait for completion.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        cmd,
        args = None,
        *,
        cwd = None,
        user = None,
        env = None,
        timeout = None,
        stdin = None,
        tty = false,
        rlimits = None,
    ))]
    fn exec<'py>(
        &self,
        py: Python<'py>,
        cmd: String,
        args: Option<&Bound<'py, PyAny>>,
        cwd: Option<String>,
        user: Option<String>,
        env: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        stdin: Option<&Bound<'py, PyAny>>,
        tty: bool,
        rlimits: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let (args, opts) = parse_exec_call(args, cwd, user, env, timeout, stdin, tty, rlimits)?;

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = Self::clone_sandbox(&inner).await?;
            let output = sandbox
                .exec_with(&cmd, |e| apply_exec_options(e, args, opts))
                .await
                .map_err(to_py_err)?;
            Ok(PyExecOutput::from_rust(output))
        })
    }

    /// Execute a command with streaming I/O.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        cmd,
        args = None,
        *,
        cwd = None,
        user = None,
        env = None,
        timeout = None,
        stdin = None,
        tty = false,
        rlimits = None,
    ))]
    fn exec_stream<'py>(
        &self,
        py: Python<'py>,
        cmd: String,
        args: Option<&Bound<'py, PyAny>>,
        cwd: Option<String>,
        user: Option<String>,
        env: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        stdin: Option<&Bound<'py, PyAny>>,
        tty: bool,
        rlimits: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let (args, opts) = parse_exec_call(args, cwd, user, env, timeout, stdin, tty, rlimits)?;

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = Self::clone_sandbox(&inner).await?;
            let handle = sandbox
                .exec_stream_with(&cmd, |e| apply_exec_options(e, args, opts))
                .await
                .map_err(to_py_err)?;
            Ok(PyExecHandle::from_rust(handle))
        })
    }

    /// Execute a shell command.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        script,
        *,
        cwd = None,
        user = None,
        env = None,
        timeout = None,
        stdin = None,
        tty = false,
        rlimits = None,
    ))]
    fn shell<'py>(
        &self,
        py: Python<'py>,
        script: String,
        cwd: Option<String>,
        user: Option<String>,
        env: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        stdin: Option<&Bound<'py, PyAny>>,
        tty: bool,
        rlimits: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let opts = parse_shell_call(cwd, user, env, timeout, stdin, tty, rlimits)?;

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = Self::clone_sandbox(&inner).await?;
            let output = sandbox
                .shell_with(&script, |e| apply_exec_options(e, Vec::new(), opts))
                .await
                .map_err(to_py_err)?;
            Ok(PyExecOutput::from_rust(output))
        })
    }

    /// Execute a shell command with streaming I/O.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        script,
        *,
        cwd = None,
        user = None,
        env = None,
        timeout = None,
        stdin = None,
        tty = false,
        rlimits = None,
    ))]
    fn shell_stream<'py>(
        &self,
        py: Python<'py>,
        script: String,
        cwd: Option<String>,
        user: Option<String>,
        env: Option<HashMap<String, String>>,
        timeout: Option<f64>,
        stdin: Option<&Bound<'py, PyAny>>,
        tty: bool,
        rlimits: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let opts = parse_shell_call(cwd, user, env, timeout, stdin, tty, rlimits)?;

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = Self::clone_sandbox(&inner).await?;
            let handle = sandbox
                .shell_stream_with(&script, |e| apply_exec_options(e, Vec::new(), opts))
                .await
                .map_err(to_py_err)?;
            Ok(PyExecHandle::from_rust(handle))
        })
    }

    //----------------------------------------------------------------------------------------------
    // SSH
    //----------------------------------------------------------------------------------------------

    /// Return the SSH namespace for this sandbox.
    fn ssh(&self) -> PySandboxSsh {
        PySandboxSsh::new(self.inner.clone())
    }

    //----------------------------------------------------------------------------------------------
    // Attach
    //----------------------------------------------------------------------------------------------

    /// Attach to the sandbox with an interactive terminal session.
    /// Note: attach requires a real terminal (PTY) and blocks the calling thread.
    /// This is primarily useful for CLI tools, not library usage.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        cmd,
        args = None,
        *,
        cwd = None,
        user = None,
        env = None,
        detach_keys = None,
    ))]
    fn attach<'py>(
        &self,
        py: Python<'py>,
        cmd: String,
        args: Option<&Bound<'py, PyAny>>,
        cwd: Option<String>,
        user: Option<String>,
        env: Option<HashMap<String, String>>,
        detach_keys: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let (args, opts) = parse_attach_call(args, cwd, user, env, detach_keys)?;

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = Self::clone_sandbox(&inner).await?;
            let exit_code = sandbox
                .attach_with(&cmd, |a| apply_attach_options(a, args, opts))
                .await
                .map_err(to_py_err)?;
            Ok(exit_code)
        })
    }

    /// Attach to the sandbox's default shell.
    fn attach_shell<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = Self::clone_sandbox(&inner).await?;
            let exit_code = sandbox.attach_shell().await.map_err(to_py_err)?;
            Ok(exit_code)
        })
    }

    //----------------------------------------------------------------------------------------------
    // Metrics
    //----------------------------------------------------------------------------------------------

    /// Get point-in-time resource metrics.
    fn metrics<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = Self::clone_sandbox(&inner).await?;
            let m = sandbox.metrics().await.map_err(to_py_err)?;
            Ok(convert_metrics(&m))
        })
    }

    //----------------------------------------------------------------------------------------------
    // Logs
    //----------------------------------------------------------------------------------------------

    /// Read captured output from `exec.log`.
    ///
    /// File-backed; works on running and stopped sandboxes alike.
    /// Defaults to `stdout + stderr` sources when `sources` is `None`.
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
            let sandbox = Self::clone_sandbox(&inner).await?;
            let name = sandbox.name().to_string();
            let entries = tokio::task::spawn_blocking(move || {
                read_logs_blocking(&name, tail, since_ms, until_ms, sources)
            })
            .await
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))??;
            Ok(entries)
        })
    }

    /// Stream metrics at a fixed interval. Returns an async iterator.
    #[pyo3(signature = (interval = 1.0))]
    fn metrics_stream<'py>(&self, py: Python<'py>, interval: f64) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let interval_dur = std::time::Duration::from_secs_f64(interval);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = Self::clone_sandbox(&inner).await?;
            let stream = sandbox.metrics_stream(interval_dur);
            Ok(PyMetricsStream::new(stream))
        })
    }

    /// Stream captured output as it appears, with optional follow.
    ///
    /// Returns an async iterator of `LogEntry`. Each entry carries
    /// an opaque `cursor` string suitable for passing back via
    /// `from_cursor` on a later call to resume exactly after that
    /// entry. `since_ms` and `from_cursor` are mutually exclusive.
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
            let sandbox = Self::clone_sandbox(&inner).await?;
            let name = sandbox.name().to_string();
            crate::logs::open_log_stream(&name, opts).await
        })
    }

    //----------------------------------------------------------------------------------------------
    // Lifecycle
    //----------------------------------------------------------------------------------------------

    /// Stop the sandbox gracefully (SIGTERM).
    fn stop<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = Self::clone_sandbox(&inner).await?;
            sandbox.stop().await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Stop and wait for exit, returning (code, success).
    fn stop_and_wait<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = Self::clone_sandbox(&inner).await?;
            let status = sandbox.stop_and_wait().await.map_err(to_py_err)?;
            Ok((status.code().unwrap_or(-1), status.success()))
        })
    }

    /// Kill the sandbox (SIGKILL).
    fn kill<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = Self::clone_sandbox(&inner).await?;
            sandbox.kill().await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Drain the sandbox (SIGUSR1).
    fn drain<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = Self::clone_sandbox(&inner).await?;
            sandbox.drain().await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Wait for the sandbox process to exit.
    fn wait<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = Self::clone_sandbox(&inner).await?;
            let status = sandbox.wait().await.map_err(to_py_err)?;
            Ok((status.code().unwrap_or(-1), status.success()))
        })
    }

    /// Detach from the sandbox (it continues running).
    fn detach<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            if let Some(sb) = guard.take() {
                sb.detach().await;
            }
            Ok(())
        })
    }

    /// Remove the persisted database record.
    fn remove_persisted<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            if let Some(sb) = guard.take() {
                sb.remove_persisted().await.map_err(to_py_err)?;
            }
            Ok(())
        })
    }

    //----------------------------------------------------------------------------------------------
    // Context Manager
    //----------------------------------------------------------------------------------------------

    fn __aenter__<'py>(slf: Bound<'py, Self>) -> PyResult<Bound<'py, PyAny>> {
        let py = slf.py();
        let obj: PyObject = slf.into();
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(obj) })
    }

    fn __aexit__<'py>(
        &self,
        py: Python<'py>,
        _exc_type: &Bound<'py, PyAny>,
        _exc_val: &Bound<'py, PyAny>,
        _exc_tb: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = {
                let mut guard = inner.lock().await;
                guard.take()
            };

            if let Some(sb) = sandbox {
                let name = sb.name().to_string();
                let _ = sb.kill().await;
                let _ = microsandbox::sandbox::Sandbox::remove(&name).await;
            }
            Ok(false) // don't suppress exceptions
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Execution Options
//--------------------------------------------------------------------------------------------------

#[derive(Default)]
struct ExecOpts {
    cwd: Option<String>,
    user: Option<String>,
    env: Vec<(String, String)>,
    timeout_secs: Option<f64>,
    tty: bool,
    stdin_mode: Option<String>,
    stdin_data: Option<Vec<u8>>,
    rlimits: Vec<(String, u64, u64)>,
}

#[derive(Default)]
struct AttachOpts {
    cwd: Option<String>,
    user: Option<String>,
    env: Vec<(String, String)>,
    detach_keys: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn parse_exec_call(
    args: Option<&Bound<'_, PyAny>>,
    cwd: Option<String>,
    user: Option<String>,
    env: Option<HashMap<String, String>>,
    timeout_secs: Option<f64>,
    stdin: Option<&Bound<'_, PyAny>>,
    tty: bool,
    rlimits: Option<&Bound<'_, PyAny>>,
) -> PyResult<(Vec<String>, ExecOpts)> {
    let (stdin_mode, stdin_data) = parse_stdin(stdin)?;
    let mut parsed_args = Vec::new();
    let mut opts = ExecOpts {
        cwd,
        user,
        env: env_to_pairs(env),
        timeout_secs,
        tty,
        stdin_mode,
        stdin_data,
        rlimits: parse_rlimits(rlimits)?,
    };

    if let Some(args_or_options) = args {
        if is_options_like(args_or_options) {
            let dict = options_dict(args_or_options, "exec options")?;
            validate_exec_options_keys(&dict)?;
            parsed_args = parse_options_args(&dict)?;
            apply_exec_options_dict(&mut opts, &dict)?;
        } else {
            parsed_args = parse_args(Some(args_or_options))?;
        }
    }

    validate_timeout(opts.timeout_secs)?;
    Ok((parsed_args, opts))
}

fn is_options_like(obj: &Bound<'_, PyAny>) -> bool {
    obj.downcast::<PyDict>().is_ok() || obj.getattr("_to_dict").is_ok()
}

fn validate_exec_options_keys(dict: &Bound<'_, PyDict>) -> PyResult<()> {
    for (key, _) in dict.iter() {
        let key = key.extract::<String>().map_err(|_| {
            pyo3::exceptions::PyTypeError::new_err("exec option keys must be strings")
        })?;
        match key.as_str() {
            "args" | "cwd" | "user" | "env" | "timeout" | "tty" | "stdin" | "stdin_data"
            | "rlimits" => {}
            other => {
                return Err(pyo3::exceptions::PyTypeError::new_err(format!(
                    "unknown exec option: {other}",
                )));
            }
        }
    }
    Ok(())
}

fn parse_options_args(dict: &Bound<'_, PyDict>) -> PyResult<Vec<String>> {
    match dict.get_item("args")? {
        Some(args) if !args.is_none() => parse_args(Some(&args)),
        _ => Ok(Vec::new()),
    }
}

fn apply_exec_options_dict(opts: &mut ExecOpts, dict: &Bound<'_, PyDict>) -> PyResult<()> {
    if let Some(cwd) = extract_optional_dict_value::<String>(dict, "cwd")? {
        opts.cwd = Some(cwd);
    }
    if let Some(user) = extract_optional_dict_value::<String>(dict, "user")? {
        opts.user = Some(user);
    }
    if let Some(env) = extract_optional_dict_value::<HashMap<String, String>>(dict, "env")? {
        opts.env = env_to_pairs(Some(env));
    }
    if let Some(timeout) = extract_optional_dict_value::<f64>(dict, "timeout")? {
        opts.timeout_secs = Some(timeout);
    }
    if let Some(tty) = extract_optional_dict_value::<bool>(dict, "tty")? {
        opts.tty = tty;
    }
    if let Some(stdin) = dict.get_item("stdin")?
        && !stdin.is_none()
    {
        let stdin_data = extract_optional_dict_value::<Vec<u8>>(dict, "stdin_data")?;
        let (mode, data) = if let Ok(mode) = stdin.extract::<String>() {
            normalize_stdin(mode, stdin_data)?
        } else {
            parse_stdin(Some(&stdin))?
        };
        opts.stdin_mode = mode;
        opts.stdin_data = data;
    } else if let Some(stdin_data) = extract_optional_dict_value::<Vec<u8>>(dict, "stdin_data")? {
        opts.stdin_mode = Some("bytes".to_string());
        opts.stdin_data = Some(stdin_data);
    }
    if let Some(rlimits) = dict.get_item("rlimits")? {
        opts.rlimits = if rlimits.is_none() {
            Vec::new()
        } else {
            parse_rlimits(Some(&rlimits))?
        };
    }
    Ok(())
}

fn extract_optional_dict_value<'py, T: FromPyObject<'py>>(
    dict: &Bound<'py, PyDict>,
    key: &str,
) -> PyResult<Option<T>> {
    dict.get_item(key)?
        .filter(|value| !value.is_none())
        .map(|value| value.extract::<T>())
        .transpose()
}

#[allow(clippy::too_many_arguments)]
fn parse_shell_call(
    cwd: Option<String>,
    user: Option<String>,
    env: Option<HashMap<String, String>>,
    timeout_secs: Option<f64>,
    stdin: Option<&Bound<'_, PyAny>>,
    tty: bool,
    rlimits: Option<&Bound<'_, PyAny>>,
) -> PyResult<ExecOpts> {
    let (stdin_mode, stdin_data) = parse_stdin(stdin)?;
    validate_timeout(timeout_secs)?;
    Ok(ExecOpts {
        cwd,
        user,
        env: env_to_pairs(env),
        timeout_secs,
        tty,
        stdin_mode,
        stdin_data,
        rlimits: parse_rlimits(rlimits)?,
    })
}

fn parse_attach_call(
    args: Option<&Bound<'_, PyAny>>,
    cwd: Option<String>,
    user: Option<String>,
    env: Option<HashMap<String, String>>,
    detach_keys: Option<String>,
) -> PyResult<(Vec<String>, AttachOpts)> {
    Ok((
        parse_args(args)?,
        AttachOpts {
            cwd,
            user,
            env: env_to_pairs(env),
            detach_keys,
        },
    ))
}

fn parse_args(args: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<String>> {
    let Some(args) = args else {
        return Ok(Vec::new());
    };
    if args.downcast::<PyDict>().is_ok() {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "args must be a list of strings",
        ));
    }
    if args.downcast::<PyBytes>().is_ok() || args.extract::<String>().is_ok() {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "args must be a list of strings, not a string",
        ));
    }
    let list = args
        .downcast::<PyList>()
        .map_err(|_| pyo3::exceptions::PyTypeError::new_err("args must be a list of strings"))?;
    list.iter().map(|item| item.extract::<String>()).collect()
}

fn options_dict<'py>(obj: &Bound<'py, PyAny>, label: &str) -> PyResult<Bound<'py, PyDict>> {
    if let Ok(dict) = obj.downcast::<PyDict>() {
        return Ok(dict.clone());
    }
    if let Ok(method) = obj.getattr("_to_dict") {
        let result = method.call0()?;
        return Ok(result.downcast::<PyDict>()?.clone());
    }
    Err(pyo3::exceptions::PyTypeError::new_err(format!(
        "{label} must be a dict or object with _to_dict()",
    )))
}

fn env_to_pairs(env: Option<HashMap<String, String>>) -> Vec<(String, String)> {
    env.unwrap_or_default().into_iter().collect()
}

fn parse_stdin(stdin: Option<&Bound<'_, PyAny>>) -> PyResult<(Option<String>, Option<Vec<u8>>)> {
    let Some(stdin) = stdin else {
        return Ok((None, None));
    };

    if let Ok(bytes) = stdin.downcast::<PyBytes>() {
        return Ok((Some("bytes".to_string()), Some(bytes.as_bytes().to_vec())));
    }
    if let Ok(mode) = stdin.extract::<String>() {
        return normalize_stdin(mode, None);
    }

    let mode_obj = stdin.getattr("_mode").map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err("stdin must be Stdin, bytes, or a stdin mode string")
    })?;
    let mode: String = mode_obj.extract()?;
    let data = stdin
        .getattr("_data")
        .ok()
        .and_then(|v| if v.is_none() { None } else { Some(v) })
        .map(|v| v.extract::<Vec<u8>>())
        .transpose()?;
    normalize_stdin(mode, data)
}

fn normalize_stdin(
    mode: String,
    data: Option<Vec<u8>>,
) -> PyResult<(Option<String>, Option<Vec<u8>>)> {
    match mode.as_str() {
        "null" => Ok((None, None)),
        "pipe" => Ok((Some(mode), None)),
        "bytes" => Ok((Some(mode), Some(data.unwrap_or_default()))),
        _ => Err(PyValueError::new_err(format!(
            "unknown stdin mode: {mode}. Expected: null, pipe, bytes"
        ))),
    }
}

fn parse_rlimits(rlimits: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<(String, u64, u64)>> {
    let Some(rlimits) = rlimits else {
        return Ok(Vec::new());
    };
    parse_rlimits_iter(rlimits)
}

fn parse_rlimits_iter(obj: &Bound<'_, PyAny>) -> PyResult<Vec<(String, u64, u64)>> {
    obj.try_iter()
        .map_err(|_| pyo3::exceptions::PyTypeError::new_err("rlimits must be a sequence"))?
        .map(|item| parse_rlimit(&item?))
        .collect()
}

fn parse_rlimit(obj: &Bound<'_, PyAny>) -> PyResult<(String, u64, u64)> {
    let (resource, soft, hard) = if let Ok(dict) = options_dict(obj, "rlimit") {
        (
            required_string_from_dict(&dict, "resource")?,
            required_from_dict(&dict, "soft")?,
            required_from_dict(&dict, "hard")?,
        )
    } else {
        (
            py_value_to_string(&obj.getattr("resource")?)?,
            obj.getattr("soft")?.extract()?,
            obj.getattr("hard")?.extract()?,
        )
    };

    validate_rlimit_resource(&resource)?;
    Ok((resource, soft, hard))
}

fn validate_rlimit_resource(resource: &str) -> PyResult<()> {
    if matches!(
        resource,
        "cpu"
            | "fsize"
            | "data"
            | "stack"
            | "core"
            | "rss"
            | "nproc"
            | "nofile"
            | "memlock"
            | "as"
            | "locks"
            | "sigpending"
            | "msgqueue"
            | "nice"
            | "rtprio"
            | "rttime"
    ) {
        Ok(())
    } else {
        Err(PyValueError::new_err(format!(
            "unknown rlimit resource: {resource}"
        )))
    }
}

fn validate_timeout(timeout_secs: Option<f64>) -> PyResult<()> {
    if timeout_secs.is_some_and(|timeout| timeout < 0.0) {
        return Err(PyValueError::new_err("timeout must be non-negative"));
    }
    Ok(())
}

fn required_from_dict<'py, T: FromPyObject<'py>>(
    dict: &Bound<'py, PyDict>,
    key: &str,
) -> PyResult<T> {
    dict.get_item(key)?
        .ok_or_else(|| PyValueError::new_err(format!("{key} is required")))?
        .extract()
}

fn required_string_from_dict(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<String> {
    let value = dict
        .get_item(key)?
        .ok_or_else(|| PyValueError::new_err(format!("{key} is required")))?;
    py_value_to_string(&value)
}

fn py_value_to_string(value: &Bound<'_, PyAny>) -> PyResult<String> {
    if let Ok(s) = value.extract::<String>() {
        return Ok(s);
    }
    Ok(value.str()?.to_str()?.to_string())
}

fn apply_exec_options(
    mut builder: microsandbox::sandbox::exec::ExecOptionsBuilder,
    args: Vec<String>,
    opts: ExecOpts,
) -> microsandbox::sandbox::exec::ExecOptionsBuilder {
    if !opts.env.is_empty() {
        builder = builder.envs(opts.env);
    }
    if let Some(cwd) = opts.cwd {
        builder = builder.cwd(cwd);
    }
    if let Some(user) = opts.user {
        builder = builder.user(user);
    }
    if let Some(timeout) = opts.timeout_secs {
        builder = builder.timeout(std::time::Duration::from_secs_f64(timeout));
    }
    if opts.tty {
        builder = builder.tty(true);
    }
    // Stdin mode.
    match opts.stdin_mode.as_deref() {
        Some("pipe") => builder = builder.stdin_pipe(),
        Some("bytes") => {
            if let Some(data) = opts.stdin_data {
                builder = builder.stdin_bytes(data);
            }
        }
        _ => {}
    }
    // Rlimits.
    for (resource, soft, hard) in &opts.rlimits {
        let res = match resource.as_str() {
            "cpu" => microsandbox::sandbox::RlimitResource::Cpu,
            "fsize" => microsandbox::sandbox::RlimitResource::Fsize,
            "data" => microsandbox::sandbox::RlimitResource::Data,
            "stack" => microsandbox::sandbox::RlimitResource::Stack,
            "core" => microsandbox::sandbox::RlimitResource::Core,
            "rss" => microsandbox::sandbox::RlimitResource::Rss,
            "nproc" => microsandbox::sandbox::RlimitResource::Nproc,
            "nofile" => microsandbox::sandbox::RlimitResource::Nofile,
            "memlock" => microsandbox::sandbox::RlimitResource::Memlock,
            "as" => microsandbox::sandbox::RlimitResource::As,
            "locks" => microsandbox::sandbox::RlimitResource::Locks,
            "sigpending" => microsandbox::sandbox::RlimitResource::Sigpending,
            "msgqueue" => microsandbox::sandbox::RlimitResource::Msgqueue,
            "nice" => microsandbox::sandbox::RlimitResource::Nice,
            "rtprio" => microsandbox::sandbox::RlimitResource::Rtprio,
            "rttime" => microsandbox::sandbox::RlimitResource::Rttime,
            _ => continue,
        };
        builder = builder.rlimit_range(res, *soft, *hard);
    }
    builder.args(args)
}

fn apply_attach_options(
    mut builder: microsandbox::sandbox::AttachOptionsBuilder,
    args: Vec<String>,
    opts: AttachOpts,
) -> microsandbox::sandbox::AttachOptionsBuilder {
    builder = builder.args(args);
    if !opts.env.is_empty() {
        builder = builder.envs(opts.env);
    }
    if let Some(cwd) = opts.cwd {
        builder = builder.cwd(cwd);
    }
    if let Some(user) = opts.user {
        builder = builder.user(user);
    }
    if let Some(keys) = opts.detach_keys {
        builder = builder.detach_keys(keys);
    }
    builder
}

//--------------------------------------------------------------------------------------------------
// Types: PullSession
//--------------------------------------------------------------------------------------------------

/// Context manager for sandbox creation with pull progress.
#[pyclass(name = "PullSession")]
pub struct PyPullSession {
    progress: Arc<Mutex<Option<microsandbox::sandbox::PullProgressHandle>>>,
    task: Arc<
        Mutex<
            Option<
                tokio::task::JoinHandle<
                    microsandbox::MicrosandboxResult<microsandbox::sandbox::Sandbox>,
                >,
            >,
        >,
    >,
}

impl PyPullSession {
    pub fn new(
        progress: microsandbox::sandbox::PullProgressHandle,
        task: tokio::task::JoinHandle<
            microsandbox::MicrosandboxResult<microsandbox::sandbox::Sandbox>,
        >,
    ) -> Self {
        Self {
            progress: Arc::new(Mutex::new(Some(progress))),
            task: Arc::new(Mutex::new(Some(task))),
        }
    }
}

#[pymethods]
impl PyPullSession {
    /// Async iterator over pull progress events.
    #[getter]
    fn progress(&self) -> PyPullProgressIter {
        PyPullProgressIter {
            handle: self.progress.clone(),
        }
    }

    fn __aenter__<'py>(slf: Bound<'py, Self>) -> PyResult<Bound<'py, PyAny>> {
        let py = slf.py();
        let obj: PyObject = slf.into();
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(obj) })
    }

    fn __aexit__<'py>(
        &self,
        py: Python<'py>,
        _exc_type: &Bound<'py, PyAny>,
        _exc_val: &Bound<'py, PyAny>,
        _exc_tb: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let task = self.task.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            // Ensure task is awaited/aborted.
            let mut guard = task.lock().await;
            if let Some(join_handle) = guard.take() {
                // Wait for it to finish. Ignore errors — __aexit__ should be safe.
                let _ = join_handle.await;
            }
            Ok(false)
        })
    }

    /// Await the task and return the Sandbox.
    fn result<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let task = self.task.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = task.lock().await;
            if let Some(join_handle) = guard.take() {
                let result = join_handle.await.map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!("create task panicked: {e}"))
                })?;
                let sb = result.map_err(to_py_err)?;
                Ok(PySandbox::from_rust(sb))
            } else {
                Err(pyo3::exceptions::PyRuntimeError::new_err(
                    "result() already consumed",
                ))
            }
        })
    }
}

/// Async iterator over PullProgress events.
#[pyclass(name = "PullProgressIter")]
struct PyPullProgressIter {
    handle: Arc<Mutex<Option<microsandbox::sandbox::PullProgressHandle>>>,
}

#[pymethods]
impl PyPullProgressIter {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let handle = self.handle.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = handle.lock().await;
            let progress = guard
                .as_mut()
                .ok_or_else(|| pyo3::exceptions::PyStopAsyncIteration::new_err(()))?;
            match progress.recv().await {
                Some(event) => Ok(convert_pull_progress(event)),
                None => {
                    // Stream ended.
                    *guard = None;
                    Err(pyo3::exceptions::PyStopAsyncIteration::new_err(()))
                }
            }
        })
    }
}

/// Convert a Rust PullProgress event to a Python dict.
fn convert_pull_progress(event: microsandbox::sandbox::PullProgress) -> PyPullEvent {
    use microsandbox::sandbox::PullProgress;
    match event {
        PullProgress::Resolving { reference } => PyPullEvent {
            event_type: "resolving",
            reference: Some(reference.to_string()),
            ..Default::default()
        },
        PullProgress::Resolved {
            reference,
            manifest_digest,
            layer_count,
            total_download_bytes,
        } => PyPullEvent {
            event_type: "resolved",
            reference: Some(reference.to_string()),
            manifest_digest: Some(manifest_digest.to_string()),
            layer_count: Some(layer_count as u32),
            total_download_bytes: total_download_bytes.map(|b| b as i64),
            ..Default::default()
        },
        PullProgress::LayerDownloadProgress {
            layer_index,
            digest,
            downloaded_bytes,
            total_bytes,
        } => PyPullEvent {
            event_type: "layer_download_progress",
            layer_index: Some(layer_index as u32),
            digest: Some(digest.to_string()),
            downloaded_bytes: Some(downloaded_bytes as i64),
            total_bytes: total_bytes.map(|b| b as i64),
            ..Default::default()
        },
        PullProgress::LayerDownloadComplete {
            layer_index,
            digest,
            downloaded_bytes,
        } => PyPullEvent {
            event_type: "layer_download_complete",
            layer_index: Some(layer_index as u32),
            digest: Some(digest.to_string()),
            downloaded_bytes: Some(downloaded_bytes as i64),
            ..Default::default()
        },
        PullProgress::LayerDownloadVerifying {
            layer_index,
            digest,
        } => PyPullEvent {
            event_type: "layer_download_verifying",
            layer_index: Some(layer_index as u32),
            digest: Some(digest.to_string()),
            ..Default::default()
        },
        PullProgress::LayerMaterializeStarted {
            layer_index,
            diff_id,
        } => PyPullEvent {
            event_type: "layer_materialize_started",
            layer_index: Some(layer_index as u32),
            diff_id: Some(diff_id.to_string()),
            ..Default::default()
        },
        PullProgress::LayerMaterializeProgress {
            layer_index,
            bytes_read,
            total_bytes,
        } => PyPullEvent {
            event_type: "layer_materialize_progress",
            layer_index: Some(layer_index as u32),
            bytes_read: Some(bytes_read as i64),
            total_bytes: Some(total_bytes as i64),
            ..Default::default()
        },
        PullProgress::LayerMaterializeWriting { layer_index } => PyPullEvent {
            event_type: "layer_materialize_writing",
            layer_index: Some(layer_index as u32),
            ..Default::default()
        },
        PullProgress::LayerMaterializeComplete {
            layer_index,
            diff_id,
        } => PyPullEvent {
            event_type: "layer_materialize_complete",
            layer_index: Some(layer_index as u32),
            diff_id: Some(diff_id.to_string()),
            ..Default::default()
        },
        PullProgress::StitchMergingTrees { layer_count } => PyPullEvent {
            event_type: "stitch_merging_trees",
            layer_count: Some(layer_count as u32),
            ..Default::default()
        },
        PullProgress::StitchWritingFsmeta => PyPullEvent {
            event_type: "stitch_writing_fsmeta",
            ..Default::default()
        },
        PullProgress::StitchWritingVmdk => PyPullEvent {
            event_type: "stitch_writing_vmdk",
            ..Default::default()
        },
        PullProgress::StitchComplete => PyPullEvent {
            event_type: "stitch_complete",
            ..Default::default()
        },
        PullProgress::Complete {
            reference,
            layer_count,
        } => PyPullEvent {
            event_type: "complete",
            reference: Some(reference.to_string()),
            layer_count: Some(layer_count as u32),
            ..Default::default()
        },
    }
}

/// Pull progress event exposed to Python.
#[pyclass(name = "PullEvent")]
#[derive(Default)]
struct PyPullEvent {
    #[pyo3(get)]
    event_type: &'static str,
    #[pyo3(get)]
    reference: Option<String>,
    #[pyo3(get)]
    manifest_digest: Option<String>,
    #[pyo3(get)]
    layer_count: Option<u32>,
    #[pyo3(get)]
    total_download_bytes: Option<i64>,
    #[pyo3(get)]
    layer_index: Option<u32>,
    #[pyo3(get)]
    digest: Option<String>,
    #[pyo3(get)]
    diff_id: Option<String>,
    #[pyo3(get)]
    downloaded_bytes: Option<i64>,
    #[pyo3(get)]
    total_bytes: Option<i64>,
    #[pyo3(get)]
    bytes_read: Option<i64>,
}
