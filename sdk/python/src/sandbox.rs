use std::sync::Arc;

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use tokio::sync::Mutex;

use crate::error::to_py_err;
use crate::exec::{PyExecHandle, PyExecOutput};
use crate::fs::PySandboxFs;
use crate::helpers::sandbox_builder_from_args;
use crate::logs::read_logs_blocking;
use crate::metrics::PyMetricsStream;
use crate::metrics::convert_metrics;
use crate::sandbox_handle::PySandboxHandle;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A running sandbox instance.
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

    /// Create a sandbox from a name + kwargs, or from a config dict.
    #[staticmethod]
    #[pyo3(signature = (name_or_config, **kwargs))]
    fn create<'py>(
        py: Python<'py>,
        name_or_config: &Bound<'py, PyAny>,
        kwargs: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (name, kwargs) = match name_or_config.downcast::<PyDict>() {
            Err(_) => (name_or_config.extract()?, kwargs),
            Ok(config_dict) => (
                config_dict
                    .get_item("name")?
                    .ok_or_else(|| PyValueError::new_err("config.name is required"))?
                    .extract()?,
                Some(config_dict),
            ),
        };

        let builder = sandbox_builder_from_args(name, kwargs)?;
        let detached = kwargs
            .and_then(|kw| kw.get_item("detached").ok().flatten())
            .and_then(|v| v.extract::<bool>().ok())
            .unwrap_or(false);

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sb = if detached {
                builder.create_detached().await.map_err(to_py_err)?
            } else {
                builder.create().await.map_err(to_py_err)?
            };
            Ok(PySandbox::from_rust(sb))
        })
    }

    /// Start an existing stopped sandbox.
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
    /// Returns a PullSession async context manager.
    #[staticmethod]
    #[pyo3(signature = (name_or_config, **kwargs))]
    fn create_with_progress<'py>(
        _py: Python<'py>,
        name_or_config: &Bound<'py, PyAny>,
        kwargs: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<PyPullSession> {
        let (name, kwargs) = if let Ok(config_dict) = name_or_config.downcast::<PyDict>() {
            let name: String = config_dict
                .get_item("name")?
                .ok_or_else(|| PyValueError::new_err("config.name is required"))?
                .extract()?;
            (name, Some(config_dict))
        } else {
            (name_or_config.extract()?, kwargs)
        };
        let builder = sandbox_builder_from_args(name, kwargs)?;
        let detached = kwargs
            .and_then(|kw| kw.get_item("detached").ok().flatten())
            .and_then(|v| v.extract::<bool>().ok())
            .unwrap_or(false);

        let (progress, task) = if detached {
            builder
                .create_detached_with_pull_progress()
                .map_err(to_py_err)?
        } else {
            builder.create_with_pull_progress().map_err(to_py_err)?
        };

        Ok(PyPullSession::new(progress, task))
    }

    //----------------------------------------------------------------------------------------------
    // Static Methods — Lookup
    //----------------------------------------------------------------------------------------------

    /// Get a lightweight handle to an existing sandbox.
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

    /// Remove a stopped sandbox.
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

    /// Sandbox name.
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
    #[pyo3(signature = (
        cmd,
        args = None,
        *,
        cwd = None,
        user = None,
        env = None,
        timeout = None,
        stdin = None,
        stdin_data = None,
        tty = false,
        rlimits = None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn exec<'py>(
        &self,
        py: Python<'py>,
        cmd: String,
        args: Option<&Bound<'py, PyAny>>,
        cwd: Option<String>,
        user: Option<String>,
        env: Option<&Bound<'py, PyDict>>,
        timeout: Option<f64>,
        stdin: Option<&Bound<'py, PyAny>>,
        stdin_data: Option<Vec<u8>>,
        tty: bool,
        rlimits: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let (args, opts) = parse_exec_call(
            args, cwd, user, env, timeout, stdin, stdin_data, tty, rlimits,
        )?;

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
    #[pyo3(signature = (
        cmd,
        args = None,
        *,
        cwd = None,
        user = None,
        env = None,
        timeout = None,
        stdin = None,
        stdin_data = None,
        tty = false,
        rlimits = None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn exec_stream<'py>(
        &self,
        py: Python<'py>,
        cmd: String,
        args: Option<&Bound<'py, PyAny>>,
        cwd: Option<String>,
        user: Option<String>,
        env: Option<&Bound<'py, PyDict>>,
        timeout: Option<f64>,
        stdin: Option<&Bound<'py, PyAny>>,
        stdin_data: Option<Vec<u8>>,
        tty: bool,
        rlimits: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let (args, opts) = parse_exec_call(
            args, cwd, user, env, timeout, stdin, stdin_data, tty, rlimits,
        )?;

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
    fn shell<'py>(&self, py: Python<'py>, script: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = Self::clone_sandbox(&inner).await?;
            let output = sandbox.shell(&script).await.map_err(to_py_err)?;
            Ok(PyExecOutput::from_rust(output))
        })
    }

    /// Execute a shell command with streaming I/O.
    fn shell_stream<'py>(&self, py: Python<'py>, script: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sandbox = Self::clone_sandbox(&inner).await?;
            let handle = sandbox.shell_stream(&script).await.map_err(to_py_err)?;
            Ok(PyExecHandle::from_rust(handle))
        })
    }

    //----------------------------------------------------------------------------------------------
    // Attach
    //----------------------------------------------------------------------------------------------

    /// Attach to the sandbox with an interactive terminal session.
    /// Note: attach requires a real terminal (PTY) and blocks the calling thread.
    /// This is primarily useful for CLI tools, not library usage.
    #[pyo3(signature = (
        cmd,
        args = None,
        *,
        cwd = None,
        user = None,
        env = None,
        detach_keys = None,
        rlimits = None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn attach<'py>(
        &self,
        py: Python<'py>,
        cmd: String,
        args: Option<&Bound<'py, PyAny>>,
        cwd: Option<String>,
        user: Option<String>,
        env: Option<&Bound<'py, PyDict>>,
        detach_keys: Option<String>,
        rlimits: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let (args, opts) = parse_attach_call(args, cwd, user, env, detach_keys, rlimits)?;

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
// Functions: Exec Arg Parsing
//--------------------------------------------------------------------------------------------------

/// Parsed exec options.
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
    detach_keys: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn parse_exec_call(
    args_or_options: Option<&Bound<'_, PyAny>>,
    cwd: Option<String>,
    user: Option<String>,
    env: Option<&Bound<'_, PyDict>>,
    timeout_secs: Option<f64>,
    stdin: Option<&Bound<'_, PyAny>>,
    stdin_data: Option<Vec<u8>>,
    tty: bool,
    rlimits: Option<&Bound<'_, PyAny>>,
) -> PyResult<(Vec<String>, ExecOpts)> {
    let keyword_options_present = cwd.is_some()
        || user.is_some()
        || env.is_some()
        || timeout_secs.is_some()
        || stdin.is_some()
        || stdin_data.is_some()
        || tty
        || rlimits.is_some();

    let (stdin_mode, stdin_data) = parse_stdin(stdin, stdin_data)?;
    let opts = ExecOpts {
        cwd,
        user,
        env: parse_env(env)?,
        timeout_secs,
        tty,
        stdin_mode,
        stdin_data,
        rlimits: parse_rlimits(rlimits)?,
        detach_keys: None,
    };

    parse_command_args(args_or_options, opts, keyword_options_present)
}

fn parse_attach_call(
    args_or_options: Option<&Bound<'_, PyAny>>,
    cwd: Option<String>,
    user: Option<String>,
    env: Option<&Bound<'_, PyDict>>,
    detach_keys: Option<String>,
    rlimits: Option<&Bound<'_, PyAny>>,
) -> PyResult<(Vec<String>, ExecOpts)> {
    let keyword_options_present = cwd.is_some()
        || user.is_some()
        || env.is_some()
        || detach_keys.is_some()
        || rlimits.is_some();

    let opts = ExecOpts {
        cwd,
        user,
        env: parse_env(env)?,
        detach_keys,
        rlimits: parse_rlimits(rlimits)?,
        ..Default::default()
    };

    parse_command_args(args_or_options, opts, keyword_options_present)
}

fn parse_command_args(
    args_or_options: Option<&Bound<'_, PyAny>>,
    keyword_opts: ExecOpts,
    keyword_options_present: bool,
) -> PyResult<(Vec<String>, ExecOpts)> {
    let Some(value) = args_or_options else {
        return Ok((Vec::new(), keyword_opts));
    };
    if value.is_none() {
        return Ok((Vec::new(), keyword_opts));
    }

    if let Some(dict) = exec_options_dict(value)? {
        if keyword_options_present {
            return Err(PyTypeError::new_err(
                "cannot combine an ExecOptions dict/object with keyword options",
            ));
        }
        return parse_exec_options_dict(&dict);
    }

    Ok((extract_args(value)?, keyword_opts))
}

fn exec_options_dict<'py>(value: &Bound<'py, PyAny>) -> PyResult<Option<Bound<'py, PyDict>>> {
    if let Ok(dict) = value.downcast::<PyDict>() {
        return Ok(Some(dict.clone()));
    }
    if let Ok(method) = value.getattr("_to_dict") {
        let result = method.call0()?;
        let dict = result
            .downcast::<PyDict>()
            .map_err(|_| PyTypeError::new_err("ExecOptions._to_dict() must return a dict"))?;
        return Ok(Some(dict.clone()));
    }
    Ok(None)
}

fn parse_exec_options_dict(dict: &Bound<'_, PyDict>) -> PyResult<(Vec<String>, ExecOpts)> {
    let args = match dict.get_item("args")? {
        Some(value) if !value.is_none() => extract_args(&value)?,
        _ => Vec::new(),
    };

    let stdin_data = optional_dict_value::<Vec<u8>>(dict, "stdin_data")?;
    let stdin = dict.get_item("stdin")?;
    let (stdin_mode, stdin_data) = parse_stdin(stdin.as_ref(), stdin_data)?;

    let opts = ExecOpts {
        cwd: optional_dict_value(dict, "cwd")?,
        user: optional_dict_value(dict, "user")?,
        env: match dict.get_item("env")? {
            Some(value) if !value.is_none() => parse_env_any(&value)?,
            _ => Vec::new(),
        },
        timeout_secs: optional_dict_value(dict, "timeout")?,
        tty: optional_dict_value(dict, "tty")?.unwrap_or(false),
        stdin_mode,
        stdin_data,
        rlimits: match dict.get_item("rlimits")? {
            Some(value) if !value.is_none() => parse_rlimits_any(&value)?,
            _ => Vec::new(),
        },
        detach_keys: optional_dict_value(dict, "detach_keys")?,
    };

    Ok((args, opts))
}

fn optional_dict_value<T>(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<T>>
where
    for<'py> T: FromPyObject<'py>,
{
    dict.get_item(key)?
        .and_then(|v| if v.is_none() { None } else { Some(v) })
        .map(|v| v.extract())
        .transpose()
}

fn extract_args(value: &Bound<'_, PyAny>) -> PyResult<Vec<String>> {
    if value.extract::<String>().is_ok() {
        return Err(PyTypeError::new_err(
            "args must be a sequence of strings, not a string",
        ));
    }
    value
        .extract::<Vec<String>>()
        .map_err(|_| PyTypeError::new_err("args must be a sequence of strings"))
}

fn parse_env(env: Option<&Bound<'_, PyDict>>) -> PyResult<Vec<(String, String)>> {
    let Some(env) = env else {
        return Ok(Vec::new());
    };
    parse_env_dict(env)
}

fn parse_env_any(value: &Bound<'_, PyAny>) -> PyResult<Vec<(String, String)>> {
    let dict: &Bound<'_, PyDict> = value
        .downcast()
        .map_err(|_| PyTypeError::new_err("env must be a dict[str, str]"))?;
    parse_env_dict(dict)
}

fn parse_env_dict(dict: &Bound<'_, PyDict>) -> PyResult<Vec<(String, String)>> {
    let mut env = Vec::with_capacity(dict.len());
    for (key, value) in dict.iter() {
        env.push((key.extract::<String>()?, value.extract::<String>()?));
    }
    Ok(env)
}

fn parse_stdin(
    stdin: Option<&Bound<'_, PyAny>>,
    stdin_data: Option<Vec<u8>>,
) -> PyResult<(Option<String>, Option<Vec<u8>>)> {
    let Some(stdin) = stdin else {
        return Ok(match stdin_data {
            Some(data) => (Some("bytes".to_string()), Some(data)),
            None => (None, None),
        });
    };
    if stdin.is_none() {
        return Ok((None, None));
    }

    let mut data = stdin_data;
    let mode = if let Ok(mode) = stdin.extract::<String>() {
        mode
    } else if let Ok(mode_attr) = stdin.getattr("_mode") {
        if data.is_none()
            && let Ok(data_attr) = stdin.getattr("_data")
            && !data_attr.is_none()
        {
            data = Some(data_attr.extract()?);
        }
        mode_attr.extract::<String>()?
    } else {
        return Err(PyTypeError::new_err(
            "stdin must be a Stdin value or one of 'null', 'pipe', 'bytes'",
        ));
    };

    match mode.as_str() {
        "null" => {
            if data.is_some() {
                Err(PyValueError::new_err(
                    "stdin_data cannot be provided when stdin is 'null'",
                ))
            } else {
                Ok((None, None))
            }
        }
        "pipe" => {
            if data.is_some() {
                Err(PyValueError::new_err(
                    "stdin_data cannot be provided when stdin is 'pipe'",
                ))
            } else {
                Ok((Some(mode), None))
            }
        }
        "bytes" => {
            let Some(data) = data else {
                return Err(PyValueError::new_err(
                    "stdin_data is required when stdin is 'bytes'",
                ));
            };
            Ok((Some(mode), Some(data)))
        }
        _ => Err(PyValueError::new_err(format!("unknown stdin mode: {mode}"))),
    }
}

fn parse_rlimits(rlimits: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<(String, u64, u64)>> {
    let Some(rlimits) = rlimits else {
        return Ok(Vec::new());
    };
    if rlimits.is_none() {
        return Ok(Vec::new());
    }
    parse_rlimits_any(rlimits)
}

fn parse_rlimits_any(value: &Bound<'_, PyAny>) -> PyResult<Vec<(String, u64, u64)>> {
    let iter = value
        .try_iter()
        .map_err(|_| PyTypeError::new_err("rlimits must be a sequence of Rlimit values"))?;
    let mut rlimits = Vec::new();
    for item in iter {
        let item = item?;
        let (resource, soft, hard) = if let Ok(dict) = item.downcast::<PyDict>() {
            let resource: String = dict
                .get_item("resource")?
                .ok_or_else(|| PyValueError::new_err("rlimit.resource is required"))?
                .extract()?;
            let soft: u64 = dict
                .get_item("soft")?
                .ok_or_else(|| PyValueError::new_err("rlimit.soft is required"))?
                .extract()?;
            let hard: u64 = dict
                .get_item("hard")?
                .ok_or_else(|| PyValueError::new_err("rlimit.hard is required"))?
                .extract()?;
            (resource, soft, hard)
        } else {
            let resource: String = item.getattr("resource")?.extract()?;
            let soft: u64 = item.getattr("soft")?.extract()?;
            let hard: u64 = item.getattr("hard")?.extract()?;
            (resource, soft, hard)
        };
        validate_rlimit_resource(&resource)?;
        rlimits.push((resource, soft, hard));
    }
    Ok(rlimits)
}

fn validate_rlimit_resource(resource: &str) -> PyResult<()> {
    let valid = matches!(
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
    );
    if valid {
        Ok(())
    } else {
        Err(PyValueError::new_err(format!(
            "unknown rlimit resource: {resource}"
        )))
    }
}

fn apply_exec_options(
    mut builder: microsandbox::sandbox::exec::ExecOptionsBuilder,
    args: Vec<String>,
    opts: ExecOpts,
) -> microsandbox::sandbox::exec::ExecOptionsBuilder {
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
    builder
}

fn apply_attach_options(
    mut builder: microsandbox::sandbox::AttachOptionsBuilder,
    args: Vec<String>,
    opts: ExecOpts,
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
