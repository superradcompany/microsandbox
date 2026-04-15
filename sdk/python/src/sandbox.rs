use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use tokio::sync::Mutex;

use crate::config::resolve_config;
use crate::error::to_py_err;
use crate::exec::{PyExecHandle, PyExecOutput};
use crate::fs::PySandboxFs;
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
        let config = resolve_config(name_or_config, kwargs)?;
        let detached = kwargs
            .and_then(|kw| kw.get_item("detached").ok().flatten())
            .and_then(|v| v.extract::<bool>().ok())
            .unwrap_or(false);

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let sb = if detached {
                microsandbox::sandbox::Sandbox::create_detached(config)
                    .await
                    .map_err(to_py_err)?
            } else {
                microsandbox::sandbox::Sandbox::create(config)
                    .await
                    .map_err(to_py_err)?
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
        let config = resolve_config(name_or_config, kwargs)?;
        let detached = kwargs
            .and_then(|kw| kw.get_item("detached").ok().flatten())
            .and_then(|v| v.extract::<bool>().ok())
            .unwrap_or(false);

        // create_with_pull_progress is on the builder, not Sandbox directly.
        // We need to build a config first, then use the builder.
        let builder = microsandbox::sandbox::SandboxBuilder::from(config);
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
    ///
    /// Second positional is either a list of args (shortcut) or an ExecOptions dict.
    #[pyo3(signature = (cmd, args_or_options=None))]
    fn exec<'py>(
        &self,
        py: Python<'py>,
        cmd: String,
        args_or_options: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let (args, options) = parse_exec_args(args_or_options)?;

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sb = guard.as_ref().ok_or_else(crate::error::consumed)?;

            let output = if let Some(opts) = options {
                sb.exec_with(&cmd, |e| apply_exec_options(e, opts))
                    .await
                    .map_err(to_py_err)?
            } else {
                sb.exec(&cmd, args).await.map_err(to_py_err)?
            };

            Ok(PyExecOutput::from_rust(output))
        })
    }

    /// Execute a command with streaming I/O.
    #[pyo3(signature = (cmd, args_or_options=None))]
    fn exec_stream<'py>(
        &self,
        py: Python<'py>,
        cmd: String,
        args_or_options: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let (args, options) = parse_exec_args(args_or_options)?;

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sb = guard.as_ref().ok_or_else(crate::error::consumed)?;

            let handle = if let Some(opts) = options {
                sb.exec_stream_with(&cmd, |e| apply_exec_options(e, opts))
                    .await
                    .map_err(to_py_err)?
            } else {
                sb.exec_stream(&cmd, args).await.map_err(to_py_err)?
            };

            Ok(PyExecHandle::from_rust(handle))
        })
    }

    /// Execute a shell command.
    fn shell<'py>(&self, py: Python<'py>, script: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sb = guard.as_ref().ok_or_else(crate::error::consumed)?;
            let output = sb.shell(&script).await.map_err(to_py_err)?;
            Ok(PyExecOutput::from_rust(output))
        })
    }

    /// Execute a shell command with streaming I/O.
    fn shell_stream<'py>(&self, py: Python<'py>, script: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sb = guard.as_ref().ok_or_else(crate::error::consumed)?;
            let handle = sb.shell_stream(&script).await.map_err(to_py_err)?;
            Ok(PyExecHandle::from_rust(handle))
        })
    }

    //----------------------------------------------------------------------------------------------
    // Attach
    //----------------------------------------------------------------------------------------------

    /// Attach to the sandbox with an interactive terminal session.
    /// Note: attach requires a real terminal (PTY) and blocks the calling thread.
    /// This is primarily useful for CLI tools, not library usage.
    #[pyo3(signature = (cmd, args_or_options=None))]
    fn attach<'py>(
        &self,
        py: Python<'py>,
        cmd: String,
        args_or_options: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let (args, options) = parse_exec_args(args_or_options)?;

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sb = guard.as_ref().ok_or_else(crate::error::consumed)?;
            let exit_code = if let Some(opts) = options {
                sb.attach_with(&cmd, |a| {
                    let mut a = a.args(args);
                    if !opts.env.is_empty() {
                        a = a.envs(opts.env);
                    }
                    if let Some(cwd) = opts.cwd {
                        a = a.cwd(cwd);
                    }
                    if let Some(user) = opts.user {
                        a = a.user(user);
                    }
                    if let Some(keys) = opts.detach_keys {
                        a = a.detach_keys(keys);
                    }
                    a
                })
                .await
                .map_err(to_py_err)?
            } else {
                sb.attach(&cmd, args).await.map_err(to_py_err)?
            };
            Ok(exit_code)
        })
    }

    /// Attach to the sandbox's default shell.
    fn attach_shell<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sb = guard.as_ref().ok_or_else(crate::error::consumed)?;
            let exit_code = sb.attach_shell().await.map_err(to_py_err)?;
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
            let guard = inner.lock().await;
            let sb = guard.as_ref().ok_or_else(crate::error::consumed)?;
            let m = sb.metrics().await.map_err(to_py_err)?;
            Ok(convert_metrics(&m))
        })
    }

    /// Stream metrics at a fixed interval. Returns an async iterator.
    #[pyo3(signature = (interval = 1.0))]
    fn metrics_stream<'py>(&self, py: Python<'py>, interval: f64) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let interval_dur = std::time::Duration::from_secs_f64(interval);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sb = guard.as_ref().ok_or_else(crate::error::consumed)?;
            let stream = sb.metrics_stream(interval_dur);
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
            let guard = inner.lock().await;
            let sb = guard.as_ref().ok_or_else(crate::error::consumed)?;
            sb.stop().await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Stop and wait for exit, returning (code, success).
    fn stop_and_wait<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sb = guard.as_ref().ok_or_else(crate::error::consumed)?;
            let status = sb.stop_and_wait().await.map_err(to_py_err)?;
            Ok((status.code().unwrap_or(-1), status.success()))
        })
    }

    /// Kill the sandbox (SIGKILL).
    fn kill<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sb = guard.as_ref().ok_or_else(crate::error::consumed)?;
            sb.kill().await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Drain the sandbox (SIGUSR1).
    fn drain<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sb = guard.as_ref().ok_or_else(crate::error::consumed)?;
            sb.drain().await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Wait for the sandbox process to exit.
    fn wait<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            let sb = guard.as_ref().ok_or_else(crate::error::consumed)?;
            let status = sb.wait().await.map_err(to_py_err)?;
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
            let guard = inner.lock().await;
            if let Some(ref sb) = *guard {
                let name = sb.name().to_string();
                let _ = sb.kill().await;
                drop(guard);
                let _ = microsandbox::sandbox::Sandbox::remove(&name).await;
            }
            Ok(false) // don't suppress exceptions
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Exec Arg Parsing
//--------------------------------------------------------------------------------------------------

/// Parsed exec arguments — either a vec of string args or a full options dict.
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

fn parse_exec_args(
    args_or_options: Option<&Bound<'_, PyAny>>,
) -> PyResult<(Vec<String>, Option<ExecOpts>)> {
    let Some(val) = args_or_options else {
        return Ok((Vec::new(), None));
    };

    // Try as list of strings first (simple args shortcut).
    if let Ok(list) = val.downcast::<pyo3::types::PyList>() {
        let args: Vec<String> = list
            .iter()
            .map(|item| item.extract())
            .collect::<PyResult<_>>()?;
        return Ok((args, None));
    }

    // Try as dict (ExecOptions), or object with _to_dict().
    let dict_result = if let Ok(dict) = val.downcast::<PyDict>() {
        Ok(dict.clone())
    } else if let Ok(method) = val.getattr("_to_dict") {
        let result = method.call0()?;
        Ok(result.downcast::<PyDict>()?.clone())
    } else {
        Err(())
    };
    if let Ok(dict) = dict_result {
        let dict = &dict;
        let args: Vec<String> = dict
            .get_item("args")?
            .map(|v| v.extract())
            .transpose()?
            .unwrap_or_default();

        let opts = ExecOpts {
            cwd: dict
                .get_item("cwd")?
                .and_then(|v| if v.is_none() { None } else { Some(v) })
                .map(|v| v.extract())
                .transpose()?,
            user: dict
                .get_item("user")?
                .and_then(|v| if v.is_none() { None } else { Some(v) })
                .map(|v| v.extract())
                .transpose()?,
            env: {
                let mut env = Vec::new();
                if let Some(env_obj) = dict.get_item("env")?
                    && !env_obj.is_none()
                {
                    let env_dict: &Bound<'_, PyDict> = env_obj.downcast()?;
                    for (k, v) in env_dict.iter() {
                        env.push((k.extract::<String>()?, v.extract::<String>()?));
                    }
                }
                env
            },
            timeout_secs: dict
                .get_item("timeout")?
                .and_then(|v| if v.is_none() { None } else { Some(v) })
                .map(|v| v.extract())
                .transpose()?,
            tty: dict
                .get_item("tty")?
                .and_then(|v| if v.is_none() { None } else { Some(v) })
                .map(|v| v.extract())
                .transpose()?
                .unwrap_or(false),
            stdin_mode: dict
                .get_item("stdin")?
                .and_then(|v| if v.is_none() { None } else { Some(v) })
                .map(|v| v.extract())
                .transpose()?,
            stdin_data: dict
                .get_item("stdin_data")?
                .and_then(|v| if v.is_none() { None } else { Some(v) })
                .map(|v| v.extract())
                .transpose()?,
            detach_keys: dict
                .get_item("detach_keys")?
                .and_then(|v| if v.is_none() { None } else { Some(v) })
                .map(|v| v.extract())
                .transpose()?,
            rlimits: {
                let mut rlimits = Vec::new();
                if let Some(rl_obj) = dict.get_item("rlimits")?
                    && !rl_obj.is_none()
                {
                    let rl_list: &Bound<'_, pyo3::types::PyList> = rl_obj.downcast()?;
                    for item in rl_list.iter() {
                        let d: &Bound<'_, PyDict> = item.downcast()?;
                        let resource: String = d.get_item("resource")?.unwrap().extract()?;
                        let valid = matches!(
                            resource.as_str(),
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
                        if !valid {
                            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                                "unknown rlimit resource: {resource}"
                            )));
                        }
                        let soft: u64 = d.get_item("soft")?.unwrap().extract()?;
                        let hard: u64 = d.get_item("hard")?.unwrap().extract()?;
                        rlimits.push((resource, soft, hard));
                    }
                }
                rlimits
            },
        };

        return Ok((args, Some(opts)));
    }

    Err(pyo3::exceptions::PyTypeError::new_err(
        "expected list[str] (args) or dict (ExecOptions)",
    ))
}

fn apply_exec_options(
    mut builder: microsandbox::sandbox::exec::ExecOptionsBuilder,
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
        PullProgress::FlatMergeStarted { layer_count } => PyPullEvent {
            event_type: "flat_merge_started",
            layer_count: Some(layer_count as u32),
            ..Default::default()
        },
        PullProgress::FlatMergeComplete { manifest_digest } => PyPullEvent {
            event_type: "flat_merge_complete",
            manifest_digest: Some(manifest_digest.to_string()),
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
