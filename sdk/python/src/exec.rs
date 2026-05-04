use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use tokio::sync::Mutex;

use crate::error::to_py_err;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Output of a completed command execution.
#[pyclass(name = "ExecOutput")]
pub struct PyExecOutput {
    inner: microsandbox::ExecOutput,
}

/// Handle for a streaming command execution.
#[pyclass(name = "ExecHandle")]
pub struct PyExecHandle {
    id: String,
    inner: Arc<Mutex<microsandbox::ExecHandle>>,
    stdin: Option<PyExecSink>,
}

/// Stdin writer for a running process.
#[pyclass(name = "ExecSink")]
pub struct PyExecSink {
    inner: Arc<microsandbox::sandbox::exec::ExecSink>,
}

//--------------------------------------------------------------------------------------------------
// Methods: ExecOutput
//--------------------------------------------------------------------------------------------------

impl PyExecOutput {
    pub fn from_rust(inner: microsandbox::ExecOutput) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl PyExecOutput {
    /// Exit code.
    #[getter]
    fn exit_code(&self) -> i32 {
        self.inner.status().code
    }

    /// Whether the process exited successfully (code == 0).
    #[getter]
    fn success(&self) -> bool {
        self.inner.status().success
    }

    /// Stdout as UTF-8 string.
    #[getter]
    fn stdout_text(&self) -> PyResult<String> {
        self.inner
            .stdout()
            .map_err(|e| pyo3::exceptions::PyUnicodeDecodeError::new_err(e.to_string()))
    }

    /// Stderr as UTF-8 string.
    #[getter]
    fn stderr_text(&self) -> PyResult<String> {
        self.inner
            .stderr()
            .map_err(|e| pyo3::exceptions::PyUnicodeDecodeError::new_err(e.to_string()))
    }

    /// Stdout as raw bytes.
    #[getter]
    fn stdout_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.stdout_bytes())
    }

    /// Stderr as raw bytes.
    #[getter]
    fn stderr_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.stderr_bytes())
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: ExecHandle
//--------------------------------------------------------------------------------------------------

impl PyExecHandle {
    pub fn from_rust(mut inner: microsandbox::ExecHandle) -> Self {
        let id = inner.id();
        let stdin = inner
            .take_stdin()
            .map(|s| PyExecSink { inner: Arc::new(s) });
        Self {
            id,
            inner: Arc::new(Mutex::new(inner)),
            stdin,
        }
    }
}

#[pymethods]
impl PyExecHandle {
    /// Correlation ID for this execution.
    #[getter]
    fn id(&self) -> &str {
        &self.id
    }

    /// Stdin writer (None if stdin was not piped). Returns None on subsequent calls.
    fn take_stdin(&mut self) -> Option<PyExecSink> {
        self.stdin.take()
    }

    /// Receive the next event. Returns None when the stream ends.
    fn recv<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            match guard.recv().await {
                Some(event) => {
                    let py_event = convert_exec_event(event);
                    Ok(Some(py_event))
                }
                None => Ok(None),
            }
        })
    }

    /// Wait for the process to exit and return (code, success).
    fn wait<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let status = guard.wait().await.map_err(to_py_err)?;
            Ok((status.code, status.success))
        })
    }

    /// Wait for completion and collect all output.
    fn collect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            let output = guard.collect().await.map_err(to_py_err)?;
            Ok(PyExecOutput::from_rust(output))
        })
    }

    /// Send a signal to the running process.
    fn signal<'py>(&self, py: Python<'py>, sig: i32) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            guard.signal(sig).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Kill the running process (SIGKILL).
    fn kill<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let guard = inner.lock().await;
            guard.kill().await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Async iterator protocol.
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Async iterator next — returns the next ExecEvent or raises StopAsyncIteration.
    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = inner.lock().await;
            match guard.recv().await {
                Some(event) => Ok(convert_exec_event(event)),
                None => Err(pyo3::exceptions::PyStopAsyncIteration::new_err(())),
            }
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: ExecSink
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PyExecSink {
    /// Write data to the process stdin.
    fn write<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.write(&data).await.map_err(to_py_err)?;
            Ok(())
        })
    }

    /// Close stdin (sends EOF).
    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.close().await.map_err(to_py_err)?;
            Ok(())
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Convert a Rust ExecEvent into a Python dict.
fn convert_exec_event(event: microsandbox::ExecEvent) -> PyExecEvent {
    match event {
        microsandbox::ExecEvent::Started { pid } => PyExecEvent {
            event_type: "started",
            pid: Some(pid),
            data: None,
            code: None,
        },
        microsandbox::ExecEvent::Stdout(data) => PyExecEvent {
            event_type: "stdout",
            pid: None,
            data: Some(data.to_vec()),
            code: None,
        },
        microsandbox::ExecEvent::Stderr(data) => PyExecEvent {
            event_type: "stderr",
            pid: None,
            data: Some(data.to_vec()),
            code: None,
        },
        microsandbox::ExecEvent::Exited { code } => PyExecEvent {
            event_type: "exited",
            pid: None,
            data: None,
            code: Some(code),
        },
        // Spawn-time failure: surface as a synthetic event for users
        // iterating events. The canonical surface is the typed
        // `ExecFailedError` exception raised by `exec()`/`shell()`.
        microsandbox::ExecEvent::Failed(payload) => PyExecEvent {
            event_type: "failed",
            pid: None,
            data: Some(payload.message.into_bytes()),
            code: payload.errno,
        },
    }
}

/// Exec event exposed to Python.
#[pyclass(name = "ExecEvent")]
pub struct PyExecEvent {
    #[pyo3(get)]
    event_type: &'static str,
    #[pyo3(get)]
    pid: Option<u32>,
    #[pyo3(get)]
    data: Option<Vec<u8>>,
    #[pyo3(get)]
    code: Option<i32>,
}
