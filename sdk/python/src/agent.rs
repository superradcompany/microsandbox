use std::sync::Arc;
use std::time::Duration;

use microsandbox::{AgentBridge, BridgeFrame};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use crate::error::to_py_err;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Low-level raw client for talking to agentd through the sandbox relay socket.
#[pyclass(name = "PyAgentClient")]
pub struct PyAgentClient {
    inner: Arc<AgentBridge>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PyAgentClient {
    /// Connect to a running sandbox by name.
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
    #[staticmethod]
    #[pyo3(signature = (name, *, timeout = None))]
    fn connect_sandbox<'py>(
        py: Python<'py>,
        name: String,
        timeout: Option<f64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let timeout = timeout_duration(timeout)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let bridge = match timeout {
                Some(timeout) => AgentBridge::connect_sandbox_with_timeout(&name, timeout).await,
                None => AgentBridge::connect_sandbox(&name).await,
            }
            .map_err(to_py_err_agent)?;
            Ok(Self {
                inner: Arc::new(bridge),
            })
        })
    }

    /// Connect to an agentd relay socket by path.
    #[staticmethod]
    #[pyo3(signature = (path, *, timeout = None))]
    fn connect<'py>(
        py: Python<'py>,
        path: String,
        timeout: Option<f64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let timeout = timeout_duration(timeout)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let bridge = match timeout {
                Some(timeout) => AgentBridge::connect_path_with_timeout(&path, timeout).await,
                None => AgentBridge::connect_path(&path).await,
            }
            .map_err(to_py_err_agent)?;
            Ok(Self {
                inner: Arc::new(bridge),
            })
        })
    }

    /// Resolve a sandbox's agentd relay socket path without connecting.
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
    #[staticmethod]
    fn socket_path(name: String) -> PyResult<String> {
        let path = microsandbox::agent::AgentClient::socket_path(&name).map_err(to_py_err)?;
        Ok(path.to_string_lossy().into_owned())
    }

    /// Send one frame and await a single response frame.
    fn request<'py>(
        &self,
        py: Python<'py>,
        flags: u8,
        body: Vec<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let frame = inner.request(flags, body).await.map_err(to_py_err_agent)?;
            frame_to_py(frame)
        })
    }

    /// Open a streaming session and return `{id, handle}`.
    fn stream_open<'py>(
        &self,
        py: Python<'py>,
        flags: u8,
        body: Vec<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let (id, handle) = inner
                .stream_open(flags, body)
                .await
                .map_err(to_py_err_agent)?;
            Python::with_gil(|py| -> PyResult<PyObject> {
                let out = PyDict::new(py);
                out.set_item("id", id)?;
                out.set_item("handle", handle)?;
                Ok(out.into())
            })
        })
    }

    /// Pull the next frame from a stream. Returns `None` at EOF.
    fn stream_next<'py>(&self, py: Python<'py>, handle: u64) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            match inner.stream_next(handle).await.map_err(to_py_err_agent)? {
                Some(frame) => frame_to_py(frame).map(Some),
                None => Ok(None),
            }
        })
    }

    /// Close a stream handle. Idempotent.
    fn stream_close<'py>(&self, py: Python<'py>, handle: u64) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.stream_close(handle).await;
            Ok(())
        })
    }

    /// Send a follow-up frame on an existing correlation id.
    fn send<'py>(
        &self,
        py: Python<'py>,
        id: u32,
        flags: u8,
        body: Vec<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.send(id, flags, body).await.map_err(to_py_err_agent)?;
            Ok(())
        })
    }

    /// Cached handshake `core.ready` frame body bytes.
    fn ready_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(
            py,
            &self.inner.ready_bytes().map_err(to_py_err_agent)?,
        ))
    }

    /// Close the connection. Idempotent.
    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.close().await;
            Ok(())
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn frame_to_py(frame: BridgeFrame) -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let out = PyDict::new(py);
        out.set_item("id", frame.id)?;
        out.set_item("flags", frame.flags)?;
        out.set_item("body", PyBytes::new(py, &frame.body))?;
        Ok(out.into())
    })
}

fn to_py_err_agent(err: microsandbox::AgentClientError) -> PyErr {
    to_py_err(microsandbox::MicrosandboxError::AgentClient(err))
}

fn timeout_duration(timeout: Option<f64>) -> PyResult<Option<Duration>> {
    match timeout {
        Some(timeout) if timeout.is_finite() && timeout >= 0.0 => {
            Ok(Some(Duration::from_secs_f64(timeout)))
        }
        Some(_) => Err(PyValueError::new_err(
            "timeout must be a non-negative finite number",
        )),
        None => Ok(None),
    }
}
