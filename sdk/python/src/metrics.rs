use std::pin::Pin;
use std::sync::Arc;

use futures::StreamExt;
use pyo3::prelude::*;
use tokio::sync::Mutex;

use crate::error::to_py_err;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Point-in-time resource metrics for a sandbox.
#[pyclass(name = "SandboxMetrics")]
pub struct PySandboxMetrics {
    #[pyo3(get)]
    pub cpu_percent: f64,
    #[pyo3(get)]
    pub memory_bytes: u64,
    #[pyo3(get)]
    pub memory_limit_bytes: u64,
    #[pyo3(get)]
    pub disk_read_bytes: u64,
    #[pyo3(get)]
    pub disk_write_bytes: u64,
    #[pyo3(get)]
    pub net_rx_bytes: u64,
    #[pyo3(get)]
    pub net_tx_bytes: u64,
    #[pyo3(get)]
    pub uptime_ms: u64,
    #[pyo3(get)]
    pub timestamp_ms: f64,
}

type MetricsStreamInner = Pin<
    Box<
        dyn futures::Stream<
                Item = microsandbox::MicrosandboxResult<microsandbox::sandbox::SandboxMetrics>,
            > + Send,
    >,
>;

/// Async iterator over streaming metrics snapshots.
#[pyclass(name = "MetricsStream")]
pub struct PyMetricsStream {
    stream: Arc<Mutex<MetricsStreamInner>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PyMetricsStream {
    pub fn new(
        stream: impl futures::Stream<
            Item = microsandbox::MicrosandboxResult<microsandbox::sandbox::SandboxMetrics>,
        > + Send
        + 'static,
    ) -> Self {
        Self {
            stream: Arc::new(Mutex::new(Box::pin(stream))),
        }
    }
}

#[pymethods]
impl PyMetricsStream {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let stream = self.stream.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = stream.lock().await;
            match guard.next().await {
                Some(Ok(m)) => Ok(convert_metrics(&m)),
                Some(Err(e)) => Err(to_py_err(e)),
                None => Err(pyo3::exceptions::PyStopAsyncIteration::new_err(())),
            }
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Convert Rust SandboxMetrics to Python.
pub fn convert_metrics(m: &microsandbox::sandbox::SandboxMetrics) -> PySandboxMetrics {
    PySandboxMetrics {
        cpu_percent: m.cpu_percent as f64,
        memory_bytes: m.memory_bytes,
        memory_limit_bytes: m.memory_limit_bytes,
        disk_read_bytes: m.disk_read_bytes,
        disk_write_bytes: m.disk_write_bytes,
        net_rx_bytes: m.net_rx_bytes,
        net_tx_bytes: m.net_tx_bytes,
        uptime_ms: m.uptime.as_millis() as u64,
        timestamp_ms: m.timestamp.timestamp_millis() as f64,
    }
}

/// Get metrics for all running sandboxes.
#[pyfunction]
pub fn all_sandbox_metrics<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let metrics = microsandbox::sandbox::all_sandbox_metrics()
            .await
            .map_err(to_py_err)?;
        let result: std::collections::HashMap<String, PySandboxMetrics> = metrics
            .into_iter()
            .map(|(name, m)| (name, convert_metrics(&m)))
            .collect();
        Ok(result)
    })
}
