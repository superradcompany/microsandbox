//! Python managed jobs retain runtime ownership independently of Python handle lifetime.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use futures::StreamExt;
use microsandbox::sandbox::jobs::{
    Job, JobAttachment, JobError, JobId, JobListBuilder, JobLogOptions, JobLogStream, JobReplay,
};
use pyo3::exceptions::{PyRuntimeError, PyStopAsyncIteration, PyValueError};
use pyo3::prelude::*;
use tokio::sync::{Mutex, Notify};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[pyclass(name = "Job", frozen)]
pub struct PyJob {
    pub(crate) inner: Job,
}

#[pyclass(name = "JobAttachment", frozen)]
pub struct PyJobAttachment {
    inner: Arc<JobAttachment>,
}

#[pyclass(name = "JobLogStream", frozen)]
pub struct PyJobLogStream {
    inner: Arc<LogReader>,
}

struct LogReader {
    stream: Mutex<Option<JobLogStream>>,
    closed: AtomicBool,
    notify: Notify,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[pymethods]
impl PyJob {
    #[getter]
    fn id(&self) -> String {
        self.inner.id().to_string()
    }

    fn inspect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let result = inner.inspect().await.map_err(job_error)?;
            decode("info", serde_json::to_value(result).map_err(invalid)?)
        })
    }

    fn wait<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let result = inner.wait().await.map_err(job_error)?;
            decode("exit", serde_json::to_value(result).map_err(invalid)?)
        })
    }

    fn signal<'py>(&self, py: Python<'py>, signal: i32) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.signal(signal).await.map_err(job_error)
        })
    }

    fn kill<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.kill().await.map_err(job_error)
        })
    }

    fn eof<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.eof().await.map_err(job_error)
        })
    }

    #[pyo3(signature = (*, read_only = false, replay_bytes = None, cursor = None))]
    fn attach<'py>(
        &self,
        py: Python<'py>,
        read_only: bool,
        replay_bytes: Option<usize>,
        cursor: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if replay_bytes.is_some() && cursor.is_some() {
            return Err(invalid("replay_bytes and cursor are mutually exclusive"));
        }
        let replay = match (replay_bytes, cursor) {
            (_, Some(cursor)) => JobReplay::After(cursor),
            (Some(max_bytes), _) => JobReplay::Recent { max_bytes },
            _ => JobReplay::None,
        };
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(PyJobAttachment {
                inner: Arc::new(
                    inner
                        .attach_with(|b| b.read_only(read_only).replay(replay))
                        .await
                        .map_err(job_error)?,
                ),
            })
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (*, tail = None, since = None, until = None, sources = None, from_cursor = None))]
    fn logs<'py>(
        &self,
        py: Python<'py>,
        tail: Option<usize>,
        since: Option<i64>,
        until: Option<i64>,
        sources: Option<Vec<String>>,
        from_cursor: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let options = JobLogOptions {
            tail,
            since,
            until,
            sources: sources.unwrap_or_default(),
            from_cursor,
            follow: false,
        };
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            decode(
                "logs",
                serde_json::to_value(inner.logs(&options).await.map_err(job_error)?)
                    .map_err(invalid)?,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (*, tail = None, since = None, until = None, sources = None, from_cursor = None, follow = false))]
    fn log_stream<'py>(
        &self,
        py: Python<'py>,
        tail: Option<usize>,
        since: Option<i64>,
        until: Option<i64>,
        sources: Option<Vec<String>>,
        from_cursor: Option<String>,
        follow: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let options = JobLogOptions {
            tail,
            since,
            until,
            sources: sources.unwrap_or_default(),
            from_cursor,
            follow,
        };
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(PyJobLogStream {
                inner: Arc::new(LogReader {
                    stream: Mutex::new(Some(inner.log_stream(&options).await.map_err(job_error)?)),
                    closed: AtomicBool::new(false),
                    notify: Notify::new(),
                }),
            })
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (*, tail = None, since = None, until = None, sources = None, from_cursor = None))]
    fn follow_logs<'py>(
        &self,
        py: Python<'py>,
        tail: Option<usize>,
        since: Option<i64>,
        until: Option<i64>,
        sources: Option<Vec<String>>,
        from_cursor: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let options = JobLogOptions {
            tail,
            since,
            until,
            sources: sources.unwrap_or_default(),
            from_cursor,
            follow: true,
        };
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(PyJobLogStream {
                inner: Arc::new(LogReader {
                    stream: Mutex::new(Some(inner.log_stream(&options).await.map_err(job_error)?)),
                    closed: AtomicBool::new(false),
                    notify: Notify::new(),
                }),
            })
        })
    }
}

#[pymethods]
impl PyJobAttachment {
    fn recv<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner
                .recv()
                .await
                .map_err(job_error)?
                .map(|event| decode("event", serde_json::to_value(event).map_err(invalid)?))
                .transpose()
        })
    }

    fn write_stdin<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.write_stdin(data).await.map_err(job_error)
        })
    }

    fn resize<'py>(&self, py: Python<'py>, rows: u16, cols: u16) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.resize(rows, cols).await.map_err(job_error)
        })
    }

    fn detach<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.detach().await.map_err(job_error)
        })
    }

    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }
    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let event = inner
                .recv()
                .await
                .map_err(job_error)?
                .ok_or_else(|| PyStopAsyncIteration::new_err(()))?;
            decode("event", serde_json::to_value(event).map_err(invalid)?)
        })
    }
}

#[pymethods]
impl PyJobLogStream {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }
    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let notified = inner.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let mut guard = inner.stream.lock().await;
            if inner.closed.load(Ordering::Acquire) {
                return Err(PyStopAsyncIteration::new_err(()));
            }
            let stream = guard
                .as_mut()
                .ok_or_else(|| PyStopAsyncIteration::new_err(()))?;
            let item = tokio::select! {
                _ = notified => None,
                item = stream.next() => item,
            }
            .ok_or_else(|| PyStopAsyncIteration::new_err(()))?
            .map_err(job_error)?;
            decode("log", serde_json::to_value(item).map_err(invalid)?)
        })
    }
    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        // Wake a pending read before acquiring its mutex.
        inner.closed.store(true, Ordering::Release);
        inner.notify.notify_waiters();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inner.stream.lock().await.take();
            Ok(())
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn decode(kind: &str, value: serde_json::Value) -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let value = crate::sandbox_handle::json_value_to_py(py, value)?;
        Ok(py
            .import("microsandbox.jobs")?
            .getattr(format!("_decode_{kind}"))?
            .call1((value,))?
            .unbind())
    })
}

pub(crate) fn job_error(error: JobError) -> PyErr {
    let id = match &error {
        JobError::LaunchUnconfirmed { id, .. } => Some(id.to_string()),
        _ => None,
    };
    Python::with_gil(|py| {
        match py
            .import("microsandbox.errors")
            .and_then(|m| m.getattr("JobError"))
            .and_then(|c| c.call1((error.code(), error.to_string(), id)))
        {
            Ok(instance) => PyErr::from_value(instance),
            Err(_) => PyRuntimeError::new_err(error.to_string()),
        }
    })
}

pub(crate) fn invalid(error: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(error.to_string())
}

pub(crate) fn list_options(
    all: bool,
    limit: usize,
    cursor: Option<String>,
) -> PyResult<JobListBuilder> {
    let mut options = JobListBuilder::default().all(all).limit(limit);
    if let Some(cursor) = cursor {
        options = options.cursor(JobId::parse(cursor).map_err(invalid)?);
    }
    Ok(options)
}
