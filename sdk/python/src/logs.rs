use std::pin::Pin;
use std::sync::Arc;

use futures::StreamExt;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use tokio::sync::Mutex;

use crate::error::to_py_err;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One captured log entry from `exec.log`.
#[pyclass(name = "LogEntry")]
pub struct PyLogEntry {
    /// Wall-clock capture time as ms since Unix epoch (UTC).
    #[pyo3(get)]
    pub timestamp_ms: f64,

    /// `"stdout"`, `"stderr"`, `"output"` (pty merged), or `"system"`.
    #[pyo3(get)]
    pub source: String,

    /// Relay-monotonic session id. `None` for `system` lifecycle
    /// markers (which aren't tied to a specific session).
    #[pyo3(get)]
    pub session_id: Option<u64>,

    /// Opaque resume token. Pass back to `Sandbox.log_stream` via
    /// `from_cursor` to resume immediately after this entry.
    #[pyo3(get)]
    pub cursor: String,

    /// Captured chunk's bytes.
    pub data: Vec<u8>,
}

#[pymethods]
impl PyLogEntry {
    #[getter]
    fn data<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.data)
    }

    /// UTF-8 lossy decode of `data`.
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.data).into_owned()
    }

    fn __repr__(&self) -> String {
        format!(
            "LogEntry(source={:?}, session_id={:?}, timestamp_ms={}, len={})",
            self.source,
            self.session_id,
            self.timestamp_ms,
            self.data.len()
        )
    }
}

type LogStreamInner = Pin<
    Box<
        dyn futures::Stream<Item = microsandbox::MicrosandboxResult<microsandbox::logs::LogEntry>>
            + Send,
    >,
>;

/// Async iterator over a live log stream. Yielded objects are
/// [`PyLogEntry`] values; iteration ends naturally when the stream
/// drains (snapshot mode or `until_ms` reached) and raises on a
/// fatal stream error.
#[pyclass(name = "LogStream")]
pub struct PyLogStream {
    stream: Arc<Mutex<LogStreamInner>>,
}

impl PyLogStream {
    pub fn new(
        stream: impl futures::Stream<
            Item = microsandbox::MicrosandboxResult<microsandbox::logs::LogEntry>,
        > + Send
        + 'static,
    ) -> Self {
        Self {
            stream: Arc::new(Mutex::new(Box::pin(stream))),
        }
    }
}

#[pymethods]
impl PyLogStream {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let stream = self.stream.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = stream.lock().await;
            match guard.next().await {
                Some(Ok(entry)) => Ok(convert_entry(entry)),
                Some(Err(e)) => Err(to_py_err(e)),
                None => Err(pyo3::exceptions::PyStopAsyncIteration::new_err(())),
            }
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Convert a Rust `LogEntry` into the Python class.
pub fn convert_entry(entry: microsandbox::logs::LogEntry) -> PyLogEntry {
    let source = match entry.source {
        microsandbox::logs::LogSource::Stdout => "stdout",
        microsandbox::logs::LogSource::Stderr => "stderr",
        microsandbox::logs::LogSource::Output => "output",
        microsandbox::logs::LogSource::System => "system",
    };
    PyLogEntry {
        timestamp_ms: entry.timestamp.timestamp_millis() as f64,
        source: source.to_string(),
        session_id: entry.session_id,
        cursor: entry.cursor.to_string(),
        data: entry.data.to_vec(),
    }
}

/// Build a [`microsandbox::logs::LogStreamOptions`] from the keyword
/// args the Python method accepts. `since_ms` and `from_cursor` are
/// mutually exclusive.
pub fn parse_log_stream_options(
    sources: Option<Vec<String>>,
    since_ms: Option<f64>,
    from_cursor: Option<String>,
    until_ms: Option<f64>,
    follow: bool,
) -> PyResult<microsandbox::logs::LogStreamOptions> {
    use microsandbox::logs::{LogCursor, LogCursorParseError, LogSource, LogStreamStart};

    if since_ms.is_some() && from_cursor.is_some() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "since_ms and from_cursor are mutually exclusive",
        ));
    }
    let start = if let Some(ms) = since_ms {
        let ts = ms_to_datetime(ms).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!("invalid since_ms value {ms}"))
        })?;
        LogStreamStart::Since(ts)
    } else if let Some(token) = from_cursor.as_deref() {
        let cursor: LogCursor = token.parse().map_err(|e: LogCursorParseError| {
            pyo3::exceptions::PyValueError::new_err(format!("invalid from_cursor: {e}"))
        })?;
        LogStreamStart::From(cursor)
    } else {
        LogStreamStart::Beginning
    };
    let mut engine_sources = Vec::new();
    if let Some(src) = sources {
        for s in src {
            match s.as_str() {
                "stdout" => engine_sources.push(LogSource::Stdout),
                "stderr" => engine_sources.push(LogSource::Stderr),
                "output" => engine_sources.push(LogSource::Output),
                "system" => engine_sources.push(LogSource::System),
                "all" => {
                    engine_sources = vec![
                        LogSource::Stdout,
                        LogSource::Stderr,
                        LogSource::Output,
                        LogSource::System,
                    ];
                }
                other => {
                    return Err(pyo3::exceptions::PyValueError::new_err(format!(
                        "unknown log source {other:?}"
                    )));
                }
            }
        }
    }
    Ok(microsandbox::logs::LogStreamOptions {
        sources: engine_sources,
        start,
        until: until_ms.and_then(ms_to_datetime),
        follow,
    })
}

/// Open a log stream against the named sandbox and wrap it as a
/// `PyLogStream`. Shared between `Sandbox.log_stream` and
/// `SandboxHandle.log_stream`.
pub async fn open_log_stream(
    name: &str,
    opts: microsandbox::logs::LogStreamOptions,
) -> PyResult<PyLogStream> {
    let stream = microsandbox::logs::log_stream(name, &opts)
        .await
        .map_err(to_py_err)?;
    Ok(PyLogStream::new(stream))
}

/// Read captured logs for a sandbox by name. Filters are encoded as a
/// `LogOptions` Rust struct on the caller's side.
pub fn read_logs_blocking(
    name: &str,
    tail: Option<usize>,
    since_ms: Option<f64>,
    until_ms: Option<f64>,
    sources: Option<Vec<String>>,
) -> PyResult<Vec<PyLogEntry>> {
    use microsandbox::logs::{LogOptions, LogSource};

    let mut opts = LogOptions {
        tail,
        since: since_ms.and_then(ms_to_datetime),
        until: until_ms.and_then(ms_to_datetime),
        sources: Vec::new(),
    };
    if let Some(src) = sources {
        for s in src {
            match s.as_str() {
                "stdout" => opts.sources.push(LogSource::Stdout),
                "stderr" => opts.sources.push(LogSource::Stderr),
                "output" => opts.sources.push(LogSource::Output),
                "system" => opts.sources.push(LogSource::System),
                "all" => {
                    opts.sources = vec![
                        LogSource::Stdout,
                        LogSource::Stderr,
                        LogSource::Output,
                        LogSource::System,
                    ];
                }
                other => {
                    return Err(pyo3::exceptions::PyValueError::new_err(format!(
                        "unknown log source {other:?}"
                    )));
                }
            }
        }
    }

    let entries = tokio::runtime::Handle::current()
        .block_on(microsandbox::logs::read_logs(name, &opts))
        .map_err(to_py_err)?;
    Ok(entries.into_iter().map(convert_entry).collect())
}

fn ms_to_datetime(ms: f64) -> Option<chrono::DateTime<chrono::Utc>> {
    let secs = (ms / 1000.0).trunc() as i64;
    let nsecs = ((ms - secs as f64 * 1000.0) * 1_000_000.0).round() as u32;
    chrono::DateTime::from_timestamp(secs, nsecs)
}
