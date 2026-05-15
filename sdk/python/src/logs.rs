use pyo3::prelude::*;
use pyo3::types::PyBytes;

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

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Convert a Rust `LogEntry` into the Python class.
pub fn convert_entry(entry: microsandbox::sandbox::LogEntry) -> PyLogEntry {
    let source = match entry.source {
        microsandbox::sandbox::LogSource::Stdout => "stdout",
        microsandbox::sandbox::LogSource::Stderr => "stderr",
        microsandbox::sandbox::LogSource::Output => "output",
        microsandbox::sandbox::LogSource::System => "system",
    };
    PyLogEntry {
        timestamp_ms: entry.timestamp.timestamp_millis() as f64,
        source: source.to_string(),
        session_id: entry.session_id,
        data: entry.data.to_vec(),
    }
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
    use microsandbox::sandbox::{LogOptions, LogSource};

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

    let entries = microsandbox::sandbox::logs::read_logs(name, &opts).map_err(to_py_err)?;
    Ok(entries.into_iter().map(convert_entry).collect())
}

fn ms_to_datetime(ms: f64) -> Option<chrono::DateTime<chrono::Utc>> {
    let secs = (ms / 1000.0).trunc() as i64;
    let nsecs = ((ms - secs as f64 * 1000.0) * 1_000_000.0).round() as u32;
    chrono::DateTime::from_timestamp(secs, nsecs)
}
