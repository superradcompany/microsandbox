//! Host-side capture of the primary exec session's stdout/stderr into
//! a JSON Lines file (`exec.log`).
//!
//! The relay taps `ExecStdout` / `ExecStderr` frames as they pass
//! through the host (see `relay.rs::ring_reader_task`) and forwards a
//! copy of the payload bytes here. Each chunk becomes one JSON line:
//!
//! ```jsonc
//! {"t": "2026-04-30T20:32:59.688Z", "s": "stdout", "d": "..."}
//! ```
//!
//! Only the **primary session** — the first exec session opened
//! against the sandbox per lifetime — feeds this file. See
//! `design/runtime/sandbox-logs.md` D3a for the rationale.
//!
//! The writer is a thin wrapper around [`crate::logging::RotatingLog`]:
//! disk size is bounded at 10 MiB × 3 rotated files (40 MiB ceiling).

use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;

use crate::RuntimeResult;
use crate::logging::RotatingLog;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Filename written into `log_dir`.
pub const EXEC_LOG_FILENAME: &str = "exec.log";

/// Per-file rotation threshold (10 MiB).
const EXEC_LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Source tag for a log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogSource {
    /// Captured from the primary session's stdout (pipe mode only).
    Stdout,

    /// Captured from the primary session's stderr (pipe mode only).
    Stderr,

    /// Captured from the primary session in pty mode.
    ///
    /// pty allocation merges stdout and stderr at the kernel level
    /// before the bytes leave the guest. Tagging these as `output`
    /// (rather than lying with `stdout`) keeps `s: "stderr"` filters
    /// honest: a programmatic consumer doing
    /// `jq 'select(.s == "stderr")'` will not accidentally pick up
    /// merged pty output that originated as stderr.
    Output,

    /// Synthetic lifecycle marker injected by the host writer
    /// (e.g. `--- sandbox started ---`).
    System,
}

/// A single JSON Lines entry.
///
/// Field names are short to keep the file compact when many small
/// chunks accumulate. Schema is locked per
/// `design/runtime/sandbox-logs.md` D2.
#[derive(Debug, Serialize)]
struct ExecLogEntry<'a> {
    t: &'a str,
    s: LogSource,
    d: &'a str,
    /// Relay-monotonic session id. Present for `stdout`/`stderr`/
    /// `output` entries, omitted for `system` lifecycle markers
    /// (which aren't tied to a specific exec session). u64 because
    /// the relay can run for a very long time and we never want
    /// wraparound; in practice values stay small (start at 1, +1 per
    /// session opened).
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<&'static str>,
}

/// Append-only writer for `exec.log`.
///
/// Cheap to clone via `Arc<LogWriter>`. Internally serialised so
/// concurrent calls from the relay's frame-dispatch task and the
/// lifecycle-marker call sites cannot interleave bytes mid-line.
pub struct LogWriter {
    inner: Mutex<RotatingLog>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LogWriter {
    /// Create or open `<log_dir>/exec.log` (appending if it exists).
    pub fn open(log_dir: &Path) -> RuntimeResult<Self> {
        let inner = RotatingLog::new(log_dir, "exec", EXEC_LOG_MAX_BYTES)?;
        Ok(Self {
            inner: Mutex::new(inner),
        })
    }

    /// Write a captured chunk as one JSON line.
    ///
    /// `data` is treated as a UTF-8 byte string; non-UTF-8 input is
    /// preserved via `to_string_lossy` (replacement char `U+FFFD` for
    /// invalid sequences). Future opt-in raw mode (`--raw`) will
    /// switch to base64; for now lossy decode keeps the file
    /// grep-friendly.
    ///
    /// `session_id` is the protocol correlation id for the exec
    /// session this chunk came from. It's recorded in the log so
    /// readers can group or filter by session.
    pub fn write_chunk(&self, source: LogSource, session_id: u64, data: &[u8]) {
        let decoded = String::from_utf8_lossy(data);
        self.write_entry(source, Some(session_id), &decoded);
    }

    /// Write a synthetic lifecycle marker as `s: "system"`.
    ///
    /// System entries are not tied to a specific session, so they
    /// have no `id` field.
    pub fn write_system(&self, message: &str) {
        // Ensure trailing newline so terminal renderings of the file
        // separate cleanly from subsequent stdout/stderr.
        let body = if message.ends_with('\n') {
            message.to_string()
        } else {
            format!("{message}\n")
        };
        self.write_entry(LogSource::System, None, &body);
    }

    fn write_entry(&self, source: LogSource, session_id: Option<u64>, data: &str) {
        let entry = ExecLogEntry {
            t: &now_rfc3339(),
            s: source,
            d: data,
            id: session_id,
            e: None,
        };
        let mut line = match serde_json::to_vec(&entry) {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "exec_log: failed to serialize entry, dropping"
                );
                return;
            }
        };
        line.push(b'\n');

        if let Ok(mut guard) = self.inner.lock()
            && let Err(err) = guard.write(&line)
        {
            tracing::warn!(error = %err, "exec_log: write failed");
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Entry {
        t: String,
        s: String,
        d: String,
        #[serde(default)]
        id: Option<u64>,
    }

    fn read_entries(dir: &Path) -> Vec<Entry> {
        let path = dir.join(EXEC_LOG_FILENAME);
        let bytes = std::fs::read(&path).unwrap_or_default();
        std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("valid json line"))
            .collect()
    }

    #[test]
    fn writes_stdout_and_stderr_as_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let writer = LogWriter::open(dir.path()).unwrap();

        writer.write_chunk(LogSource::Stdout, 7, b"hello\n");
        writer.write_chunk(LogSource::Stderr, 7, b"oops\n");

        let entries = read_entries(dir.path());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].s, "stdout");
        assert_eq!(entries[0].d, "hello\n");
        assert_eq!(entries[0].id, Some(7));
        assert_eq!(entries[1].s, "stderr");
        assert_eq!(entries[1].d, "oops\n");
        assert_eq!(entries[1].id, Some(7));
        // Timestamp is RFC 3339 with Z suffix.
        assert!(entries[0].t.ends_with('Z'));
    }

    #[test]
    fn distinct_sessions_get_distinct_ids() {
        let dir = tempfile::tempdir().unwrap();
        let writer = LogWriter::open(dir.path()).unwrap();

        writer.write_chunk(LogSource::Stdout, 1, b"a\n");
        writer.write_chunk(LogSource::Stdout, 42, b"b\n");

        let entries = read_entries(dir.path());
        assert_eq!(entries[0].id, Some(1));
        assert_eq!(entries[1].id, Some(42));
    }

    #[test]
    fn write_system_appends_newline_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let writer = LogWriter::open(dir.path()).unwrap();

        writer.write_system("--- sandbox started ---");

        let entries = read_entries(dir.path());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].s, "system");
        assert_eq!(entries[0].d, "--- sandbox started ---\n");
        // System entries are not tied to a session.
        assert_eq!(entries[0].id, None);
    }

    #[test]
    fn non_utf8_bytes_use_replacement_char() {
        let dir = tempfile::tempdir().unwrap();
        let writer = LogWriter::open(dir.path()).unwrap();

        writer.write_chunk(LogSource::Stdout, 1, &[0xff, 0xfe, b'h', b'i']);

        let entries = read_entries(dir.path());
        assert_eq!(entries.len(), 1);
        assert!(entries[0].d.contains('\u{FFFD}'));
        assert!(entries[0].d.contains("hi"));
    }

    #[test]
    fn second_open_appends() {
        let dir = tempfile::tempdir().unwrap();
        {
            let writer = LogWriter::open(dir.path()).unwrap();
            writer.write_chunk(LogSource::Stdout, 1, b"line1\n");
        }
        {
            let writer = LogWriter::open(dir.path()).unwrap();
            writer.write_chunk(LogSource::Stdout, 1, b"line2\n");
        }
        let entries = read_entries(dir.path());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].d, "line1\n");
        assert_eq!(entries[1].d, "line2\n");
    }
}
