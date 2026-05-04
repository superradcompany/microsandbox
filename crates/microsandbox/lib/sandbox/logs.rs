//! Programmatic access to a sandbox's captured output (`exec.log`).
//!
//! Reads the JSON Lines file the runtime writes via the relay tap (see
//! `crates/runtime/lib/exec_log.rs`). Works on running and stopped
//! sandboxes alike — there is no protocol traffic involved; we read
//! the persisted file directly.
//!
//! For the CLI, see `crates/cli/lib/commands/logs.rs`. This module
//! exposes the same data to SDK callers as a typed iterator.

use std::path::{Path, PathBuf};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use microsandbox_utils::log_text::{base64_decode, split_leading_timestamp, strip_ansi};
use serde::Deserialize;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Source tag on a captured log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSource {
    /// Captured from the primary session's stdout (pipe mode).
    Stdout,

    /// Captured from the primary session's stderr (pipe mode).
    Stderr,

    /// Captured from the primary session in pty mode (stdout+stderr
    /// are merged at the kernel level inside the guest, so they
    /// arrive as a single stream — tagged `output` rather than
    /// pretending to be `stdout`).
    Output,

    /// Synthetic system entry (lifecycle marker, runtime/kernel diag).
    System,
}

/// A single captured log entry.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Wall-clock time the chunk was captured by the host.
    pub timestamp: DateTime<Utc>,

    /// Where the chunk came from.
    pub source: LogSource,

    /// Relay-monotonic session id. Distinct from the protocol
    /// correlation id (which is reused across slot recycling): every
    /// session opened against the sandbox per lifetime gets a
    /// unique id, starting at 1 and counting up. `None` for `system`
    /// lifecycle markers, which are not tied to a specific session.
    pub session_id: Option<u64>,

    /// Decoded body bytes. UTF-8 lossy by default; if the underlying
    /// chunk was raw-mode base64, this is the decoded raw bytes.
    pub data: Bytes,
}

/// Filters applied when reading historical log entries.
#[derive(Debug, Clone, Default)]
pub struct LogOptions {
    /// Show only the last N entries after all other filters apply.
    pub tail: Option<usize>,

    /// Inclusive lower bound on entry timestamp.
    pub since: Option<DateTime<Utc>>,

    /// Exclusive upper bound on entry timestamp.
    pub until: Option<DateTime<Utc>>,

    /// Sources to include. If empty, defaults to
    /// `Stdout` + `Stderr` (matching the CLI default).
    pub sources: Vec<LogSource>,
}

//--------------------------------------------------------------------------------------------------
// Internal types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawEntry {
    t: String,
    s: String,
    #[serde(default)]
    d: String,
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    e: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Read all matching log entries from the on-disk file for the named
/// sandbox.
///
/// Returns an empty vector if the sandbox has no `exec.log` yet (i.e.
/// has been created but never opened a primary exec session).
pub fn read_logs(name: &str, opts: &LogOptions) -> MicrosandboxResult<Vec<LogEntry>> {
    let log_dir = log_dir_for(name);
    if !log_dir.exists() {
        return Err(MicrosandboxError::SandboxNotFound(name.to_string()));
    }

    let sources = effective_sources(opts);

    let mut entries = read_jsonl_history(&log_dir, &sources)?;

    apply_filters(&mut entries, opts);
    Ok(entries)
}

/// Compute the on-disk log directory for a sandbox name.
pub fn log_dir_for(name: &str) -> PathBuf {
    crate::config::config()
        .sandboxes_dir()
        .join(name)
        .join("logs")
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn effective_sources(opts: &LogOptions) -> Vec<LogSource> {
    if opts.sources.is_empty() {
        // Default = the user-program output. Includes `Output`
        // (pty merged) so a pty session's logs aren't silently
        // filtered out under the default.
        vec![LogSource::Stdout, LogSource::Stderr, LogSource::Output]
    } else {
        opts.sources.clone()
    }
}

fn read_jsonl_history(log_dir: &Path, sources: &[LogSource]) -> MicrosandboxResult<Vec<LogEntry>> {
    let mut out: Vec<LogEntry> = Vec::new();

    let want_exec = sources
        .iter()
        .any(|s| matches!(s, LogSource::Stdout | LogSource::Stderr | LogSource::Output));
    if want_exec {
        // Rotated files first so output is chronological.
        for suffix in [".3", ".2", ".1", ""].iter() {
            let path = if suffix.is_empty() {
                log_dir.join("exec.log")
            } else {
                log_dir.join(format!("exec.log{suffix}"))
            };
            if !path.exists() {
                continue;
            }
            append_jsonl_file(&path, &mut out, sources)?;
        }
    }

    if sources.iter().any(|s| matches!(s, LogSource::System)) {
        // Cross-merge runtime.log and kernel.log as system lines.
        for filename in ["runtime.log", "kernel.log"].iter() {
            let path = log_dir.join(filename);
            append_text_log_as_system(&path, &mut out);
        }
        // Already typed `DateTime<Utc>`, so sort_by_key on the field
        // is correct (no precision-loss issue here — that bug only
        // affected the CLI's string-keyed sort).
        out.sort_by_key(|e| e.timestamp);
    }

    Ok(out)
}

fn append_jsonl_file(
    path: &Path,
    out: &mut Vec<LogEntry>,
    sources: &[LogSource],
) -> MicrosandboxResult<()> {
    let bytes = std::fs::read(path)?;
    let text = String::from_utf8_lossy(&bytes);
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let raw: RawEntry = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let source = match raw.s.as_str() {
            "stdout" => LogSource::Stdout,
            "stderr" => LogSource::Stderr,
            "output" => LogSource::Output,
            "system" => LogSource::System,
            _ => continue,
        };
        if !sources.contains(&source) {
            continue;
        }
        let timestamp = match DateTime::parse_from_rfc3339(&raw.t) {
            Ok(t) => t.with_timezone(&Utc),
            Err(_) => continue,
        };
        let data = decode_body(&raw);
        out.push(LogEntry {
            timestamp,
            source,
            session_id: raw.id,
            data,
        });
    }
    Ok(())
}

fn decode_body(raw: &RawEntry) -> Bytes {
    if raw.e.as_deref() == Some("b64") {
        match base64_decode(&raw.d) {
            Some(bytes) => Bytes::from(bytes),
            None => Bytes::from(raw.d.clone().into_bytes()),
        }
    } else {
        Bytes::from(raw.d.clone().into_bytes())
    }
}

fn append_text_log_as_system(path: &Path, out: &mut Vec<LogEntry>) {
    if !path.exists() {
        return;
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return,
    };
    let text = String::from_utf8_lossy(&bytes);
    let mtime = std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|t| -> DateTime<Utc> { t.into() })
        .unwrap_or_else(Utc::now);

    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        // Strip ANSI before parsing — tracing wraps the timestamp in
        // color escapes which would otherwise hide it from the
        // leading-token detector. Fall back to file mtime if a line
        // genuinely lacks an RFC 3339 prefix.
        let stripped = strip_ansi(line);
        let (ts, body) = match split_leading_timestamp(&stripped) {
            Some((s, rest)) => (
                DateTime::parse_from_rfc3339(s)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or(mtime),
                rest.trim_start().to_string(),
            ),
            None => (mtime, stripped.clone()),
        };
        out.push(LogEntry {
            timestamp: ts,
            source: LogSource::System,
            session_id: None,
            data: Bytes::from(format!("{body}\n").into_bytes()),
        });
    }
}

fn apply_filters(entries: &mut Vec<LogEntry>, opts: &LogOptions) {
    if let Some(s) = opts.since {
        entries.retain(|e| e.timestamp >= s);
    }
    if let Some(u) = opts.until {
        entries.retain(|e| e.timestamp < u);
    }
    if let Some(n) = opts.tail
        && entries.len() > n
    {
        let drop = entries.len() - n;
        entries.drain(0..drop);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_sources_are_user_program_output() {
        let opts = LogOptions::default();
        let s = effective_sources(&opts);
        assert_eq!(
            s,
            vec![LogSource::Stdout, LogSource::Stderr, LogSource::Output]
        );
    }

    #[test]
    fn explicit_sources_used_when_set() {
        let opts = LogOptions {
            sources: vec![LogSource::System],
            ..Default::default()
        };
        let s = effective_sources(&opts);
        assert_eq!(s, vec![LogSource::System]);
    }

    #[test]
    fn round_trip_jsonl_via_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let exec_log_path = dir.path().join("exec.log");
        let lines = [
            r#"{"t":"2026-04-30T20:32:59.000Z","s":"stdout","d":"hello\n","id":7}"#,
            r#"{"t":"2026-04-30T20:33:00.000Z","s":"stderr","d":"oops\n","id":7}"#,
            r#"{"t":"2026-04-30T20:33:01.000Z","s":"system","d":"--- sandbox stopped ---\n"}"#,
        ];
        std::fs::write(&exec_log_path, lines.join("\n").into_bytes()).unwrap();

        let mut out = Vec::new();
        append_jsonl_file(
            &exec_log_path,
            &mut out,
            &[LogSource::Stdout, LogSource::Stderr],
        )
        .unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].source, LogSource::Stdout);
        assert_eq!(out[0].data, Bytes::from("hello\n".as_bytes()));
        assert_eq!(out[0].session_id, Some(7u64));
        assert_eq!(out[1].source, LogSource::Stderr);
        assert_eq!(out[1].session_id, Some(7u64));
    }

    #[test]
    fn apply_filters_tail() {
        let mut entries = (0..5)
            .map(|i| LogEntry {
                timestamp: DateTime::parse_from_rfc3339(&format!("2026-04-30T00:00:0{i}.000Z"))
                    .unwrap()
                    .with_timezone(&Utc),
                source: LogSource::Stdout,
                session_id: Some(1u64),
                data: Bytes::from(format!("line {i}").into_bytes()),
            })
            .collect::<Vec<_>>();
        apply_filters(
            &mut entries,
            &LogOptions {
                tail: Some(2),
                ..Default::default()
            },
        );
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn base64_decode_basic() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
    }
}
