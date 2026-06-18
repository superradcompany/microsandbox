//! Public value types: source tags, the entry shape, and the
//! snapshot filter options.

use bytes::Bytes;
use chrono::{DateTime, Utc};

use super::cursor::LogCursor;

//--------------------------------------------------------------------------------------------------
// LogSource
//--------------------------------------------------------------------------------------------------

/// Source tag on a captured log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSource {
    /// Captured from a session's stdout (pipe mode).
    Stdout,

    /// Captured from a session's stderr (pipe mode).
    Stderr,

    /// Captured from a session in pty mode (stdout + stderr merged
    /// at the kernel level inside the guest arrive as a single
    /// stream — tagged `output` rather than pretending to be
    /// `stdout`).
    Output,

    /// Synthetic system entry: lifecycle markers, runtime
    /// diagnostics, kernel console output.
    System,
}

impl LogSource {
    /// Apply the empty-means-default rule used by both
    /// [`read_logs`](super::read_logs) and
    /// [`log_stream`](super::log_stream): if `requested` is empty,
    /// return the default user-program sources
    /// (`Stdout` + `Stderr` + `Output`); otherwise return a
    /// sorted, deduplicated copy of `requested`.
    pub(crate) fn effective(requested: &[Self]) -> Vec<Self> {
        if requested.is_empty() {
            vec![Self::Stdout, Self::Stderr, Self::Output]
        } else {
            let mut s = requested.to_vec();
            s.sort_by_key(|src| match src {
                Self::Stdout => 0,
                Self::Stderr => 1,
                Self::Output => 2,
                Self::System => 3,
            });
            s.dedup();
            s
        }
    }
}

//--------------------------------------------------------------------------------------------------
// LogEntry
//--------------------------------------------------------------------------------------------------

/// A single captured log entry.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Wall-clock time the chunk was captured by the host.
    pub timestamp: DateTime<Utc>,

    /// Where the chunk came from.
    pub source: LogSource,

    /// Per-session identifier. Set for entries captured from an
    /// exec session; `None` for `system` entries which are not
    /// tied to a specific session.
    pub session_id: Option<u64>,

    /// Decoded body bytes. UTF-8 lossy by default; if the underlying
    /// chunk was raw-mode base64, this is the decoded raw bytes.
    pub data: Bytes,

    /// Opaque per-source resume handle. Snapshot of the positions
    /// each source has reached after emitting this entry. Pass to
    /// [`LogStreamStart::From`](super::LogStreamStart::From) to
    /// resume; each source picks up independently from its
    /// captured position.
    pub cursor: LogCursor,
}

//--------------------------------------------------------------------------------------------------
// LogOptions
//--------------------------------------------------------------------------------------------------

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
    /// `Stdout` + `Stderr` + `Output`.
    pub sources: Vec<LogSource>,
}

impl LogOptions {
    /// Apply `since`, `until`, and `tail` filters to `entries`
    /// in place, in that order.
    pub(crate) fn apply_to(&self, entries: &mut Vec<LogEntry>) {
        if let Some(s) = self.since {
            entries.retain(|e| e.timestamp >= s);
        }
        if let Some(u) = self.until {
            entries.retain(|e| e.timestamp < u);
        }
        if let Some(n) = self.tail
            && entries.len() > n
        {
            let drop = entries.len() - n;
            entries.drain(0..drop);
        }
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
        let s = LogSource::effective(&[]);
        assert_eq!(
            s,
            vec![LogSource::Stdout, LogSource::Stderr, LogSource::Output]
        );
    }

    #[test]
    fn explicit_sources_used_when_set() {
        let s = LogSource::effective(&[LogSource::System]);
        assert_eq!(s, vec![LogSource::System]);
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
                cursor: LogCursor::empty(),
            })
            .collect::<Vec<_>>();
        LogOptions {
            tail: Some(2),
            ..Default::default()
        }
        .apply_to(&mut entries);
        assert_eq!(entries.len(), 2);
    }
}
