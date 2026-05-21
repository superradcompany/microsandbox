//! Rotation-aware multi-file log streaming.
//!
//! Two public entry points keyed by sandbox name:
//!
//! - [`read_logs`] returns a snapshot `Vec<LogEntry>` filtered with
//!   [`LogOptions`]. Reads everything currently on disk, sorts by
//!   timestamp, and returns.
//! - [`log_stream`] returns a [`futures::Stream`] over the same
//!   files, suitable for live-tailing or replaying a fixed range.
//!   Uses filesystem change notifications (the `notify` crate) for
//!   live updates with a fallback poll, and stamps each entry with
//!   an opaque [`LogCursor`] for exact per-source resume.
//!
//! # Files read
//!
//! - `exec.log` + rotated siblings (`exec.log.1` ... `exec.log.4`):
//!   JSON Lines, captured stdout / stderr / pty output written by
//!   the runtime relay tap. Rotates at 10 MiB per file, retains up
//!   to four historical files on disk (~40 MiB ceiling).
//! - `runtime.log`: plain text, runtime diagnostics. Only read when
//!   `System` is in the requested sources. Does not rotate.
//! - `kernel.log`: plain text, guest kernel console. Only read when
//!   `System` is in the requested sources. Does not rotate.
//!
//! Adding a new log file type is one entry in `LOG_FILES`.
//!
//! # Ordering contract
//!
//! - [`read_logs`] returns entries in strict chronological order
//!   (it sorts by timestamp before returning).
//! - [`log_stream`] preserves chronological order **within each
//!   source** but emits **across sources** in "as parsed" order —
//!   a `runtime.log` entry timestamped slightly earlier than an
//!   `exec.log` entry may be yielded after it if the `exec.log`
//!   read landed first. Use [`read_logs`] if you need strict
//!   global ordering.
//!
//! # Keeping up
//!
//! [`log_stream`] holds an open file descriptor on each file it is
//! reading. Because rotation is a `rename` (not a delete), the FD
//! remains valid across rotations: the stream can drain whatever
//! the producer wrote to the now-rotated file before transitioning
//! to the new active file.
//!
//! However, the producer caps disk retention at four rotated files
//! (~40 MiB). If a consumer falls behind enough that the inode it
//! was reading rotates past that retention window before the
//! stream catches up, the file is overwritten and lost. When that
//! happens, the stream yields
//! [`crate::MicrosandboxError::MissedRotation`]
//! and ends. Hard-fail by design — restart from
//! [`LogStreamStart::Beginning`], [`LogStreamStart::Since`] with
//! the current time, or [`LogStreamStart::From`] with the cursor
//! of the last entry successfully consumed.

mod cursor;
mod parser;
mod stream;
mod types;

pub use cursor::{LogCursor, LogCursorParseError};
pub use stream::{LogStreamOptions, LogStreamStart};
pub use types::{LogEntry, LogOptions, LogSource};

use std::path::PathBuf;

use futures::Stream;

use stream::{LogEngine, LogFileConfig, LogFileFormat};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// LOG_FILES
//--------------------------------------------------------------------------------------------------

/// The set of log files microsandbox produces. Add a new file
/// type by adding an entry here — the [`LogEngine`] opens a
/// reader for any entry whose `produces` list intersects the
/// caller's requested sources.
const LOG_FILES: &[LogFileConfig] = &[
    LogFileConfig {
        filename: "exec.log",
        format: LogFileFormat::Jsonl,
        max_rotation_index: 4,
        produces: &[
            LogSource::Stdout,
            LogSource::Stderr,
            LogSource::Output,
            LogSource::System,
        ],
    },
    LogFileConfig {
        filename: "runtime.log",
        format: LogFileFormat::Text,
        max_rotation_index: 0,
        produces: &[LogSource::System],
    },
    LogFileConfig {
        filename: "kernel.log",
        format: LogFileFormat::Text,
        max_rotation_index: 0,
        produces: &[LogSource::System],
    },
];

//--------------------------------------------------------------------------------------------------
// Public API
//--------------------------------------------------------------------------------------------------

/// Chronologically sorted log snapshot plus the cursor at the end
/// of the drained on-disk content.
#[derive(Debug, Clone)]
pub struct LogSnapshot {
    /// Entries matching the requested [`LogOptions`].
    pub entries: Vec<LogEntry>,

    /// Cursor positioned after all content consumed for the
    /// snapshot, including entries later removed by `tail` /
    /// `until` filtering.
    pub cursor: LogCursor,
}

/// Compute the on-disk log directory for a sandbox name.
pub fn log_dir_for(name: &str) -> PathBuf {
    crate::config::config()
        .sandboxes_dir()
        .join(name)
        .join("logs")
}

/// Read all matching log entries for the named sandbox.
///
/// Returns entries sorted by timestamp (strict chronological order
/// across all sources). Returns
/// [`MicrosandboxError::SandboxNotFound`] if the sandbox's log
/// directory doesn't exist.
///
/// Implemented as a drain of [`log_stream`] with `follow: false`,
/// sorted post-collect; `until` and `tail` are applied
/// post-collect because the stream's per-source ordering doesn't
/// match snapshot's "filter after sort" contract.
pub async fn read_logs(name: &str, opts: &LogOptions) -> MicrosandboxResult<Vec<LogEntry>> {
    Ok(read_logs_snapshot(name, opts).await?.entries)
}

/// Read all matching log entries and return the snapshot end cursor.
///
/// This is useful when handing a bounded historical read to
/// [`log_stream`] with [`LogStreamStart::From`] without losing log
/// lines written between the snapshot drain and follow startup.
pub async fn read_logs_snapshot(name: &str, opts: &LogOptions) -> MicrosandboxResult<LogSnapshot> {
    let stream_opts = LogStreamOptions {
        sources: opts.sources.clone(),
        // Push `since` into the parser when possible so early
        // entries are discarded at parse time rather than after.
        start: opts.since.map(LogStreamStart::Since).unwrap_or_default(),
        until: None,
        follow: false,
    };
    let log_dir = log_dir_for(name);
    if !tokio::fs::try_exists(&log_dir).await.unwrap_or(false) {
        return Err(MicrosandboxError::SandboxNotFound(name.to_string()));
    }
    let sources = LogSource::effective(&stream_opts.sources);
    let engine = LogEngine::new(
        log_dir,
        LOG_FILES,
        sources,
        &stream_opts.start,
        stream_opts.until,
        stream_opts.follow,
    )
    .await?;
    let (mut entries, cursor) = engine.drain_sorted_snapshot().await?;
    opts.apply_to(&mut entries);
    Ok(LogSnapshot { entries, cursor })
}

/// Stream log entries for the named sandbox.
///
/// Returns [`MicrosandboxError::SandboxNotFound`] if the sandbox's
/// log directory doesn't exist. Within each source, entries are
/// chronological; across sources, ordering is "as parsed."
pub async fn log_stream(
    name: &str,
    opts: &LogStreamOptions,
) -> MicrosandboxResult<impl Stream<Item = MicrosandboxResult<LogEntry>> + Send + 'static + use<>> {
    let log_dir = log_dir_for(name);
    if !tokio::fs::try_exists(&log_dir).await.unwrap_or(false) {
        return Err(MicrosandboxError::SandboxNotFound(name.to_string()));
    }
    let sources = LogSource::effective(&opts.sources);
    let engine = LogEngine::new(
        log_dir,
        LOG_FILES,
        sources,
        &opts.start,
        opts.until,
        opts.follow,
    )
    .await?;
    Ok(engine.into_stream())
}
