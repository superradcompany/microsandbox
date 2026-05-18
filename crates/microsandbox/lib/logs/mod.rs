//! Rotation-aware multi-file log streaming.
//!
//! Two public entry points keyed by sandbox name:
//!
//! - [`read_logs`] returns a snapshot `Vec<LogEntry>` filtered with
//!   [`LogOptions`]. Reads everything currently on disk, sorts by
//!   timestamp, and returns. Implemented as a thin drain of
//!   [`log_stream`] with `follow: false`.
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

use futures::{Stream, TryStreamExt};

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
    let stream_opts = LogStreamOptions {
        sources: opts.sources.clone(),
        // Push `since` into the parser when possible so early
        // entries are discarded at parse time rather than after.
        start: opts.since.map(LogStreamStart::Since).unwrap_or_default(),
        until: None,
        follow: false,
    };
    let mut entries: Vec<LogEntry> = log_stream(name, &stream_opts).await?.try_collect().await?;
    entries.sort_by_key(|e| e.timestamp);
    opts.apply_to(&mut entries);
    Ok(entries)
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
