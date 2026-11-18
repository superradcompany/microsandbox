//! Rotation-aware multi-file log streaming.
//!
//! The public entry points are keyed by sandbox name:
//!
//! - [`boot_error`] returns the latest backend-provided startup diagnostic.
//! - [`read_logs`] routes a bounded snapshot through the selected backend.
//! - [`follow_logs`] routes filtered history plus live output through the
//!   selected backend.
//! - [`log_stream`] returns a [`futures::Stream`] over the same
//!   local files, suitable for live-tailing or replaying a fixed range.
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
#[cfg(feature = "local")]
mod logger;
mod parser;
mod stream;
mod types;
mod watch;

pub use cursor::{LogCursor, LogCursorParseError};
#[cfg(feature = "local")]
pub use logger::{RegisteredSandboxLogger, SandboxLogger};
pub use microsandbox_protocol::core::InitFailureReason;
#[cfg(feature = "local")]
pub use microsandbox_runtime::boot_error::{BootError, BootErrorStage};
pub use stream::{LogStreamOptions, LogStreamStart};
#[cfg(not(feature = "local"))]
pub use types::{BootError, BootErrorStage};
pub use types::{LogEntry, LogOptions, LogSource};
pub use watch::{LogRegistration, LogRegistry, RegistryStatsSnapshot};

#[cfg(feature = "local")]
use std::path::PathBuf;

#[cfg(feature = "local")]
use futures::Stream;

#[cfg(feature = "local")]
use stream::{LogEngine, LogFileConfig, LogFileFormat};

#[cfg(feature = "local")]
use crate::MicrosandboxError;
use crate::MicrosandboxResult;
#[cfg(feature = "local")]
use crate::backend::LocalBackend;
use crate::backend::sandbox::LogStream;

//--------------------------------------------------------------------------------------------------
// LOG_FILES
//--------------------------------------------------------------------------------------------------

/// The set of log files microsandbox produces. Add a new file
/// type by adding an entry here — the [`LogEngine`] opens a
/// reader for any entry whose `produces` list intersects the
/// caller's requested sources.
#[cfg(feature = "local")]
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
#[cfg(feature = "local")]
pub fn log_dir_for(name: &str) -> PathBuf {
    default_logger(name).log_dir
}

/// Compute the on-disk log directory for an explicit local backend.
#[cfg(feature = "local")]
pub(crate) fn log_dir_for_local(local: &LocalBackend, name: &str) -> PathBuf {
    local.config().sandboxes_dir().join(name).join("logs")
}

/// Read all matching log entries for the named sandbox.
///
/// Sandbox names are limited to 128 UTF-8 bytes.
///
/// Routes through the selected backend. Local entries are sorted by timestamp
/// (strict chronological order across all sources) and return
/// [`MicrosandboxError::SandboxNotFound`] if the sandbox's log directory does
/// not exist. Backends without bounded log snapshots return a typed
/// [`MicrosandboxError::Unsupported`] error.
///
/// The local implementation drains [`log_stream`] with `follow: false` and
/// sorts post-collect; `until` and `tail` are applied post-collect because the
/// stream's per-source ordering doesn't match snapshot's "filter after sort"
/// contract.
pub async fn read_logs(name: &str, opts: &LogOptions) -> MicrosandboxResult<Vec<LogEntry>> {
    let backend = crate::backend::default_backend();
    backend.sandboxes().logs(backend.clone(), name, opts).await
}

/// Replay filtered history, then follow new entries through the selected backend.
///
/// The backend owns any snapshot-to-stream cursor handoff. Backends that cannot
/// satisfy a requested filter return a typed [`MicrosandboxError::Unsupported`]
/// error.
pub async fn follow_logs(name: &str, opts: &LogOptions) -> MicrosandboxResult<LogStream> {
    let backend = crate::backend::default_backend();
    backend
        .sandboxes()
        .follow_logs(backend.clone(), name, opts)
        .await
}

/// Return the most recent startup diagnostic for the named sandbox, when any.
///
/// Local sandboxes read the same persisted record used to produce
/// [`MicrosandboxError::BootStart`] during create/start. The cloud backend
/// currently returns `None` because its API has no boot-error concept yet.
pub async fn boot_error(name: &str) -> MicrosandboxResult<Option<BootError>> {
    let backend = crate::backend::default_backend();
    backend.sandboxes().boot_error(backend.clone(), name).await
}

/// Read all matching log entries through an explicit local backend.
#[cfg(feature = "local")]
pub(crate) async fn read_logs_local(
    local: &LocalBackend,
    name: &str,
    opts: &LogOptions,
) -> MicrosandboxResult<Vec<LogEntry>> {
    Ok(read_logs_snapshot_local(local, name, opts).await?.entries)
}

/// Read a filtered snapshot and cursor through an explicit local backend.
#[cfg(feature = "local")]
pub(crate) async fn read_logs_snapshot_local(
    local: &LocalBackend,
    name: &str,
    opts: &LogOptions,
) -> MicrosandboxResult<LogSnapshot> {
    SandboxLogger::for_local(local, name)
        .read_snapshot(opts)
        .await
}

/// Read all matching local log entries and return the snapshot end cursor.
///
/// This is useful when handing a bounded historical read to
/// [`log_stream`] with [`LogStreamStart::From`] without losing log
/// lines written between the snapshot drain and follow startup.
#[cfg(feature = "local")]
pub async fn read_logs_snapshot(name: &str, opts: &LogOptions) -> MicrosandboxResult<LogSnapshot> {
    default_logger(name).read_snapshot(opts).await
}

#[cfg(feature = "local")]
async fn read_logs_snapshot_from_dir(
    name: &str,
    log_dir: PathBuf,
    opts: &LogOptions,
    strict_host_files: bool,
) -> MicrosandboxResult<LogSnapshot> {
    crate::sandbox::validate_sandbox_name(name)?;
    let stream_opts = LogStreamOptions {
        sources: opts.sources.clone(),
        // Push `since` into the parser when possible so early
        // entries are discarded at parse time rather than after.
        start: opts.since.map(LogStreamStart::Since).unwrap_or_default(),
        until: None,
        follow: false,
    };
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
        strict_host_files,
    )
    .await?;
    let (mut entries, cursor) = engine.drain_sorted_snapshot().await?;
    opts.apply_to(&mut entries);
    Ok(LogSnapshot { entries, cursor })
}

/// Stream log entries for the named sandbox.
///
/// Sandbox names are limited to 128 UTF-8 bytes.
///
/// Returns [`MicrosandboxError::SandboxNotFound`] if the sandbox's
/// log directory doesn't exist. Within each source, entries are
/// chronological; across sources, ordering is "as parsed."
#[cfg(feature = "local")]
pub async fn log_stream(
    name: &str,
    opts: &LogStreamOptions,
) -> MicrosandboxResult<impl Stream<Item = MicrosandboxResult<LogEntry>> + Send + 'static + use<>> {
    let logger = default_logger(name);
    log_stream_from_dir(name, logger.log_dir, opts, logger.strict_host_files).await
}

/// Stream log entries through an explicit local backend.
#[cfg(feature = "local")]
pub(crate) async fn log_stream_local(
    local: &LocalBackend,
    name: &str,
    opts: &LogStreamOptions,
) -> MicrosandboxResult<impl Stream<Item = MicrosandboxResult<LogEntry>> + Send + 'static + use<>> {
    let logger = SandboxLogger::for_local(local, name);
    log_stream_from_dir(name, logger.log_dir, opts, logger.strict_host_files).await
}

#[cfg(feature = "local")]
async fn log_stream_from_dir(
    name: &str,
    log_dir: PathBuf,
    opts: &LogStreamOptions,
    strict_host_files: bool,
) -> MicrosandboxResult<impl Stream<Item = MicrosandboxResult<LogEntry>> + Send + 'static + use<>> {
    crate::sandbox::validate_sandbox_name(name)?;
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
        strict_host_files,
    )
    .await?;
    Ok(engine.into_stream())
}

/// Stream from an explicit directory, waking from a shared
/// [`LogRegistry`](watch::LogRegistry) subscription rather than
/// a private watcher. Always follows — a non-follow read has no wake
/// source and takes [`log_stream_from_dir`] / the snapshot path.
#[cfg(feature = "local")]
pub(crate) async fn log_stream_from_dir_registry(
    name: &str,
    log_dir: PathBuf,
    opts: &LogStreamOptions,
    subscription: watch::LogSubscription,
    strict_host_files: bool,
) -> MicrosandboxResult<impl Stream<Item = MicrosandboxResult<LogEntry>> + Send + 'static + use<>> {
    crate::sandbox::validate_sandbox_name(name)?;
    if !tokio::fs::try_exists(&log_dir).await.unwrap_or(false) {
        return Err(MicrosandboxError::SandboxNotFound(name.to_string()));
    }
    let sources = LogSource::effective(&opts.sources);
    let engine = LogEngine::new_registry(
        log_dir,
        LOG_FILES,
        sources,
        &opts.start,
        opts.until,
        subscription,
        strict_host_files,
    )
    .await?;
    Ok(engine.into_stream())
}

/// Take the log directory and host file policy from one retained default backend.
#[cfg(feature = "local")]
fn default_logger(name: &str) -> SandboxLogger {
    let backend = crate::backend::default_backend();
    if let Some(local) = backend.as_local() {
        return SandboxLogger::for_local(local, name);
    }
    SandboxLogger::new(
        name.to_string(),
        microsandbox_utils::resolve_home()
            .join(microsandbox_utils::SANDBOXES_SUBDIR)
            .join(name)
            .join("logs"),
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix, feature = "local"))]
mod tests {
    use futures::TryStreamExt;

    use super::*;
    use crate::config::{GlobalConfig, RuntimeConfig};

    async fn read_through_local_backend(strict: bool) -> Vec<MicrosandboxResult<usize>> {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap();
        let real = home.join("real-logs");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(
            real.join("exec.log"),
            "{\"t\":\"2026-04-30T20:32:59.000Z\",\"s\":\"stdout\",\"d\":\"hi\\n\",\"id\":7}\n",
        )
        .unwrap();
        let sandbox = home.join(microsandbox_utils::SANDBOXES_SUBDIR).join("sbx");
        std::fs::create_dir_all(&sandbox).unwrap();
        std::os::unix::fs::symlink(&real, sandbox.join("logs")).unwrap();
        let local = crate::test_support::local_backend(GlobalConfig {
            home: Some(home),
            runtime: RuntimeConfig {
                strict_host_files: strict,
                ..Default::default()
            },
            ..Default::default()
        });

        let opts = LogOptions::default();
        let logger = SandboxLogger::for_local(&local, "sbx");
        let streamed = match log_stream_local(&local, "sbx", &LogStreamOptions::default()).await {
            Ok(stream) => stream.try_collect::<Vec<_>>().await.map(|e| e.len()),
            Err(error) => Err(error),
        };
        vec![
            read_logs_local(&local, "sbx", &opts).await.map(|e| e.len()),
            streamed,
            logger.read_snapshot(&opts).await.map(|s| s.entries.len()),
        ]
    }

    #[tokio::test]
    async fn local_backend_log_readers_apply_its_strict_host_file_policy() {
        for result in read_through_local_backend(false).await {
            assert_eq!(result.unwrap(), 1);
        }

        for result in read_through_local_backend(true).await {
            let message = result.unwrap_err().to_string();
            assert!(message.contains("runtime.strict_host_files"), "{message}");
            assert!(message.contains("\"logs\""), "{message}");
        }
    }
}
