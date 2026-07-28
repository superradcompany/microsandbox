//! Sandbox-scoped log handles.
//!
//! A [`SandboxLogger`] is a plain, cheap handle to one sandbox's on-disk
//! log directory, obtained from
//! [`Sandbox::logger`](crate::sandbox::Sandbox::logger). Used directly,
//! it behaves exactly like [`Sandbox::log_stream`] /
//! [`Sandbox::logs`] — each followed stream owns a private watcher.
//!
//! Registering it with a
//! [`LogRegistry`](super::watch::LogRegistry) yields a
//! [`RegisteredSandboxLogger`], whose followed streams share the
//! registry's single watcher instead. Everything else — parsing,
//! cursors, ordering, rotation, the fallback poll — is identical; the
//! registry only changes where the "files may have new bytes" wake
//! comes from.

use std::path::{Path, PathBuf};

use super::watch::LogRegistration;
use super::{LogEntry, LogOptions, LogSnapshot, LogStreamOptions};
use crate::MicrosandboxResult;
use crate::backend::sandbox::LogStream;

//--------------------------------------------------------------------------------------------------
// SandboxLogger
//--------------------------------------------------------------------------------------------------

/// A handle to one sandbox's log directory. Reads and streams delegate
/// to the same engine as the backend log methods; followed streams use
/// a private watcher until the logger is registered with a
/// [`LogRegistry`](super::watch::LogRegistry).
pub struct SandboxLogger {
    name: String,
    log_dir: PathBuf,
}

impl SandboxLogger {
    /// Construct a logger for a named sandbox rooted at `log_dir`.
    pub(crate) fn new(name: String, log_dir: PathBuf) -> Self {
        Self { name, log_dir }
    }

    /// The sandbox name this logger reads.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The on-disk log directory this logger reads.
    pub fn log_dir(&self) -> &Path {
        &self.log_dir
    }

    /// Read a chronologically sorted log snapshot's entries.
    pub async fn read(&self, opts: &LogOptions) -> MicrosandboxResult<Vec<LogEntry>> {
        Ok(self.read_snapshot(opts).await?.entries)
    }

    /// Read a chronologically sorted log snapshot plus its end cursor.
    pub async fn read_snapshot(&self, opts: &LogOptions) -> MicrosandboxResult<LogSnapshot> {
        super::read_logs_snapshot_from_dir(&self.name, self.log_dir.clone(), opts).await
    }

    /// Stream log entries. When `opts.follow` is set, each stream owns a
    /// private filesystem watcher (the standalone behavior).
    pub async fn stream(&self, opts: &LogStreamOptions) -> MicrosandboxResult<LogStream> {
        let stream = super::log_stream_from_dir(&self.name, self.log_dir.clone(), opts).await?;
        Ok(Box::pin(stream) as LogStream)
    }
}

//--------------------------------------------------------------------------------------------------
// RegisteredSandboxLogger
//--------------------------------------------------------------------------------------------------

/// A [`SandboxLogger`] registered with a
/// [`LogRegistry`](super::watch::LogRegistry). Followed
/// streams share the registry's single watcher; the held
/// [`LogRegistration`] keeps the directory watched, and each stream
/// carries its own registration clone so it stays watched even if this
/// logger is dropped first.
pub struct RegisteredSandboxLogger {
    logger: SandboxLogger,
    registration: LogRegistration,
}

impl RegisteredSandboxLogger {
    pub(crate) fn new(logger: SandboxLogger, registration: LogRegistration) -> Self {
        Self {
            logger,
            registration,
        }
    }

    /// The sandbox name this logger reads.
    pub fn name(&self) -> &str {
        self.logger.name()
    }

    /// The on-disk log directory this logger reads.
    pub fn log_dir(&self) -> &Path {
        self.logger.log_dir()
    }

    /// Read a chronologically sorted log snapshot's entries.
    pub async fn read(&self, opts: &LogOptions) -> MicrosandboxResult<Vec<LogEntry>> {
        self.logger.read(opts).await
    }

    /// Read a chronologically sorted log snapshot plus its end cursor.
    pub async fn read_snapshot(&self, opts: &LogOptions) -> MicrosandboxResult<LogSnapshot> {
        self.logger.read_snapshot(opts).await
    }

    /// Stream log entries. A followed stream subscribes to the registry's
    /// shared watch for this directory — no private watcher — and holds a
    /// registration clone for its lifetime. A non-follow stream needs no
    /// wake source and takes the plain path.
    pub async fn stream(&self, opts: &LogStreamOptions) -> MicrosandboxResult<LogStream> {
        if !opts.follow {
            return self.logger.stream(opts).await;
        }
        let subscription = self.registration.subscribe();
        let stream = super::log_stream_from_dir_registry(
            &self.logger.name,
            self.logger.log_dir.clone(),
            opts,
            subscription,
        )
        .await?;
        Ok(Box::pin(stream) as LogStream)
    }
}
