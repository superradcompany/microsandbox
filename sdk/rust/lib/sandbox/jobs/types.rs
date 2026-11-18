//! Additive value types for managed execution; existing exec types remain unchanged.

use std::pin::Pin;

use bytes::Bytes;
use futures::Stream;
use serde::{Deserialize, Serialize};

use super::{JobId, JobInfo};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Result of a managed-job operation.
pub type JobResult<T> = Result<T, JobError>;
/// Bounded, fallible stream of captured job output.
pub type JobLogStream = Pin<Box<dyn Stream<Item = JobResult<JobLogEntry>> + Send>>;

/// Errors specific to new job operations without extending a released public error enum.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JobError {
    /// An existing sandbox/transport operation failed.
    #[error(transparent)]
    Sandbox(#[from] crate::MicrosandboxError),
    /// Persistent history could not be read or written.
    #[error("job history: {0}")]
    Io(#[from] std::io::Error),
    /// Structured refusal with a stable code across language bindings.
    #[error("{code}: {message}")]
    Operation {
        /// Machine-readable error code.
        code: String,
        /// Human-readable diagnostic.
        message: String,
    },
    /// Spawn admission may have succeeded; preserve the ID so callers can inspect it.
    #[error("launch result for {id} is unknown: {message}; inspect this job before retrying")]
    LaunchUnconfirmed {
        /// Identity of the possibly admitted command.
        id: JobId,
        /// Transport or acknowledgement diagnostic.
        message: String,
    },
}

/// A confirmed process result, independent of attachment and output consumption.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct JobExit {
    /// Guest-reported exit code.
    pub code: i32,
    /// Whether the code is zero.
    pub success: bool,
    /// Whether the runtime requested deadline termination.
    pub timed_out: bool,
}

/// Original output bytes and an opaque job-scoped replay cursor.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct JobLogEntry {
    /// Capture time in Unix milliseconds.
    pub timestamp: i64,
    /// stdout, stderr, output (PTY), or stdin_error.
    pub source: String,
    /// Original output bytes, never lossy-decoded by the SDK.
    #[serde(rename = "data_base64", with = "super::encoding")]
    pub data: Bytes,
    /// Resume strictly after this record using the same job.
    pub cursor: String,
}

/// History selection. Defaults include stdout, stderr and merged PTY output.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct JobLogOptions {
    /// Last N records after other filters are applied.
    pub tail: Option<usize>,
    /// Inclusive lower timestamp in Unix milliseconds.
    pub since: Option<i64>,
    /// Exclusive upper timestamp in Unix milliseconds.
    pub until: Option<i64>,
    /// Source names; empty selects program output.
    pub sources: Vec<String>,
    /// Resume after this opaque job-scoped cursor.
    pub from_cursor: Option<String>,
    /// Continue observing after the retained snapshot.
    pub follow: bool,
}

/// Bounded history requested when attaching.
#[derive(Clone, Debug, Default)]
pub enum JobReplay {
    /// Only output captured after attachment admission.
    #[default]
    None,
    /// Replay the most recent bytes, up to the runtime's retained bound.
    Recent {
        /// Maximum decoded bytes to replay.
        max_bytes: usize,
    },
    /// Resume after a cursor from this same job.
    After(String),
}

/// Configure one temporary attachment.
#[derive(Clone, Debug, Default)]
pub struct JobAttachOptionsBuilder {
    pub(super) read_only: bool,
    pub(super) replay: JobReplay,
}

/// Configure one bounded job-list page.
#[derive(Clone, Debug)]
pub struct JobListBuilder {
    pub(super) all: bool,
    pub(super) limit: usize,
    pub(super) cursor: Option<JobId>,
}

/// Attachment observations; terminal state is independent of retained output.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
#[non_exhaustive]
pub enum JobEvent {
    /// Original stdout, stderr, PTY, or input-error bytes.
    Output(JobLogEntry),
    /// Requested history has been pruned; resume from this available cursor.
    Gap {
        /// Last pruned position; subsequent output resumes after this cursor.
        cursor: String,
    },
    /// Final state once all retained output has been delivered.
    Completed(JobInfo),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl JobError {
    pub(super) fn operation(code: &str, message: impl Into<String>) -> Self {
        Self::Operation {
            code: code.into(),
            message: message.into(),
        }
    }

    /// Stable code used by language bindings and automation.
    pub fn code(&self) -> &str {
        match self {
            Self::Operation { code, .. } => code,
            Self::LaunchUnconfirmed { .. } => "launch_unconfirmed",
            Self::Io(_) => "history_error",
            Self::Sandbox(_) => "sandbox_error",
        }
    }
}

impl JobAttachOptionsBuilder {
    /// Observe without acquiring input ownership.
    pub fn read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }
    /// Choose bounded replay before live output.
    pub fn replay(mut self, replay: JobReplay) -> Self {
        self.replay = replay;
        self
    }
}

impl JobListBuilder {
    /// Include retained terminal records.
    pub fn all(mut self, all: bool) -> Self {
        self.all = all;
        self
    }
    /// Set a page size between one and one hundred.
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }
    /// Continue after a previous page's cursor.
    pub fn cursor(mut self, cursor: JobId) -> Self {
        self.cursor = Some(cursor);
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for JobListBuilder {
    fn default() -> Self {
        Self {
            all: false,
            limit: 50,
            cursor: None,
        }
    }
}
