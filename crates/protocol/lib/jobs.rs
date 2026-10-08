//! Additive host-control contract for runtime-owned command jobs.
//!
//! This extension deliberately does not change guest exec messages or the released control enums.
//! Clients first request `Hello`, then fence every operation with the returned runtime identity.

use serde::{Deserialize, Serialize};

use crate::exec::{ExecFailed, ExecRequest};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// First version of the managed-job contract and persisted metadata.
pub const JOB_PROTOCOL_VERSION: u32 = 1;
/// Capability-probed host-control extension name.
pub const JOB_REQUEST: &str = "control.jobs";
/// Terminal response to one bounded job operation.
pub const JOB_RESPONSE: &str = "control.jobs.result";
/// Maximum bytes accepted in one input write or returned in one output chunk.
pub const JOB_CHUNK_BYTES: usize = 16 * 1024;
/// Maximum simultaneously active jobs in one sandbox.
pub const MAX_ACTIVE_JOBS: usize = 32;
/// Maximum retained job records, including active jobs.
pub const MAX_RETAINED_JOBS: usize = 256;
/// Maximum encoded metadata in a listing page, independently of its item limit.
pub const JOB_LIST_BYTES: usize = 256 * 1024;
/// Reserved reply capacity for one job operation, including metadata and output chunks.
pub const JOB_REPLY_BYTES: u32 = 512 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An opaque job identity, distinct from guest PIDs and connection-local exec IDs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct JobId(String);

/// Persisted lifecycle observation. A lost runtime never implies a successful exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JobState {
    /// Admission is durable; guest spawn has not yet been confirmed.
    Starting,
    /// Guest spawn was confirmed. Sandbox pause is orthogonal to this state.
    Running,
    /// The guest reported process completion.
    Exited,
    /// The guest rejected the command before it started.
    Failed,
    /// Ownership or transport was lost without a confirmed exit result.
    Lost,
}

/// Durable job metadata. Environment values and stdin bytes are never included.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct JobInfo {
    /// Metadata format version.
    pub version: u32,
    /// Stable identity within the owning sandbox.
    pub id: JobId,
    /// Runtime generation that created this job.
    pub runtime_boot_id: String,
    /// Program followed by its arguments.
    pub command: Vec<String>,
    /// Most recent lifecycle observation.
    pub state: JobState,
    /// Whether output is a merged PTY stream.
    pub tty: bool,
    /// Whether further input has been permanently disabled.
    pub stdin_closed: bool,
    /// Guest PID, if spawn was acknowledged.
    pub pid: Option<u32>,
    /// Admission time in Unix milliseconds.
    pub created_at: i64,
    /// Confirmed spawn time in Unix milliseconds.
    pub started_at: Option<i64>,
    /// Completion or loss observation time in Unix milliseconds.
    pub finished_at: Option<i64>,
    /// Confirmed guest exit code, never synthesized on transport loss.
    pub exit_code: Option<i32>,
    /// Structured spawn failure, when supplied by the guest.
    pub failure: Option<ExecFailed>,
    /// Diagnostic for unconfirmed completion or host I/O failure.
    pub error: Option<String>,
    /// Whether the runtime requested termination after the execution deadline.
    pub timed_out: bool,
}

/// Byte-preserving output record. Sequence numbers remain monotonic across log rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct JobOutput {
    /// Monotonic sequence number, starting at one.
    pub sequence: u64,
    /// Unix milliseconds at capture.
    pub timestamp: i64,
    /// `stdout`, `stderr`, `output` (PTY), or `stdin_error`.
    pub source: String,
    /// Original bytes, encoded explicitly for portable persisted JSON.
    pub data_base64: String,
}

/// One bounded list page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobPage {
    /// Job summaries in stable identity order.
    pub items: Vec<JobInfo>,
    /// Last identity in this page when more records remain.
    pub next_cursor: Option<JobId>,
}

/// One bounded replay result; missing retained output is reported explicitly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobOutputPage {
    /// Captured records after the requested cursor.
    pub items: Vec<JobOutput>,
    /// Cursor after the returned records, or the requested cursor when empty.
    pub cursor: u64,
    /// Earliest available sequence when requested records were pruned.
    pub gap_before: Option<u64>,
    /// Latest metadata, including terminal state after output has been captured.
    pub info: JobInfo,
}

/// One capability-probed, runtime-fenced request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRequest {
    /// Expected extension version.
    pub version: u32,
    /// Required for every operation except Hello.
    pub runtime_boot_id: Option<String>,
    /// Requested bounded operation.
    pub operation: JobOperation,
}

/// Host-only operations. None waits for a process to exit or for output to become available.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum JobOperation {
    /// Discover support without creating a process.
    Hello,
    /// Admit a launch exactly once for this ID and command fingerprint.
    Start {
        /// Client-generated random identity and idempotency key.
        id: JobId,
        /// Existing guest command contract.
        command: ExecRequest,
        /// Close guest stdin immediately after confirmed spawn.
        no_stdin: bool,
        /// Optional finite pipe input (at most 64 KiB), followed by EOF.
        input_base64: Option<String>,
        /// Host-enforced elapsed execution limit in milliseconds.
        timeout_ms: Option<u64>,
    },
    /// List active or all retained jobs.
    List {
        /// Include terminal records.
        all: bool,
        /// Maximum page size (1..=100).
        limit: usize,
        /// Continue after this identity.
        cursor: Option<JobId>,
    },
    /// Inspect one retained job.
    Inspect {
        /// Owning job identity.
        id: JobId,
    },
    /// Read bounded output, optionally renewing an attachment lease.
    Read {
        /// Owning job identity.
        id: JobId,
        /// Resume strictly after this output sequence.
        after: u64,
        /// Opaque attachment lease token.
        attachment: Option<String>,
    },
    /// Acquire one attachment. Reusing the same token is idempotent.
    Attach {
        /// Owning job identity.
        id: JobId,
        /// Opaque attachment lease token.
        attachment: String,
        /// Observe without acquiring input ownership.
        read_only: bool,
    },
    /// Release an attachment without EOF or process termination.
    Detach {
        /// Owning job identity.
        id: JobId,
        /// Lease to release.
        attachment: String,
    },
    /// Keep an attachment alive without consuming output.
    Renew {
        /// Owning job identity.
        id: JobId,
        /// Lease to renew.
        attachment: String,
    },
    /// Queue input for the current input-owning attachment.
    Write {
        /// Owning job identity.
        id: JobId,
        /// Opaque attachment lease token.
        attachment: String,
        /// Original input bytes encoded as base64.
        data_base64: String,
    },
    /// Resize the terminal for the input-owning attachment.
    Resize {
        /// Owning job identity.
        id: JobId,
        /// Opaque attachment lease token.
        attachment: String,
        /// Nonzero terminal row count.
        rows: u16,
        /// Nonzero terminal column count.
        cols: u16,
    },
    /// Send a Linux guest process-group signal.
    Signal {
        /// Owning job identity.
        id: JobId,
        /// Linux guest signal number.
        signal: i32,
    },
    /// Close a pipe after already admitted input; invalid for PTYs.
    Eof {
        /// Owning job identity.
        id: JobId,
    },
}

/// Result of one operation. Errors retain machine-readable codes across SDKs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
#[non_exhaustive]
pub enum JobResponse {
    /// Successful capability discovery.
    Hello {
        /// Selected managed-job protocol version.
        version: u32,
        /// Immutable identity of the selected runtime.
        runtime_boot_id: String,
    },
    /// Admission or inspection result.
    Info {
        /// Current job metadata.
        info: JobInfo,
    },
    /// List page.
    Page {
        /// Bounded list result.
        page: JobPage,
    },
    /// Output page.
    Output {
        /// Bounded output result.
        page: JobOutputPage,
    },
    /// Attachment metadata and current replay cursor.
    Attached {
        /// Current job metadata.
        info: JobInfo,
        /// Latest captured sequence at admission.
        cursor: u64,
    },
    /// Control operation was admitted.
    Ok,
    /// Explicit refusal or failure; never a fabricated process exit.
    Error {
        /// Stable machine-readable code.
        code: String,
        /// Human-readable diagnostic.
        message: String,
    },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl JobId {
    /// Validate the portable opaque ID, including before it becomes a path component.
    pub fn parse(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.len() != 36
            || !value.starts_with("job_")
            || !value[4..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("job ID must be job_ followed by 32 lowercase hexadecimal digits".into());
        }
        Ok(Self(value))
    }

    /// Return the stable string representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl JobState {
    /// Whether the runtime may still own a live process for this record.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Starting | Self::Running)
    }
}

impl JobInfo {
    /// Construct a pending admission without persisting the command's environment or input.
    pub fn starting(
        id: JobId,
        runtime_boot_id: String,
        command: &ExecRequest,
        no_stdin: bool,
        created_at: i64,
    ) -> Self {
        Self {
            version: JOB_PROTOCOL_VERSION,
            id,
            runtime_boot_id,
            command: std::iter::once(command.cmd.clone())
                .chain(command.args.clone())
                .collect(),
            state: JobState::Starting,
            tty: command.tty,
            stdin_closed: no_stdin,
            pid: None,
            created_at,
            started_at: None,
            finished_at: None,
            exit_code: None,
            failure: None,
            error: None,
            timed_out: false,
        }
    }
}

impl JobOutput {
    /// Construct one captured output record.
    pub fn new(sequence: u64, timestamp: i64, source: String, data_base64: String) -> Self {
        Self {
            sequence,
            timestamp,
            source,
            data_base64,
        }
    }
}

impl JobResponse {
    /// Construct a structured failure without exposing request contents.
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Error {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl JobPage {
    /// Page sorted, filtered records by both count and encoded size.
    pub fn bounded(
        records: impl IntoIterator<Item = JobInfo>,
        limit: usize,
    ) -> Result<Self, String> {
        let mut items: Vec<JobInfo> = Vec::new();
        let mut bytes = 0;
        let mut encoded = Vec::new();
        for info in records {
            encoded.clear();
            ciborium::ser::into_writer(&info, &mut encoded).map_err(|error| error.to_string())?;
            let size = encoded.len();
            if limit == 0 || size > JOB_LIST_BYTES {
                return Err("invalid page limit or oversized job metadata".into());
            }
            if !items.is_empty() && (items.len() >= limit || bytes + size > JOB_LIST_BYTES) {
                return Ok(Self {
                    next_cursor: items.last().map(|info| info.id.clone()),
                    items,
                });
            }
            bytes += size;
            items.push(info);
        }
        Ok(Self {
            items,
            next_cursor: None,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl TryFrom<String> for JobId {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}
impl From<JobId> for String {
    fn from(value: JobId) -> Self {
        value.0
    }
}
impl AsRef<str> for JobId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl std::fmt::Display for JobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_ids_cannot_escape_their_storage_directory() {
        for invalid in [
            "../outside",
            "job_../../../../../../../../../../..",
            "job_ABCDEF",
            "job_0000000000000000000000000000000/",
        ] {
            assert!(JobId::parse(invalid).is_err());
            assert!(serde_json::from_value::<JobId>(serde_json::json!(invalid)).is_err());
        }
        assert!(JobId::parse("job_0123456789abcdef0123456789abcdef").is_ok());
    }

    #[test]
    fn job_pages_are_bounded_by_encoded_bytes_as_well_as_count() {
        let command: ExecRequest =
            serde_json::from_value(serde_json::json!({"cmd": "x".repeat(16 * 1024)})).unwrap();
        let records = (0..100).map(|n| {
            JobInfo::starting(
                JobId::parse(format!("job_{n:032x}")).unwrap(),
                "boot".into(),
                &command,
                false,
                0,
            )
        });
        let page = JobPage::bounded(records, 100).unwrap();
        assert!(page.items.len() < 100);
        assert_eq!(
            page.next_cursor.as_ref(),
            page.items.last().map(|info| &info.id)
        );
        assert!(serde_json::to_vec(&page).unwrap().len() < JOB_REPLY_BYTES as usize);
    }
}
