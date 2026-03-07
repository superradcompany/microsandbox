//! Filesystem-related protocol message payloads.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum chunk size for streaming file data (3 MiB).
///
/// This stays safely under the 4 MiB frame limit after CBOR envelope overhead.
pub const FS_CHUNK_SIZE: usize = 3 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A filesystem operation requested by the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FsOp {
    /// Get metadata for a path.
    Stat {
        /// Guest path to stat.
        path: String,
    },

    /// List directory contents.
    List {
        /// Guest directory path to list.
        path: String,
    },

    /// Read a file (streaming: guest replies with FsData chunks then FsResponse).
    Read {
        /// Guest file path to read.
        path: String,
    },

    /// Write a file (streaming: host sends FsData chunks, guest replies with FsResponse).
    Write {
        /// Guest file path to write.
        path: String,
        /// Permission bits to set on creation (e.g. 0o644).
        #[serde(default)]
        mode: Option<u32>,
    },

    /// Create a directory (and parents).
    Mkdir {
        /// Guest directory path to create.
        path: String,
    },

    /// Remove a file.
    Remove {
        /// Guest file path to remove.
        path: String,
    },

    /// Remove a directory recursively.
    RemoveDir {
        /// Guest directory path to remove.
        path: String,
    },

    /// Copy a file or directory within the guest.
    Copy {
        /// Source path in guest.
        src: String,
        /// Destination path in guest.
        dst: String,
    },

    /// Rename/move a file or directory.
    Rename {
        /// Source path in guest.
        src: String,
        /// Destination path in guest.
        dst: String,
    },
}

/// Request to perform a filesystem operation in the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsRequest {
    /// The operation to perform.
    pub op: FsOp,
}

/// Metadata about a filesystem entry (wire format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsEntryInfo {
    /// Path of the entry.
    pub path: String,

    /// Kind of entry: `"file"`, `"dir"`, `"symlink"`, or `"other"`.
    pub kind: String,

    /// Size in bytes.
    pub size: u64,

    /// Unix permission bits.
    pub mode: u32,

    /// Last modification time as Unix timestamp (seconds since epoch).
    pub modified: Option<i64>,
}

/// Data variants that can be included in a filesystem response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FsResponseData {
    /// Stat result.
    Stat(FsEntryInfo),

    /// Directory listing result.
    List(Vec<FsEntryInfo>),
}

/// Terminal response for a filesystem operation.
///
/// This is always the last message sent for a given correlation ID.
/// For streaming reads, it follows the `FsData` chunks.
/// For simple operations, it carries the result directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsResponse {
    /// Whether the operation succeeded.
    pub ok: bool,

    /// Error message if `ok` is false.
    #[serde(default)]
    pub error: Option<String>,

    /// Optional result data (for stat/list operations).
    #[serde(default)]
    pub data: Option<FsResponseData>,
}

/// A chunk of file data for streaming read/write operations.
///
/// An empty `data` field signals EOF (like `ExecStdin` with empty data).
#[derive(Debug, Serialize, Deserialize)]
pub struct FsData {
    /// The raw file data.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}
