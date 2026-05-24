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
    /// Resolve a path to its canonical absolute form.
    RealPath {
        /// Guest path to resolve.
        path: String,
    },

    /// Get metadata for a path.
    Stat {
        /// Guest path to stat.
        path: String,

        /// Whether to follow symlinks.
        follow_symlink: bool,
    },

    /// Update metadata for a path.
    SetStat {
        /// Guest path to update.
        path: String,

        /// Whether to follow symlinks.
        follow_symlink: bool,

        /// Attributes to update.
        attrs: FsSetAttrs,
    },

    /// List directory contents.
    List {
        /// Guest directory path to list.
        path: String,
    },

    /// Read a symlink target.
    ReadLink {
        /// Guest symlink path to read.
        path: String,
    },

    /// Create a symlink.
    Symlink {
        /// Symlink target.
        target: String,

        /// Symlink path to create.
        link_path: String,
    },

    /// Create a directory (and parents).
    Mkdir {
        /// Guest directory path to create.
        path: String,

        /// Permission bits to set on creation (e.g. 0o755).
        #[serde(default)]
        mode: Option<u32>,
    },

    /// Remove a file.
    Remove {
        /// Guest file path to remove.
        path: String,
    },

    /// Remove a directory.
    RemoveDir {
        /// Guest directory path to remove.
        path: String,

        /// Whether to remove recursively.
        recursive: bool,
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

    /// Open a file and allocate an agentd-side handle.
    OpenFile {
        /// Guest file path to open.
        path: String,

        /// File open options.
        options: FsOpenOptions,
    },

    /// Open a directory and allocate an agentd-side handle.
    OpenDir {
        /// Guest directory path to open.
        path: String,
    },

    /// Close a file or directory handle.
    CloseHandle {
        /// Agentd-side handle.
        handle: u64,
    },

    /// Read from an open file handle.
    Read {
        /// Agentd-side file handle.
        handle: u64,

        /// Byte offset to read from.
        offset: u64,

        /// Maximum bytes to read. `None` means read to EOF.
        len: Option<u64>,
    },

    /// Write to an open file handle.
    Write {
        /// Agentd-side file handle.
        handle: u64,

        /// Byte offset to write at.
        offset: u64,

        /// Expected byte count. `None` disables count validation.
        len: Option<u64>,
    },

    /// Read the next batch of entries from an open directory handle.
    ReadDir {
        /// Agentd-side directory handle.
        handle: u64,

        /// Maximum entries to return. `None` uses the agent default.
        limit: Option<u32>,
    },

    /// Get metadata for an open file or directory handle.
    FStat {
        /// Agentd-side handle.
        handle: u64,
    },

    /// Update metadata for an open file handle.
    FSetStat {
        /// Agentd-side handle.
        handle: u64,

        /// Attributes to update.
        attrs: FsSetAttrs,
    },
}

/// Attributes accepted by setstat-style filesystem operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FsSetAttrs {
    /// Unix permission bits.
    pub mode: Option<u32>,

    /// Owner user ID.
    pub uid: Option<u32>,

    /// Owner group ID.
    pub gid: Option<u32>,

    /// File size.
    pub size: Option<u64>,

    /// Access time as Unix timestamp seconds.
    pub atime: Option<i64>,

    /// Modification time as Unix timestamp seconds.
    pub mtime: Option<i64>,
}

/// Options used when opening a file handle.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FsOpenOptions {
    /// Open for reading.
    pub read: bool,

    /// Open for writing.
    pub write: bool,

    /// Append writes to the end.
    pub append: bool,

    /// Create the file if it is missing.
    pub create: bool,

    /// Truncate the file after opening.
    pub truncate: bool,

    /// Create a new file and fail if it already exists.
    pub create_new: bool,

    /// Permission bits to set on creation.
    pub mode: Option<u32>,
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

    /// Owner user ID.
    pub uid: u32,

    /// Owner group ID.
    pub gid: u32,

    /// Last access time as Unix timestamp (seconds since epoch).
    pub atime: Option<i64>,

    /// Last modification time as Unix timestamp (seconds since epoch).
    pub mtime: Option<i64>,
}

/// Data variants that can be included in a filesystem response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FsResponseData {
    /// Stat result.
    Stat(FsEntryInfo),

    /// Directory listing result.
    List(Vec<FsEntryInfo>),

    /// Open handle.
    Handle(u64),

    /// Resolved path or symlink target.
    Path(String),
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
