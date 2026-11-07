//! Fixed endpoints and bounded replies for the trusted recovery guest reader.

use serde::{Deserialize, Serialize};

/// Both the runtime and the selected agent must support this private binary invocation.
pub const READER_ARG: &str = "--msb-private-recovery-reader-v1";
/// Probe returned by a functioning reader in the isolated guest.
pub const HANDSHAKE: &str = "microsandbox-private-storage-reader/1";
/// Guest mount for the detached candidate filesystem.
pub const DATA: &str = "/msb-preview-data";
/// Guest mount for the exact manifest-bound OCI lower filesystem.
pub const LOWER: &str = "/msb-preview-lower";
/// Merged read-only OCI mount, created by trusted PID 1.
pub const MERGED: &str = "/msb-preview-merged";
/// Maximum complete regular file returned by one preview.
pub const MAX_FILE: usize = 64 * 1024;
/// Maximum entries returned by one directory listing.
pub const MAX_ENTRIES: usize = 512;
/// Dedicated exit code for a positively missing path inside a mounted view.
pub const ABSENT: i32 = 44;

/// One directory entry in a mounted recovery view. Names are untrusted display data.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoragePreviewEntry {
    /// UTF-8 filename without path separators.
    pub name: String,
    /// One of file, directory, symlink or other.
    pub kind: String,
    /// File size in bytes, as returned by the guest filesystem.
    pub size: u64,
}
