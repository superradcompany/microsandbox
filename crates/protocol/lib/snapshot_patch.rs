//! Private input to the isolated snapshot child-disk editor.

use serde::{Deserialize, Serialize};

/// This argument selects the editor in the embedded guest running as PID 1.
pub const BOOT_ARG: &str = "--msb-private-disk-editor-v1";
/// Acknowledged only after the edited filesystem has been synced and unmounted.
pub const RECEIPT: &str = "microsandbox-private-disk-editor/1";

/// Paths are Linux bytes, including names discovered by CopyDir. File data is
/// streamed in order from one separate file so large inputs do not expand into JSON.
#[derive(Serialize, Deserialize)]
pub struct Edit {
    /// Absolute path in the captured filesystem.
    pub path: Vec<u8>,
    /// Operation requested on this path.
    pub action: Action,
}

/// Ordered mutations on the mounted guest view.
#[derive(Serialize, Deserialize)]
pub enum Action {
    /// Ensure a directory exists. An existing directory keeps its metadata.
    Directory {
        /// Unix permission bits.
        mode: u32,
    },
    /// Copy a directory and preserve its declared permissions.
    CopyDirectory {
        /// Unix permission bits of the source directory.
        mode: u32,
        /// Merge with a directory or replace another existing entry.
        replace: bool,
    },
    /// Replace or create a regular file with the next bytes from the payload.
    Write {
        /// Unix permission bits.
        mode: u32,
        /// Permit replacement of an existing entry.
        replace: bool,
        /// Exact byte count from the ordered data stream.
        len: u64,
    },
    /// Append the next bytes to an existing regular file.
    Append {
        /// Exact byte count from the ordered data stream.
        len: u64,
    },
    /// Create a symbolic link with a guest-local target.
    Symlink {
        /// Raw guest symlink target.
        target: Vec<u8>,
        /// Permit replacement of an existing entry.
        replace: bool,
    },
    /// Remove the named entry, including a directory tree.
    Remove,
}
