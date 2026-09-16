//! Options for cloning an existing disk snapshot into a new artifact.
//!
//! The clone implementation lives in the local backend; this module carries the public options
//! type so the marker-free public surface stays backend-neutral.

use std::path::PathBuf;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options for [`Snapshot::clone_snapshot`](crate::snapshot::Snapshot::clone_snapshot).
#[derive(Debug, Clone, Default)]
pub struct CloneOpts {
    /// Parent directory to create the new artifact's group under. `None` = the default
    /// snapshots directory.
    pub dest_dir: Option<PathBuf>,

    /// Snapshot group to create the clone in. `None` creates a group named after the new member.
    pub group: Option<String>,

    /// User-supplied labels for the new snapshot. Not inherited from the source.
    pub labels: Vec<(String, String)>,

    /// Overwrite an existing artifact at the destination.
    ///
    /// Local grouped snapshots are immutable and reject this option; it is kept for
    /// contract completeness.
    pub force: bool,

    /// Deallocate host storage for blocks the guest ext4 filesystem has already freed, while
    /// cloning. Opt-in: never changes guest-visible content, only host disk usage, and never
    /// fails the clone if compaction itself fails.
    pub compact: bool,

    /// Grow the cloned upper's ext4 filesystem to this size in MiB, offline, before recording
    /// the artifact. `None` keeps the source's size. Grow-only: a target at or below the
    /// source's current size is a hard error, same as the live sandbox `--root-disk` path.
    pub root_disk_size_mib: Option<u32>,
}