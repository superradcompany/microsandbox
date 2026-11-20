//! Memory-cache observation contracts, independent of the local runtime.

use serde::Serialize;
use std::{path::PathBuf, time::Duration};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Selection policy shared by explicit pruning and bounded lifecycle sweeps.
#[derive(Clone, Debug, Default)]
pub struct MemoryPruneOptions {
    /// Observe eligibility without unlinking files or creating lock files.
    pub dry_run: bool,
    /// Minimum age of the backing's modification time, independent of ownership checks.
    pub older_than: Duration,
    /// Bound directory entries examined by an opportunistic sweep; explicit prune uses `None`.
    pub max_entries: Option<usize>,
    /// Automatic reclamation targets branch RAM; retain reusable snapshot realizations until explicit prune.
    pub branches_only: bool,
}

/// Namespace of a complete, immutable RAM realization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryCacheKind {
    /// Transient local branch backing.
    BranchMemory,
    /// Rebuildable RAM realized from a durable snapshot's objects.
    SnapshotMemory,
}

/// Eligibility observed while holding the same locks used for actual reclamation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryCacheState {
    /// No owner prevents removal at the instant of inspection.
    Reclaimable,
    /// A mapping, SDK handle, or retained baseline still owns the inode.
    InUse,
    /// A branch request is still transferring ownership to its children.
    PendingHandoff,
    /// The age filter excludes this file.
    TooYoung,
    /// No stable handoff lock exists, so branch ownership cannot be established safely.
    MissingHandoffLock,
    /// The observed file disappeared or was replaced; a subsequent scan can retry it.
    Changed,
    /// This operation successfully unlinked the observed inode.
    Removed,
    /// An I/O or validation failure prevented a safe decision.
    Error,
}

/// Per-file observations; allocated bytes are not exclusive physical ownership on CoW filesystems.
#[derive(Clone, Debug, Serialize)]
pub struct MemoryCacheEntry {
    /// Published backing pathname.
    pub path: PathBuf,
    /// Branch or durable-snapshot realization.
    pub kind: MemoryCacheKind,
    /// Observed logical file length, or unknown when metadata could not be read.
    pub logical_bytes: Option<u64>,
    /// Observed allocated blocks, when supported, without deduplicating shared extents.
    pub allocated_bytes: Option<u64>,
    /// Reason the entry can or cannot be reclaimed.
    pub state: MemoryCacheState,
    /// I/O diagnostic when eligibility could not be established.
    pub error: Option<String>,
}

/// Machine-readable result shared by CLI and SDK reporting.
#[derive(Clone, Debug, Default, Serialize)]
pub struct MemoryCacheReport {
    /// Whether this operation only inspected candidates.
    pub dry_run: bool,
    /// Files observed during this scan.
    pub entries: Vec<MemoryCacheEntry>,
    /// Number of files successfully unlinked.
    pub files_removed: u64,
    /// Sum of logical lengths of files successfully unlinked, not physical bytes freed.
    pub logical_bytes_removed: u64,
    /// Physical reclamation is not measurable from per-file metadata on shared storage.
    pub physical_bytes_reclaimed: Option<u64>,
    /// Whether the scan reached its entry bound before examining both namespaces completely.
    pub truncated: bool,
}
