//! Backend-neutral snapshot result and operation types.

use serde::Serialize;
use std::path::PathBuf;

/// Result of explicit snapshot verification.
#[derive(Debug, Clone)]
pub struct SnapshotVerifyReport {
    /// Snapshot manifest digest.
    pub digest: String,
    /// Artifact directory.
    pub path: PathBuf,
    /// Upper-layer content verification result.
    pub upper: UpperVerifyStatus,
    /// Composite-checkpoint closure verification result, when this is a full snapshot.
    pub checkpoint: Option<CheckpointVerifyStatus>,
}

/// Verified identity of a composite-checkpoint closure.
#[derive(Debug, Clone)]
pub struct CheckpointVerifyStatus {
    /// SHA-256 identity of the canonical checkpoint root manifest.
    pub root: String,
}

/// Upper-layer content verification result.
#[derive(Debug, Clone)]
pub enum UpperVerifyStatus {
    /// The snapshot intentionally has no persistent payload integrity.
    NotRecorded,
    /// Recorded content integrity matched the computed digest.
    Verified {
        /// Digest algorithm.
        algorithm: String,
        /// Matching digest or Merkle root.
        digest: String,
    },
}

/// Options for installing an archive in a local snapshot group.
#[derive(Debug, Clone, Default)]
pub struct LoadOpts {
    /// Group-store root; defaults to the configured snapshots directory.
    pub dest: Option<PathBuf>,
    /// Explicit base selector for omitted disk layers and RAM objects.
    pub base: Option<String>,
    /// Existing/new destination group, or a freshly generated group when omitted.
    pub group: Option<String>,
    /// Select the imported target even when it is not a fast-forward.
    pub set_head: bool,
}

/// Options for [`super::Snapshot::save`].
#[derive(Debug, Clone, Default)]
pub struct SaveOpts {
    /// Walk parent chain and include each ancestor in the archive.
    pub with_parents: bool,
    /// Include the OCI image artifacts (EROFS layers, VMDK descriptor)
    /// from the global cache so the archive boots offline.
    pub with_image: bool,
    /// Skip zstd compression and write a plain `.tar`. Default: zstd.
    pub plain_tar: bool,
    /// Omit disk layers and RAM objects supplied by this base (name, directory, or archive).
    /// The base must be an exact physical disk prefix; full-snapshot metadata stays complete.
    /// Mutually exclusive with `last_layers` and `with_parents`.
    pub since: Option<String>,
    /// Export the newest N sealed disk layers, requiring an explicit base when loading omissions.
    /// Memory, execution, and device objects remain complete for full snapshots.
    pub last_layers: Option<usize>,
}

/// Outcome of publishing snapshots into a local group or explicitly selecting its head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeadUpdate {
    /// Local group name.
    pub group: String,
    /// Previously selected stable snapshot ID, if the group had a head.
    pub previous: Option<String>,
    /// Stable snapshot ID selected after the operation.
    pub head: String,
    /// Explanation for advancing or retaining the selected head.
    pub reason: HeadUpdateReason,
    /// Whether the selected head changed.
    pub changed: bool,
}

/// Why a snapshot group's head advanced or remained selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeadUpdateReason {
    /// The first candidate initialized an empty group.
    Initialized,
    /// The candidate is a proven descendant of the current head.
    FastForwarded,
    /// The caller explicitly selected an installed member.
    Selected,
    /// The candidate was already selected, or the caller only read the head.
    Unchanged,
    /// The candidate is not a descendant of the current head.
    Diverged,
    /// Missing history prevents proving that the candidate descends from the head.
    UnknownAncestry,
    /// Supplied archive heads have multiple tips that known ancestry cannot order.
    AmbiguousCandidates,
}
