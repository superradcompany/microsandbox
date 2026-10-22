//! Backend-neutral snapshot result and operation types.

use serde::Serialize;
use std::path::PathBuf;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Metadata observed from one protected read of a named history.
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotGroupInfo {
    /// Selected group's name.
    pub name: String,
    /// Group location in the backend's filesystem, not a client-relative path.
    pub path: PathBuf,
    /// Selected checkpoint, including an explicitly headless history.
    pub head: Option<super::SnapshotId>,
    /// Number of installed members observed with this head.
    pub checkpoint_count: u64,
    /// Local capture association; absent for unbound/imported histories.
    pub source: Option<SnapshotSourceBinding>,
}

/// A saved local association and the status of that exact sandbox instance.
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotSourceBinding {
    /// Catalog instance that owns the recorded sandbox row.
    pub database_uuid: String,
    /// Stable row identity within that catalog, never resolved by its display name.
    pub sandbox_id: i32,
    /// Sandbox name when this association was recorded.
    pub recorded_name: String,
    /// Current name of the same sandbox instance, when available.
    pub current_name: Option<String>,
    /// Whether the recorded source still belongs to this catalog and exists.
    pub status: SnapshotSourceStatus,
}

/// Availability of the saved capture association at inspection time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSourceStatus {
    /// The exact catalog and sandbox row still exist; this is not a capture-readiness check.
    Available,
    /// The owning catalog matches, but its recorded sandbox row was deleted.
    MissingSandbox,
    /// This installation has another catalog identity, or has no recorded identity.
    DifferentCatalog,
}

/// Outcome of explicitly removing a whole history and its members.
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotRemoveResult {
    /// Removed group's name.
    pub group: String,
    /// Exact member identities removed, in stable order.
    pub removed: Vec<super::SnapshotId>,
    /// This operation's head removal, including an already-headless group.
    pub head_update: HeadUpdate,
    /// Recoverable cleanup remaining after confirmed publication.
    pub warnings: Vec<String>,
}

/// Result owned by one exact checkpoint removal, never reconstructed from a later head read.
#[derive(Debug, Clone, Serialize)]
pub struct CheckpointRemoveResult {
    /// Immutable identity removed by this operation.
    pub id: super::SnapshotId,
    /// Group head decision; absent only for a standalone artifact.
    pub head_update: Option<HeadUpdate>,
    /// Removal committed, but these cleanup steps remain recoverable.
    pub warnings: Vec<String>,
}

/// Exact checkpoint removal controls. Force permits indexed dependents, never active readers.
#[derive(Debug, Clone, Default)]
pub struct CheckpointRemoveOptions {
    pub(crate) force: bool,
}

/// Result of explicit snapshot verification.
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotVerifyReport {
    /// Snapshot manifest digest.
    pub digest: String,
    /// Artifact directory.
    pub path: PathBuf,
    /// Upper-layer content verification result.
    pub upper: UpperVerifyStatus,
    /// Composite-checkpoint closure verification result, when this is a full snapshot.
    pub checkpoint: Option<CheckpointVerifyStatus>,
    /// Whether every required payload had recorded integrity, including ancestors and owned disks.
    /// The legacy `upper` field describes only the head and cannot establish this coverage.
    pub coverage: SnapshotVerifyCoverage,
}

/// Integrity coverage of a successful verification operation. Corruption still returns an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SnapshotVerifyCoverage {
    /// All required payload integrity was recorded and checked.
    Complete,
    /// These payloads have no recorded checksum; their contents cannot be authenticated.
    Incomplete {
        /// Artifact payload paths with unrecorded integrity, in deterministic order.
        unrecorded: Vec<PathBuf>,
    },
}

/// Verified identity of a composite-checkpoint closure.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename = "verified")]
pub struct CheckpointVerifyStatus {
    /// SHA-256 identity of the canonical checkpoint root manifest.
    pub root: String,
}

/// Upper-layer content verification result.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
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

/// Outcome of verification, with empty selections distinct from checked artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotVerificationState {
    /// All selected members and required payload bindings were verified.
    Complete,
    /// Required integrity was unrecorded or could not be checked.
    Incomplete,
    /// A selected artifact was missing, changed, malformed, or corrupt.
    Invalid,
    /// The group contained no members; no checkpoint was verified.
    Empty,
}

/// Why one payload or member could not be fully verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotVerificationFindingKind {
    /// A required file or dependency was absent.
    Missing,
    /// Content or structure did not match its recorded binding.
    Invalid,
    /// The file could not be read because of an operational failure.
    Unavailable,
    /// A selected file changed while verification was in progress.
    Changed,
    /// This reader cannot interpret a required artifact feature.
    Unsupported,
    /// No checksum was recorded for this required payload.
    NotRecorded,
}

/// A specific verification failure or coverage gap, attached to every affected checkpoint.
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotVerificationFinding {
    /// File or member whose verification could not complete.
    pub path: PathBuf,
    /// Machine-readable reason, independent of the human diagnostic.
    pub kind: SnapshotVerificationFindingKind,
    /// Diagnostic explaining the failed check.
    pub detail: String,
}

/// Verification of one member in the group membership selected at operation start.
#[derive(Debug, Clone, Serialize)]
pub struct CheckpointVerification {
    /// Stable member identity, if the directory name or descriptor provided a valid identity.
    pub id: Option<super::SnapshotId>,
    /// Selected member directory.
    pub path: PathBuf,
    /// Complete, incomplete or invalid; members never have the group's empty state.
    pub state: SnapshotVerificationState,
    /// Existing artifact report when all recorded checks succeeded, even if coverage is incomplete.
    pub report: Option<SnapshotVerifyReport>,
    /// Every observed failure or missing checksum, including shared dependency failures.
    pub findings: Vec<SnapshotVerificationFinding>,
}

/// Report for one pinned whole-group verification. Corruption and operational failures return
/// this report through `MicrosandboxError::SnapshotVerification`; they are never successful results.
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotGroupVerifyReport {
    /// Selected group name.
    pub group: String,
    /// Aggregate status; an empty group is not a verified checkpoint.
    pub state: SnapshotVerificationState,
    /// All selected members, in stable directory-name order, including malformed members.
    pub checkpoints: Vec<CheckpointVerification>,
    /// Physical payload hash passes; shared hard links use one pass per required algorithm.
    pub payload_hashes: usize,
}

/// Options for a canonical group import. The destination group is a separate argument.
#[derive(Debug, Clone, Default)]
pub struct SnapshotImportOptions {
    /// Group-store root; defaults to the configured snapshots directory.
    pub dest: Option<PathBuf>,
    /// Explicit base selector for omitted disk layers and RAM objects.
    pub base: Option<String>,
    /// Select the unique imported tip even when it is not a fast-forward.
    pub set_head: bool,
}

/// Legacy artifact-loading options. Canonical group import uses [`SnapshotImportOptions`].
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

/// Options for [`super::Checkpoint::save`].
#[derive(Debug, Clone, Default)]
pub struct SaveOpts {
    /// Recipient archive dialect; unsupported required behavior is refused, never stripped.
    pub compatibility: super::ArchiveCompatibility,
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
    /// Stable snapshot ID selected after the operation, or none for a cleared head.
    pub head: Option<String>,
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
    /// The caller explicitly cleared the selected head.
    Cleared,
    /// Removing the head selected its surviving recorded same-group parent.
    ParentSelected,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SnapshotImportOptions {
    /// Supply a base for omitted disk layers or memory objects.
    pub fn base(mut self, base: impl Into<String>) -> Self {
        self.base = Some(base.into());
        self
    }

    /// Install the named group beneath this local store root.
    pub fn dest_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.dest = Some(path.into());
        self
    }

    /// Select the unique imported tip even when it is not a fast-forward.
    pub fn set_head(mut self) -> Self {
        self.set_head = true;
        self
    }

    /// Keep the legacy backend transport internal; callers cannot provide a second group.
    pub(crate) fn into_load_opts(self) -> LoadOpts {
        LoadOpts {
            dest: self.dest,
            base: self.base,
            group: None,
            set_head: self.set_head,
        }
    }
}

impl LoadOpts {
    /// Supply a base for omitted disk layers or memory objects.
    pub fn base(mut self, base: impl Into<String>) -> Self {
        self.base = Some(base.into());
        self
    }

    /// Install the named group beneath this local store root.
    pub fn dest_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.dest = Some(path.into());
        self
    }

    /// Select the unique imported tip even when it is not a fast-forward.
    pub fn set_head(mut self) -> Self {
        self.set_head = true;
        self
    }
}

impl SaveOpts {
    /// Target an archive reader without changing immutable checkpoint descriptors.
    pub fn compatibility(mut self, target: super::ArchiveCompatibility) -> Self {
        self.compatibility = target;
        self
    }

    /// Include the recorded parent chain.
    pub fn with_parents(mut self) -> Self {
        self.with_parents = true;
        self
    }

    /// Include the base image so the exported checkpoint can boot offline.
    pub fn with_image(mut self) -> Self {
        self.with_image = true;
        self
    }

    /// Write an uncompressed tar archive.
    pub fn plain_tar(mut self) -> Self {
        self.plain_tar = true;
        self
    }

    /// Omit payload already supplied by an exact base.
    pub fn since(mut self, base: impl Into<String>) -> Self {
        self.since = Some(base.into());
        self
    }

    /// Export only the newest root-disk layers, retaining explicit dependencies.
    pub fn last_layers(mut self, count: usize) -> Self {
        self.last_layers = Some(count);
        self
    }
}

impl CheckpointRemoveOptions {
    /// Permit removing an artifact with indexed dependents. Reader protections remain mandatory.
    pub fn force(mut self) -> Self {
        self.force = true;
        self
    }
}
