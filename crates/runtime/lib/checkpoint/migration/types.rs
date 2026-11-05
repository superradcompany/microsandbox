//! Host-authorized migration inputs and read-only diagnostic results.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::super::layout::LegacyRootBinding;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Host catalog bindings; legacy journals cannot extend this authority.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationBindings {
    /// Stable catalog incarnation, distinct from deletion/recreation of the same name.
    pub identity: String,
    /// Saved configuration revision. It must remain unchanged until migration completes.
    pub config_revision: String,
    /// Configured root, if this sandbox has a runtime-owned writable root.
    pub root: Option<LegacyRootBinding>,
    /// Individually configured owned disks, excluding directory mounts.
    pub owned_disks: Vec<OwnedDiskBinding>,
    /// Additional known aliases whose resources and writers the caller has admitted.
    pub aliases: Vec<AuthorizedAlias>,
}

/// A disk role derived from a persisted owned-volume mount, never from a journal.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnedDiskBinding {
    /// Deterministic owned-volume mount ID.
    pub id: String,
    /// Exact nominal `owned-volumes/<id>/disk.raw` binding.
    pub path: PathBuf,
    /// Configured guest-visible capacity in bytes.
    pub capacity: u64,
    /// Configured read-only attachment policy.
    pub readonly: bool,
}

/// A separately authorized alias, supplied while all corresponding writers are excluded.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedAlias {
    /// `root` or the corresponding owned-volume mount ID.
    pub disk_id: String,
    /// Exact resource path; this does not authorize its directory or neighbors.
    pub path: PathBuf,
}

/// Migration state without mutation or implicit recovery.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MigrationStatus {
    /// Protected layout is already complete.
    Ready,
    /// A complete authorized selected view can be imported.
    Eligible,
    /// Selection, source authority, or writer exclusion needs attention.
    RecoveryRequired,
    /// A durable operation exists and must resume its frozen selection.
    InProgress,
}

/// One selected complete disk view. IDs describe a disk role, not an arbitrary host path.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateSummary {
    /// Stable role-bound candidate identifier.
    pub id: String,
    /// `root` or the owned disk mount ID.
    pub disk_id: String,
    /// Number of explicitly authorized layers.
    pub layers: usize,
    /// Guest-visible capacity in bytes.
    pub virtual_size: u64,
    /// Conservative apparent bytes to capture, including private validation copies for external QCOW disks.
    pub estimated_bytes: u64,
}

/// Non-mutating inspection result. Messages contain no raw guest metadata or secret values.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Inspection {
    /// Current storage admission classification.
    pub status: MigrationStatus,
    /// True when all discovered alternatives pass the bounded preview preflight. Existing
    /// serialized reports lack this proof and conservatively default to unavailable.
    #[serde(default)]
    pub preview_available: bool,
    /// Bounded actionable reasons; metadata parser errors are not echoed.
    pub reasons: Vec<String>,
    /// Complete selected views within independently authorized disk resources.
    pub candidates: Vec<CandidateSummary>,
    /// Conservative staging bytes; filesystem cloning may use less physical space.
    pub estimated_bytes: u64,
}

/// Provisional metadata for a selected disk object; no disk contents have been read.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AliasSource {
    /// Configured disk role (`root` or owned mount ID).
    pub disk_id: String,
    /// Source selected within a validated historical producer role.
    pub path: PathBuf,
    /// Platform file identity, used only to compare aliases, never as provenance.
    pub identity_object: String,
    /// Number of directory links which must be independently accounted.
    pub links: u64,
    /// True for a selected sealed ancestor or an explicitly read-only disk.
    pub readonly: bool,
}

/// Explicit selection of a currently inspected authorized view; never a path override.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoverySelection {
    /// Configured disk role.
    pub disk_id: String,
    /// Identity-bound candidate ID returned by the inspector.
    pub candidate_id: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Inspection {
    /// A bounded complete set can provisionally be captured under fresh writer protection.
    /// Catalog authority and VM liveness must also be established by the caller.
    pub fn can_preview(&self) -> bool {
        self.status == MigrationStatus::RecoveryRequired && self.preview_available
    }
}
