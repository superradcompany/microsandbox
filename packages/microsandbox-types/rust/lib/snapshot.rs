//! Snapshot maintenance results shared by SDK and runtime without linking a VM runner.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Disks eligible for explicit maintenance. Named and external disks are never included.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DiskCompactionTarget {
    /// The managed/flat root, when present, and every sandbox-owned data disk.
    #[default]
    All,
    /// Only the managed or flat root disk.
    Root,
    /// Only the sandbox-owned data disk mounted at this guest path.
    Disk {
        /// Canonical absolute guest mount path; `/` selects the root.
        guest_path: String,
    },
}

/// Per-disk outcome; a selected count below two means the chain was unchanged.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DiskCompactionDiskResult {
    /// Guest mount path; `/` identifies the root disk.
    pub guest_path: String,
    /// Physical layers before compaction, including the writable head.
    pub input_layers: usize,
    /// Oldest sealed physical layers selected, including the base.
    pub selected_layers: usize,
    /// Physical layers after compaction, including the writable head.
    pub output_layers: usize,
    /// Guest bytes materialized; not reclaimed disk space.
    pub materialized_bytes: u64,
    /// This disk's preparation/materialization duration in microseconds, excluding journal
    /// adoption and backend switching. Those shared phases are included in the aggregate timing.
    pub total_us: u64,
}

/// Aggregate outcome or dry-run projection of explicit disk compaction.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DiskCompactionResult {
    /// Whether only selection was performed.
    pub dry_run: bool,
    /// Sum of physical layers before compaction, including each writable head.
    pub input_layers: usize,
    /// Sum of selected oldest sealed layers, including each base, excluding writable heads.
    pub selected_layers: usize,
    /// Sum of physical layers after compaction, including each writable head.
    pub output_layers: usize,
    /// Guest bytes materialized; not a disk-space saving estimate.
    pub materialized_bytes: u64,
    /// Total operation duration in microseconds.
    pub total_us: u64,
    /// Measured VM pause through resume, zero for stopped sources and dry runs.
    pub pause_us: u64,
    /// Individual selected disks, including unchanged chains with fewer than two sealed layers.
    pub disks: Vec<DiskCompactionDiskResult>,
}

/// How full restore validates authorized external filesystem mappings and captured objects.
///
/// This policy does not authorize or inherit host resources, or waive required backing.
/// When the restore operation explicitly allows an unmapped filesystem, it remains
/// unavailable under either policy; backend operations return EIO.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExternalMountRestorePolicy {
    /// Refuse activation when a supplied mapping or its captured objects cannot be reconstructed.
    #[default]
    Strict,
    /// Accept supported mapping mismatches with warnings and errors for stale or unavailable objects.
    Relaxed,
}

/// An unmapped external filesystem or a mismatch accepted during relaxed full restore.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalMountWarning {
    /// Guest-visible mount path.
    pub guest_path: String,
    /// Actionable reason the resource could not be reconstructed.
    pub reason: String,
    /// Permanently invalid captured node IDs; empty when the whole export is unavailable.
    pub stale_inodes: Vec<u64>,
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compaction_targets_have_closed_wire_shapes() {
        for (target, json) in [
            (DiskCompactionTarget::All, r#"{"kind":"all"}"#),
            (DiskCompactionTarget::Root, r#"{"kind":"root"}"#),
            (
                DiskCompactionTarget::Disk {
                    guest_path: "/data".into(),
                },
                r#"{"kind":"disk","guest_path":"/data"}"#,
            ),
        ] {
            assert_eq!(serde_json::to_string(&target).unwrap(), json);
            assert_eq!(
                serde_json::from_str::<DiskCompactionTarget>(json).unwrap(),
                target
            );
        }
        assert!(serde_json::from_str::<DiskCompactionTarget>(r#"{"kind":"disk"}"#).is_err());
        assert!(
            serde_json::from_str::<DiskCompactionTarget>(
                r#"{"kind":"disk","guest_path":"/data","external":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn compaction_result_preserves_per_disk_metrics() {
        let result = DiskCompactionResult {
            dry_run: true,
            disks: vec![DiskCompactionDiskResult {
                guest_path: "/data".into(),
                input_layers: 1,
                output_layers: 1,
                ..Default::default()
            }],
            ..Default::default()
        };
        let encoded = serde_json::to_string(&result).unwrap();
        let decoded: DiskCompactionResult = serde_json::from_str(&encoded).unwrap();
        assert!(decoded.dry_run);
        assert_eq!(decoded.disks[0].guest_path, "/data");
        assert_eq!(decoded.disks[0].selected_layers, 0);
        assert!(serde_json::from_str::<DiskCompactionResult>(r#"{"dry_run":false,"input_layers":1,"selected_layers":0,"output_layers":1,"materialized_bytes":0,"total_us":0,"pause_us":0}"#).is_err());
    }
}

/// Released cloud descriptor wire contract.
pub mod cloud_manifest;
/// Pure disk generation descriptors.
pub mod disk;
/// Existing legacy descriptor identity and cloud projection rules.
pub mod legacy;
/// Canonical portable snapshot descriptor.
pub mod manifest;
/// Pure owned-storage snapshot inventory.
pub mod owned;
mod restore_defaults;

pub use manifest::*;
pub use owned::{
    OWNED_VOLUMES_EXTENSION, OwnedDirectoryPayload, OwnedMountSnapshot, OwnedVolumeCapture,
    OwnedVolumeData, validate_owned_volumes,
};
pub use restore_defaults::{RESTORE_DEFAULTS_EXTENSION, RestoreDefaults};
