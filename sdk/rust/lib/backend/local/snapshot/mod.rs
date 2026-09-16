//! Local snapshot lifecycle and complete artifact engine.

pub(super) mod archive;
mod artifact;
mod copy;
mod create;
mod dispatch;
pub mod downgrade;
mod group;
pub(crate) mod lineage;
mod metadata;
pub(super) mod migration;
mod restore;
mod store;
mod verify;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

use crate::snapshot::{
    HeadUpdate, Manifest, SnapshotArchive, SnapshotConfig, SnapshotFormat, SnapshotId,
    SnapshotScope, UpperIntegrity,
};
pub(crate) use archive::materialize_archive_for_child_with_overrides as materialize_archive_for_child;
use artifact::{Snapshot, SnapshotHandle};
pub(crate) use create::{
    CHECKPOINT_DIRECTORY, stage_local_branch_closure, validate_checkpoint_owned_inventory,
    validate_owned_inventory,
};
pub(crate) use restore::{
    adopt_local_branch_for_child, apply_additional_disks, materialize_additional_disks,
    materialize_checkpoint_child_disk_state, materialize_checkpoint_child_state,
    materialize_checkpoint_disk_for_child, materialize_checkpoint_for_child,
    materialize_file_snapshot_for_child, materialize_owned_volumes, root_device,
};
