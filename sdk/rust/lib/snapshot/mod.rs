//! Backend-neutral snapshot capture, inspection, archives, and restore references.
//!
//! Local storage supports disk and full execution snapshots, immutable groups,
//! layered disks, owned storage, and incremental archives. Cloud storage retains
//! its own wire contract and reports unsupported local artifact operations explicitly.

mod api;
mod copy;
mod types;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use api::{Snapshot, SnapshotArchive, SnapshotBuilder, SnapshotHandle, SnapshotReference};
pub use copy::SnapshotCopyBuilder;
pub use microsandbox_types::snapshot::{
    CheckpointSnapshotState, DESCRIPTOR_FILENAME, DiskLayer, DiskLayerId, FileSnapshotState,
    ImageRef, LayerFileKind, LayerPayload, Manifest, SnapshotCapture, SnapshotConsistency,
    SnapshotDescriptor, SnapshotFormat, SnapshotId, SnapshotRootDisk, SnapshotScope, SnapshotState,
    UpperIntegrity, UpperLayer,
};
pub use microsandbox_types::{GuestFlush, SnapshotSpec, SnapshotSpec as SnapshotConfig};
pub use types::{
    CheckpointVerifyStatus, HeadUpdate, HeadUpdateReason, LoadOpts, SaveOpts, SnapshotVerifyReport,
    UpperVerifyStatus,
};

#[cfg(feature = "local")]
#[doc(hidden)]
pub use crate::backend::local::snapshot::downgrade;
#[cfg(feature = "local")]
pub(crate) use crate::backend::local::snapshot::{
    CHECKPOINT_DIRECTORY, adopt_local_branch_for_child, apply_additional_disks, lineage,
    materialize_additional_disks, materialize_archive_for_child,
    materialize_checkpoint_disk_for_child, materialize_checkpoint_for_child,
    materialize_file_snapshot_for_child, materialize_owned_volumes, root_device,
    stage_local_branch_closure, validate_checkpoint_owned_inventory, validate_owned_inventory,
};
