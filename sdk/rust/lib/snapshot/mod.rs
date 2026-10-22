//! Backend-neutral snapshot capture, inspection, archives, and restore references.
//!
//! Local storage supports mutable groups of immutable disk and full checkpoints,
//! layered disks, owned storage, and incremental archives. Cloud storage retains
//! its own wire contract and reports unsupported local artifact operations explicitly.

mod api;
mod archive_compatibility;
mod copy;
mod group;
mod import;
#[doc(hidden)]
pub mod saved_config;
mod types;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use api::{Checkpoint, SnapshotArchive, SnapshotBuilder, SnapshotHandle, SnapshotReference};
pub use archive_compatibility::ArchiveCompatibility;
pub use copy::SnapshotCopyBuilder;
pub use group::{
    CheckpointCaptureResult, Snapshot, SnapshotCaptureOptions, SnapshotCreateResult,
    SnapshotImportResult,
};
#[doc(hidden)]
pub use import::PreparedSnapshotImport;
pub use microsandbox_types::snapshot::{
    CheckpointSnapshotState, DESCRIPTOR_FILENAME, DiskLayer, DiskLayerId, FileSnapshotState,
    ImageRef, LayerFileKind, LayerPayload, Manifest, SnapshotCapture, SnapshotConsistency,
    SnapshotDescriptor, SnapshotFormat, SnapshotId, SnapshotRootDisk, SnapshotScope, SnapshotState,
    UpperIntegrity, UpperLayer,
};
pub use microsandbox_types::{GuestFlush, SnapshotSpec, SnapshotSpec as SnapshotConfig};
pub use types::{
    CheckpointRemoveOptions, CheckpointRemoveResult, CheckpointVerification,
    CheckpointVerifyStatus, HeadUpdate, HeadUpdateReason, LoadOpts, SaveOpts, SnapshotGroupInfo,
    SnapshotGroupVerifyReport, SnapshotImportOptions, SnapshotRemoveResult, SnapshotSourceBinding,
    SnapshotSourceStatus, SnapshotVerificationFinding, SnapshotVerificationFindingKind,
    SnapshotVerificationState, SnapshotVerifyCoverage, SnapshotVerifyReport, UpperVerifyStatus,
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
