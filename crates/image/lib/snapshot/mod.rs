//! Snapshot artifact format.
//!
//! A snapshot is a self-describing artifact with a stable opaque identity, a
//! conflict-detecting descriptor digest, and a complete state closure. The
//! artifact is the source of truth; databases are rebuildable projections.
//!
//! See `planning/microsandbox/implementation/snapshot-api-resumable-cloning.md`
//! for the full design.

pub mod manifest;
#[doc(hidden)]
pub mod migration;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use manifest::{
    CheckpointSnapshotState, DEFAULT_UPPER_FILE, DESCRIPTOR_FILENAME, DiskLayer, DiskLayerId,
    FILE_MERKLE_BLAKE3_LEAF_SIZE, FILE_MERKLE_BLAKE3_V1, FileSnapshotState, ImageRef,
    LAYERS_DIRECTORY, LayerFileKind, LayerPayload, MAX_DESCRIPTOR_BYTES, MAX_FILE_LAYERS,
    MAX_JSON_SAFE_INTEGER, Manifest, SCHEMA, SCHEMA_VERSION, SNAPSHOT_ARTIFACT_KIND,
    SPARSE_SHA256_V1, SUPPORTED_REQUIRES, SnapshotCapture, SnapshotConsistency, SnapshotDescriptor,
    SnapshotFormat, SnapshotId, SnapshotScope, SnapshotState, UpperIntegrity, UpperLayer,
    layer_path,
};
