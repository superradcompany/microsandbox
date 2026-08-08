//! Snapshot descriptor schema and canonical (de)serialization.
//!
//! The schema types live in `microsandbox-types` so lower layers can share
//! them. This module re-exports them under their original paths.

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use microsandbox_types::snapshot::{
    CheckpointSnapshotState, DEFAULT_UPPER_FILE, DESCRIPTOR_FILENAME, FILE_MERKLE_BLAKE3_LEAF_SIZE,
    FILE_MERKLE_BLAKE3_V1, FileSnapshotState, ImageRef, MAX_JSON_SAFE_INTEGER, Manifest,
    SCHEMA_VERSION, SNAPSHOT_ARTIFACT_KIND, SPARSE_SHA256_V1, SUPPORTED_REQUIRES,
    SnapshotDescriptor, SnapshotFormat, SnapshotScope, SnapshotState, UpperIntegrity, UpperLayer,
};
