//! Snapshot artifact format.
//!
//! A snapshot is a self-describing, content-addressed artifact that captures
//! a sandbox's writable upper layer plus enough metadata to pin the immutable
//! lower (image) it was taken from. The artifact is the source of truth;
//! databases are caches.
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
    CheckpointSnapshotState, DEFAULT_UPPER_FILE, DESCRIPTOR_FILENAME, FileSnapshotState, ImageRef,
    MAX_JSON_SAFE_INTEGER, Manifest, SCHEMA_VERSION, SNAPSHOT_ARTIFACT_KIND, SPARSE_SHA256_V1,
    SUPPORTED_REQUIRES, SnapshotDescriptor, SnapshotFormat, SnapshotScope, SnapshotState,
    UpperIntegrity, UpperLayer,
};
