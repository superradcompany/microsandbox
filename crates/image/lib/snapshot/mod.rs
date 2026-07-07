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

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use manifest::{
    DEFAULT_UPPER_FILE, DESCRIPTOR_FILENAME, ImageRef, Manifest, SCHEMA_VERSION,
    SNAPSHOT_ARTIFACT_KIND, SPARSE_SHA256_V1, SUPPORTED_REQUIRES, SnapshotFormat, SnapshotScope,
    UpperIntegrity, UpperLayer,
};
