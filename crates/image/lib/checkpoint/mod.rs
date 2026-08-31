//! Immutable composite-checkpoint manifests and local content storage.
//!
//! Checkpoint artifacts keep guest-visible state in canonical, content-addressed objects. Mutable
//! operation progress, runtime ownership, and provider locations deliberately live elsewhere.

mod manifest;
mod store;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use manifest::{
    CaptureIntent, CheckpointManifest, ContentRef, DeviceStateRef, DiskGenerationManifest,
    DiskLayerRef, MemoryCaptureMode, MemoryExtent, MemoryExtentContent, MemoryManifest,
    ResourceDescriptor, ResourceTreatment,
};
pub use store::{LocalObjectStore, ObjectId, SparseFileIntegrity, sparse_file_integrity};
