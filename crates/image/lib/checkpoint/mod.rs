//! Immutable composite-checkpoint manifests and local content storage.
//!
//! Checkpoint artifacts keep guest-visible state in canonical, content-addressed objects. Mutable
//! operation progress, runtime ownership, and provider locations deliberately live elsewhere.

mod layer_selection;
mod manifest;
mod qcow;
mod resolver;
mod store;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use layer_selection::{DiskCompactionPlan, DiskLayerExportPlan, LayerSelectionError};
pub use manifest::{
    CaptureIntent, CheckpointManifest, ContentRef, DeviceStateRef, DiskGenerationManifest,
    DiskLayerRef, MemoryCaptureMode, MemoryExtent, MemoryExtentContent, MemoryManifest,
    ResourceDescriptor, ResourceTreatment,
};
pub use qcow::{create_qcow2_overlay, relocate_qcow2_backing, relocated_qcow2_header};
pub use resolver::CheckpointClosure;
pub use store::{LocalObjectStore, ObjectId, SparseFileIntegrity, sparse_file_integrity};
