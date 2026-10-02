//! Immutable composite-checkpoint manifests and local content storage.
//!
//! Checkpoint artifacts keep guest-visible state in canonical, content-addressed objects. Mutable
//! operation progress, runtime ownership, and provider locations deliberately live elsewhere.

mod admitted_disk;
mod compact;
mod layer_selection;
mod manifest;
mod qcow;
mod resolver;
mod store;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub(crate) use compact::open_writable_chain;
pub use compact::{
    CompactLayer, CompactMaterialization, compact_layer_capacity, layer_capacities,
    materialize_compact_prefix, materialize_raw_prefix, validate_compact_chain,
};
pub use layer_selection::{DiskCompactionPlan, DiskLayerExportPlan, LayerSelectionError};
pub use manifest::{
    CaptureIntent, CheckpointGeometry, CheckpointManifest, ContentRef, DeviceStateRef,
    DiskGenerationManifest, DiskLayerRef, MemoryCaptureMode, MemoryExtent, MemoryExtentContent,
    MemoryManifest, ResourceDescriptor, ResourceTreatment,
};
pub use qcow::{
    create_qcow2_overlay, qcow2_backing_basename, relocate_qcow2_backing, relocated_qcow2_header,
    validate_standalone_qcow2,
};
pub use resolver::{CheckpointClosure, CheckpointObjectReadTiming};
pub use store::{
    AdmittedObject, CaptureObjectBatch, CaptureObjectBatchStats, LocalObjectStore, ObjectId,
    SparseFileIntegrity, sparse_file_integrity,
};
