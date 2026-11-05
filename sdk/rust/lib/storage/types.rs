use std::path::PathBuf;

use serde::Serialize;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Storage operations scoped to the currently selected backend.
pub struct Storage;

/// A point-in-time storage observation, not an atomic filesystem snapshot.
#[derive(Clone, Debug, Default, Serialize)]
pub struct StorageUsage {
    /// Indexed image references and their shared on-disk cache.
    pub images: StorageCategoryUsage,
    /// Indexed durable snapshots and managed snapshot directories.
    pub snapshots: StorageCategoryUsage,
    /// Persisted sandbox directories, including stopped sandboxes.
    pub sandboxes: StorageCategoryUsage,
    /// Managed named-volume directories.
    pub volumes: StorageCategoryUsage,
    /// Published branch RAM backing files.
    pub branch_memory: StorageCategoryUsage,
    /// Rebuildable RAM realizations of durable snapshots.
    pub snapshot_memory: StorageCategoryUsage,
    /// Scope and accounting limitations that apply to the complete report.
    pub notes: Vec<String>,
}

/// Aggregate observations for one storage category. `None` means unknown, never zero.
#[derive(Clone, Debug, Default, Serialize)]
pub struct StorageCategoryUsage {
    /// Indexed objects, or recognized cache files for memory categories.
    pub count: Option<u64>,
    /// Objects observed as in use, when ownership can be established.
    pub in_use: Option<u64>,
    /// Sum of regular-file lengths, deduplicating hard links on Unix.
    pub logical_bytes: Option<u64>,
    /// Sum of allocated blocks where supported; shared CoW extents may be counted repeatedly.
    pub allocated_bytes: Option<u64>,
    /// Logical bytes eligible for the category's cleanup policy at inspection time.
    pub reclaimable_logical_bytes: Option<u64>,
    /// Per-object observations or shared-cache components for detailed presentation.
    pub items: Vec<StorageItemUsage>,
    /// Category-specific scope or uncertainty explanations.
    pub notes: Vec<String>,
}

/// Storage observation for an object or shared-cache component.
#[derive(Clone, Debug, Default, Serialize)]
pub struct StorageItemUsage {
    /// Object name, snapshot identity, or shared-cache component name.
    pub name: String,
    /// Explicitly selected local object or cache directory.
    pub path: PathBuf,
    /// Sum of regular-file lengths, or unknown if the scan was incomplete.
    pub logical_bytes: Option<u64>,
    /// Allocated-block observation, or unknown where unavailable or incomplete.
    pub allocated_bytes: Option<u64>,
    /// Whether ownership was observed; unknown for durable objects without reader leases.
    pub in_use: Option<bool>,
    /// Whether this object is eligible for its category's cleanup policy.
    pub reclaimable: Option<bool>,
    /// Retention, exclusion, and incomplete-observation explanations.
    pub reasons: Vec<String>,
}
