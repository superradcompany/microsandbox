//! Context-scoped storage observations and runtime-cache cleanup.
//!
//! Byte counts do not measure exclusive physical ownership.

mod types;
mod usage;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use microsandbox_types::memory_cache::{
    MemoryCacheEntry, MemoryCacheKind, MemoryCacheReport, MemoryCacheState, MemoryPruneOptions,
};
pub use types::{Storage, StorageCategoryUsage, StorageItemUsage, StorageUsage};
