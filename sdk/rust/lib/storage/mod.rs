//! Backend-scoped storage observations and runtime-cache cleanup.
//!
//! Byte counts do not measure exclusive physical ownership.

mod types;
mod usage;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "local")]
pub use microsandbox_runtime::checkpoint::{
    MemoryCacheEntry, MemoryCacheKind, MemoryCacheReport, MemoryCacheState, MemoryPruneOptions,
};
pub use types::{Storage, StorageCategoryUsage, StorageItemUsage, StorageUsage};
