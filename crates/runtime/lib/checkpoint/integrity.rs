//! Where a backend keeps host-local integrity receipts for immutable disk inputs.

use std::path::Path;

use microsandbox_image::checkpoint::IntegrityReceipts;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Backend cache subdirectory holding integrity receipts, beside the memory cache.
pub const INTEGRITY_RECEIPTS_DIRECTORY: &str = "integrity";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Receipts for a runtime whose backend resolved its memory cache to `<cache>/memory`.
///
/// The launch contract carries only the memory cache directory, so the runtime derives the
/// sibling the backend uses rather than adding a field older runtimes would refuse.
pub fn integrity_receipts_beside(memory_cache_dir: &Path) -> Option<IntegrityReceipts> {
    memory_cache_dir
        .parent()
        .map(|cache| IntegrityReceipts::new(cache.join(INTEGRITY_RECEIPTS_DIRECTORY)))
}
