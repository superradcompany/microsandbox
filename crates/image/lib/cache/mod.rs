pub(crate) mod lock;
mod store;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub(crate) use store::is_valid_erofs_artifact;
pub(crate) use store::is_valid_erofs_artifact_async;
pub(crate) use store::parse_cached_image_metadata;
pub use store::{CachedImageMetadata, CachedLayerMetadata, GlobalCache};
