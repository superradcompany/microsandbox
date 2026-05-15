//! OCI image pulling, EROFS materialization, and caching for microsandbox.
//!
//! This crate implements the OCI image lifecycle:
//! - Registry communication (pull, auth, platform resolution)
//! - Layer caching with content-addressable dedup
//! - Tar ingestion into in-memory file trees
//! - EROFS filesystem image generation (per-layer and flat modes)
//! - ext4 upper disk formatting for writable overlay upper layer
//! - Minimal EROFS reader for Append patches

// New lints introduced in rustc 1.95 fire on existing code; cleanup
// tracked separately.
#![allow(
    clippy::identity_op,
    clippy::useless_conversion,
    clippy::needless_update
)]

mod auth;
mod config;
pub(crate) mod crc32c;
mod digest;
pub mod erofs;
mod error;
pub mod ext4;
pub mod filetree;
pub(crate) mod layer;
pub(crate) mod lock;
mod manifest;
mod platform;
mod progress;
mod pull;
mod registry;
pub mod snapshot;
mod store;
pub mod tar_ingest;
pub mod vmdk;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use auth::RegistryAuth;
pub use config::ImageConfig;
pub use digest::Digest;
pub use error::{ImageError, ImageResult};
pub use oci_client::Reference;
pub use platform::{Arch, Os, Platform};
pub use progress::{PullProgress, PullProgressHandle, PullProgressSender, progress_channel};
pub use pull::{PullOptions, PullPolicy, PullResult};
pub use registry::{Registry, RegistryBuilder};
pub use store::{CachedImageMetadata, CachedLayerMetadata, GlobalCache};
