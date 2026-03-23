//! OCI image pulling, layer extraction, and caching for microsandbox.
//!
//! This crate implements the OCI image lifecycle:
//! - Registry communication (pull, auth, platform resolution)
//! - Layer caching with content-addressable dedup
//! - Layer extraction (async tar pipeline, stat virtualization, whiteouts)
//! - Binary sidecar index generation for OverlayFs acceleration

mod auth;
mod config;
mod digest;
mod error;
pub(crate) mod layer;
mod manifest;
mod platform;
mod progress;
mod pull;
mod registry;
mod store;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use auth::RegistryAuth;
pub use config::ImageConfig;
pub use digest::Digest;
pub use error::{ImageError, ImageResult};
pub use oci_client::Reference;
pub use platform::Platform;
pub use progress::{PullProgress, PullProgressHandle, PullProgressSender, progress_channel};
pub use pull::{PullOptions, PullPolicy, PullResult};
pub use registry::Registry;
pub use store::{CachedImageMetadata, CachedLayerMetadata, GlobalCache};
