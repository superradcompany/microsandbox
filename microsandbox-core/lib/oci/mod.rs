//! OCI (Open Container Initiative) module for interacting with container registries.
//!
//! This module provides functionality for:
//! - Pulling container images from OCI-compliant registries
//! - Parsing and validating image references (tags and digests)
//! - Managing image manifests, configurations, and layers

mod global_cache;
mod image;
mod layer;
#[cfg(test)]
pub(crate) mod mocks;
mod reference;
mod registry;
#[cfg(test)]
mod tests;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub(crate) use global_cache::*;
pub use image::*;
pub(crate) use layer::*;
pub use reference::*;
pub(crate) use registry::*;
