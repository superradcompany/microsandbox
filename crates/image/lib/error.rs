//! Error types for image operations.

use std::path::PathBuf;

use crate::platform::{Arch, Os};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Errors that can occur during image operations.
#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    /// Network or registry communication error.
    #[error("registry error: {0}")]
    Registry(#[from] oci_client::errors::OciDistributionError),

    /// No manifest found matching the requested platform.
    #[error("no manifest for platform {os}/{arch} in {reference}")]
    PlatformNotFound {
        /// The image reference.
        reference: String,
        /// Requested OS.
        os: Os,
        /// Requested architecture.
        arch: Arch,
    },

    /// OCI manifest or index parsing failed.
    #[error("manifest parse error: {0}")]
    ManifestParse(String),

    /// OCI image config parsing failed.
    #[error("config parse error: {0}")]
    ConfigParse(String),

    /// Layer download hash mismatch (possible corruption or tampering).
    #[error("digest mismatch for layer {digest}: expected {expected}, got {actual}")]
    DigestMismatch {
        /// The layer digest.
        digest: String,
        /// Expected hash.
        expected: String,
        /// Actual computed hash.
        actual: String,
    },

    /// Layer extraction failed.
    #[error("extraction failed for layer {digest}: {message}")]
    Extraction {
        /// The layer digest.
        digest: String,
        /// Error detail.
        message: String,
        /// The underlying error.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Sidecar index generation failed.
    #[error("index generation failed for layer {0}: {1}")]
    IndexBuild(String, #[source] std::io::Error),

    /// Cache I/O error.
    #[error("cache error at {}: {source}", path.display())]
    Cache {
        /// The path that caused the error.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Image not found in local cache (PullPolicy::Never).
    #[error("image not cached: {reference}")]
    NotCached {
        /// The image reference.
        reference: String,
    },

    /// General I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

//--------------------------------------------------------------------------------------------------
// Type Aliases
//--------------------------------------------------------------------------------------------------

/// Result type for image operations.
pub type ImageResult<T> = Result<T, ImageError>;
