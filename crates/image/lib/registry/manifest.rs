//! OCI manifest and image index parsing.

use oci_spec::image::{ImageIndex, ImageManifest};

use crate::error::ImageError;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Parsed OCI manifest — either a single-platform manifest or a multi-platform index.
pub(crate) enum OciManifest {
    /// Single-platform image manifest.
    Image(Box<ImageManifest>),
    /// Multi-platform index (fat manifest).
    ///
    /// The inner `ImageIndex` is currently unused because `resolve_platform_manifest`
    /// re-parses from raw bytes. TODO: pass this through to avoid re-deserialization.
    Index(#[allow(dead_code)] Box<ImageIndex>),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl OciManifest {
    /// Parse from raw JSON bytes + media type.
    pub fn parse(bytes: &[u8], media_type: &str) -> Result<Self, ImageError> {
        match media_type {
            "application/vnd.oci.image.manifest.v1+json"
            | "application/vnd.docker.distribution.manifest.v2+json" => {
                let manifest: ImageManifest = serde_json::from_slice(bytes)
                    .map_err(|e| ImageError::ManifestParse(format!("image manifest: {e}")))?;
                Ok(Self::Image(Box::new(manifest)))
            }
            "application/vnd.oci.image.index.v1+json"
            | "application/vnd.docker.distribution.manifest.list.v2+json" => {
                let index: ImageIndex = serde_json::from_slice(bytes)
                    .map_err(|e| ImageError::ManifestParse(format!("image index: {e}")))?;
                Ok(Self::Index(Box::new(index)))
            }
            other => Err(ImageError::ManifestParse(format!(
                "unsupported manifest media type: {other}"
            ))),
        }
    }

    /// True if this is a multi-platform index.
    pub fn is_index(&self) -> bool {
        matches!(self, Self::Index(_))
    }

    /// Return the config blob digest for a single-platform manifest.
    pub fn config_digest(&self) -> Option<String> {
        match self {
            Self::Image(m) => Some(m.config().digest().to_string()),
            Self::Index(_) => None,
        }
    }
}
