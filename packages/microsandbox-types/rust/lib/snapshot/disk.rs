//! Pure canonical disk generations shared by snapshots and local checkpoint storage.

use crate::error::{SnapshotManifestError, SnapshotManifestResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Algorithm-qualified immutable object identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ObjectId(String);

/// One immutable disk layer in a complete oldest-first dependency closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskLayerRef {
    /// Stable layer identity.
    pub layer_id: String,
    /// Physical format (`raw` or `qcow2`).
    pub format: String,
    /// Guest-visible virtual size.
    pub virtual_size: u64,
    /// Exact physical file length; checked even when content integrity is not recorded.
    pub file_size: u64,
    /// Immediate predecessor when present.
    pub predecessor: Option<String>,
    /// Optional content integrity of the exact physical layer, independent of layer identity.
    pub integrity_root: Option<String>,
}

/// Immutable sealed disk generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskGenerationManifest {
    /// Schema identifier.
    pub schema: String,
    /// Logical writable volume identity.
    pub volume_id: String,
    /// Stable guest-visible block device whose bytes this generation captures.
    #[serde(
        default = "default_root_disk_device_id",
        skip_serializing_if = "is_default_root_disk_device_id"
    )]
    pub device_id: String,
    /// Monotonic immutable generation.
    pub generation: u64,
    /// Complete oldest-first physical closure.
    pub layers: Vec<DiskLayerRef>,
    /// Layer identity of the sealed head.
    pub head: String,
    /// VM-wide pause boundary at which the writable head was sealed.
    pub pause_generation: u64,
}

impl ObjectId {
    /// Compute an identity from exact bytes.
    pub fn from_bytes(bytes: &[u8]) -> SnapshotManifestResult<Self> {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self::new(format!("sha256:{}", hex::encode(hasher.finalize())))
    }

    /// Parse and validate an algorithm-qualified identity.
    pub fn new(value: impl Into<String>) -> SnapshotManifestResult<Self> {
        let value = value.into();
        let Some(encoded) = value.strip_prefix("sha256:") else {
            return Err(SnapshotManifestError::ManifestParse(
                "object identity must use sha256".into(),
            ));
        };
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(SnapshotManifestError::ManifestParse(format!(
                "invalid object identity: {value}"
            )));
        }
        Ok(Self(value))
    }

    /// Return the qualified identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the unqualified SHA-256 hexadecimal digest.
    pub fn hex(&self) -> &str {
        self.0.strip_prefix("sha256:").expect("validated identity")
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl TryFrom<String> for ObjectId {
    type Error = SnapshotManifestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ObjectId> for String {
    fn from(value: ObjectId) -> Self {
        value.0
    }
}

impl DiskGenerationManifest {
    fn validate_body(&self) -> SnapshotManifestResult<()> {
        if !portable_member_id(&self.volume_id)
            || !portable_member_id(&self.device_id)
            || self.generation == 0
            || self.layers.is_empty()
        {
            return manifest_error("disk generation has invalid identity, generation, or layers");
        }
        if self.layers.len() > 256 {
            return manifest_error("disk generation exceeds 256 layers");
        }
        if self.layers.last().map(|layer| layer.layer_id.as_str()) != Some(self.head.as_str()) {
            return manifest_error("disk head does not name the final layer");
        }
        for (index, layer) in self.layers.iter().enumerate() {
            if !portable_member_id(&layer.layer_id)
                || layer.virtual_size == 0
                || layer.file_size == 0
            {
                return manifest_error("disk layer has invalid identity or zero virtual size");
            }
            if let Some(root) = &layer.integrity_root {
                validate_blake3_root(root)?;
            }
            match (index, layer.format.as_str(), layer.predecessor.as_deref()) {
                (0, "raw" | "qcow2", None) => {}
                (_, "qcow2", Some(parent))
                    if parent == self.layers[index - 1].layer_id.as_str() => {}
                _ => return manifest_error("disk layer closure is not a valid oldest-first chain"),
            }
        }
        Ok(())
    }
}

fn validate_blake3_root(root: &str) -> SnapshotManifestResult<()> {
    let Some(encoded) = root.strip_prefix("blake3:") else {
        return manifest_error("disk layer integrity must use blake3");
    };
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return manifest_error("disk layer integrity has an invalid digest");
    }
    Ok(())
}

fn portable_member_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn default_root_disk_device_id() -> String {
    "vdb".into()
}

fn is_default_root_disk_device_id(value: &str) -> bool {
    value == "vdb"
}

impl DiskGenerationManifest {
    /// Validate the exact released disk generation contract.
    pub fn validate(&self) -> SnapshotManifestResult<()> {
        if self.schema != "microsandbox.disk-generation/1" {
            return manifest_error(format!(
                "unsupported schema {} (expected microsandbox.disk-generation/1)",
                self.schema
            ));
        }
        self.validate_body()
    }
    /// Serialize using the bounded canonical checkpoint encoding.
    pub fn to_canonical_bytes(&self) -> SnapshotManifestResult<Vec<u8>> {
        self.validate()?;
        let value = serde_json::to_value(self)
            .map_err(|error| manifest_error_value(format!("serialize failed: {error}")))?;
        let mut output = Vec::new();
        super::manifest::write_canonical_json(&value, &mut output)?;
        if output.len() > 8 * 1024 * 1024 {
            return manifest_error("manifest exceeds the encoded-size bound");
        }
        Ok(output)
    }
    /// Parse one complete, canonical disk generation.
    pub fn from_bytes(bytes: &[u8]) -> SnapshotManifestResult<Self> {
        if bytes.len() > 8 * 1024 * 1024 {
            return manifest_error("manifest exceeds the encoded-size bound");
        }
        super::manifest::reject_duplicate_json_keys(bytes)?;
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|error| manifest_error_value(format!("parse failed: {error}")))?;
        manifest.validate()?;
        if manifest.to_canonical_bytes()? != bytes {
            return manifest_error("stored manifest bytes are not canonical");
        }
        Ok(manifest)
    }
    /// Compute the immutable SHA-256 identity of canonical bytes.
    pub fn digest(&self) -> SnapshotManifestResult<ObjectId> {
        ObjectId::from_bytes(&self.to_canonical_bytes()?)
    }
}
fn manifest_error<T>(message: impl Into<String>) -> SnapshotManifestResult<T> {
    Err(manifest_error_value(message))
}
fn manifest_error_value(message: impl Into<String>) -> SnapshotManifestError {
    SnapshotManifestError::ManifestParse(format!("checkpoint manifest: {}", message.into()))
}
