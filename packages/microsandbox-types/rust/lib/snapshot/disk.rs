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

/// Immutable caller-managed image that a generation's oldest layer reads through.
///
/// The base is not a member of the closure. Captures, snapshots and archives record only this
/// identity; every restore must be supplied a file that matches it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalDiskBase {
    /// Physical format; only `raw` is supported.
    pub format: String,
    /// Guest-visible size, equal to every layer's virtual size.
    pub virtual_size: u64,
    /// Exact physical file length.
    pub file_size: u64,
    /// Sparse BLAKE3 root of the exact base file, as recorded for sealed layers.
    pub integrity_root: String,
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
    /// Immutable base the oldest layer reads through, held by reference and never captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_base: Option<ExternalDiskBase>,
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
        if let Some(base) = &self.external_base {
            if base.format != "raw"
                || base.virtual_size == 0
                || !base.virtual_size.is_multiple_of(512)
                || base.file_size != base.virtual_size
            {
                return manifest_error("external disk base must be a sector-aligned raw image");
            }
            validate_blake3_root(&base.integrity_root)?;
            if self.layers[0].format != "qcow2" {
                return manifest_error(
                    "a disk over an external base must start with a qcow2 layer",
                );
            }
            if self
                .layers
                .iter()
                .any(|layer| layer.virtual_size != base.virtual_size)
            {
                return manifest_error("disk layers and their external base differ in size");
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

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn root(digit: char) -> String {
        format!("blake3:{}", digit.to_string().repeat(64))
    }

    fn generation(format: &str, external_base: Option<ExternalDiskBase>) -> DiskGenerationManifest {
        DiskGenerationManifest {
            schema: "microsandbox.disk-generation/1".into(),
            volume_id: "vol_a".into(),
            device_id: "data_0123abcd".into(),
            generation: 1,
            layers: vec![DiskLayerRef {
                layer_id: "layer_a".into(),
                format: format.into(),
                virtual_size: MIB,
                file_size: 4096,
                predecessor: None,
                integrity_root: Some(root('a')),
            }],
            head: "layer_a".into(),
            pause_generation: 1,
            external_base,
        }
    }

    fn base() -> ExternalDiskBase {
        ExternalDiskBase {
            format: "raw".into(),
            virtual_size: MIB,
            file_size: MIB,
            integrity_root: root('b'),
        }
    }

    #[test]
    fn external_base_needs_a_qcow2_first_layer_of_its_size() {
        generation("qcow2", Some(base())).validate().unwrap();
        assert!(generation("raw", Some(base())).validate().is_err());
        let mut wrong_size = base();
        wrong_size.virtual_size = 2 * MIB;
        wrong_size.file_size = 2 * MIB;
        assert!(generation("qcow2", Some(wrong_size)).validate().is_err());
        let mut qcow2_base = base();
        qcow2_base.format = "qcow2".into();
        assert!(generation("qcow2", Some(qcow2_base)).validate().is_err());
        let mut sparse_length = base();
        sparse_length.file_size = 4096;
        assert!(generation("qcow2", Some(sparse_length)).validate().is_err());
        let mut bad_root = base();
        bad_root.integrity_root = "sha256:00".into();
        assert!(generation("qcow2", Some(bad_root)).validate().is_err());
    }

    #[test]
    fn generations_without_a_base_keep_their_encoding() {
        let plain = serde_json::to_value(generation("raw", None)).unwrap();
        assert!(plain.get("external_base").is_none());
        let based = serde_json::to_value(generation("qcow2", Some(base()))).unwrap();
        assert_eq!(based["external_base"]["format"], "raw");
        let decoded: DiskGenerationManifest = serde_json::from_value(based).unwrap();
        assert_eq!(decoded.external_base, Some(base()));
    }
}
