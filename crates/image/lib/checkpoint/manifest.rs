//! Canonical schemas for one same-epoch checkpoint closure.

use std::collections::BTreeMap;

use super::ObjectId;
use crate::error::{ImageError, ImageResult};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_COMPONENTS: usize = 4096;
const MAX_MEMORY_EXTENTS: usize = 4 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Why a checkpoint was captured.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureIntent {
    /// A user-requested resumable snapshot.
    ResumableSnapshot,
    /// A local idle/park checkpoint.
    Park,
    /// A transparent continuity operation.
    TransparentTransfer,
}

/// Whether memory bytes were produced completely or from a retained runtime baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryCaptureMode {
    /// Every ordinary memory range was read.
    Full,
    /// Only dirty ranges were read; unchanged references were reused.
    Incremental,
}

/// A byte range backed by one immutable object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRef {
    /// Object containing the bytes.
    pub object: ObjectId,
    /// Byte offset within the object.
    pub object_offset: u64,
}

/// Content of one memory range.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum MemoryExtentContent {
    /// Exact bytes stored in an immutable object.
    Object(ContentRef),
    /// An all-zero range that requires no object.
    Zero,
}

/// One sorted, non-overlapping memory range.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryExtent {
    /// Guest-physical start address.
    pub start: u64,
    /// Non-zero range length.
    pub length: u64,
    /// Range content.
    pub content: MemoryExtentContent,
}

/// Complete logical memory generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryManifest {
    /// Schema identifier.
    pub schema: String,
    /// Guest architecture.
    pub architecture: String,
    /// Guest page size in bytes.
    pub guest_page_size: u64,
    /// Runtime-local memory topology generation.
    pub topology_generation: u64,
    /// Published memory content generation.
    pub generation: u64,
    /// How bytes for this generation were produced.
    pub capture_mode: MemoryCaptureMode,
    /// VM-wide pause boundary shared with execution and device state.
    pub pause_generation: u64,
    /// Complete sorted logical content table.
    pub extents: Vec<MemoryExtent>,
}

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
    /// Immediate predecessor when present.
    pub predecessor: Option<String>,
    /// Sparse-aware BLAKE3 Merkle identity of the exact physical layer.
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
    /// Monotonic immutable generation.
    pub generation: u64,
    /// Complete oldest-first physical closure.
    pub layers: Vec<DiskLayerRef>,
    /// Layer identity of the sealed head.
    pub head: String,
    /// VM-wide pause boundary at which the writable head was sealed.
    pub pause_generation: u64,
}

/// Treatment selected for a runtime resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceTreatment {
    /// Exact reusable state is serialized.
    Serialize,
    /// Destination reconstructs a host binding before activation.
    Reconnect,
    /// The resource deliberately starts a fresh observation/session epoch.
    Reset,
    /// The resource makes this checkpoint ineligible.
    Reject,
}

/// Frozen logical resource-plan entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDescriptor {
    /// Stable resource identity within the VM.
    pub id: String,
    /// Resource family.
    pub kind: String,
    /// Selected treatment.
    pub treatment: ResourceTreatment,
    /// Restore-relevant logical binding, excluding host-local paths.
    pub binding: BTreeMap<String, String>,
}

/// One device-state object bound to its logical resource.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceStateRef {
    /// Virtio device type.
    pub device_type: u32,
    /// Stable device identifier.
    pub device_id: String,
    /// Encoded transport/device state object.
    pub state: ObjectId,
}

/// Root manifest binding one complete same-epoch checkpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointManifest {
    /// Schema identifier.
    pub schema: String,
    /// Stable checkpoint identity.
    pub checkpoint_id: String,
    /// Capture purpose.
    pub capture_intent: CaptureIntent,
    /// Guest architecture.
    pub architecture: String,
    /// VM-wide pause boundary shared by every captured participant.
    pub pause_generation: u64,
    /// Encoded hypervisor execution state.
    pub execution_state: ObjectId,
    /// Complete logical memory-generation manifest.
    pub memory: ObjectId,
    /// Sealed disk-generation manifests.
    pub disks: Vec<ObjectId>,
    /// Device transport/state objects.
    pub devices: Vec<DeviceStateRef>,
    /// Frozen resource plan used for admission and restore.
    pub resources: Vec<ResourceDescriptor>,
    /// Namespaced must-understand extensions.
    pub requires: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

macro_rules! manifest_methods {
    ($type:ty, $schema:literal) => {
        impl $type {
            /// Validate structural and same-record invariants.
            pub fn validate(&self) -> ImageResult<()> {
                if self.schema != $schema {
                    return manifest_error(format!(
                        "unsupported schema {} (expected {})",
                        self.schema, $schema
                    ));
                }
                self.validate_body()
            }

            /// Serialize this manifest using the repository's bounded RFC 8785 subset.
            pub fn to_canonical_bytes(&self) -> ImageResult<Vec<u8>> {
                self.validate()?;
                canonical_bytes(self)
            }

            /// Parse and validate one complete canonical manifest.
            pub fn from_bytes(bytes: &[u8]) -> ImageResult<Self> {
                parse_manifest(bytes)
            }

            /// Compute the immutable SHA-256 identity of canonical bytes.
            pub fn digest(&self) -> ImageResult<ObjectId> {
                ObjectId::from_bytes(&self.to_canonical_bytes()?)
            }
        }
    };
}

impl MemoryManifest {
    fn validate_body(&self) -> ImageResult<()> {
        if self.architecture.is_empty() || self.guest_page_size == 0 || self.generation == 0 {
            return manifest_error("memory manifest has empty architecture or zero geometry");
        }
        if self.extents.len() > MAX_MEMORY_EXTENTS {
            return manifest_error("memory extent count exceeds the format bound");
        }
        validate_extents(&self.extents)
    }
}

impl DiskGenerationManifest {
    fn validate_body(&self) -> ImageResult<()> {
        if self.volume_id.is_empty() || self.generation == 0 || self.layers.is_empty() {
            return manifest_error("disk generation is missing identity, generation, or layers");
        }
        if self.layers.len() > 256 {
            return manifest_error("disk generation exceeds 256 layers");
        }
        if self.layers.last().map(|layer| layer.layer_id.as_str()) != Some(self.head.as_str()) {
            return manifest_error("disk head does not name the final layer");
        }
        for (index, layer) in self.layers.iter().enumerate() {
            if layer.layer_id.is_empty() || layer.virtual_size == 0 {
                return manifest_error("disk layer has empty identity or zero virtual size");
            }
            validate_blake3_root(&layer.integrity_root)?;
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

fn validate_blake3_root(root: &str) -> ImageResult<()> {
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

impl CheckpointManifest {
    fn validate_body(&self) -> ImageResult<()> {
        if self.checkpoint_id.is_empty() || self.architecture.is_empty() {
            return manifest_error("checkpoint is missing identity or architecture");
        }
        if self.disks.len() > MAX_COMPONENTS
            || self.devices.len() > MAX_COMPONENTS
            || self.resources.len() > MAX_COMPONENTS
        {
            return manifest_error("checkpoint component count exceeds the format bound");
        }
        let mut devices = std::collections::BTreeSet::new();
        for device in &self.devices {
            if !devices.insert((device.device_type, device.device_id.as_str())) {
                return manifest_error("checkpoint contains a duplicate logical device");
            }
        }
        let mut resources = std::collections::BTreeSet::new();
        for resource in &self.resources {
            if resource.id.is_empty() || resource.kind.is_empty() || !resources.insert(&resource.id)
            {
                return manifest_error("checkpoint contains an invalid or duplicate resource");
            }
            if resource.treatment == ResourceTreatment::Reject {
                return manifest_error("published checkpoint contains a rejected resource");
            }
        }
        if self.requires.windows(2).any(|pair| pair[0] >= pair[1]) {
            return manifest_error("checkpoint requires must be sorted and unique");
        }
        Ok(())
    }
}

manifest_methods!(MemoryManifest, "microsandbox.memory/1");
manifest_methods!(DiskGenerationManifest, "microsandbox.disk-generation/1");
manifest_methods!(CheckpointManifest, "microsandbox.checkpoint/1");

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn validate_extents(extents: &[MemoryExtent]) -> ImageResult<()> {
    let mut previous_end = 0u64;
    for (index, extent) in extents.iter().enumerate() {
        if extent.length == 0 {
            return manifest_error("memory extent has zero length");
        }
        let end = extent
            .start
            .checked_add(extent.length)
            .ok_or_else(|| manifest_error_value("memory extent overflows the address space"))?;
        if index != 0 && extent.start < previous_end {
            return manifest_error("memory extents overlap or are unsorted");
        }
        if let MemoryExtentContent::Object(content) = &extent.content {
            content
                .object_offset
                .checked_add(extent.length)
                .ok_or_else(|| manifest_error_value("memory object slice overflows"))?;
        }
        previous_end = end;
    }
    Ok(())
}

fn canonical_bytes<T: Serialize>(manifest: &T) -> ImageResult<Vec<u8>> {
    let value = serde_json::to_value(manifest)
        .map_err(|error| manifest_error_value(format!("serialize failed: {error}")))?;
    let mut output = Vec::new();
    crate::snapshot::manifest::write_canonical_json(&value, &mut output)?;
    if output.len() > MAX_MANIFEST_BYTES {
        return manifest_error("manifest exceeds the encoded-size bound");
    }
    Ok(output)
}

fn parse_manifest<T>(bytes: &[u8]) -> ImageResult<T>
where
    T: DeserializeOwned + Serialize + Validate,
{
    if bytes.len() > MAX_MANIFEST_BYTES {
        return manifest_error("manifest exceeds the encoded-size bound");
    }
    crate::snapshot::manifest::reject_duplicate_json_keys(bytes)?;
    let manifest: T = serde_json::from_slice(bytes)
        .map_err(|error| manifest_error_value(format!("parse failed: {error}")))?;
    manifest.validate_manifest()?;
    if canonical_bytes(&manifest)? != bytes {
        return manifest_error("stored manifest bytes are not canonical");
    }
    Ok(manifest)
}

trait Validate {
    fn validate_manifest(&self) -> ImageResult<()>;
}

impl Validate for MemoryManifest {
    fn validate_manifest(&self) -> ImageResult<()> {
        self.validate()
    }
}

impl Validate for DiskGenerationManifest {
    fn validate_manifest(&self) -> ImageResult<()> {
        self.validate()
    }
}

impl Validate for CheckpointManifest {
    fn validate_manifest(&self) -> ImageResult<()> {
        self.validate()
    }
}

fn manifest_error<T>(message: impl Into<String>) -> ImageResult<T> {
    Err(manifest_error_value(message))
}

fn manifest_error_value(message: impl Into<String>) -> ImageError {
    ImageError::ManifestParse(format!("checkpoint manifest: {}", message.into()))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incremental_memory_manifest_may_slice_reused_objects() {
        let object = ObjectId::from_bytes(b"memory").unwrap();
        let manifest = MemoryManifest {
            schema: "microsandbox.memory/1".into(),
            architecture: "aarch64".into(),
            guest_page_size: 4096,
            topology_generation: 1,
            generation: 2,
            capture_mode: MemoryCaptureMode::Incremental,
            pause_generation: 42,
            extents: vec![MemoryExtent {
                start: 0,
                length: 4096,
                content: MemoryExtentContent::Object(ContentRef {
                    object,
                    object_offset: 4096,
                }),
            }],
        };

        let bytes = manifest.to_canonical_bytes().unwrap();
        assert_eq!(MemoryManifest::from_bytes(&bytes).unwrap(), manifest);
    }
}
