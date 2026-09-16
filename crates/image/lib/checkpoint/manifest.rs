//! Canonical schemas for one same-epoch checkpoint closure.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::{ImageError, ImageResult};

use super::ObjectId;

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
    /// A user-requested full snapshot.
    FullSnapshot,
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

pub use microsandbox_types::snapshot::disk::{DiskGenerationManifest, DiskLayerRef};

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

/// Original construction layout, independent of live CPU/memory resize targets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointGeometry {
    /// CPU count supplied at construction, not the current online count.
    pub vcpus: u8,
    /// Number of possible CPUs constructed for this VM.
    pub max_vcpus: u8,
    /// Initially populated RAM in MiB; hotplug RAM occupies a separate address range.
    pub memory_mib: u32,
    /// Reserved RAM capacity in MiB, including the initial RAM.
    pub max_memory_mib: u32,
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
    /// Immutable layout required to reconstruct the captured address space and devices.
    pub geometry: CheckpointGeometry,
    /// VM-wide pause boundary shared by every captured participant.
    pub pause_generation: u64,
    /// Encoded hypervisor execution state.
    pub execution_state: ObjectId,
    /// Complete logical memory-generation manifest.
    pub memory: ObjectId,
    /// Sealed disk-generation manifests.
    pub disks: Vec<ObjectId>,
    /// Required lifetime-owned backing. Older strict checkpoint readers refuse this field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owned_volumes: Vec<crate::snapshot::OwnedVolumeCapture>,
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

impl CheckpointManifest {
    fn validate_body(&self) -> ImageResult<()> {
        if self.checkpoint_id.is_empty() || self.architecture.is_empty() {
            return manifest_error("checkpoint is missing identity or architecture");
        }
        if self.geometry.vcpus == 0
            || self.geometry.vcpus > self.geometry.max_vcpus
            || self.geometry.memory_mib == 0
            || self.geometry.memory_mib > self.geometry.max_memory_mib
        {
            return manifest_error("checkpoint has invalid construction geometry");
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
        crate::snapshot::validate_owned_volumes(&self.owned_volumes)?;
        crate::snapshot::validate_owned_resources(&self.owned_volumes, &self.resources)?;
        for volume in &self.owned_volumes {
            if let crate::snapshot::OwnedVolumeData::Disk { generation } = &volume.data
                && generation.pause_generation != self.pause_generation
            {
                return manifest_error("owned disk belongs to another checkpoint epoch");
            }
        }
        Ok(())
    }
}

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
// Macros
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
                Ok(ObjectId::from_bytes(&self.to_canonical_bytes()?)?)
            }
        }
    };
}

manifest_methods!(MemoryManifest, "microsandbox.memory/1");
manifest_methods!(CheckpointManifest, "microsandbox.checkpoint/1");

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_checkpoint_requires_valid_original_geometry() {
        let object = ObjectId::from_bytes(b"state").unwrap();
        let mut manifest = CheckpointManifest {
            schema: "microsandbox.checkpoint/1".into(),
            checkpoint_id: "checkpoint_geometry".into(),
            capture_intent: CaptureIntent::FullSnapshot,
            architecture: "aarch64".into(),
            geometry: CheckpointGeometry {
                vcpus: 2,
                max_vcpus: 8,
                memory_mib: 8192,
                max_memory_mib: 32768,
            },
            pause_generation: 1,
            execution_state: object.clone(),
            memory: object,
            disks: Vec::new(),
            devices: Vec::new(),
            resources: Vec::new(),
            owned_volumes: Vec::new(),
            requires: Vec::new(),
        };
        let bytes = manifest.to_canonical_bytes().unwrap();
        assert_eq!(CheckpointManifest::from_bytes(&bytes).unwrap(), manifest);
        // Earlier development full captures cannot reconstruct hotplug topology reliably.
        let mut old = serde_json::to_value(&manifest).unwrap();
        old.as_object_mut().unwrap().remove("geometry");
        assert!(CheckpointManifest::from_bytes(&serde_json::to_vec(&old).unwrap()).is_err());
        let original_geometry = manifest.geometry;
        for geometry in [
            CheckpointGeometry {
                vcpus: 0,
                ..original_geometry
            },
            CheckpointGeometry {
                max_vcpus: 1,
                ..original_geometry
            },
            CheckpointGeometry {
                memory_mib: 0,
                ..original_geometry
            },
            CheckpointGeometry {
                max_memory_mib: 4096,
                ..original_geometry
            },
        ] {
            manifest.geometry = geometry;
            assert!(manifest.to_canonical_bytes().is_err());
        }
    }

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

    #[test]
    fn disk_layer_identity_cannot_escape_the_closure_directory() {
        let manifest = DiskGenerationManifest {
            schema: "microsandbox.disk-generation/1".into(),
            volume_id: "vol_test".into(),
            device_id: "vdb".into(),
            generation: 1,
            layers: vec![DiskLayerRef {
                file_size: 4096,
                layer_id: "../outside".into(),
                format: "raw".into(),
                virtual_size: 4096,
                predecessor: None,
                integrity_root: Some(format!("blake3:{}", "0".repeat(64))),
            }],
            head: "../outside".into(),
            pause_generation: 1,
        };

        assert!(manifest.validate().is_err());
    }

    #[test]
    fn earlier_disk_generation_defaults_to_managed_device() {
        let manifest = DiskGenerationManifest {
            schema: "microsandbox.disk-generation/1".into(),
            volume_id: "vol_test".into(),
            device_id: "vdb".into(),
            generation: 1,
            layers: vec![DiskLayerRef {
                file_size: 4096,
                layer_id: "layer_test".into(),
                format: "raw".into(),
                virtual_size: 4096,
                predecessor: None,
                integrity_root: Some(format!("blake3:{}", "0".repeat(64))),
            }],
            head: "layer_test".into(),
            pause_generation: 1,
        };
        let mut value = serde_json::to_value(manifest).unwrap();
        value.as_object_mut().unwrap().remove("device_id");
        let parsed =
            DiskGenerationManifest::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(parsed.device_id, "vdb");
    }
}
