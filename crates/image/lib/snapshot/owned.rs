//! Required snapshot inventory for storage whose lifetime belongs to one sandbox.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use microsandbox_types::{
    HostPermissions, MountOptions, OwnedVolumeStorage, StatVirtualization, VolumeMount,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::Manifest;
use crate::checkpoint::{DiskGenerationManifest, ResourceDescriptor};
use crate::error::{ImageError, ImageResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Must-understand extension for complete, privately restored sandbox-owned storage.
pub const OWNED_VOLUMES_EXTENSION: &str = "microsandbox.owned-volumes";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One immutable regular payload, addressed by its exact SHA-256 bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedDirectoryPayload {
    /// Lowercase unqualified SHA-256 digest.
    pub digest: String,
    /// Exact logical length, including sparse holes.
    pub bytes: u64,
}

/// Complete captured backing for one owned mount.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum OwnedVolumeData {
    /// A complete immutable disk chain using the existing layer store.
    Disk {
        /// Captured bytes and their guest-visible block identity.
        generation: DiskGenerationManifest,
    },
    /// A namespace descriptor and all linked or detached regular-file payloads.
    Directory {
        /// Identity of `owned/<mount_id>/directory.bin`.
        descriptor: OwnedDirectoryPayload,
        /// Sorted unique content payloads under `owned/<mount_id>/files/`.
        files: Vec<OwnedDirectoryPayload>,
    },
}

/// Required ownership and content inventory; never contains a caller-selected host path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedVolumeCapture {
    /// Stable mount tag derived by the launcher from the canonical guest path.
    pub mount_id: String,
    /// Lossless owned mount configuration, including guest metadata and mount policies.
    pub mount: OwnedMountSnapshot,
    /// Complete private backing required before child activation.
    pub data: OwnedVolumeData,
}

/// Owned-only mount metadata; its type cannot encode an external host binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedMountSnapshot {
    /// Canonical guest destination.
    pub guest: String,
    /// Directory quota or disk capacity.
    pub storage: OwnedVolumeStorage,
    /// Common mount flags and owner policy.
    pub options: MountOptions,
    /// Directory stat virtualization policy.
    pub stat_virtualization: StatVirtualization,
    /// Directory host-permission policy.
    pub host_permissions: HostPermissions,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Manifest {
    /// Record required owned state without changing the released root-layer semantics.
    pub fn set_owned_volumes(&mut self, volumes: Vec<OwnedVolumeCapture>) -> ImageResult<()> {
        validate_owned_volumes(&volumes)?;
        self.requires.retain(|key| key != OWNED_VOLUMES_EXTENSION);
        if volumes.is_empty() {
            self.extensions.remove(OWNED_VOLUMES_EXTENSION);
        } else {
            self.extensions.insert(
                OWNED_VOLUMES_EXTENSION.into(),
                serde_json::to_value(volumes)
                    .map_err(|error| ImageError::ManifestParse(error.to_string()))?,
            );
            self.requires.push(OWNED_VOLUMES_EXTENSION.into());
            self.requires.sort();
        }
        Ok(())
    }

    /// Read and validate the required inventory; released snapshots have no owned mounts.
    pub fn owned_volumes(&self) -> ImageResult<Vec<OwnedVolumeCapture>> {
        let Some(value) = self.extensions.get(OWNED_VOLUMES_EXTENSION) else {
            return Ok(Vec::new());
        };
        if !self
            .requires
            .iter()
            .any(|key| key == OWNED_VOLUMES_EXTENSION)
        {
            return invalid("owned volumes must be a required snapshot extension");
        }
        let volumes: Vec<OwnedVolumeCapture> = serde_json::from_value(value.clone())
            .map_err(|error| ImageError::ManifestParse(format!("owned volumes: {error}")))?;
        validate_owned_volumes(&volumes)?;
        Ok(volumes)
    }
}

impl OwnedVolumeCapture {
    /// Relative directory containing this mount's immutable filesystem generation.
    pub fn directory_path(&self) -> PathBuf {
        Path::new("owned").join(&self.mount_id)
    }

    /// Enumerate only required directory files; disk layers use the existing disk inventory.
    pub fn directory_payloads(&self) -> Vec<(PathBuf, &OwnedDirectoryPayload)> {
        match &self.data {
            OwnedVolumeData::Disk { .. } => Vec::new(),
            OwnedVolumeData::Directory { descriptor, files } => {
                let directory = self.directory_path();
                std::iter::once((directory.join("directory.bin"), descriptor))
                    .chain(
                        files
                            .iter()
                            .map(|file| (directory.join("files").join(&file.digest), file)),
                    )
                    .collect()
            }
        }
    }
}

impl OwnedMountSnapshot {
    /// Extract only sandbox-owned configuration from a public mount value.
    pub fn from_mount(mount: &VolumeMount) -> ImageResult<Self> {
        let VolumeMount::Owned {
            guest,
            storage,
            options,
            stat_virtualization,
            host_permissions,
        } = mount
        else {
            return invalid("owned volume inventory contains an external mount");
        };
        Ok(Self {
            guest: guest.clone(),
            storage: storage.clone(),
            options: *options,
            stat_virtualization: *stat_virtualization,
            host_permissions: *host_permissions,
        })
    }

    /// Reconstruct the lossless public owned discriminant after private materialization.
    pub fn to_mount(&self) -> VolumeMount {
        VolumeMount::Owned {
            guest: self.guest.clone(),
            storage: self.storage.clone(),
            options: self.options,
            stat_virtualization: self.stat_virtualization,
            host_permissions: self.host_permissions,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate confined identities and the agreement between ownership and captured backing.
pub fn validate_owned_volumes(volumes: &[OwnedVolumeCapture]) -> ImageResult<()> {
    if volumes.len() > 256 {
        return invalid("owned volume count exceeds the format bound");
    }
    let mut ids = BTreeSet::new();
    let mut guests = BTreeSet::new();
    for volume in volumes {
        if volume.mount_id.is_empty()
            || volume.mount_id.len() > 128
            || !volume
                .mount_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            || !ids.insert(&volume.mount_id)
            || !guests.insert(volume.mount.guest.as_str())
        {
            return invalid("owned volume has an invalid or repeated mount identity");
        }
        let guest = &volume.mount.guest;
        let storage = &volume.mount.storage;
        if microsandbox_types::owned_volume_mount_id(guest) != volume.mount_id {
            return invalid("owned volume mount identity differs from its guest path");
        }
        if guest == "/"
            || !guest.starts_with('/')
            || guest
                .split('/')
                .skip(1)
                .any(|part| matches!(part, "" | "." | ".."))
        {
            return invalid("owned volume guest path is not canonical");
        }
        match (storage, &volume.data) {
            (OwnedVolumeStorage::Disk { capacity_mib }, OwnedVolumeData::Disk { generation }) => {
                generation.validate()?;
                if *capacity_mib == 0
                    || generation.device_id != volume.mount_id
                    || generation
                        .layers
                        .iter()
                        .any(|layer| layer.virtual_size != u64::from(*capacity_mib) * 1024 * 1024)
                {
                    return invalid("owned disk generation differs from its storage specification");
                }
            }
            (
                OwnedVolumeStorage::Directory { .. },
                OwnedVolumeData::Directory { descriptor, files },
            ) => {
                validate_payload(descriptor)?;
                let mut previous = None;
                for payload in files {
                    validate_payload(payload)?;
                    if previous.is_some_and(|digest: &str| digest >= payload.digest.as_str()) {
                        return invalid("owned directory payloads must be sorted and unique");
                    }
                    previous = Some(payload.digest.as_str());
                }
            }
            _ => return invalid("owned volume storage and captured backing kinds differ"),
        }
    }
    Ok(())
}

/// Require a one-to-one binding between owned runtime resources and their captured backing.
/// A missing inventory must not turn a formerly owned device into an optional external mount.
pub fn validate_owned_resources(
    volumes: &[OwnedVolumeCapture],
    resources: &[ResourceDescriptor],
) -> ImageResult<()> {
    let mut matched = BTreeSet::new();
    for resource in resources {
        let directory = resource
            .binding
            .get("role")
            .is_some_and(|role| role == "owned_directory");
        let disk = resource
            .binding
            .get("lifecycle_owned")
            .is_some_and(|owned| owned == "true");
        if !directory && !disk {
            continue;
        }
        if directory && disk {
            return invalid("owned resource has conflicting storage roles");
        }
        let id = resource
            .binding
            .get(if directory { "guest_tag" } else { "device_id" })
            .ok_or_else(|| {
                ImageError::ManifestParse("owned resource has no mount identity".into())
            })?;
        let volume = volumes
            .iter()
            .find(|volume| volume.mount_id == *id)
            .ok_or_else(|| {
                ImageError::ManifestParse("owned resource has no required captured backing".into())
            })?;
        if !matched.insert(id)
            || directory != matches!(volume.data, OwnedVolumeData::Directory { .. })
        {
            return invalid("owned resource binding is duplicated or has the wrong storage kind");
        }
        if disk && resource.binding.get("guest_path") != Some(&volume.mount.guest) {
            return invalid("owned disk resource guest path differs from its inventory");
        }
    }
    if matched.len() != volumes.len() {
        return invalid("owned captured backing has no corresponding runtime resource");
    }
    Ok(())
}

/// Verify every required namespace/data file without following archive-provided symlinks.
pub fn verify_owned_directory_payloads(
    root: &Path,
    volumes: &[OwnedVolumeCapture],
) -> ImageResult<()> {
    validate_owned_volumes(volumes)?;
    for volume in volumes {
        if !matches!(volume.data, OwnedVolumeData::Directory { .. }) {
            continue;
        }
        for directory in [
            root.join("owned"),
            root.join(volume.directory_path()),
            root.join(volume.directory_path()).join("files"),
        ] {
            if !std::fs::symlink_metadata(directory)?.file_type().is_dir() {
                return invalid("owned directory payload parent is not a directory");
            }
        }
        for (path, expected) in volume.directory_payloads() {
            let path = root.join(path);
            let metadata = std::fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_file() || metadata.len() != expected.bytes {
                return invalid("owned directory payload is missing or has a different size");
            }
            let mut file = File::open(path)?;
            let mut hasher = Sha256::new();
            let mut bytes = [0; 64 * 1024];
            loop {
                let count = file.read(&mut bytes)?;
                if count == 0 {
                    break;
                }
                hasher.update(&bytes[..count]);
            }
            if hex::encode(hasher.finalize()) != expected.digest {
                return invalid("owned directory payload digest differs");
            }
        }
    }
    Ok(())
}

fn validate_payload(payload: &OwnedDirectoryPayload) -> ImageResult<()> {
    if payload.digest.len() != 64
        || !payload
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid("owned directory payload has an invalid SHA-256 identity");
    }
    Ok(())
}

fn invalid<T>(message: &str) -> ImageResult<T> {
    Err(ImageError::ManifestParse(message.into()))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::checkpoint::ResourceTreatment;

    use super::*;

    fn directory(guest: &str) -> OwnedVolumeCapture {
        OwnedVolumeCapture {
            mount_id: microsandbox_types::owned_volume_mount_id(guest),
            mount: OwnedMountSnapshot {
                guest: guest.into(),
                storage: OwnedVolumeStorage::Directory { quota_mib: None },
                options: Default::default(),
                stat_virtualization: StatVirtualization::Strict,
                host_permissions: HostPermissions::Private,
            },
            data: OwnedVolumeData::Directory {
                descriptor: OwnedDirectoryPayload {
                    digest: "a".repeat(64),
                    bytes: 20,
                },
                files: Vec::new(),
            },
        }
    }

    fn disk() -> OwnedVolumeCapture {
        let mut volume = directory("/data");
        volume.mount.storage = OwnedVolumeStorage::Disk { capacity_mib: 1 };
        volume.data = OwnedVolumeData::Disk {
            generation: DiskGenerationManifest {
                schema: "microsandbox.disk-generation/1".into(),
                volume_id: "owned".into(),
                device_id: volume.mount_id.clone(),
                generation: 2,
                head: "head".into(),
                pause_generation: 2,
                layers: vec![
                    crate::checkpoint::DiskLayerRef {
                        layer_id: "base".into(),
                        format: "raw".into(),
                        virtual_size: 1024 * 1024,
                        predecessor: None,
                        integrity_root: format!("blake3:{}", "a".repeat(64)),
                    },
                    crate::checkpoint::DiskLayerRef {
                        layer_id: "head".into(),
                        format: "qcow2".into(),
                        virtual_size: 1024 * 1024,
                        predecessor: Some("base".into()),
                        integrity_root: format!("blake3:{}", "b".repeat(64)),
                    },
                ],
            },
        };
        volume
    }

    #[test]
    fn owned_disk_accepts_complete_raw_and_compacted_qcow2_chains() {
        let mut volume = disk();
        validate_owned_volumes(std::slice::from_ref(&volume)).unwrap();
        let OwnedVolumeData::Disk { generation } = &mut volume.data else {
            unreachable!()
        };
        generation.layers[0].format = "qcow2".into();
        validate_owned_volumes(std::slice::from_ref(&volume)).unwrap();
        let OwnedVolumeData::Disk { generation } = &mut volume.data else {
            unreachable!()
        };
        generation.layers.truncate(1);
        generation.head = "base".into();
        validate_owned_volumes(&[volume]).unwrap();
    }

    #[test]
    fn owned_disk_chain_refuses_wrong_capacity_device_or_predecessor() {
        for mismatch in ["capacity", "device", "predecessor", "raw-successor"] {
            let mut volume = disk();
            let OwnedVolumeData::Disk { generation } = &mut volume.data else {
                unreachable!()
            };
            match mismatch {
                "capacity" => generation.layers[1].virtual_size *= 2,
                "device" => generation.device_id = "other".into(),
                "predecessor" => generation.layers[1].predecessor = Some("missing".into()),
                "raw-successor" => generation.layers[1].format = "raw".into(),
                _ => unreachable!(),
            }
            assert!(validate_owned_volumes(&[volume]).is_err(), "{mismatch}");
        }
    }

    #[test]
    fn owned_inventory_preserves_unicode_and_refuses_rebinding_or_duplicates() {
        let volume = directory("/缓存 data");
        validate_owned_volumes(std::slice::from_ref(&volume)).unwrap();
        let bytes = serde_json::to_vec(&volume).unwrap();
        assert_eq!(
            serde_json::from_slice::<OwnedVolumeCapture>(&bytes).unwrap(),
            volume
        );
        assert!(validate_owned_volumes(&[volume.clone(), volume.clone()]).is_err());
        let mut changed = volume;
        changed.mount.guest = "/other".into();
        assert!(validate_owned_volumes(&[changed]).is_err());
        for guest in ["/", "/cache/../other", "/cache//nested", "relative"] {
            assert!(validate_owned_volumes(&[directory(guest)]).is_err());
        }
    }

    #[test]
    fn owned_runtime_resources_cannot_lose_their_required_inventory() {
        let volume = directory("/cache");
        let resource = ResourceDescriptor {
            id: "virtio_fs2".into(),
            kind: "filesystem".into(),
            treatment: ResourceTreatment::Serialize,
            binding: BTreeMap::from([
                ("role".into(), "owned_directory".into()),
                ("guest_tag".into(), volume.mount_id.clone()),
            ]),
        };
        validate_owned_resources(
            std::slice::from_ref(&volume),
            std::slice::from_ref(&resource),
        )
        .unwrap();
        assert!(validate_owned_resources(&[], std::slice::from_ref(&resource)).is_err());
        assert!(validate_owned_resources(std::slice::from_ref(&volume), &[]).is_err());
        assert!(validate_owned_resources(&[volume], &[resource.clone(), resource]).is_err());
    }

    #[test]
    fn owned_payload_inventory_refuses_prefixed_or_unsorted_hashes() {
        let mut volume = directory("/cache");
        let OwnedVolumeData::Directory { descriptor, .. } = &mut volume.data else {
            unreachable!()
        };
        descriptor.digest = format!("sha256:{}", "a".repeat(64));
        assert!(validate_owned_volumes(std::slice::from_ref(&volume)).is_err());
        let OwnedVolumeData::Directory { descriptor, files } = &mut volume.data else {
            unreachable!()
        };
        descriptor.digest = "a".repeat(64);
        files.extend([
            OwnedDirectoryPayload {
                digest: "b".repeat(64),
                bytes: 2,
            },
            OwnedDirectoryPayload {
                digest: "a".repeat(64),
                bytes: 1,
            },
        ]);
        assert!(validate_owned_volumes(&[volume]).is_err());
    }
}
