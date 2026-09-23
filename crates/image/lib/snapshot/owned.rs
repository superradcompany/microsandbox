//! Filesystem verification and checkpoint resource bindings for owned snapshot storage.

#[cfg(test)]
use crate::checkpoint::DiskGenerationManifest;
use crate::checkpoint::ResourceDescriptor;
use crate::error::{ImageError, ImageResult};
pub use microsandbox_types::snapshot::owned::{
    OWNED_VOLUMES_EXTENSION, OwnedDirectoryPayload, OwnedMountSnapshot, OwnedVolumeCapture,
    OwnedVolumeData, validate_owned_volumes,
};
#[cfg(test)]
use microsandbox_types::{HostPermissions, OwnedVolumeStorage, StatVirtualization};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

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
                        file_size: 1024 * 1024,
                        virtual_size: 1024 * 1024,
                        predecessor: None,
                        integrity_root: Some(format!("blake3:{}", "a".repeat(64))),
                    },
                    crate::checkpoint::DiskLayerRef {
                        layer_id: "head".into(),
                        format: "qcow2".into(),
                        file_size: 1024 * 1024,
                        virtual_size: 1024 * 1024,
                        predecessor: Some("base".into()),
                        integrity_root: Some(format!("blake3:{}", "b".repeat(64))),
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
