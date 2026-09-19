//! Required snapshot inventory for storage whose lifetime belongs to one sandbox.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::{HostPermissions, MountOptions, OwnedVolumeStorage, StatVirtualization, VolumeMount};
use serde::{Deserialize, Serialize};

use super::Manifest;
use super::disk::DiskGenerationManifest;
use crate::error::{SnapshotManifestError, SnapshotManifestResult};

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
    pub fn set_owned_volumes(
        &mut self,
        volumes: Vec<OwnedVolumeCapture>,
    ) -> SnapshotManifestResult<()> {
        validate_owned_volumes(&volumes)?;
        self.requires.retain(|key| key != OWNED_VOLUMES_EXTENSION);
        if volumes.is_empty() {
            self.extensions.remove(OWNED_VOLUMES_EXTENSION);
        } else {
            self.extensions.insert(
                OWNED_VOLUMES_EXTENSION.into(),
                serde_json::to_value(volumes)
                    .map_err(|error| SnapshotManifestError::ManifestParse(error.to_string()))?,
            );
            self.requires.push(OWNED_VOLUMES_EXTENSION.into());
            self.requires.sort();
        }
        Ok(())
    }

    /// Read and validate the required inventory; released snapshots have no owned mounts.
    pub fn owned_volumes(&self) -> SnapshotManifestResult<Vec<OwnedVolumeCapture>> {
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
        let volumes: Vec<OwnedVolumeCapture> =
            serde_json::from_value(value.clone()).map_err(|error| {
                SnapshotManifestError::ManifestParse(format!("owned volumes: {error}"))
            })?;
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
    pub fn from_mount(mount: &VolumeMount) -> SnapshotManifestResult<Self> {
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
pub fn validate_owned_volumes(volumes: &[OwnedVolumeCapture]) -> SnapshotManifestResult<()> {
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
        if crate::owned_volume_mount_id(guest) != volume.mount_id {
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

fn validate_payload(payload: &OwnedDirectoryPayload) -> SnapshotManifestResult<()> {
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

fn invalid<T>(message: &str) -> SnapshotManifestResult<T> {
    Err(SnapshotManifestError::ManifestParse(message.into()))
}
