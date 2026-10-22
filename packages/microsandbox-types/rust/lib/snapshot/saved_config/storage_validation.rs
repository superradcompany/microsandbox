//! Validation without filesystem access, host lookup, resource creation or waiver application.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::snapshot::Manifest;
use crate::{
    HostPermissions, MountOptions, OwnedVolumeStorage, SnapshotManifestResult, StatVirtualization,
    VolumeMount, VsockSocketType, canonicalize_volume_mounts, owned_volume_mount_id,
};

use super::inventory::record;
use super::validation::{
    MAX_GUEST_PATH_BYTES, MAX_NAME_BYTES, binding, count, decode, encoded_size, invalid,
};
use super::{
    SavedBindRootKind, SavedBindingConsumer, SavedBindingKind, SavedBindingUses, SavedMount,
    SavedMountOptions, SavedNamedStorage, SavedOrigin, SavedStorageConfig, SavedValue,
};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SavedStorageConfig {
    /// Decode portable storage/IPC requirements without touching source or destination paths.
    pub fn from_bytes(bytes: &[u8]) -> SnapshotManifestResult<Self> {
        let config: Self = decode(bytes, "active.storage")?;
        config.validate()?;
        Ok(config)
    }

    /// Enforce normalized guest identities, kind-specific policies and closed binding shapes.
    pub fn validate(&self) -> SnapshotManifestResult<()> {
        encoded_size(self, "active.storage")?;
        if let Some(mounts) = self.mounts.as_ref().and_then(SavedValue::value) {
            count(mounts.len(), "active.storage.mounts")?;
            let mut guests = BTreeSet::new();
            let mut owned_ids = BTreeSet::new();
            let mut previous = None;
            for mount in mounts {
                let guest = mount.guest();
                validate_guest(guest)?;
                if !guests.insert(guest) {
                    return invalid(
                        "SCFG_IDENTITY",
                        "active.storage.mounts",
                        "duplicate guest mount path",
                    );
                }
                let order = (guest.split('/').count(), guest);
                if previous.is_some_and(|previous| previous > order) {
                    return invalid(
                        "SCFG_IDENTITY",
                        "active.storage.mounts",
                        "mounts must use canonical parent-before-child order",
                    );
                }
                previous = Some(order);
                validate_mount(mount)?;
                if matches!(mount, SavedMount::RequestedOwned { .. })
                    && !matches!(
                        self.mounts,
                        Some(SavedValue::Value {
                            origin: SavedOrigin::Configured,
                            ..
                        })
                    )
                {
                    return invalid(
                        "SCFG_VALUE",
                        "active.storage.mounts",
                        "pending storage declarations require configured origin",
                    );
                }
                if let SavedMount::Owned { mount_id, .. } = mount
                    && !owned_ids.insert(mount_id)
                {
                    return invalid(
                        "SCFG_IDENTITY",
                        "active.storage.mounts.mount_id",
                        "duplicate owned mount identity",
                    );
                }
            }
        }
        if let Some(routes) = self.vsock.as_ref().and_then(SavedValue::value) {
            count(routes.len(), "active.storage.vsock")?;
            let mut identities = HashSet::new();
            for route in routes {
                binding(&route.binding.id, "active.storage.vsock.binding")?;
                if route.port == 0
                    || route.port == u32::MAX
                    || (route.socket_type == VsockSocketType::Dgram && route.port == 123)
                {
                    return invalid(
                        "SCFG_VALUE",
                        "active.storage.vsock.port",
                        "invalid or reserved vsock port",
                    );
                }
                if !identities.insert((route.port, route.socket_type)) {
                    return invalid(
                        "SCFG_IDENTITY",
                        "active.storage.vsock",
                        "duplicate socket type and port",
                    );
                }
            }
        }
        Ok(())
    }

    /// Reject next-start declarations before active selection, overrides or fresh mode.
    pub fn validate_active(&self) -> SnapshotManifestResult<()> {
        self.validate()?;
        if self
            .mounts
            .as_ref()
            .and_then(SavedValue::value)
            .is_some_and(|mounts| {
                mounts
                    .iter()
                    .any(|mount| matches!(mount, SavedMount::RequestedOwned { .. }))
            })
        {
            return invalid(
                "SCFG_VALUE",
                "active.storage.mounts",
                "pending storage declaration is not captured backing",
            );
        }
        Ok(())
    }

    /// Derive immediate resource consumers. Full resume additionally needs authoritative
    /// captured resource identity; matching this configuration alone is never sufficient.
    pub fn binding_uses(&self) -> SnapshotManifestResult<SavedBindingUses> {
        self.validate()?;
        let mut uses = BTreeMap::new();
        if let Some(mounts) = self.mounts.as_ref().and_then(SavedValue::value) {
            for mount in mounts {
                let (reference, kind) = match mount {
                    SavedMount::Bind {
                        binding, root_kind, ..
                    } => (
                        binding,
                        match root_kind {
                            SavedBindRootKind::File => SavedBindingKind::FilesystemFile,
                            SavedBindRootKind::Directory => SavedBindingKind::FilesystemDirectory,
                        },
                    ),
                    SavedMount::Named {
                        binding, storage, ..
                    } => (
                        binding,
                        match storage {
                            SavedNamedStorage::Directory { .. } => SavedBindingKind::NamedDirectory,
                            SavedNamedStorage::Disk { .. } => SavedBindingKind::NamedDisk,
                        },
                    ),
                    SavedMount::DiskImage { binding, .. } => (binding, SavedBindingKind::DiskImage),
                    SavedMount::Owned { .. }
                    | SavedMount::RequestedOwned { .. }
                    | SavedMount::Tmpfs { .. } => continue,
                };
                record(&mut uses, &reference.id, kind, SavedBindingConsumer::Mount)?;
            }
        }
        if let Some(routes) = self.vsock.as_ref().and_then(SavedValue::value) {
            for route in routes {
                let kind = match route.socket_type {
                    VsockSocketType::Stream => SavedBindingKind::StreamSocket,
                    VsockSocketType::Dgram => SavedBindingKind::DatagramSocket,
                };
                record(
                    &mut uses,
                    &route.binding.id,
                    kind,
                    SavedBindingConsumer::Vsock,
                )?;
            }
        }
        Ok(uses)
    }

    /// Validate references against existing authoritative private backing without rewriting it.
    /// A concrete mount list is complete; omissions/unknowns do not erase legacy requirements.
    pub fn validate_owned_projection(&self, manifest: &Manifest) -> SnapshotManifestResult<()> {
        self.validate_active()?;
        let owned = manifest.owned_volumes().map_err(|_| {
            super::validation::error(
                "SCFG_IDENTITY",
                "active.storage.mounts",
                "invalid authoritative owned-volume inventory",
            )
        })?;
        for volume in &owned {
            validate_guest(&volume.mount.guest)?;
            let options = SavedMountOptions::from(&volume.mount.options);
            match volume.mount.storage {
                OwnedVolumeStorage::Directory { .. } => validate_directory(
                    &options,
                    volume.mount.stat_virtualization,
                    volume.mount.host_permissions,
                )?,
                OwnedVolumeStorage::Disk { .. } => validate_disk_policy(
                    &options,
                    volume.mount.stat_virtualization,
                    volume.mount.host_permissions,
                )?,
            }
        }
        let Some(mounts) = self.mounts.as_ref().and_then(SavedValue::value) else {
            return Ok(());
        };
        let references: BTreeMap<_, _> = mounts
            .iter()
            .filter_map(|mount| match mount {
                SavedMount::Owned { guest, mount_id } => Some((mount_id.as_str(), guest.as_str())),
                _ => None,
            })
            .collect();
        if references.len() != owned.len()
            || owned.iter().any(|volume| {
                references.get(volume.mount_id.as_str()).copied()
                    != Some(volume.mount.guest.as_str())
            })
        {
            return invalid(
                "SCFG_IDENTITY",
                "active.storage.mounts",
                "owned references disagree with authoritative captured backing",
            );
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn validate_guest(guest: &str) -> SnapshotManifestResult<()> {
    if guest.len() > MAX_GUEST_PATH_BYTES || guest.contains('\0') {
        return invalid(
            "SCFG_VALUE",
            "active.storage.mounts.guest",
            "invalid guest mount path",
        );
    }
    // Reuse the cross-platform Unix guest-path grammar, not the host's Path rules.
    // This synthetic tmpfs is never created; it only exercises the shared normalizer.
    let mut probe = VolumeMount::Tmpfs {
        guest: guest.to_owned(),
        size_mib: None,
        options: MountOptions::default(),
    };
    canonicalize_volume_mounts(std::slice::from_mut(&mut probe)).map_err(|_| {
        super::validation::error(
            "SCFG_VALUE",
            "active.storage.mounts.guest",
            "invalid guest mount path",
        )
    })?;
    if probe.guest() != guest {
        return invalid(
            "SCFG_IDENTITY",
            "active.storage.mounts.guest",
            "guest mount path must already be canonical",
        );
    }
    Ok(())
}

fn validate_mount(mount: &SavedMount) -> SnapshotManifestResult<()> {
    match mount {
        SavedMount::RequestedOwned {
            storage,
            options,
            stat_virtualization,
            host_permissions,
            ..
        } => match storage {
            OwnedVolumeStorage::Directory { .. } => {
                validate_directory(options, *stat_virtualization, *host_permissions)?
            }
            OwnedVolumeStorage::Disk { capacity_mib } => {
                if *capacity_mib == 0 {
                    return invalid(
                        "SCFG_VALUE",
                        "active.storage.mounts.storage.capacity_mib",
                        "disk capacity must be positive",
                    );
                }
                validate_disk_policy(options, *stat_virtualization, *host_permissions)?;
            }
        },
        SavedMount::Owned { guest, mount_id } => {
            if owned_volume_mount_id(guest) != *mount_id {
                return invalid(
                    "SCFG_IDENTITY",
                    "active.storage.mounts.mount_id",
                    "owned identity does not match its guest path",
                );
            }
        }
        SavedMount::Bind {
            binding: reference,
            options,
            stat_virtualization,
            host_permissions,
            ..
        } => {
            binding(&reference.id, "active.storage.mounts.binding")?;
            validate_directory(options, *stat_virtualization, *host_permissions)?;
        }
        SavedMount::Named {
            binding: reference,
            storage,
            options,
            stat_virtualization,
            host_permissions,
            ..
        } => {
            binding(&reference.id, "active.storage.mounts.binding")?;
            match storage {
                SavedNamedStorage::Directory { .. } => {
                    validate_directory(options, *stat_virtualization, *host_permissions)?
                }
                SavedNamedStorage::Disk { capacity_mib } => {
                    if *capacity_mib == 0 {
                        return invalid(
                            "SCFG_VALUE",
                            "active.storage.mounts.storage.capacity_mib",
                            "disk capacity must be positive",
                        );
                    }
                    validate_disk_policy(options, *stat_virtualization, *host_permissions)?;
                }
            }
        }
        SavedMount::DiskImage {
            binding: reference,
            fstype,
            options,
            ..
        } => {
            binding(&reference.id, "active.storage.mounts.binding")?;
            validate_non_virtiofs(options)?;
            if fstype.as_ref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > MAX_NAME_BYTES
                    || value.contains([',', ';', ':', '='])
                    || value.chars().any(char::is_control)
            }) {
                return invalid(
                    "SCFG_VALUE",
                    "active.storage.mounts.fstype",
                    "invalid guest filesystem type",
                );
            }
        }
        SavedMount::Tmpfs { options, .. } => validate_non_virtiofs(options)?,
    }
    Ok(())
}

fn validate_directory(
    options: &SavedMountOptions,
    stat: StatVirtualization,
    host: HostPermissions,
) -> SnapshotManifestResult<()> {
    if options.override_uid.is_some() != options.override_gid.is_some() {
        return invalid(
            "SCFG_VALUE",
            "active.storage.mounts.options",
            "guest uid and gid must be paired",
        );
    }
    if stat == StatVirtualization::Off
        && (host == HostPermissions::Mirror || options.override_uid.is_some())
    {
        return invalid(
            "SCFG_VALUE",
            "active.storage.mounts.options",
            "literal host metadata conflicts with mirroring or guest ownership overrides",
        );
    }
    Ok(())
}

fn validate_non_virtiofs(options: &SavedMountOptions) -> SnapshotManifestResult<()> {
    if options.override_uid.is_some() || options.override_gid.is_some() {
        return invalid(
            "SCFG_VALUE",
            "active.storage.mounts.options",
            "guest ownership overrides require a filesystem overlay",
        );
    }
    Ok(())
}

fn validate_disk_policy(
    options: &SavedMountOptions,
    stat: StatVirtualization,
    host: HostPermissions,
) -> SnapshotManifestResult<()> {
    validate_non_virtiofs(options)?;
    if stat != StatVirtualization::Strict || host != HostPermissions::Private {
        return invalid(
            "SCFG_VALUE",
            "active.storage.mounts.options",
            "disk storage cannot apply directory metadata policies",
        );
    }
    Ok(())
}
