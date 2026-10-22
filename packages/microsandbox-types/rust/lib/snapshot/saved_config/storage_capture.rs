//! Explicit portable projections that never read or clone source-host paths/names.

use crate::{SnapshotManifestResult, VolumeMount, VsockRouteSpec, owned_volume_mount_id};

use super::validation::invalid;
use super::{
    SavedBindRootKind, SavedBindingReference, SavedMount, SavedMountOptions, SavedNamedStorage,
    SavedOrigin, SavedStorageConfig, SavedValue, SavedVsockRoute,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Caller-supplied binding and active backing evidence. Capture must obtain this under
/// its coherent source guard; it cannot infer named-volume storage from creation intent.
#[derive(Clone)]
pub enum SavedExternalMountCapture {
    /// Observed bind root kind, with a caller-selected logical destination reference.
    Bind {
        binding: SavedBindingReference,
        root_kind: SavedBindRootKind,
    },
    /// Resolved active named storage, not an unrelated same-named destination resource.
    Named {
        binding: SavedBindingReference,
        storage: SavedNamedStorage,
    },
    /// External disk image; its public format/options are copied from the guarded source.
    DiskImage { binding: SavedBindingReference },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SavedMount {
    /// Preserve declared owned-storage policy without inventing a captured payload ID.
    /// Other mount kinds use the existing logical external-reference projection.
    pub fn requested_owned_from_source(source: &VolumeMount) -> SnapshotManifestResult<Self> {
        let VolumeMount::Owned {
            guest,
            storage,
            options,
            stat_virtualization,
            host_permissions,
        } = source
        else {
            return invalid(
                "SCFG_VALUE",
                "pending.storage.mounts",
                "expected an owned-storage declaration",
            );
        };
        let mount = Self::RequestedOwned {
            guest: guest.clone(),
            storage: storage.clone(),
            options: SavedMountOptions::from(options),
            stat_virtualization: *stat_virtualization,
            host_permissions: *host_permissions,
        };
        SavedStorageConfig {
            mounts: Some(SavedValue::Value {
                value: vec![mount.clone()],
                origin: SavedOrigin::Configured,
            }),
            ..Default::default()
        }
        .validate()?;
        Ok(mount)
    }

    /// Project a normalized active source mount, excluding source host paths, volume names,
    /// transient creation metadata and implicit destination authorization.
    pub fn from_source(
        source: &VolumeMount,
        external: Option<SavedExternalMountCapture>,
    ) -> SnapshotManifestResult<Self> {
        // Exhaustive destructuring deliberately fails compilation when source mount
        // fields change, so new host-affecting or secret fields need a policy decision.
        let mount = match (source, external) {
            (
                VolumeMount::Owned {
                    guest,
                    storage: _,
                    options: _,
                    stat_virtualization: _,
                    host_permissions: _,
                },
                None,
            ) => Self::Owned {
                guest: guest.clone(),
                mount_id: owned_volume_mount_id(guest),
            },
            (
                VolumeMount::Bind {
                    host: _,
                    guest,
                    options,
                    stat_virtualization,
                    host_permissions,
                    follow_root_symlinks,
                    quota_mib,
                },
                Some(SavedExternalMountCapture::Bind { binding, root_kind }),
            ) => Self::Bind {
                guest: guest.clone(),
                binding,
                root_kind,
                options: SavedMountOptions::from(options),
                stat_virtualization: *stat_virtualization,
                host_permissions: *host_permissions,
                follow_root_symlinks: *follow_root_symlinks,
                quota_mib: *quota_mib,
            },
            (
                VolumeMount::Named {
                    name: _,
                    guest,
                    create: _,
                    options,
                    stat_virtualization,
                    host_permissions,
                    follow_root_symlinks,
                },
                Some(SavedExternalMountCapture::Named { binding, storage }),
            ) => Self::Named {
                guest: guest.clone(),
                binding,
                storage,
                options: SavedMountOptions::from(options),
                stat_virtualization: *stat_virtualization,
                host_permissions: *host_permissions,
                follow_root_symlinks: *follow_root_symlinks,
            },
            (
                VolumeMount::DiskImage {
                    host: _,
                    guest,
                    format,
                    fstype,
                    options,
                },
                Some(SavedExternalMountCapture::DiskImage { binding }),
            ) => Self::DiskImage {
                guest: guest.clone(),
                binding,
                format: *format,
                fstype: fstype.clone(),
                options: SavedMountOptions::from(options),
            },
            (
                VolumeMount::Tmpfs {
                    guest,
                    size_mib,
                    options,
                },
                None,
            ) => Self::Tmpfs {
                guest: guest.clone(),
                size_mib: *size_mib,
                options: SavedMountOptions::from(options),
            },
            _ => {
                return invalid(
                    "SCFG_BINDING",
                    "active.storage.mounts",
                    "source mount requires matching destination binding and backing evidence",
                );
            }
        };
        let projected = SavedStorageConfig {
            mounts: Some(SavedValue::Value {
                value: vec![mount.clone()],
                origin: SavedOrigin::Observed,
            }),
            ..Default::default()
        };
        projected.validate()?;
        Ok(mount)
    }
}

impl SavedVsockRoute {
    /// Copy guest port/type, replacing the source host endpoint with a logical binding.
    pub fn from_source(
        source: &VsockRouteSpec,
        binding: SavedBindingReference,
    ) -> SnapshotManifestResult<Self> {
        let VsockRouteSpec {
            host_socket: _,
            port,
            socket_type,
        } = source;
        let route = Self {
            port: *port,
            socket_type: *socket_type,
            binding,
        };
        SavedStorageConfig {
            vsock: Some(SavedValue::Value {
                value: vec![route.clone()],
                origin: SavedOrigin::Observed,
            }),
            ..Default::default()
        }
        .validate()?;
        Ok(route)
    }
}
