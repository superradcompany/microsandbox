//! Keyed storage/IPC selection, before destination I/O, permissions or identity admission.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use microsandbox_types::snapshot::OwnedVolumeCapture;
use microsandbox_types::snapshot::saved_config::{
    SavedBindingUses, SavedMount, SavedMountOptions, SavedNamedStorage, SavedStorageConfig,
    SavedValue, SavedVsockRoute,
};
use microsandbox_types::{
    HostPermissions, MountOptions, SandboxSpecPatch, StatVirtualization, VolumeMount,
    VsockRouteSpec, VsockSocketType, canonicalize_volume_mounts, owned_volume_mount_id,
};

use crate::{
    MicrosandboxError, MicrosandboxResult,
    snapshot::{Manifest, SnapshotScope},
};

use super::SnapshotConfigMode;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One guest identity with its source requirements and optional destination input.
/// A destination path is not proof of physical backing identity or authorization.
#[derive(Clone)]
pub struct MountInputSelection {
    /// Canonical guest path; ordering is parent before child.
    pub guest: String,
    /// Retained source semantics, including owned backing references.
    pub saved: Option<SavedMount>,
    /// Explicit destination mapping; host paths retain their original resolution policy.
    pub destination: Option<VolumeMount>,
    /// This guest path requires external backing; empty owned/tmpfs state cannot satisfy it.
    pub external_required: bool,
}

/// Independent stream/datagram port namespaces retain unsupplied source routes.
#[derive(Clone)]
pub struct VsockInputSelection {
    /// Guest host-CID port.
    pub port: u32,
    /// Stream/datagram namespace.
    pub socket_type: VsockSocketType,
    /// Original resource requirement, if one was recorded.
    pub saved: Option<SavedVsockRoute>,
    /// Explicit destination endpoint, never copied into portable metadata.
    pub destination: Option<VsockRouteSpec>,
}

/// Saved filesystem behavior requiring separate, field-specific destination intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageRelaxation {
    /// Propagate guest permission changes to host backing.
    MirrorHostPermissions,
    /// Tolerate missing metadata-overlay support.
    RelaxedStatVirtualization,
    /// Disable the metadata overlay entirely.
    DisabledStatVirtualization,
    /// Follow symlinks while resolving the destination mount root.
    FollowRootSymlinks,
}

/// An obligation to obtain destination permission, not permission encoded in an artifact.
#[derive(Clone, PartialEq, Eq)]
pub struct StorageApprovalRequirement {
    /// Exact guest identity whose selected saved behavior needs approval.
    pub guest: String,
    /// The particular behavior; no blanket trust switch is implied.
    pub relaxation: StorageRelaxation,
}

/// A plan requiring further binding, permission, physical identity and policy checks.
pub struct StorageInputSelection {
    /// All retained requirements plus explicit new disk-boot mounts.
    pub mounts: Vec<MountInputSelection>,
    /// All retained IPC requirements plus permitted destination routes.
    pub vsock: Vec<VsockInputSelection>,
    /// Source binding uses still unsatisfied by explicit per-resource mappings.
    pub remaining_bindings: SavedBindingUses,
    /// Saved relaxations still requiring explicit destination intent.
    pub required_approvals: Vec<StorageApprovalRequirement>,
    /// Recorded unknown sections; explicit partial mappings do not make them known.
    pub unknown_fields: BTreeSet<&'static str>,
    /// Every full plan must pass authoritative captured-resource checks before activation.
    pub requires_full_identity: bool,
    /// Whether saved metadata enumerated the complete source mount list.
    pub mount_inventory_complete: bool,
    /// Whether saved metadata enumerated the complete source IPC route list.
    pub vsock_inventory_complete: bool,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for MountInputSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MountInputSelection")
            .field("has_saved_requirement", &self.saved.is_some())
            .field("has_destination", &self.destination.is_some())
            .field("external_required", &self.external_required)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for VsockInputSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VsockInputSelection")
            .field("has_saved_requirement", &self.saved.is_some())
            .field("has_destination", &self.destination.is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for StorageInputSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageInputSelection")
            .field("mount_count", &self.mounts.len())
            .field("route_count", &self.vsock.len())
            .field("binding_count", &self.remaining_bindings.len())
            .field("approval_count", &self.required_approvals.len())
            .field("requires_full_identity", &self.requires_full_identity)
            .field("unknown_fields", &self.unknown_fields)
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Match explicit inputs by guest path or (socket type, port), retaining other requirements.
///
/// Fresh mode does not waive captured mounts or required host bindings. This function
/// never opens a host path, creates a volume, reads source-local state or grants a waiver.
/// Callers must retain the original explicit-input provenance and finish activation checks.
pub fn select_storage_inputs(
    saved: &SavedStorageConfig,
    manifest: &Manifest,
    explicit: &SandboxSpecPatch,
    _config_mode: SnapshotConfigMode,
    full_resume: bool,
) -> MicrosandboxResult<StorageInputSelection> {
    if full_resume && manifest.scope != SnapshotScope::Full {
        return Err(error(
            "SCFG_MODE",
            "storage",
            "full resume requires a full snapshot",
        ));
    }
    saved
        .validate_owned_projection(manifest)
        .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))?;
    saved
        .binding_uses()
        .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))?;
    let SavedStorageConfig {
        mounts: saved_mounts,
        vsock: saved_vsock,
    } = saved;
    let mount_inventory_complete = complete(saved_mounts);
    let vsock_inventory_complete = complete(saved_vsock);
    let mut mounts = BTreeMap::new();
    if let Some(source) = saved_mounts.as_ref().and_then(SavedValue::value) {
        for mount in source {
            mounts.insert(
                mount.guest().to_owned(),
                MountInputSelection {
                    guest: mount.guest().to_owned(),
                    saved: Some(mount.clone()),
                    destination: None,
                    external_required: external(mount),
                },
            );
        }
    }
    // An omitted/unknown optional section cannot erase authoritative owned backing.
    let owned_volumes = manifest
        .owned_volumes()
        .map_err(|_| error("SCFG_IDENTITY", "storage.mounts", "invalid owned inventory"))?;
    for owned in &owned_volumes {
        mounts
            .entry(owned.mount.guest.clone())
            .or_insert_with(|| MountInputSelection {
                guest: owned.mount.guest.clone(),
                saved: Some(SavedMount::Owned {
                    guest: owned.mount.guest.clone(),
                    mount_id: owned.mount_id.clone(),
                }),
                destination: None,
                external_required: false,
            });
    }
    for guest in legacy_external_guests(manifest)? {
        match mounts.get_mut(&guest) {
            Some(entry) if entry.saved.as_ref().is_some_and(external) => {
                entry.external_required = true
            }
            Some(_) => {
                return Err(error(
                    "SCFG_IDENTITY",
                    "storage.mounts",
                    "external and owned/tmpfs requirements conflict",
                ));
            }
            None if mount_inventory_complete => {
                return Err(error(
                    "SCFG_IDENTITY",
                    "storage.mounts",
                    "complete saved mount list omits recorded external backing",
                ));
            }
            None => {
                mounts.insert(
                    guest.clone(),
                    MountInputSelection {
                        guest,
                        saved: None,
                        destination: None,
                        external_required: true,
                    },
                );
            }
        }
    }
    let mut destinations = explicit.mounts.clone().unwrap_or_default();
    canonicalize_volume_mounts(&mut destinations).map_err(|_| {
        error(
            "SCFG_IDENTITY",
            "storage.mounts",
            "invalid or duplicate destination guest paths",
        )
    })?;
    for destination in destinations {
        let guest = destination.guest().to_owned();
        if full_resume && mount_inventory_complete && !mounts.contains_key(&guest) {
            return Err(error(
                "SCFG_FULL_STATE",
                "storage.mounts",
                "full resume cannot add a guest mount",
            ));
        }
        let entry = mounts
            .entry(guest.clone())
            .or_insert_with(|| MountInputSelection {
                guest,
                saved: None,
                destination: None,
                external_required: false,
            });
        admit_mount_shape(entry, &destination, full_resume)?;
        entry.destination = Some(destination);
    }
    // New disk-boot owned mounts share the released backing namespace with
    // captured owned references. Distinct guest paths can collide in its short hash.
    let mut owned_ids = BTreeSet::new();
    for entry in mounts.values() {
        let id = match (&entry.saved, &entry.destination) {
            (Some(SavedMount::Owned { mount_id, .. }), _) => Some(mount_id.clone()),
            (_, Some(VolumeMount::Owned { .. })) => Some(owned_volume_mount_id(&entry.guest)),
            _ => None,
        };
        if id.is_some_and(|id| !owned_ids.insert(id)) {
            return Err(error(
                "SCFG_IDENTITY",
                "storage.mounts",
                "distinct guest paths collide in the owned backing namespace",
            ));
        }
    }
    let mut routes = BTreeMap::new();
    if let Some(source) = saved_vsock.as_ref().and_then(SavedValue::value) {
        for route in source {
            routes.insert(
                route_key(route.port, route.socket_type),
                VsockInputSelection {
                    port: route.port,
                    socket_type: route.socket_type,
                    saved: Some(route.clone()),
                    destination: None,
                },
            );
        }
    }
    let mut explicit_routes = BTreeSet::new();
    for route in explicit.vsock.routes.iter().flatten() {
        validate_port(route.port, route.socket_type)?;
        let key = route_key(route.port, route.socket_type);
        if !explicit_routes.insert(key) {
            return Err(error(
                "SCFG_IDENTITY",
                "storage.vsock",
                "duplicate destination socket type and port",
            ));
        }
        if full_resume && vsock_inventory_complete && !routes.contains_key(&key) {
            return Err(error(
                "SCFG_FULL_STATE",
                "storage.vsock",
                "full resume cannot add an IPC route",
            ));
        }
        let entry = routes.entry(key).or_insert_with(|| VsockInputSelection {
            port: route.port,
            socket_type: route.socket_type,
            saved: None,
            destination: None,
        });
        entry.destination = Some(route.clone());
    }
    // Remove only consumers that got an explicit mapping. A shared binding ID can
    // still be required by another mount/route; never erase the entire ID by name.
    let mut remaining = saved.clone();
    if let Some(SavedValue::Value { value, .. }) = &mut remaining.mounts {
        value.retain(|mount| mounts[mount.guest()].destination.is_none());
    }
    if let Some(SavedValue::Value { value, .. }) = &mut remaining.vsock {
        value.retain(|route| {
            routes[&route_key(route.port, route.socket_type)]
                .destination
                .is_none()
        });
    }
    let remaining_bindings = remaining
        .binding_uses()
        .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))?;
    let mut mounts: Vec<_> = mounts.into_values().collect();
    mounts.sort_by(|a, b| {
        (a.guest.split('/').count(), &a.guest).cmp(&(b.guest.split('/').count(), &b.guest))
    });
    let required_approvals = approval_requirements(&mounts, &owned_volumes);
    let unknown_fields = [
        (
            "storage.mounts",
            matches!(saved_mounts, Some(SavedValue::Unknown { .. })),
        ),
        (
            "storage.vsock",
            matches!(saved_vsock, Some(SavedValue::Unknown { .. })),
        ),
    ]
    .into_iter()
    .filter_map(|(path, unknown)| unknown.then_some(path))
    .collect();
    Ok(StorageInputSelection {
        mounts,
        vsock: routes.into_values().collect(),
        remaining_bindings,
        required_approvals,
        unknown_fields,
        requires_full_identity: full_resume,
        mount_inventory_complete,
        vsock_inventory_complete,
    })
}

fn admit_mount_shape(
    entry: &MountInputSelection,
    destination: &VolumeMount,
    full: bool,
) -> MicrosandboxResult<()> {
    if matches!(entry.saved, Some(SavedMount::Owned { .. })) {
        return Err(error(
            "SCFG_IDENTITY",
            "storage.mounts",
            "captured owned backing cannot be replaced by a destination mount",
        ));
    }
    if entry.external_required
        && matches!(
            destination,
            VolumeMount::Owned { .. } | VolumeMount::Tmpfs { .. }
        )
    {
        return Err(error(
            "SCFG_IDENTITY",
            "storage.mounts",
            "recorded external backing cannot be replaced with empty owned or tmpfs state",
        ));
    }
    if !full {
        return Ok(());
    }
    if matches!(
        destination,
        VolumeMount::Owned { .. }
            | VolumeMount::Named {
                create: Some(_),
                ..
            }
    ) {
        return Err(error(
            "SCFG_FULL_STATE",
            "storage.mounts",
            "full resume cannot provision new backing",
        ));
    }
    let Some(saved) = &entry.saved else {
        return Ok(());
    };
    match (saved, destination) {
        (
            SavedMount::Tmpfs {
                size_mib, options, ..
            },
            VolumeMount::Tmpfs {
                size_mib: target_size,
                options: target_options,
                ..
            },
        ) if size_mib == target_size && *options == SavedMountOptions::from(target_options) => {
            return Ok(());
        }
        (SavedMount::Tmpfs { .. }, _) | (_, VolumeMount::Tmpfs { .. }) => {
            return Err(error(
                "SCFG_FULL_STATE",
                "storage.mounts",
                "captured tmpfs layout and flags cannot change",
            ));
        }
        (
            SavedMount::Bind { .. }
            | SavedMount::Named {
                storage: SavedNamedStorage::Directory { .. },
                ..
            },
            VolumeMount::DiskImage { .. },
        )
        | (
            SavedMount::DiskImage { .. }
            | SavedMount::Named {
                storage: SavedNamedStorage::Disk { .. },
                ..
            },
            VolumeMount::Bind { .. },
        ) => {
            return Err(error(
                "SCFG_FULL_STATE",
                "storage.mounts",
                "captured filesystem/block resource kind cannot change",
            ));
        }
        (
            SavedMount::DiskImage { format, fstype, .. },
            VolumeMount::DiskImage {
                format: target_format,
                fstype: target_fstype,
                ..
            },
        ) if format != target_format
            || matches!((fstype, target_fstype), (Some(source), Some(target)) if source != target) =>
        {
            return Err(error(
                "SCFG_FULL_STATE",
                "storage.mounts",
                "captured disk format and filesystem cannot change",
            ));
        }
        _ => {}
    }
    let saved_options = match saved {
        SavedMount::Bind { options, .. }
        | SavedMount::Named { options, .. }
        | SavedMount::DiskImage { options, .. }
        | SavedMount::Tmpfs { options, .. } => options,
        SavedMount::Owned { .. } | SavedMount::RequestedOwned { .. } => {
            return Err(error(
                "SCFG_IDENTITY",
                "storage.mounts",
                "captured owned backing cannot be replaced",
            ));
        }
    };
    let target_options = match destination {
        VolumeMount::Bind { options, .. }
        | VolumeMount::Named { options, .. }
        | VolumeMount::Owned { options, .. }
        | VolumeMount::DiskImage { options, .. }
        | VolumeMount::Tmpfs { options, .. } => options,
    };
    if *saved_options != SavedMountOptions::from(target_options) {
        return Err(error(
            "SCFG_FULL_STATE",
            "storage.mounts",
            "full resume must retain captured mount flags and guest ownership",
        ));
    }
    Ok(())
}

fn approval_requirements(
    mounts: &[MountInputSelection],
    owned: &[OwnedVolumeCapture],
) -> Vec<StorageApprovalRequirement> {
    let mut requirements = Vec::new();
    for selected in mounts
        .iter()
        .filter(|selected| selected.destination.is_none())
    {
        let policy = match selected.saved.as_ref() {
            Some(
                SavedMount::Bind {
                    stat_virtualization,
                    host_permissions,
                    follow_root_symlinks,
                    ..
                }
                | SavedMount::Named {
                    stat_virtualization,
                    host_permissions,
                    follow_root_symlinks,
                    ..
                },
            ) => Some((
                *stat_virtualization,
                *host_permissions,
                *follow_root_symlinks,
            )),
            Some(SavedMount::Owned { mount_id, .. }) => owned
                .iter()
                .find(|volume| volume.mount_id == *mount_id)
                .map(|volume| {
                    (
                        volume.mount.stat_virtualization,
                        volume.mount.host_permissions,
                        false,
                    )
                }),
            _ => None,
        };
        let Some((stat, permissions, follow)) = policy else {
            continue;
        };
        let mut require = |relaxation| {
            requirements.push(StorageApprovalRequirement {
                guest: selected.guest.clone(),
                relaxation,
            })
        };
        match stat {
            StatVirtualization::Strict => {}
            StatVirtualization::Relaxed => require(StorageRelaxation::RelaxedStatVirtualization),
            StatVirtualization::Off => require(StorageRelaxation::DisabledStatVirtualization),
        }
        match permissions {
            HostPermissions::Private => {}
            HostPermissions::Mirror => require(StorageRelaxation::MirrorHostPermissions),
        }
        if follow {
            require(StorageRelaxation::FollowRootSymlinks);
        }
    }
    requirements
}

fn complete<T>(value: &Option<SavedValue<T>>) -> bool {
    matches!(
        value,
        Some(SavedValue::Value { .. } | SavedValue::Default {})
    )
}

fn external(mount: &SavedMount) -> bool {
    matches!(
        mount,
        SavedMount::Bind { .. } | SavedMount::Named { .. } | SavedMount::DiskImage { .. }
    )
}

fn route_key(port: u32, socket_type: VsockSocketType) -> (u32, u8) {
    (
        port,
        match socket_type {
            VsockSocketType::Stream => 0,
            VsockSocketType::Dgram => 1,
        },
    )
}

fn validate_port(port: u32, socket_type: VsockSocketType) -> MicrosandboxResult<()> {
    if port == 0 || port == u32::MAX || (port == 123 && socket_type == VsockSocketType::Dgram) {
        return Err(error(
            "SCFG_VALUE",
            "storage.vsock",
            "invalid or reserved destination port",
        ));
    }
    Ok(())
}

fn legacy_external_guests(manifest: &Manifest) -> MicrosandboxResult<Vec<String>> {
    let paths = manifest.external_mounts().map_err(|_| {
        error(
            "SCFG_IDENTITY",
            "storage.mounts",
            "invalid recorded external inventory",
        )
    })?;
    let mut guests = BTreeSet::new();
    for guest in paths {
        let mut probe = VolumeMount::Tmpfs {
            guest,
            size_mib: None,
            options: MountOptions::default(),
        };
        canonicalize_volume_mounts(std::slice::from_mut(&mut probe)).map_err(|_| {
            error(
                "SCFG_IDENTITY",
                "storage.mounts",
                "invalid recorded external guest path",
            )
        })?;
        guests.insert(probe.guest().to_owned());
    }
    Ok(guests.into_iter().collect())
}

fn error(code: &str, path: &str, reason: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!("{code}: {path}: {reason}"))
}
