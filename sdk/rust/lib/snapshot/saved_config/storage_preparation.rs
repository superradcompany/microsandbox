//! Prepare destination storage references without opening, provisioning or authorizing backing.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_BYTES, MAX_SAVED_CONFIG_ENTRIES, MAX_SAVED_TEXT_BYTES, SavedBindingKind,
    SavedMount, SavedStorageConfig,
};
use microsandbox_types::{SandboxSpec, SandboxSpecPatch, VolumeMount, VsockRouteSpec};

use super::{SnapshotConfigMode, StorageInputSelection, select_storage_inputs};
use crate::{MicrosandboxError, MicrosandboxResult, snapshot::Manifest};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Destination-owned inputs. The variant declares the requested resource kind, not proof that
/// a path exists, has that kind or satisfies captured identity and destination policy.
#[derive(Clone)]
pub enum StorageBindingInput {
    /// Host file exported through virtiofs.
    FilesystemFile(PathBuf),
    /// Host directory exported through virtiofs.
    FilesystemDirectory(PathBuf),
    /// Existing destination named directory volume; never create it from saved metadata.
    NamedDirectory(String),
    /// Existing destination named disk volume.
    NamedDisk(String),
    /// External disk whose saved format/filesystem still need admission.
    DiskImage(PathBuf),
    /// Destination stream socket or supported local pipe.
    StreamSocket(PathBuf),
    /// Destination datagram socket.
    DatagramSocket(PathBuf),
}

/// Native configuration and immutable source obligations, not materialized or admitted storage.
pub struct StorageConfigurationPlan {
    mounts: Vec<VolumeMount>,
    routes: Vec<VsockRouteSpec>,
    captured_owned_ids: Vec<String>,
    selection: StorageInputSelection,
}

#[derive(Default)]
struct InputBudget(usize);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl StorageBindingInput {
    pub(super) fn kind(&self) -> SavedBindingKind {
        match self {
            Self::FilesystemFile(_) => SavedBindingKind::FilesystemFile,
            Self::FilesystemDirectory(_) => SavedBindingKind::FilesystemDirectory,
            Self::NamedDirectory(_) => SavedBindingKind::NamedDirectory,
            Self::NamedDisk(_) => SavedBindingKind::NamedDisk,
            Self::DiskImage(_) => SavedBindingKind::DiskImage,
            Self::StreamSocket(_) => SavedBindingKind::StreamSocket,
            Self::DatagramSocket(_) => SavedBindingKind::DatagramSocket,
        }
    }

    fn path(&self) -> MicrosandboxResult<&Path> {
        match self {
            Self::FilesystemFile(path)
            | Self::FilesystemDirectory(path)
            | Self::DiskImage(path)
            | Self::StreamSocket(path)
            | Self::DatagramSocket(path) => Ok(path),
            _ => Err(error("SCFG_BINDING", "storage binding needs a path")),
        }
    }

    fn name(&self) -> MicrosandboxResult<&str> {
        match self {
            Self::NamedDirectory(name) | Self::NamedDisk(name) => Ok(name),
            _ => Err(error("SCFG_BINDING", "storage binding needs a volume name")),
        }
    }
}

impl StorageConfigurationPlan {
    /// Keep approvals, recorded resource semantics and full-state identity obligations.
    /// The binding inventory describes source requirements, including now-supplied inputs.
    pub fn selection(&self) -> &StorageInputSelection {
        &self.selection
    }

    /// These mounts require restoration of their captured private payloads before activation.
    /// Their native Owned discriminants must never provision empty replacement backing.
    pub fn captured_owned_ids(&self) -> &[String] {
        &self.captured_owned_ids
    }

    /// Apply complete mount/route inventories only. Unknown sections refuse before mutation.
    /// This does not admit paths, install backing, grant saved relaxations or open sockets.
    pub fn apply_to(&self, destination: &mut SandboxSpec) -> MicrosandboxResult<()> {
        if !self.selection.unknown_fields.is_empty() {
            return Err(error("SCFG_UNKNOWN", "storage inventory needs resolution"));
        }
        destination.mounts.clone_from(&self.mounts);
        destination.vsock.routes.clone_from(&self.routes);
        Ok(())
    }
}

impl InputBudget {
    fn bytes(&mut self, value: &[u8]) -> MicrosandboxResult<()> {
        if value.is_empty() || value.len() > MAX_SAVED_TEXT_BYTES || value.contains(&0) {
            return Err(error("SCFG_VALUE", "invalid destination storage reference"));
        }
        self.0 = self
            .0
            .checked_add(value.len())
            .ok_or_else(|| error("SCFG_LIMIT", "expanded storage references are too large"))?;
        if self.0 > MAX_SAVED_CONFIG_BYTES {
            return Err(error(
                "SCFG_LIMIT",
                "expanded storage references are too large",
            ));
        }
        Ok(())
    }

    fn path(&mut self, path: &Path) -> MicrosandboxResult<()> {
        // Resolve at the existing destination-input boundary, not by canonicalizing a
        // deferred path here. In particular, symlink/.. and non-UTF-8 spelling survives.
        self.bytes(path.as_os_str().as_encoded_bytes())
    }

    fn mount(&mut self, mount: &VolumeMount) -> MicrosandboxResult<()> {
        match mount {
            VolumeMount::Bind { host, .. } | VolumeMount::DiskImage { host, .. } => self.path(host),
            VolumeMount::Named { name, .. } => {
                crate::volume::validate_volume_name(name)
                    .map_err(|_| error("SCFG_VALUE", "invalid destination volume name"))?;
                self.bytes(name.as_bytes())
            }
            VolumeMount::Owned { .. } | VolumeMount::Tmpfs { .. } => Ok(()),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for StorageBindingInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageBindingInput")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for StorageConfigurationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageConfigurationPlan")
            .field("selection", &self.selection)
            .field("captured_owned_count", &self.captured_owned_ids.len())
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Prepare immediate storage/IPC inputs after global binding-demand validation. Explicit
/// per-resource mappings take precedence; bindings supply only surviving source consumers.
/// A missing legacy external mount is not an invitation to recreate empty storage.
pub fn prepare_storage_configuration(
    saved: &SavedStorageConfig,
    manifest: &Manifest,
    explicit: &SandboxSpecPatch,
    mode: SnapshotConfigMode,
    full_resume: bool,
    inputs: &BTreeMap<String, StorageBindingInput>,
) -> MicrosandboxResult<StorageConfigurationPlan> {
    let selection = select_storage_inputs(saved, manifest, explicit, mode, full_resume)?;
    if inputs.len() > MAX_SAVED_CONFIG_ENTRIES
        || selection.mounts.len().saturating_add(selection.vsock.len()) > MAX_SAVED_CONFIG_ENTRIES
    {
        return Err(error("SCFG_LIMIT", "too many destination storage inputs"));
    }
    if inputs.iter().any(|(id, input)| {
        selection.remaining_bindings.get(id).map(|entry| entry.kind) != Some(input.kind())
    }) || selection
        .remaining_bindings
        .keys()
        .any(|id| !inputs.contains_key(id))
    {
        return Err(error(
            "SCFG_BINDING",
            "storage binding inputs do not match requirements",
        ));
    }
    let owned = manifest
        .owned_volumes()
        .map_err(|_| error("SCFG_IDENTITY", "invalid captured owned inventory"))?;
    let owned_by_id: BTreeMap<_, _> = owned
        .iter()
        .map(|capture| (capture.mount_id.as_str(), capture))
        .collect();
    let mut budget = InputBudget::default();
    let mut mounts = Vec::with_capacity(selection.mounts.len());
    let mut captured_owned_ids = Vec::new();
    for entry in &selection.mounts {
        let mount = if let Some(destination) = &entry.destination {
            budget.mount(destination)?;
            destination.clone()
        } else {
            let saved = entry.saved.as_ref().ok_or_else(|| {
                error(
                    "SCFG_BINDING",
                    "legacy external backing needs an explicit destination mount",
                )
            })?;
            if let SavedMount::Owned { mount_id, .. } = saved {
                let captured = owned_by_id
                    .get(mount_id.as_str())
                    .ok_or_else(|| error("SCFG_IDENTITY", "captured owned backing is missing"))?;
                captured_owned_ids.push(mount_id.clone());
                captured.mount.to_mount()
            } else {
                prepare_mount(saved, inputs, &mut budget)?
            }
        };
        mounts.push(mount);
    }
    let mut routes = Vec::with_capacity(selection.vsock.len());
    for entry in &selection.vsock {
        let route = if let Some(destination) = &entry.destination {
            budget.path(&destination.host_socket)?;
            destination.clone()
        } else {
            let source = entry.saved.as_ref().ok_or_else(|| {
                error("SCFG_BINDING", "IPC endpoint needs an explicit destination")
            })?;
            let path = inputs[&source.binding.id].path()?;
            budget.path(path)?;
            VsockRouteSpec {
                host_socket: path.to_owned(),
                port: source.port,
                socket_type: source.socket_type,
            }
        };
        routes.push(route);
    }
    Ok(StorageConfigurationPlan {
        mounts,
        routes,
        captured_owned_ids,
        selection,
    })
}

fn prepare_mount(
    source: &SavedMount,
    inputs: &BTreeMap<String, StorageBindingInput>,
    budget: &mut InputBudget,
) -> MicrosandboxResult<VolumeMount> {
    Ok(match source {
        SavedMount::Bind {
            guest,
            binding,
            options,
            stat_virtualization,
            host_permissions,
            follow_root_symlinks,
            quota_mib,
            ..
        } => {
            let path = inputs[&binding.id].path()?;
            budget.path(path)?;
            VolumeMount::Bind {
                host: path.to_owned(),
                guest: guest.clone(),
                options: (*options).into(),
                stat_virtualization: *stat_virtualization,
                host_permissions: *host_permissions,
                follow_root_symlinks: *follow_root_symlinks,
                quota_mib: *quota_mib,
            }
        }
        SavedMount::Named {
            guest,
            binding,
            options,
            stat_virtualization,
            host_permissions,
            follow_root_symlinks,
            ..
        } => {
            let name = inputs[&binding.id].name()?;
            crate::volume::validate_volume_name(name)
                .map_err(|_| error("SCFG_VALUE", "invalid destination volume name"))?;
            budget.bytes(name.as_bytes())?;
            // Saved quota/capacity stays in selection for actual backing admission. It must
            // not become transient creation/ensure intent or resize an existing volume.
            VolumeMount::Named {
                name: name.to_owned(),
                guest: guest.clone(),
                create: None,
                options: (*options).into(),
                stat_virtualization: *stat_virtualization,
                host_permissions: *host_permissions,
                follow_root_symlinks: *follow_root_symlinks,
            }
        }
        SavedMount::DiskImage {
            guest,
            binding,
            format,
            fstype,
            options,
        } => {
            let path = inputs[&binding.id].path()?;
            budget.path(path)?;
            VolumeMount::DiskImage {
                host: path.to_owned(),
                guest: guest.clone(),
                format: *format,
                fstype: fstype.clone(),
                options: (*options).into(),
            }
        }
        SavedMount::Tmpfs {
            guest,
            size_mib,
            options,
        } => VolumeMount::Tmpfs {
            guest: guest.clone(),
            size_mib: *size_mib,
            options: (*options).into(),
        },
        SavedMount::Owned { .. } | SavedMount::RequestedOwned { .. } => {
            return Err(error(
                "SCFG_IDENTITY",
                "owned mount needs its captured inventory",
            ));
        }
    })
}

fn error(code: &str, message: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!("{code}: {message}"))
}
