//! Guarded storage projection with explicit observed backing and no source-host lookup.

use std::collections::BTreeMap;

use microsandbox_runtime::retention::{MountedFilesystemKind, MountedStorageEvidence};
use microsandbox_types::VolumeMount;
use microsandbox_types::snapshot::Manifest;
use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, SavedBindRootKind, SavedBindingReference, SavedExternalMountCapture,
    SavedMount, SavedNamedStorage, SavedOrigin, SavedStorageConfig, SavedUnknownReason, SavedValue,
    SavedVsockRoute,
};
use serde_json::Value;

use super::RuntimeCaptureSource;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Logical replacements and independently observed storage, acquired under the same source
/// guard as the configuration and descriptor. This never contains source paths or volume names.
#[derive(Default)]
pub struct StorageCaptureBindings {
    /// Exact canonical guest path to external backing requirement. Owned/tmpfs mounts need none.
    /// Named storage must reflect the active volume, not transient creation/ensure metadata.
    pub mounts: BTreeMap<String, SavedExternalMountCapture>,
    /// One logical endpoint per recorded socket route, in original source order.
    pub routes: Vec<SavedBindingReference>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeCaptureSource<'_> {
    /// Produce a complete known inventory or preserve it as unknown. A partially recorded
    /// mount list must not become a shorter list that silently drops required resources.
    /// The authoritative descriptor retains owned backing; this projection cannot replace it.
    /// This method performs no filesystem access, named-volume lookup or socket connection.
    pub fn project_storage(
        &self,
        bindings: StorageCaptureBindings,
        manifest: &Manifest,
    ) -> MicrosandboxResult<SavedStorageConfig> {
        self.project_storage_sections(bindings, Some(manifest), true, None)
    }

    /// Preserve next-start requirements without claiming that requested owned storage
    /// belongs to the active descriptor. External kinds still need independently classified
    /// requirements; source paths, volume names and transient provisioning are not exported.
    pub fn project_pending_storage(
        &self,
        mut bindings: StorageCaptureBindings,
    ) -> MicrosandboxResult<SavedStorageConfig> {
        // Explicit selections must match the complete declaration. Without a selection,
        // a pending bind's root kind or a named volume's actual backing cannot be derived
        // from its private source path/name or borrowed from the currently running guest.
        let complete =
            !bindings.mounts.is_empty()
                || !self.config.spec.mounts.iter().any(|mount| {
                    matches!(mount, VolumeMount::Bind { .. } | VolumeMount::Named { .. })
                });
        if complete && bindings.mounts.is_empty() && self.complete_mount_inventory(true) {
            for (index, mount) in self.config.spec.mounts.iter().enumerate() {
                if let VolumeMount::DiskImage { guest, .. } = mount {
                    bindings.mounts.insert(
                        guest.clone(),
                        SavedExternalMountCapture::DiskImage {
                            binding: SavedBindingReference {
                                id: format!("pending.storage.mounts.{index}"),
                            },
                        },
                    );
                }
            }
        }
        self.project_storage_sections(bindings, None, complete, None)
    }

    fn complete_mount_inventory(&self, pending: bool) -> bool {
        self.recorded
            .get("mounts")
            .and_then(Value::as_array)
            .is_some_and(|mounts| {
                mounts.iter().enumerate().all(|(index, raw)| {
                    let ownership_known = self.config.spec.mounts.get(index).is_some_and(|mount| {
                        self.config
                            .field_presence
                            .as_ref()
                            .is_some_and(|presence| presence.knows_default_mount_ownership(mount))
                    });
                    if pending && raw.get("type").and_then(Value::as_str) == Some("Owned") {
                        complete_owned_declaration(raw, ownership_known)
                    } else {
                        complete_mount(raw, ownership_known)
                    }
                })
            })
    }

    fn complete_route_inventory(&self) -> bool {
        if self.recorded.get("vsock").is_none()
            && self
                .config
                .field_presence
                .as_ref()
                .is_some_and(|hint| hint.knows_empty_vsock(&self.config.spec))
        {
            return true;
        }
        self.recorded
            .pointer("/vsock/routes")
            .and_then(Value::as_array)
            .is_some_and(|routes| {
                routes
                    .iter()
                    .all(|route| fields(route, &["port", "socket_type"]))
            })
    }

    /// Resolve portable requirements from the immutable capture receipt. Never reopen a host
    /// pathname or assume the requested named-volume creation settings describe active backing.
    pub(crate) fn project_observed_storage(
        &self,
        observed: Option<&MountedStorageEvidence>,
        manifest: &Manifest,
        mut selection: StorageCaptureBindings,
    ) -> MicrosandboxResult<SavedStorageConfig> {
        if self.config.spec.mounts.len() > MAX_SAVED_CONFIG_ENTRIES
            || self.config.spec.vsock.routes.len() > MAX_SAVED_CONFIG_ENTRIES
        {
            return Err(error("SCFG_LIMIT", "too many storage resources"));
        }
        let mut bindings = StorageCaptureBindings::default();
        let explicit_mounts = !selection.mounts.is_empty();
        let mut complete = self.complete_mount_inventory(false);
        if complete {
            for (index, mount) in self.config.spec.mounts.iter().enumerate() {
                let selected = selection.mounts.remove(mount.guest());
                if matches!(mount, VolumeMount::Owned { .. } | VolumeMount::Tmpfs { .. }) {
                    if selected.is_some() {
                        return Err(error(
                            "SCFG_BINDING",
                            "internal mount cannot use an external binding",
                        ));
                    }
                    continue;
                }
                let binding = match &selected {
                    Some(
                        SavedExternalMountCapture::Bind { binding, .. }
                        | SavedExternalMountCapture::Named { binding, .. }
                        | SavedExternalMountCapture::DiskImage { binding },
                    ) => binding.clone(),
                    None => SavedBindingReference {
                        id: format!("active.storage.mounts.{index}"),
                    },
                };
                let Some(requirement) = observed_external_mount(mount, binding, observed) else {
                    complete = false;
                    break;
                };
                if selected.is_some_and(|expected| requirement != expected) {
                    return Err(error(
                        "SCFG_IDENTITY",
                        "selected external mount contradicts its observed backing",
                    ));
                }
                if bindings
                    .mounts
                    .insert(mount.guest().to_owned(), requirement)
                    .is_some()
                {
                    return Err(error(
                        "SCFG_IDENTITY",
                        "duplicate captured mount destination",
                    ));
                }
            }
        }
        if !complete {
            if explicit_mounts {
                return Err(error(
                    "SCFG_BINDING",
                    "cannot verify selected mounts against incomplete backing evidence",
                ));
            }
            // A partial list could silently remove a required mount on restore.
            bindings.mounts.clear();
        }
        if complete && !selection.mounts.is_empty() {
            return Err(error(
                "SCFG_BINDING",
                "no captured mount for a selected binding",
            ));
        }
        bindings.routes = selection.routes;
        self.complete_socket_bindings(&mut bindings, "active.storage.routes")?;
        self.project_storage_sections(bindings, Some(manifest), complete, observed)
    }

    /// A complete socket declaration establishes the guest port and type. Its private
    /// host endpoint becomes a destination requirement scoped to this capture section.
    pub(super) fn complete_socket_bindings(
        &self,
        bindings: &mut StorageCaptureBindings,
        prefix: &'static str,
    ) -> MicrosandboxResult<()> {
        let count = self.config.spec.vsock.routes.len();
        if count > MAX_SAVED_CONFIG_ENTRIES {
            return Err(error("SCFG_LIMIT", "too many socket routes"));
        }
        if bindings.routes.is_empty() && self.complete_route_inventory() {
            bindings.routes = (0..count)
                .map(|index| SavedBindingReference {
                    id: format!("{prefix}.{index}"),
                })
                .collect();
        }
        Ok(())
    }

    fn project_storage_sections(
        &self,
        mut bindings: StorageCaptureBindings,
        manifest: Option<&Manifest>,
        mount_evidence_available: bool,
        observed: Option<&MountedStorageEvidence>,
    ) -> MicrosandboxResult<SavedStorageConfig> {
        if bindings.mounts.len() > MAX_SAVED_CONFIG_ENTRIES
            || bindings.routes.len() > MAX_SAVED_CONFIG_ENTRIES
            || self.config.spec.mounts.len() > MAX_SAVED_CONFIG_ENTRIES
            || self.config.spec.vsock.routes.len() > MAX_SAVED_CONFIG_ENTRIES
        {
            return Err(error("SCFG_LIMIT", "too many storage resources"));
        }
        let mounts =
            if mount_evidence_available && self.complete_mount_inventory(manifest.is_none()) {
                let mut mounts = self
                    .config
                    .spec
                    .mounts
                    .iter()
                    .map(|source| {
                        let external = bindings.mounts.remove(source.guest());
                        if manifest.is_none() && matches!(source, VolumeMount::Owned { .. }) {
                            if external.is_some() {
                                return Err(error(
                                    "SCFG_BINDING",
                                    "owned declaration cannot use an external binding",
                                ));
                            }
                            return SavedMount::requested_owned_from_source(source)
                                .map_err(manifest_error);
                        }
                        let mut mount =
                            SavedMount::from_source(source, external).map_err(manifest_error)?;
                        if let SavedMount::Bind {
                            guest, quota_mib, ..
                        } = &mut mount
                            && let Some(receipt) = observed
                        {
                            // Only active storage uses the applied budget. The pending
                            // declaration continues to distinguish an omitted caller quota.
                            *quota_mib =
                                Some(observed_bind_quota(receipt, guest).ok_or_else(|| {
                                    error("SCFG_IDENTITY", "missing observed bind quota")
                                })?);
                        }
                        Ok(mount)
                    })
                    .collect::<MicrosandboxResult<Vec<_>>>()?;
                // Guest paths must already be canonical (validated by from_source). Sort only
                // the portable inventory; never normalize or re-resolve a source host path.
                mounts.sort_by(|a, b| {
                    (a.guest().split('/').count(), a.guest())
                        .cmp(&(b.guest().split('/').count(), b.guest()))
                });
                configured(mounts)
            } else {
                unknown()
            };
        if !bindings.mounts.is_empty() {
            return Err(error(
                "SCFG_BINDING",
                "mount requirements do not match a complete recorded inventory",
            ));
        }
        let routes = if self.complete_route_inventory() {
            if bindings.routes.len() != self.config.spec.vsock.routes.len() {
                return Err(error(
                    "SCFG_BINDING",
                    "each recorded socket route needs one endpoint requirement",
                ));
            }
            configured(
                self.config
                    .spec
                    .vsock
                    .routes
                    .iter()
                    .zip(bindings.routes)
                    .map(|(source, binding)| {
                        SavedVsockRoute::from_source(source, binding).map_err(manifest_error)
                    })
                    .collect::<MicrosandboxResult<Vec<_>>>()?,
            )
        } else {
            if !bindings.routes.is_empty() {
                return Err(error(
                    "SCFG_BINDING",
                    "socket requirements do not match a complete recorded inventory",
                ));
            }
            unknown()
        };
        let result = SavedStorageConfig {
            mounts: Some(mounts),
            vsock: Some(routes),
        };
        if let Some(manifest) = manifest {
            result
                .validate_owned_projection(manifest)
                .map_err(manifest_error)?;
        } else {
            result.validate().map_err(manifest_error)?;
        }
        // An ID reused for incompatible mount/socket kinds must fail at capture,
        // before a later document assembly could mistakenly unify its consumers.
        result.binding_uses().map_err(manifest_error)?;
        Ok(result)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Convert only exact observed geometry. An absent receipt and an observed unlimited
/// quota have different meanings. Rounding a byte quota would loosen the restored limit.
fn observed_external_mount(
    mount: &VolumeMount,
    binding: SavedBindingReference,
    observed: Option<&MountedStorageEvidence>,
) -> Option<SavedExternalMountCapture> {
    const MIB: u64 = 1024 * 1024;
    let backing = observed.and_then(|e| e.get(mount.guest()));
    Some(match mount {
        VolumeMount::DiskImage { .. } => SavedExternalMountCapture::DiskImage { binding },
        VolumeMount::Bind { quota_mib, .. } => {
            let actual = backing?;
            let applied = observed_bind_quota(observed?, mount.guest())?;
            if quota_mib.is_some_and(|requested| requested != applied) {
                return None;
            }
            let root_kind = match actual.kind {
                MountedFilesystemKind::File => SavedBindRootKind::File,
                MountedFilesystemKind::Directory => SavedBindRootKind::Directory,
            };
            SavedExternalMountCapture::Bind { binding, root_kind }
        }
        VolumeMount::Named { .. } => {
            let storage = match observed?.block_capacity_bytes(mount.guest()) {
                Some(bytes) if bytes.is_multiple_of(MIB) => SavedNamedStorage::Disk {
                    capacity_mib: u32::try_from(bytes / MIB).ok()?,
                },
                Some(_) => return None,
                None => {
                    let directory =
                        backing.filter(|fs| fs.kind == MountedFilesystemKind::Directory)?;
                    let quota_mib = match directory.quota_bytes {
                        Some(bytes) if bytes.is_multiple_of(MIB) => {
                            Some(u32::try_from(bytes / MIB).ok()?)
                        }
                        Some(_) => return None,
                        None => None,
                    };
                    SavedNamedStorage::Directory { quota_mib }
                }
            };
            SavedExternalMountCapture::Named { binding, storage }
        }
        VolumeMount::Owned { .. } | VolumeMount::Tmpfs { .. } => return None,
    })
}

/// A bind quota in the portable format is an exact MiB budget. Its omitted form
/// selects a host default, so it cannot express a confirmed unlimited backend.
fn observed_bind_quota(receipt: &MountedStorageEvidence, guest: &str) -> Option<u32> {
    const MIB: u64 = 1024 * 1024;
    let bytes = receipt.get(guest)?.quota_bytes?;
    if !bytes.is_multiple_of(MIB) {
        return None;
    }
    u32::try_from(bytes / MIB).ok()
}

fn complete_mount(raw: &Value, ownership_known: bool) -> bool {
    let Some(kind) = raw.get("type").and_then(Value::as_str) else {
        return false;
    };
    if raw.get("guest").is_none() {
        return false;
    }
    // Owned mounts refer to the independently validated descriptor inventory; their
    // backing/options are authoritative there and are deliberately not duplicated.
    if kind == "Owned" {
        return true;
    }
    if !complete_options(raw.get("options"), ownership_known) {
        return false;
    }
    match kind {
        "Bind" => fields(
            raw,
            &[
                "stat_virtualization",
                "host_permissions",
                "follow_root_symlinks",
                "quota_mib",
            ],
        ),
        "Named" => fields(
            raw,
            &[
                "stat_virtualization",
                "host_permissions",
                "follow_root_symlinks",
            ],
        ),
        "Tmpfs" => fields(raw, &["size_mib"]),
        "DiskImage" => fields(raw, &["format", "fstype"]),
        _ => false,
    }
}

fn complete_owned_declaration(raw: &Value, ownership_known: bool) -> bool {
    fields(
        raw,
        &[
            "guest",
            "storage",
            "stat_virtualization",
            "host_permissions",
        ],
    ) && complete_options(raw.get("options"), ownership_known)
        && raw.get("storage").is_some_and(|storage| {
            match storage.get("kind").and_then(Value::as_str) {
                Some("directory") => fields(storage, &["quota_mib"]),
                Some("disk") => fields(storage, &["capacity_mib"]),
                _ => false,
            }
        })
}

fn complete_options(raw: Option<&Value>, ownership_known: bool) -> bool {
    raw.is_some_and(|options| {
        fields(options, &["readonly", "noexec", "nosuid", "nodev"])
            && (ownership_known || fields(options, &["override_uid", "override_gid"]))
    })
}

fn fields(raw: &Value, names: &[&str]) -> bool {
    names.iter().all(|name| raw.get(*name).is_some())
}

fn configured<T>(value: T) -> SavedValue<T> {
    SavedValue::Value {
        value,
        origin: SavedOrigin::Configured,
    }
}

fn unknown<T>() -> SavedValue<T> {
    SavedValue::Unknown {
        reason: SavedUnknownReason::NotRecorded,
    }
}

fn manifest_error(error: impl std::fmt::Display) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(error.to_string())
}

fn error(code: &str, detail: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!("{code}: storage: {detail}"))
}
