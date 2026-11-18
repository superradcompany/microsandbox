//! Guarded storage projection with explicit observed backing and no source-host lookup.

use std::collections::BTreeMap;

use microsandbox_types::VolumeMount;
use microsandbox_types::snapshot::Manifest;
use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, SavedBindingReference, SavedExternalMountCapture, SavedMount,
    SavedOrigin, SavedStorageConfig, SavedUnknownReason, SavedValue, SavedVsockRoute,
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
        self.project_storage_sections(bindings, Some(manifest))
    }

    /// Preserve next-start requirements without claiming that requested owned storage
    /// belongs to the active descriptor. External kinds still need independently classified
    /// requirements; source paths, volume names and transient provisioning are not exported.
    pub fn project_pending_storage(
        &self,
        bindings: StorageCaptureBindings,
    ) -> MicrosandboxResult<SavedStorageConfig> {
        self.project_storage_sections(bindings, None)
    }

    fn project_storage_sections(
        &self,
        mut bindings: StorageCaptureBindings,
        manifest: Option<&Manifest>,
    ) -> MicrosandboxResult<SavedStorageConfig> {
        if bindings.mounts.len() > MAX_SAVED_CONFIG_ENTRIES
            || bindings.routes.len() > MAX_SAVED_CONFIG_ENTRIES
            || self.config.spec.mounts.len() > MAX_SAVED_CONFIG_ENTRIES
            || self.config.spec.vsock.routes.len() > MAX_SAVED_CONFIG_ENTRIES
        {
            return Err(error("SCFG_LIMIT", "too many storage resources"));
        }
        let mounts = if self
            .recorded
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
                    if manifest.is_none()
                        && raw.get("type").and_then(Value::as_str) == Some("Owned")
                    {
                        complete_owned_declaration(raw, ownership_known)
                    } else {
                        complete_mount(raw, ownership_known)
                    }
                })
            }) {
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
                    SavedMount::from_source(source, external).map_err(manifest_error)
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
        let routes = if self
            .recorded
            .pointer("/vsock/routes")
            .and_then(Value::as_array)
            .is_some_and(|routes| {
                routes
                    .iter()
                    .all(|route| fields(route, &["port", "socket_type"]))
            }) {
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
