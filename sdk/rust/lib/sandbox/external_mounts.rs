//! Resolve external checkpoint bindings against explicit or source-local authorization.

use std::collections::BTreeSet;

use microsandbox_image::checkpoint::{CheckpointClosure, ObjectId, ResourceDescriptor};
use microsandbox_protocol::bootstrap::BootstrapDirMount;
use microsandbox_runtime::{
    checkpoint::ExternalMountAuthorization, launch::ExternalMountRestoreBinding,
};
use microsandbox_types::{
    ExternalMountRestorePolicy, VolumeKind, VolumeMount, canonicalize_volume_mounts,
    snapshot::ExternalMountPolicy,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use super::SandboxConfig;
use crate::{
    MicrosandboxError, MicrosandboxResult,
    backend::LocalBackend,
    db::entity::{sandbox, volume},
    error::RestoreKind,
    snapshot::Manifest,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Refuse a disk restore that would silently drop mounts its snapshot recorded.
///
/// A disk snapshot carries only guest paths, never host paths, so each one needs a destination
/// mapping unless the restore opted out with `allow_missing_resources`.
pub(crate) fn require_recorded_mounts(
    config: &SandboxConfig,
    manifest: &Manifest,
) -> MicrosandboxResult<()> {
    let guest_paths = manifest.external_mounts().map_err(integrity)?;
    let policies = manifest.external_mount_policies().map_err(integrity)?;
    if policies.is_none() && !guest_paths.is_empty() {
        tracing::warn!(
            mounts = guest_paths.len(),
            "snapshot records external mounts without a captured hide-path policy; \
             a restored hide-path list cannot be compared and is accepted as unknown"
        );
    }

    require_guest_mounts(config, guest_paths, policies)
}

/// Guest paths of the external bind mounts a checkpoint captured (owned directories are restored
/// from the snapshot and need no mapping).
pub(crate) fn external_bind_guest_paths(
    resources: &[ResourceDescriptor],
) -> MicrosandboxResult<Vec<String>> {
    let mut guest_paths = Vec::new();
    for resource in resources {
        let is_external_bind = resource
            .binding
            .get("role")
            .is_some_and(|role| role == "external_bind");
        if !is_external_bind {
            continue;
        }

        let guest_mount = resource
            .binding
            .get("guest_mount")
            .ok_or_else(|| integrity("external resource is missing its guest mount"))?;
        let mount: BootstrapDirMount = serde_json::from_str(guest_mount).map_err(integrity)?;

        guest_paths.push(mount.guest_path);
    }

    Ok(guest_paths)
}

/// Require a destination mapping for each guest path unless the restore opted out.
pub(crate) fn require_guest_mounts(
    config: &SandboxConfig,
    guest_paths: Vec<String>,
    captured_policies: Option<Vec<ExternalMountPolicy>>,
) -> MicrosandboxResult<()> {
    let has_policies = captured_policies
        .as_ref()
        .is_some_and(|policies| !policies.is_empty());
    if !config.restore_resources.require_complete && !has_policies {
        return Ok(());
    }

    // The backend canonicalizes mounts later; compare the same form (`/data/` is `/data`).
    let mut mounts = config.spec.mounts.clone();
    canonicalize_volume_mounts(&mut mounts)?;

    reject_weakened_hide_path(&mounts, captured_policies.as_deref())?;

    if !config.restore_resources.require_complete {
        return Ok(());
    }

    // Only host-backed kinds satisfy a recorded path; tmpfs or owned mounts would
    // restart with empty state in place of the captured host binding.
    let mut destination_paths = BTreeSet::new();
    for mount in &mounts {
        if matches!(
            mount,
            VolumeMount::Bind { .. } | VolumeMount::Named { .. } | VolumeMount::DiskImage { .. }
        ) {
            destination_paths.insert(mount.guest());
        }
    }

    let mut missing = BTreeSet::new();
    for guest in guest_paths {
        if !destination_paths.contains(guest.as_str()) {
            missing.insert(format!("mount {guest}"));
        }
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing_disk_mounts(missing))
    }
}

/// Refuse a destination hide-path list that is not at least as strict as the captured one.
///
/// Only bind mounts carry a hide-path list; a destination that remaps a captured bind
/// to a non-bind or drops one of its patterns would re-expose a path the source
/// hid. A stricter (superset) hide-path list is accepted, but a gitignore negation
/// (`!name`) re-exposes a name, so a negation the capture did not contain is a
/// weakening even when every captured positive pattern is still present.
/// Reordering matters too because gitignore is last-match-wins, so the captured
/// patterns must appear in the destination as an order-preserving subsequence.
/// `None` means the capture predates policy recording and is treated as unknown,
/// never as an empty list.
fn reject_weakened_hide_path(
    mounts: &[VolumeMount],
    captured_policies: Option<&[ExternalMountPolicy]>,
) -> MicrosandboxResult<()> {
    let Some(policies) = captured_policies else {
        return Ok(());
    };

    for policy in policies {
        let Some(destination) = mounts
            .iter()
            .find(|mount| mount.guest() == policy.guest_path)
        else {
            continue;
        };
        let destination_hide_path: &[String] = match destination {
            VolumeMount::Bind { hide_path, .. } => hide_path,
            _ => &[],
        };
        // Gitignore rules are last-match-wins, so a destination that keeps the
        // captured patterns but reorders them can still expose a name an earlier
        // rule hid (e.g. captured ["*", "!*.txt", "secret.txt"] versus destination
        // ["*", "secret.txt", "!*.txt"]). Require the captured list to be an
        // order-preserving subsequence of the destination: this rejects drops and
        // reorders while still allowing extra positive patterns (which only hide
        // more).
        let mut remaining = destination_hide_path.iter();
        let preserves_order = policy
            .hide_path
            .iter()
            .all(|pattern| remaining.by_ref().any(|candidate| candidate == pattern));
        let introduces_negation = destination_hide_path
            .iter()
            .any(|pattern| pattern.starts_with('!') && !policy.hide_path.contains(pattern));
        if !preserves_order || introduces_negation {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "restore would weaken bind-mount hide-path policy at {}; re-declare the hide-path list",
                policy.guest_path
            )));
        }
    }

    Ok(())
}

/// Refuse a branch child whose explicit mounts drop or weaken a source bind's hide-path list.
///
/// A local branch clears the source's external binds, so a child that does not
/// inherit resources must re-declare each hide_path-bearing bind with a hide-path list at
/// least as strict as the source's. Omitting the mount entirely is refused too:
/// the source bind is gone, so silently proceeding would drop its policy. Callers
/// use [`require_preserved_inherited_bind_hide_path`] instead when the child inherits
/// resources, because the source mount (including its hide-path list) is reconnected.
pub(crate) fn require_preserved_bind_hide_path(
    source_mounts: &[VolumeMount],
    destination_mounts: &[VolumeMount],
) -> MicrosandboxResult<()> {
    let policies = hide_path_policies(source_mounts)?;
    if policies.is_empty() {
        return Ok(());
    }

    let mut destination = destination_mounts.to_vec();
    canonicalize_volume_mounts(&mut destination)?;

    for policy in &policies {
        if !destination
            .iter()
            .any(|mount| mount.guest() == policy.guest_path)
        {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "branch of a hide_path-bearing source must re-declare the hide_path-bearing mount at {}; \
                 the child omits it",
                policy.guest_path
            )));
        }
    }

    reject_weakened_hide_path(&destination, Some(&policies))
}

/// Refuse a branch child whose explicit mount weakens an inherited hide_path-bearing bind.
///
/// With resource inheritance the source's hide_path-bearing bind is reconnected, so an
/// omitted explicit mount is safe. But an explicit child mount at the same guest path
/// overrides that inherited source mount, so it must not drop or weaken the source's
/// hide-path list. This applies the same weakening check as a restore, without requiring
/// the mount to be present merely because it is inherited.
pub(crate) fn require_preserved_inherited_bind_hide_path(
    source_mounts: &[VolumeMount],
    destination_mounts: &[VolumeMount],
) -> MicrosandboxResult<()> {
    let policies = hide_path_policies(source_mounts)?;
    if policies.is_empty() {
        return Ok(());
    }

    let mut destination = destination_mounts.to_vec();
    canonicalize_volume_mounts(&mut destination)?;

    reject_weakened_hide_path(&destination, Some(&policies))
}

/// Capture the hide_path policies of the source bind mounts, canonicalizing guest paths.
fn hide_path_policies(
    source_mounts: &[VolumeMount],
) -> MicrosandboxResult<Vec<ExternalMountPolicy>> {
    let mut source = source_mounts.to_vec();
    canonicalize_volume_mounts(&mut source)?;

    Ok(source
        .iter()
        .filter_map(|mount| match mount {
            VolumeMount::Bind {
                guest, hide_path, ..
            } if !hide_path.is_empty() => Some(ExternalMountPolicy {
                guest_path: guest.clone(),
                hide_path: hide_path.clone(),
            }),
            _ => None,
        })
        .collect())
}

/// Reconnect only user-selected bindings or an exact locally recorded source binding.
pub(crate) async fn resolve_external_mounts(
    local: &LocalBackend,
    config: &mut SandboxConfig,
) -> MicrosandboxResult<()> {
    let Some(restore) = config.checkpoint_restore.as_ref() else {
        return Ok(());
    };
    let resources = if restore.local_branch {
        microsandbox_runtime::checkpoint::LocalBranchState::open(&restore.closure)?.resources
    } else {
        let root = ObjectId::new(&restore.checkpoint_root).map_err(integrity)?;
        CheckpointClosure::inspect_manifest(&restore.closure, Some(&root))
            .map_err(integrity)?
            .resources
    };
    let mut bindings = Vec::new();
    let mut missing = BTreeSet::new();
    let mut unavailable_disks = std::collections::BTreeMap::new();
    let mut disk_ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for resource in resources.iter().filter(|resource| {
        resource
            .binding
            .get("managed_disk")
            .is_some_and(|value| value == "true")
    }) {
        let guest = resource
            .binding
            .get("guest_path")
            .ok_or_else(|| integrity("disk resource lacks guest path"))?;
        let id = resource
            .binding
            .get("device_id")
            .ok_or_else(|| integrity("disk resource lacks device identity"))?;
        let expected_id = if resource
            .binding
            .get("lifecycle_owned")
            .is_some_and(|value| value == "true")
        {
            microsandbox_types::owned_volume_mount_id(guest)
        } else {
            crate::runtime::spawn::guest_mount_tag(guest)
        };
        if guest == "/"
            || !guest.starts_with('/')
            || expected_id != *id
            || !disk_ids.insert(id.clone())
            || !paths.insert(guest.clone())
        {
            return Err(integrity("invalid additional disk binding"));
        }
        let selected = config
            .spec
            .mounts
            .iter()
            .find(|mount| mount.guest() == guest)
            .cloned();
        let available = if let Some(selected) = &selected {
            match selected {
                VolumeMount::DiskImage { host, .. } => backing_exists(host).await?,
                VolumeMount::Owned {
                    storage: microsandbox_types::OwnedVolumeStorage::Disk { .. },
                    ..
                } => true,
                VolumeMount::Named { name, .. } => {
                    let db = local.db().await?;
                    let model = volume::Entity::find()
                        .filter(volume::Column::Name.eq(name.as_str()))
                        .one(db.read())
                        .await?;
                    if let Some(model) = model {
                        if model.kind != "disk" {
                            return Err(integrity("captured block device requires a disk mapping"));
                        }
                        backing_exists(&local.volume_path(name).join("disk.raw")).await?
                    } else {
                        false
                    }
                }
                _ => return Err(integrity("captured block device requires a disk mapping")),
            }
        } else {
            false
        };
        if !available {
            if selected.is_some()
                && !config.restore_resources.require_complete
                && !config.restore_resources.allow_missing
            {
                return Err(integrity("explicit disk volume does not exist"));
            }
            config.spec.mounts.retain(|mount| mount.guest() != guest);
            missing.insert(format!("disk {guest}"));
            if unavailable_disks
                .insert(id.clone(), guest.clone())
                .is_some()
            {
                return Err(integrity("duplicate additional disk binding"));
            }
        }
    }
    let mut tags = BTreeSet::new();
    for resource in resources.iter().filter(|resource| {
        resource
            .binding
            .get("role")
            .is_some_and(|role| role == "external_bind" || role == "owned_directory")
    }) {
        let mount: BootstrapDirMount = serde_json::from_str(
            resource
                .binding
                .get("guest_mount")
                .ok_or_else(|| integrity("external resource is missing its guest mount"))?,
        )
        .map_err(integrity)?;
        if !mount.guest_path.starts_with('/')
            || !tags.insert(mount.tag.clone())
            || !paths.insert(mount.guest_path.clone())
        {
            return Err(integrity("duplicate or invalid external mount topology"));
        }
        let device_id = resource
            .binding
            .get("device_id")
            .ok_or_else(|| integrity("external resource has no device identity"))?
            .clone();
        let explicit = config
            .spec
            .mounts
            .iter()
            .find(|candidate| candidate.guest() == mount.guest_path)
            .cloned();
        let explicitly_mapped = explicit.is_some();
        let owned = resource
            .binding
            .get("role")
            .is_some_and(|role| role == "owned_directory");
        if owned
            && !matches!(
                explicit,
                Some(VolumeMount::Owned {
                    storage: microsandbox_types::OwnedVolumeStorage::Directory { .. },
                    ..
                })
            )
        {
            return Err(integrity(
                "required owned directory has no privately materialized backing",
            ));
        }
        let (selected, remapped) = match explicit {
            Some(selected) => (Some(selected), !owned && !restore.local_branch),
            None if config.restore_resources.inherit => (
                authorized_source_mount(local, resource, &mount.guest_path).await?,
                false,
            ),
            None => (None, false),
        };
        let mut selected = admit_existing_named_mount(local, selected).await?;
        // Missing backing is not a stale-object mismatch. Resolve it before launch so
        // opting out grants an unavailable device, never a newly created empty export.
        if (config.restore_resources.require_complete || config.restore_resources.allow_missing)
            && let Some(mount) = &selected
        {
            let path = match mount {
                VolumeMount::Bind { host, .. } => Some(host.clone()),
                VolumeMount::Named { name, .. } => Some(local.volume_path(name)),
                _ => None,
            };
            if let Some(path) = path {
                match tokio::fs::metadata(&path).await {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => selected = None,
                    Err(error) => {
                        return Err(MicrosandboxError::InvalidConfig(format!(
                            "cannot access restore filesystem {}: {error}",
                            mount.guest()
                        )));
                    }
                    Ok(_) => {}
                }
            }
        }
        let unavailable = selected.is_none();
        if unavailable {
            missing.insert(format!("filesystem {}", mount.guest_path));
        }
        if let Some(selected) = selected {
            let options = match &selected {
                VolumeMount::Bind { options, .. }
                | VolumeMount::Named { options, .. }
                | VolumeMount::Owned { options, .. } => options,
                _ => {
                    return Err(MicrosandboxError::InvalidConfig(format!(
                        "external mount {} requires a directory volume mapping",
                        mount.guest_path
                    )));
                }
            };
            if (
                options.readonly,
                options.noexec,
                options.nosuid,
                options.nodev,
            ) != (
                mount.flags.readonly,
                mount.flags.noexec,
                mount.flags.nosuid,
                mount.flags.nodev,
            ) {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "external mount {} must retain captured mount flags",
                    mount.guest_path
                )));
            }
            if let Some(existing) = config
                .spec
                .mounts
                .iter_mut()
                .find(|existing| existing.guest() == mount.guest_path)
            {
                *existing = selected;
            } else {
                config.spec.mounts.push(selected);
            }
        } else if explicitly_mapped
            && !config.restore_resources.require_complete
            && !config.restore_resources.allow_missing
            && config.external_mount_policy == ExternalMountRestorePolicy::Strict
        {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "explicit external mount {} is unavailable; provide an existing compatible volume or select relaxed validation",
                mount.guest_path
            )));
        } else {
            config
                .spec
                .mounts
                .retain(|existing| existing.guest() != mount.guest_path);
        }
        bindings.push(ExternalMountRestoreBinding {
            require_backing: !owned
                && config.restore_resources.require_complete
                && config.external_mount_policy == ExternalMountRestorePolicy::Relaxed,
            device_id,
            mount,
            filename: resource.binding.get("filename").cloned(),
            remapped,
            unavailable,
        });
    }
    if config.restore_resources.require_complete && !missing.is_empty() {
        return Err(missing_resources(missing));
    }
    // The source's complete writeback evidence belongs to this captured boundary, not a
    // caller option. Relaxed mode does not waive it or repair old dirty memory images.
    if !bindings.is_empty()
        && !resources.iter().any(|resource| {
            resource.id == "guest:agentd"
                && resource
                    .binding
                    .get("external_mounts_synced")
                    .is_some_and(|value| value == "true")
        })
    {
        return Err(integrity(
            "external mount checkpoint lacks a clean guest writeback boundary",
        ));
    }
    bindings.sort_by_key(|binding| {
        binding
            .device_id
            .strip_prefix("virtio_fs")
            .and_then(|index| index.parse::<usize>().ok())
            .unwrap_or(usize::MAX)
    });
    let restore = config
        .checkpoint_restore
        .as_mut()
        .expect("restore was resolved above");
    restore.external_mount_policy = config.external_mount_policy;
    restore.external_mounts = bindings;
    restore.unavailable_disks = unavailable_disks;
    Ok(())
}

async fn admit_existing_named_mount(
    local: &LocalBackend,
    selected: Option<VolumeMount>,
) -> MicrosandboxResult<Option<VolumeMount>> {
    let Some(mut selected) = selected else {
        return Ok(None);
    };
    if let VolumeMount::Named { name, create, .. } = &mut selected {
        let db = local.db().await?;
        let Some(model) = volume::Entity::find()
            .filter(volume::Column::Name.eq(name.as_str()))
            .one(db.read())
            .await?
        else {
            // Restoring a logical dependency must never recreate a missing named
            // resource, even when the source originally declared create-if-absent.
            return Ok(None);
        };
        if VolumeKind::from_db_value(&model.kind) != VolumeKind::Directory {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "external filesystem mapping {name:?} must be an existing directory volume"
            )));
        }
        // The later volume-lock admission still validates this record. Removing
        // creation intent makes a deletion race fail closed instead of making data.
        *create = None;
    }
    Ok(Some(selected))
}

async fn authorized_source_mount(
    local: &LocalBackend,
    resource: &ResourceDescriptor,
    guest: &str,
) -> MicrosandboxResult<Option<VolumeMount>> {
    let Some(source) = resource.binding.get("source_sandbox") else {
        return Ok(None);
    };
    microsandbox_types::validate_sandbox_name(source).map_err(integrity)?;
    let Some(token) = resource.binding.get("source_binding_token") else {
        return Ok(None);
    };
    let runtime = local.sandboxes_dir().join(source).join("runtime");
    let authorization = match ExternalMountAuthorization::read(&runtime) {
        Ok(authorization) if authorization.token == *token => authorization,
        _ => return Ok(None),
    };
    let Some(tag) = resource.binding.get("guest_tag") else {
        return Ok(None);
    };
    if !authorization.mounts.iter().any(|spec| {
        spec.split_once(':')
            .is_some_and(|(actual, _)| actual == tag)
    }) {
        return Ok(None);
    }
    let database = local.db().await?;
    let Some(model) = sandbox::Entity::find()
        .filter(sandbox::Column::Name.eq(source))
        .one(database.read())
        .await?
    else {
        return Ok(None);
    };
    let source: SandboxConfig =
        serde_json::from_str(model.active_config.as_deref().unwrap_or(&model.config))?;
    Ok(source
        .spec
        .mounts
        .into_iter()
        .find(|mount| mount.guest() == guest))
}

fn integrity(error: impl std::fmt::Display) -> MicrosandboxError {
    MicrosandboxError::SnapshotIntegrity(error.to_string())
}

/// Keep the entire missing set actionable without disclosing source host paths.
fn missing_resources(missing: BTreeSet<String>) -> MicrosandboxError {
    MicrosandboxError::MissingRestoreBindings {
        missing: missing.into_iter().collect(),
        restore: RestoreKind::Full,
    }
}

/// A disk restore maps host paths itself; captured disks cannot satisfy this check.
fn missing_disk_mounts(missing: BTreeSet<String>) -> MicrosandboxError {
    MicrosandboxError::MissingRestoreBindings {
        missing: missing.into_iter().collect(),
        restore: RestoreKind::Disk,
    }
}

async fn backing_exists(path: &std::path::Path) -> MicrosandboxResult<bool> {
    match tokio::fs::metadata(path).await {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use microsandbox_image::checkpoint::ResourceTreatment;
    use sea_orm::Set;

    use super::*;
    use crate::{Sandbox, sandbox::SandboxBuilder};

    #[test]
    fn missing_resource_diagnostic_lists_dependencies_and_explicit_opt_out() {
        let error = missing_resources(BTreeSet::from([
            "filesystem /work".into(),
            "disk /data".into(),
        ]))
        .to_string();

        assert!(error.contains("disk /data, filesystem /work"));
        assert!(error.contains("select a captured disk"));
        assert!(error.contains("explicitly allow missing resources"));
        assert!(!error.contains("--"));
        assert!(!error.contains("select relaxed"));
    }

    fn resource(role: &str, guest: &str) -> ResourceDescriptor {
        let mount = serde_json::json!({ "tag": "t", "guest_path": guest });
        ResourceDescriptor {
            id: format!("fs:{guest}"),
            kind: "filesystem".into(),
            treatment: ResourceTreatment::Reconnect,
            binding: BTreeMap::from([
                ("role".into(), role.into()),
                ("guest_mount".into(), mount.to_string()),
            ]),
        }
    }

    #[test]
    fn disk_restore_of_a_checkpoint_requires_its_external_binds() {
        let resources = [
            resource("external_bind", "/data"),
            resource("owned_directory", "/own"),
        ];

        let paths = external_bind_guest_paths(&resources).unwrap();

        assert_eq!(paths, ["/data"]);

        let config = |builder: SandboxBuilder, complete: bool| {
            let mut config = builder.config.into_config();
            config.restore_resources.require_complete = complete;
            config
        };
        let unmapped = config(SandboxBuilder::new("restore"), true);

        let refusal = require_guest_mounts(&unmapped, paths.clone(), None).unwrap_err();
        let error = refusal.to_string();
        let MicrosandboxError::MissingRestoreBindings { missing, restore } = refusal else {
            panic!("an unmapped disk restore must report missing bindings");
        };

        assert_eq!(missing, ["mount /data"]);
        assert_eq!(restore, RestoreKind::Disk);
        assert!(error.contains("restore requires destination bindings for: mount /data;"));
        assert!(error.contains("provide a destination mount for each path"));
        assert!(error.contains("explicitly allow missing resources"));
        assert!(!error.contains("--"));
        assert!(!error.contains("captured disk"));

        let tmpfs = config(
            SandboxBuilder::new("restore").volume("/data", |m| m.tmpfs()),
            true,
        );

        let Err(MicrosandboxError::MissingRestoreBindings { missing, restore }) =
            require_guest_mounts(&tmpfs, paths.clone(), None)
        else {
            panic!("a tmpfs is not a host binding");
        };

        assert_eq!(missing, ["mount /data"]);
        assert_eq!(restore, RestoreKind::Disk);

        let mapped = config(
            SandboxBuilder::new("restore").volume("/data/", |m| m.bind("/tmp/d")),
            true,
        );
        let opted_out = config(SandboxBuilder::new("restore"), false);

        require_guest_mounts(&mapped, paths.clone(), None).unwrap();
        require_guest_mounts(&opted_out, paths, None).unwrap();
    }

    #[test]
    fn restore_rejects_bind_that_drops_captured_hide_path() {
        let mut config = SandboxBuilder::new("restore")
            .volume("/data", |m| m.bind("/tmp/d"))
            .config
            .into_config();
        config.restore_resources.require_complete = true;
        let captured = vec![ExternalMountPolicy {
            guest_path: "/data".into(),
            hide_path: vec![".env".into()],
        }];

        let refusal =
            require_guest_mounts(&config, vec!["/data".into()], Some(captured)).unwrap_err();
        let error = refusal.to_string();

        assert!(
            error.contains("weaken bind-mount hide-path policy at /data"),
            "{error}"
        );
        assert!(error.contains("re-declare the hide-path list"), "{error}");
    }

    #[test]
    fn restore_accepts_bind_that_preserves_hide_path() {
        let mut config = SandboxBuilder::new("restore")
            .volume("/data", |m| m.bind("/tmp/d").hide_path([".env"]))
            .config
            .into_config();
        config.restore_resources.require_complete = true;
        let captured = vec![ExternalMountPolicy {
            guest_path: "/data".into(),
            hide_path: vec![".env".into()],
        }];

        require_guest_mounts(&config, vec!["/data".into()], Some(captured)).unwrap();
    }

    #[test]
    fn restore_accepts_bind_that_strengthens_hide_path() {
        let mut config = SandboxBuilder::new("restore")
            .volume("/data", |m| m.bind("/tmp/d").hide_path([".env", "*.log"]))
            .config
            .into_config();
        config.restore_resources.require_complete = true;
        let captured = vec![ExternalMountPolicy {
            guest_path: "/data".into(),
            hide_path: vec![".env".into()],
        }];

        require_guest_mounts(&config, vec!["/data".into()], Some(captured)).unwrap();
    }

    #[test]
    fn restore_accepts_bind_that_adds_a_positive_pattern() {
        let mut config = SandboxBuilder::new("restore")
            .volume("/data", |m| m.bind("/tmp/d").hide_path([".env", ".git"]))
            .config
            .into_config();
        config.restore_resources.require_complete = true;
        let captured = vec![ExternalMountPolicy {
            guest_path: "/data".into(),
            hide_path: vec![".env".into()],
        }];

        require_guest_mounts(&config, vec!["/data".into()], Some(captured)).unwrap();
    }

    #[test]
    fn restore_rejects_destination_negation_that_reopens_captured_hide_path() {
        let mut config = SandboxBuilder::new("restore")
            .volume("/data", |m| m.bind("/tmp/d").hide_path([".env", "!.env"]))
            .config
            .into_config();
        config.restore_resources.require_complete = true;
        let captured = vec![ExternalMountPolicy {
            guest_path: "/data".into(),
            hide_path: vec![".env".into()],
        }];

        let refusal = require_guest_mounts(&config, vec!["/data".into()], Some(captured))
            .expect_err("a destination negation that reopens .env must be refused");
        let error = refusal.to_string();

        assert!(
            error.contains("weaken bind-mount hide-path policy at /data"),
            "{error}"
        );
    }

    #[test]
    fn restore_rejects_reordered_hide_path_that_reopens_captured_name() {
        // Same set, different order: gitignore is last-match-wins, so moving the
        // `!*.txt` negation after `secret.txt` re-exposes it even though every
        // captured pattern is still present.
        let mut config = SandboxBuilder::new("restore")
            .volume("/data", |m| {
                m.bind("/tmp/d").hide_path(["*", "secret.txt", "!*.txt"])
            })
            .config
            .into_config();
        config.restore_resources.require_complete = true;
        let captured = vec![ExternalMountPolicy {
            guest_path: "/data".into(),
            hide_path: vec!["*".into(), "!*.txt".into(), "secret.txt".into()],
        }];

        let refusal = require_guest_mounts(&config, vec!["/data".into()], Some(captured))
            .expect_err("reordering rules that re-exposes a name must be refused");
        let error = refusal.to_string();

        assert!(
            error.contains("weaken bind-mount hide-path policy at /data"),
            "{error}"
        );
    }

    #[test]
    fn restore_accepts_legacy_manifest_without_policy() {
        let mut config = SandboxBuilder::new("restore")
            .volume("/data", |m| m.bind("/tmp/d"))
            .config
            .into_config();
        config.restore_resources.require_complete = true;

        require_guest_mounts(&config, vec!["/data".into()], None).unwrap();
    }

    async fn requested_mount() -> VolumeMount {
        Sandbox::builder("mount-admission")
            .image("/tmp/rootfs")
            .volume("/data", |mount| {
                mount.named_with("external-dir", |volume| volume.ensure_exists())
            })
            .build()
            .await
            .unwrap()
            .spec
            .mounts
            .remove(0)
    }

    #[tokio::test]
    async fn missing_named_external_mount_never_recreates_catalog_or_directory() {
        let temp = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(temp.path())
            .build()
            .await
            .unwrap();
        assert!(
            admit_existing_named_mount(&local, Some(requested_mount().await))
                .await
                .unwrap()
                .is_none()
        );
        assert!(!local.volume_path("external-dir").exists());
        let db = local.db().await.unwrap();
        assert!(
            volume::Entity::find()
                .one(db.read())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn existing_named_external_mount_loses_creation_intent_without_creating_path() {
        let temp = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(temp.path())
            .build()
            .await
            .unwrap();
        let db = local.db().await.unwrap();
        volume::Entity::insert(volume::ActiveModel {
            name: Set("external-dir".into()),
            kind: Set(VolumeKind::Directory.as_str().into()),
            ..Default::default()
        })
        .exec(db.write())
        .await
        .unwrap();
        let admitted = admit_existing_named_mount(&local, Some(requested_mount().await))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(admitted, VolumeMount::Named { create: None, .. }));
        assert!(!local.volume_path("external-dir").exists());
    }

    #[tokio::test]
    async fn named_disk_cannot_replace_an_external_filesystem_transport() {
        let temp = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(temp.path())
            .build()
            .await
            .unwrap();
        let db = local.db().await.unwrap();
        volume::Entity::insert(volume::ActiveModel {
            name: Set("external-dir".into()),
            kind: Set(VolumeKind::Disk.as_str().into()),
            ..Default::default()
        })
        .exec(db.write())
        .await
        .unwrap();
        assert!(
            admit_existing_named_mount(&local, Some(requested_mount().await))
                .await
                .unwrap_err()
                .to_string()
                .contains("directory volume")
        );
        assert!(!local.volume_path("external-dir").exists());
    }
}
