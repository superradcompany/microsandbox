//! Resolve external checkpoint bindings against explicit or source-local authorization.

use std::collections::BTreeSet;

use microsandbox_image::checkpoint::{CheckpointClosure, ObjectId};
use microsandbox_runtime::{
    checkpoint::ExternalMountAuthorization, launch::ExternalMountRestoreBinding,
};
use microsandbox_types::{ExternalMountRestorePolicy, VolumeKind, VolumeMount};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use super::SandboxConfig;
use crate::{
    MicrosandboxError, MicrosandboxResult,
    backend::LocalBackend,
    db::entity::{sandbox, volume},
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

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
        if let Some(selected) = config
            .spec
            .mounts
            .iter()
            .find(|mount| mount.guest() == guest)
        {
            match selected {
                VolumeMount::DiskImage { .. }
                | VolumeMount::Owned {
                    storage: microsandbox_types::OwnedVolumeStorage::Disk { .. },
                    ..
                } => {}
                VolumeMount::Named { name, .. } => {
                    let db = local.db().await?;
                    let model = volume::Entity::find()
                        .filter(volume::Column::Name.eq(name.as_str()))
                        .one(db.read())
                        .await?
                        .ok_or_else(|| integrity("explicit disk volume does not exist"))?;
                    if model.kind != "disk" {
                        return Err(integrity("captured block device requires a disk mapping"));
                    }
                }
                _ => return Err(integrity("captured block device requires a disk mapping")),
            }
        } else if unavailable_disks
            .insert(id.clone(), guest.clone())
            .is_some()
        {
            return Err(integrity("duplicate additional disk binding"));
        }
    }
    let mut tags = BTreeSet::new();
    for resource in resources.iter().filter(|resource| {
        resource
            .binding
            .get("role")
            .is_some_and(|role| role == "external_bind" || role == "owned_directory")
    }) {
        let mount: microsandbox_protocol::bootstrap::BootstrapDirMount = serde_json::from_str(
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
        let selected = admit_existing_named_mount(local, selected).await?;
        let unavailable = selected.is_none();
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
            device_id,
            mount,
            filename: resource.binding.get("filename").cloned(),
            remapped,
            unavailable,
        });
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
    resource: &microsandbox_image::checkpoint::ResourceDescriptor,
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm::Set;

    use super::*;
    use crate::Sandbox;

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
        let local = LocalBackend::builder()
            .home(temp.path())
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
        let local = LocalBackend::builder()
            .home(temp.path())
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
        let local = LocalBackend::builder()
            .home(temp.path())
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
