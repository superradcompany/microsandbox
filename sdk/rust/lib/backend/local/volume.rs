//! Local volume preparation, recovery, and sandbox mount resolution.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, QueryFilter, Set, Statement,
};

use super::LocalBackend;
use super::creation::CreationStorage;
use crate::db::entity::volume as volume_entity;
use crate::sandbox::{
    DiskImageFormat, NamedVolumeMode, SandboxConfig, VolumeMount, validate_named_disk_mount_options,
};
use crate::volume::{
    VolumeConfig, VolumeKind, lock_volume_name, provision_volume_path, validate_volume_config,
    validate_volume_name,
};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Local storage metadata for a named volume mounted by a sandbox.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedNamedVolume {
    pub(crate) kind: VolumeKind,
    pub(crate) path: PathBuf,
    pub(crate) format: Option<DiskImageFormat>,
    pub(crate) fstype: Option<String>,
    pub(crate) quota_mib: Option<u32>,
}

/// Named volume row and path created for one sandbox create attempt.
#[derive(Debug)]
pub(crate) struct CreatedNamedVolume {
    pub(crate) id: i32,
    pub(crate) path: PathBuf,
}

/// Sandbox-create named volume preflight state.
#[derive(Debug, Default)]
pub(crate) struct EnsuredNamedVolumes {
    created: Vec<CreatedNamedVolume>,
    _locks: Vec<Arc<File>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl EnsuredNamedVolumes {
    pub(crate) fn is_empty(&self) -> bool {
        self.created.is_empty()
    }
}

impl LocalBackend {
    /// Prevent another sandbox or a direct volume handle from adopting provisional storage.
    pub(crate) async fn ensure_volume_available(
        &self,
        volume_id: i32,
        creator: Option<&str>,
    ) -> MicrosandboxResult<()> {
        if self.volume_creation_pending(volume_id).await? {
            return Err(MicrosandboxError::InvalidConfig(
                "volume creation is incomplete; remove the volume and create it again before using it".into(),
            ));
        }

        let db = self.db().await?.read();

        if !microsandbox_db::catalog::has_column(db, "volume", "pending_creation_sandbox_id")
            .await?
        {
            return Ok(());
        }

        let row = db.query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT sandbox.name FROM volume JOIN sandbox ON sandbox.id = volume.pending_creation_sandbox_id WHERE volume.id = ?",
            [volume_id.into()],
        )).await?;

        if let Some(row) = row {
            let name: String = row.try_get("", "name")?;
            if creator != Some(name.as_str()) {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "volume belongs to incomplete sandbox {name:?}; remove or complete that sandbox before using the volume"
                )));
            }
        }

        Ok(())
    }

    /// Whether a standalone volume still needs preparation or recovery.
    pub(crate) async fn volume_creation_pending(&self, volume_id: i32) -> MicrosandboxResult<bool> {
        let db = self.db().await?.read();

        if !microsandbox_db::catalog::has_column(db, "volume", "creation_state").await? {
            return Ok(false);
        }

        Ok(db
            .query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "SELECT id FROM volume WHERE id = ? AND creation_state IS NOT NULL",
                [volume_id.into()],
            ))
            .await?
            .is_some())
    }

    /// Prepare a reserved standalone volume; the worker retains its name lock on cancellation.
    pub(crate) async fn materialize_volume(
        &self,
        config: &VolumeConfig,
        volume_id: i32,
        name_lock: Arc<File>,
    ) -> MicrosandboxResult<()> {
        let path = self.volume_path(&config.name);
        let config = config.clone();
        let worker_lock = name_lock.clone();

        tokio::task::spawn_blocking(move || {
            let _lock = worker_lock;

            crate::volume::provision_volume_path_sync(&config, &path)
        })
        .await
        .map_err(|error| MicrosandboxError::Runtime(format!("volume preparation: {error}")))??;

        self.db()
            .await?
            .write()
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE volume SET creation_state = NULL WHERE id = ?",
                [volume_id.into()],
            ))
            .await?;
        Ok(())
    }

    /// Delete files before atomically releasing the catalog reservation.
    pub(crate) async fn remove_volume_storage(
        &self,
        volume_id: i32,
        path: PathBuf,
        name_lock: Arc<File>,
        disk_lock: Option<File>,
    ) -> MicrosandboxResult<()> {
        let worker_lock = name_lock.clone();

        tokio::task::spawn_blocking(move || {
            let _name_lock = worker_lock;
            let _disk_lock = disk_lock;

            crate::sandbox::remove_dir_if_exists(&path)
        })
        .await
        .map_err(|error| MicrosandboxError::Runtime(format!("volume cleanup: {error}")))??;

        self.db()
            .await?
            .write()
            .transaction(|txn| async move {
                txn.execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "UPDATE volume SET creation_state = NULL WHERE id = ?",
                    [volume_id.into()],
                ))
                .await?;

                txn.execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "DELETE FROM volume WHERE id = ?",
                    [volume_id.into()],
                ))
                .await?;

                Ok::<_, MicrosandboxError>((txn, ()))
            })
            .await
    }

    pub(crate) async fn ensure_named_volumes(
        &self,
        storage: &CreationStorage,
        config: &SandboxConfig,
    ) -> MicrosandboxResult<EnsuredNamedVolumes> {
        let locks =
            lock_named_volume_mounts(
                config,
                |name| async move { lock_volume_name(self, &name).await },
            )
            .await?;

        let mut created = Vec::new();

        // The sandbox recovery record owns every new volume, including a failed one.
        // Keep partial storage intact until recovery can exclude all filesystem workers.
        self.ensure_named_volumes_inner(storage, config, &mut created)
            .await?;

        // Resolve every named mount while the volume locks are still held and
        // before launch. Existing disk-backed volumes are only distinguishable
        // through the catalog, so ownership validation needs the resolved mounts.
        self.resolve_named_volumes(config).await?;

        Ok(EnsuredNamedVolumes {
            created,
            _locks: locks,
        })
    }

    async fn ensure_named_volumes_inner(
        &self,
        storage: &CreationStorage,
        config: &SandboxConfig,
        created: &mut Vec<CreatedNamedVolume>,
    ) -> MicrosandboxResult<()> {
        for mount in &config.spec.mounts {
            let Some(create) = mount.named_create() else {
                continue;
            };

            validate_volume_name(create.name())?;
            let pools = self.db().await?;
            let existing = volume_entity::Entity::find()
                .filter(volume_entity::Column::Name.eq(create.name()))
                .one(pools.read())
                .await?;

            if let Some(existing) = existing {
                self.ensure_volume_available(existing.id, Some(&config.spec.name))
                    .await?;

                match create.mode() {
                    NamedVolumeMode::Create => {
                        return Err(MicrosandboxError::VolumeAlreadyExists(
                            create.name().to_string(),
                        ));
                    }
                    NamedVolumeMode::EnsureExists => {
                        validate_existing_named_volume(create, &existing)?;
                        continue;
                    }
                    NamedVolumeMode::Existing => continue,
                }
            }

            if create.mode() == NamedVolumeMode::Existing {
                return Err(MicrosandboxError::VolumeNotFound(create.name().to_string()));
            }

            let volume_config = VolumeConfig {
                name: create.name().to_string(),
                kind: create.kind(),
                quota_mib: create.quota_mib(),
                capacity_mib: create.capacity_mib(),
                labels: create.labels().to_vec(),
            };
            validate_volume_config(&volume_config)?;

            let labels_json = if create.labels().is_empty() {
                None
            } else {
                Some(serde_json::to_string(create.labels())?)
            };
            let now = chrono::Utc::now().naive_utc();
            let capacity_bytes = volume_config
                .capacity_mib
                .map(|mib| i64::from(mib) * 1024 * 1024);
            let model = volume_entity::ActiveModel {
                name: Set(volume_config.name.clone()),
                kind: Set(volume_config.kind.as_str().to_string()),
                quota_mib: Set(volume_config.quota_mib.map(|value| value as i32)),
                size_bytes: Set(None),
                capacity_bytes: Set(capacity_bytes),
                disk_format: Set(
                    (volume_config.kind == VolumeKind::Disk).then(|| "raw".to_string())
                ),
                disk_fstype: Set(
                    (volume_config.kind == VolumeKind::Disk).then(|| "ext4".to_string())
                ),
                labels: Set(labels_json),
                created_at: Set(Some(now)),
                updated_at: Set(Some(now)),
                ..Default::default()
            };
            // The volume row and its create ownership commit together, before provisioning files.
            // A crash cannot make a newly-created volume look like a preexisting shared volume.
            let owner = pools
                .write()
                .query_one_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "SELECT id FROM sandbox WHERE name = ? AND creation_state IS NOT NULL",
                    [config.spec.name.clone().into()],
                ))
                .await?
                .ok_or_else(|| {
                    MicrosandboxError::Runtime(
                        "named volume creation requires a reserved sandbox".into(),
                    )
                })?
                .try_get::<i32>("", "id")?;

            let path = self.volume_path(&volume_config.name);
            if tokio::fs::try_exists(&path).await? {
                return Err(MicrosandboxError::VolumeAlreadyExists(
                    volume_config.name.clone(),
                ));
            }

            let volume_id = pools
                .write()
                .transaction(|txn| {
                    let model = model.clone();

                    async move {
                        let inserted = volume_entity::Entity::insert(model).exec(&txn).await?;
                        let volume_id = inserted.last_insert_id;
                        txn.execute_raw(Statement::from_sql_and_values(
                            DatabaseBackend::Sqlite,
                            "UPDATE volume SET pending_creation_sandbox_id = ? WHERE id = ?",
                            [owner.into(), volume_id.into()],
                        ))
                        .await?;
                        Ok::<_, MicrosandboxError>((txn, volume_id))
                    }
                })
                .await?;

            // The sandbox's recovery record owns this path before any files are written.
            provision_volume_path(&volume_config, &storage.at(&path)).await?;
            created.push(CreatedNamedVolume {
                id: volume_id,
                path,
            });
        }

        Ok(())
    }

    /// Roll back published volumes; provisional volumes belong to sandbox recovery.
    pub(crate) async fn rollback_created_named_volumes(
        &self,
        volumes: &EnsuredNamedVolumes,
    ) -> MicrosandboxResult<()> {
        if volumes.is_empty() {
            return Ok(());
        }

        for volume in &volumes.created {
            self.ensure_volume_available(volume.id, None).await?;
            crate::sandbox::remove_dir_if_exists(&volume.path)?;
        }

        let ids = volumes
            .created
            .iter()
            .map(|volume| volume.id)
            .collect::<Vec<_>>();
        volume_entity::Entity::delete_many()
            .filter(volume_entity::Column::Id.is_in(ids))
            .exec(self.db().await?.write())
            .await?;

        Ok(())
    }

    pub(crate) async fn resolve_named_volumes(
        &self,
        config: &SandboxConfig,
    ) -> MicrosandboxResult<HashMap<String, ResolvedNamedVolume>> {
        let mut resolved: HashMap<String, ResolvedNamedVolume> = HashMap::new();

        for mount in &config.spec.mounts {
            let VolumeMount::Named {
                name,
                options,
                stat_virtualization,
                host_permissions,
                ..
            } = mount
            else {
                continue;
            };

            if let Some(volume) = resolved.get(name) {
                if volume.kind == VolumeKind::Disk {
                    validate_named_disk_mount_options(
                        name,
                        *stat_virtualization,
                        *host_permissions,
                        options,
                    )?;
                }
                continue;
            }

            let pools = self.db().await?;
            let model = volume_entity::Entity::find()
                .filter(volume_entity::Column::Name.eq(name))
                .one(pools.read())
                .await?
                .ok_or_else(|| MicrosandboxError::VolumeNotFound(name.clone()))?;

            let kind = VolumeKind::from_db_value(&model.kind);
            self.ensure_volume_available(model.id, Some(&config.spec.name))
                .await?;

            let path = self.volume_path(name);
            let volume = match kind {
                VolumeKind::Directory => ResolvedNamedVolume {
                    kind,
                    path,
                    format: None,
                    fstype: None,
                    quota_mib: model.quota_mib.map(|value| value.max(0) as u32),
                },
                VolumeKind::Disk => {
                    validate_named_disk_mount_options(
                        name,
                        *stat_virtualization,
                        *host_permissions,
                        options,
                    )?;
                    let format = model
                        .disk_format
                        .as_deref()
                        .unwrap_or("raw")
                        .parse::<DiskImageFormat>()
                        .map_err(|err| {
                            MicrosandboxError::InvalidConfig(format!(
                                "disk named volume {name:?} has invalid disk format: {err}"
                            ))
                        })?;

                    ResolvedNamedVolume {
                        kind,
                        path: path.join("disk.raw"),
                        format: Some(format),
                        fstype: model.disk_fstype,
                        quota_mib: None,
                    }
                }
            };

            resolved.insert(name.clone(), volume);
        }

        Ok(resolved)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn lock_named_volume_mounts<Guard, Acquire>(
    config: &SandboxConfig,
    mut acquire: impl FnMut(String) -> Acquire,
) -> MicrosandboxResult<Vec<Guard>>
where
    Acquire: Future<Output = MicrosandboxResult<Guard>>,
{
    let mut names = BTreeSet::new();
    for mount in &config.spec.mounts {
        if let VolumeMount::Named { name, create, .. } = mount {
            validate_volume_name(name)?;
            if create.as_ref().is_some_and(|create| create.name() != name) {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "named volume {name:?} has a different creation name"
                )));
            }
            names.insert(name.clone());
        }
    }

    let mut locks = Vec::with_capacity(names.len());
    for name in names {
        locks.push(acquire(name).await?);
    }
    Ok(locks)
}

fn validate_existing_named_volume(
    requested: &microsandbox_types::NamedVolumeCreate,
    existing: &volume_entity::Model,
) -> MicrosandboxResult<()> {
    let actual_kind = VolumeKind::from_db_value(&existing.kind);
    if requested.kind() != actual_kind {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "named volume {:?} already exists as {}, but this sandbox requested {}",
            requested.name(),
            actual_kind.as_str(),
            requested.kind().as_str()
        )));
    }

    if let Some(requested_quota_mib) = requested.quota_mib()
        && existing.quota_mib != Some(requested_quota_mib as i32)
    {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "named volume {:?} already exists with quota {:?} MiB, but this sandbox requested {} MiB",
            requested.name(),
            existing.quota_mib,
            requested_quota_mib
        )));
    }

    if let Some(requested_capacity_mib) = requested.capacity_mib() {
        let requested_capacity_bytes = i64::from(requested_capacity_mib) * 1024 * 1024;
        if existing.capacity_bytes != Some(requested_capacity_bytes) {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "named volume {:?} already exists with capacity {:?} bytes, but this sandbox requested {} bytes",
                requested.name(),
                existing.capacity_bytes,
                requested_capacity_bytes
            )));
        }
    }

    validate_requested_named_volume_labels(requested, existing)?;

    Ok(())
}

fn validate_requested_named_volume_labels(
    requested: &microsandbox_types::NamedVolumeCreate,
    existing: &volume_entity::Model,
) -> MicrosandboxResult<()> {
    if requested.labels().is_empty() {
        return Ok(());
    }

    let existing_labels = existing
        .labels
        .as_deref()
        .map(serde_json::from_str::<Vec<(String, String)>>)
        .transpose()?
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    for (key, requested_value) in requested.labels() {
        match existing_labels.get(key) {
            Some(existing_value) if existing_value == requested_value => {}
            Some(existing_value) => {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "named volume {:?} already exists with label {key:?}={existing_value:?}, but this sandbox requested {requested_value:?}",
                    requested.name()
                )));
            }
            None => {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "named volume {:?} already exists without requested label {key:?}",
                    requested.name()
                )));
            }
        }
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::future::{Future, poll_fn};
    use std::sync::mpsc;
    use std::task::Poll;
    use std::time::Duration;

    use sea_orm::{
        ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, QueryFilter,
        Set, Statement,
    };
    use tempfile::tempdir;

    use super::*;
    use crate::backend::Backend;
    use crate::sandbox::SandboxBuilder;
    use crate::volume::Volume;

    fn named_volume_create(
        name: &str,
        kind: VolumeKind,
        quota_mib: Option<u32>,
        capacity_mib: Option<u32>,
        labels: Vec<(String, String)>,
    ) -> microsandbox_types::NamedVolumeCreate {
        microsandbox_types::NamedVolumeCreate {
            mode: crate::sandbox::NamedVolumeMode::EnsureExists,
            name: name.to_string(),
            kind,
            quota_mib,
            capacity_mib,
            labels,
        }
    }

    fn existing_volume_model(
        name: &str,
        kind: VolumeKind,
        quota_mib: Option<i32>,
        capacity_bytes: Option<i64>,
        labels: Option<Vec<(String, String)>>,
    ) -> super::volume_entity::Model {
        super::volume_entity::Model {
            id: 1,
            name: name.to_string(),
            kind: kind.as_str().to_string(),
            quota_mib,
            size_bytes: None,
            capacity_bytes,
            disk_format: (kind == VolumeKind::Disk).then(|| "raw".to_string()),
            disk_fstype: (kind == VolumeKind::Disk).then(|| "ext4".to_string()),
            labels: labels.map(|labels| serde_json::to_string(&labels).unwrap()),
            created_at: Some(chrono::Utc::now().naive_utc()),
            updated_at: Some(chrono::Utc::now().naive_utc()),
        }
    }

    #[test]
    fn test_validate_existing_named_volume_rejects_quota_mismatch() {
        let requested =
            named_volume_create("mydir", VolumeKind::Directory, Some(1024), None, Vec::new());
        let existing = existing_volume_model("mydir", VolumeKind::Directory, Some(512), None, None);

        let err = super::validate_existing_named_volume(&requested, &existing).unwrap_err();

        assert!(err.to_string().contains("quota"), "got: {err}");
    }

    #[test]
    fn test_validate_existing_named_volume_rejects_capacity_mismatch() {
        let requested =
            named_volume_create("mydisk", VolumeKind::Disk, None, Some(2048), Vec::new());
        let existing_capacity_bytes = 1024_i64 * 1024 * 1024;
        let existing = existing_volume_model(
            "mydisk",
            VolumeKind::Disk,
            None,
            Some(existing_capacity_bytes),
            None,
        );

        let err = super::validate_existing_named_volume(&requested, &existing).unwrap_err();

        assert!(err.to_string().contains("capacity"), "got: {err}");
    }

    #[test]
    fn test_validate_existing_named_volume_rejects_requested_label_mismatch() {
        let requested = named_volume_create(
            "mydir",
            VolumeKind::Directory,
            None,
            None,
            vec![("env".to_string(), "prod".to_string())],
        );
        let existing = existing_volume_model(
            "mydir",
            VolumeKind::Directory,
            None,
            None,
            Some(vec![("env".to_string(), "dev".to_string())]),
        );

        let err = super::validate_existing_named_volume(&requested, &existing).unwrap_err();

        assert!(err.to_string().contains("label"), "got: {err}");
    }

    #[test]
    fn test_validate_existing_named_volume_allows_extra_existing_labels() {
        let requested = named_volume_create(
            "mydir",
            VolumeKind::Directory,
            None,
            None,
            vec![("env".to_string(), "prod".to_string())],
        );
        let existing = existing_volume_model(
            "mydir",
            VolumeKind::Directory,
            None,
            None,
            Some(vec![
                ("env".to_string(), "prod".to_string()),
                ("team".to_string(), "runtime".to_string()),
            ]),
        );

        super::validate_existing_named_volume(&requested, &existing).unwrap();
    }

    #[tokio::test]
    async fn test_failed_named_volume_formatting_retains_owner_until_recovery() {
        let temp = tempdir().unwrap();
        let home = temp.path().join("home");
        let volumes_dir = temp.path().join("volumes");
        std::fs::create_dir_all(&volumes_dir).unwrap();
        let local = LocalBackend::builder()
            .config_path(home.join("config.json"))
            .managed_config_path(home.join("managed.json"))
            .home(&home)
            .volumes_dir(&volumes_dir)
            .build()
            .await
            .unwrap();
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/data", |m| {
                m.named_with("broken", |v| v.ensure_exists().disk().size(1))
            })
            .build()
            .await
            .unwrap();

        let pools = local.db().await.unwrap();
        pools.write().execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO sandbox (id, name, config, status, ephemeral, creation_state) VALUES (1, 'test', ?, 'Starting', 0, 'preparing')",
            [serde_json::to_string(&config).unwrap().into()],
        )).await.unwrap();

        let err = local
            .ensure_named_volumes(
                &crate::backend::local::creation::CreationStorage::for_test(
                    &local.sandboxes_dir().join(&config.spec.name),
                ),
                &config,
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("too small"), "got: {err}");
        let pools = local.db().await.unwrap();
        let existing = super::volume_entity::Entity::find()
            .filter(super::volume_entity::Column::Name.eq("broken"))
            .one(pools.read())
            .await
            .unwrap();
        assert!(
            existing.is_some(),
            "failed formatting must retain its recovery owner"
        );
        local
            .remove_incomplete_sandbox(
                1,
                "test",
                crate::backend::local::creation::RemovalMode::Recovery,
            )
            .await
            .unwrap();
        assert!(!local.volume_path("broken").exists());
        assert!(
            super::volume_entity::Entity::find()
                .all(pools.read())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn mismatched_named_volume_creation_name_is_rejected_before_locking() {
        let mut config = SandboxBuilder::new("mismatch")
            .image("/tmp/rootfs")
            .volume("/data", |m| m.named_with("expected", |v| v.ensure_exists()))
            .build()
            .await
            .unwrap();
        let VolumeMount::Named {
            create: Some(create),
            ..
        } = &mut config.spec.mounts[0]
        else {
            panic!("expected a named-volume creation request");
        };
        create.name = "different".into();

        let acquired = Cell::new(false);
        let error = super::lock_named_volume_mounts(&config, |name| {
            acquired.set(true);
            std::future::ready(Ok(name))
        })
        .await
        .unwrap_err();
        assert!(!acquired.get());
        assert!(error.to_string().contains("different creation name"));
    }

    #[tokio::test]
    async fn named_volume_waiter_yields_and_cancellation_releases_partial_locks() {
        use std::cell::RefCell;

        use tokio::sync::oneshot;

        let config = SandboxBuilder::new("waiter")
            .image("/tmp/rootfs")
            // Deliberately reverse the mount order: acquisition must still take a-first
            // before waiting for z-shared, and cancellation must release that partial set.
            .volume("/shared", |mount| mount.named("z-shared"))
            .volume("/first", |mount| mount.named("a-first"))
            .volume("/first-again", |mount| mount.named("a-first"))
            .build()
            .await
            .unwrap();
        // Dropping the sender reports guard release without OS locks that unrelated
        // parallel tests can inherit between fork and exec.
        let (first_guard, mut first_released) = oneshot::channel::<()>();
        let mut first_guard = Some(first_guard);
        let attempts = RefCell::new(Vec::new());
        let mut waiter = Box::pin(super::lock_named_volume_mounts(&config, |name| {
            attempts.borrow_mut().push(name.clone());
            let guard = match name.as_str() {
                "a-first" => Some(first_guard.take().expect("lock acquired only once")),
                "z-shared" => None,
                _ => panic!("unexpected volume: {name}"),
            };
            async move {
                match guard {
                    Some(guard) => Ok(guard),
                    None => std::future::pending().await,
                }
            }
        }));

        // One poll must yield at the contended second lock while retaining the first.
        assert!(futures::poll!(waiter.as_mut()).is_pending());
        assert_eq!(*attempts.borrow(), ["a-first", "z-shared"]);
        assert_eq!(
            first_released.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );

        drop(waiter);
        assert_eq!(
            first_released.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        );

        let locks = super::lock_named_volume_mounts(&config, |name| std::future::ready(Ok(name)))
            .await
            .unwrap();
        assert_eq!(locks, ["a-first", "z-shared"]);
    }

    #[tokio::test]
    async fn test_later_named_volume_failure_keeps_earlier_volume_recoverable() {
        let temp = tempdir().unwrap();
        let home = temp.path().join("home");
        let volumes_dir = temp.path().join("volumes");
        let local = LocalBackend::builder()
            .config_path(home.join("config.json"))
            .managed_config_path(home.join("managed.json"))
            .home(&home)
            .volumes_dir(&volumes_dir)
            .build()
            .await
            .unwrap();
        let config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/a-ok", |m| {
                m.named_with("first-created", |v| v.ensure_exists())
            })
            .volume("/z-bad", |m| {
                m.named_with("bad-disk", |v| v.ensure_exists().disk().size(1_u32))
            })
            .build()
            .await
            .unwrap();

        let pools = local.db().await.unwrap();
        pools.write().execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO sandbox (id, name, config, status, ephemeral, creation_state) VALUES (1, 'test', ?, 'Starting', 0, 'preparing')",
            [serde_json::to_string(&config).unwrap().into()],
        )).await.unwrap();

        let err = local
            .ensure_named_volumes(
                &crate::backend::local::creation::CreationStorage::for_test(
                    &local.sandboxes_dir().join(&config.spec.name),
                ),
                &config,
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("too small"), "got: {err}");
        assert!(local.volume_path("first-created").exists());
        let pools = local.db().await.unwrap();
        let existing = super::volume_entity::Entity::find()
            .filter(super::volume_entity::Column::Name.eq("first-created"))
            .one(pools.read())
            .await
            .unwrap();
        assert!(
            existing.is_some(),
            "earlier volumes must remain tracked until sandbox recovery"
        );
        local
            .remove_incomplete_sandbox(
                1,
                "test",
                crate::backend::local::creation::RemovalMode::Recovery,
            )
            .await
            .unwrap();
        assert!(!local.volume_path("first-created").exists());
        assert!(!local.volume_path("bad-disk").exists());
        assert!(
            super::volume_entity::Entity::find()
                .all(pools.read())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_existing_named_volume_mode_does_not_validate_default_metadata() {
        let temp = tempdir().unwrap();
        let local = LocalBackend::builder()
            .config_path(temp.path().join("config.json"))
            .managed_config_path(temp.path().join("managed.json"))
            .home(temp.path())
            .build()
            .await
            .unwrap();
        let pools = local.db().await.unwrap();
        super::volume_entity::ActiveModel {
            name: Set("docker-data".to_string()),
            kind: Set(VolumeKind::Disk.as_str().to_string()),
            capacity_bytes: Set(Some(2048_i64 * 1024 * 1024)),
            disk_format: Set(Some("raw".to_string())),
            disk_fstype: Set(Some("ext4".to_string())),
            created_at: Set(Some(chrono::Utc::now().naive_utc())),
            updated_at: Set(Some(chrono::Utc::now().naive_utc())),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();

        let mut config = SandboxBuilder::new("test")
            .image("/tmp/rootfs")
            .volume("/var/lib/docker", |m| m.named("docker-data"))
            .build()
            .await
            .unwrap();
        if let VolumeMount::Named { create, .. } = &mut config.spec.mounts[0] {
            // Directly deserialized configs can still carry an explicit
            // Existing create object even though the builder normalizes this
            // path to a plain named mount.
            *create = Some(microsandbox_types::NamedVolumeCreate {
                mode: crate::sandbox::NamedVolumeMode::Existing,
                name: "docker-data".to_string(),
                kind: VolumeKind::Directory,
                quota_mib: None,
                capacity_mib: None,
                labels: Vec::new(),
            });
        }

        let ensured = local
            .ensure_named_volumes(
                &crate::backend::local::creation::CreationStorage::for_test(
                    &local.sandboxes_dir().join(&config.spec.name),
                ),
                &config,
            )
            .await
            .unwrap();
        assert!(ensured.is_empty());
    }

    #[tokio::test]
    async fn failed_standalone_disk_formatting_releases_files_and_name() {
        let home = tempfile::tempdir().unwrap();
        let local = Arc::new(
            crate::test_support::local_backend_builder(home.path().join("home"))
                .build()
                .await
                .unwrap(),
        );
        let backend: Arc<dyn Backend> = local.clone();

        let error = backend
            .volumes()
            .create(
                backend.clone(),
                Volume::builder("retry").disk().size(1).build(),
            )
            .await
            .err()
            .expect("undersized disk must fail formatting");
        assert!(error.to_string().contains("too small"), "{error}");
        assert!(!local.volume_path("retry").exists());
        assert!(
            backend
                .volumes()
                .list(backend.clone())
                .await
                .unwrap()
                .is_empty()
        );

        backend
            .volumes()
            .create(
                backend.clone(),
                Volume::builder("retry").disk().size(128).build(),
            )
            .await
            .unwrap();
        assert!(
            backend
                .volumes()
                .get(backend.clone(), "retry")
                .await
                .is_ok()
        );
        backend
            .volumes()
            .remove(backend.clone(), "retry")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn interrupted_volume_is_unavailable_until_removed_and_recreated() {
        let home = tempfile::tempdir().unwrap();
        let local = Arc::new(
            crate::test_support::local_backend_builder(home.path().join("home"))
                .build()
                .await
                .unwrap(),
        );
        let backend: Arc<dyn Backend> = local.clone();
        let db = local.db().await.unwrap();
        db.write().execute_unprepared(
            "INSERT INTO volume (name, kind, creation_state) VALUES ('interrupted', 'directory', 'creating')"
        ).await.unwrap();
        let path = local.volume_path("interrupted");
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("partial"), b"unfinished").unwrap();

        let error = backend
            .volumes()
            .get(backend.clone(), "interrupted")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("creation is incomplete"));
        assert!(
            backend
                .volumes()
                .fs_read("interrupted", "partial")
                .await
                .is_err()
        );
        let error = backend
            .volumes()
            .create(
                backend.clone(),
                Volume::builder("interrupted").directory().build(),
            )
            .await
            .err()
            .expect("incomplete volume must reject creation");
        assert!(error.to_string().contains("creation is incomplete"));
        assert!(
            error
                .to_string()
                .contains("remove the volume and create it again")
        );
        assert!(
            backend
                .volumes()
                .list(backend.clone())
                .await
                .unwrap()
                .iter()
                .any(|v| v.name() == "interrupted")
        );

        // Failed cleanup must keep the reservation when the path cannot be removed.
        let parked = home.path().join("parked");
        std::fs::rename(&path, &parked).unwrap();
        std::fs::write(&path, b"blocks directory removal").unwrap();
        assert!(
            backend
                .volumes()
                .remove(backend.clone(), "interrupted")
                .await
                .is_err()
        );
        assert!(
            backend
                .volumes()
                .get(backend.clone(), "interrupted")
                .await
                .unwrap_err()
                .to_string()
                .contains("creation is incomplete")
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(&parked, &path).unwrap();

        // A fresh backend recovers the persisted reservation after the creator has disappeared.
        let reopened: Arc<dyn Backend> = Arc::new(
            crate::test_support::local_backend_builder(home.path().join("home"))
                .build()
                .await
                .unwrap(),
        );
        reopened
            .volumes()
            .remove(reopened.clone(), "interrupted")
            .await
            .unwrap();
        assert!(!path.exists());
        reopened
            .volumes()
            .create(
                reopened.clone(),
                Volume::builder("interrupted").directory().build(),
            )
            .await
            .unwrap();
        assert!(
            reopened
                .volumes()
                .get(reopened.clone(), "interrupted")
                .await
                .is_ok()
        );
    }

    #[test]
    fn cancelled_volume_worker_retains_lock_and_recovery_record() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let home = tempfile::tempdir().unwrap();
            let local = Arc::new(
                crate::test_support::local_backend_builder(home.path().join("home"))
                    .build()
                    .await
                    .unwrap(),
            );
            let backend: Arc<dyn Backend> = local.clone();
            let db = local.db().await.unwrap();
            db.write().execute_unprepared(
                "INSERT INTO volume (id, name, kind, creation_state) VALUES (1, 'cancelled', 'directory', 'creating')"
            ).await.unwrap();
            let lock = lock_volume_name(&local, "cancelled").await.unwrap();

            let (release, released) = mpsc::channel();
            let (started, started_rx) = tokio::sync::oneshot::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                started.send(()).unwrap();
                let _ = released.recv_timeout(Duration::from_secs(10));
            });
            started_rx.await.unwrap();

            let config = Volume::builder("cancelled").directory().build();
            let mut create = Box::pin(local.materialize_volume(&config, 1, lock));
            let first_poll = poll_fn(|cx| Poll::Ready(create.as_mut().poll(cx))).await;
            assert!(first_poll.is_pending());
            drop(create);

            let lock_is_retained = tokio::time::timeout(
                Duration::from_millis(50),
                lock_volume_name(&local, "cancelled"),
            ).await.is_err();
            release.send(()).unwrap();
            blocker.await.unwrap();
            tokio::task::spawn_blocking(|| ()).await.unwrap();

            assert!(lock_is_retained, "cancelled worker released the volume name before finishing");
            assert!(local.volume_creation_pending(1).await.unwrap());
            assert!(local.volume_path("cancelled").exists());

            backend.volumes().remove(backend.clone(), "cancelled").await.unwrap();
            assert!(!local.volume_path("cancelled").exists());
        });
    }
}
