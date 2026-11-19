//! Host configuration admission for sandbox storage, shared by launch and stopped operations.

use std::path::Path;

use microsandbox_runtime::checkpoint::layout::{self, LegacyRootBinding};
use microsandbox_runtime::checkpoint::migration::{self, MigrationBindings, OwnedDiskBinding};
use microsandbox_types::{OwnedVolumeStorage, VolumeMount};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
use sha2::{Digest, Sha256};

use crate::backend::local::creation::CreationStorage;
use crate::sandbox::{RootDisk, RootfsSource, SandboxConfig, StorageRecoveryOptions};
use crate::{LocalBackend, MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fresh creation is proven by the live caller's reservation, never a writable catalog flag.
/// Keep its original persisted config while materialization adds image defaults in memory.
#[derive(Clone, Copy)]
pub(crate) enum StoragePreparation<'a> {
    Existing,
    New {
        catalog_id: i32,
        expected_config: &'a str,
    },
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Derive disk authority only from saved host configuration. Legacy journals are deliberately
/// absent here: they can select a view within these roles but cannot grant access to another disk.
pub(crate) fn bindings(
    config: &SandboxConfig,
    sandbox: &Path,
    catalog_id: i32,
    stored_config: &str,
) -> MicrosandboxResult<MigrationBindings> {
    let mut owned_disks = Vec::new();
    for mount in &config.spec.mounts {
        let VolumeMount::Owned {
            guest,
            storage: OwnedVolumeStorage::Disk { capacity_mib },
            options,
            ..
        } = mount
        else {
            continue;
        };
        let id = microsandbox_types::owned_volume_mount_id(guest);
        owned_disks.push(OwnedDiskBinding {
            path: sandbox.join("owned-volumes").join(&id).join("disk.raw"),
            id,
            capacity: u64::from(*capacity_mib) * 1024 * 1024,
            readonly: options.readonly,
        });
    }
    // The AUTOINCREMENT catalog ID distinguishes deletion/recreation of a sandbox name. Bind
    // the plan to persisted configuration as well, so a retry cannot silently change disk roles.
    let revision = Sha256::digest(stored_config.as_bytes());
    Ok(MigrationBindings {
        identity: format!("local:{catalog_id}"),
        config_revision: hex::encode(revision),
        root: root_binding(config, sandbox),
        owned_disks,
        aliases: Vec::new(),
    })
}

/// Caller owns the sandbox lifecycle and creation/storage guards for the entire operation.
pub(crate) async fn prepare(
    backend: &LocalBackend,
    config: &SandboxConfig,
    storage: &CreationStorage,
) -> MicrosandboxResult<()> {
    prepare_selected(backend, config, storage, &StorageRecoveryOptions::default()).await
}

/// Explicit recovery uses the same validation, catalog fence and publication path as startup.
pub(crate) async fn prepare_selected(
    backend: &LocalBackend,
    config: &SandboxConfig,
    storage: &CreationStorage,
    options: &StorageRecoveryOptions,
) -> MicrosandboxResult<()> {
    prepare_storage(
        backend,
        config,
        storage,
        StoragePreparation::Existing,
        options,
        None,
    )
    .await
}

/// Launch callers explicitly distinguish a newly reserved sandbox from existing storage.
pub(crate) async fn prepare_launch(
    backend: &LocalBackend,
    config: &SandboxConfig,
    storage: &CreationStorage,
    preparation: StoragePreparation<'_>,
) -> MicrosandboxResult<()> {
    prepare_storage(
        backend,
        config,
        storage,
        preparation,
        &StorageRecoveryOptions::default(),
        None,
    )
    .await
}

pub(crate) async fn prepare_storage(
    backend: &LocalBackend,
    config: &SandboxConfig,
    storage: &CreationStorage,
    preparation: StoragePreparation<'_>,
    options: &StorageRecoveryOptions,
    preview: Option<&migration::RecoveryPreview>,
) -> MicrosandboxResult<()> {
    let runtime = storage.join("runtime");
    // Unaffected workloads do only the bounded normal layout checks. In particular, do not
    // inventory legacy storage or write a protection row on every protected restart.
    if matches!(preparation, StoragePreparation::Existing)
        && layout::require_ready(&runtime).is_ok()
    {
        if preview.is_some() || !options.selections.is_empty() {
            return Err(MicrosandboxError::InvalidConfig(
                "protected storage is already ready; legacy recovery cannot replace its current view".into(),
            ));
        }
        return Ok(());
    }
    let database = backend
        .config()
        .home()
        .join(microsandbox_utils::DB_SUBDIR)
        .join(microsandbox_utils::DB_FILENAME);
    #[cfg(windows)]
    let database = if matches!(preparation, StoragePreparation::Existing) {
        // Legacy journals may select only within saved host authority. A catalog or WAL
        // writable by another account cannot supply that authority; inspect without repair
        // before reading the row, enumerating sources or recording a migration intent.
        microsandbox_db::private_storage::validate_database_inspection(&database).map_err(
            |error| MicrosandboxError::Runtime(format!(
                "storage migration/recovery required: catalog permissions do not establish private host authority: {error}; secure and inspect the preserved catalog before retrying"
            )),
        )?
    } else {
        database
    };
    let db = backend.db().await?;
    let row = db
        .write()
        .query_one_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT id, creation_state, config FROM sandbox WHERE name = ?",
            [config.spec.name.clone().into()],
        ))
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(config.spec.name.clone()))?;
    let id: i32 = row.try_get("", "id")?;
    let creating: Option<String> = row.try_get("", "creation_state")?;
    let stored_config: String = row.try_get("", "config")?;
    if let StoragePreparation::New {
        catalog_id,
        expected_config,
    } = preparation
    {
        if id != catalog_id || creating.is_none() || stored_config != expected_config {
            return Err(MicrosandboxError::Runtime(
                "new storage reservation identity or configuration changed before preparation"
                    .into(),
            ));
        }
        // Only this live creation call can authorize fresh initialization. An existing
        // sandbox cannot bypass legacy admission by changing creation_state in its catalog.
        microsandbox_db::protected_state::admit(&database, id, &config.spec.name, &stored_config)
            .await
            .map_err(|error| MicrosandboxError::Runtime(format!("storage admission: {error}")))?;
        return layout::initialize_new(&runtime).map_err(MicrosandboxError::Runtime);
    }
    if creating.is_some() {
        return Err(MicrosandboxError::InvalidConfig(
            "incomplete creation cannot be admitted as existing sandbox storage".into(),
        ));
    }

    // A terminal catalog row and a free lifecycle lock do not prove teardown of older
    // runtimes. This shared gate covers stopped snapshots, growth and compaction as well
    // as startup/recovery; none may capture a disk still held by the previous process.
    if LocalBackend::load_latest_run(db.read(), id)
        .await?
        .and_then(|run| run.pid)
        .is_some_and(microsandbox_utils::process::pid_exists)
    {
        return Err(MicrosandboxError::SandboxStillRunning(format!(
            "sandbox '{}' still has a recorded runtime process; wait for teardown before migrating storage and retry",
            config.spec.name
        )));
    }

    // Old full snapshots can leave writable aliases in another home's guest export, even
    // after their last visible name is removed. macOS has no usable per-file writer lease
    // for this application. Only explicit recovery may assert the required maintenance
    // window; scanning this catalog cannot establish host-wide quiescence. Keep the local
    // writer checks below as defense in depth, never as proof of this wider prerequisite.
    require_maintenance(options)?;

    let mut authority = bindings(config, storage.path(), id, &stored_config)?;
    // Parent checkpoints can expose an otherwise sealed ancestor through an old guest export.
    // Retain every related writer's guards until capture/publication has actually completed.
    let _related = super::storage_aliases::resolve(backend, config, id, &mut authority).await?;
    let selections = options
        .selections
        .iter()
        .map(|selection| migration::RecoverySelection {
            disk_id: selection.disk_id.clone(),
            candidate_id: selection.candidate_id.clone(),
        })
        .collect::<Vec<_>>();
    let mut plan = filesystem_work(&config.spec.name, || {
        if let Some(preview) = preview {
            migration::plan_previewed(&runtime, &authority, preview, &selections)
        } else if selections.is_empty() {
            migration::plan(&runtime, &authority)
        } else {
            migration::plan_selected(&runtime, &authority, &selections)
        }
    })?;
    if plan.is_ready() {
        return Ok(());
    }
    // Validation precedes protection registration. An ineligible legacy layout must not gain
    // new downgrade restrictions merely because the user tried to inspect or start it.
    filesystem_work(&config.spec.name, || plan.record_intent())?;
    microsandbox_db::protected_state::admit(&database, id, &config.spec.name, &stored_config)
        .await
        .map_err(|error| MicrosandboxError::Runtime(format!("storage admission: {error}")))?;
    filesystem_work(&config.spec.name, || plan.complete())
}

pub(crate) fn require_maintenance(options: &StorageRecoveryOptions) -> MicrosandboxResult<()> {
    if cfg!(target_os = "macos") && !options.legacy_writers_stopped {
        return Err(MicrosandboxError::Runtime(
            "macOS legacy storage requires explicit maintenance recovery: stop legacy VMs across all microsandbox homes and prevent old-tool launches or writes to this storage until recovery finishes; then recover with confirmation that legacy writers are stopped. New and already migrated sandboxes do not require this maintenance".into(),
        ));
    }
    Ok(())
}

/// Keep the caller's lifecycle/storage guards alive until filesystem I/O has actually stopped.
/// A detached blocking task would outlive a cancelled future and release its borrowed guards.
/// Multi-thread executors hand other work to a replacement thread; single-thread callers retain
/// ownership synchronously rather than pretending a live copy has been cancelled.
pub(crate) fn filesystem_work<T>(
    name: &str,
    work: impl FnOnce() -> Result<T, String>,
) -> MicrosandboxResult<T> {
    if tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    {
        tokio::task::block_in_place(work)
    } else {
        work()
    }
    .map_err(|error| MicrosandboxError::Runtime(format!(
        "storage migration/recovery required for '{name}': {error}; inspect the preserved storage before retrying recovery"
    )))
}

/// A live legacy VM cannot be migrated under its lifecycle lock. Its checkpoint and disk
/// journals remain guest-writable until a protected restart, so do not consume them as authority.
pub(crate) fn require_running(backend: &LocalBackend, name: &str) -> MicrosandboxResult<()> {
    layout::require_ready(&backend.sandboxes_dir().join(name).join("runtime")).map_err(|_| {
        MicrosandboxError::Runtime(format!(
            "upgrade required: sandbox '{name}' is not running with protected sandbox state. \
             Update the SDK/CLI and runtime, then stop and restart this sandbox before taking \
             snapshots, forking, growing disks, or compacting disks. Exec and stop remain available."
        ))
    })
}

fn root_binding(config: &SandboxConfig, sandbox: &Path) -> Option<LegacyRootBinding> {
    let RootfsSource::Oci(oci) = &config.spec.image else {
        return None;
    };
    let (path, format, flat) = match &oci.root_disk {
        Some(RootDisk::Tmpfs { .. }) => return None,
        Some(RootDisk::Flat { .. }) => (sandbox.join("rootfs.raw"), "raw".to_owned(), true),
        Some(RootDisk::DiskImage { path, format, .. }) => (path.clone(), format.to_string(), false),
        _ => (sandbox.join("upper.ext4"), "raw".to_owned(), false),
    };
    Some(LegacyRootBinding { path, format, flat })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn private_test_home() -> tempfile::TempDir {
        let temporary = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Host umasks must not accidentally turn an admission test into an unsafe-home test.
            std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        temporary
    }

    async fn saved_sandbox(backend: &LocalBackend, name: &str) -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.spec.name = name.into();
        backend
            .db()
            .await
            .unwrap()
            .write()
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO sandbox (name,config,status,ephemeral) VALUES (?,?,'Stopped',0)",
                [
                    name.to_owned().into(),
                    serde_json::to_string(&config).unwrap().into(),
                ],
            ))
            .await
            .unwrap();
        std::fs::create_dir_all(backend.sandboxes_dir().join(name).join("runtime")).unwrap();
        config
    }

    async fn reservation(backend: &LocalBackend, name: &str) -> (i32, String) {
        let db = backend.db().await.unwrap();
        db.write()
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE sandbox SET creation_state='preparing' WHERE name=?",
                [name.to_owned().into()],
            ))
            .await
            .unwrap();
        let row = db
            .read()
            .query_one_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "SELECT id,config FROM sandbox WHERE name=?",
                [name.to_owned().into()],
            ))
            .await
            .unwrap()
            .unwrap();
        (
            row.try_get("", "id").unwrap(),
            row.try_get("", "config").unwrap(),
        )
    }

    async fn registered(backend: &LocalBackend) -> i64 {
        backend
            .db()
            .await
            .unwrap()
            .read()
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT count(*) AS count FROM protected_sandbox_state",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "count")
            .unwrap()
    }

    #[cfg(windows)]
    fn grant_untrusted_catalog_access(path: &Path) {
        assert!(path.is_file());
        assert!(
            std::process::Command::new("icacls.exe")
                .arg(path)
                .arg("/grant:r")
                .arg("*S-1-1-0:(M)")
                .output()
                .unwrap()
                .status
                .success()
        );
    }

    #[tokio::test]
    async fn catalog_creation_flag_cannot_authorize_fresh_storage() {
        let temporary = private_test_home();
        let backend = crate::test_support::local_backend_builder(temporary.path())
            .build()
            .await
            .unwrap();
        let config = saved_sandbox(&backend, "forged-reservation").await;
        let storage = CreationStorage::acquire(&backend, "forged-reservation").unwrap();
        reservation(&backend, "forged-reservation").await;
        let original = storage.join("upper.ext4");
        std::fs::write(&original, b"preserve existing sandbox bytes").unwrap();
        let error = prepare(&backend, &config, &storage).await.unwrap_err();
        assert!(error.to_string().contains("incomplete creation"));
        assert_eq!(
            std::fs::read(original).unwrap(),
            b"preserve existing sandbox bytes"
        );
        assert!(!storage.join("state-layout.json").exists());
        assert!(!storage.join(".storage-migration").exists());
        assert_eq!(registered(&backend).await, 0);
    }

    #[tokio::test]
    async fn fresh_preparation_requires_the_live_reservation_identity_and_config() {
        let temporary = private_test_home();
        let backend = crate::test_support::local_backend_builder(temporary.path())
            .build()
            .await
            .unwrap();
        let config = saved_sandbox(&backend, "fresh").await;
        let storage = CreationStorage::acquire(&backend, "fresh").unwrap();
        let (id, saved) = reservation(&backend, "fresh").await;
        for (catalog_id, expected_config) in
            [(id + 1, saved.as_str()), (id, "changed configuration")]
        {
            let error = prepare_launch(
                &backend,
                &config,
                &storage,
                StoragePreparation::New {
                    catalog_id,
                    expected_config,
                },
            )
            .await
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("reservation identity or configuration changed")
            );
            assert!(!storage.join("state-layout.json").exists());
            assert_eq!(registered(&backend).await, 0);
        }
        prepare_launch(
            &backend,
            &config,
            &storage,
            StoragePreparation::New {
                catalog_id: id,
                expected_config: &saved,
            },
        )
        .await
        .unwrap();
        layout::require_ready(&storage.join("runtime")).unwrap();
        assert!(!storage.join(".storage-migration").exists());
        // Once publication retires the reservation, replaying its old in-memory token
        // must not authorize another fresh initialization, even though the layout is Ready.
        backend
            .db()
            .await
            .unwrap()
            .write()
            .execute_unprepared("UPDATE sandbox SET creation_state=NULL WHERE name='fresh'")
            .await
            .unwrap();
        assert!(
            prepare_launch(
                &backend,
                &config,
                &storage,
                StoragePreparation::New {
                    catalog_id: id,
                    expected_config: &saved,
                }
            )
            .await
            .is_err()
        );
        layout::require_ready(&storage.join("runtime")).unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_untrusted_catalog_or_sidecar_refuses_before_legacy_authority() {
        for suffix in ["", "-wal", "-shm"] {
            let temporary = private_test_home();
            let backend = crate::test_support::local_backend_builder(temporary.path())
                .build()
                .await
                .unwrap();
            let config = saved_sandbox(&backend, "untrusted").await;
            let storage = CreationStorage::acquire(&backend, "untrusted").unwrap();
            // An attacker-controlled creation flag must not bypass the catalog check.
            reservation(&backend, "untrusted").await;
            let original = storage.join("upper.ext4");
            std::fs::write(&original, vec![23u8; 131072]).unwrap();
            let path = backend
                .config()
                .home()
                .join(microsandbox_utils::DB_SUBDIR)
                .join(format!("{}{suffix}", microsandbox_utils::DB_FILENAME));
            grant_untrusted_catalog_access(&path);
            let error = prepare(&backend, &config, &storage).await.unwrap_err();
            assert!(error.to_string().contains("catalog permissions"), "{error}");
            assert_eq!(std::fs::read(original).unwrap(), vec![23u8; 131072]);
            assert!(!storage.join("state-layout.json").exists());
            assert!(!storage.join(".storage-migration").exists());
            assert_eq!(registered(&backend).await, 0);
            // Inspection must not silently remove the unsafe grant to bless this catalog.
            assert!(
                microsandbox_db::private_storage::validate_database_inspection(
                    &backend
                        .config()
                        .home()
                        .join(microsandbox_utils::DB_SUBDIR)
                        .join(microsandbox_utils::DB_FILENAME)
                )
                .is_err()
            );
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_private_legacy_catalog_can_migrate() {
        let temporary = private_test_home();
        let backend = crate::test_support::local_backend_builder(temporary.path())
            .build()
            .await
            .unwrap();
        let config = saved_sandbox(&backend, "eligible").await;
        let storage = CreationStorage::acquire(&backend, "eligible").unwrap();
        let original = storage.join("upper.ext4");
        std::fs::write(&original, vec![23u8; 131072]).unwrap();
        prepare(&backend, &config, &storage).await.unwrap();
        layout::require_ready(&storage.join("runtime")).unwrap();
        assert_eq!(std::fs::read(original).unwrap(), vec![23u8; 131072]);
        assert_eq!(registered(&backend).await, 1);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_fresh_and_ready_paths_do_not_apply_legacy_catalog_admission() {
        let temporary = private_test_home();
        let backend = crate::test_support::local_backend_builder(temporary.path())
            .build()
            .await
            .unwrap();
        let config = saved_sandbox(&backend, "fresh").await;
        let storage = CreationStorage::acquire(&backend, "fresh").unwrap();
        let (id, saved) = reservation(&backend, "fresh").await;
        grant_untrusted_catalog_access(
            &backend
                .config()
                .home()
                .join(microsandbox_utils::DB_SUBDIR)
                .join(microsandbox_utils::DB_FILENAME),
        );
        prepare_launch(
            &backend,
            &config,
            &storage,
            StoragePreparation::New {
                catalog_id: id,
                expected_config: &saved,
            },
        )
        .await
        .unwrap();
        // Existing Ready storage still bypasses DB inspection and migration inventory.
        prepare(&backend, &config, &storage).await.unwrap();
        assert!(!storage.join(".storage-migration").exists());
    }

    #[tokio::test]
    async fn refused_admission_preserves_originals_and_does_not_register_protection() {
        let temporary = private_test_home();
        let backend = crate::test_support::local_backend_builder(temporary.path())
            .build()
            .await
            .unwrap();
        let config = saved_sandbox(&backend, "refused").await;
        let storage = CreationStorage::acquire(&backend, "refused").unwrap();
        let journal = storage.join("runtime/root-disk.json");
        std::fs::write(&journal, b"not a complete selected disk view").unwrap();
        assert!(prepare(&backend, &config, &storage).await.is_err());
        assert_eq!(
            std::fs::read(&journal).unwrap(),
            b"not a complete selected disk view"
        );
        assert!(!storage.join("state-layout.json").exists());
        assert!(!storage.join(".storage-migration").exists());
        let row = backend
            .db()
            .await
            .unwrap()
            .read()
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT count(*) AS count FROM protected_sandbox_state",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<i64>("", "count").unwrap(), 0);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn macos_requires_explicit_maintenance_for_hidden_cross_home_writers() {
        let target_home = private_test_home();
        let other_home = private_test_home();
        let backend = crate::test_support::local_backend_builder(target_home.path())
            .build()
            .await
            .unwrap();
        let config = saved_sandbox(&backend, "legacy-target").await;
        let storage = CreationStorage::acquire(&backend, &config.spec.name).unwrap();
        let original = storage.join("upper.ext4");
        std::fs::write(&original, vec![23u8; 131072]).unwrap();

        // Another home's old guest export can lose its last visible alias while its VM
        // retains the open writer. Neither this catalog nor a link-count scan can prove
        // that capture is safe. This uses a real unlinked handle without running a VM.
        let alias = other_home.path().join("legacy-checkpoint.raw");
        std::fs::hard_link(&original, &alias).unwrap();
        let hidden_writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&alias)
            .unwrap();
        std::fs::remove_file(alias).unwrap();
        let error = prepare(&backend, &config, &storage)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("explicit maintenance recovery"), "{error}");
        assert!(error.contains("across all microsandbox homes"), "{error}");
        assert!(
            prepare_selected(
                &backend,
                &config,
                &storage,
                &StorageRecoveryOptions::default()
            )
            .await
            .is_err()
        );
        assert!(!storage.join("state-layout.json").exists());
        assert!(!storage.join(".storage-migration").exists());
        let row = backend
            .db()
            .await
            .unwrap()
            .read()
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT count(*) AS count FROM protected_sandbox_state",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<i64>("", "count").unwrap(), 0);
        assert_eq!(std::fs::read(&original).unwrap(), vec![23u8; 131072]);

        drop(hidden_writer);
        let options = StorageRecoveryOptions {
            legacy_writers_stopped: true,
            ..Default::default()
        };
        prepare_selected(&backend, &config, &storage, &options)
            .await
            .unwrap();
        layout::require_ready(&storage.join("runtime")).unwrap();
        assert_eq!(std::fs::read(original).unwrap(), vec![23u8; 131072]);
        // The one-time acknowledgement is unnecessary after successful publication.
        prepare(&backend, &config, &storage).await.unwrap();
    }

    #[tokio::test]
    async fn terminal_row_does_not_admit_a_still_running_legacy_owner() {
        let temporary = private_test_home();
        let backend = crate::test_support::local_backend_builder(temporary.path())
            .build()
            .await
            .unwrap();
        let config = saved_sandbox(&backend, "departing").await;
        let storage = CreationStorage::acquire(&backend, "departing").unwrap();
        let journal = storage.join("runtime/root-disk.json");
        std::fs::write(&journal, b"legacy bytes still owned by the departing VM").unwrap();
        backend
            .db()
            .await
            .unwrap()
            .write()
            .execute_raw(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "INSERT INTO run(sandbox_id,pid,status) SELECT id,?,'Terminated' FROM sandbox WHERE name='departing'",
                [(std::process::id() as i32).into()],
            ))
            .await
            .unwrap();
        let error = prepare(&backend, &config, &storage).await.unwrap_err();
        assert!(error.to_string().contains("wait for teardown"));
        assert_eq!(
            std::fs::read(journal).unwrap(),
            b"legacy bytes still owned by the departing VM"
        );
        assert!(!storage.join("state-layout.json").exists());
        assert!(!storage.join(".storage-migration").exists());
        let count = backend
            .db()
            .await
            .unwrap()
            .read()
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT count(*) AS count FROM protected_sandbox_state",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(count.try_get::<i64>("", "count").unwrap(), 0);
    }

    #[tokio::test]
    async fn ready_storage_skips_migration_inventory_and_catalog_writes() {
        let temporary = private_test_home();
        let backend = crate::test_support::local_backend_builder(temporary.path())
            .build()
            .await
            .unwrap();
        let config = saved_sandbox(&backend, "ready").await;
        let storage = CreationStorage::acquire(&backend, "ready").unwrap();
        layout::initialize_new(&storage.join("runtime")).unwrap();
        backend.db().await.unwrap().write().execute_unprepared(
            "INSERT INTO protected_sandbox_state SELECT id,1 FROM sandbox WHERE name='ready'; \
             CREATE TRIGGER forbid_admission_insert BEFORE INSERT ON protected_sandbox_state BEGIN SELECT RAISE(ABORT,'unexpected migration write'); END; \
             CREATE TRIGGER forbid_admission_update BEFORE UPDATE ON protected_sandbox_state BEGIN SELECT RAISE(ABORT,'unexpected migration write'); END;"
        ).await.unwrap();
        std::fs::create_dir_all(storage.join("runtime/owned-disks/unrelated")).unwrap();
        std::fs::write(
            storage.join("runtime/owned-disks/unrelated/disk.json"),
            b"invalid inert legacy metadata",
        )
        .unwrap();
        prepare(&backend, &config, &storage).await.unwrap();
        assert!(!storage.join(".storage-migration").exists());
    }

    #[tokio::test]
    async fn live_storage_requires_completed_protection_without_migrating_the_source() {
        let temporary = private_test_home();
        let backend = crate::test_support::local_backend_builder(temporary.path())
            .build()
            .await
            .unwrap();
        let sandbox = backend.sandboxes_dir().join("source");
        std::fs::create_dir_all(sandbox.join("runtime")).unwrap();
        let journal = sandbox.join("runtime/root-disk.json");
        std::fs::write(&journal, b"legacy authority").unwrap();
        let error = require_running(&backend, "source").unwrap_err().to_string();
        assert!(error.contains("upgrade required") && error.contains("stop and restart"));
        assert_eq!(std::fs::read(&journal).unwrap(), b"legacy authority");
        assert!(!sandbox.join("state-layout.json").exists());
        std::fs::remove_file(journal).unwrap();
        layout::initialize_new(&sandbox.join("runtime")).unwrap();
        require_running(&backend, "source").unwrap();
        std::fs::remove_dir(sandbox.join("runtime/heartbeat.json")).unwrap();
        assert!(require_running(&backend, "source").is_err());
    }
}
