//! Cancellation cleanup for an unpublished local create, retaining namespace ownership.

use std::sync::Arc;
use std::time::Duration;

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use tokio::sync::Mutex;

use super::SandboxTransitionGuard;
use crate::backend::Backend;
use crate::backend::local::volume::EnsuredNamedVolumes;
use crate::db::entity::sandbox as sandbox_entity;
use crate::runtime::ProcessHandle;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Armed after preparation; the durable creation record covers earlier interruption.
/// The name transition remains locked until cleanup finishes; a replacement cannot be targeted.
pub(super) struct CreationCleanup {
    state: Option<CleanupState>,
}

struct CleanupState {
    backend: Arc<dyn Backend>,
    name: String,
    _transition: SandboxTransitionGuard,
    volumes: Arc<EnsuredNamedVolumes>,
    process: Option<Arc<Mutex<ProcessHandle>>>,
    publication_started: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CreationCleanup {
    pub(super) fn new(
        backend: Arc<dyn Backend>,
        name: String,
        transition: SandboxTransitionGuard,
        volumes: Arc<EnsuredNamedVolumes>,
    ) -> Self {
        Self {
            state: Some(CleanupState {
                backend,
                name,
                _transition: transition,
                volumes,
                process: None,
                publication_started: false,
            }),
        }
    }

    /// A cancelled commit may have published successfully; cleanup must consult its journal first.
    pub(super) fn begin_publication(&mut self) {
        if let Some(state) = &mut self.state {
            state.publication_started = true;
        }
    }

    pub(super) fn retain_process(&mut self, process: Option<Arc<Mutex<ProcessHandle>>>) {
        if let Some(state) = &mut self.state {
            state.process = process;
        }
    }

    /// Disarm after publication or after a failed create has been fully reconciled.
    pub(super) fn disarm(&mut self) {
        self.state.take();
    }

    /// Finish ordinary create failures before the caller's runtime can exit.
    /// Keep the state armed across the await so cancellation still delegates to Drop.
    pub(super) async fn finish_failure(
        &mut self,
        error: crate::MicrosandboxError,
    ) -> crate::MicrosandboxError {
        if let Some(state) = &self.state {
            if let Err(cleanup) = state.cleanup().await {
                return crate::MicrosandboxError::Runtime(format!("{error}; {cleanup}"));
            }
            self.disarm();
        }
        error
    }
}

impl CleanupState {
    async fn cleanup(&self) -> crate::MicrosandboxResult<()> {
        let local = self.backend.as_local().ok_or_else(|| {
            crate::MicrosandboxError::Runtime("local creation cleanup lost its backend".into())
        })?;
        let pools = local.db().await?;
        if self.publication_started {
            let model = sandbox_entity::Entity::find()
                .filter(sandbox_entity::Column::Name.eq(&self.name))
                .one(pools.write())
                .await?;
            let Some(model) = model else {
                // Successful ephemeral publication may already have been removed by the runtime.
                return Ok(());
            };
            if !crate::backend::local::creation::pending(pools.write(), model.id).await? {
                return Ok(());
            }
        }
        if let Some(process) = &self.process {
            process.lock().await.terminate_failed_startup().await?;
        }

        // Before publication, StartupProcess owns termination/reaping. Wait for its exact
        // lifecycle lock to be released before reconciling; never mistake cancellation for exit.
        let guard = crate::runtime::acquire_sandbox_lifecycle_guard(
            &local.config().run_dir(),
            &self.name,
            Duration::from_secs(10),
        )
        .await?;
        let model = sandbox_entity::Entity::find()
            .filter(sandbox_entity::Column::Name.eq(&self.name))
            // Queue behind any cancelled insert/commit on the single writer connection.
            // A WAL reader could otherwise observe "no row" before that commit completes.
            .one(pools.write())
            .await?;
        // Keep the same lifecycle guard through reconciliation. Dropping and reopening
        // it can race a fork that briefly retains the original open file description.
        if let Some(model) = model {
            local
                .rollback_failed_startup_guarded(pools.write(), model.id, &self.volumes, &guard)
                .await?;
        } else {
            local.rollback_created_named_volumes(&self.volumes).await?;
        }

        // Rollback can retain a recoverable stopped row, or remove the row when
        // one-shot named volumes were created. Prove which outcome committed before
        // deleting anything, while still excluding both runtimes and replacements.
        let retained = sandbox_entity::Entity::find()
            .filter(sandbox_entity::Column::Name.eq(&self.name))
            .one(pools.write())
            .await?;

        if retained.is_none() {
            // The guard was armed only after this create reserved a previously absent
            // name. Remove its root disk/staging too, or the directory alone would
            // prevent an immediate retry. External bind/named storage is not beneath it.
            // A cancelled formatter only owns its unique sibling temporary directory.
            crate::sandbox::remove_dir_if_exists(&local.sandboxes_dir().join(&self.name))?;
        }

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for CreationCleanup {
    fn drop(&mut self) {
        let Some(state) = self.state.take() else {
            return;
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(error) = state.cleanup().await {
                    // Retain durable restore intent and storage on uncertain cleanup. Normal
                    // startup maintenance may reconcile only after ownership is actually gone.
                    tracing::error!(%error, "cancelled creation cleanup remains pending");
                }
            });
        } else {
            tracing::error!(sandbox = %state.name, "runtime unavailable for cancelled creation reconciliation");
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use sea_orm::{ConnectionTrait, Set, TransactionTrait};

    use super::*;
    use crate::backend::local::LocalBackend;
    use crate::backend::local::creation::CreationStorage;
    use crate::db::entity::run as run_entity;
    use crate::sandbox::{MountBuilder, SandboxBuilder, SandboxConfig, SandboxStatus};

    struct OwnedFixture {
        _directory: tempfile::TempDir,
        backend: Arc<LocalBackend>,
        config: SandboxConfig,
        sandbox_dir: PathBuf,
        preserved: Vec<PathBuf>,
    }

    impl OwnedFixture {
        async fn new(name: &str) -> Self {
            // macOS's default temp root is too long for the derived runtime socket path.
            #[cfg(unix)]
            let directory = tempfile::Builder::new()
                .prefix("msb-owned-cleanup-")
                .tempdir_in("/tmp")
                .unwrap();
            #[cfg(not(unix))]
            let directory = tempfile::tempdir().unwrap();
            let rootfs = directory.path().join("rootfs");
            std::fs::create_dir(&rootfs).unwrap();
            let backend = Arc::new(
                crate::test_support::local_backend_builder(directory.path().join("home"))
                    .build()
                    .await
                    .unwrap(),
            );
            crate::volume::create_local(
                backend.clone(),
                crate::volume::Volume::builder("shared").directory().build(),
            )
            .await
            .unwrap();
            let neighbor = backend.sandboxes_dir().join("neighbor");
            std::fs::create_dir_all(&neighbor).unwrap();
            let preserved = vec![
                rootfs.join("sentinel"),
                backend.volume_path("shared").join("sentinel"),
                neighbor.join("sentinel"),
            ];
            for path in &preserved {
                std::fs::write(path, b"not owned by this creation").unwrap();
            }
            let config = SandboxBuilder::new(name)
                .image(rootfs.clone())
                .volume("/bind", |mount| {
                    // Bind roots refuse symlinks, and /tmp is one on macOS.
                    mount.bind(rootfs.canonicalize().unwrap())
                })
                .volume("/shared", |mount| mount.named("shared"))
                .volume("/owned", |mount| mount.owned())
                .build()
                .await
                .unwrap();
            let sandbox_dir = backend.sandboxes_dir().join(name);
            Self {
                _directory: directory,
                backend,
                config,
                sandbox_dir,
                preserved,
            }
        }

        async fn arm(&self) -> CreationCleanup {
            let transition = LocalBackend::acquire_sandbox_transition_guard(
                &self.backend.config().run_dir(),
                &self.config.spec.name,
            )
            .await
            .unwrap();
            LocalBackend::prepare_create_target(
                self.backend.db().await.unwrap(),
                &self.config,
                &self.sandbox_dir,
                &self.backend.config().run_dir(),
            )
            .await
            .unwrap();
            // These tests also cover legacy cleanup after creation has completed.
            // New named volumes must first belong to a reserved creation.
            let reservation = if self
                .config
                .spec
                .mounts
                .iter()
                .any(|mount| mount.named_create().is_some())
            {
                Some(
                    LocalBackend::insert_sandbox_record_impl(
                        self.backend.db().await.unwrap().write(),
                        &self.config,
                        SandboxStatus::Starting,
                        true,
                    )
                    .await
                    .unwrap(),
                )
            } else {
                None
            };
            let volumes = Arc::new(
                self.backend
                    .ensure_named_volumes(
                        &CreationStorage::for_test(
                            &self.backend.sandboxes_dir().join(&self.config.spec.name),
                        ),
                        &self.config,
                    )
                    .await
                    .unwrap(),
            );
            if let Some(id) = reservation {
                crate::backend::local::creation::complete(
                    self.backend.db().await.unwrap().write(),
                    id,
                    SandboxStatus::Starting,
                )
                .await
                .unwrap();
            }
            let cleanup = CreationCleanup::new(
                self.backend.clone(),
                self.config.spec.name.clone(),
                transition,
                volumes,
            );
            crate::runtime::owned_volumes::prepare(
                &CreationStorage::for_test(&self.sandbox_dir),
                &self.config.spec.mounts,
                false,
            )
            .await
            .unwrap();
            std::fs::create_dir_all(&self.sandbox_dir).unwrap();
            std::fs::write(self.sandbox_dir.join("upper.ext4"), b"private root disk").unwrap();
            cleanup
        }

        fn assert_preserved(&self) {
            for path in &self.preserved {
                assert_eq!(std::fs::read(path).unwrap(), b"not owned by this creation");
            }
        }
    }

    #[tokio::test]
    async fn owned_format_failure_cleans_unpublished_directory_before_returning() {
        let mut fixture = OwnedFixture::new("owned-format-failure").await;
        fixture.config = SandboxBuilder::from(fixture.config)
            .volume("/too-small", |mount| {
                mount.owned_with(|volume| volume.disk().size(1_u32))
            })
            .build()
            .await
            .unwrap();
        let error = fixture
            .backend
            .create_sandbox(
                fixture.backend.clone(),
                fixture.config.clone(),
                crate::runtime::SpawnMode::Detached,
                None,
            )
            .await
            .err()
            .expect("one MiB cannot hold the default ext4 journal");
        assert!(error.to_string().contains("too small"), "{error}");
        assert!(
            !fixture.sandbox_dir.exists(),
            "cleanup must finish before the caller exits"
        );
        assert!(
            std::fs::read_dir(fixture.backend.sandboxes_dir())
                .unwrap()
                .all(|entry| {
                    !entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".owned-volume-create-")
                })
        );
        LocalBackend::prepare_create_target(
            fixture.backend.db().await.unwrap(),
            &fixture.config,
            &fixture.sandbox_dir,
            &fixture.backend.config().run_dir(),
        )
        .await
        .unwrap();
        fixture.assert_preserved();
    }

    async fn finish_test_failure(cleanup: &mut CreationCleanup) -> crate::MicrosandboxError {
        // Cleanup drops its lifecycle probe before rollback reacquires ownership.
        // Parallel fork/exec tests can transiently retain that probe, correctly
        // leaving cleanup pending. Retry only that refusal, with the guard still armed.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let error = cleanup
                    .finish_failure(crate::MicrosandboxError::Custom("startup failed".into()))
                    .await;
                if !error.to_string().contains("startup cleanup pending") {
                    break error;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("runtime ownership was not released before cleanup")
    }

    #[tokio::test]
    async fn cleanup_removes_storage_when_named_rollback_deletes_row() {
        // Exercise both ordinary startup rollback and cancellation cleanup doing the rollback.
        for (direct_rollback, owned) in [(false, false), (true, false), (false, true), (true, true)]
        {
            let mut fixture = OwnedFixture::new("named-rollback").await;
            if !owned {
                fixture.config.spec.mounts.retain(|mount| {
                    !matches!(mount, microsandbox_types::VolumeMount::Owned { .. })
                });
            }
            fixture.config.spec.mounts.push(
                MountBuilder::new("/created")
                    .named_with("created", |volume| volume.ensure_exists())
                    .build()
                    .unwrap(),
            );
            let mut cleanup = fixture.arm().await;
            let pools = fixture.backend.db().await.unwrap();
            let id = sandbox_entity::Entity::find()
                .filter(sandbox_entity::Column::Name.eq(&fixture.config.spec.name))
                .one(pools.write())
                .await
                .unwrap()
                .unwrap()
                .id;
            if direct_rollback {
                fixture
                    .backend
                    .rollback_failed_startup(
                        pools.write(),
                        id,
                        &fixture.config.spec.name,
                        &cleanup.state.as_ref().unwrap().volumes,
                    )
                    .await
                    .unwrap();
            }
            let error = finish_test_failure(&mut cleanup).await;
            assert_eq!(error.to_string(), "startup failed");
            assert!(!fixture.sandbox_dir.exists());
            assert!(!fixture.backend.volume_path("created").exists());
            assert!(
                sandbox_entity::Entity::find_by_id(id)
                    .one(pools.write())
                    .await
                    .unwrap()
                    .is_none()
            );
            LocalBackend::prepare_create_target(
                pools,
                &fixture.config,
                &fixture.sandbox_dir,
                &fixture.backend.config().run_dir(),
            )
            .await
            .unwrap();
            fixture.assert_preserved();
        }
    }

    #[tokio::test]
    async fn cleanup_preserves_backing_whenever_catalog_row_survives() {
        for owned in [false, true] {
            for refused_operation in [None, Some("DELETE"), Some("UPDATE")] {
                let mut fixture = OwnedFixture::new("owned-retained-row").await;
                if !owned {
                    fixture.config.spec.mounts.retain(|mount| {
                        !matches!(mount, microsandbox_types::VolumeMount::Owned { .. })
                    });
                }
                if refused_operation == Some("DELETE") {
                    fixture.config.spec.mounts.push(
                        MountBuilder::new("/created")
                            .named_with("created", |volume| volume.ensure_exists())
                            .build()
                            .unwrap(),
                    );
                }
                let mut cleanup = fixture.arm().await;
                let pools = fixture.backend.db().await.unwrap();
                let id = match sandbox_entity::Entity::find()
                    .filter(sandbox_entity::Column::Name.eq(&fixture.config.spec.name))
                    .one(pools.write())
                    .await
                    .unwrap()
                {
                    Some(row) => row.id,
                    None => LocalBackend::insert_starting_sandbox_record(
                        pools.write(),
                        &fixture.config,
                        None,
                    )
                    .await
                    .unwrap(),
                };
                if let Some(operation) = refused_operation {
                    pools.write().execute_unprepared(&format!(
                        "CREATE TRIGGER retain_sandbox BEFORE {operation} ON sandbox BEGIN SELECT RAISE(ABORT, 'retained'); END;",
                    )).await.unwrap();
                }
                let error = finish_test_failure(&mut cleanup).await;
                if refused_operation.is_some() {
                    let message = error.to_string();
                    assert!(message.contains("startup failed"), "{message}");
                    assert!(message.contains("retained"), "{message}");
                } else {
                    assert_eq!(error.to_string(), "startup failed");
                }
                let row = sandbox_entity::Entity::find_by_id(id)
                    .one(pools.write())
                    .await
                    .unwrap()
                    .unwrap();
                if refused_operation.is_none() {
                    assert_eq!(row.status, SandboxStatus::Stopped);
                }
                assert_eq!(
                    std::fs::read(fixture.sandbox_dir.join("upper.ext4")).unwrap(),
                    b"private root disk"
                );
                crate::runtime::owned_volumes::validate(
                    &fixture.sandbox_dir,
                    &fixture.config.spec.mounts,
                )
                .unwrap();
                fixture.assert_preserved();
            }
        }
    }

    #[tokio::test]
    async fn unpublished_cleanup_removes_storage_without_owned_volumes() {
        let mut fixture = OwnedFixture::new("legacy-unpublished").await;
        fixture
            .config
            .spec
            .mounts
            .retain(|mount| !matches!(mount, microsandbox_types::VolumeMount::Owned { .. }));

        let mut cleanup = fixture.arm().await;

        let error = finish_test_failure(&mut cleanup).await;
        assert_eq!(error.to_string(), "startup failed");
        assert!(!fixture.sandbox_dir.exists());
        fixture.assert_preserved();
    }

    #[tokio::test]
    async fn cancelled_cleanup_excludes_live_owner_and_later_replacement() {
        for owned in [false, true] {
            let mut fixture = OwnedFixture::new("owned-replacement").await;
            if !owned {
                fixture.config.spec.mounts.retain(|mount| {
                    !matches!(mount, microsandbox_types::VolumeMount::Owned { .. })
                });
            }
            let cleanup = fixture.arm().await;
            let runtime = microsandbox_runtime::ipc::try_acquire_lifecycle_guard(
                &fixture.backend.config().run_dir(),
                &fixture.config.spec.name,
            )
            .unwrap()
            .unwrap();
            drop(cleanup);
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(
                fixture.sandbox_dir.exists(),
                "a live owner must retain its storage"
            );
            assert!(
                microsandbox_runtime::ipc::try_acquire_transition_guard(
                    &fixture.backend.config().run_dir(),
                    &fixture.config.spec.name,
                )
                .unwrap()
                .is_none()
            );

            let backend = fixture.backend.clone();
            let config = fixture.config.clone();
            let replacement_dir = fixture.sandbox_dir.clone();
            let replacement = tokio::spawn(async move {
                let _transition = LocalBackend::acquire_sandbox_transition_guard(
                    &backend.config().run_dir(),
                    &config.spec.name,
                )
                .await
                .unwrap();
                LocalBackend::prepare_create_target(
                    backend.db().await.unwrap(),
                    &config,
                    &replacement_dir,
                    &backend.config().run_dir(),
                )
                .await
                .unwrap();
                std::fs::create_dir(&replacement_dir).unwrap();
                std::fs::write(replacement_dir.join("replacement"), b"new owner").unwrap();
            });
            drop(runtime);
            tokio::time::timeout(Duration::from_secs(2), replacement)
                .await
                .unwrap()
                .unwrap();
            // The old cleanup released its transition only after its last filesystem mutation.
            assert_eq!(
                std::fs::read(fixture.sandbox_dir.join("replacement")).unwrap(),
                b"new owner"
            );
            fixture.assert_preserved();
        }
    }

    #[tokio::test]
    async fn cancelled_insert_waits_for_catalog_before_removing_restored_staging() {
        for owned in [false, true] {
            for committed in [false, true] {
                let mut fixture = OwnedFixture::new("owned-cancelled-insert").await;
                if !owned {
                    fixture.config.spec.mounts.retain(|mount| {
                        !matches!(mount, microsandbox_types::VolumeMount::Owned { .. })
                    });
                }

                let cleanup = fixture.arm().await;

                let pools = fixture.backend.db().await.unwrap();
                // In the missing-row case, the insert never obtains the writer connection.
                // In the committed case, hold its result at the caller boundary instead.
                let mut writer_gate = if committed {
                    None
                } else {
                    Some(pools.write().inner().begin().await.unwrap())
                };
                let (ready, insertion_pending) = tokio::sync::oneshot::channel();
                let backend = fixture.backend.clone();
                let config = fixture.config.clone();
                let launcher = tokio::spawn(async move {
                    // Retain catalog-aware cleanup across the pending insert.
                    let _cleanup = cleanup;
                    let pools = backend.db().await.unwrap();
                    if committed {
                        let result = LocalBackend::insert_starting_sandbox_record(
                            pools.write(),
                            &config,
                            None,
                        )
                        .await
                        .unwrap();
                        ready.send(()).unwrap();
                        // Deterministically model SQL committing before the outer future gets
                        // its result; cancellation must preserve that committed row's backing.
                        std::future::pending::<()>().await;
                        result
                    } else {
                        ready.send(()).unwrap();
                        LocalBackend::insert_starting_sandbox_record(pools.write(), &config, None)
                            .await
                            .unwrap()
                    }
                });
                insertion_pending.await.unwrap();
                if committed {
                    writer_gate = Some(pools.write().inner().begin().await.unwrap());
                }
                launcher.abort();
                assert!(launcher.await.unwrap_err().is_cancelled());
                assert_eq!(
                    std::fs::read(fixture.sandbox_dir.join("upper.ext4")).unwrap(),
                    b"private root disk",
                    "the synchronous staging guard must not bypass the blocked catalog check",
                );
                assert!(
                    microsandbox_runtime::ipc::try_acquire_transition_guard(
                        &fixture.backend.config().run_dir(),
                        &fixture.config.spec.name,
                    )
                    .unwrap()
                    .is_none()
                );
                writer_gate.take().unwrap().rollback().await.unwrap();

                // Reacquiring the transition proves every old cleanup mutation is finished.
                let _transition = tokio::time::timeout(
                    Duration::from_secs(2),
                    LocalBackend::acquire_sandbox_transition_guard(
                        &fixture.backend.config().run_dir(),
                        &fixture.config.spec.name,
                    ),
                )
                .await
                .unwrap()
                .unwrap();
                let row = sandbox_entity::Entity::find()
                    .filter(sandbox_entity::Column::Name.eq(&fixture.config.spec.name))
                    .one(pools.write())
                    .await
                    .unwrap();
                if committed {
                    assert_eq!(row.unwrap().status, SandboxStatus::Stopped);
                    assert_eq!(
                        std::fs::read(fixture.sandbox_dir.join("upper.ext4")).unwrap(),
                        b"private root disk"
                    );
                    crate::runtime::owned_volumes::validate(
                        &fixture.sandbox_dir,
                        &fixture.config.spec.mounts,
                    )
                    .unwrap();
                } else {
                    assert!(row.is_none());
                    assert!(!fixture.sandbox_dir.exists());
                }
                fixture.assert_preserved();
            }
        }
    }

    #[tokio::test]
    async fn cancelled_creation_retains_name_until_ownership_and_catalog_are_reconciled() {
        let directory = tempfile::tempdir().unwrap();
        let rootfs = directory.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();
        let backend = Arc::new(
            crate::test_support::local_backend_builder(directory.path().join("home"))
                .build()
                .await
                .unwrap(),
        );
        let config = SandboxBuilder::new("cancelled-create")
            .image(rootfs)
            .build()
            .await
            .unwrap();
        let pools = backend.db().await.unwrap();
        let transition = LocalBackend::acquire_sandbox_transition_guard(
            &backend.config().run_dir(),
            &config.spec.name,
        )
        .await
        .unwrap();
        let runtime = microsandbox_runtime::ipc::try_acquire_lifecycle_guard(
            &backend.config().run_dir(),
            &config.spec.name,
        )
        .unwrap()
        .unwrap();
        let volumes = Arc::new(
            backend
                .ensure_named_volumes(
                    &CreationStorage::for_test(&backend.sandboxes_dir().join(&config.spec.name)),
                    &config,
                )
                .await
                .unwrap(),
        );
        let cleanup = CreationCleanup::new(
            backend.clone(),
            config.spec.name.clone(),
            transition,
            volumes,
        );
        let id = LocalBackend::insert_starting_sandbox_record(pools.write(), &config, None)
            .await
            .unwrap();
        LocalBackend::update_sandbox_status(pools.write(), id, SandboxStatus::Running)
            .await
            .unwrap();
        run_entity::Entity::insert(run_entity::ActiveModel {
            sandbox_id: Set(id),
            status: Set(run_entity::RunStatus::Running),
            ..Default::default()
        })
        .exec(pools.write())
        .await
        .unwrap();
        drop(cleanup);
        assert!(
            microsandbox_runtime::ipc::try_acquire_transition_guard(
                &backend.config().run_dir(),
                &config.spec.name,
            )
            .unwrap()
            .is_none(),
            "cleanup must exclude a replacement until ownership is gone"
        );
        assert_eq!(
            sandbox_entity::Entity::find_by_id(id)
                .one(pools.read())
                .await
                .unwrap()
                .unwrap()
                .status,
            SandboxStatus::Running
        );
        drop(runtime);
        // Cleanup owns the transition through its final catalog write. Reacquiring it
        // waits for completion; the timeout is only a watchdog for a stuck cleanup.
        let _transition = tokio::time::timeout(
            Duration::from_secs(30),
            LocalBackend::acquire_sandbox_transition_guard(
                &backend.config().run_dir(),
                &config.spec.name,
            ),
        )
        .await
        .expect("cancelled creation cleanup did not release the name transition")
        .unwrap();
        assert_eq!(
            sandbox_entity::Entity::find_by_id(id)
                .one(pools.read())
                .await
                .unwrap()
                .unwrap()
                .status,
            SandboxStatus::Stopped
        );
        let runs = run_entity::Entity::find()
            .filter(run_entity::Column::SandboxId.eq(id))
            .all(pools.read())
            .await
            .unwrap();
        assert!(
            runs.iter()
                .all(|run| run.status == run_entity::RunStatus::Terminated)
        );
    }
}
