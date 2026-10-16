//! Cancellation cleanup for an unpublished local create, retaining namespace ownership.

use std::sync::Arc;
use std::time::Duration;

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use tokio::sync::Mutex;

use super::{ChildStageGuard, SandboxTransitionGuard};
use crate::backend::Backend;
use crate::db::entity::sandbox as sandbox_entity;
use crate::runtime::ProcessHandle;
use crate::runtime::spawn::EnsuredNamedVolumes;
use crate::sandbox::SandboxConfig;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Armed before inserting the provisional row, so cancellation during the DB commit is covered.
/// The name transition remains locked until cleanup finishes; a replacement cannot be targeted.
pub(super) struct CreationCleanup {
    state: Option<CleanupState>,
}

struct CleanupState {
    backend: Arc<dyn Backend>,
    name: String,
    _transition: SandboxTransitionGuard,
    volumes: Arc<EnsuredNamedVolumes>,
    has_owned_volumes: bool,
    owns_staging: bool,
    ephemeral: bool,
    returned_error: bool,
    process: Option<Arc<Mutex<ProcessHandle>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CreationCleanup {
    pub(super) fn new(
        backend: Arc<dyn Backend>,
        config: &SandboxConfig,
        transition: SandboxTransitionGuard,
        volumes: Arc<EnsuredNamedVolumes>,
        child_stage: Option<&mut ChildStageGuard>,
    ) -> Self {
        let has_owned_volumes = config
            .spec
            .mounts
            .iter()
            .any(|mount| matches!(mount, microsandbox_types::VolumeMount::Owned { .. }));
        let owns_staging = (has_owned_volumes || config.spec.lifecycle.ephemeral)
            && child_stage.as_ref().is_some_and(|stage| stage.armed);
        let cleanup = Self {
            state: Some(CleanupState {
                backend,
                name: config.spec.name.clone(),
                _transition: transition,
                volumes,
                has_owned_volumes,
                owns_staging,
                ephemeral: config.spec.lifecycle.ephemeral,
                returned_error: false,
                process: None,
            }),
        };
        // Transfer before the next await, not just on a returned error: cancellation
        // while an insert commits must not let a synchronous stage destructor bypass
        // this cleanup's final writer-side catalog and runtime-ownership checks.
        if owns_staging && let Some(stage) = child_stage {
            stage.disarm();
        }
        cleanup
    }

    pub(super) fn retain_process(&mut self, process: Option<Arc<Mutex<ProcessHandle>>>) {
        if let Some(state) = &mut self.state {
            state.process = process;
        }
    }

    /// Disarm after publication or after a failed owned create has been fully reconciled.
    pub(super) fn disarm(&mut self) {
        self.state.take();
    }

    /// Record the future's outcome synchronously before dropping the cleanup guard.
    /// A returned startup error keeps diagnostics; only a dropped pending create is cancelled.
    pub(super) fn complete<T>(
        &mut self,
        result: crate::MicrosandboxResult<T>,
    ) -> crate::MicrosandboxResult<T> {
        if result.is_ok() {
            self.disarm();
        } else if let Some(state) = &mut self.state {
            state.returned_error = true;
        }
        result
    }

    /// Finish ordinary owned-create failures before the caller's runtime can exit.
    /// Keep the state armed across the await so cancellation still delegates to Drop.
    pub(super) async fn finish_owned_failure(
        &mut self,
        error: crate::MicrosandboxError,
    ) -> crate::MicrosandboxError {
        // Once ordinary failure handling begins, even cancellation during that cleanup
        // must preserve its existing diagnostics policy.
        if let Some(state) = &mut self.state {
            state.returned_error = true;
        }
        if let Some(state) = &self.state
            && state.has_owned_volumes
        {
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
        if let Some(process) = &self.process {
            process.lock().await.terminate_failed_startup().await?;
        }
        let local = self.backend.as_local().ok_or_else(|| {
            crate::MicrosandboxError::Runtime("local creation cleanup lost its backend".into())
        })?;
        // Before publication, StartupProcess owns termination/reaping. Wait for its exact
        // lifecycle lock to be released before reconciling; never mistake cancellation for exit.
        let guard = crate::runtime::acquire_sandbox_lifecycle_guard(
            &local.config().run_dir(),
            &self.name,
            Duration::from_secs(10),
        )
        .await?;
        let pools = local.db().await?;
        let model = sandbox_entity::Entity::find()
            .filter(sandbox_entity::Column::Name.eq(&self.name))
            // Queue behind any cancelled insert/commit on the single writer connection.
            // A WAL reader could otherwise observe "no row" before that commit completes.
            .one(pools.write())
            .await?;
        // Keep the same lifecycle guard through reconciliation. Dropping and reopening
        // it can race a fork that briefly retains the original open file description.
        let remove_ephemeral = self.ephemeral && !self.returned_error;
        if let Some(model) = model {
            local
                .rollback_failed_startup_guarded(
                    pools.write(),
                    model.id,
                    &self.volumes,
                    remove_ephemeral,
                    &guard,
                )
                .await?;
        } else {
            crate::runtime::rollback_created_named_volumes(local, &self.volumes).await;
        }
        if self.has_owned_volumes || self.owns_staging || remove_ephemeral {
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
                let directory = local.sandboxes_dir().join(&self.name);
                if remove_ephemeral {
                    microsandbox_runtime::ipc::SandboxSocketPaths::new(
                        &local.config().run_dir(),
                        &directory,
                        &self.name,
                    )
                    .remove_artifacts()?;
                }
                crate::sandbox::remove_dir_if_exists(&directory)?;
            }
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
            let shared = SandboxBuilder::new("shared-volume-owner")
                .image(rootfs.clone())
                .volume("/shared", |mount| {
                    mount.named_with("shared", |volume| volume.ensure_exists())
                })
                .build()
                .await
                .unwrap();
            // Publish a preexisting named volume, then release its creation locks.
            drop(
                crate::runtime::ensure_named_volumes(&backend, &shared)
                    .await
                    .unwrap(),
            );
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
                    #[cfg(unix)]
                    let bind_root = rootfs.canonicalize().unwrap();
                    // Windows TempDir already has an absolute path. canonicalize
                    // adds a verbatim prefix that the mount wire syntax rejects.
                    #[cfg(not(unix))]
                    let bind_root = rootfs.clone();
                    mount.bind(bind_root)
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
            self.arm_with_stage(None).await
        }

        async fn arm_with_stage(
            &self,
            child_stage: Option<&mut ChildStageGuard>,
        ) -> CreationCleanup {
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
            let volumes = Arc::new(
                crate::runtime::ensure_named_volumes(&self.backend, &self.config)
                    .await
                    .unwrap(),
            );
            let cleanup = CreationCleanup::new(
                self.backend.clone(),
                &self.config,
                transition,
                volumes,
                child_stage,
            );
            crate::runtime::owned_volumes::prepare(
                &self.sandbox_dir,
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
        fixture.config.spec.mounts.push(
            MountBuilder::new("/too-small")
                .owned_with(|volume| volume.disk().size(1_u32))
                .build()
                .unwrap(),
        );
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

    async fn finish_test_owned_failure(cleanup: &mut CreationCleanup) -> crate::MicrosandboxError {
        // Cleanup drops its lifecycle probe before rollback reacquires ownership.
        // Parallel fork/exec tests can transiently retain that probe, correctly
        // leaving cleanup pending. Retry only that refusal, with the guard still armed.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let error = cleanup
                    .finish_owned_failure(crate::MicrosandboxError::Custom("startup failed".into()))
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
    async fn owned_cleanup_removes_storage_when_mixed_named_rollback_deletes_row() {
        // Exercise both ordinary startup rollback and cancellation cleanup doing the rollback.
        for direct_rollback in [false, true] {
            let mut fixture = OwnedFixture::new("owned-mixed-rollback").await;
            fixture.config.spec.mounts.push(
                MountBuilder::new("/created")
                    .named_with("created", |volume| volume.ensure_exists())
                    .build()
                    .unwrap(),
            );
            let mut cleanup = fixture.arm().await;
            let pools = fixture.backend.db().await.unwrap();
            let id =
                LocalBackend::insert_starting_sandbox_record(pools.write(), &fixture.config, None)
                    .await
                    .unwrap();
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
            let error = finish_test_owned_failure(&mut cleanup).await;
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
    async fn owned_cleanup_preserves_backing_whenever_catalog_row_survives() {
        for refused_operation in [None, Some("DELETE"), Some("UPDATE")] {
            let mut fixture = OwnedFixture::new("owned-retained-row").await;
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
            let id =
                LocalBackend::insert_starting_sandbox_record(pools.write(), &fixture.config, None)
                    .await
                    .unwrap();
            if let Some(operation) = refused_operation {
                pools.write().execute_unprepared(&format!(
                    "CREATE TRIGGER retain_sandbox BEFORE {operation} ON sandbox BEGIN SELECT RAISE(ABORT, 'retained'); END;",
                )).await.unwrap();
            }
            let error = finish_test_owned_failure(&mut cleanup).await;
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

    #[tokio::test]
    async fn legacy_only_cleanup_does_not_gain_owned_directory_removal() {
        let mut fixture = OwnedFixture::new("legacy-unpublished").await;
        fixture
            .config
            .spec
            .mounts
            .retain(|mount| !matches!(mount, microsandbox_types::VolumeMount::Owned { .. }));
        let mut stage = ChildStageGuard::new(fixture.sandbox_dir.clone());
        let mut cleanup = fixture.arm_with_stage(Some(&mut stage)).await;
        assert!(
            stage.armed,
            "legacy staging retains its existing synchronous cleanup"
        );
        cleanup.state.take().unwrap().cleanup().await.unwrap();
        assert_eq!(
            std::fs::read(fixture.sandbox_dir.join("upper.ext4")).unwrap(),
            b"private root disk"
        );
        fixture.assert_preserved();
    }

    #[tokio::test]
    async fn owned_cancelled_cleanup_excludes_live_owner_and_later_replacement() {
        let fixture = OwnedFixture::new("owned-replacement").await;
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

    #[tokio::test]
    async fn owned_cancelled_insert_waits_for_catalog_before_removing_restored_staging() {
        for committed in [false, true] {
            let fixture = OwnedFixture::new("owned-cancelled-insert").await;
            let mut stage = ChildStageGuard::new(fixture.sandbox_dir.clone());
            let cleanup = fixture.arm_with_stage(Some(&mut stage)).await;
            assert!(
                !stage.armed,
                "owned staging belongs to the catalog-aware cleanup"
            );
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
                // These are the two guards the create future owns at its insert await.
                let _stage = stage;
                let _cleanup = cleanup;
                let pools = backend.db().await.unwrap();
                if committed {
                    let result =
                        LocalBackend::insert_starting_sandbox_record(pools.write(), &config, None)
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
            crate::runtime::ensure_named_volumes(&backend, &config)
                .await
                .unwrap(),
        );
        let cleanup = CreationCleanup::new(backend.clone(), &config, transition, volumes, None);
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

    #[tokio::test]
    async fn cancelled_ephemeral_cleanup_waits_for_exit_and_allows_same_name_recreation() {
        for owned in [false, true] {
            for named in [false, true] {
                let mut fixture = OwnedFixture::new("cancelled-ephemeral").await;
                fixture.config.spec.lifecycle.ephemeral = true;
                if !owned {
                    fixture.config.spec.mounts.retain(|mount| {
                        !matches!(mount, microsandbox_types::VolumeMount::Owned { .. })
                    });
                }
                if named {
                    fixture.config.spec.mounts.push(
                        MountBuilder::new("/created")
                            .named_with("created", |volume| volume.ensure_exists())
                            .build()
                            .unwrap(),
                    );
                }
                let cleanup = fixture.arm().await;
                let pools = fixture.backend.db().await.unwrap();
                let id = LocalBackend::insert_starting_sandbox_record(
                    pools.write(),
                    &fixture.config,
                    None,
                )
                .await
                .unwrap();
                let runtime = microsandbox_runtime::ipc::try_acquire_lifecycle_guard(
                    &fixture.backend.config().run_dir(),
                    &fixture.config.spec.name,
                )
                .unwrap()
                .unwrap();
                drop(cleanup);

                assert!(
                    microsandbox_runtime::ipc::try_acquire_transition_guard(
                        &fixture.backend.config().run_dir(),
                        &fixture.config.spec.name,
                    )
                    .unwrap()
                    .is_none()
                );
                assert!(fixture.sandbox_dir.join("upper.ext4").exists());
                assert!(
                    sandbox_entity::Entity::find_by_id(id)
                        .one(pools.write())
                        .await
                        .unwrap()
                        .is_some()
                );
                drop(runtime);

                // Acquiring the name proves old cleanup is finished, without sleeping
                // or launching another VM that could conceal a missing cleanup sweep.
                let _transition = tokio::time::timeout(
                    Duration::from_secs(30),
                    LocalBackend::acquire_sandbox_transition_guard(
                        &fixture.backend.config().run_dir(),
                        &fixture.config.spec.name,
                    ),
                )
                .await
                .unwrap()
                .unwrap();
                assert!(
                    sandbox_entity::Entity::find_by_id(id)
                        .one(pools.write())
                        .await
                        .unwrap()
                        .is_none()
                );
                assert!(!fixture.sandbox_dir.exists());
                assert!(!fixture.backend.volume_path("created").exists());
                fixture.assert_preserved();
                LocalBackend::prepare_create_target(
                    pools,
                    &fixture.config,
                    &fixture.sandbox_dir,
                    &fixture.backend.config().run_dir(),
                )
                .await
                .unwrap();
                LocalBackend::insert_starting_sandbox_record(pools.write(), &fixture.config, None)
                    .await
                    .unwrap();
                std::fs::create_dir_all(&fixture.sandbox_dir).unwrap();
                std::fs::write(fixture.sandbox_dir.join("replacement"), b"new create").unwrap();
                assert_eq!(
                    std::fs::read(fixture.sandbox_dir.join("replacement")).unwrap(),
                    b"new create"
                );
            }
        }
    }

    #[tokio::test]
    async fn ephemeral_returned_failure_preserves_diagnostics_and_success_disarms_cleanup() {
        for success in [false, true] {
            let mut fixture = OwnedFixture::new("ephemeral-outcome").await;
            fixture.config.spec.lifecycle.ephemeral = true;
            let mut cleanup = fixture.arm().await;
            let pools = fixture.backend.db().await.unwrap();
            let id =
                LocalBackend::insert_starting_sandbox_record(pools.write(), &fixture.config, None)
                    .await
                    .unwrap();
            std::fs::create_dir_all(fixture.sandbox_dir.join("logs")).unwrap();
            let log = fixture.sandbox_dir.join("logs/runtime.log");
            std::fs::write(&log, b"boot failure diagnostics").unwrap();
            let result = if success {
                Ok(())
            } else {
                Err(crate::MicrosandboxError::Custom("boot failure".into()))
            };
            assert_eq!(cleanup.complete(result).is_ok(), success);
            drop(cleanup);
            let _transition = tokio::time::timeout(
                Duration::from_secs(30),
                LocalBackend::acquire_sandbox_transition_guard(
                    &fixture.backend.config().run_dir(),
                    &fixture.config.spec.name,
                ),
            )
            .await
            .unwrap()
            .unwrap();
            let row = sandbox_entity::Entity::find_by_id(id)
                .one(pools.write())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                row.status,
                if success {
                    SandboxStatus::Starting
                } else {
                    SandboxStatus::Stopped
                }
            );
            assert_eq!(std::fs::read(log).unwrap(), b"boot failure diagnostics");
            assert!(fixture.sandbox_dir.join("upper.ext4").exists());
            fixture.assert_preserved();
        }
    }

    #[tokio::test]
    async fn cancelled_ephemeral_cleanup_keeps_failed_removal_retryable() {
        let mut fixture = OwnedFixture::new("ephemeral-delete-retry").await;
        fixture.config.spec.lifecycle.ephemeral = true;
        let mut cleanup = fixture.arm().await;
        let pools = fixture.backend.db().await.unwrap();
        let id = LocalBackend::insert_starting_sandbox_record(pools.write(), &fixture.config, None)
            .await
            .unwrap();
        // A regular file in place of the private directory deterministically rejects
        // remove_dir_all on every host, without permission-dependent root-user behavior.
        std::fs::remove_dir_all(&fixture.sandbox_dir).unwrap();
        std::fs::write(&fixture.sandbox_dir, b"removal blocked").unwrap();
        let state = cleanup.state.take().unwrap();
        assert!(state.cleanup().await.is_err());
        assert_eq!(
            sandbox_entity::Entity::find_by_id(id)
                .one(pools.write())
                .await
                .unwrap()
                .unwrap()
                .status,
            SandboxStatus::Stopped
        );
        assert_eq!(
            std::fs::read(&fixture.sandbox_dir).unwrap(),
            b"removal blocked"
        );
        std::fs::remove_file(&fixture.sandbox_dir).unwrap();
        state.cleanup().await.unwrap();
        assert!(
            sandbox_entity::Entity::find_by_id(id)
                .one(pools.write())
                .await
                .unwrap()
                .is_none()
        );
        fixture.assert_preserved();
    }

    #[tokio::test]
    async fn cancelled_ephemeral_cleanup_waits_for_inflight_catalog_commit() {
        for committed in [false, true] {
            let mut fixture = OwnedFixture::new("ephemeral-commit-race").await;
            fixture.config.spec.lifecycle.ephemeral = true;
            fixture
                .config
                .spec
                .mounts
                .retain(|mount| !matches!(mount, microsandbox_types::VolumeMount::Owned { .. }));
            let mut stage = ChildStageGuard::new(fixture.sandbox_dir.clone());
            let cleanup = fixture.arm_with_stage(Some(&mut stage)).await;
            assert!(
                !stage.armed,
                "asynchronous cleanup owns staging until the catalog settles"
            );
            let pools = fixture.backend.db().await.unwrap();
            if committed {
                LocalBackend::insert_starting_sandbox_record(pools.write(), &fixture.config, None)
                    .await
                    .unwrap();
            }
            let writer_gate = pools.write().inner().begin().await.unwrap();
            drop(cleanup);
            drop(stage);
            assert!(fixture.sandbox_dir.join("upper.ext4").exists());
            assert!(
                microsandbox_runtime::ipc::try_acquire_transition_guard(
                    &fixture.backend.config().run_dir(),
                    &fixture.config.spec.name,
                )
                .unwrap()
                .is_none()
            );
            writer_gate.rollback().await.unwrap();
            let _transition = tokio::time::timeout(
                Duration::from_secs(30),
                LocalBackend::acquire_sandbox_transition_guard(
                    &fixture.backend.config().run_dir(),
                    &fixture.config.spec.name,
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(!fixture.sandbox_dir.exists());
            assert!(
                sandbox_entity::Entity::find()
                    .filter(sandbox_entity::Column::Name.eq(&fixture.config.spec.name))
                    .one(pools.write())
                    .await
                    .unwrap()
                    .is_none()
            );
            fixture.assert_preserved();
        }
    }
}
