//! Recovery after abrupt launcher exit. These children deliberately skip every destructor.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use sea_orm::{ConnectionTrait, EntityTrait};

use super::LocalBackend;
use crate::backend::local::creation;
use crate::db::entity::{sandbox, volume};
use crate::runtime::{SpawnMode, ensure_named_volumes};
use crate::sandbox::{SandboxBuilder, SandboxConfig, SandboxListBuilder, SandboxStatus};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct RecoveryFixture {
    _home: tempfile::TempDir,
    local: Arc<LocalBackend>,
    config: SandboxConfig,
    id: i32,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RecoveryFixture {
    async fn new() -> Self {
        #[cfg(unix)]
        let home = tempfile::tempdir_in("/tmp").unwrap();
        #[cfg(not(unix))]
        let home = tempfile::tempdir().unwrap();
        let local = Arc::new(
            crate::test_support::local_backend_builder(home.path())
                .build()
                .await
                .unwrap(),
        );
        let rootfs = home.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();
        let config = SandboxBuilder::new("recoverable")
            .image(rootfs.canonicalize().unwrap())
            .ephemeral(true)
            .volume("/data", |mount| {
                mount.named_with("new", |volume| volume.ensure_exists())
            })
            .build()
            .await
            .unwrap();
        let id = LocalBackend::insert_sandbox_record_impl(
            local.db().await.unwrap().write(),
            &config,
            SandboxStatus::Starting,
            true,
        )
        .await
        .unwrap();
        Self {
            _home: home,
            local,
            config,
            id,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn crash_child() {
    let Some(home) = std::env::var_os("MSB_CREATION_TEST_HOME") else {
        return;
    };
    let home = PathBuf::from(home);
    let phase = std::env::var("MSB_CREATION_TEST_PHASE").unwrap();
    let local = crate::test_support::local_backend_builder(&home)
        .build()
        .await
        .unwrap();
    let rootfs = home.join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();
    let rootfs = rootfs.canonicalize().unwrap();
    let shared = SandboxBuilder::new("shared-owner")
        .image(rootfs.clone())
        .volume("/shared", |m| m.named_with("shared", |v| v.ensure_exists()))
        .build()
        .await
        .unwrap();
    drop(ensure_named_volumes(&local, &shared).await.unwrap());
    std::fs::write(local.volume_path("shared").join("sentinel"), b"shared data").unwrap();
    let config = SandboxBuilder::new("interrupted")
        .image(rootfs)
        .volume("/shared", |m| m.named("shared"))
        .volume("/new", |m| m.named_with("new", |v| v.ensure_exists()))
        .build()
        .await
        .unwrap();
    let pools = local.db().await.unwrap();
    let _transition =
        LocalBackend::acquire_sandbox_transition_guard(&local.config().run_dir(), "interrupted")
            .await
            .unwrap();
    let _runtime = crate::runtime::acquire_sandbox_lifecycle_guard(
        &local.config().run_dir(),
        "interrupted",
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    let preparation = creation::lock_preparation(&local, "interrupted").unwrap();
    let id = LocalBackend::insert_sandbox_record_impl(
        pools.write(),
        &config,
        SandboxStatus::Starting,
        true,
    )
    .await
    .unwrap();
    if phase == "before-storage" {
        std::process::exit(73);
    }

    let _volumes = ensure_named_volumes(&local, &config).await.unwrap();
    let directory = local.sandboxes_dir().join("interrupted");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("upper.ext4"), b"partial disk").unwrap();
    if phase == "after-volumes" {
        let error = creation::remove(&local, id, "interrupted", creation::RemovalMode::Recovery)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("preparation is still finishing"));
        assert!(directory.exists());
        assert!(local.volume_path("new").exists());
    }

    drop(preparation);

    if phase == "delete-error" {
        let path = local.volume_path("new");
        std::fs::remove_dir_all(&path).unwrap();
        std::fs::write(path, b"not a directory").unwrap();
        assert!(
            creation::remove(&local, id, "interrupted", creation::RemovalMode::Creator)
                .await
                .is_err()
        );
    } else if phase == "after-unlink" {
        pools.write().execute_unprepared(
            "CREATE TRIGGER interrupt_delete BEFORE DELETE ON sandbox BEGIN SELECT RAISE(ABORT, 'interrupted final commit'); END;",
        ).await.unwrap();
        assert!(
            creation::remove(&local, id, "interrupted", creation::RemovalMode::Creator)
                .await
                .is_err()
        );
        assert!(!directory.exists());
        assert!(!local.volume_path("new").exists());
    }
    std::process::exit(73);
}

#[tokio::test]
async fn interrupted_creates_refuse_start_and_remain_removable_after_reopen() {
    for phase in [
        "before-storage",
        "after-volumes",
        "delete-error",
        "after-unlink",
    ] {
        #[cfg(unix)]
        let home = tempfile::tempdir_in("/tmp").unwrap();
        #[cfg(not(unix))]
        let home = tempfile::tempdir().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend::local::sandbox::create::recovery_tests::crash_child",
                "--nocapture",
            ])
            .env("MSB_CREATION_TEST_HOME", home.path())
            .env("MSB_CREATION_TEST_PHASE", phase)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(73),
            "{phase}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let local = Arc::new(
            crate::test_support::local_backend_builder(home.path())
                .build()
                .await
                .unwrap(),
        );
        let pools = local.db().await.unwrap();
        let rows = sandbox::Entity::find().all(pools.read()).await.unwrap();
        assert_eq!(rows.len(), 1, "{phase}: the recovery owner must survive");
        assert!(creation::pending(pools.read(), rows[0].id).await.unwrap());
        assert_eq!(
            volume::Entity::find()
                .all(pools.read())
                .await
                .unwrap()
                .len(),
            if phase == "before-storage" { 1 } else { 2 }
        );
        let error = local
            .start_sandbox(local.clone(), "interrupted", None, SpawnMode::Detached)
            .await
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("incomplete creation"),
            "{phase}: {error}"
        );
        if phase != "before-storage" {
            let error = crate::volume::get_local(local.clone(), "new")
                .await
                .err()
                .unwrap();
            assert!(error.to_string().contains("incomplete sandbox"), "{error}");
            let error = crate::volume::fs::VolumeFs::with_backend(local.clone(), "new")
                .write("unexpected", b"must not adopt provisional storage")
                .await
                .unwrap_err();
            assert!(error.to_string().contains("incomplete sandbox"), "{error}");
        }

        if phase == "after-unlink" {
            pools
                .write()
                .execute_unprepared("DROP TRIGGER interrupt_delete")
                .await
                .unwrap();
        } else if phase == "delete-error" {
            // Repair the deliberate filesystem obstruction, not any catalog state.
            std::fs::remove_file(local.volume_path("new")).unwrap();
        }
        local
            .remove_sandbox(local.clone(), "interrupted", None)
            .await
            .unwrap();
        assert!(
            sandbox::Entity::find()
                .all(pools.read())
                .await
                .unwrap()
                .is_empty()
        );
        assert!(!local.sandboxes_dir().join("interrupted").exists());
        assert!(!local.volume_path("new").exists());
        assert_eq!(
            std::fs::read(local.volume_path("shared").join("sentinel")).unwrap(),
            b"shared data"
        );
        assert_eq!(
            volume::Entity::find()
                .all(pools.read())
                .await
                .unwrap()
                .len(),
            1
        );
    }
}

#[tokio::test]
async fn cancelled_preparation_remains_fenced_until_its_worker_finishes() {
    let fixture = RecoveryFixture::new().await;
    let directory = fixture.local.sandboxes_dir().join("recoverable");
    std::fs::create_dir_all(&directory).unwrap();
    let guard = creation::lock_preparation(&fixture.local, "recoverable").unwrap();
    let (release, released) = std::sync::mpsc::channel();
    let (started, started_rx) = tokio::sync::oneshot::channel();
    let (worker, worker_rx) = tokio::sync::oneshot::channel();
    let path = directory.join("upper.ext4");
    let task = tokio::spawn(creation::preparing(guard, async move {
        let handle = creation::spawn_blocking(move || {
            started.send(()).unwrap();
            // Dropping release also unblocks the worker if the test fails.
            let _ = released.recv();
            std::fs::write(path, b"late formatter write").unwrap();
        });
        worker.send(handle).unwrap();
        std::future::pending::<()>().await;
    }));
    started_rx.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());

    let error = fixture
        .local
        .remove_sandbox(fixture.local.clone(), "recoverable", None)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("preparation is still finishing"),
        "{error}"
    );
    assert!(directory.exists());

    release.send(()).unwrap();
    worker_rx.await.unwrap().await.unwrap();
    // The creating process is still this test process. No PID lifetime should block recovery.
    fixture
        .local
        .remove_sandbox(fixture.local.clone(), "recoverable", None)
        .await
        .unwrap();
    assert!(!directory.exists());
    assert!(
        sandbox::Entity::find_by_id(fixture.id)
            .one(fixture.local.db().await.unwrap().read())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn prepared_config_preserves_labels_and_caller_overrides() {
    let mut fixture = RecoveryFixture::new().await;
    let mut overrides = crate::SandboxConfigPatch::new();
    overrides.spec.runtime.cmd = Some(Vec::new());
    fixture.config.caller_config_overrides = Some(Box::new(overrides));

    // This is the same late merge used by snapshot and archive restores.
    let mut image = microsandbox_image::ImageConfig::default();
    image.labels.insert("tier".into(), "web".into());
    fixture.config.merge_image_defaults(&image);
    fixture
        .local
        .prepare_reserved_sandbox(
            fixture.local.db().await.unwrap().write(),
            fixture.id,
            &fixture.config,
        )
        .await
        .unwrap();

    let (rows, _) = fixture
        .local
        .list_sandbox_handle_state(&SandboxListBuilder::default().label("tier", "web"))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let saved = SandboxConfig::from_stored(
        &rows[0].0.config,
        rows[0].0.caller_config_overrides.as_deref(),
    )
    .unwrap();
    assert_eq!(
        saved
            .caller_config_overrides
            .as_ref()
            .unwrap()
            .spec
            .runtime
            .cmd,
        Some(Vec::new()),
    );
    assert_eq!(
        saved.spec.labels.get("tier").map(String::as_str),
        Some("web")
    );
}

#[tokio::test]
async fn publication_and_recovery_retirement_commit_together() {
    let fixture = RecoveryFixture::new().await;
    let pools = fixture.local.db().await.unwrap();
    fixture
        .local
        .prepare_reserved_sandbox(pools.write(), fixture.id, &fixture.config)
        .await
        .unwrap();
    let transition = LocalBackend::acquire_sandbox_transition_guard(
        &fixture.local.config().run_dir(),
        "recoverable",
    )
    .await
    .unwrap();
    let volumes = Arc::new(
        ensure_named_volumes(&fixture.local, &fixture.config)
            .await
            .unwrap(),
    );
    let mut cleanup = super::cleanup::CreationCleanup::new(
        fixture.local.clone(),
        "recoverable".into(),
        transition,
        volumes,
        None,
    );
    cleanup.begin_publication();
    pools.write().execute_unprepared(
        "CREATE TRIGGER refuse_publication BEFORE UPDATE OF pending_creation_sandbox_id ON volume WHEN OLD.pending_creation_sandbox_id IS NOT NULL AND NEW.pending_creation_sandbox_id IS NULL BEGIN SELECT RAISE(ABORT, 'test publication failure'); END;",
    ).await.unwrap();
    assert!(
        creation::complete(pools.write(), fixture.id, SandboxStatus::Running)
            .await
            .is_err()
    );

    let row = sandbox::Entity::find_by_id(fixture.id)
        .one(pools.read())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, SandboxStatus::Starting);
    assert!(!row.ephemeral);
    assert!(creation::pending(pools.read(), fixture.id).await.unwrap());
    assert!(
        crate::volume::get_local(fixture.local.clone(), "new")
            .await
            .is_err()
    );

    pools
        .write()
        .execute_unprepared("DROP TRIGGER refuse_publication")
        .await
        .unwrap();
    creation::complete(pools.write(), fixture.id, SandboxStatus::Running)
        .await
        .unwrap();
    // Model cancellation after SQLite commits but before the caller observes success.
    cleanup
        .finish_failure(crate::MicrosandboxError::Runtime(
            "cancelled publication".into(),
        ))
        .await;
    let row = sandbox::Entity::find_by_id(fixture.id)
        .one(pools.read())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, SandboxStatus::Running);
    assert!(row.ephemeral);
    assert!(!creation::pending(pools.read(), fixture.id).await.unwrap());
    assert!(
        crate::volume::get_local(fixture.local.clone(), "new")
            .await
            .is_ok()
    );
}
