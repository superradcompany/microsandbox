//! Refused replacement preserves the catalog, process and storage namespace.

use std::os::unix::fs::PermissionsExt;

use sea_orm::{EntityTrait, Set};

use super::{LocalContext, SandboxConfig, run_entity, sandbox_entity};
use crate::sandbox::SandboxStatus;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn refuse_replacement_with_owner(socket: bool) {
    let home = tempfile::Builder::new()
        .prefix("replace-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .unwrap();
    let context = crate::test_support::local_backend_builder(home.path())
        .build()
        .unwrap();
    let mut config = SandboxConfig {
        spec: microsandbox_types::SandboxSpec {
            name: "owned".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    config.spec.mounts.push(
        crate::sandbox::MountBuilder::new("/data")
            .owned_with(|owned| owned.disk().size(1_u32))
            .build()
            .unwrap(),
    );
    let pools = context.db().await.unwrap();
    let id = LocalContext::insert_sandbox_record(pools.write(), &config)
        .await
        .unwrap();
    LocalContext::update_sandbox_status(pools.write(), id, SandboxStatus::Stopped)
        .await
        .unwrap();
    let directory = context.sandboxes_dir().join("owned");
    std::fs::create_dir_all(&directory).unwrap();
    let sentinel = directory.join("sentinel");
    std::fs::write(&sentinel, "retain").unwrap();
    let sockets = microsandbox_runtime::ipc::SandboxSocketPaths::new(
        &context.config().run_dir(),
        &directory,
        "owned",
    );
    let mut listener = None;
    let mut guards = None;
    if socket {
        std::fs::create_dir_all(sockets.runtime.legacy_agent.parent().unwrap()).unwrap();
        listener = Some(tokio::net::UnixListener::bind(&sockets.runtime.legacy_agent).unwrap());
    } else {
        let backing = crate::runtime::owned_volumes::backing_path(
            &directory,
            "/data",
            &microsandbox_types::OwnedVolumeStorage::Disk { capacity_mib: 1 },
        );
        std::fs::create_dir_all(backing.parent().unwrap()).unwrap();
        crate::runtime::owned_volumes::disk_lock_path(&directory, "/data").unwrap();
        guards =
            crate::runtime::owned_volumes::try_acquire_disk_guards(&directory, &config.spec.mounts)
                .unwrap();
        assert_eq!(guards.as_ref().unwrap().len(), 1);
    }
    config.replace_existing = true;
    assert!(
        LocalContext::prepare_create_target(
            pools,
            &config,
            &directory,
            &context.config().run_dir()
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "retain");
    assert_eq!(
        sandbox_entity::Entity::find_by_id(id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap()
            .status,
        SandboxStatus::Stopped
    );
    // Explicit removal uses the same fences even when the catalog is terminal.
    assert!(
        crate::sandbox::remove_local_persisted_sandbox(&context, "owned", id)
            .await
            .is_err()
    );
    assert!(sentinel.exists());
    drop((listener, guards));
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn replacement_preserves_live_endpoint_even_for_terminal_row() {
    refuse_replacement_with_owner(true).await;
}

#[tokio::test]
async fn replacement_preserves_owned_disk_after_lifecycle_release() {
    refuse_replacement_with_owner(false).await;
}

#[tokio::test]
async fn renamed_process_and_old_timestamp_do_not_authorize_replacement() {
    let home = tempfile::tempdir().unwrap();
    let context = crate::test_support::local_backend_builder(home.path())
        .build()
        .unwrap();
    let pools = context.db().await.unwrap();
    let mut config = SandboxConfig {
        spec: microsandbox_types::SandboxSpec {
            name: "ambiguous".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let id = LocalContext::insert_sandbox_record(pools.write(), &config)
        .await
        .unwrap();
    LocalContext::update_sandbox_status(pools.write(), id, SandboxStatus::Running)
        .await
        .unwrap();
    let (child, _bin) = super::super::runtime_identity::test_support::spawn_msb_child();
    let mut child = scopeguard::guard(child, |mut child| {
        super::super::runtime_identity::test_support::cleanup_child(&mut child)
    });
    run_entity::Entity::insert(run_entity::ActiveModel {
        sandbox_id: Set(id),
        pid: Set(Some(child.id() as i32)),
        status: Set(run_entity::RunStatus::Running),
        started_at: Set(Some(
            (chrono::Utc::now() - chrono::TimeDelta::hours(1)).naive_utc(),
        )),
        ..Default::default()
    })
    .exec(pools.write())
    .await
    .unwrap();
    let directory = context.sandboxes_dir().join("ambiguous");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("sentinel"), "retain").unwrap();
    config.replace_existing = true;
    assert!(
        LocalContext::prepare_create_target(
            pools,
            &config,
            &directory,
            &context.config().run_dir()
        )
        .await
        .is_err()
    );
    assert!(child.try_wait().unwrap().is_none());
    assert!(directory.join("sentinel").exists());
    assert_eq!(
        sandbox_entity::Entity::find_by_id(id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap()
            .status,
        SandboxStatus::Running
    );
}
