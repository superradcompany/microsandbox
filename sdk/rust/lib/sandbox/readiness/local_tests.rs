//! Exercise receiver ownership with a catalog and real child, without booting a VM.

use std::sync::Arc;

use sea_orm::{ActiveModelTrait, EntityTrait, Set};

use crate::sandbox::lifetime::tests::{finish, fixture};
use crate::{
    Sandbox, SandboxConfig,
    db::entity::{run, sandbox},
    sandbox::SandboxStatus,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn persist_owner(sb: &Sandbox) {
    let local = sb.backend.as_local().unwrap();
    let state = sb.local_state().unwrap();
    let pid = state.handle.as_ref().unwrap().lock().await.pid();
    let db = local.db().await.unwrap();
    let mut config = SandboxConfig::default();
    config.spec.name = "task".into();
    let record = sandbox::ActiveModel {
        id: Set(state.db_id),
        name: Set("task".into()),
        config: Set(serde_json::to_string(&config).unwrap()),
        status: Set(SandboxStatus::Running),
        ephemeral: Set(false),
        ..Default::default()
    }
    .insert(db.write())
    .await
    .unwrap();
    run::ActiveModel {
        id: Set(state.run_id.unwrap()),
        sandbox_id: Set(record.id),
        status: Set(run::RunStatus::Running),
        pid: Set(Some(pid as i32)),
        ..Default::default()
    }
    .insert(db.write())
    .await
    .unwrap();
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn repeated_preparation_preserves_local_owner_and_connection() {
    let (sb, _peer, _stdin, _home) = fixture(None).await;
    persist_owner(&sb).await;
    let local = sb.backend.as_local().unwrap();
    let _runtime =
        microsandbox_runtime::ipc::try_acquire_lifecycle_guard(&local.config().run_dir(), "task")
            .unwrap()
            .unwrap();
    let original = sb.prepared_runtime().unwrap();
    let clone = sb.clone();
    let (a, b) = tokio::join!(sb.ensure_running(), clone.ensure_running());
    a.unwrap();
    b.unwrap();
    assert!(Arc::ptr_eq(&original, &sb.prepared_runtime().unwrap()));
    assert!(sb.owns_lifecycle() && clone.owns_lifecycle());
    assert!(Arc::ptr_eq(
        &sb.client().await.unwrap(),
        &sb.local_state().unwrap().client
    ));
    // Lookup starts unprepared and cannot inherit this group's cleanup authority.
    let independent = Sandbox::ctx(sb.context()).get("task").await.unwrap();
    assert!(!independent.owns_lifecycle());
    assert!(independent.binding.current().is_none());
    finish(&sb).await;
}

#[tokio::test]
async fn health_preparation_reuses_owner_but_never_starts_a_stopped_resource() {
    let (owner, _peer, _stdin, _home) = fixture(None).await;
    persist_owner(&owner).await;
    let local = owner.backend.as_local().unwrap();
    let runtime =
        microsandbox_runtime::ipc::try_acquire_lifecycle_guard(&local.config().run_dir(), "task")
            .unwrap()
            .unwrap();
    let original = owner.prepared_runtime().unwrap();
    assert!(Arc::ptr_eq(
        &original,
        &owner.connect_running().await.unwrap()
    ));
    assert!(owner.owns_lifecycle());
    let resource = Sandbox::ctx(owner.context()).get("task").await.unwrap();
    finish(&owner).await;
    drop(runtime);
    assert!(matches!(
        resource.ping().await,
        Err(crate::MicrosandboxError::SandboxNotRunning(_))
    ));
    assert!(matches!(
        resource.touch().await,
        Err(crate::MicrosandboxError::SandboxNotRunning(_))
    ));
    assert!(resource.binding.current().is_none());
    assert!(!resource.owns_lifecycle());
}

#[tokio::test]
async fn config_reads_other_clients_changes_without_preparation() {
    let (owner, _peer, _stdin, _home) = fixture(None).await;
    persist_owner(&owner).await;
    let local = owner.backend.as_local().unwrap();
    let _runtime =
        microsandbox_runtime::ipc::try_acquire_lifecycle_guard(&local.config().run_dir(), "task")
            .unwrap()
            .unwrap();
    let resource = Sandbox::ctx(owner.context()).get("task").await.unwrap();
    let first = resource.config().await.unwrap();
    let db = local.db().await.unwrap();
    let mut config = SandboxConfig {
        spec: first.local_spec().unwrap().clone(),
        ..Default::default()
    };
    config.spec.resources.memory_mib = first.local_spec().unwrap().resources.memory_mib + 256;
    let mut record: sandbox::ActiveModel = sandbox::Entity::find_by_id(1)
        .one(db.read())
        .await
        .unwrap()
        .unwrap()
        .into();
    record.config = Set(serde_json::to_string(&config).unwrap());
    record.update(db.write()).await.unwrap();
    assert_eq!(
        resource
            .config()
            .await
            .unwrap()
            .local_spec()
            .unwrap()
            .resources
            .memory_mib,
        first.local_spec().unwrap().resources.memory_mib + 256
    );
    assert!(resource.binding.current().is_none());
    // Fresh persisted settings never rewrite the connection's applied settings.
    assert_eq!(
        owner
            .prepared_runtime()
            .unwrap()
            .config
            .spec
            .resources
            .memory_mib,
        first.local_spec().unwrap().resources.memory_mib
    );
    finish(&owner).await;
}

#[tokio::test]
async fn streaming_execution_pins_its_runtime_until_completion() {
    use microsandbox_protocol::{
        codec,
        exec::ExecExited,
        message::{Message, MessageType},
    };
    let (sb, mut peer, _stdin, _home) = fixture(None).await;
    persist_owner(&sb).await;
    let local = sb.backend.as_local().unwrap();
    let _runtime =
        microsandbox_runtime::ipc::try_acquire_lifecycle_guard(&local.config().run_dir(), "task")
            .unwrap()
            .unwrap();
    let generation = Arc::downgrade(&sb.prepared_runtime().unwrap());
    // No name-addressed relay exists in this fixture: dispatch must use the
    // already prepared client, not redial and risk selecting another run.
    let mut execution = sb.shell_stream("echo retained").await.unwrap();
    let request = codec::read_message(&mut peer).await.unwrap();
    assert_eq!(request.t, MessageType::ExecRequest);
    drop(sb);
    assert!(generation.upgrade().is_some());
    codec::write_message(
        &mut peer,
        &Message::with_payload(MessageType::ExecExited, request.id, &ExecExited { code: 0 })
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(execution.wait().await.unwrap().code, 0);
    assert!(generation.upgrade().is_none());
    assert_eq!(execution.wait().await.unwrap().code, 0);
}

#[tokio::test]
async fn idle_helpers_do_not_keep_a_run_alive_or_resurrect_a_released_receiver() {
    let (sb, _peer, _stdin, _home) = fixture(None).await;
    let generation = Arc::downgrade(&sb.prepared_runtime().unwrap());
    let fs = sb.fs();
    #[cfg(feature = "ssh")]
    let ssh = sb.ssh();
    drop(sb);
    assert!(generation.upgrade().is_none());
    assert!(
        fs.list("/")
            .await
            .unwrap_err()
            .to_string()
            .contains("released")
    );
    #[cfg(feature = "ssh")]
    assert!(
        ssh.connect()
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("released")
    );
}

#[tokio::test]
async fn owned_file_retains_its_opening_run_after_receiver_changes_generation() {
    use microsandbox_protocol::{
        codec,
        fs::{FsOp, FsRequest, FsResponse, FsResponseData},
        message::{Message, MessageType},
    };
    let (sb, mut peer, _stdin, _home) = fixture(None).await;
    persist_owner(&sb).await;
    let local = sb.backend.as_local().unwrap();
    let _runtime =
        microsandbox_runtime::ipc::try_acquire_lifecycle_guard(&local.config().run_dir(), "task")
            .unwrap()
            .unwrap();
    let generation = Arc::downgrade(&sb.prepared_runtime().unwrap());
    let server = tokio::spawn(async move {
        for index in 0..3 {
            let request = codec::read_message(&mut peer).await.unwrap();
            let payload: FsRequest = request.payload().unwrap();
            let data = match (index, payload.op) {
                (0, FsOp::OpenDir { .. }) => Some(FsResponseData::Handle(17)),
                (1, FsOp::ReadDir { handle: 17, .. }) => Some(FsResponseData::List(vec![])),
                (2, FsOp::CloseHandle { handle: 17 }) => None,
                (_, other) => panic!("unexpected file request {index}: {other:?}"),
            };
            codec::write_message(
                &mut peer,
                &Message::with_payload(
                    MessageType::FsResponse,
                    request.id,
                    &FsResponse {
                        ok: true,
                        error: None,
                        data,
                    },
                )
                .unwrap(),
            )
            .await
            .unwrap();
        }
    });
    let file = sb.fs().open_dir("/").await.unwrap();
    let (replacement, _replacement_peer, _replacement_stdin, _replacement_home) =
        fixture(None).await;
    // Simulate receiver publication of a later connection. The file must still
    // use its original relay-client handle range, without consulting the receiver.
    sb.binding.publish(replacement.prepared_runtime().unwrap());
    drop(sb);
    assert!(generation.upgrade().is_some());
    assert!(file.read_dir(None).await.unwrap().is_empty());
    file.close().await.unwrap();
    server.await.unwrap();
    assert!(generation.upgrade().is_none());
    finish(&replacement).await;
}

#[tokio::test]
async fn filesystem_stream_releases_run_on_terminal_success_or_failure() {
    use microsandbox_protocol::{
        codec,
        fs::{FsData, FsOp, FsRequest, FsResponse, FsResponseData},
        message::{Message, MessageType},
    };
    for success in [true, false] {
        let (sb, mut peer, _stdin, _home) =
            crate::sandbox::lifetime::tests::fixture_with_version(None, 6).await;
        persist_owner(&sb).await;
        let local = sb.backend.as_local().unwrap();
        let _runtime = microsandbox_runtime::ipc::try_acquire_lifecycle_guard(
            &local.config().run_dir(),
            "task",
        )
        .unwrap()
        .unwrap();
        let generation = Arc::downgrade(&sb.prepared_runtime().unwrap());
        let server = tokio::spawn(async move {
            let open = codec::read_message(&mut peer).await.unwrap();
            assert!(matches!(
                open.payload::<FsRequest>().unwrap().op,
                FsOp::OpenFile { .. }
            ));
            codec::write_message(
                &mut peer,
                &Message::with_payload(
                    MessageType::FsResponse,
                    open.id,
                    &FsResponse {
                        ok: true,
                        error: None,
                        data: Some(FsResponseData::Handle(23)),
                    },
                )
                .unwrap(),
            )
            .await
            .unwrap();
            let read = codec::read_message(&mut peer).await.unwrap();
            assert!(matches!(
                read.payload::<FsRequest>().unwrap().op,
                FsOp::Read { handle: 23, .. }
            ));
            codec::write_message(
                &mut peer,
                &Message::with_payload(
                    MessageType::FsData,
                    read.id,
                    &FsData {
                        data: b"hello".to_vec(),
                    },
                )
                .unwrap(),
            )
            .await
            .unwrap();
            codec::write_message(
                &mut peer,
                &Message::with_payload(
                    MessageType::FsResponse,
                    read.id,
                    &FsResponse {
                        ok: success,
                        error: (!success).then(|| "read failed".into()),
                        data: None,
                    },
                )
                .unwrap(),
            )
            .await
            .unwrap();
            let close = codec::read_message(&mut peer).await.unwrap();
            assert!(matches!(
                close.payload::<FsRequest>().unwrap().op,
                FsOp::CloseHandle { handle: 23 }
            ));
            codec::write_message(
                &mut peer,
                &Message::with_payload(
                    MessageType::FsResponse,
                    close.id,
                    &FsResponse {
                        ok: true,
                        error: None,
                        data: None,
                    },
                )
                .unwrap(),
            )
            .await
            .unwrap();
        });
        let mut stream = sb.fs().read_stream("/file").await.unwrap();
        drop(sb);
        assert!(generation.upgrade().is_some());
        assert_eq!(stream.recv().await.unwrap().unwrap().as_ref(), b"hello");
        let terminal = stream.recv().await;
        if success {
            assert!(terminal.unwrap().is_none());
        } else {
            assert!(terminal.unwrap_err().to_string().contains("read failed"));
        }
        server.await.unwrap();
        // Keeping the completed stream object must not keep the VM running.
        assert!(generation.upgrade().is_none());
        assert!(stream.recv().await.unwrap().is_none());
    }
}

#[cfg(feature = "ssh")]
#[tokio::test]
async fn ssh_client_retains_selected_run_and_reuses_its_existing_agent() {
    use microsandbox_protocol::{
        codec,
        exec::ExecExited,
        message::{Message, MessageType},
    };
    let (sb, mut peer, _stdin, _home) = fixture(None).await;
    persist_owner(&sb).await;
    let local = sb.backend.as_local().unwrap();
    let _runtime =
        microsandbox_runtime::ipc::try_acquire_lifecycle_guard(&local.config().run_dir(), "task")
            .unwrap()
            .unwrap();
    let generation = Arc::downgrade(&sb.prepared_runtime().unwrap());
    let client = sb.ssh().connect().await.unwrap();
    let server = tokio::spawn(async move {
        let request = codec::read_message(&mut peer).await.unwrap();
        assert_eq!(request.t, MessageType::ExecRequest);
        codec::write_message(
            &mut peer,
            &Message::with_payload(MessageType::ExecExited, request.id, &ExecExited { code: 0 })
                .unwrap(),
        )
        .await
        .unwrap();
    });
    drop(sb);
    assert!(generation.upgrade().is_some());
    assert_eq!(client.exec("true").await.unwrap().status, 0);
    server.await.unwrap();
    client.close().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while generation.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("closed SSH client must release the selected runtime");
}

#[tokio::test]
async fn cancelled_filesystem_open_closes_a_late_returned_handle() {
    use microsandbox_protocol::{
        codec,
        fs::{FsOp, FsRequest, FsResponse, FsResponseData},
        message::{Message, MessageType},
    };
    let (sb, mut peer, _stdin, _home) = fixture(None).await;
    persist_owner(&sb).await;
    let local = sb.backend.as_local().unwrap();
    let _runtime =
        microsandbox_runtime::ipc::try_acquire_lifecycle_guard(&local.config().run_dir(), "task")
            .unwrap()
            .unwrap();
    let generation = Arc::downgrade(&sb.prepared_runtime().unwrap());
    let fs = sb.fs();
    let opening = tokio::spawn(async move { fs.open_dir("/").await });
    let request = codec::read_message(&mut peer).await.unwrap();
    assert!(matches!(
        request.payload::<FsRequest>().unwrap().op,
        FsOp::OpenDir { .. }
    ));
    opening.abort();
    assert!(opening.await.is_err());
    drop(sb);
    assert!(generation.upgrade().is_some());
    codec::write_message(
        &mut peer,
        &Message::with_payload(
            MessageType::FsResponse,
            request.id,
            &FsResponse {
                ok: true,
                error: None,
                data: Some(FsResponseData::Handle(47)),
            },
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let close = codec::read_message(&mut peer).await.unwrap();
    assert!(matches!(
        close.payload::<FsRequest>().unwrap().op,
        FsOp::CloseHandle { handle: 47 }
    ));
    codec::write_message(
        &mut peer,
        &Message::with_payload(
            MessageType::FsResponse,
            close.id,
            &FsResponse {
                ok: true,
                error: None,
                data: None,
            },
        )
        .unwrap(),
    )
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while generation.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("abandoned open must release its run after closing the late handle");
}

#[tokio::test]
async fn creation_workdir_validation_uses_ready_session_before_running_publication() {
    use microsandbox_protocol::{
        codec,
        fs::FsResponse,
        message::{Message, MessageType},
    };
    let (sb, mut peer, _stdin, _home) = fixture(None).await;
    persist_owner(&sb).await;
    let db = sb.backend.as_local().unwrap().db().await.unwrap();
    let mut row: sandbox::ActiveModel = sandbox::Entity::find_by_id(1)
        .one(db.read())
        .await
        .unwrap()
        .unwrap()
        .into();
    row.status = Set(SandboxStatus::Starting);
    row.update(db.write()).await.unwrap();
    let reply = async {
        let request = codec::read_message(&mut peer).await.unwrap();
        assert_eq!(request.t, MessageType::FsRequest);
        codec::write_message(
            &mut peer,
            &Message::with_payload(
                MessageType::FsResponse,
                request.id,
                &FsResponse {
                    ok: false,
                    error: Some("missing workdir".into()),
                    data: None,
                },
            )
            .unwrap(),
        )
        .await
        .unwrap();
    };
    let check = super::super::fs::SandboxFsOps::stat_prepared(&sb, "/missing");
    let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::join!(check, reply)
    })
    .await
    .expect("startup validation must not wait for Running publication");
    assert!(result.unwrap().unwrap_err().contains("missing workdir"));
    assert_eq!(
        sandbox::Entity::find_by_id(1)
            .one(db.read())
            .await
            .unwrap()
            .unwrap()
            .status,
        SandboxStatus::Starting
    );
    finish(&sb).await;
}

#[tokio::test]
async fn retained_compaction_builder_rejects_a_same_name_replacement() {
    let (sb, _peer, _stdin, _home) = fixture(None).await;
    persist_owner(&sb).await;
    let builder = sb.compact();
    let db = sb.backend.as_local().unwrap().db().await.unwrap();
    use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
    db.write()
        .execute_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "UPDATE sandbox SET name = ? WHERE id = ?",
            ["original".into(), 1.into()],
        ))
        .await
        .unwrap();
    let mut config = SandboxConfig::default();
    config.spec.name = "task".into();
    sandbox::ActiveModel {
        name: Set("task".into()),
        config: Set(serde_json::to_string(&config).unwrap()),
        status: Set(SandboxStatus::Stopped),
        ephemeral: Set(false),
        ..Default::default()
    }
    .insert(db.write())
    .await
    .unwrap();
    assert!(matches!(
        builder.apply().await,
        Err(crate::MicrosandboxError::SandboxReplaced { .. })
    ));
    finish(&sb).await;
}

#[tokio::test]
async fn live_config_does_not_erase_launch_outcomes() {
    let (owner, _peer, _stdin, _home) = fixture(None).await;
    persist_owner(&owner).await;
    let session = owner.prepared_runtime().unwrap();
    let mut config = session.config.clone();
    config.init_owns_workload = true;
    config.resumed_from_full_snapshot = true;
    owner
        .binding
        .publish(Arc::new(crate::sandbox::state::RuntimeSession {
            inner: crate::context::SandboxInner::Local(owner.local_state().unwrap()),
            config,
        }));
    let clone = owner.clone();
    let persisted = owner.config().await.unwrap();
    let json = serde_json::to_value(&persisted).unwrap();
    assert!(json["spec"].get("init_owns_workload").is_none());
    assert!(json["spec"].get("resumed_from_full_snapshot").is_none());
    let launch = clone.launch_info().unwrap();
    assert!(launch.init_owns_boot_workload);
    assert!(launch.resumed_from_full_snapshot);
    let independent = Sandbox::ctx(owner.context()).get("task").await.unwrap();
    assert!(independent.launch_info().is_none());
    finish(&owner).await;
}
