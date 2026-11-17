//! Ownership tests use ordinary child processes and in-memory agent handshakes, not VMs.

use std::{os::fd::OwnedFd, process::Stdio, sync::Arc, time::Duration};

use microsandbox_protocol::{
    codec,
    core::Ready,
    message::{Message, MessageType},
};
use sea_orm::{EntityTrait, Set};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::sync::Mutex;

use crate::{Context, Sandbox, SandboxConfig, context::SandboxLocalState, runtime::ProcessHandle};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(in crate::sandbox) async fn fixture(
    watchdog: Option<OwnedFd>,
) -> (
    Sandbox,
    DuplexStream,
    tokio::process::ChildStdin,
    tempfile::TempDir,
) {
    fixture_with_version(watchdog, microsandbox_protocol::message::PROTOCOL_VERSION).await
}

pub(in crate::sandbox) async fn fixture_with_version(
    watchdog: Option<OwnedFd>,
    version: u8,
) -> (
    Sandbox,
    DuplexStream,
    tokio::process::ChildStdin,
    tempfile::TempDir,
) {
    let home = tempfile::tempdir_in("/tmp").unwrap();
    let backend: Arc<dyn Context> = Arc::new(
        crate::test_support::local_backend_builder(home.path())
            .build()
            .unwrap(),
    );
    let mut child = tokio::process::Command::new("/bin/sh")
        .args(["-c", "printf 'ready\\n'; read value"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .await
        .unwrap();
    assert_eq!(ready, "ready\n");
    let stdin = child.stdin.take().unwrap();
    let process = ProcessHandle::new(
        child.id().unwrap(),
        "task".into(),
        child,
        vec![],
        watchdog,
        None,
    );
    let cleanup = Some(process.cleanup_control());
    let (client, mut server) = tokio::io::duplex(4096);
    let handshake = tokio::spawn(async move {
        server.write_all(&1u32.to_be_bytes()).await.unwrap();
        server.write_all(&1024u32.to_be_bytes()).await.unwrap();
        let mut ready = Message::with_payload(MessageType::Ready, 0, &Ready::default()).unwrap();
        ready.v = version;
        codec::write_message(&mut server, &ready).await.unwrap();
        server
    });
    let client =
        crate::agent::AgentClient::connect_stream_with_timeout(client, Duration::from_secs(1))
            .await
            .unwrap();
    let mut config = SandboxConfig::default();
    config.spec.name = "task".into();
    let sandbox = Sandbox::from_local(
        backend,
        SandboxLocalState {
            db_id: 1,
            run_id: Some(1),
            handle: Some(Arc::new(Mutex::new(process))),
            cleanup,
            owned_run_id: Some(1),
            client: Arc::new(client),
        },
        config,
    );
    (sandbox, handshake.await.unwrap(), stdin, home)
}

pub(in crate::sandbox) async fn finish(sb: &Sandbox) {
    let local = sb.local_state().unwrap();
    let mut child = local.handle.as_ref().unwrap().lock().await;
    child.kill().unwrap();
    child.wait().await.unwrap();
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn reaping_preserves_a_live_run_and_does_not_wait_for_its_process_lock() {
    let (sb, _peer, _stdin, _home) = fixture(None).await;
    sb.reap_exited_child().unwrap();
    assert!(sb.owns_lifecycle());

    let local = sb.local_state().unwrap();
    let mut process = local.handle.as_ref().unwrap().lock().await;
    assert!(process.try_wait().unwrap().is_none());

    // A concurrent process waiter may hold this lock until exit. Cleanup must
    // neither block behind it nor terminate a live run to make it available.
    sb.reap_exited_child().unwrap();
    assert!(process.try_wait().unwrap().is_none());
    assert!(sb.owns_lifecycle());
    drop(process);

    sb.detach().await.unwrap();
    sb.reap_exited_child().unwrap();
    assert!(!sb.owns_lifecycle());
    finish(&sb).await;
}

#[tokio::test]
async fn final_owner_drop_stops_the_child_but_one_clone_drop_does_not() {
    let (sb, _peer, _stdin, _home) = fixture(None).await;
    let clone = sb.clone();
    let pid = sb
        .local_state()
        .unwrap()
        .handle
        .as_ref()
        .unwrap()
        .lock()
        .await
        .pid();
    drop(sb);
    assert!(
        clone
            .local_state()
            .unwrap()
            .handle
            .as_ref()
            .unwrap()
            .lock()
            .await
            .try_wait()
            .unwrap()
            .is_none()
    );
    drop(clone);
    tokio::time::timeout(Duration::from_secs(3), async {
        while nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_ok() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("final-owner fallback must stop and reap the child");
}

#[tokio::test]
async fn detached_final_owner_drop_leaves_the_child_running() {
    let (sb, _peer, mut stdin, _home) = fixture(None).await;
    let pid = sb
        .local_state()
        .unwrap()
        .handle
        .as_ref()
        .unwrap()
        .lock()
        .await
        .pid();
    sb.detach().await.unwrap();
    drop(sb);
    // Its private stdin is still open, so neither EOF nor a dropped process
    // owner should have ended this child. Complete it through that same pipe.
    assert!(nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_ok());
    stdin.write_all(b"finish\n").await.unwrap();
    drop(stdin);
    tokio::time::timeout(Duration::from_secs(3), async {
        while nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_ok() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("fixture must finish without leaking a child");
}

#[tokio::test]
async fn concurrent_detach_sends_the_existing_watchdog_byte_once() {
    use std::io::Read;
    let (writer, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
    let (sb, _peer, _stdin, _home) = fixture(Some(writer.into())).await;
    let clone = sb.clone();
    let (first, second) = tokio::join!(sb.detach(), clone.detach());
    first.unwrap();
    second.unwrap();
    let mut byte = [0];
    reader.read_exact(&mut byte).unwrap();
    assert_eq!(byte, [microsandbox_runtime::vm::PARENT_WATCH_DETACH]);
    reader.set_nonblocking(true).unwrap();
    assert_eq!(
        reader.read(&mut byte).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    finish(&sb).await;
}

#[tokio::test]
async fn detach_is_repeatable_shared_and_non_consuming() {
    let (sb, _peer, _stdin, _home) = fixture(None).await;
    let clone = sb.clone();
    let identity = sb.id();
    assert!(sb.owns_lifecycle());
    clone.detach().await.unwrap();
    sb.detach().await.unwrap();
    assert!(!sb.owns_lifecycle());
    assert!(!clone.owns_lifecycle());
    assert_eq!(sb.id(), identity);
    assert_eq!(sb.name(), "task");
    assert!(
        sb.local_state()
            .unwrap()
            .handle
            .as_ref()
            .unwrap()
            .lock()
            .await
            .try_wait()
            .unwrap()
            .is_none()
    );
    // The resource and its original connection survive detaching a different clone.
    assert!(Arc::ptr_eq(
        &sb.local_state().unwrap().client,
        &clone.local_state().unwrap().client
    ));
    drop(clone);
    finish(&sb).await;
}

#[tokio::test]
async fn failed_detach_preserves_the_receiver_and_cleanup_authority() {
    // A read-only descriptor produces a deterministic write failure without SIGPIPE.
    let watchdog = std::fs::File::open("/dev/null").unwrap().into();
    let (sb, _peer, _stdin, _home) = fixture(Some(watchdog)).await;
    let clone = sb.clone();
    assert!(sb.detach().await.is_err());
    assert!(sb.owns_lifecycle());
    assert!(clone.owns_lifecycle());
    assert_eq!(sb.name(), "task");
    finish(&sb).await;
}

#[tokio::test]
async fn nonowner_cannot_disarm_an_independent_owner() {
    let (sb, _peer, _stdin, _home) = fixture(None).await;
    let nonowner = Sandbox::from_local(
        sb.backend.clone(),
        SandboxLocalState {
            db_id: 1,
            run_id: Some(1),
            handle: None,
            cleanup: None,
            owned_run_id: None,
            client: sb.local_state().unwrap().client.clone(),
        },
        sb.prepared_runtime().unwrap().config.clone(),
    );
    nonowner.detach().await.unwrap();
    nonowner.shutdown_owned().await.unwrap();
    assert!(!nonowner.owns_lifecycle());
    assert!(sb.owns_lifecycle());
    finish(&sb).await;
}

#[tokio::test]
async fn detach_does_not_wait_for_the_process_wait_lock() {
    let (sb, _peer, _stdin, _home) = fixture(None).await;
    let local = sb.local_state().unwrap();
    let guard = local.handle.as_ref().unwrap().lock().await;
    tokio::time::timeout(Duration::from_secs(1), sb.detach())
        .await
        .unwrap()
        .unwrap();
    assert!(!sb.owns_lifecycle());
    drop(guard);
    sb.detach().await.unwrap();
    assert!(!sb.owns_lifecycle());
    finish(&sb).await;
}

#[tokio::test]
async fn old_scope_cannot_stop_a_new_run_of_the_same_resource() {
    use crate::db::entity::{run, sandbox};
    let home = tempfile::tempdir_in("/tmp").unwrap();
    let local = crate::test_support::local_backend_builder(home.path())
        .build()
        .unwrap();
    let db = local.db().await.unwrap();
    let id = sandbox::Entity::insert(sandbox::ActiveModel {
        name: Set("task".into()),
        config: Set(serde_json::to_string(&SandboxConfig::default()).unwrap()),
        status: Set(crate::sandbox::SandboxStatus::Running),
        ephemeral: Set(false),
        ..Default::default()
    })
    .exec(db.write())
    .await
    .unwrap()
    .last_insert_id;
    let newer = run::Entity::insert(run::ActiveModel {
        sandbox_id: Set(id),
        status: Set(run::RunStatus::Running),
        pid: Set(Some(std::process::id() as i32)),
        ..Default::default()
    })
    .exec(db.write())
    .await
    .unwrap()
    .last_insert_id;
    // Hold the runtime lock: accidentally falling through would try to contact a
    // nonexistent agent and fail, rather than silently completing a stopped case.
    let _runtime =
        microsandbox_runtime::ipc::try_acquire_lifecycle_guard(&local.config().run_dir(), "task")
            .unwrap()
            .unwrap();
    local
        .stop_owned_generation("task", id, false, newer - 1)
        .await
        .unwrap();
    assert_eq!(
        run::Entity::find_by_id(newer)
            .one(db.read())
            .await
            .unwrap()
            .unwrap()
            .status,
        run::RunStatus::Running
    );
    // The existing storage-repair authorization stays strict about mismatches.
    assert!(
        local
            .stop_complete_generation("task", id, false, Some(newer - 1))
            .await
            .is_err()
    );
}
