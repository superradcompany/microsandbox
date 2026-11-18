//! Deadline, cancellation and transport failures over real SDK control connections.

use std::sync::Arc;
use std::time::Duration;

use microsandbox_control_client::ControlWelcome;
use microsandbox_db::entity::{run, sandbox};
use microsandbox_protocol::{codec, wire::Envelope};
use microsandbox_runtime::ipc::RuntimeSocketPaths;
use sea_orm::{ActiveModelTrait, Set};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum MemoryFault {
    Stall,
    Disconnect,
    WrongGeneration,
    ContradictoryCompletion,
}

struct PeerScenario {
    fault: MemoryFault,
    trigger_read: usize,
    recovered: tokio::sync::watch::Sender<bool>,
    reached: tokio::sync::Notify,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PeerScenario {
    fn new(fault: MemoryFault, trigger_read: usize) -> Arc<Self> {
        Arc::new(Self {
            fault,
            trigger_read,
            recovered: tokio::sync::watch::channel(false).0,
            reached: tokio::sync::Notify::new(),
        })
    }

    fn recover(&self) {
        self.recovered.send_replace(true);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn recorded(resource: ResourceKind) -> ResizeOperation {
    let target = match resource {
        ResourceKind::Cpus => ResizeTarget::Cpus { online: 4 },
        ResourceKind::Memory => ResizeTarget::Memory { total_mib: 512 },
    };
    ResizeOperation {
        id: if resource == ResourceKind::Cpus {
            "cpu"
        } else {
            "memory"
        }
        .into(),
        runtime_boot_id: "boot".into(),
        generation: 1,
        requested_target: target.clone(),
        accepted_target: target,
        status: ResourceResizeStatus {
            resource,
            requested: if resource == ResourceKind::Cpus {
                "4"
            } else {
                "512 MiB"
            }
            .into(),
            actual: "1".into(),
            enforced: "4".into(),
            state: ResourceConvergenceState::Converging,
        },
        outcome: ResizeOutcome::Pending,
        observation: ResizeObservation::Available,
    }
}

async fn delayed_memory_peer(listener: tokio::net::UnixListener, delay_pass: usize) {
    fault_peer(listener, PeerScenario::new(MemoryFault::Stall, delay_pass)).await;
}

async fn fault_peer(listener: tokio::net::UnixListener, scenario: Arc<PeerScenario>) {
    let mut peers = tokio::task::JoinSet::new();
    loop {
        let (socket, _) = tokio::select! {
            accepted = listener.accept() => accepted.unwrap(),
            Some(done) = peers.join_next(), if !peers.is_empty() => {
                done.unwrap();
                continue;
            }
        };
        let scenario = scenario.clone();
        peers.spawn(async move {
            let mut socket = BufReader::new(socket);
            match socket.fill_buf().await.unwrap().first().copied() {
                None => return,
                Some(0) => {},
                _ => {
                    let mut line = String::new();
                    socket.read_line(&mut line).await.unwrap();
                    assert_eq!(line, "{\"op\":\"capabilities\"}\n");
                    socket.write_all(b"{\"ok\":true,\"capabilities\":{\"cpu_resize\":true,\"memory_resize\":true,\"secrets_update\":false,\"resize_operations\":true},\"control_protocols\":[\"json\",\"cbor\"]}\n").await.unwrap();
                    return;
                }
            }
            let frame = codec::read_raw_frame(&mut socket).await.unwrap();
            let hello = Envelope::decode(&frame.body).unwrap().payload().unwrap();
            let welcome = ControlWelcome::negotiate(&hello, 64).unwrap();
            codec::write_raw_frame(&mut socket, &Envelope::new(1, "control.welcome", &welcome).unwrap().frame(0, 1).unwrap()).await.unwrap();
            let mut cpu_reads = 0;
            let mut memory_reads = 0;
            while let Ok(frame) = codec::read_raw_frame(&mut socket).await {
                let envelope = Envelope::decode(&frame.body).unwrap();
                if envelope.t == "control.pause.state" {
                    let state = microsandbox_protocol::control::PauseState {
                        paused: false,
                        recovery_required: false,
                        capture_unavailable: None,
                    };
                    codec::write_raw_frame(&mut socket, &Envelope::new(2, "control.pause.state", &state).unwrap().frame(frame.id, 1).unwrap()).await.unwrap();
                    continue;
                }
                assert_eq!(envelope.t, microsandbox_protocol::resize::RESIZE_REQUEST);
                let ResizeRequest::Read { id, .. } = envelope.payload().unwrap() else {
                    panic!("unexpected request {}", envelope.t);
                };
                let mut operation = if id == "cpu" {
                    cpu_reads += 1;
                    let mut operation = recorded(ResourceKind::Cpus);
                    operation.status.actual = cpu_reads.to_string();
                    operation
                } else {
                    memory_reads += 1;
                    let mut operation = recorded(ResourceKind::Memory);
                    if memory_reads == scenario.trigger_read && !*scenario.recovered.borrow() {
                        scenario.reached.notify_one();
                        match scenario.fault {
                            MemoryFault::Stall => {
                                // Cancellation must not undo the accepted operation. A released
                                // delayed reply also must not poison a later wait on this client.
                                let mut recovery = scenario.recovered.subscribe();
                                recovery.wait_for(|recovered| *recovered).await.unwrap();
                            }
                            MemoryFault::Disconnect => return,
                            MemoryFault::WrongGeneration => operation.generation += 1,
                            MemoryFault::ContradictoryCompletion => {
                                operation.outcome = ResizeOutcome::Applied;
                                operation.observation = ResizeObservation::Unavailable;
                            }
                        }
                    }
                    operation
                };
                if *scenario.recovered.borrow() {
                    operation.outcome = ResizeOutcome::Applied;
                    operation.observation = ResizeObservation::Available;
                    operation.status.state = ResourceConvergenceState::Applied;
                    operation.status.actual = operation.status.requested.clone();
                    operation.status.enforced = operation.status.requested.clone();
                }
                operation.id = id;
                let reply = ResizeResponse {
                    tracking: ResizeTracking { runtime_boot_id: "boot".into(), max_retained: 256 },
                    operations: vec![operation],
                };
                codec::write_raw_frame(&mut socket, &Envelope::new(2, microsandbox_protocol::resize::RESIZE_RESPONSE, &reply).unwrap().frame(frame.id, 1).unwrap()).await.unwrap();
            }
        });
    }
}

async fn fixture() -> (
    tempfile::TempDir,
    Arc<dyn Backend>,
    sandbox::Model,
    tokio::net::UnixListener,
) {
    let home = tempfile::Builder::new()
        .prefix("msb-rsz-")
        .tempdir_in("/tmp")
        .unwrap();
    let local = Arc::new(
        crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap(),
    );
    let pools = local.db().await.unwrap();
    let mut config = crate::SandboxConfig::default();
    config.spec.name = "resize-wait".into();
    let config = serde_json::to_string(&config).unwrap();
    let sandbox = sandbox::ActiveModel {
        name: Set("resize-wait".into()),
        config: Set(config.clone()),
        active_config: Set(Some(config)),
        status: Set(sandbox::SandboxStatus::Running),
        ephemeral: Set(false),
        ..Default::default()
    }
    .insert(pools.write())
    .await
    .unwrap();
    run::ActiveModel {
        sandbox_id: Set(sandbox.id),
        pid: Set(Some(std::process::id() as i32)),
        status: Set(run::RunStatus::Running),
        ..Default::default()
    }
    .insert(pools.write())
    .await
    .unwrap();
    let paths = RuntimeSocketPaths::new(&local.config().run_dir(), "resize-wait");
    std::fs::create_dir_all(paths.control.parent().unwrap()).unwrap();
    let listener = tokio::net::UnixListener::bind(paths.control).unwrap();
    (home, local, sandbox, listener)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn timeout_keeps_each_completed_resource_reply() {
    for (delay_pass, check_once, expected_cpu_reads, expected_statuses) in [
        (1, false, 1, 1),
        (2, false, 2, 2),
        (1, true, 1, 1),
        // Both resources reply Pending. A single check must return immediately,
        // rather than use the remaining transport budget for additional polls.
        (3, true, 1, 2),
    ] {
        let (_home, backend, sandbox, listener) = fixture().await;
        let peer = tokio::spawn(delayed_memory_peer(listener, delay_pass));
        let identity = SandboxIdentity::Local(sandbox.id);
        // Warm identity discovery before the deliberate response-delay deadline.
        open_session(&backend, "resize-wait", &identity)
            .await
            .unwrap();
        let selected = [recorded(ResourceKind::Cpus), recorded(ResourceKind::Memory)];
        let result = if check_once {
            let handle = super::super::SandboxHandle::from_local_model(backend, sandbox, None);
            handle
                .check_resize_operations_with_budget(Some(&selected), Duration::from_secs(2))
                .await
        } else {
            wait_for_operations(
                &backend,
                "resize-wait",
                &identity,
                Some(&selected),
                Some(Duration::from_secs(2)),
            )
            .await
        };
        peer.abort();
        if let Err(error) = peer.await {
            assert!(error.is_cancelled(), "peer failed: {error}");
        }
        let Err(MicrosandboxError::ResizeTimeout {
            status, timeout, ..
        }) = result
        else {
            panic!("expected response timeout, got {result:?}");
        };
        assert_eq!(
            status.len(),
            expected_statuses,
            "retain only replies actually received"
        );
        assert_eq!(status[0].resource, ResourceKind::Cpus);
        assert_eq!(status[0].actual, expected_cpu_reads.to_string());
        assert_eq!(
            timeout,
            if check_once {
                Duration::ZERO
            } else {
                Duration::from_secs(2)
            }
        );
        if expected_statuses == 2 {
            assert_eq!(status[1].resource, ResourceKind::Memory);
            assert_eq!(status[1].actual, "1");
        }
    }
}

#[tokio::test]
async fn read_faults_preserve_validated_progress_and_allow_exact_operation_reconnect() {
    for fault in [
        MemoryFault::Disconnect,
        MemoryFault::WrongGeneration,
        MemoryFault::ContradictoryCompletion,
    ] {
        for pass in [1, 2] {
            let (_home, backend, sandbox, listener) = fixture().await;
            let scenario = PeerScenario::new(fault, pass);
            let peer = tokio::spawn(fault_peer(listener, scenario.clone()));
            let identity = SandboxIdentity::Local(sandbox.id);
            let selected = [recorded(ResourceKind::Cpus), recorded(ResourceKind::Memory)];
            let result = wait_for_operations(
                &backend,
                "resize-wait",
                &identity,
                Some(&selected),
                Some(Duration::from_secs(5)),
            )
            .await;
            let Err(MicrosandboxError::ResizeWait(failure)) = result else {
                panic!("expected structured observation failure, got {result:?}");
            };
            assert_eq!(
                failure.reason,
                match fault {
                    MemoryFault::Disconnect => ResizeWaitFailure::ObservationUnavailable,
                    _ => ResizeWaitFailure::InvalidResponse,
                }
            );
            assert_eq!(failure.operation_id.as_deref(), Some("memory"));
            assert_eq!(failure.sandbox.as_deref(), Some("resize-wait"));
            assert!(failure.cause.is_some());
            assert_eq!(failure.status.len(), pass);
            assert_eq!(failure.status[0].actual, pass.to_string());
            assert_eq!(failure.status[0].resource, ResourceKind::Cpus);
            if pass == 2 {
                // The malformed/disconnected read must not replace the preceding
                // validated memory observation with an invented completion.
                assert_eq!(failure.status[1].actual, "1");
                assert_eq!(
                    failure.status[1].state,
                    ResourceConvergenceState::Converging
                );
            }
            scenario.recover();
            let status = wait_for_operations(
                &backend,
                "resize-wait",
                &identity,
                Some(&selected),
                Some(Duration::from_secs(5)),
            )
            .await
            .unwrap();
            assert_eq!(status.len(), 2);
            assert!(
                status
                    .iter()
                    .all(|v| v.state == ResourceConvergenceState::Applied)
            );
            peer.abort();
            if let Err(error) = peer.await {
                assert!(error.is_cancelled(), "peer failed: {error}");
            }
        }
    }
}

#[tokio::test]
async fn cancelled_wait_does_not_replay_mutation_or_poison_later_exact_wait() {
    let (_home, backend, sandbox, listener) = fixture().await;
    let scenario = PeerScenario::new(MemoryFault::Stall, 1);
    let peer = tokio::spawn(fault_peer(listener, scenario.clone()));
    let identity = SandboxIdentity::Local(sandbox.id);
    let selected = [recorded(ResourceKind::Cpus), recorded(ResourceKind::Memory)];
    {
        let wait = wait_for_operations(&backend, "resize-wait", &identity, Some(&selected), None);
        tokio::pin!(wait);
        tokio::select! {
            result = &mut wait => panic!("wait finished before cancellation: {result:?}"),
            _ = scenario.reached.notified() => {},
            _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("peer never received memory read"),
        }
        // Drop the actual SDK future while a read is in flight. No timeout response
        // or peer terminal outcome authorizes undoing the accepted target.
    }
    scenario.recover();
    let status = wait_for_operations(
        &backend,
        "resize-wait",
        &identity,
        Some(&selected),
        Some(Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert_eq!(status.len(), 2);
    assert!(
        status
            .iter()
            .all(|v| v.state == ResourceConvergenceState::Applied)
    );
    peer.abort();
    if let Err(error) = peer.await {
        assert!(error.is_cancelled(), "peer failed: {error}");
    }
}
