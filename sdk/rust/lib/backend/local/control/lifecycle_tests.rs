//! Opt-in runtime replacement tests using actual process and socket identities.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use futures::FutureExt;
use microsandbox_control_client::{
    ControlClientError, ControlClientResult, ControlConnection, ControlMode, Delivery, ErrorKind,
    GetCpuState, JsonControlClient, SetCpuTarget, VerifiedControlConnector,
};
use microsandbox_protocol_client::{BoxFuture, BoxTransport};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::backend::LocalBackend;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct PausedOwner {
    owner: Arc<dyn VerifiedControlConnector>,
    pause_at: usize,
    attempts: AtomicUsize,
    completed: AtomicUsize,
    reached: Notify,
    release: Notify,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl VerifiedControlConnector for PausedOwner {
    fn connect(&self, deadline: Instant) -> BoxFuture<'_, ControlClientResult<BoxTransport>> {
        Box::pin(async move {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt == self.pause_at {
                self.reached.notify_one();
                self.release.notified().await;
            }
            // Only scheduling is controlled here. The original SDK owner
            // performs every database, process-birth, and peer-credential check.
            let stream = self.owner.connect(deadline).await?;
            self.completed.fetch_add(1, Ordering::SeqCst);
            Ok(stream)
        })
    }

    fn verify_session(&self, deadline: Instant) -> BoxFuture<'_, ControlClientResult<()>> {
        self.owner.verify_session(deadline)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a stopped disposable framed-control VM with two possible CPUs, MSB_PATH, MSB_LIBKRUNFW_PATH, and MSB_CONTROL_TEST_HOME/NAME"]
async fn live_replacement_before_discovery_and_between_probe_and_hello() {
    let home = std::env::var("MSB_CONTROL_TEST_HOME").unwrap();
    let name = std::env::var("MSB_CONTROL_TEST_NAME").unwrap();
    let local = Arc::new(LocalBackend::builder().home(home).build().await.unwrap());
    let backend: Arc<dyn crate::backend::Backend> = local.clone();
    crate::backend::with_backend(backend, async {
        for (pause_at, phase) in [(1, "before discovery"), (2, "between probe and hello")] {
            let mut pending = None;
            let result = std::panic::AssertUnwindSafe(async {
                crate::Sandbox::get(&name)
                    .await
                    .unwrap()
                    .start_detached()
                    .await
                    .unwrap();
                let stale = local.control_session(&name).await.unwrap().unwrap();
                let previous = stale.entry.key;
                let endpoints =
                    crate::runtime::sandbox_agent_socket_path_candidates_for(&local, &name);
                let gate = Arc::new(PausedOwner {
                    owner: stale.entry.connector.clone(),
                    pause_at,
                    attempts: AtomicUsize::new(0),
                    completed: AtomicUsize::new(0),
                    reached: Notify::new(),
                    release: Notify::new(),
                });
                let dialer = gate.clone();
                // Keep a mutation queued behind setup to prove failure cannot
                // replay it into the replacement after reusing the same path.
                pending = Some(tokio::spawn(async move {
                    let connection = ControlConnection::connect_verified_connector_with(
                        dialer,
                        |options| options.setup_timeout(Duration::from_secs(60)),
                    )
                    .await?;
                    let response = connection.request_typed(&SetCpuTarget::new(2)).await;
                    connection.close().await;
                    response
                }));
                tokio::time::timeout(Duration::from_secs(10), gate.reached.notified())
                    .await
                    .expect("setup reached the chosen replacement boundary");
                assert_eq!(gate.completed.load(Ordering::SeqCst), pause_at - 1);

                crate::Sandbox::get(&name).await.unwrap().stop().await.unwrap();
                crate::Sandbox::get(&name)
                    .await
                    .unwrap()
                    .start_detached()
                    .await
                    .unwrap();
                let current = local.control_session(&name).await.unwrap().unwrap();
                assert_ne!(previous.run_id, current.entry.key.run_id);
                assert_ne!(previous.pid, current.entry.key.pid);
                assert_eq!(
                    endpoints,
                    crate::runtime::sandbox_agent_socket_path_candidates_for(&local, &name)
                );
                let before = current.request(&GetCpuState).await.unwrap();
                assert_eq!(before.requested_online, 1, "fixture must start with one CPU");
                assert!(before.possible >= 2);
                gate.release.notify_one();
                let error = pending.take().unwrap().await.unwrap().unwrap_err();
                assert!(matches!(error, ControlClientError::RuntimeChanged), "{error:?}");
                assert_eq!(error.delivery(), Delivery::NotSent);
                assert_eq!(gate.attempts.load(Ordering::SeqCst), pause_at);
                assert_eq!(gate.completed.load(Ordering::SeqCst), pause_at - 1);
                assert_eq!(
                    current.request(&GetCpuState).await.unwrap().requested_online,
                    before.requested_online
                );

                // Deliver an old registry lookup after the replacement has a
                // healthy session. It must not retire the replacement's entry.
                let error = local
                    .control_sessions
                    .get(previous, stale.entry.connector.clone())
                    .await
                    .err()
                    .unwrap();
                assert!(matches!(&*error, ControlClientError::RuntimeChanged));
                assert!(!current.entry.invalidated.is_cancelled());
                let reused = local.control_session(&name).await.unwrap().unwrap();
                assert!(Arc::ptr_eq(&current.entry, &reused.entry));
                assert_eq!(
                    current.request(&SetCpuTarget::new(2)).await.unwrap().requested_online,
                    2
                );
                current.request(&SetCpuTarget::new(1)).await.unwrap();
                println!(
                    "{phase}: run {} / PID {} -> run {} / PID {}; completed old-owner dials {}; stale mutation NotSent; current session reused and target restored",
                    previous.run_id,
                    previous.pid,
                    current.entry.key.run_id,
                    current.entry.key.pid,
                    gate.completed.load(Ordering::SeqCst),
                );
            })
            .catch_unwind()
            .await;
            if let Some(pending) = pending {
                pending.abort();
                let _ = pending.await;
            }
            // Resolve the current run independently so cleanup also covers a
            // failure after stop but before successful replacement setup.
            crate::Sandbox::get(&name)
                .await
                .unwrap()
                .stop()
                .await
                .expect("stop current disposable fixture");
            result.unwrap();
        }
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an already-running disposable historical JSON VM with one CPU/two possible, candidate MSB_PATH/MSB_LIBKRUNFW_PATH, and MSB_CONTROL_TEST_HOME/NAME; back up the historical DB before current SDK access"]
async fn live_historical_json_replacement_before_a_fresh_send() {
    let home = std::env::var("MSB_CONTROL_TEST_HOME").unwrap();
    let name = std::env::var("MSB_CONTROL_TEST_NAME").unwrap();
    let local = Arc::new(LocalBackend::builder().home(home).build().await.unwrap());
    let backend: Arc<dyn crate::backend::Backend> = local.clone();
    crate::backend::with_backend(backend, async {
        let mut pending = None;
        let result = std::panic::AssertUnwindSafe(async {
            let stale = local.control_session(&name).await.unwrap().unwrap();
            assert_eq!(stale.mode(), ControlMode::Json);
            let previous = stale.entry.key;
            let old_endpoint =
                crate::runtime::sandbox_agent_socket_path_candidates_for(&local, &name)
                    .iter()
                    .map(|path| microsandbox_runtime::control::control_socket_path_for(path))
                    .find(|path| path.exists())
                    .expect("historical control endpoint");
            let gate = Arc::new(PausedOwner {
                owner: stale.entry.connector.clone(),
                pause_at: 2,
                attempts: AtomicUsize::new(0),
                completed: AtomicUsize::new(0),
                reached: Notify::new(),
                release: Notify::new(),
            });
            let connection = ControlConnection::connect_verified_connector_with(
                gate.clone(),
                |options| options.setup_timeout(Duration::from_secs(60)),
            )
            .await
            .unwrap();
            assert_eq!(connection.mode(), ControlMode::Json);
            assert_eq!(gate.completed.load(Ordering::SeqCst), 1);
            let active = connection.clone();
            pending = Some(tokio::spawn(async move {
                active
                    .request_typed_with(&SetCpuTarget::new(2), |options| {
                        options.request_timeout(Duration::from_secs(60))
                    })
                    .await
            }));
            tokio::time::timeout(Duration::from_secs(10), gate.reached.notified())
                .await
                .expect("JSON mutation reached the fresh-dial boundary");

            // The old SDK/CLI already launched the historical process. Replace
            // it through a current SDK/candidate launch without adapting the
            // known-incompatible old launch contract or rolling back its DB.
            crate::Sandbox::get(&name).await.unwrap().stop().await.unwrap();
            crate::Sandbox::get(&name)
                .await
                .unwrap()
                .start_detached()
                .await
                .unwrap();
            let current = local.control_session(&name).await.unwrap().unwrap();
            assert_eq!(current.mode(), ControlMode::Framed);
            assert_ne!(previous.run_id, current.entry.key.run_id);
            assert_ne!(previous.pid, current.entry.key.pid);

            // Prove that the exact old pathname now reaches the new runtime,
            // including when it is the published legacy compatibility link.
            let peer = tokio::net::UnixStream::connect(&old_endpoint).await.unwrap();
            assert_eq!(peer.peer_cred().unwrap().pid(), Some(current.entry.key.pid));
            drop(peer);
            let before = JsonControlClient::new(&old_endpoint)
                .request_typed(&GetCpuState)
                .await
                .unwrap();
            assert_eq!(before.requested_online, 1);
            assert!(before.possible >= 2);

            gate.release.notify_one();
            let error = pending.take().unwrap().await.unwrap().unwrap_err();
            assert!(matches!(error, ControlClientError::RuntimeChanged), "{error:?}");
            assert_eq!(error.delivery(), Delivery::NotSent);
            assert_eq!(gate.attempts.load(Ordering::SeqCst), 2);
            assert_eq!(gate.completed.load(Ordering::SeqCst), 1);
            assert!(connection.is_closed());
            let error = connection.request_typed(&SetCpuTarget::new(2)).await.unwrap_err();
            assert!(matches!(&error, ControlClientError::Client(error) if error.kind == ErrorKind::Closed));
            assert_eq!(error.delivery(), Delivery::NotSent);
            assert_eq!(gate.attempts.load(Ordering::SeqCst), 2);
            assert_eq!(
                current.request(&GetCpuState).await.unwrap().requested_online,
                before.requested_online
            );
            assert_eq!(
                current.request(&SetCpuTarget::new(2)).await.unwrap().requested_online,
                2
            );
            current.request(&SetCpuTarget::new(1)).await.unwrap();
            println!(
                "before fresh JSON send: run {} / PID {} / JSON -> run {} / PID {} / framed; same endpoint {}; stale mutation RuntimeChanged/NotSent; closed handle made no new dial; replacement unchanged and fresh mutation restored",
                previous.run_id,
                previous.pid,
                current.entry.key.run_id,
                current.entry.key.pid,
                old_endpoint.display(),
            );
        })
        .catch_unwind()
        .await;
        if let Some(pending) = pending {
            pending.abort();
            let _ = pending.await;
        }
        crate::Sandbox::get(&name)
            .await
            .unwrap()
            .stop()
            .await
            .expect("stop disposable historical or replacement fixture");
        result.unwrap();
    })
    .await;
}
