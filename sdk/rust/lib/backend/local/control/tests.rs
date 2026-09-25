//! Kernel identity and actual shared-connection tests; no VM is needed here.

use super::identity::DatabaseIdentity;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn database_identity_detects_replacement_but_not_ordinary_writes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("database");
    std::fs::write(&path, b"original").unwrap();
    let identity = DatabaseIdentity::capture(&path).unwrap();
    std::fs::write(&path, b"updated contents").unwrap();
    identity.verify().unwrap();
    std::fs::rename(&path, directory.path().join("old")).unwrap();
    std::fs::write(&path, b"replacement").unwrap();
    assert!(matches!(
        identity.verify(),
        Err(microsandbox_control_client::ControlClientError::RuntimeChanged)
    ));
}

#[cfg(unix)]
mod unix {
    use futures::FutureExt;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use microsandbox_control_client::{
        ControlClientError, ControlClientResult, ControlWelcome, Delivery, ErrorKind,
        GetCapabilities, VerifiedControlConnector,
    };
    use microsandbox_db::entity::{run, sandbox};
    use microsandbox_protocol::{codec, wire::Envelope};
    use microsandbox_protocol_client::{BoxFuture, BoxTransport};
    use sea_orm::{ActiveModelTrait, EntityTrait, Set};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::sync::Notify;
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;

    use super::super::identity::{ProcessIdentity, ProcessStart};
    use super::super::registry::{ControlSessions, RuntimeKey};
    use crate::backend::LocalBackend;

    //--------------------------------------------------------------------------------------------------
    // Types
    //--------------------------------------------------------------------------------------------------

    struct GatedConnector {
        dials: AtomicUsize,
        blocked: AtomicBool,
        valid: AtomicBool,
        started: Notify,
        gate: Notify,
        peer_closed: Notify,
    }

    struct Fixture {
        root: tempfile::TempDir,
        backend: Arc<LocalBackend>,
        sandbox_id: i32,
        run_id: i32,
        probes: Arc<AtomicUsize>,
        frames: Arc<AtomicUsize>,
        disconnect: CancellationToken,
        listener: tokio::task::JoinHandle<()>,
    }

    //--------------------------------------------------------------------------------------------------
    // Methods
    //--------------------------------------------------------------------------------------------------

    impl GatedConnector {
        fn new(blocked: bool) -> Arc<Self> {
            Arc::new(Self {
                dials: AtomicUsize::new(0),
                blocked: AtomicBool::new(blocked),
                valid: AtomicBool::new(true),
                started: Notify::new(),
                gate: Notify::new(),
                peer_closed: Notify::new(),
            })
        }
        fn release(&self) {
            self.blocked.store(false, Ordering::SeqCst);
            self.gate.notify_waiters();
        }
    }

    //--------------------------------------------------------------------------------------------------
    // Trait Implementations
    //--------------------------------------------------------------------------------------------------

    impl VerifiedControlConnector for GatedConnector {
        fn connect(&self, deadline: Instant) -> BoxFuture<'_, ControlClientResult<BoxTransport>> {
            Box::pin(async move {
                self.verify_session(deadline).await?;
                self.dials.fetch_add(1, Ordering::SeqCst);
                self.started.notify_one();
                struct Cancel<'a>(&'a Notify);
                impl Drop for Cancel<'_> {
                    fn drop(&mut self) {
                        self.0.notify_one();
                    }
                }
                let _cancel = Cancel(&self.peer_closed);
                while self.blocked.load(Ordering::SeqCst) {
                    self.gate.notified().await;
                }
                // A verified connector must reject replacement during a dial
                // as well as before it, just like the production runtime owner.
                self.verify_session(deadline).await?;
                let (client, mut peer) = tokio::io::duplex(4096);
                tokio::spawn(async move {
                    let mut line = String::new();
                    BufReader::new(&mut peer)
                        .read_line(&mut line)
                        .await
                        .unwrap();
                    let _ = peer.write_all(b"{\"ok\":true,\"capabilities\":{\"cpu_resize\":true,\"memory_resize\":true,\"secrets_update\":false}}\n").await;
                });
                Ok(Box::new(client) as BoxTransport)
            })
        }
        fn verify_session(&self, _: Instant) -> BoxFuture<'_, ControlClientResult<()>> {
            Box::pin(async move {
                if self.valid.load(Ordering::SeqCst) {
                    Ok(())
                } else {
                    Err(ControlClientError::RuntimeChanged)
                }
            })
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.disconnect.cancel();
            self.listener.abort();
        }
    }

    //--------------------------------------------------------------------------------------------------
    // Functions
    //--------------------------------------------------------------------------------------------------

    fn key(sandbox_id: i32) -> RuntimeKey {
        RuntimeKey {
            sandbox_id,
            run_id: 1,
            pid: 1,
            start: ProcessStart(1, 1),
        }
    }

    async fn fixture(legacy: bool, stale: bool) -> Fixture {
        let root = tempfile::Builder::new()
            .prefix("msb-reg-")
            .tempdir_in("/tmp")
            .unwrap();
        let backend = Arc::new(crate::test_support::local_backend(
            crate::config::GlobalConfig {
                home: Some(root.path().to_path_buf()),
                ..Default::default()
            },
        ));
        let pools = backend.db().await.unwrap();
        let mut config = crate::SandboxConfig::default();
        config.spec.name = "control-fixture".into();
        let config = serde_json::to_string(&config).unwrap();
        let sandbox = sandbox::ActiveModel {
            name: Set("control-fixture".into()),
            config: Set(config.clone()),
            active_config: Set(Some(config)),
            status: Set(sandbox::SandboxStatus::Running),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();
        let run = run::ActiveModel {
            sandbox_id: Set(sandbox.id),
            pid: Set(Some(std::process::id() as i32)),
            status: Set(run::RunStatus::Running),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();
        let paths = microsandbox_runtime::ipc::sandbox_socket_paths(
            &backend.config().run_dir(),
            "control-fixture",
        );
        let endpoint = if legacy {
            paths.legacy_control.clone()
        } else {
            paths.control.clone()
        };
        std::fs::create_dir_all(endpoint.parent().unwrap()).unwrap();
        if stale {
            std::fs::create_dir_all(&paths.canonical_dir).unwrap();
            drop(tokio::net::UnixListener::bind(paths.control).unwrap());
        }
        let listener = tokio::net::UnixListener::bind(endpoint).unwrap();
        let probes = Arc::new(AtomicUsize::new(0));
        let frames = Arc::new(AtomicUsize::new(0));
        let counted_probes = probes.clone();
        let counted_frames = frames.clone();
        let disconnect = CancellationToken::new();
        let peer_disconnect = disconnect.clone();
        let task = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let probes = counted_probes.clone();
                let frames = counted_frames.clone();
                let disconnect = peer_disconnect.clone();
                tokio::spawn(async move {
                    let mut socket = BufReader::new(socket);
                    let first = socket.fill_buf().await.unwrap().first().copied();
                    if first.is_none() {
                        return;
                    }
                    if first != Some(0) {
                        let mut line = String::new();
                        socket.read_line(&mut line).await.unwrap();
                        assert_eq!(line, "{\"op\":\"capabilities\"}\n");
                        probes.fetch_add(1, Ordering::SeqCst);
                        let protocols = if legacy {
                            ""
                        } else {
                            ",\"control_protocols\":[\"json\",\"cbor\"]"
                        };
                        let reply = format!(
                            "{{\"ok\":true,\"capabilities\":{{\"cpu_resize\":true,\"memory_resize\":true,\"secrets_update\":false}}{protocols}}}\n"
                        );
                        socket.get_mut().write_all(reply.as_bytes()).await.unwrap();
                    } else {
                        let hello = codec::read_raw_frame(&mut socket).await.unwrap();
                        let hello = Envelope::decode(&hello.body).unwrap().payload().unwrap();
                        let welcome = ControlWelcome::negotiate(&hello, 64).unwrap();
                        codec::write_raw_frame(
                            socket.get_mut(),
                            &Envelope::new(1, "control.welcome", &welcome)
                                .unwrap()
                                .frame(0, 1)
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                        loop {
                            let frame = tokio::select! {
                                _ = disconnect.cancelled() => break,
                                frame = codec::read_raw_frame(&mut socket) => match frame {
                                    Ok(frame) => frame,
                                    Err(_) => break,
                                },
                            };
                            frames.fetch_add(1, Ordering::SeqCst);
                            let request = Envelope::decode(&frame.body).unwrap();
                            assert_eq!(request.t, "control.capabilities");
                            let caps = microsandbox_protocol::control::Capabilities {
                                root_disk_grow: false,
                                cpu_resize: true,
                                memory_resize: true,
                                secrets_update: false,
                            };
                            let _ = codec::write_raw_frame(
                                socket.get_mut(),
                                &Envelope::new(1, "control.capabilities.result", &caps)
                                    .unwrap()
                                    .frame(frame.id, 1)
                                    .unwrap(),
                            )
                            .await;
                        }
                    }
                });
            }
        });
        Fixture {
            root,
            backend,
            sandbox_id: sandbox.id,
            run_id: run.id,
            probes,
            frames,
            disconnect,
            listener: task,
        }
    }

    //--------------------------------------------------------------------------------------------------
    // Tests
    //--------------------------------------------------------------------------------------------------

    #[tokio::test]
    async fn shared_setup_survives_one_cancelled_waiter() {
        let registry = Arc::new(ControlSessions::default());
        let connector = GatedConnector::new(true);
        let mut waiters = Vec::new();
        for _ in 0..12 {
            let registry = registry.clone();
            let connector = connector.clone();
            waiters.push(tokio::spawn(async move {
                registry.get(key(1), connector).await
            }));
        }
        connector.started.notified().await;
        tokio::task::yield_now().await;
        waiters.pop().unwrap().abort();
        connector.release();
        for waiter in waiters {
            assert!(waiter.await.unwrap().is_ok());
        }
        assert_eq!(connector.dials.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn last_cancelled_waiter_cancels_setup_and_a_later_operation_starts_fresh() {
        let registry = Arc::new(ControlSessions::default());
        let connector = GatedConnector::new(true);
        let other = registry.clone();
        let dialer = connector.clone();
        let waiter = tokio::spawn(async move { other.get(key(1), dialer).await });
        connector.started.notified().await;
        waiter.abort();
        let _ = waiter.await;
        tokio::time::timeout(Duration::from_secs(1), connector.peer_closed.notified())
            .await
            .unwrap();
        connector.release();
        registry.get(key(1), connector.clone()).await.unwrap();
        assert_eq!(connector.dials.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn capacity_never_evicts_a_valid_session_and_invalid_entries_are_reclaimed() {
        let registry = ControlSessions::with_limit(1);
        let first = GatedConnector::new(false);
        let handle = registry.get(key(1), first.clone()).await.unwrap();
        let next = GatedConnector::new(false);
        let error = registry.get(key(2), next.clone()).await.err().unwrap();
        assert!(
            matches!(&*error, ControlClientError::Client(error) if error.kind == ErrorKind::Capacity)
        );
        assert_eq!(next.dials.load(Ordering::SeqCst), 0);
        first.valid.store(false, Ordering::SeqCst);
        registry.get(key(2), next.clone()).await.unwrap();
        let error = handle.request(&GetCapabilities).await.unwrap_err();
        assert!(matches!(&*error, ControlClientError::RuntimeChanged));
        assert_eq!(error.delivery(), Delivery::NotSent);
    }

    #[tokio::test]
    async fn delayed_old_run_lookup_does_not_cancel_the_current_run_or_its_waiters() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let registry = ControlSessions::default();
            let current = GatedConnector::new(false);
            let current_key = RuntimeKey {
                run_id: 2,
                ..key(1)
            };
            let session = registry.get(current_key, current.clone()).await.unwrap();
            current.started.notified().await;

            // An operation is already waiting for a fresh JSON connection to
            // the current run. A delayed lookup still carries the previous
            // run key captured before the runtime was replaced.
            current.blocked.store(true, Ordering::SeqCst);
            let active = session.clone();
            let pending = tokio::spawn(async move { active.request(&GetCapabilities).await });
            current.started.notified().await;
            let previous = GatedConnector::new(false);
            previous.valid.store(false, Ordering::SeqCst);
            let error = registry.get(key(1), previous).await.err().unwrap();
            assert!(matches!(&*error, ControlClientError::RuntimeChanged));
            assert!(!session.entry.invalidated.is_cancelled());

            current.release();
            assert!(pending.await.unwrap().unwrap().cpu_resize);
            let reused = registry.get(current_key, current.clone()).await.unwrap();
            assert!(Arc::ptr_eq(&session.entry, &reused.entry));
            assert_eq!(current.dials.load(Ordering::SeqCst), 2);
        })
        .await
        .expect("delayed lookup regression deadline");
    }

    #[tokio::test]
    async fn delayed_old_run_lookup_does_not_cancel_current_setup() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let registry = Arc::new(ControlSessions::default());
            let current = GatedConnector::new(true);
            let current_key = RuntimeKey {
                run_id: 2,
                ..key(1)
            };
            let owner = registry.clone();
            let dialer = current.clone();
            let pending = tokio::spawn(async move { owner.get(current_key, dialer).await });
            current.started.notified().await;

            // Keep the current run's discovery suspended while the obsolete
            // caller arrives, then prove that the original setup still wins.
            let previous = GatedConnector::new(false);
            previous.valid.store(false, Ordering::SeqCst);
            let error = registry.get(key(1), previous.clone()).await.err().unwrap();
            assert!(matches!(&*error, ControlClientError::RuntimeChanged));
            assert_eq!(previous.dials.load(Ordering::SeqCst), 0);

            current.release();
            let session = pending.await.unwrap().unwrap();
            let reused = registry.get(current_key, current.clone()).await.unwrap();
            assert!(Arc::ptr_eq(&session.entry, &reused.entry));
            assert_eq!(current.dials.load(Ordering::SeqCst), 1);
        })
        .await
        .expect("delayed lookup during setup deadline");
    }

    #[tokio::test]
    async fn verified_dead_run_is_reclaimed_for_its_replacement_at_capacity() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let registry = ControlSessions::with_limit(1);
            let previous = GatedConnector::new(false);
            let stale = registry.get(key(1), previous.clone()).await.unwrap();
            previous.valid.store(false, Ordering::SeqCst);

            let current = GatedConnector::new(false);
            let current_key = RuntimeKey {
                run_id: 2,
                ..key(1)
            };
            let session = registry.get(current_key, current.clone()).await.unwrap();
            assert!(stale.entry.invalidated.is_cancelled());
            let error = stale.request(&GetCapabilities).await.unwrap_err();
            assert!(matches!(&*error, ControlClientError::RuntimeChanged));
            assert_eq!(error.delivery(), Delivery::NotSent);
            assert_eq!(previous.dials.load(Ordering::SeqCst), 1);
            assert!(session.request(&GetCapabilities).await.unwrap().cpu_resize);
        })
        .await
        .expect("replacement at capacity deadline");
    }

    #[tokio::test]
    async fn real_legacy_peer_and_stale_canonical_path_use_verified_fresh_json_connections() {
        let fixture = fixture(true, true).await;
        for _ in 0..3 {
            let session = fixture
                .backend
                .control_session("control-fixture")
                .await
                .unwrap()
                .unwrap();
            assert!(session.request(&GetCapabilities).await.unwrap().cpu_resize);
        }
        assert_eq!(fixture.probes.load(Ordering::SeqCst), 4); // One discovery plus three operations.
    }

    #[tokio::test]
    async fn real_framed_peer_reuses_one_setup_across_temporary_sdk_handles() {
        let fixture = fixture(false, false).await;
        let mut requests = Vec::new();
        for _ in 0..16 {
            let backend = fixture.backend.clone();
            requests.push(tokio::spawn(async move {
                backend
                    .control_session("control-fixture")
                    .await
                    .unwrap()
                    .unwrap()
                    .request(&GetCapabilities)
                    .await
                    .unwrap()
            }));
        }
        for request in requests {
            assert!(request.await.unwrap().memory_resize);
        }
        assert_eq!(fixture.probes.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.frames.load(Ordering::SeqCst), 16);
    }

    #[tokio::test]
    async fn idle_framed_disconnect_releases_the_registry_entry_without_another_lookup() {
        let fixture = fixture(false, false).await;
        let session = fixture
            .backend
            .control_session("control-fixture")
            .await
            .unwrap()
            .unwrap();
        let entry = Arc::downgrade(&session.entry);
        fixture.disconnect.cancel();
        tokio::time::timeout(
            Duration::from_secs(1),
            session.entry.invalidated.cancelled(),
        )
        .await
        .unwrap();
        drop(session);
        tokio::time::timeout(Duration::from_secs(1), async {
            while entry.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn run_replacement_with_the_same_pid_invalidates_prepared_operations() {
        let fixture = fixture(false, false).await;
        let session = fixture
            .backend
            .control_session("control-fixture")
            .await
            .unwrap()
            .unwrap();
        let pools = fixture.backend.db().await.unwrap();
        run::ActiveModel {
            id: Set(fixture.run_id),
            status: Set(run::RunStatus::Terminated),
            ..Default::default()
        }
        .update(pools.write())
        .await
        .unwrap();
        run::ActiveModel {
            sandbox_id: Set(fixture.sandbox_id),
            pid: Set(Some(std::process::id() as i32)),
            status: Set(run::RunStatus::Running),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();
        let error = session.request(&GetCapabilities).await.unwrap_err();
        assert!(matches!(&*error, ControlClientError::RuntimeChanged));
        assert_eq!(fixture.frames.load(Ordering::SeqCst), 0);
        fixture
            .backend
            .control_session("control-fixture")
            .await
            .unwrap()
            .unwrap()
            .request(&GetCapabilities)
            .await
            .unwrap();
        assert_eq!(fixture.probes.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn recording_a_live_result_compares_both_the_run_and_active_snapshot_atomically() {
        let fixture = fixture(false, false).await;
        let pools = fixture.backend.db().await.unwrap();
        let registry = ControlSessions::default();
        // An affirmative verifier models the point just after OS/run validation.
        // Changes below must still be rejected by the atomic database write.
        let session = registry
            .get(
                RuntimeKey {
                    sandbox_id: fixture.sandbox_id,
                    run_id: fixture.run_id,
                    pid: std::process::id() as i32,
                    start: ProcessStart(1, 1),
                },
                GatedConnector::new(false),
            )
            .await
            .unwrap();
        let before = sandbox::Entity::find_by_id(fixture.sandbox_id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap()
            .active_config;
        let mut active: crate::SandboxConfig =
            serde_json::from_str(before.as_deref().unwrap()).unwrap();
        active.spec.resources.cpus = 2;
        let accepted = session
            .persist_active_config(pools.write(), before.as_deref(), &active)
            .await
            .unwrap();

        // A modifier holding the original snapshot cannot erase the accepted CPU
        // change while recording its independent memory change.
        active.spec.resources.memory_mib += 256;
        let error = session
            .persist_active_config(pools.write(), before.as_deref(), &active)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            crate::MicrosandboxError::ControlStateChanged
        ));

        // Even if the prior row still says Running, a newer run wins. Keeping
        // the same PID also proves the guard is not just a PID comparison.
        run::ActiveModel {
            sandbox_id: Set(fixture.sandbox_id),
            pid: Set(Some(std::process::id() as i32)),
            status: Set(run::RunStatus::Running),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();
        let error = session
            .persist_active_config(pools.write(), Some(&accepted), &active)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            crate::MicrosandboxError::ControlStateChanged
        ));
        let after = sandbox::Entity::find_by_id(fixture.sandbox_id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.active_config.as_deref(), Some(accepted.as_str()));
    }

    #[tokio::test]
    async fn connected_peer_must_match_the_recorded_runtime_pid() {
        let fixture = fixture(true, false).await;
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        run::ActiveModel {
            id: Set(fixture.run_id),
            pid: Set(Some(child.id().unwrap() as i32)),
            ..Default::default()
        }
        .update(fixture.backend.db().await.unwrap().write())
        .await
        .unwrap();
        let error = fixture
            .backend
            .control_session("control-fixture")
            .await
            .err()
            .unwrap();
        assert!(
            matches!(error, crate::MicrosandboxError::ControlClient(error) if matches!(&*error, ControlClientError::RuntimeChanged))
        );
        assert_eq!(fixture.probes.load(Ordering::SeqCst), 0);
        child.kill().await.unwrap();
    }

    #[tokio::test]
    async fn configured_homes_never_share_discovery_even_with_equal_run_keys() {
        let first = fixture(false, false).await;
        let second = fixture(false, false).await;
        assert_ne!(first.root.path(), second.root.path());
        for fixture in [&first, &second] {
            fixture
                .backend
                .control_session("control-fixture")
                .await
                .unwrap()
                .unwrap()
                .request(&GetCapabilities)
                .await
                .unwrap();
            assert_eq!(fixture.probes.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn process_birth_identity_rejects_an_exited_child() {
        let mut child = tokio::process::Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap() as i32;
        let identity = ProcessIdentity::capture(pid).unwrap();
        identity.verify().unwrap();
        child.kill().await.unwrap();
        let error = identity.verify().unwrap_err();
        assert!(
            matches!(error, ControlClientError::RuntimeChanged),
            "{error:?}"
        );
        assert_eq!(error.delivery(), Delivery::NotSent);
        let error = ProcessIdentity::capture(pid).err().unwrap();
        assert!(
            matches!(error, ControlClientError::RuntimeChanged),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn registry_drop_closes_handles_that_outlive_the_backend() {
        let registry = ControlSessions::default();
        let connector = GatedConnector::new(false);
        let session = registry.get(key(1), connector.clone()).await.unwrap();
        drop(registry);
        let error = session.request(&GetCapabilities).await.unwrap_err();
        assert!(matches!(&*error, ControlClientError::RuntimeChanged));
        assert_eq!(connector.dials.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn replacing_the_database_file_invalidates_cached_connections_before_io() {
        let fixture = fixture(false, false).await;
        let session = fixture
            .backend
            .control_session("control-fixture")
            .await
            .unwrap()
            .unwrap();
        let path = fixture
            .root
            .path()
            .join(microsandbox_utils::DB_SUBDIR)
            .join(microsandbox_utils::DB_FILENAME);
        std::fs::rename(&path, path.with_extension("original")).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        assert!(session.request(&GetCapabilities).await.is_err());
        assert!(
            fixture
                .backend
                .control_session("control-fixture")
                .await
                .is_err()
        );
        assert_eq!(fixture.frames.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn reading_discovery_capabilities_never_opens_another_json_exchange() {
        let fixture = fixture(true, false).await;
        for _ in 0..12 {
            let session = fixture
                .backend
                .control_session("control-fixture")
                .await
                .unwrap()
                .unwrap();
            assert!(session.capabilities().cpu_resize);
            assert_eq!(
                session.mode(),
                microsandbox_control_client::ControlMode::Json
            );
        }
        assert_eq!(fixture.probes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    #[ignore = "requires a running pre-control release and MSB_CONTROL_TEST_HOME/NAME"]
    async fn live_sdk_missing_control_preserves_guest_execution() {
        let home = std::env::var("MSB_CONTROL_TEST_HOME").unwrap();
        let name = std::env::var("MSB_CONTROL_TEST_NAME").unwrap();
        let local = Arc::new(LocalBackend::builder().home(home).build().await.unwrap());
        // This checks the backend's real endpoint discovery, not a fake server
        // returning disabled capabilities. The historical VM stays running.
        assert!(local.control_session(&name).await.unwrap().is_none());
        let backend: Arc<dyn crate::backend::Backend> = local;
        crate::backend::with_backend(backend, async {
            let sandbox = crate::Sandbox::get(&name)
                .await
                .unwrap()
                .connect()
                .await
                .unwrap();
            let output = sandbox
                .exec(
                    "sh",
                    ["-c", "printf no-control-exec; printf no-control-stderr >&2"],
                )
                .await
                .unwrap();
            assert!(output.status().success);
            assert_eq!(output.stdout().unwrap(), "no-control-exec");
            assert_eq!(output.stderr().unwrap(), "no-control-stderr");
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "requires an existing stopped disposable sandbox, MSB_PATH and MSB_LIBKRUNFW_PATH, plus MSB_CONTROL_TEST_HOME/NAME/MODE"]
    async fn live_sdk_launches_the_selected_runtime_and_executes() {
        let home = std::env::var("MSB_CONTROL_TEST_HOME").unwrap();
        let name = std::env::var("MSB_CONTROL_TEST_NAME").unwrap();
        let mode = std::env::var("MSB_CONTROL_TEST_MODE").unwrap();
        let local = Arc::new(LocalBackend::builder().home(home).build().await.unwrap());
        let selected = crate::setup::resolve_runtime(local.config()).unwrap();
        assert_eq!(
            selected.msb_path,
            std::path::PathBuf::from(std::env::var("MSB_PATH").unwrap())
        );
        assert_eq!(
            selected.libkrunfw_path,
            std::path::PathBuf::from(std::env::var("MSB_LIBKRUNFW_PATH").unwrap())
        );
        let backend: Arc<dyn crate::backend::Backend> = local.clone();
        crate::backend::with_backend(backend, async {
            let handle = crate::Sandbox::get(&name).await.unwrap();
            let sandbox = if std::env::var("MSB_CONTROL_TEST_ATTACHED").as_deref() == Ok("1") {
                handle.start().await
            } else {
                handle.start_detached().await
            }
            .expect("SDK launch of selected runtime");
            let result = std::panic::AssertUnwindSafe(async {
                let session = local.control_session(&name).await?;
                if mode == "none" {
                    assert!(session.is_none());
                } else {
                    let session = session.as_ref().unwrap();
                    assert_eq!(
                        session.mode(),
                        if mode == "json" {
                            microsandbox_control_client::ControlMode::Json
                        } else {
                            microsandbox_control_client::ControlMode::Framed
                        }
                    );
                }
                let output = sandbox
                    .exec(
                        "sh",
                        ["-c", "printf sdk-launch-ok; printf sdk-launch-stderr >&2"],
                    )
                    .await?;
                assert!(output.status().success);
                assert_eq!(output.stdout().unwrap(), "sdk-launch-ok");
                assert_eq!(output.stderr().unwrap(), "sdk-launch-stderr");
                if let Some(session) = session {
                    session
                        .request(&GetCapabilities)
                        .await
                        .map_err(crate::MicrosandboxError::ControlClient)?;
                }
                Ok::<(), crate::MicrosandboxError>(())
            })
            .catch_unwind()
            .await;
            // Cleanup remains a separately initiated action even on assertion
            // failure. Never replay a failed control request into another run.
            sandbox.stop().await.expect("stop launched fixture");
            result.unwrap().unwrap();
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "requires a running disposable VM with at least two possible CPUs and MSB_CONTROL_TEST_HOME/NAME"]
    async fn live_sdk_restart_does_not_retarget_a_stale_control_session() {
        let home = std::env::var("MSB_CONTROL_TEST_HOME").unwrap();
        let name = std::env::var("MSB_CONTROL_TEST_NAME").unwrap();
        let local = Arc::new(LocalBackend::builder().home(home).build().await.unwrap());
        let backend: Arc<dyn crate::backend::Backend> = local.clone();
        crate::backend::with_backend(backend, async {
            let stale = local.control_session(&name).await.unwrap().unwrap();
            let previous = stale.entry.key;
            let endpoints = crate::runtime::sandbox_agent_socket_path_candidates_for(&local, &name);
            crate::Sandbox::get(&name)
                .await
                .unwrap()
                .stop()
                .await
                .unwrap();
            let replacement = crate::Sandbox::get(&name)
                .await
                .unwrap()
                .start_detached()
                .await
                .unwrap();
            let result = std::panic::AssertUnwindSafe(async {
                let current = local.control_session(&name).await?.unwrap();
                assert_ne!(previous, current.entry.key);
                assert_ne!(previous.run_id, current.entry.key.run_id);
                assert!(!Arc::ptr_eq(&stale.entry, &current.entry));
                assert_eq!(
                    endpoints,
                    crate::runtime::sandbox_agent_socket_path_candidates_for(&local, &name)
                );
                let before = current
                    .request(&microsandbox_control_client::GetCpuState)
                    .await
                    .map_err(crate::MicrosandboxError::ControlClient)?;
                assert!(before.possible >= 2);
                let other = if before.requested_online == 1 { 2 } else { 1 };
                // The socket pathname is reused, but a prepared handle still
                // belongs to the old run. It must send nothing to its successor.
                let error = stale
                    .request(&microsandbox_control_client::SetCpuTarget::new(other))
                    .await
                    .unwrap_err();
                assert!(matches!(&*error, ControlClientError::RuntimeChanged));
                assert_eq!(error.delivery(), Delivery::NotSent);
                assert_eq!(
                    current
                        .request(&microsandbox_control_client::GetCpuState)
                        .await
                        .map_err(crate::MicrosandboxError::ControlClient)?
                        .requested_online,
                    before.requested_online
                );
                // A separately prepared operation can use the new run, and
                // its accepted mutation is explicitly restored before cleanup.
                let accepted = current
                    .request(&microsandbox_control_client::SetCpuTarget::new(other))
                    .await
                    .map_err(crate::MicrosandboxError::ControlClient)?;
                assert_eq!(accepted.requested_online, other);
                current
                    .request(&microsandbox_control_client::SetCpuTarget::new(
                        before.requested_online,
                    ))
                    .await
                    .map_err(crate::MicrosandboxError::ControlClient)?;
                println!(
                    "control restart: run {} / PID {} -> run {} / PID {}; stale delivery NotSent",
                    previous.run_id, previous.pid, current.entry.key.run_id, current.entry.key.pid
                );
                Ok::<(), crate::MicrosandboxError>(())
            })
            .catch_unwind()
            .await;
            replacement.stop().await.expect("stop replacement fixture");
            result.unwrap().unwrap();
        })
        .await;
    }

    #[tokio::test]
    #[ignore = "requires MSB_CONTROL_TEST_HOME, MSB_CONTROL_TEST_NAME, MSB_CONTROL_TEST_MODE for a disposable running VM"]
    async fn live_sdk_modification_uses_verified_control_and_restores_resources() {
        let home = std::env::var("MSB_CONTROL_TEST_HOME").unwrap();
        let name = std::env::var("MSB_CONTROL_TEST_NAME").unwrap();
        let mode = std::env::var("MSB_CONTROL_TEST_MODE").unwrap();
        let local = Arc::new(LocalBackend::builder().home(home).build().await.unwrap());
        let connection = local.control_session(&name).await.unwrap().unwrap();
        assert_eq!(
            connection.mode(),
            if mode == "json" {
                microsandbox_control_client::ControlMode::Json
            } else {
                microsandbox_control_client::ControlMode::Framed
            }
        );
        let backend: Arc<dyn crate::backend::Backend> = local;
        crate::backend::with_backend(backend, async {
            let sandbox = crate::Sandbox::get(&name).await.unwrap();
            let before = sandbox.config().unwrap();
            let active = sandbox.active_config().unwrap().unwrap();
            let max_cpus = active.spec.resources.max_cpus;
            let max_memory = active.spec.resources.max_memory_mib;
            let result = std::panic::AssertUnwindSafe(async {
                let plan = sandbox
                    .modify()
                    .cpus(max_cpus)
                    .memory(crate::size::SizeExt::mib(max_memory))
                    .dry_run()
                    .await?;
                assert!(!plan.applied);
                let applied = sandbox
                    .modify()
                    .cpus(max_cpus)
                    .memory(crate::size::SizeExt::mib(max_memory))
                    .apply()
                    .await?;
                assert!(applied.applied);
                let after = crate::Sandbox::get(&name).await?;
                assert_eq!(after.config()?.spec.resources.cpus, max_cpus);
                assert_eq!(after.config()?.spec.resources.memory_mib, max_memory);
                let active = after.active_config()?.unwrap();
                assert_eq!(active.spec.resources.cpus, max_cpus);
                assert_eq!(active.spec.resources.memory_mib, max_memory);
                let state = connection
                    .request(&microsandbox_control_client::GetCpuState)
                    .await
                    .map_err(crate::MicrosandboxError::ControlClient)?;
                assert_eq!(state.requested_online, u32::from(max_cpus));
                tokio::time::timeout(Duration::from_secs(10), async {
                    loop {
                        let cpu = connection
                            .request(&microsandbox_control_client::GetCpuState)
                            .await
                            .map_err(crate::MicrosandboxError::ControlClient)?;
                        let memory = connection
                            .request(&microsandbox_control_client::GetMemoryState)
                            .await
                            .map_err(crate::MicrosandboxError::ControlClient)?;
                        if cpu.actual_online == u32::from(max_cpus)
                            && memory.current_mib >= u64::from(max_memory)
                        {
                            return Ok::<(), crate::MicrosandboxError>(());
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                })
                .await
                .map_err(|_| {
                    crate::MicrosandboxError::Runtime(
                        "live fixture did not converge within ten seconds".into(),
                    )
                })??;
                Ok::<(), crate::MicrosandboxError>(())
            })
            .catch_unwind()
            .await;
            // A separately initiated cleanup explicitly restores the fixture's
            // original desired values even when the preceding operation failed.
            let restore = crate::Sandbox::get(&name).await.unwrap();
            restore
                .modify()
                .cpus(before.spec.resources.cpus)
                .memory(crate::size::SizeExt::mib(before.spec.resources.memory_mib))
                .apply()
                .await
                .unwrap();
            result.unwrap().unwrap();
        })
        .await;
    }
}
