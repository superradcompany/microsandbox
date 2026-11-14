//! Identity-bound agent connections for cloud sandbox objects.

use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use tokio_tungstenite::{
    connect_async_tls_with_config,
    tungstenite::{
        client::IntoClientRequest,
        http::{
            HeaderValue as WsHeaderValue,
            header::{AUTHORIZATION as WS_AUTHORIZATION, USER_AGENT as WS_USER_AGENT},
        },
    },
};

#[cfg(test)]
use super::agent_reuse::{AgentPool, Policy};
use super::{CloudBackend, cloud_agent_tls_connector, default_user_agent};
use crate::agent::AgentConnection;
use crate::backend::{Backend, BackendInfo, BackendKind, SandboxBackend, VolumeBackend};
use crate::{MicrosandboxError, MicrosandboxResult, timing};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CloudBackend {
    /// Take a connection for one operation on the named sandbox from this backend's pool.
    ///
    /// Returns `None` when reuse is off or when this backend is not bound to the sandbox's
    /// identity. Only bound backends pool: connections are kept by sandbox ID, and resolving a
    /// name first would cost a request and could hand the operation a connection to a
    /// replacement sandbox.
    pub(crate) async fn pooled_agent(
        &self,
        name: &str,
        timeout: Duration,
    ) -> MicrosandboxResult<Option<AgentConnection>> {
        let Some(pool) = &self.agent_pool else {
            return Ok(None);
        };
        let Some((bound_name, sandbox_id)) = &self.agent_identity else {
            return Ok(None);
        };
        if bound_name != name {
            return Ok(None);
        }

        let checkout = pool
            .checkout(sandbox_id, || self.dial_agent(name, timeout))
            .await?;
        tracing::trace!(target: timing::TARGET, %sandbox_id, reused = checkout.reused, "cloud agent connection selected");

        Ok(Some(checkout.connection))
    }

    /// Turn on agent connection reuse with an explicit keep policy.
    #[cfg(test)]
    pub(crate) fn with_agent_pool(mut self, policy: Policy) -> Self {
        self.agent_pool = Some(Arc::new(AgentPool::with_policy(policy)));
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Backend for CloudBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Cloud
    }

    fn info(&self) -> crate::MicrosandboxResult<BackendInfo> {
        Ok(BackendInfo {
            kind: BackendKind::Cloud,
            api_url: Some(self.url.clone()),
            source: self.selection_source,
            profile: self.profile.clone(),
        })
    }

    fn as_cloud(&self) -> Option<&CloudBackend> {
        Some(self)
    }

    fn sandboxes(&self) -> &dyn SandboxBackend {
        self
    }

    fn volumes(&self) -> &dyn VolumeBackend {
        self
    }

    fn snapshots(&self) -> &dyn crate::backend::SnapshotBackend {
        self
    }

    fn with_agent_identity(&self, name: &str, id: &str) -> Option<Arc<dyn Backend>> {
        let mut bound = self.clone();
        bound.agent_identity = Some((name.to_owned(), id.to_owned()));
        Some(Arc::new(bound))
    }

    /// Open an agent connection over `GET /v1/sandboxes/:id/agent`.
    ///
    /// The route upgrades to a WebSocket that pipes bytes to and from the
    /// sandbox's agent, so the standard agent client runs over it unchanged.
    fn dial_agent<'a>(
        &'a self,
        name: &'a str,
        timeout: std::time::Duration,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::agent::AgentClient>> {
        Box::pin(async move {
            // Treat the caller's timeout as one budget for lookup, WebSocket
            // establishment, and the agent handshake. In particular, a peer
            // that accepts TCP but never completes TLS/HTTP upgrade must not
            // leave exec, filesystem, or attach calls hanging indefinitely.
            let mut timing = timing::ConnectionTiming::new(name);
            let result = tokio::time::timeout(timeout, async {
                timing.stage("identity");
                let lookup_started = std::time::Instant::now();
                let id = match &self.agent_identity {
                    Some((bound_name, id)) if bound_name == name => id.clone(),
                    _ => self.get_sandbox(name).await?.id,
                };
                tracing::trace!(target: timing::TARGET, sandbox_id = %id, elapsed_seconds = lookup_started.elapsed().as_secs_f64(),
                    "cloud agent identity resolved");
                timing.identity(&id);
                let url = self.agent_ws_url(&id)?;
                let mut request = url
                    .into_client_request()
                    .map_err(|e| MicrosandboxError::Runtime(format!("cloud agent request: {e}")))?;
                let bearer = format!("Bearer {}", self.api_key);
                let mut auth_value = WsHeaderValue::from_str(&bearer).map_err(|e| {
                    MicrosandboxError::InvalidConfig(format!("invalid API key header value: {e}"))
                })?;
                auth_value.set_sensitive(true);
                request.headers_mut().insert(WS_AUTHORIZATION, auth_value);
                request.headers_mut().insert(
                    WS_USER_AGENT,
                    WsHeaderValue::from_str(&default_user_agent()).map_err(|e| {
                        MicrosandboxError::InvalidConfig(format!("invalid user-agent value: {e}"))
                    })?,
                );

                timing.stage("websocket");
                let websocket_started = std::time::Instant::now();
                let connector = cloud_agent_tls_connector()?;
                let (socket, _) =
                    connect_async_tls_with_config(request, None, false, Some(connector))
                        .await
                        .map_err(|e| {
                            tracing::trace!(target: timing::TARGET, sandbox_id = %id, elapsed_seconds = websocket_started.elapsed().as_secs_f64(), success = false, "cloud agent websocket finished");
                            MicrosandboxError::Runtime(format!("cloud agent websocket: {e}"))
                        })?;

                tracing::trace!(target: timing::TARGET, sandbox_id = %id, elapsed_seconds = websocket_started.elapsed().as_secs_f64(), success = true, "cloud agent websocket finished");
                timing.stage("handshake");
                let handshake_started = std::time::Instant::now();
                let client = crate::agent::AgentClient::connect_stream_with_timeout(
                    super::ws_io::WsByteStream::new(socket),
                    timeout,
                )
                .await;
                tracing::trace!(target: timing::TARGET, sandbox_id = %id, elapsed_seconds = handshake_started.elapsed().as_secs_f64(), success = client.is_ok(), "cloud agent handshake finished");
                client.map_err(Into::into)
            })
            .await;
            match result {
                Ok(result) => {
                    timing.finish(if result.is_ok() { "success" } else { "error" });
                    result
                }
                Err(_) => {
                    timing.finish("timeout");
                    Err(MicrosandboxError::Runtime(format!(
                        "timed out connecting to cloud sandbox agent {name:?} after {timeout:?}"
                    )))
                }
            }
        })
    }
}
//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use microsandbox_protocol::{
        codec,
        core::Ready,
        exec::{ExecExited, ExecRequest, ExecSignal, ExecStarted, ExecStdout},
        fs::FsResponse,
        message::{Message, MessageType},
    };
    use tokio::{
        io::{AsyncRead, AsyncWrite, AsyncWriteExt},
        net::TcpListener,
        sync::mpsc,
    };

    use super::*;
    use crate::{
        backend::{
            SandboxCloudState,
            cloud::{
                agent_reuse::{Candidate, Policy},
                ws_io::WsByteStream,
            },
        },
        sandbox::{Sandbox, SandboxConfig, exec::ExecEvent},
    };

    /// Stands in for the cloud's agent route.
    ///
    /// Accepts WebSocket upgrades, performs the relay handshake, and plays the guest: every file
    /// request succeeds, and every command starts and exits at once. `echo` prints a line first,
    /// and `sleep` runs until it is signalled or its connection closes.
    struct FakeGateway {
        url: String,
        upgrades: Arc<AtomicUsize>,
        /// One entry for each WebSocket the client has closed.
        closes: mpsc::UnboundedReceiver<()>,
        /// Signals delivered in-band, as `(correlation, signal)`.
        signals: mpsc::UnboundedReceiver<(u32, i32)>,
    }

    impl FakeGateway {
        /// Start a gateway whose guest predates exec flow control.
        async fn start() -> Self {
            Self::start_with(Ready::default()).await
        }

        /// Start a gateway whose guest greets every client with the given handshake.
        async fn start_with(hello: Ready) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let upgrades = Arc::new(AtomicUsize::new(0));
            let (close_tx, closes) = mpsc::unbounded_channel();
            let (signal_tx, signals) = mpsc::unbounded_channel();

            let counted = Arc::clone(&upgrades);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let counted = Arc::clone(&counted);
                    let hello = hello.clone();
                    let close_tx = close_tx.clone();
                    let signal_tx = signal_tx.clone();
                    tokio::spawn(async move {
                        let Ok(socket) = tokio_tungstenite::accept_async(stream).await else {
                            return;
                        };
                        counted.fetch_add(1, Ordering::SeqCst);
                        play_guest(WsByteStream::new(socket), hello, signal_tx).await;
                        let _ = close_tx.send(());
                    });
                }
            });

            Self {
                url,
                upgrades,
                closes,
                signals,
            }
        }

        fn upgrades(&self) -> usize {
            self.upgrades.load(Ordering::SeqCst)
        }

        /// Wait until the client has closed one more WebSocket.
        async fn expect_close(&mut self) {
            tokio::time::timeout(Duration::from_secs(2), self.closes.recv())
                .await
                .expect("the gateway sees a connection close")
                .unwrap();
        }

        /// A cloud sandbox handle pointed at this gateway, pooling connections when given a policy.
        fn sandbox(&self, policy: Option<Policy>) -> Sandbox {
            let backend = crate::test_support::cloud_backend(self.url.clone(), "test-key").unwrap();
            let backend = match policy {
                Some(policy) => backend.with_agent_pool(policy),
                None => backend,
            };

            self.sandbox_on(backend)
        }

        /// A cloud sandbox handle on the given backend, pointed at this gateway.
        fn sandbox_on(&self, backend: CloudBackend) -> Sandbox {
            Sandbox::from_cloud_state(
                Arc::new(backend),
                SandboxCloudState {
                    id: "sandbox-id".to_owned(),
                    org_id: "test-org".to_owned(),
                    created_at: chrono::Utc::now(),
                },
                "sandbox".to_owned(),
                SandboxConfig::default(),
            )
        }
    }

    async fn play_guest<S>(mut stream: S, hello: Ready, signals: mpsc::UnboundedSender<(u32, i32)>)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        stream.write_all(&1u32.to_be_bytes()).await.unwrap();
        stream.write_all(&1024u32.to_be_bytes()).await.unwrap();
        let ready = Message::with_payload(MessageType::Ready, 0, &hello).unwrap();
        codec::write_message(&mut stream, &ready).await.unwrap();

        while let Ok(message) = codec::read_message(&mut stream).await {
            let id = message.id;
            let replies = match message.t {
                MessageType::ExecRequest => {
                    let request = message.payload::<ExecRequest>().unwrap();
                    let started = Message::with_payload(
                        MessageType::ExecStarted,
                        id,
                        &ExecStarted { pid: 7 },
                    );
                    let exited =
                        Message::with_payload(MessageType::ExecExited, id, &ExecExited { code: 0 });

                    match request.cmd.as_str() {
                        "sleep" => vec![started],
                        "echo" => {
                            let line = ExecStdout {
                                data: b"hello\n".to_vec(),
                            };
                            let printed = Message::with_payload(MessageType::ExecStdout, id, &line);

                            vec![started, printed, exited]
                        }
                        _ => vec![started, exited],
                    }
                }
                MessageType::ExecSignal => {
                    let signal = message.payload::<ExecSignal>().unwrap().signal;
                    let _ = signals.send((id, signal));

                    vec![Message::with_payload(
                        MessageType::ExecExited,
                        id,
                        &ExecExited { code: 137 },
                    )]
                }
                MessageType::FsRequest => {
                    let done = FsResponse {
                        ok: true,
                        error: None,
                        data: None,
                    };

                    vec![Message::with_payload(MessageType::FsResponse, id, &done)]
                }
                _ => Vec::new(),
            };

            for reply in replies {
                if codec::write_message(&mut stream, &reply.unwrap())
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }

    fn keep_all(_: &Candidate) -> bool {
        true
    }

    fn keep_one_per_sandbox(candidate: &Candidate) -> bool {
        candidate.idle_peers == 0
    }

    #[tokio::test]
    async fn pool_runs_one_command_after_another_over_one_websocket() {
        let per_command = FakeGateway::start().await;
        let pooled = FakeGateway::start().await;
        let plain_sandbox = per_command.sandbox(None);
        let pooled_sandbox = pooled.sandbox(Some(keep_all));

        for sandbox in [&plain_sandbox, &pooled_sandbox] {
            for _ in 0..3 {
                let output = sandbox.exec("true", Vec::<String>::new()).await.unwrap();
                assert!(output.status().success);
            }
        }

        assert_eq!(per_command.upgrades(), 3);
        assert_eq!(pooled.upgrades(), 1);
    }

    #[tokio::test]
    async fn reuse_flag_keeps_connections_under_the_default_policy() {
        let gateway = FakeGateway::start().await;
        let backend =
            crate::test_support::cloud_backend_reusing_agents(gateway.url.clone(), "test-key")
                .unwrap();
        let sandbox = gateway.sandbox_on(backend);

        for _ in 0..3 {
            let output = sandbox.exec("true", Vec::<String>::new()).await.unwrap();
            assert!(output.status().success);
        }

        assert_eq!(gateway.upgrades(), 1);
    }

    #[tokio::test]
    async fn abandoned_command_closes_its_websocket_and_the_next_one_dials() {
        let mut gateway = FakeGateway::start().await;
        let sandbox = gateway.sandbox(Some(keep_all));
        let mut running = sandbox.exec_stream("sleep", ["1000"]).await.unwrap();
        assert!(matches!(
            running.recv().await,
            Some(ExecEvent::Started { .. })
        ));

        drop(running);
        gateway.expect_close().await;
        let next = sandbox.exec("true", Vec::<String>::new()).await.unwrap();

        // Closing was the kill, as it is without the pool: nothing travelled in-band.
        assert!(gateway.signals.try_recv().is_err());
        assert!(next.status().success);
        assert_eq!(gateway.upgrades(), 2);
    }

    #[tokio::test]
    async fn commands_at_once_use_a_websocket_each() {
        let gateway = FakeGateway::start().await;
        let sandbox = gateway.sandbox(Some(keep_all));
        let mut running = sandbox.exec_stream("sleep", ["1000"]).await.unwrap();
        assert!(matches!(
            running.recv().await,
            Some(ExecEvent::Started { .. })
        ));

        let output = sandbox.exec("true", Vec::<String>::new()).await.unwrap();

        // The running command has its connection to itself, so the second command dials.
        assert!(output.status().success);
        assert_eq!(gateway.upgrades(), 2);
    }

    #[tokio::test]
    async fn file_requests_and_commands_take_turns_on_one_websocket() {
        let gateway = FakeGateway::start().await;
        let sandbox = gateway.sandbox(Some(keep_all));

        sandbox.fs().mkdir("/work").await.unwrap();
        let output = sandbox.exec("true", Vec::<String>::new()).await.unwrap();
        sandbox.fs().mkdir("/work/out").await.unwrap();

        assert!(output.status().success);
        assert_eq!(gateway.upgrades(), 1);
    }

    /// A finished command must hold nothing of its connection by the time its caller hears the
    /// exit. Otherwise the caller's next command finds the pool empty and dials.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn back_to_back_commands_always_find_the_connection_waiting() {
        // With exec limits advertised, stdin waits for the start and output is acknowledged, so
        // a quick command exits while its own tasks are still at work on other threads.
        let hello = Ready {
            exec_limits: Some(Default::default()),
            ..Default::default()
        };
        let gateway = FakeGateway::start_with(hello).await;
        let sandbox = gateway.sandbox(Some(keep_one_per_sandbox));

        for round in 0..200 {
            let cmd = if round % 2 == 0 { "true" } else { "echo" };
            let output = sandbox.exec(cmd, Vec::<String>::new()).await.unwrap();
            assert!(output.status().success);
        }

        assert_eq!(gateway.upgrades(), 1);
    }

    #[tokio::test]
    async fn unbound_and_other_name_dials_still_resolve_by_name() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for bound in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let backend = crate::test_support::cloud_backend(
                format!("http://{}", listener.local_addr().unwrap()),
                "test-key",
            )
            .unwrap();
            let backend: Arc<dyn Backend> = if bound {
                backend
                    .with_agent_identity("original-name", "original-id")
                    .unwrap()
            } else {
                Arc::new(backend)
            };
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                    assert!(request.len() < 16_384);
                }
                stream
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
                String::from_utf8(request)
                    .unwrap()
                    .lines()
                    .next()
                    .unwrap()
                    .to_owned()
            });
            assert!(
                backend
                    .dial_agent("current-name", Duration::from_secs(2))
                    .await
                    .is_err()
            );
            assert_eq!(
                server.await.unwrap(),
                "GET /v1/sandboxes/by-name/current-name HTTP/1.1"
            );
        }
    }

    #[tokio::test]
    async fn stalled_cloud_upgrade_timeout_and_cancellation_close_transport() {
        use tokio::io::AsyncReadExt;

        for cancel in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let backend = crate::test_support::cloud_backend(
                format!("http://{}", listener.local_addr().unwrap()),
                "test-key",
            )
            .unwrap()
            .with_agent_identity("sandbox", "captured-id")
            .unwrap();
            let (accepted, ready) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                    assert!(request.len() < 16_384);
                }
                accepted.send(()).unwrap();
                // Deliberately never send the WebSocket upgrade response.
                // Both timeout and caller cancellation must close this socket.
                stream.read(&mut [0u8; 1]).await.unwrap()
            });
            let mut dial = backend.dial_agent("sandbox", Duration::from_millis(500));
            tokio::select! {
                result = &mut dial => panic!("dial ended before upgrade stall: {:?}", result.err()),
                result = ready => result.unwrap(),
            }
            if cancel {
                drop(dial);
            } else {
                let error = dial.await.err().expect("stalled upgrade must time out");
                assert!(
                    error
                        .to_string()
                        .contains("timed out connecting to cloud sandbox agent")
                );
            }
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), server)
                    .await
                    .unwrap()
                    .unwrap(),
                0,
            );
        }
    }

    #[tokio::test]
    async fn cloud_handle_agent_calls_use_captured_identity_without_lookup() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut paths = Vec::new();
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let byte = stream.read_u8().await.unwrap();
                    request.push(byte);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    assert!(request.len() < 16_384);
                }
                let request = String::from_utf8(request).unwrap();
                paths.push(request.lines().next().unwrap().to_owned());
                // A missing UUID must fail; it must never retry by name and
                // accidentally connect to a replacement sandbox.
                stream
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
            }
            paths
        });
        let backend: Arc<dyn Backend> =
            Arc::new(crate::test_support::cloud_backend(url, "test-key").unwrap());
        let make_handle = |backend, id: &str| {
            crate::sandbox::Sandbox::from_cloud_state(
                backend,
                crate::backend::SandboxCloudState {
                    id: id.to_owned(),
                    org_id: "test-org".to_owned(),
                    created_at: chrono::Utc::now(),
                },
                "reused-name".to_owned(),
                crate::sandbox::SandboxConfig::default(),
            )
        };
        let original = make_handle(backend, "original-id");
        // Lifecycle factories can receive a previously bound backend. The new
        // handle must capture its own identity without mutating the old one.
        let replacement = make_handle(original.backend().clone(), "replacement-id");
        assert!(original.exec("node", ["-v"]).await.is_err());
        assert!(replacement.exec("node", ["-v"]).await.is_err());
        assert!(original.fs().stat("/tmp").await.is_err());
        let paths = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            paths,
            [
                "GET /v1/sandboxes/original-id/agent HTTP/1.1",
                "GET /v1/sandboxes/replacement-id/agent HTTP/1.1",
                "GET /v1/sandboxes/original-id/agent HTTP/1.1",
            ]
        );
    }
}
