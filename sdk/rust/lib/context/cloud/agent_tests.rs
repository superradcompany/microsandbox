//! Integration tests for cloud agent dialing, connection reuse, and readiness caching.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures::StreamExt;
use microsandbox_protocol::{
    codec,
    core::Ready,
    exec::{ExecExited, ExecRequest, ExecSignal, ExecStarted, ExecStdout},
    fs::{FsData, FsOp, FsRequest, FsResponse, FsResponseData},
    message::{Message, MessageType},
};
use microsandbox_types::CloudCreateSandboxResponse;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{broadcast, mpsc},
};

use super::{RemoteContext, ws_io::WsByteStream};
use crate::{
    MicrosandboxError,
    context::{Context, SandboxRemoteState},
    sandbox::{Sandbox, SandboxConfig, exec::ExecEvent},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fake cloud control-plane + WebSocket agent gateway for integration tests.
struct FakeGateway {
    url: String,
    upgrades: Arc<AtomicUsize>,
    control_requests: Arc<AtomicUsize>,
    stopped: Arc<AtomicBool>,
    /// Signals active guest connections to disconnect (simulating an external stop).
    disconnect_tx: broadcast::Sender<()>,
    closes: mpsc::UnboundedReceiver<()>,
    signals: mpsc::UnboundedReceiver<(u32, i32)>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl FakeGateway {
    async fn start() -> Self {
        Self::start_with(Ready::default()).await
    }

    async fn start_with(hello: Ready) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let upgrades = Arc::new(AtomicUsize::new(0));
        let control_requests = Arc::new(AtomicUsize::new(0));
        let stopped = Arc::new(AtomicBool::new(false));
        let (disconnect_tx, _) = broadcast::channel(8);
        let (close_tx, closes) = mpsc::unbounded_channel();
        let (signal_tx, signals) = mpsc::unbounded_channel();

        let counted = Arc::clone(&upgrades);
        let control_counted = Arc::clone(&control_requests);
        let stopped_state = Arc::clone(&stopped);
        let disconnect = disconnect_tx.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let counted = Arc::clone(&counted);
                let control_counted = Arc::clone(&control_counted);
                let stopped_state = Arc::clone(&stopped_state);
                let hello = hello.clone();
                let close_tx = close_tx.clone();
                let signal_tx = signal_tx.clone();
                let mut disconnect_rx = disconnect.subscribe();
                tokio::spawn(async move {
                    let mut peek = [0u8; 512];
                    let Ok(n) = stream.peek(&mut peek).await else {
                        return;
                    };
                    let request_line = std::str::from_utf8(&peek[..n])
                        .ok()
                        .and_then(|head| head.lines().next())
                        .unwrap_or_default();
                    let path = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .split('?')
                        .next()
                        .unwrap_or_default();
                    if path.ends_with("/agent") {
                        if stopped_state.load(Ordering::SeqCst) {
                            let mut request = Vec::new();
                            while !request.ends_with(b"\r\n\r\n") {
                                let Ok(byte) = stream.read_u8().await else {
                                    return;
                                };
                                request.push(byte);
                                if request.len() >= 16_384 {
                                    return;
                                }
                            }
                            let body = serde_json::json!({
                                "error": {
                                    "code": "sandbox_not_running",
                                    "message": "sandbox is not running"
                                }
                            })
                            .to_string();
                            let response = format!(
                                "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = stream.write_all(response.as_bytes()).await;
                            return;
                        }
                        let Ok(socket) = tokio_tungstenite::accept_async(stream).await else {
                            return;
                        };
                        counted.fetch_add(1, Ordering::SeqCst);
                        tokio::select! {
                            () = play_guest(WsByteStream::new(socket), hello, signal_tx) => {}
                            _ = disconnect_rx.recv() => {}
                        }
                        let _ = close_tx.send(());
                    } else {
                        control_counted.fetch_add(1, Ordering::SeqCst);
                        serve_http_control(stream, &stopped_state).await;
                    }
                });
            }
        });

        Self {
            url,
            upgrades,
            control_requests,
            stopped,
            disconnect_tx,
            closes,
            signals,
        }
    }

    fn upgrades(&self) -> usize {
        self.upgrades.load(Ordering::SeqCst)
    }

    fn control_requests(&self) -> usize {
        self.control_requests.load(Ordering::SeqCst)
    }

    /// Simulate an external stop: mark stopped and close active agent WebSockets.
    async fn stop_externally(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        let _ = self.disconnect_tx.send(());
        self.expect_close().await;
        // Let the client transport task observe EOF before the next checkout.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    async fn expect_close(&mut self) {
        tokio::time::timeout(Duration::from_secs(2), self.closes.recv())
            .await
            .expect("the gateway sees a connection close")
            .unwrap();
    }

    fn sandbox(&self) -> Sandbox {
        let backend = crate::test_support::cloud_backend(self.url.clone(), "test-key").unwrap();
        self.sandbox_on(backend)
    }

    fn sandbox_on(&self, backend: RemoteContext) -> Sandbox {
        Sandbox::from_cloud_state(
            Arc::new(backend),
            SandboxRemoteState {
                id: "sandbox-id".to_owned(),
                org_id: "test-org".to_owned(),
                created_at: chrono::Utc::now(),
            },
            "sandbox".to_owned(),
            SandboxConfig::default(),
        )
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn serve_http_control(mut stream: TcpStream, stopped: &AtomicBool) {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        let Ok(byte) = stream.read_u8().await else {
            return;
        };
        request.push(byte);
        if request.len() >= 16_384 {
            return;
        }
    }
    let header_text = String::from_utf8_lossy(&request);
    let mut content_length = 0usize;
    for line in header_text.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }
    if content_length > 0 {
        let mut body = vec![0u8; content_length];
        if stream.read_exact(&mut body).await.is_err() {
            return;
        }
    }
    let mut parts = header_text
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts
        .next()
        .unwrap_or_default()
        .split('?')
        .next()
        .unwrap_or_default();

    let body = if method == "DELETE" {
        stopped.store(true, Ordering::SeqCst);
        serde_json::json!({"message": "deleted"}).to_string()
    } else {
        if method == "POST" && path.ends_with("/stop") {
            stopped.store(true, Ordering::SeqCst);
        } else if method == "POST" && (path.ends_with("/restart") || path.ends_with("/start")) {
            stopped.store(false, Ordering::SeqCst);
        }
        let status = if stopped.load(Ordering::SeqCst) {
            "stopped"
        } else {
            "running"
        };
        serde_json::json!({
            "id": "sandbox-id",
            "org_id": "test-org",
            "name": "sandbox",
            "slug": "sandbox",
            "status": status,
            "ephemeral": false,
            "created_at": "2026-11-15T00:00:00Z"
        })
        .to_string()
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

async fn play_guest<S>(mut stream: S, hello: Ready, signals: mpsc::UnboundedSender<(u32, i32)>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(&1u32.to_be_bytes()).await.unwrap();
    stream.write_all(&1024u32.to_be_bytes()).await.unwrap();
    let mut ready = Message::with_payload(MessageType::Ready, 0, &hello).unwrap();
    if hello.exec_limits.is_none() {
        // Speak generation 6 (inline CBOR FsData) in this lightweight test guest.
        ready.v = 6;
    }
    codec::write_message(&mut stream, &ready).await.unwrap();

    while let Ok(message) = codec::read_message(&mut stream).await {
        let id = message.id;
        let replies = match message.t {
            MessageType::ExecRequest => {
                let request = message.payload::<ExecRequest>().unwrap();
                let started =
                    Message::with_payload(MessageType::ExecStarted, id, &ExecStarted { pid: 7 });
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
                let request = message.payload::<FsRequest>().unwrap();
                match request.op {
                    FsOp::OpenFile { .. } => {
                        let opened = FsResponse {
                            ok: true,
                            error: None,
                            data: Some(FsResponseData::Handle(1)),
                        };
                        vec![Message::with_payload(MessageType::FsResponse, id, &opened)]
                    }
                    FsOp::Read { .. } => {
                        let chunk = FsData {
                            data: b"file-contents".to_vec(),
                        };
                        let done = FsResponse {
                            ok: true,
                            error: None,
                            data: None,
                        };
                        vec![
                            Message::with_payload(MessageType::FsData, id, &chunk),
                            Message::with_payload(MessageType::FsResponse, id, &done),
                        ]
                    }
                    FsOp::Write { .. } => {
                        // Wait for empty FsData EOF frame before acknowledging.
                        Vec::new()
                    }
                    _ => {
                        let done = FsResponse {
                            ok: true,
                            error: None,
                            data: None,
                        };
                        vec![Message::with_payload(MessageType::FsResponse, id, &done)]
                    }
                }
            }
            MessageType::FsData => {
                let chunk = message.payload::<FsData>().unwrap();
                if chunk.data.is_empty() {
                    let done = FsResponse {
                        ok: true,
                        error: None,
                        data: None,
                    };
                    vec![Message::with_payload(MessageType::FsResponse, id, &done)]
                } else {
                    Vec::new()
                }
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn sequential_commands_reuse_one_websocket() {
    let gateway = FakeGateway::start().await;
    let sandbox = gateway.sandbox();

    for _ in 0..3 {
        let output = sandbox.exec("true", Vec::<String>::new()).await.unwrap();
        assert!(output.status().success);
    }

    assert_eq!(gateway.upgrades(), 1);
}

#[tokio::test]
async fn abandoned_command_closes_its_websocket_and_the_next_one_dials() {
    let mut gateway = FakeGateway::start().await;
    let sandbox = gateway.sandbox();
    let mut running = sandbox.exec_stream("sleep", ["1000"]).await.unwrap();
    assert!(matches!(
        running.recv().await,
        Some(ExecEvent::Started { .. })
    ));

    drop(running);
    gateway.expect_close().await;
    let next = sandbox.exec("true", Vec::<String>::new()).await.unwrap();

    // Closing was the kill: nothing travelled in-band.
    assert!(gateway.signals.try_recv().is_err());
    assert!(next.status().success);
    assert_eq!(gateway.upgrades(), 2);
}

#[tokio::test]
async fn commands_at_once_use_a_websocket_each() {
    let gateway = FakeGateway::start().await;
    let sandbox = gateway.sandbox();
    let mut running = sandbox.exec_stream("sleep", ["1000"]).await.unwrap();
    assert!(matches!(
        running.recv().await,
        Some(ExecEvent::Started { .. })
    ));

    let output = sandbox.exec("true", Vec::<String>::new()).await.unwrap();

    assert!(output.status().success);
    assert_eq!(gateway.upgrades(), 2);
}

#[tokio::test]
async fn file_requests_and_commands_take_turns_on_one_websocket() {
    let gateway = FakeGateway::start().await;
    let sandbox = gateway.sandbox();

    sandbox.fs().mkdir("/work").await.unwrap();
    sandbox
        .fs()
        .write("/work/app.py", b"print(1)")
        .await
        .unwrap();
    let output = sandbox.exec("true", Vec::<String>::new()).await.unwrap();
    let content = sandbox.fs().read("/work/app.py").await.unwrap();
    sandbox.fs().mkdir("/work/out").await.unwrap();
    sandbox
        .fs()
        .symlink("/work/out", "/work/link")
        .await
        .unwrap();

    assert!(output.status().success);
    assert_eq!(content.as_ref(), b"file-contents");
    assert_eq!(gateway.upgrades(), 1);
}

#[tokio::test]
async fn abandoned_write_stream_closes_its_websocket() {
    let mut gateway = FakeGateway::start().await;
    let sandbox = gateway.sandbox();

    let sink = sandbox.fs().write_stream("/work/partial").await.unwrap();
    sink.write(b"partial").await.unwrap();
    drop(sink);
    gateway.expect_close().await;

    let output = sandbox.exec("true", Vec::<String>::new()).await.unwrap();
    assert!(output.status().success);
    assert_eq!(gateway.upgrades(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn back_to_back_commands_always_find_the_connection_waiting() {
    let hello = Ready {
        exec_limits: Some(Default::default()),
        ..Default::default()
    };
    let gateway = FakeGateway::start_with(hello).await;
    let sandbox = gateway.sandbox();

    for round in 0..200 {
        let cmd = if round % 2 == 0 { "true" } else { "echo" };
        let output = sandbox.exec(cmd, Vec::<String>::new()).await.unwrap();
        assert!(output.status().success);
    }

    assert_eq!(gateway.upgrades(), 1);
}

#[tokio::test]
async fn stop_and_restart_evict_waiting_agent_connections() {
    let mut gateway = FakeGateway::start().await;
    let sandbox = gateway.sandbox();

    assert!(
        sandbox
            .exec("true", Vec::<String>::new())
            .await
            .unwrap()
            .status()
            .success
    );
    assert_eq!(gateway.upgrades(), 1);

    // Restarting invalidates the session and closes the idle socket immediately.
    let restarted = sandbox.restart().await.unwrap();
    gateway.expect_close().await;
    assert!(
        restarted
            .exec("true", Vec::<String>::new())
            .await
            .unwrap()
            .status()
            .success
    );
    assert_eq!(gateway.upgrades(), 2);

    // Stopping also invalidates the session and closes any waiting socket.
    restarted.stop().await.unwrap();
    gateway.expect_close().await;
    assert!(gateway.stopped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn unbound_and_other_name_dials_still_resolve_by_name() {
    for bound in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = crate::test_support::cloud_backend(
            format!("http://{}", listener.local_addr().unwrap()),
            "test-key",
        )
        .unwrap();
        let backend: Arc<dyn Context> = if bound {
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
    for cancel in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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
            assert!(error.to_string().contains("stage: websocket"));
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
async fn stalled_agent_handshake_reports_phase_and_closes_transport() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = crate::test_support::cloud_backend(
        format!("http://{}", listener.local_addr().unwrap()),
        "test-key",
    )
    .unwrap()
    .with_agent_identity("sandbox", "captured-id")
    .unwrap();
    let (upgraded, ready) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        upgraded.send(()).unwrap();
        while let Some(message) = socket.next().await {
            if message.is_err() {
                break;
            }
        }
    });
    let mut dial = backend.dial_agent("sandbox", Duration::from_millis(500));
    tokio::select! {
        result = &mut dial => panic!("dial ended before handshake stall: {:?}", result.err()),
        result = ready => result.unwrap(),
    }
    let error = dial.await.err().expect("silent agent must time out");
    let message = error.to_string();
    assert!(
        message.contains("handshake") && message.contains("timed out"),
        "{error}"
    );
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn repeat_exec_shell_and_fs_skip_control_plane_lookups() {
    let gateway = FakeGateway::start().await;
    let sandbox = gateway.sandbox();

    for _ in 0..3 {
        assert!(
            sandbox
                .exec("true", Vec::<String>::new())
                .await
                .unwrap()
                .status()
                .success
        );
    }
    assert!(sandbox.shell("echo ok").await.unwrap().status().success);
    sandbox.fs().mkdir("/work").await.unwrap();
    sandbox.fs().symlink("/work", "/link").await.unwrap();

    assert_eq!(gateway.control_requests(), 0);
    assert_eq!(gateway.upgrades(), 1);
}

#[tokio::test]
async fn stop_invalidates_cached_readiness_so_next_exec_restarts() {
    let mut gateway = FakeGateway::start().await;
    let sandbox = gateway.sandbox();

    assert!(
        sandbox
            .exec("true", Vec::<String>::new())
            .await
            .unwrap()
            .status()
            .success
    );
    assert_eq!(gateway.control_requests(), 0);
    assert_eq!(gateway.upgrades(), 1);

    sandbox.stop().await.unwrap();
    gateway.expect_close().await;
    assert!(gateway.stopped.load(Ordering::SeqCst));

    // Next exec sees the invalidated session, starts the sandbox, and caches again.
    assert!(
        sandbox
            .exec("true", Vec::<String>::new())
            .await
            .unwrap()
            .status()
            .success
    );
    assert!(!gateway.stopped.load(Ordering::SeqCst));
    let control_after_restart = gateway.control_requests();

    assert!(
        sandbox
            .exec("true", Vec::<String>::new())
            .await
            .unwrap()
            .status()
            .success
    );
    assert_eq!(gateway.control_requests(), control_after_restart);
    assert_eq!(gateway.upgrades(), 2);
}

#[tokio::test]
async fn external_stop_recovers_transparently_on_next_exec_and_fs() {
    let mut gateway = FakeGateway::start().await;
    let sandbox = gateway.sandbox();

    assert!(
        sandbox
            .exec("true", Vec::<String>::new())
            .await
            .unwrap()
            .status()
            .success
    );
    assert_eq!(gateway.control_requests(), 0);

    // Simulate an external stop: gateway closes the idle socket and rejects new upgrades with 409.
    gateway.stop_externally().await;
    assert!(
        sandbox
            .exec("true", Vec::<String>::new())
            .await
            .unwrap()
            .status()
            .success
    );
    assert!(!gateway.stopped.load(Ordering::SeqCst));
    let control_after_exec_recovery = gateway.control_requests();
    assert!(control_after_exec_recovery > 0);

    // Subsequent exec skips control-plane lookups again.
    assert!(
        sandbox
            .exec("true", Vec::<String>::new())
            .await
            .unwrap()
            .status()
            .success
    );
    assert_eq!(gateway.control_requests(), control_after_exec_recovery);

    // Same transparent recovery on filesystem operations.
    gateway.stop_externally().await;
    sandbox.fs().mkdir("/recovered").await.unwrap();
    assert!(!gateway.stopped.load(Ordering::SeqCst));
    let control_after_fs_recovery = gateway.control_requests();
    assert!(control_after_fs_recovery > control_after_exec_recovery);

    sandbox.fs().mkdir("/recovered/sub").await.unwrap();
    assert_eq!(gateway.control_requests(), control_after_fs_recovery);
}

#[tokio::test]
async fn unstarted_cloud_create_prepares_before_first_exec() {
    let gateway = FakeGateway::start().await;
    gateway.stopped.store(true, Ordering::SeqCst);
    let backend = crate::test_support::cloud_backend(gateway.url.clone(), "test-key").unwrap();
    let cloud: CloudCreateSandboxResponse = serde_json::from_value(serde_json::json!({
        "id": "sandbox-id",
        "org_id": "test-org",
        "name": "sandbox",
        "slug": "sandbox",
        "status": "created",
        "ephemeral": false,
        "created_at": "2026-11-15T00:00:00Z"
    }))
    .unwrap();
    let sandbox = Sandbox::from_cloud(Arc::new(backend), cloud, SandboxConfig::default());

    assert!(
        sandbox
            .exec("true", Vec::<String>::new())
            .await
            .unwrap()
            .status()
            .success
    );
    assert!(!gateway.stopped.load(Ordering::SeqCst));
    assert!(gateway.control_requests() > 0);
}

#[tokio::test]
async fn prepared_agent_calls_keep_captured_identity_without_name_lookup() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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
            stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        }
        paths
    });
    let backend: Arc<dyn Context> =
        Arc::new(crate::test_support::cloud_backend(url, "test-key").unwrap());
    let make_handle = |backend, id: &str| {
        Sandbox::from_cloud_state(
            backend,
            SandboxRemoteState {
                id: id.to_owned(),
                org_id: "test-org".to_owned(),
                created_at: chrono::Utc::now(),
            },
            "reused-name".to_owned(),
            SandboxConfig::default(),
        )
    };
    let original = make_handle(backend, "original-id");
    let replacement = make_handle(original.backend().clone(), "replacement-id");
    assert!(matches!(
        original.exec("node", ["-v"]).await,
        Err(MicrosandboxError::SandboxNotFound(_))
    ));
    assert!(matches!(
        replacement.exec("node", ["-v"]).await,
        Err(MicrosandboxError::SandboxNotFound(_))
    ));
    assert!(matches!(
        original.fs().stat("/tmp").await,
        Err(MicrosandboxError::SandboxNotFound(_))
    ));
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
