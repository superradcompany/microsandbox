use microsandbox_protocol::control::{
    Capabilities as ControlCapabilities, JsonControlResponse as ControlResponse,
    SecretChange as SecretLiveChange,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use microsandbox_control_client::{ControlClient, GetCapabilities, GetMemoryState, SetCpuTarget};
use microsandbox_protocol::{codec, control::*, wire::Envelope};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::dispatch::{Dispatcher, Input, Job, MAX_QUEUED, RUNTIME_BYTES};
use super::handler::{Handler, Reply, Response};

#[derive(Default)]
struct FakeHost {
    calls: Mutex<Vec<u32>>,
}

impl Handler for FakeHost {
    fn handle(&self, request: ControlRequest) -> Response {
        let value = match request {
            ControlRequest::CpuTarget { online } => online,
            _ => 0,
        };
        self.calls.lock().unwrap().push(value);
        match request {
            ControlRequest::Capabilities => {
                let caps = Capabilities {
                    root_disk_grow: false,
                    cpu_resize: true,
                    memory_resize: true,
                    secrets_update: true,
                };
                Response {
                    json: JsonControlResponse {
                        ok: true,
                        capabilities: Some(caps),
                        control_protocols: Some(vec!["json".into(), "cbor".into()]),
                        ..Default::default()
                    },
                    framed: Reply::Capabilities(caps),
                }
            }
            ControlRequest::CpuTarget { online } => {
                let cpu = CpuState {
                    possible: 8,
                    requested_online: online,
                    actual_online: online,
                    enforced: online,
                };
                Response {
                    json: JsonControlResponse {
                        ok: true,
                        cpu: Some(cpu),
                        ..Default::default()
                    },
                    framed: Reply::Cpu(cpu),
                }
            }
            _ => {
                let memory = MemoryState {
                    boot_mib: 512,
                    target_mib: 2048,
                    current_mib: 1024,
                    max_mib: 4096,
                };
                Response {
                    json: JsonControlResponse {
                        ok: true,
                        memory: Some(memory),
                        ..Default::default()
                    },
                    framed: Reply::Memory(memory),
                }
            }
        }
    }
}

fn dispatcher(start: bool) -> (Arc<FakeHost>, Arc<Dispatcher>) {
    let host = Arc::new(FakeHost::default());
    let dispatcher = Dispatcher::new(host.clone());
    if start {
        tokio::spawn(Arc::clone(&dispatcher).run());
    }
    (host, dispatcher)
}

fn connection(
    dispatcher: &Arc<Dispatcher>,
) -> (DuplexStream, tokio::task::JoinHandle<std::io::Result<()>>) {
    let (client, mut server) = tokio::io::duplex(16384);
    let dispatcher = Arc::clone(dispatcher);
    let handle = tokio::spawn(async move { super::server::serve(&mut server, dispatcher).await });
    (client, handle)
}

async fn handshake(stream: &mut DuplexStream, capacity: u32) {
    let hello = ControlHello {
        max_in_flight: capacity,
        ..Default::default()
    };
    codec::write_raw_frame(
        stream,
        &Envelope::new(1, "control.hello", &hello)
            .unwrap()
            .frame(0, 0)
            .unwrap(),
    )
    .await
    .unwrap();
    let response = codec::read_raw_frame(stream).await.unwrap();
    let welcome: ControlWelcome = Envelope::decode(&response.body).unwrap().payload().unwrap();
    welcome.validate_for(&hello).unwrap();
    assert_eq!(welcome.max_in_flight, capacity.min(64));
}

async fn request(
    stream: &mut DuplexStream,
    id: u32,
    flags: u8,
    name: &str,
    payload: &impl serde::Serialize,
) {
    codec::write_raw_frame(
        stream,
        &Envelope::new(1, name, payload)
            .unwrap()
            .frame(id, flags)
            .unwrap(),
    )
    .await
    .unwrap();
}

async fn response(stream: &mut DuplexStream) -> Envelope {
    let frame = codec::read_raw_frame(stream).await.unwrap();
    assert_eq!(frame.flags, 1);
    Envelope::decode(&frame.body).unwrap()
}

fn queued_json(online: u32, reply: mpsc::Sender<super::dispatch::Outgoing>) -> Job {
    Job {
        input: Input::Json(ControlRequest::CpuTarget { online }),
        reply,
        output_budget: None,
        lease: None,
        cancelled: CancellationToken::new(),
    }
}

#[test]
fn secret_value_debug_is_redacted() {
    let request = ControlRequest::SecretsUpdate {
        changes: vec![SecretLiveChange::Rotate {
            name: "API_KEY".into(),
            value: SecretValue("sentinel-secret-value".into()),
        }],
    };

    let debug = format!("{request:?}");
    assert!(!debug.contains("sentinel-secret-value"));
    assert!(debug.contains("[redacted]"));
    assert!(debug.contains("API_KEY"));
}

#[test]
fn secrets_update_round_trips_through_json() {
    let request = ControlRequest::SecretsUpdate {
        changes: vec![
            SecretLiveChange::Rotate {
                name: "API_KEY".into(),
                value: SecretValue("new-material".into()),
            },
            SecretLiveChange::Remove {
                name: "OLD_KEY".into(),
            },
            SecretLiveChange::SetAllowedHosts {
                name: "API_KEY".into(),
                hosts: vec!["api.example.com".into(), "*".into()],
            },
        ],
    };

    let json = serde_json::to_string(&request).unwrap();
    let parsed: ControlRequest = serde_json::from_str(&json).unwrap();
    let ControlRequest::SecretsUpdate { changes } = parsed else {
        panic!("expected secrets_update");
    };
    assert_eq!(changes.len(), 3);
    let SecretLiveChange::Rotate { name, value } = &changes[0] else {
        panic!("expected rotate");
    };
    assert_eq!(name, "API_KEY");
    assert_eq!(value.0, "new-material");
}

#[test]
fn capabilities_response_serializes_flags() {
    let response = ControlResponse {
        ok: true,
        capabilities: Some(ControlCapabilities {
            root_disk_grow: false,
            cpu_resize: true,
            memory_resize: false,
            secrets_update: true,
        }),
        ..Default::default()
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"secrets_update\":true"));
    assert!(json.contains("\"memory_resize\":false"));

    let parsed: ControlResponse = serde_json::from_str(&json).unwrap();
    assert!(parsed.capabilities.unwrap().secrets_update);
}

#[test]
fn legacy_responses_without_capabilities_still_parse() {
    let parsed: ControlResponse = serde_json::from_str(r#"{"ok":true}"#).unwrap();
    assert!(parsed.ok);
    assert!(parsed.capabilities.is_none());
}

#[tokio::test]
async fn json_and_framed_clients_share_the_actual_server_dispatcher() {
    let (host, dispatcher) = dispatcher(true);
    let (mut json, json_server) = connection(&dispatcher);
    // Unicode/ASCII whitespace and a second request retain old line semantics.
    json.write_all(
        " \t\u{2003}{\"op\":\"capabilities\"} \r\n{\"op\":\"cpu_target\",\"online\":99}\n"
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut bytes = Vec::new();
    json.read_to_end(&mut bytes).await.unwrap();
    let decoded: JsonControlResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded.control_protocols.unwrap(), ["json", "cbor"]);
    assert!(decoded.capabilities.unwrap().cpu_resize);
    json_server.await.unwrap().unwrap();
    let (stream, server) = connection(&dispatcher);
    let client = ControlClient::connect_stream(stream).await.unwrap();
    assert!(
        client
            .request_typed(&GetCapabilities)
            .await
            .unwrap()
            .memory_resize
    );
    assert_eq!(
        client
            .request_typed(&GetMemoryState)
            .await
            .unwrap()
            .target_mib,
        2048
    );
    client.close().await;
    server.await.unwrap().unwrap();
    assert_eq!(*host.calls.lock().unwrap(), [0, 0, 0]);
}

#[tokio::test]
async fn legacy_json_has_no_new_frame_size_cap_and_accepts_eof_delimited_lines() {
    let (host, dispatcher) = dispatcher(true);
    let (mut stream, server) = connection(&dispatcher);
    let mut bytes = b"{\"op\":\"capabilities\",\"future_padding\":\"".to_vec();
    bytes.resize(bytes.len() + 4 * 1024 * 1024 + 1024, b'x');
    bytes.extend_from_slice(b"\"}");
    stream.write_all(&bytes).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.unwrap();
    assert!(
        serde_json::from_slice::<JsonControlResponse>(&reply)
            .unwrap()
            .ok
    );
    server.await.unwrap().unwrap();
    assert_eq!(host.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn parser_selection_is_pinned_and_no_mutation_precedes_welcome() {
    let (host, dispatcher) = dispatcher(true);
    let (mut stream, server) = connection(&dispatcher);
    request(
        &mut stream,
        17,
        0,
        "control.cpu.target",
        &CpuTarget { online: 3 },
    )
    .await;
    let refusal: ControlError = response(&mut stream).await.payload().unwrap();
    assert_eq!(refusal.code, "invalid_handshake");
    server.await.unwrap().unwrap();
    assert!(host.calls.lock().unwrap().is_empty());

    let (mut stream, server) = connection(&dispatcher);
    handshake(&mut stream, 64).await;
    // A JSON object after welcome is an invalid frame prefix, never a downgrade.
    stream
        .write_all(b"{\"op\":\"cpu_target\",\"online\":3}\n")
        .await
        .unwrap();
    assert!(server.await.unwrap().is_err());
    assert!(host.calls.lock().unwrap().is_empty());

    let (mut stream, server) = connection(&dispatcher);
    handshake(&mut stream, 64).await;
    request(&mut stream, 1, 0, "control.hello", &ControlHello::default()).await;
    assert!(server.await.unwrap().is_err());
    assert!(host.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn recoverable_bad_operations_return_structured_errors_before_dispatch() {
    let (host, dispatcher) = dispatcher(true);
    let (mut stream, server) = connection(&dispatcher);
    handshake(&mut stream, 64).await;
    for (id, flags, name, expected) in [
        (1, 2, "control.cpu.target", "invalid_request"),
        (2, 0, "future.control", "unsupported_operation"),
        (3, 0, "control.memory.target", "invalid_request"),
    ] {
        request(&mut stream, id, flags, name, &Empty {}).await;
        let error: ControlError = response(&mut stream).await.payload().unwrap();
        assert_eq!(error.code, expected);
        assert_eq!(error.effect, ErrorEffect::None);
    }
    assert!(host.calls.lock().unwrap().is_empty());
    request(&mut stream, 4, 0, "control.capabilities", &Empty {}).await;
    assert_eq!(response(&mut stream).await.t, "control.capabilities.result");
    drop(stream);
    server.await.unwrap().unwrap();
    assert_eq!(host.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn duplicate_or_excessive_in_flight_ids_close_and_remove_queued_mutations() {
    for second_id in [1, 2] {
        let (host, dispatcher) = dispatcher(false);
        let (mut stream, server) = connection(&dispatcher);
        handshake(&mut stream, if second_id == 1 { 2 } else { 1 }).await;
        request(
            &mut stream,
            1,
            0,
            "control.cpu.target",
            &CpuTarget { online: 1 },
        )
        .await;
        request(
            &mut stream,
            second_id,
            0,
            "control.cpu.target",
            &CpuTarget { online: 2 },
        )
        .await;
        assert!(server.await.unwrap().is_err());
        assert_eq!(dispatcher.bytes.available_permits(), RUNTIME_BYTES);
        tokio::spawn(Arc::clone(&dispatcher).run());
        tokio::task::yield_now().await;
        assert!(host.calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn a_completed_id_can_be_reused_immediately_at_capacity_one() {
    let (host, dispatcher) = dispatcher(true);
    let (mut stream, server) = connection(&dispatcher);
    handshake(&mut stream, 1).await;
    for online in 0..100 {
        request(
            &mut stream,
            7,
            0,
            "control.cpu.target",
            &CpuTarget { online },
        )
        .await;
        assert_eq!(
            response(&mut stream)
                .await
                .payload::<CpuState>()
                .unwrap()
                .requested_online,
            online
        );
    }
    drop(stream);
    server.await.unwrap().unwrap();
    assert_eq!(host.calls.lock().unwrap().len(), 100);
}

#[tokio::test]
async fn dispatch_is_fifo_per_connection_and_round_robin_between_connections() {
    let (host, dispatcher) = dispatcher(false);
    let (reply, mut replies) = mpsc::channel(16);
    for value in 0..6 {
        assert!(
            dispatcher
                .submit(1, queued_json(value, reply.clone()))
                .is_ok()
        );
    }
    for value in 100..103 {
        assert!(
            dispatcher
                .submit(2, queued_json(value, reply.clone()))
                .is_ok()
        );
    }
    let worker = tokio::spawn(Arc::clone(&dispatcher).run());
    for _ in 0..9 {
        replies.recv().await.unwrap();
    }
    assert_eq!(
        *host.calls.lock().unwrap(),
        [0, 100, 1, 101, 2, 102, 3, 4, 5]
    );
    worker.abort();
}

#[tokio::test]
async fn a_full_runtime_queue_returns_busy_without_executing_the_request() {
    let (host, dispatcher) = dispatcher(false);
    let (reply, _replies) = mpsc::channel(MAX_QUEUED);
    for value in 0..MAX_QUEUED {
        assert!(
            dispatcher
                .submit(u64::MAX, queued_json(value as u32, reply.clone()))
                .is_ok()
        );
    }
    let (stream, server) = connection(&dispatcher);
    let client = ControlClient::connect_stream(stream).await.unwrap();
    match client
        .request_typed(&SetCpuTarget::new(8))
        .await
        .unwrap_err()
    {
        microsandbox_control_client::ControlClientError::Peer { error, .. } => {
            assert_eq!(error.code, "busy")
        }
        error => panic!("wrong error: {error}"),
    }
    assert!(host.calls.lock().unwrap().is_empty());
    client.close().await;
    server.await.unwrap().unwrap();
    dispatcher.cancel(u64::MAX);
}

#[tokio::test]
async fn reply_capacity_is_reserved_before_mutation_and_released_on_teardown() {
    let (host, dispatcher) = dispatcher(true);
    let (mut stream, server) = connection(&dispatcher);
    handshake(&mut stream, 1).await;
    let frame = Envelope::new(1, "control.cpu.target", &CpuTarget { online: 8 })
        .unwrap()
        .frame(1, 0)
        .unwrap();
    let packet_size = frame.body.len() + 9;
    // Leave just enough room to read this request, but no room for its reply.
    let held = Arc::clone(&dispatcher.bytes)
        .acquire_many_owned((RUNTIME_BYTES - packet_size) as u32)
        .await
        .unwrap();
    codec::write_raw_frame(&mut stream, &frame).await.unwrap();
    assert!(server.await.unwrap().is_err());
    assert!(host.calls.lock().unwrap().is_empty());
    drop(held);
    assert_eq!(dispatcher.bytes.available_permits(), RUNTIME_BYTES);
}

#[tokio::test(start_paused = true)]
async fn setup_and_incomplete_frames_expire_but_complete_idle_sessions_do_not() {
    let (_, dispatcher) = dispatcher(true);
    let (_stream, server) = connection(&dispatcher);
    assert_eq!(
        server.await.unwrap().unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    let (mut stream, server) = connection(&dispatcher);
    handshake(&mut stream, 1).await;
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(!server.is_finished());
    request(&mut stream, 1, 0, "control.capabilities", &Empty {}).await;
    assert_eq!(response(&mut stream).await.t, "control.capabilities.result");
    stream.write_all(&[0, 0]).await.unwrap();
    assert_eq!(
        server.await.unwrap().unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(dispatcher.bytes.available_permits(), RUNTIME_BYTES);
}

#[tokio::test]
async fn zero_byte_probes_and_oversized_prefixes_do_not_dispatch() {
    let (host, dispatcher) = dispatcher(true);
    let (stream, server) = connection(&dispatcher);
    drop(stream);
    server.await.unwrap().unwrap();
    let (mut stream, server) = connection(&dispatcher);
    handshake(&mut stream, 1).await;
    stream
        .write_all(&(4 * 1024 * 1024 + 1u32).to_be_bytes())
        .await
        .unwrap();
    assert!(server.await.unwrap().is_err());
    assert_eq!(dispatcher.bytes.available_permits(), RUNTIME_BYTES);
    assert!(host.calls.lock().unwrap().is_empty());
}

#[rustfmt::skip]
#[path = "../../../tests/fixtures/legacy_control_records.rs"]
#[allow(dead_code)]
mod historical;

#[cfg(unix)]
#[tokio::test]
async fn historical_json_and_current_framed_consumers_use_one_real_unix_endpoint() {
    let (host, dispatcher) = dispatcher(true);
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    let path = directory.path().join("control.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let accept = tokio::spawn(super::server::listen_unix(listener, dispatcher));
    let mut old = tokio::net::UnixStream::connect(&path).await.unwrap();
    let mut bytes = serde_json::to_vec(&historical::ControlRequest::Capabilities).unwrap();
    bytes.push(b'\n');
    old.write_all(&bytes).await.unwrap();
    let mut received = Vec::new();
    old.read_to_end(&mut received).await.unwrap();
    let result: historical::ControlResponse = serde_json::from_slice(&received).unwrap();
    assert!(result.ok && result.capabilities.unwrap().memory_resize);
    let stream = tokio::net::UnixStream::connect(&path).await.unwrap();
    let new = ControlClient::connect_stream(stream).await.unwrap();
    assert_eq!(
        new.request_typed(&SetCpuTarget::new(3))
            .await
            .unwrap()
            .enforced,
        3
    );
    new.close().await;
    assert_eq!(*host.calls.lock().unwrap(), [0, 3]);
    accept.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn runtime_live_connection_cap_is_shared_and_released_on_close() {
    let (host, dispatcher) = dispatcher(true);
    let directory = tempfile::tempdir_in("/tmp").unwrap();
    let path = directory.path().join("control.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let accept = tokio::spawn(super::server::listen_unix(listener, dispatcher));
    let mut idle = Vec::new();
    for _ in 0..super::server::MAX_CONNECTIONS {
        idle.push(tokio::net::UnixStream::connect(&path).await.unwrap());
    }
    let mut queued = tokio::net::UnixStream::connect(&path).await.unwrap();
    queued
        .write_all(b"{\"op\":\"capabilities\"}\n")
        .await
        .unwrap();
    let mut first = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(20), queued.read(&mut first))
            .await
            .is_err()
    );
    assert!(host.calls.lock().unwrap().is_empty());
    idle.pop();
    let mut result = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), queued.read_to_end(&mut result))
        .await
        .unwrap()
        .unwrap();
    assert!(
        serde_json::from_slice::<JsonControlResponse>(&result)
            .unwrap()
            .ok
    );
    drop(idle);
    accept.abort();
}

#[tokio::test]
async fn structurally_invalid_secret_batches_are_rejected_before_any_entry_dispatches() {
    let (host, dispatcher) = dispatcher(true);
    let (mut stream, server) = connection(&dispatcher);
    handshake(&mut stream, 1).await;
    let payload = serde_json::json!({"changes": [
        {"change":"remove", "name":"existing"},
        {"change":"rotate", "name":"missing_value"}
    ]});
    request(&mut stream, 1, 0, "control.secrets.update", &payload).await;
    assert_eq!(
        response(&mut stream)
            .await
            .payload::<ControlError>()
            .unwrap()
            .code,
        "invalid_request"
    );
    assert!(host.calls.lock().unwrap().is_empty());
    drop(stream);
    server.await.unwrap().unwrap();
}

#[cfg(feature = "net")]
#[test]
fn actual_secret_store_preserves_ordered_partial_progress_and_legacy_errors() {
    use microsandbox_network::secrets::{
        config::{HostPattern, SecretEntry, SecretsConfig},
        handle::SecretsHandle,
    };
    let secrets = SecretsHandle::new(SecretsConfig {
        secrets: vec![SecretEntry {
            env_var: "TOKEN".into(),
            value: zeroize::Zeroizing::new("before".into()),
            source: None,
            placeholder: "$MSB_TOKEN".into(),
            allowed_hosts: vec![HostPattern::Exact("api.example.test".into())],
            substitution: Default::default(),
            passthrough_hosts: vec![],
            violation_action: None,
            require_tls_identity: true,
        }],
        ..Default::default()
    });
    let response = super::handler::apply_secret_changes(
        Some(&secrets),
        vec![
            SecretChange::Remove {
                name: "already_absent".into(),
            },
            SecretChange::Rotate {
                name: "TOKEN".into(),
                value: SecretValue("after".into()),
            },
            SecretChange::SetAllowedHosts {
                name: "TOKEN".into(),
                hosts: vec![],
            },
            SecretChange::Rotate {
                name: "TOKEN".into(),
                value: SecretValue("must_not_run".into()),
            },
        ],
    );
    assert!(!response.json.ok);
    assert_eq!(
        response.json.error.as_deref(),
        Some("secret TOKEN: at least one allowed host is required")
    );
    match response.framed {
        Reply::Secrets(SecretsResult::Failed {
            applied_count,
            failed_index,
            error,
        }) => {
            assert_eq!((applied_count, failed_index), (2, 2));
            assert_eq!(error.code, "invalid_secret_hosts");
            assert_eq!(error.effect, ErrorEffect::None);
        }
        _ => panic!("expected partial progress"),
    }
    let current = secrets.load();
    assert_eq!(current.secrets[0].value.as_str(), "after");
    assert_eq!(
        current.secrets[0].allowed_hosts,
        vec![HostPattern::Exact("api.example.test".into())]
    );
    let response = super::handler::apply_secret_changes(
        Some(&secrets),
        vec![
            SecretChange::Rotate {
                name: "absent".into(),
                value: SecretValue("fixture".into()),
            },
            SecretChange::Remove {
                name: "TOKEN".into(),
            },
        ],
    );
    assert_eq!(
        response.json.error.as_deref(),
        Some("no secret named absent is configured")
    );
    assert!(matches!(
        response.framed,
        Reply::Secrets(SecretsResult::Failed {
            applied_count: 0,
            failed_index: 0,
            ..
        })
    ));
    assert_eq!(secrets.load().secrets.len(), 1);
    let empty = super::handler::apply_secret_changes(Some(&secrets), vec![]);
    assert!(empty.json.ok);
    assert!(matches!(
        empty.framed,
        Reply::Secrets(SecretsResult::Complete { applied_count: 0 })
    ));
    let unsupported = super::handler::apply_secret_changes(None, vec![]);
    assert!(!unsupported.json.ok);
    assert!(matches!(
        unsupported.framed,
        Reply::Error(ControlError {
            effect: ErrorEffect::None,
            ..
        })
    ));
}

#[cfg(windows)]
async fn native_pipe(
    dispatcher: Arc<Dispatcher>,
    flush_timeout: Duration,
) -> (
    std::fs::File,
    tokio::task::JoinHandle<std::io::Result<()>>,
    Arc<tokio::sync::Semaphore>,
) {
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::net::windows::named_pipe::ServerOptions;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let name = format!(
        r"\\.\pipe\msb-drain-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&name)
        .unwrap();
    // Tokio clients issue background reads before application read calls. A
    // synchronous handle is necessary to test a genuinely unread server reply.
    let client = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&name)
        .unwrap();
    server.connect().await.unwrap();
    let admission = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = Arc::clone(&admission).acquire_owned().await.unwrap();
    let serving = tokio::spawn(super::windows::serve_named_pipe(
        server,
        dispatcher,
        permit,
        flush_timeout,
    ));
    (client, serving, admission)
}

#[cfg(windows)]
async fn native_reply(mut client: std::fs::File) -> Vec<u8> {
    let read = tokio::task::spawn_blocking(move || {
        let mut bytes = Vec::new();
        let result = std::io::Read::read_to_end(&mut client, &mut bytes);
        // A disconnected Windows byte pipe reports EOF as one of these native
        // errors. Preserve all preceding bytes so tests still detect lost data.
        match result {
            Ok(_) => {}
            Err(error) if matches!(error.raw_os_error(), Some(109 | 232 | 233)) => {}
            Err(error) => panic!("pipe read failed: {error}"),
        }
        bytes
    });
    tokio::time::timeout(Duration::from_secs(2), read)
        .await
        .unwrap()
        .unwrap()
}

#[cfg(windows)]
#[tokio::test]
async fn windows_json_reply_survives_a_delayed_reader_until_eof() {
    let (host, dispatch) = dispatcher(true);
    let (mut client, serving, _) = native_pipe(dispatch, Duration::from_secs(2)).await;
    std::io::Write::write_all(&mut client, b"{\"op\":\"capabilities\"}\n").unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while host.calls.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !serving.is_finished(),
        "reply must remain available for the reader"
    );
    let reply = native_reply(client).await;
    let response: JsonControlResponse = serde_json::from_slice(&reply).unwrap();
    assert!(response.ok);
    assert_eq!(response.control_protocols.unwrap(), vec!["json", "cbor"]);
    serving.await.unwrap().unwrap();
}

#[cfg(windows)]
#[tokio::test]
async fn windows_unread_reply_times_out_and_releases_its_flush_worker() {
    let (_, dispatch) = dispatcher(true);
    let (mut client, serving, admission) = native_pipe(dispatch, Duration::from_millis(50)).await;
    std::io::Write::write_all(&mut client, b"{\"op\":\"capabilities\"}\n").unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), serving)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    // Keep the client open: only server disconnect can release this worker.
    let _permit = tokio::time::timeout(Duration::from_secs(2), admission.acquire())
        .await
        .unwrap()
        .unwrap();
    drop(client);
}

#[cfg(windows)]
#[tokio::test]
async fn windows_zero_byte_probe_releases_admission() {
    let (_, dispatch) = dispatcher(true);
    let (client, serving, admission) = native_pipe(dispatch, Duration::from_secs(2)).await;
    drop(client);
    let _ = tokio::time::timeout(Duration::from_secs(2), serving)
        .await
        .unwrap()
        .unwrap();
    let _permit = tokio::time::timeout(Duration::from_secs(2), admission.acquire())
        .await
        .unwrap()
        .unwrap();
}

#[cfg(windows)]
#[tokio::test]
async fn windows_handshake_refusal_is_delivered_before_eof() {
    let (_, dispatch) = dispatcher(true);
    let (mut client, serving, _) = native_pipe(dispatch, Duration::from_secs(2)).await;
    let opening = Envelope::new(1, "control.hello", &ControlHello::default())
        .unwrap()
        .frame(7, 0)
        .unwrap();
    let mut encoded = Vec::new();
    codec::write_raw_frame(&mut encoded, &opening)
        .await
        .unwrap();
    std::io::Write::write_all(&mut client, &encoded).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let reply = native_reply(client).await;
    let mut reader = reply.as_slice();
    let frame = codec::read_raw_frame(&mut reader).await.unwrap();
    let error: ControlError = Envelope::decode(&frame.body).unwrap().payload().unwrap();
    assert_eq!(error.code, "invalid_handshake");
    assert!(reader.is_empty());
    serving.await.unwrap().unwrap();
}

#[cfg(windows)]
#[tokio::test]
async fn windows_cancelled_reply_drain_releases_its_flush_worker() {
    let (host, dispatch) = dispatcher(true);
    let (mut client, serving, admission) = native_pipe(dispatch, Duration::from_secs(30)).await;
    std::io::Write::write_all(&mut client, b"{\"op\":\"capabilities\"}\n").unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while host.calls.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!serving.is_finished());
    serving.abort();
    assert!(serving.await.unwrap_err().is_cancelled());
    let _permit = tokio::time::timeout(Duration::from_secs(2), admission.acquire())
        .await
        .unwrap()
        .unwrap();
    drop(client);
}
