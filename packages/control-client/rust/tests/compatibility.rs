//! Compatibility tests use original historical records and independent streams.

use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use microsandbox_control_client::*;
use microsandbox_protocol::{codec, wire::Envelope};
use microsandbox_protocol_client::{BoxFuture, BoxTransport, ClientResult};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::time::Instant;

#[rustfmt::skip]
#[path = "fixtures/legacy_control_records.rs"]
mod historical;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const LEGACY_CAPS: &[u8] =
    br#"{"ok":true,"capabilities":{"cpu_resize":true,"memory_resize":true,"secrets_update":true}}"#;
const FRAMED_CAPS: &[u8] = br#"{"ok":true,"capabilities":{"cpu_resize":true,"memory_resize":true,"secrets_update":true},"control_protocols":["json","cbor"]}"#;
const CBOR_ONLY_CAPS: &[u8] = br#"{"ok":true,"capabilities":{"cpu_resize":true,"memory_resize":true,"secrets_update":true},"control_protocols":["cbor"]}"#;
const MEMORY: &[u8] = br#"{"ok":true,"memory":{"boot_mib":0,"target_mib":18446744073709551615,"current_mib":9007199254740993,"max_mib":18446744073709551615},"extension":123456789012345678901234567890}"#;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct QueueConnector {
    streams: Mutex<VecDeque<DuplexStream>>,
    dials: AtomicUsize,
    checks: AtomicUsize,
    valid: AtomicBool,
    peer_valid: AtomicBool,
    delay: Duration,
    stall_verification: AtomicBool,
    verification_started: tokio::sync::Notify,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl QueueConnector {
    fn new(count: usize) -> (Arc<Self>, Vec<DuplexStream>) {
        let (clients, peers): (VecDeque<_>, Vec<_>) =
            (0..count).map(|_| tokio::io::duplex(8192)).unzip();
        (
            Arc::new(Self {
                streams: Mutex::new(clients),
                dials: AtomicUsize::new(0),
                checks: AtomicUsize::new(0),
                valid: AtomicBool::new(true),
                peer_valid: AtomicBool::new(true),
                delay: Duration::ZERO,
                stall_verification: AtomicBool::new(false),
                verification_started: tokio::sync::Notify::new(),
            }),
            peers,
        )
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Connector for QueueConnector {
    fn connect(&self, _deadline: Instant) -> BoxFuture<'_, ClientResult<BoxTransport>> {
        Box::pin(async move {
            self.dials.fetch_add(1, Ordering::SeqCst);
            let stream = self
                .streams
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| ClientError::new(ErrorKind::Io(std::io::ErrorKind::NotFound)))?;
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            Ok(Box::new(stream) as BoxTransport)
        })
    }
}

impl VerifiedControlConnector for QueueConnector {
    fn connect(&self, deadline: Instant) -> BoxFuture<'_, ControlClientResult<BoxTransport>> {
        Box::pin(async move {
            let stream = Connector::connect(self, deadline).await?;
            if !self.peer_valid.load(Ordering::SeqCst) {
                return Err(ControlClientError::RuntimeChanged);
            }
            Ok(stream)
        })
    }

    fn verify_session(&self, _deadline: Instant) -> BoxFuture<'_, ControlClientResult<()>> {
        Box::pin(async move {
            self.checks.fetch_add(1, Ordering::SeqCst);
            if self.stall_verification.load(Ordering::SeqCst) {
                self.verification_started.notify_one();
                return std::future::pending().await;
            }
            if self.valid.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(ControlClientError::RuntimeChanged)
            }
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn json_peer(mut stream: DuplexStream, expected: &str, reply: &[u8]) {
    let mut line = Vec::new();
    BufReader::new(&mut stream)
        .read_until(b'\n', &mut line)
        .await
        .unwrap();
    let request: historical::ControlRequest = serde_json::from_slice(&line).unwrap();
    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(value["op"], expected);
    stream.write_all(reply).await.unwrap();
    stream.write_all(b"\n").await.unwrap();
}

async fn welcome(peer: &mut DuplexStream) {
    let raw = codec::read_raw_frame(peer).await.unwrap();
    assert_eq!((raw.id, raw.flags), (0, 0));
    let envelope = Envelope::decode(&raw.body).unwrap();
    assert_eq!(envelope.t, "control.hello");
    let hello: ControlHello = envelope.payload().unwrap();
    let selected = ControlWelcome::negotiate(&hello, 64).unwrap();
    codec::write_raw_frame(
        peer,
        &Envelope::new(1, "control.welcome", &selected)
            .unwrap()
            .frame(0, 1)
            .unwrap(),
    )
    .await
    .unwrap();
}

fn assert_local(error: ControlClientError, kind: ErrorKind, delivery: Delivery) {
    assert!(
        matches!(error, ControlClientError::Client(error) if error.kind == kind && error.delivery == delivery),
        "{error:?}"
    );
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn json_numbers_unknown_fields_and_original_bytes_are_lossless() {
    let historical = historical::ControlResponse {
        ok: true,
        memory: Some(historical::MemoryControlState {
            boot_mib: 1,
            target_mib: u64::MAX,
            current_mib: 1,
            max_mib: u64::MAX,
        }),
        ..Default::default()
    };
    assert_eq!(
        GetMemoryState
            .decode_json(JsonReply::parse(serde_json::to_vec(&historical).unwrap()).unwrap())
            .unwrap()
            .target_mib,
        u64::MAX
    );
    let reply = JsonReply::parse(MEMORY.to_vec()).unwrap();
    assert_eq!(reply.raw(), MEMORY);
    let JsonValue::Number(extension) = reply.value().get("extension").unwrap() else {
        panic!()
    };
    assert_eq!(extension.as_str(), "123456789012345678901234567890");
    assert_eq!(extension.as_u64(), None);
    let memory = GetMemoryState.decode_json(reply).unwrap();
    assert_eq!(
        (memory.boot_mib, memory.target_mib, memory.current_mib),
        (0, u64::MAX, 9007199254740993)
    );
    let value = JsonValue::parse(br#"{"n":1e9999,"minus":-0,"array":[null,true,"x"]}"#).unwrap();
    let JsonValue::Number(number) = value.get("n").unwrap() else {
        panic!()
    };
    assert_eq!(number.as_str(), "1e9999");
    assert_eq!(value.get("minus").unwrap().as_u64(), None);
    assert!(!format!("{value:?}").contains("9999"));
}

#[test]
fn json_duplicate_keys_and_non_integer_memory_are_rejected() {
    for bytes in [
        br#"{"ok":true,"ok":false}"#.as_slice(),
        br#"{"x":{"a":0,"\u0061":1}}"#,
        br#"{"x":[{"a":0,"a":1}]}"#,
        br#"{"x":1}{}"#,
        br#"{"x":"\ud800"}"#,
    ] {
        assert!(JsonReply::parse(bytes.to_vec()).is_err());
    }
    for token in [
        "1.0",
        "1e0",
        "-1",
        "-0",
        "18446744073709551616",
        "true",
        "\"1\"",
    ] {
        let bytes = format!(
            "{{\"ok\":true,\"memory\":{{\"boot_mib\":0,\"target_mib\":{token},\"current_mib\":0,\"max_mib\":1}}}}"
        );
        assert!(matches!(
            GetMemoryState.decode_json(JsonReply::parse(bytes.into_bytes()).unwrap()),
            Err(ControlClientError::InvalidJsonResponse { .. })
        ));
    }
}

#[tokio::test]
async fn explicit_json_is_inert_and_uses_exact_historical_operations() {
    let (connector, mut peers) = QueueConnector::new(2);
    let client = JsonControlClient::from_connector(connector.clone());
    assert_eq!(connector.dials.load(Ordering::SeqCst), 0);
    let second = peers.pop().unwrap();
    let first = peers.pop().unwrap();
    let peer = tokio::spawn(async move {
        json_peer(first, "memory_target", MEMORY).await;
        json_peer(second, "cpu_target", br#"{"ok":true,"cpu":{"possible":8,"requested_online":2,"actual_online":1,"enforced":2}}"#).await;
    });
    let memory = client
        .request_typed(&SetMemoryTarget {
            total_mib: u64::MAX,
        })
        .await
        .unwrap();
    assert_eq!(memory.target_mib, u64::MAX);
    let cpu = client
        .clone()
        .request_typed(&SetCpuTarget::new(2))
        .await
        .unwrap();
    assert_eq!(cpu.actual_online, 1);
    assert!(!client.is_closed());
    assert_eq!(connector.dials.load(Ordering::SeqCst), 2);
    peer.await.unwrap();
}

#[tokio::test]
async fn automatic_framed_discovery_runs_once_then_reuses_the_same_connection() {
    // JSON discovery remains valid even when JSON operations are retired.
    for advertisement in [FRAMED_CAPS, CBOR_ONLY_CAPS] {
        let (connector, mut peers) = QueueConnector::new(2);
        let mut framed = peers.pop().unwrap();
        let discovery = peers.pop().unwrap();
        let peer = tokio::spawn(async move {
            json_peer(discovery, "capabilities", advertisement).await;
            welcome(&mut framed).await;
            for _ in 0..3 {
                let raw = codec::read_raw_frame(&mut framed).await.unwrap();
                let request = Envelope::decode(&raw.body).unwrap();
                assert_eq!(request.t, "control.memory.state");
                codec::write_raw_frame(
                    &mut framed,
                    &Envelope::new(
                        1,
                        "control.memory.state",
                        &MemoryState {
                            boot_mib: 1,
                            target_mib: 2,
                            current_mib: 1,
                            max_mib: 4,
                        },
                    )
                    .unwrap()
                    .frame(raw.id, 1)
                    .unwrap(),
                )
                .await
                .unwrap();
            }
        });
        let connection = ControlConnection::connect_connector(connector.clone())
            .await
            .unwrap();
        assert_eq!(connection.mode(), ControlMode::Framed);
        assert!(connection.framed().is_ok());
        assert_eq!(
            connection
                .request_typed(&GetMemoryState)
                .await
                .unwrap()
                .target_mib,
            2
        );
        assert!(matches!(
            connection
                .clone()
                .request(TypedMessage::new("control.memory.state", Empty {}))
                .await
                .unwrap(),
            ControlReply::Framed(_)
        ));
        connection
            .framed()
            .unwrap()
            .request_raw(
                0,
                Envelope::new(1, "control.memory.state", &Empty {})
                    .unwrap()
                    .encode()
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(connector.dials.load(Ordering::SeqCst), 2);
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn automatic_json_rediscovers_without_identity_but_verified_json_reuses_selection() {
    for verified in [false, true] {
        let count = if verified { 3 } else { 5 };
        let (connector, peers) = QueueConnector::new(count);
        let peer = tokio::spawn(async move {
            let mut peers = peers.into_iter();
            json_peer(peers.next().unwrap(), "capabilities", LEGACY_CAPS).await;
            for _ in 0..2 {
                if !verified {
                    json_peer(peers.next().unwrap(), "capabilities", LEGACY_CAPS).await;
                }
                json_peer(peers.next().unwrap(), "memory_state", MEMORY).await;
            }
        });
        let connection = if verified {
            ControlConnection::connect_verified_connector(connector.clone()).await
        } else {
            ControlConnection::connect_connector(connector.clone()).await
        }
        .unwrap();
        assert_eq!(connection.mode(), ControlMode::Json);
        assert!(matches!(
            connection.framed(),
            Err(ControlClientError::UnsupportedMode)
        ));
        for _ in 0..2 {
            assert_eq!(
                connection
                    .request_typed(&GetMemoryState)
                    .await
                    .unwrap()
                    .current_mib,
                9007199254740993
            );
        }
        assert!(!connection.is_closed());
        assert_eq!(connector.dials.load(Ordering::SeqCst), count);
        if verified {
            assert_eq!(connector.checks.load(Ordering::SeqCst), count);
        }
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn unsupported_raw_encoded_and_unknown_json_operations_do_not_dial() {
    let (connector, _) = QueueConnector::new(0);
    let client = JsonControlClient::from_connector(connector.clone());
    assert!(matches!(
        client
            .request(EncodedMessage::new("control.memory.state", vec![0xa0]))
            .await,
        Err(ControlClientError::UnsupportedMode)
    ));
    assert!(matches!(
        client
            .request(TypedMessage::new("extension", Empty {}))
            .await,
        Err(ControlClientError::UnsupportedMode)
    ));
    assert!(
        client
            .request(TypedMessage::new(
                "control.memory.target",
                serde_json::json!({"total_mib": 1.5})
            ))
            .await
            .is_err()
    );
    assert_eq!(connector.dials.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unknown_legacy_remote_errors_preserve_actual_reply_and_unknown_batch_progress() {
    let (connector, mut peers) = QueueConnector::new(2);
    let client = JsonControlClient::from_connector(connector);
    let second = peers.pop().unwrap();
    let first = peers.pop().unwrap();
    let response = br#"{"ok":false,"error":"unrecognized private diagnostic","extension":18446744073709551616}"#;
    let peer = tokio::spawn(async move {
        json_peer(first, "secrets_update", response).await;
        json_peer(second, "secrets_update", response).await;
    });
    let reply = client
        .request(TypedMessage::new(
            "control.secrets.update",
            SecretsUpdate { changes: vec![] },
        ))
        .await
        .unwrap();
    assert_eq!(reply.value().get("ok").unwrap().as_bool(), Some(false));
    let error = client
        .request_typed(&UpdateSecrets::new(vec![]))
        .await
        .unwrap_err();
    assert!(!format!("{error:?} {error}").contains("private diagnostic"));
    let ControlClientError::LegacyRemote { reply } = error else {
        panic!()
    };
    assert!(reply.raw().starts_with(response));
    assert!(!client.is_closed());
    peer.await.unwrap();
}

#[tokio::test]
async fn malformed_discovery_and_unknown_advertisements_never_guess_legacy_support() {
    let cases: &[&[u8]] = &[
        br#"{"ok":false,"error":"unknown operation capabilities"}"#,
        br#"{"ok":true}"#, br#"{"ok":true,"capabilities":{}}"#,
        br#"{"ok":true,"capabilities":{"cpu_resize":true,"memory_resize":true,"secrets_update":true},"control_protocols":null}"#,
        br#"{"ok":true,"capabilities":{"cpu_resize":true,"memory_resize":true,"secrets_update":true},"control_protocols":[1]}"#,
        br#"{"ok":true,"capabilities":{"cpu_resize":true,"memory_resize":true,"secrets_update":true},"control_protocols":["future"]}"#,
    ];
    for bytes in cases {
        let (connector, mut peers) = QueueConnector::new(1);
        let stream = peers.pop().unwrap();
        let bytes = bytes.to_vec();
        let peer = tokio::spawn(async move {
            json_peer(stream, "capabilities", &bytes).await;
        });
        assert!(
            ControlConnection::connect_connector(connector.clone())
                .await
                .is_err()
        );
        assert_eq!(connector.dials.load(Ordering::SeqCst), 1);
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn affirmative_discovery_followed_by_bad_welcome_does_not_fall_back() {
    // JSON discovery remains valid even when JSON operations are retired.
    for advertisement in [FRAMED_CAPS, CBOR_ONLY_CAPS] {
        let (connector, mut peers) = QueueConnector::new(2);
        let mut framed = peers.pop().unwrap();
        let discovery = peers.pop().unwrap();
        let peer = tokio::spawn(async move {
            json_peer(discovery, "capabilities", advertisement).await;
            let hello = codec::read_raw_frame(&mut framed).await.unwrap();
            assert_eq!((hello.id, hello.flags), (0, 0));
            assert_eq!(Envelope::decode(&hello.body).unwrap().t, "control.hello");
            framed.write_all(&[0, 1, 0, 0]).await.unwrap(); // Above the opening ceiling.
        });
        let error = ControlConnection::connect_connector(connector.clone())
            .await
            .err()
            .unwrap();
        assert_local(error, ErrorKind::InvalidData, Delivery::NotSent);
        assert_eq!(connector.dials.load(Ordering::SeqCst), 2);
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn identity_failure_and_changed_format_stop_before_mutation() {
    for verified in [true, false] {
        let (connector, mut peers) = QueueConnector::new(2);
        let mut next = peers.pop().unwrap();
        let discovery = peers.pop().unwrap();
        let peer = tokio::spawn(async move {
            json_peer(discovery, "capabilities", LEGACY_CAPS).await;
            if verified {
                assert_eq!(
                    next.read_u8().await.unwrap_err().kind(),
                    std::io::ErrorKind::UnexpectedEof
                );
            } else {
                json_peer(next, "capabilities", FRAMED_CAPS).await;
            }
        });
        let connection = if verified {
            ControlConnection::connect_verified_connector(connector.clone()).await
        } else {
            ControlConnection::connect_connector(connector.clone()).await
        }
        .unwrap();
        connector.valid.store(false, Ordering::SeqCst);
        assert!(matches!(
            connection.request_typed(&SetCpuTarget::new(2)).await,
            Err(ControlClientError::RuntimeChanged)
        ));
        assert!(connection.is_closed());
        assert_eq!(connector.dials.load(Ordering::SeqCst), 2);
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn explicit_close_and_zero_timeout_do_not_reopen_or_send() {
    let (connector, _) = QueueConnector::new(1);
    let client = JsonControlClient::from_connector(connector.clone());
    let clone = client.clone();
    client.close().await;
    assert_local(
        clone.request_typed(&GetMemoryState).await.unwrap_err(),
        ErrorKind::Closed,
        Delivery::NotSent,
    );
    assert_eq!(connector.dials.load(Ordering::SeqCst), 0);
    let client = JsonControlClient::from_connector(connector.clone());
    assert_local(
        client
            .request_typed_with(&SetCpuTarget::new(1), |o| o.request_timeout(Duration::ZERO))
            .await
            .unwrap_err(),
        ErrorKind::Timeout,
        Delivery::NotSent,
    );
    assert_eq!(connector.dials.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn lost_reply_has_unknown_delivery_and_never_replays() {
    let (connector, mut peers) = QueueConnector::new(1);
    let mut stream = peers.pop().unwrap();
    let peer = tokio::spawn(async move {
        let mut line = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut line)
            .await
            .unwrap();
        assert!(line.contains("cpu_target")); // Drop after consuming the request.
    });
    let client = JsonControlClient::from_connector(connector.clone());
    assert_local(
        client
            .request_typed(&SetCpuTarget::new(1))
            .await
            .unwrap_err(),
        ErrorKind::PeerClosed,
        Delivery::Unknown,
    );
    assert!(client.is_closed());
    assert_local(
        client
            .request_typed(&SetCpuTarget::new(1))
            .await
            .unwrap_err(),
        ErrorKind::Closed,
        Delivery::NotSent,
    );
    assert_eq!(connector.dials.load(Ordering::SeqCst), 1);
    peer.await.unwrap();
}

#[tokio::test]
async fn legacy_json_requests_do_not_inherit_the_framed_size_ceiling() {
    let (connector, mut peers) = QueueConnector::new(1);
    let stream = peers.pop().unwrap();
    let peer = tokio::spawn(async move {
        json_peer(stream, "secrets_update", br#"{"ok":true}"#).await;
    });
    let client = JsonControlClient::from_connector(connector);
    let reply = client
        .request(TypedMessage::new(
            "control.secrets.update",
            SecretsUpdate {
                changes: vec![SecretChange::Rotate {
                    name: "large-test".into(),
                    value: SecretValue("x".repeat(4 * 1024 * 1024 + 100)),
                }],
            },
        ))
        .await
        .unwrap();
    assert_eq!(reply.value().get("ok").unwrap().as_bool(), Some(true));
    peer.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn setup_deadline_is_shared_across_discovery_and_redial() {
    let (mut connector, mut peers) = QueueConnector::new(2);
    Arc::get_mut(&mut connector).unwrap().delay = Duration::from_millis(30);
    let mut framed = peers.pop().unwrap();
    let discovery = peers.pop().unwrap();
    let peer = tokio::spawn(async move {
        json_peer(discovery, "capabilities", FRAMED_CAPS).await;
        assert_eq!(
            framed.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    });
    let started = Instant::now();
    let error = ControlConnection::connect_connector_with(connector.clone(), |o| {
        o.setup_timeout(Duration::from_millis(50))
    })
    .await
    .err()
    .unwrap();
    assert_local(error, ErrorKind::Timeout, Delivery::NotSent);
    assert!(started.elapsed() < Duration::from_millis(60));
    assert_eq!(connector.dials.load(Ordering::SeqCst), 2);
    peer.await.unwrap();
}

#[tokio::test]
async fn shared_close_wakes_an_admitted_json_request_without_replaying_it() {
    let (connector, mut peers) = QueueConnector::new(1);
    let mut stream = peers.pop().unwrap();
    let (sent, received) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let mut line = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut line)
            .await
            .unwrap();
        sent.send(()).unwrap();
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    });
    let client = JsonControlClient::from_connector(connector.clone());
    let other = client.clone();
    let request = tokio::spawn(async move { other.request_typed(&SetCpuTarget::new(1)).await });
    received.await.unwrap();
    client.close().await;
    assert_local(
        request.await.unwrap().unwrap_err(),
        ErrorKind::Closed,
        Delivery::Unknown,
    );
    assert_eq!(connector.dials.load(Ordering::SeqCst), 1);
    peer.await.unwrap();
}

#[tokio::test]
async fn shared_close_cancels_verification_before_framed_writer_admission() {
    let (connector, mut peers) = QueueConnector::new(2);
    let mut framed = peers.pop().unwrap();
    let discovery = peers.pop().unwrap();
    let peer = tokio::spawn(async move {
        json_peer(discovery, "capabilities", FRAMED_CAPS).await;
        welcome(&mut framed).await;
        // No operation bytes can reach this connection after hello.
        assert_eq!(
            framed.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    });
    let client = ControlConnection::connect_verified_connector(connector.clone())
        .await
        .unwrap();
    connector.stall_verification.store(true, Ordering::SeqCst);
    let other = client.clone();
    let request = tokio::spawn(async move { other.request_typed(&SetCpuTarget::new(2)).await });
    connector.verification_started.notified().await;
    client.close().await;
    let result = tokio::time::timeout(Duration::from_secs(1), request)
        .await
        .unwrap()
        .unwrap();
    assert_local(result.unwrap_err(), ErrorKind::Closed, Delivery::NotSent);
    assert!(client.is_closed());
    peer.await.unwrap();
}

#[tokio::test]
async fn discovery_reply_ceiling_and_unexpected_eof_are_not_legacy_evidence() {
    for oversize in [true, false] {
        let (connector, mut peers) = QueueConnector::new(1);
        let mut stream = peers.pop().unwrap();
        let peer = tokio::spawn(async move {
            let mut line = String::new();
            BufReader::new(&mut stream)
                .read_line(&mut line)
                .await
                .unwrap();
            if oversize {
                // No newline: the client must reject excess before waiting for
                // completion or treating the close as a successful discovery.
                let _ = stream
                    .write_all(&vec![b' '; MAX_DISCOVERY_RESPONSE_SIZE + 1])
                    .await;
            }
        });
        let error = ControlConnection::connect_connector(connector.clone())
            .await
            .err()
            .unwrap();
        assert_local(
            error,
            if oversize {
                ErrorKind::InvalidData
            } else {
                ErrorKind::PeerClosed
            },
            Delivery::NotSent,
        );
        assert_eq!(connector.dials.load(Ordering::SeqCst), 1);
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn ordinary_json_accepts_eof_delimiter_and_retains_only_the_first_response_line() {
    for tail in [b"".as_slice(), b"\nsecond line must not enter the reply"] {
        let (connector, mut peers) = QueueConnector::new(1);
        let mut stream = peers.pop().unwrap();
        let tail = tail.to_vec();
        let peer = tokio::spawn(async move {
            let mut line = String::new();
            BufReader::new(&mut stream)
                .read_line(&mut line)
                .await
                .unwrap();
            stream.write_all(b" \t{\"ok\":true} ").await.unwrap();
            stream.write_all(&tail).await.unwrap();
        });
        let client = JsonControlClient::from_connector(connector);
        let reply = client
            .request(TypedMessage::new(
                "control.secrets.update",
                SecretsUpdate { changes: vec![] },
            ))
            .await
            .unwrap();
        assert!(reply.raw() == b" \t{\"ok\":true} " || reply.raw() == b" \t{\"ok\":true} \n");
        assert!(!client.is_closed());
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn failed_rediscovery_is_not_sent_for_the_prepared_mutation() {
    let (connector, mut peers) = QueueConnector::new(2);
    let mut failed_probe = peers.pop().unwrap();
    let discovery = peers.pop().unwrap();
    let peer = tokio::spawn(async move {
        json_peer(discovery, "capabilities", LEGACY_CAPS).await;
        let mut line = String::new();
        BufReader::new(&mut failed_probe)
            .read_line(&mut line)
            .await
            .unwrap();
        assert_eq!(line, "{\"op\":\"capabilities\"}\n");
    });
    let client = ControlConnection::connect_connector(connector.clone())
        .await
        .unwrap();
    assert_local(
        client
            .request_typed(&SetCpuTarget::new(2))
            .await
            .unwrap_err(),
        ErrorKind::PeerClosed,
        Delivery::NotSent,
    );
    assert!(client.is_closed());
    assert_eq!(connector.dials.load(Ordering::SeqCst), 2);
    peer.await.unwrap();
}

#[tokio::test]
async fn mismatched_connected_peer_is_runtime_changed_before_any_operation_bytes() {
    let (connector, mut peers) = QueueConnector::new(2);
    let mut replacement = peers.pop().unwrap();
    let discovery = peers.pop().unwrap();
    let peer = tokio::spawn(async move {
        json_peer(discovery, "capabilities", LEGACY_CAPS).await;
        assert_eq!(
            replacement.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    });
    let client = ControlConnection::connect_verified_connector(connector.clone())
        .await
        .unwrap();
    connector.peer_valid.store(false, Ordering::SeqCst);
    let error = client
        .request_typed(&SetCpuTarget::new(2))
        .await
        .unwrap_err();
    assert_eq!(error.delivery(), Delivery::NotSent);
    assert!(matches!(error, ControlClientError::RuntimeChanged));
    assert!(client.is_closed());
    assert_eq!(connector.dials.load(Ordering::SeqCst), 2);
    peer.await.unwrap();
}
