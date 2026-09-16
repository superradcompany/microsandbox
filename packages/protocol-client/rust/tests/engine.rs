//! External-consumer tests: custom protocols use only public extension APIs.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use microsandbox_protocol::{codec, wire::Envelope};
use microsandbox_protocol_client::{
    BoxFuture, BoxTransport, CborEnvelopeCodec, Client, ClientError, ClientLimits, ClientResult,
    ConnectOptions, Connector, Delivery, EncodedMessage, ErrorKind, Established, IdRange, Protocol,
    RawFrame, Request, SendMetadata, TypedMessage,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

#[cfg(all(windows, feature = "named-pipe"))]
#[path = "platform/named_pipe.rs"]
mod named_pipe;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct ExternalProtocol;

struct CheckedRequest;

struct CountingConnector(AtomicUsize);

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Connector for CountingConnector {
    fn connect(&self, _: tokio::time::Instant) -> BoxFuture<'_, ClientResult<BoxTransport>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(ClientError::new(ErrorKind::PeerClosed)) })
    }
}

impl Protocol for ExternalProtocol {
    type Ready = u8;

    fn establish(
        mut stream: BoxTransport,
        options: ConnectOptions,
    ) -> BoxFuture<'static, ClientResult<Established<u8>>> {
        Box::pin(async move {
            let ready = stream.read_u8().await?;
            Ok(Established {
                transport: stream,
                codec: Arc::new(CborEnvelopeCodec),
                ids: IdRange {
                    start: 1,
                    end_exclusive: 1u64 << 32,
                },
                ready,
                limits: options.limits,
            })
        })
    }

    fn prepare(ready: &u8, name: &str) -> ClientResult<SendMetadata> {
        if name == "future.gated" && *ready < 2 {
            return Err(ClientError::new(ErrorKind::UnsupportedOperation));
        }
        Ok(SendMetadata {
            generation: *ready,
            flags: 2,
        })
    }
}

impl Request<ExternalProtocol> for CheckedRequest {
    type Response = u64;
    type Error = ClientError;

    fn message(&self) -> ClientResult<EncodedMessage> {
        Ok(EncodedMessage::new("future.checked", [0xa0]))
    }

    fn decode(&self, message: microsandbox_protocol_client::Message) -> ClientResult<u64> {
        if message.t != "future.checked.result" {
            return Err(ClientError::new(ErrorKind::InvalidData).with_delivery(Delivery::Unknown));
        }
        message.payload()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn pair(ids: IdRange, limits: ClientLimits) -> (Client<ExternalProtocol>, DuplexStream) {
    let (transport, server) = tokio::io::duplex(1024);
    let client = Client::from_established(Established {
        transport: Box::new(transport),
        codec: Arc::new(CborEnvelopeCodec),
        ids,
        ready: 1,
        limits,
    })
    .await
    .unwrap();
    (client, server)
}

async fn read(server: &mut DuplexStream) -> RawFrame {
    tokio::time::timeout(Duration::from_secs(2), codec::read_raw_frame(server))
        .await
        .unwrap()
        .unwrap()
}

async fn reply(server: &mut DuplexStream, id: u32, flags: u8, body: Vec<u8>) {
    codec::write_raw_frame(server, &RawFrame { id, flags, body })
        .await
        .unwrap();
}

fn only_id() -> IdRange {
    IdRange {
        start: 1,
        end_exclusive: 2,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn invalid_or_expired_setup_does_not_dial_or_establish() {
    let connector = CountingConnector(AtomicUsize::new(0));
    for (timeout, kind) in [
        (Duration::MAX, ErrorKind::InvalidOptions),
        (Duration::ZERO, ErrorKind::Timeout),
    ] {
        let error = Client::<ExternalProtocol>::connect_connector_with(&connector, |options| {
            options.setup_timeout(timeout)
        })
        .await
        .err()
        .unwrap();
        assert_eq!(error.kind, kind);
        assert_eq!(error.delivery, Delivery::NotSent);

        // A ready handshake would complete in one poll. Expired setup must
        // still fail before that poll instead of succeeding through timeout_at.
        let (transport, mut peer) = tokio::io::duplex(1024);
        peer.write_u8(1).await.unwrap();
        let error = Client::<ExternalProtocol>::connect_stream_with(transport, |options| {
            options.setup_timeout(timeout)
        })
        .await
        .err()
        .unwrap();
        assert_eq!(error.kind, kind);
        assert_eq!(
            peer.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
    assert_eq!(connector.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unrepresentable_connection_timers_are_rejected_before_workers_start() {
    for limits in [
        ClientLimits {
            incomplete_frame_timeout: Some(Duration::MAX),
            ..ClientLimits::default()
        },
        ClientLimits {
            request_timeout: Some(Duration::MAX),
            ..ClientLimits::default()
        },
    ] {
        let (transport, mut peer) = tokio::io::duplex(1024);
        let result = Client::<ExternalProtocol>::from_established(Established {
            transport: Box::new(transport),
            codec: Arc::new(CborEnvelopeCodec),
            ids: only_id(),
            ready: 1,
            limits,
        })
        .await;
        assert_eq!(result.err().unwrap().kind, ErrorKind::InvalidOptions);
        assert_eq!(
            peer.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
}

#[tokio::test]
async fn invalid_or_zero_request_waits_do_not_admit_bytes_or_leak_the_id() {
    let (client, mut server) = pair(only_id(), ClientLimits::default()).await;
    for (timeout, kind) in [
        (Duration::MAX, ErrorKind::InvalidOptions),
        (Duration::ZERO, ErrorKind::Timeout),
    ] {
        let error = client
            .request_raw_with(0, vec![1], |options| options.request_timeout(timeout))
            .await
            .unwrap_err();
        assert_eq!(error.kind, kind);
        assert_eq!(error.delivery, Delivery::NotSent);
        let error = client
            .stream_raw_with(0, vec![2], |options| options.request_timeout(timeout))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind, kind);
        assert_eq!(error.delivery, Delivery::NotSent);
    }
    let peer = tokio::spawn(async move {
        // If any failed attempt admitted bytes, this first frame is wrong.
        let frame = read(&mut server).await;
        assert_eq!(frame.id, 1);
        assert_eq!(frame.body, [3]);
        reply(&mut server, frame.id, 1, vec![4]).await;
    });
    assert_eq!(client.request_raw(0, vec![3]).await.unwrap().body, [4]);
    peer.await.unwrap();
}

#[tokio::test]
async fn custom_protocol_and_native_encoded_unknown_messages() {
    let (transport, mut server) = tokio::io::duplex(1024);
    server.write_all(&[1]).await.unwrap();
    let client = Client::<ExternalProtocol>::connect_stream(transport)
        .await
        .unwrap();
    assert_eq!(*client.ready(), 1);
    let peer = tokio::spawn(async move {
        let native = read(&mut server).await;
        let decoded = Envelope::decode(&native.body).unwrap();
        assert_eq!(native.flags, 2);
        assert_eq!(decoded.t, "future.native");
        assert_eq!(decoded.p, [0xa1, 0x65, b'v', b'a', b'l', b'u', b'e', 7]);
        reply(&mut server, native.id, 1, native.body).await;
        let encoded = read(&mut server).await;
        let decoded = Envelope::decode(&encoded.body).unwrap();
        // Raw CBOR supplied by the caller is allowed to be noncanonical, or even
        // invalid application data. The engine must not normalize or parse it.
        assert_eq!(decoded.p, [0xff, 0x00, 0x18, 0x01]);
        let mut body = encoded.body;
        assert_eq!(body[0], 0xa3);
        body[0] = 0xa4;
        body.extend_from_slice(&[0x65, b'e', b'x', b't', b'r', b'a', 0xf5]);
        reply(&mut server, encoded.id, 1, body.clone()).await;
        body
    });
    let native = client
        .request(TypedMessage::new(
            "future.native",
            std::collections::BTreeMap::from([("value", 7u8)]),
        ))
        .await
        .unwrap();
    assert_eq!(native.t, "future.native");
    let message = client
        .request(EncodedMessage::new("future.encoded", [0xff, 0, 0x18, 1]))
        .await
        .unwrap();
    assert_eq!(message.p, [0xff, 0, 0x18, 1]);
    assert_eq!(message.into_raw().body, peer.await.unwrap());
}

#[tokio::test]
async fn concurrent_raw_requests_route_reordered_fragmented_frames_across_u32_max() {
    let (client, mut server) = pair(
        IdRange {
            start: u32::MAX - 31,
            end_exclusive: 1u64 << 32,
        },
        ClientLimits::default(),
    )
    .await;
    let peer = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in 0..32 {
            requests.push(read(&mut server).await);
        }
        assert!(requests.iter().any(|request| request.id == u32::MAX));
        for request in requests.into_iter().rev() {
            let mut packet = Vec::new();
            codec::encode_raw_to_buf(
                &RawFrame {
                    flags: 1,
                    ..request
                },
                &mut packet,
            )
            .unwrap();
            for byte in packet {
                server.write_all(&[byte]).await.unwrap();
            }
        }
    });
    let mut requests = Vec::new();
    for n in 0..32u8 {
        let client = client.clone();
        requests.push(tokio::spawn(async move {
            let response = client.request_raw(0, vec![0xff, n]).await.unwrap();
            assert_eq!(response.body, [0xff, n]);
        }));
    }
    for request in requests {
        request.await.unwrap();
    }
    peer.await.unwrap();
}

#[tokio::test]
async fn split_retains_connection_terminal_delivers_once_and_stale_sender_is_rejected() {
    let (client, mut server) = pair(only_id(), ClientLimits::default()).await;
    let stream = client.stream_raw(0, vec![9]).await.unwrap();
    let (sender, mut receiver) = stream.into_parts();
    let cloned = sender.clone();
    assert_eq!(read(&mut server).await.id, 1);
    drop(sender);
    cloned.send(0, &[8]).await.unwrap();
    assert_eq!(read(&mut server).await.body, [8]);
    reply(&mut server, 1, 0, vec![1]).await;
    reply(&mut server, 1, 1, vec![2]).await;
    assert_eq!(receiver.recv().await.unwrap().unwrap().body, [1]);
    assert_eq!(receiver.recv().await.unwrap().unwrap().body, [2]);
    assert!(receiver.recv().await.unwrap().is_none());
    let next = client.stream_raw(0, vec![3]).await.unwrap();
    assert_eq!(read(&mut server).await.body, [3]);
    assert_eq!(
        cloned.send(0, &[0xaa]).await.unwrap_err().kind,
        ErrorKind::StreamClosed
    );
    drop(client);
    drop(receiver);
    drop(cloned);
    // The remaining stream owns the connection after the original client drops.
    next.send(0, &[4]).await.unwrap();
    assert_eq!(read(&mut server).await.body, [4]);
    drop(next);
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), server.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn receiver_drop_disables_sends_and_keeps_id_until_terminal() {
    let (client, mut server) = pair(only_id(), ClientLimits::default()).await;
    let stream = client.stream_raw(0, vec![0]).await.unwrap();
    let (sender, receiver) = stream.into_parts();
    read(&mut server).await;
    drop(receiver);
    assert_eq!(
        sender.send(0, &[1]).await.unwrap_err().kind,
        ErrorKind::StreamClosed
    );
    assert_eq!(
        client.request_raw(0, vec![]).await.unwrap_err().kind,
        ErrorKind::IdRangeExhausted
    );
    reply(&mut server, 1, 0, vec![7]).await;
    reply(&mut server, 1, 1, vec![8]).await;
    // Wait for actual router progress without assuming task scheduling order.
    let next = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match client.stream_raw(0, vec![2]).await {
                Ok(stream) => break stream,
                Err(error) if error.kind == ErrorKind::IdRangeExhausted => {
                    tokio::task::yield_now().await
                }
                Err(error) => panic!("{error}"),
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(read(&mut server).await.body, [2]);
    assert_eq!(
        sender.send(0, &[3]).await.unwrap_err().kind,
        ErrorKind::StreamClosed
    );
    drop(next);
}

#[tokio::test]
async fn first_nonterminal_unary_response_drains_without_releasing_id() {
    let (client, mut server) = pair(only_id(), ClientLimits::default()).await;
    let task = {
        let client = client.clone();
        tokio::spawn(async move { client.request_raw(0, vec![0]).await.unwrap() })
    };
    let opening = read(&mut server).await;
    reply(&mut server, opening.id, 0, vec![1]).await;
    assert_eq!(task.await.unwrap().body, [1]);
    assert_eq!(
        client.request_raw(0, vec![2]).await.unwrap_err().kind,
        ErrorKind::IdRangeExhausted
    );
    assert_eq!(
        client.send_raw(1, 0, &[3]).await.unwrap_err().kind,
        ErrorKind::StreamClosed
    );
}

#[tokio::test]
async fn request_timeout_after_admission_reports_unknown_and_does_not_replay() {
    let (client, mut server) = pair(only_id(), ClientLimits::default()).await;
    let call = {
        let client = client.clone();
        tokio::spawn(async move {
            client
                .request_raw_with(0, vec![1], |o| o.request_timeout(Duration::from_millis(20)))
                .await
        })
    };
    read(&mut server).await;
    let error = call.await.unwrap().unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout);
    assert_eq!(error.delivery, Delivery::Unknown);
    assert_eq!(
        client.request_raw(0, vec![2]).await.unwrap_err().kind,
        ErrorKind::IdRangeExhausted
    );
    let mut byte = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), server.read(&mut byte))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn request_cancel_before_admission_reports_not_sent_and_releases_id() {
    let limits = ClientLimits {
        max_frame_size: 12,
        buffered_bytes: 16,
        ..Default::default()
    };
    let (transport, mut server) = tokio::io::duplex(1);
    let client = Client::<ExternalProtocol>::from_established(Established {
        transport: Box::new(transport),
        codec: Arc::new(CborEnvelopeCodec),
        ids: only_id(),
        ready: 1,
        limits,
    })
    .await
    .unwrap();
    let blocked = {
        let client = client.clone();
        tokio::spawn(async move {
            client.write_unchecked(vec![0xaa; 16]).await.unwrap();
        })
    };
    let mut first = [0];
    server.read_exact(&mut first).await.unwrap(); // Proves the byte budget is held by the blocked writer.
    let error = client
        .request_raw_with(0, vec![], |o| o.request_timeout(Duration::from_millis(20)))
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout);
    assert_eq!(error.delivery, Delivery::NotSent);
    let mut rest = [0; 15];
    server.read_exact(&mut rest).await.unwrap();
    blocked.await.unwrap();
    let next = {
        let client = client.clone();
        tokio::spawn(async move { client.request_raw(0, vec![]).await.unwrap() })
    };
    assert_eq!(read(&mut server).await.id, 1);
    reply(&mut server, 1, 1, vec![]).await;
    next.await.unwrap();
}

#[tokio::test]
async fn closure_waiters_observe_idle_disconnect_and_late_subscription() {
    let (client, server) = pair(only_id(), ClientLimits::default()).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(10), client.closed())
            .await
            .is_err()
    );
    assert!(!client.is_closed());
    let peer = client.clone();
    let waiter = tokio::spawn(async move { peer.closed().await });
    drop(server);
    tokio::time::timeout(Duration::from_secs(1), waiter)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), client.closed())
        .await
        .unwrap();
}

#[tokio::test]
async fn shared_close_wakes_pending_and_rejects_future_operations() {
    let (client, mut server) = pair(only_id(), ClientLimits::default()).await;
    let mut stream = client.stream_raw(0, vec![1]).await.unwrap();
    read(&mut server).await;
    client.clone().close().await;
    let error = stream.recv().await.unwrap_err();
    assert_eq!(error.kind, ErrorKind::Closed);
    assert_eq!(error.delivery, Delivery::Unknown);
    assert!(stream.recv().await.unwrap().is_none());
    assert!(client.is_closed());
    let error = client.request_raw(0, vec![2]).await.unwrap_err();
    assert_eq!(error.delivery, Delivery::NotSent);
}

#[tokio::test]
async fn incomplete_eof_and_idle_eof_are_distinct_from_terminal() {
    for (bytes, expected) in [
        (vec![], ErrorKind::PeerClosed),
        (vec![0, 0], ErrorKind::TruncatedFrame),
    ] {
        let (client, mut server) = pair(only_id(), ClientLimits::default()).await;
        let mut stream = client.stream_raw(0, vec![1]).await.unwrap();
        read(&mut server).await;
        server.write_all(&bytes).await.unwrap();
        drop(server);
        let error = stream.recv().await.unwrap_err();
        assert_eq!(error.kind, expected);
        assert_eq!(error.delivery, Delivery::Unknown);
    }
}

#[tokio::test]
async fn gates_and_oversize_fail_before_any_bytes_or_ids_are_admitted() {
    let (client, mut server) = pair(only_id(), ClientLimits::default()).await;
    let error = client
        .request(TypedMessage::new("future.gated", ()))
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::UnsupportedOperation);
    assert_eq!(error.delivery, Delivery::NotSent);
    let error = client
        .request_raw(0, vec![0; 4 * 1024 * 1024])
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Capacity);
    assert_eq!(error.delivery, Delivery::NotSent);
    client.write_unchecked(vec![4, 3, 2, 1]).await.unwrap();
    let mut bytes = [0; 4];
    server.read_exact(&mut bytes).await.unwrap();
    assert_eq!(bytes, [4, 3, 2, 1]);
    let error = client.send_raw(1, 0, &[]).await.unwrap_err();
    assert_eq!(error.kind, ErrorKind::StreamClosed);
}

#[tokio::test]
async fn frame_timeout_is_absolute_but_idle_connection_remains_open() {
    let limits = ClientLimits {
        incomplete_frame_timeout: Some(Duration::from_millis(30)),
        ..Default::default()
    };
    let (client, mut server) = pair(only_id(), limits).await;
    let mut stream = client.stream_raw(0, vec![1]).await.unwrap();
    read(&mut server).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!client.is_closed());
    server.write_all(&[0]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    server.write_all(&[0]).await.unwrap();
    let error = tokio::time::timeout(Duration::from_millis(25), stream.recv())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout);
}

#[test]
fn public_id_ranges_validate_full_u32_space_without_overflow() {
    assert!(
        IdRange {
            start: 1,
            end_exclusive: 1u64 << 32
        }
        .validate()
        .is_ok()
    );
    assert!(
        IdRange {
            start: u32::MAX,
            end_exclusive: 1u64 << 32
        }
        .validate()
        .is_ok()
    );
    for ids in [
        IdRange {
            start: 0,
            end_exclusive: 2,
        },
        IdRange {
            start: 2,
            end_exclusive: 2,
        },
        IdRange {
            start: 1,
            end_exclusive: (1u64 << 32) + 1,
        },
    ] {
        assert!(ids.validate().is_err());
    }
}

#[tokio::test]
async fn checked_request_borrows_input_requires_terminal_and_retains_drain() {
    let (client, mut server) = pair(only_id(), ClientLimits::default()).await;
    let request = CheckedRequest;
    let peer = tokio::spawn(async move {
        let first = read(&mut server).await;
        reply(
            &mut server,
            first.id,
            1,
            Envelope::new(1, "future.checked.result", &u64::MAX)
                .unwrap()
                .encode()
                .unwrap(),
        )
        .await;
        let second = read(&mut server).await;
        reply(
            &mut server,
            second.id,
            0,
            Envelope::new(1, "future.checked.result", &7u64)
                .unwrap()
                .encode()
                .unwrap(),
        )
        .await;
        server
    });
    assert_eq!(client.request_typed(&request).await.unwrap(), u64::MAX);
    let error = client.request_typed(&request).await.unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidData);
    assert_eq!(error.delivery, Delivery::Unknown);
    let _server = peer.await.unwrap();
    assert_eq!(
        client.request_typed(&request).await.unwrap_err().kind,
        ErrorKind::IdRangeExhausted
    );
}

#[tokio::test]
async fn dropping_unary_future_after_admission_does_not_recycle_id() {
    let (client, mut server) = pair(only_id(), ClientLimits::default()).await;
    let call = {
        let client = client.clone();
        tokio::spawn(async move { client.request_raw(0, vec![1]).await })
    };
    read(&mut server).await;
    call.abort();
    assert!(call.await.unwrap_err().is_cancelled());
    assert_eq!(
        client.request_raw(0, vec![2]).await.unwrap_err().kind,
        ErrorKind::IdRangeExhausted
    );
    assert_eq!(
        client.send_raw(1, 0, &[3]).await.unwrap_err().kind,
        ErrorKind::StreamClosed
    );
}

#[tokio::test]
async fn dropped_slow_receiver_unblocks_bounded_connection_backpressure() {
    let limits = ClientLimits {
        queued_responses: 1,
        max_in_flight: 2,
        ..Default::default()
    };
    let (client, mut server) = pair(
        IdRange {
            start: 1,
            end_exclusive: 3,
        },
        limits,
    )
    .await;
    let slow = client.stream_raw(0, vec![1]).await.unwrap();
    read(&mut server).await;
    let mut other = client.stream_raw(0, vec![2]).await.unwrap();
    read(&mut server).await;
    reply(&mut server, slow.id(), 0, vec![1]).await;
    reply(&mut server, slow.id(), 0, vec![2]).await;
    reply(&mut server, other.id(), 1, vec![3]).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), other.recv())
            .await
            .is_err()
    );
    drop(slow);
    let frame = tokio::time::timeout(Duration::from_secs(1), other.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(frame.body, [3]);
}

#[cfg(all(unix, feature = "uds"))]
#[tokio::test]
async fn native_unix_connector_and_setup_deadline_use_real_sockets() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("generic.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(&[1]).await.unwrap();
        let request = codec::read_raw_frame(&mut socket).await.unwrap();
        codec::write_raw_frame(
            &mut socket,
            &RawFrame {
                flags: 1,
                ..request
            },
        )
        .await
        .unwrap();
        let (_stalled_socket, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    });
    let client = Client::<ExternalProtocol>::connect(&path).await.unwrap();
    assert_eq!(
        client.request_raw(0, vec![0xff, 5]).await.unwrap().body,
        [0xff, 5]
    );
    let result = Client::<ExternalProtocol>::connect_with(&path, |o| {
        o.setup_timeout(Duration::from_millis(20))
    })
    .await;
    assert!(matches!(
        result,
        Err(ClientError {
            kind: ErrorKind::Timeout,
            delivery: Delivery::NotSent
        })
    ));
    peer.await.unwrap();
}

#[tokio::test]
async fn cancelled_partial_write_finishes_packet_and_drains_before_id_reuse() {
    for expire in [false, true] {
        // One byte of capacity prevents the whole packet from reaching the peer
        // before cancellation, even after the first observed byte frees space.
        let (transport, mut server) = tokio::io::duplex(1);
        let client = Client::<ExternalProtocol>::from_established(Established {
            transport: Box::new(transport),
            codec: Arc::new(CborEnvelopeCodec),
            ids: only_id(),
            ready: 1,
            limits: ClientLimits::default(),
        })
        .await
        .unwrap();
        let body = vec![0x31; 64];
        let mut expected = Vec::new();
        codec::encode_raw_to_buf(
            &RawFrame {
                id: 1,
                flags: 0,
                body: body.clone(),
            },
            &mut expected,
        )
        .unwrap();
        let call = {
            let client = client.clone();
            tokio::spawn(async move {
                if expire {
                    client
                        .request_raw_with(0, body, |o| o.request_timeout(Duration::from_millis(20)))
                        .await
                } else {
                    client.request_raw(0, body).await
                }
            })
        };
        let mut received = vec![0; expected.len()];
        tokio::time::timeout(
            Duration::from_secs(1),
            server.read_exact(&mut received[..1]),
        )
        .await
        .unwrap()
        .unwrap();
        if expire {
            let error = call.await.unwrap().unwrap_err();
            assert_eq!(error.kind, ErrorKind::Timeout);
            assert_eq!(error.delivery, Delivery::Unknown);
        } else {
            call.abort();
            assert!(call.await.unwrap_err().is_cancelled());
        }
        assert!(!client.is_closed());
        assert_eq!(
            client.send_raw(1, 0, &[9]).await.unwrap_err().kind,
            ErrorKind::StreamClosed
        );
        assert_eq!(
            client.request_raw(0, vec![2]).await.unwrap_err().kind,
            ErrorKind::IdRangeExhausted
        );

        // Cancellation drops only the waiter. The owned writer must finish this
        // exact packet, while the abandoned ID remains reserved for late replies.
        tokio::time::timeout(
            Duration::from_secs(1),
            server.read_exact(&mut received[1..]),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, expected);
        assert_eq!(
            client.request_raw(0, vec![2]).await.unwrap_err().kind,
            ErrorKind::IdRangeExhausted
        );
        reply(&mut server, 1, 0, vec![0x71]).await;
        reply(&mut server, 1, 1, vec![0x72]).await;

        // The router may still be consuming the terminal byte. Retry only local
        // reservation failures; exactly one subsequent request reaches the wire.
        let next = {
            let client = client.clone();
            tokio::spawn(async move {
                tokio::time::timeout(Duration::from_secs(1), async {
                    loop {
                        match client.request_raw(0, vec![0x22]).await {
                            Err(error) if error.kind == ErrorKind::IdRangeExhausted => {
                                tokio::task::yield_now().await;
                            }
                            result => break result.unwrap(),
                        }
                    }
                })
                .await
                .unwrap()
            })
        };
        let request = read(&mut server).await;
        assert_eq!(request.id, 1);
        assert_eq!(request.body, [0x22]);
        reply(&mut server, 1, 1, vec![0x44]).await;
        assert_eq!(next.await.unwrap().body, [0x44]);
        client.close().await;
        let mut byte = [0];
        assert_eq!(server.read(&mut byte).await.unwrap(), 0);
    }
}
