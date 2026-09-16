//! An external protocol controls its envelope using only exported APIs.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use microsandbox_protocol::{codec, wire::Envelope};
use microsandbox_protocol_client::{
    BoxFuture, BoxTransport, Client, ClientError, ClientResult, ConnectOptions, Connector,
    Delivery, EncodedMessage, EnvelopeCodec, ErrorKind, Established, IdRange, Message, Protocol,
    RawFrame, Request, SendMetadata, TypedMessage,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::Instant;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct ExternalProtocol;

struct ExternalCodec;

struct ExternalConnector {
    stream: Mutex<Option<DuplexStream>>,
    calls: AtomicUsize,
}

struct CheckedNumber;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Connector for ExternalConnector {
    fn connect(&self, deadline: Instant) -> BoxFuture<'_, ClientResult<BoxTransport>> {
        Box::pin(async move {
            assert!(deadline > Instant::now());
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(self.stream.lock().unwrap().take().unwrap()) as BoxTransport)
        })
    }
}

impl Protocol for ExternalProtocol {
    type Ready = u8;

    fn establish(
        mut transport: BoxTransport,
        options: ConnectOptions,
    ) -> BoxFuture<'static, ClientResult<Established<u8>>> {
        Box::pin(async move {
            let ready = transport.read_u8().await?;
            Ok(Established {
                transport,
                codec: Arc::new(ExternalCodec),
                ids: IdRange {
                    start: u32::MAX - 1,
                    end_exclusive: 1u64 << 32,
                },
                ready,
                limits: options.limits,
            })
        })
    }

    fn prepare(ready: &u8, _: &str) -> ClientResult<SendMetadata> {
        Ok(SendMetadata {
            generation: *ready,
            flags: 2,
        })
    }
}

impl EnvelopeCodec for ExternalCodec {
    fn encode(&self, generation: u8, name: &str, payload: Vec<u8>) -> ClientResult<Vec<u8>> {
        let length = u8::try_from(name.len()).map_err(|_| ClientError::new(ErrorKind::Encode))?;
        // This envelope deliberately cannot be decoded as a CBOR map. Native
        // payloads still use the Rust client's documented CBOR serialization.
        let mut bytes = vec![generation, length];
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend(payload);
        Ok(bytes)
    }

    fn decode(&self, frame: RawFrame) -> ClientResult<Message> {
        let invalid = || ClientError::new(ErrorKind::InvalidData);
        let generation = *frame.body.first().ok_or_else(invalid)?;
        let end = 2 + usize::from(*frame.body.get(1).ok_or_else(invalid)?);
        let name = std::str::from_utf8(frame.body.get(2..end).ok_or_else(invalid)?)
            .map_err(|_| invalid())?
            .to_owned();
        let envelope = Envelope {
            v: generation,
            t: name,
            p: frame.body[end..].to_vec(),
        };
        Ok(Message::new(frame, envelope))
    }
}

impl Request<ExternalProtocol> for CheckedNumber {
    type Response = u64;
    type Error = ClientError;

    fn message(&self) -> ClientResult<EncodedMessage> {
        Ok(EncodedMessage::new("custom.checked", [0x18, 0x2a]))
    }

    fn decode(&self, message: Message) -> ClientResult<u64> {
        assert_eq!(message.t, "custom.checked");
        assert_eq!(message.flags, 1);
        message.payload()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn read(peer: &mut DuplexStream) -> RawFrame {
    codec::read_raw_frame(peer).await.unwrap()
}

async fn echo(peer: &mut DuplexStream, mut frame: RawFrame) {
    frame.flags = 1;
    codec::write_raw_frame(peer, &frame).await.unwrap();
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn external_connector_and_non_cbor_codec_cover_every_access_level() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (transport, mut peer) = tokio::io::duplex(1024);
        let connector = ExternalConnector {
            stream: Mutex::new(Some(transport)),
            calls: AtomicUsize::new(0),
        };
        peer.write_u8(7).await.unwrap();
        let connecting = Client::<ExternalProtocol>::connect_connector(&connector);
        assert_eq!(connector.calls.load(Ordering::SeqCst), 0);
        let client = connecting.await.unwrap();
        assert_eq!(connector.calls.load(Ordering::SeqCst), 1);
        assert_eq!(*client.ready(), 7);

        let server = tokio::spawn(async move {
            let native = read(&mut peer).await;
            assert_eq!(native.id, u32::MAX - 1);
            assert_eq!(native.flags, 2);
            assert_eq!(native.body, b"\x07\x0dcustom.native\x11");
            echo(&mut peer, native).await;

            let encoded = read(&mut peer).await;
            assert_eq!(encoded.id, u32::MAX);
            assert_eq!(encoded.body, b"\x07\x0ecustom.encoded\xff\x00");
            echo(&mut peer, encoded).await;

            let raw = read(&mut peer).await;
            assert_eq!(raw.flags, 0xd6);
            assert_eq!(raw.body, [0xff, 0]);
            echo(&mut peer, raw).await;

            let checked = read(&mut peer).await;
            assert_eq!(checked.body, b"\x07\x0ecustom.checked\x18\x2a");
            echo(&mut peer, checked).await;

            let opening = read(&mut peer).await;
            assert_eq!(opening.body, b"\x07\x0dcustom.stream\xf6");
            for _ in 0..2 {
                let sent = read(&mut peer).await;
                assert_eq!(sent.id, opening.id);
                assert_eq!(sent.body, b"\x07\x0ccustom.chunk\xff\x00");
            }
            echo(&mut peer, opening).await;

            let raw_opening = read(&mut peer).await;
            assert_eq!(raw_opening.flags, 2);
            assert_eq!(raw_opening.body, [0xff, 0]);
            for _ in 0..2 {
                let sent = read(&mut peer).await;
                assert_eq!(sent.id, raw_opening.id);
                assert_eq!(sent.flags, 0xa0);
                assert_eq!(sent.body, [0xff, 0]);
            }
            echo(&mut peer, raw_opening).await;

            // Exact writes have neither a length prefix nor an allocated ID.
            let mut exact = [0; 4];
            peer.read_exact(&mut exact).await.unwrap();
            assert_eq!(exact, [0xde, 0xad, 0, 0xbe]);
            let mut byte = [0];
            assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
        });

        let native = client
            .request(TypedMessage::new("custom.native", 17u8))
            .await
            .unwrap();
        assert_eq!(native.payload::<u8>().unwrap(), 17);
        assert_eq!(native.raw().body, b"\x07\x0dcustom.native\x11");
        let encoded = client
            .request(EncodedMessage::new("custom.encoded", [0xff, 0]))
            .await
            .unwrap();
        assert_eq!(encoded.p, [0xff, 0]);
        assert_eq!(encoded.into_raw().body, b"\x07\x0ecustom.encoded\xff\x00");
        assert_eq!(
            client.request_raw(0xd6, vec![0xff, 0]).await.unwrap().body,
            [0xff, 0]
        );
        assert_eq!(client.request_typed(&CheckedNumber).await.unwrap(), 42);

        let stream = client
            .stream(TypedMessage::new("custom.stream", ()))
            .await
            .unwrap();
        let (sender, mut receiver) = stream.into_parts();
        sender
            .clone()
            .send(EncodedMessage::new("custom.chunk", [0xff, 0]))
            .await
            .unwrap();
        client
            .send(sender.id(), EncodedMessage::new("custom.chunk", [0xff, 0]))
            .await
            .unwrap();
        let terminal = receiver.recv().await.unwrap().unwrap();
        assert_eq!(terminal.t, "custom.stream");
        assert_eq!(terminal.flags, 1);
        assert!(receiver.recv().await.unwrap().is_none());
        assert_eq!(
            sender
                .send(TypedMessage::new("custom.chunk", ()))
                .await
                .unwrap_err()
                .delivery,
            Delivery::NotSent
        );

        let raw = client.stream_raw(2, vec![0xff, 0]).await.unwrap();
        let (sender, mut receiver) = raw.into_parts();
        sender.clone().send(0xa0, &[0xff, 0]).await.unwrap();
        client
            .send_raw(sender.id(), 0xa0, &[0xff, 0])
            .await
            .unwrap();
        assert_eq!(receiver.recv().await.unwrap().unwrap().body, [0xff, 0]);
        assert!(receiver.recv().await.unwrap().is_none());
        assert_eq!(
            sender.send(0xa0, &[0xff, 0]).await.unwrap_err().delivery,
            Delivery::NotSent
        );

        client
            .write_unchecked(vec![0xde, 0xad, 0, 0xbe])
            .await
            .unwrap();
        let sibling = client.clone();
        client.close().await;
        assert_eq!(
            sibling.request_raw(0, vec![1]).await.unwrap_err().delivery,
            Delivery::NotSent
        );
        server.await.unwrap();
    })
    .await
    .unwrap();
}
