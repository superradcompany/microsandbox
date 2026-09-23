//! Real Windows byte transports complement the platform-independent engine tests.

use std::path::PathBuf;
use std::time::Duration;

use microsandbox_protocol::codec;
use microsandbox_protocol_client::{
    Client, Connector, Delivery, ErrorKind, LocalConnector, RawFrame,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, PipeMode, ServerOptions};
use tokio::time::{Instant, timeout};

use super::ExternalProtocol;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn pipe_name(case: &str) -> PathBuf {
    // Each test has a distinct suffix; the process ID isolates concurrent Cargo runs.
    PathBuf::from(format!(
        r"\\.\pipe\msb-engine-test-{}-{case}",
        std::process::id()
    ))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn native_pipe_preserves_raw_bytes_and_bounds_handshake_setup() {
    timeout(Duration::from_secs(10), async {
        let path = pipe_name("framing");
        let mut server = ServerOptions::new()
            .pipe_mode(PipeMode::Byte)
            .first_pipe_instance(true)
            .create(&path)
            .unwrap();
        let peer = tokio::spawn(async move {
            server.connect().await.unwrap();
            server.write_u8(1).await.unwrap();
            let request = codec::read_raw_frame(&mut server).await.unwrap();
            assert_eq!(request.body, [0xff, 0, 5]);
            codec::write_raw_frame(
                &mut server,
                &RawFrame {
                    flags: 1,
                    ..request
                },
            )
            .await
            .unwrap();
            // Keep the server handle alive until the client consumes the reply
            // and closes; Windows disconnect can discard unread pipe data.
            let _ = server.read_u8().await;
        });
        let client = Client::<ExternalProtocol>::connect(&path).await.unwrap();
        assert_eq!(
            client.request_raw(0, vec![0xff, 0, 5]).await.unwrap().body,
            [0xff, 0, 5]
        );
        client.close().await;
        peer.await.unwrap();

        let path = pipe_name("handshake-timeout");
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&path)
            .unwrap();
        let (release, held) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            server.connect().await.unwrap();
            // Connected transport, but deliberately no protocol-ready byte.
            let _ = held.await;
        });
        let error = Client::<ExternalProtocol>::connect_with(&path, |options| {
            options.setup_timeout(Duration::from_millis(100))
        })
        .await
        .err()
        .unwrap();
        assert_eq!(error.kind, ErrorKind::Timeout);
        assert_eq!(error.delivery, Delivery::NotSent);
        release.send(()).unwrap();
        peer.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_pipe_missing_and_busy_endpoints_obey_the_dial_deadline() {
    timeout(Duration::from_secs(10), async {
        let missing = LocalConnector::new(pipe_name("missing"));
        let error = missing
            .connect(Instant::now() + Duration::from_millis(100))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind, ErrorKind::Timeout);
        assert_eq!(error.delivery, Delivery::NotSent);

        let path = pipe_name("busy");
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .max_instances(1)
            .create(&path)
            .unwrap();
        let occupied = ClientOptions::new().open(&path).unwrap();
        server.connect().await.unwrap();
        // Establish the OS condition independently before testing the retry loop.
        assert_eq!(
            ClientOptions::new()
                .open(&path)
                .err()
                .unwrap()
                .raw_os_error(),
            Some(231)
        );
        let connector = LocalConnector::new(&path);
        let error = connector
            .connect(Instant::now() + Duration::from_millis(100))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind, ErrorKind::Timeout);
        assert_eq!(error.delivery, Delivery::NotSent);
        drop(occupied);
        server.disconnect().unwrap();
        // Reusing the same endpoint after release must succeed; no cached busy state.
        let (accepted, stream) = tokio::join!(
            server.connect(),
            connector.connect(Instant::now() + Duration::from_secs(2))
        );
        accepted.unwrap();
        drop(stream.unwrap());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_pipe_disconnect_after_receipt_reports_unknown_delivery() {
    timeout(Duration::from_secs(10), async {
        let path = pipe_name("disconnect");
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&path)
            .unwrap();
        let peer = tokio::spawn(async move {
            server.connect().await.unwrap();
            server.write_u8(1).await.unwrap();
            let request = codec::read_raw_frame(&mut server).await.unwrap();
            assert_eq!(request.body, [7]);
            // The request reached the peer, but the terminal reply is lost.
        });
        let client = Client::<ExternalProtocol>::connect(&path).await.unwrap();
        let error = client.request_raw(0, vec![7]).await.unwrap_err();
        assert_eq!(error.delivery, Delivery::Unknown);
        assert!(client.is_closed());
        peer.await.unwrap();
        client.close().await;
    })
    .await
    .unwrap();
}
