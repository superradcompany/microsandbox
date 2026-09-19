//! Exercise automatic discovery and reuse over a real Windows named pipe.
#![cfg(all(windows, feature = "named-pipe"))]

use std::path::PathBuf;
use std::time::Duration;

use microsandbox_control_client::{
    Capabilities, ControlConnection, ControlHello, ControlMode, ControlWelcome, GetCapabilities,
    JsonControlClient,
};
use microsandbox_protocol::{codec, wire::Envelope};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::task::JoinSet;
use tokio::time::timeout;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CAPS: Capabilities = Capabilities {
    root_disk_grow: false,
    cpu_resize: true,
    memory_resize: true,
    secrets_update: false,
};
const JSON_CAPS: &[u8] = b"{\"ok\":true,\"capabilities\":{\"cpu_resize\":true,\"memory_resize\":true,\"secrets_update\":false},\"control_protocols\":[\"json\",\"cbor\"]}\n";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn json_peer(mut server: NamedPipeServer) {
    let mut line = Vec::new();
    BufReader::new(&mut server)
        .read_until(b'\n', &mut line)
        .await
        .unwrap();
    assert_eq!(line, b"{\"op\":\"capabilities\"}\n");
    server.write_all(JSON_CAPS).await.unwrap();
    // Wait for client closure so disconnect cannot discard its unread response.
    let _ = server.read_u8().await;
}

async fn framed_peer(mut server: NamedPipeServer) {
    let opening = codec::read_raw_frame(&mut server).await.unwrap();
    assert_eq!((opening.id, opening.flags), (0, 0));
    let envelope = Envelope::decode(&opening.body).unwrap();
    assert_eq!(envelope.t, "control.hello");
    let hello: ControlHello = envelope.payload().unwrap();
    let welcome = ControlWelcome::negotiate(&hello, 64).unwrap();
    codec::write_raw_frame(
        &mut server,
        &Envelope::new(1, "control.welcome", &welcome)
            .unwrap()
            .frame(0, 1)
            .unwrap(),
    )
    .await
    .unwrap();
    // Both concurrent application requests must use this established connection.
    let mut ids = Vec::new();
    for _ in 0..2 {
        let request = codec::read_raw_frame(&mut server).await.unwrap();
        assert_ne!(request.id, 0);
        assert!(!ids.contains(&request.id));
        ids.push(request.id);
        assert_eq!(
            Envelope::decode(&request.body).unwrap().t,
            "control.capabilities"
        );
    }
    // Reply in reverse order to exercise multiplexing over the native byte pipe.
    for id in ids.into_iter().rev() {
        codec::write_raw_frame(
            &mut server,
            &Envelope::new(1, "control.capabilities.result", &CAPS)
                .unwrap()
                .frame(id, 1)
                .unwrap(),
        )
        .await
        .unwrap();
    }
    let _ = server.read_u8().await;
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn native_pipe_discovers_once_then_reuses_cbor_beside_explicit_json() {
    timeout(Duration::from_secs(10), async {
        let path = PathBuf::from(format!(
            r"\\.\pipe\msb-control-test-{}-discovery",
            std::process::id()
        ));
        let first = ServerOptions::new()
            .pipe_mode(PipeMode::Byte)
            .first_pipe_instance(true)
            .create(&path)
            .unwrap();
        let peer_path = path.clone();
        let peer = tokio::spawn(async move {
            let mut pending = Some(first);
            let mut sessions = JoinSet::new();
            // Exactly one discovery, one persistent session, one explicit JSON call.
            for index in 0..3 {
                let server = pending.take().unwrap();
                server.connect().await.unwrap();
                if index < 2 {
                    pending = Some(
                        ServerOptions::new()
                            .pipe_mode(PipeMode::Byte)
                            .create(&peer_path)
                            .unwrap(),
                    );
                }
                sessions.spawn(async move {
                    if index == 1 {
                        framed_peer(server).await
                    } else {
                        json_peer(server).await
                    }
                });
            }
            while let Some(result) = sessions.join_next().await {
                result.unwrap();
            }
        });
        let client = ControlConnection::connect(&path).await.unwrap();
        assert_eq!(client.mode(), ControlMode::Framed);
        let (left, right) = tokio::join!(
            client.request_typed(&GetCapabilities),
            client.request_typed(&GetCapabilities)
        );
        assert_eq!(left.unwrap(), CAPS);
        assert_eq!(right.unwrap(), CAPS);
        let json = JsonControlClient::new(&path);
        assert_eq!(json.request_typed(&GetCapabilities).await.unwrap(), CAPS);
        json.close().await;
        client.close().await;
        peer.await.unwrap();
    })
    .await
    .unwrap();
}
