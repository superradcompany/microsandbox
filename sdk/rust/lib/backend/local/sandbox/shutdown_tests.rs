//! Verify the lifecycle shutdown packet without relying on PID fallback.

use std::time::Duration;

use microsandbox_protocol::{
    codec,
    core::Ready,
    message::{Message, MessageType, PROTOCOL_VERSION},
};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;

use crate::backend::LocalBackend;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn graceful_shutdown_reaches_current_and_legacy_agent_without_an_owned_id() {
    for legacy in [false, true] {
        let directory = tempfile::Builder::new()
            .prefix("msb-shutdown-")
            .tempdir_in("/tmp")
            .unwrap();
        let backend = LocalBackend::builder()
            .home(directory.path())
            .build()
            .await
            .unwrap();
        let name = "shutdown";
        let socket = crate::runtime::sandbox_agent_socket_path_candidates_for(&backend, name)
            .into_iter()
            .next()
            .unwrap();
        std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(socket).unwrap();
        let wire_version = if legacy { 1 } else { PROTOCOL_VERSION };
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // ID zero is outside this connection's application lease range.
            // Shutdown remains a global, uncorrelated message with no reply.
            stream
                .write_all(&0x0200_0000u32.to_be_bytes())
                .await
                .unwrap();
            if !legacy {
                stream
                    .write_all(&0x0300_0000u32.to_be_bytes())
                    .await
                    .unwrap();
            }
            let mut ready =
                Message::with_payload(MessageType::Ready, 0, &Ready::default()).unwrap();
            ready.v = wire_version;
            codec::write_message(&mut stream, &ready).await.unwrap();
            let shutdown = codec::read_raw_frame(&mut stream).await.unwrap();
            let mut actual = Vec::new();
            codec::encode_raw_to_buf(&shutdown, &mut actual).unwrap();
            actual
        });
        tokio::time::timeout(Duration::from_secs(2), backend.request_agent_shutdown(name))
            .await
            .expect("shutdown send deadline")
            .expect("shutdown must reach the guest instead of falling back to PID termination");
        let actual = tokio::time::timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
        // Literal bytes from the previous client's empty-unit shutdown body:
        // zero ID, SHUTDOWN flag, CBOR {v, t: "core.shutdown", p: h'f6'}.
        let mut expected = vec![0, 0, 0, 29, 0, 0, 0, 0, 4, 0xa3, 0x61, b'v', wire_version];
        expected.extend_from_slice(b"\x61t\x6dcore.shutdown\x61p\x41\xf6");
        assert_eq!(actual, expected, "legacy={legacy}");
    }
}
