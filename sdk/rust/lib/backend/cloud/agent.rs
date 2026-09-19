//! Identity-bound agent connections for cloud sandbox objects.

use std::sync::Arc;

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

use super::{CloudBackend, cloud_agent_tls_connector, default_user_agent};
use crate::backend::{Backend, BackendInfo, BackendKind, SandboxBackend, VolumeBackend};
use crate::{MicrosandboxError, MicrosandboxResult, timing};

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Backend for CloudBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Cloud
    }

    fn info(&self) -> BackendInfo {
        BackendInfo {
            kind: BackendKind::Cloud,
            api_url: Some(self.url.clone()),
            source: self.selection_source,
            profile: self.profile.clone(),
        }
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
    use std::time::Duration;

    use super::*;

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
