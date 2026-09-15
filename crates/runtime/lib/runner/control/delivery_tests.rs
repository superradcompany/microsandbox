//! Lost replies cross the real parser, dispatcher, and secret-store mutation.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use microsandbox_control_client::{
    ControlClientError, ControlConnection, ControlMode, Delivery, ErrorKind, GetCapabilities,
    UpdateSecrets,
};
use microsandbox_network::secrets::{
    config::{HostPattern, SecretEntry, SecretsConfig},
    handle::SecretsHandle,
};
use microsandbox_protocol::control::{
    Capabilities, ControlRequest, JsonControlResponse, SecretChange, SecretValue,
};
use microsandbox_protocol_client::{BoxFuture, BoxTransport, ClientResult, Connector};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout};

use super::dispatch::{Dispatcher, RUNTIME_BYTES};
use super::handler::{Handler, Reply, Response, apply_secret_changes};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct SecretHost {
    secrets: SecretsHandle,
    mutations: AtomicUsize,
    fail_writes: Arc<AtomicBool>,
    framed: bool,
}

struct FaultStream {
    inner: DuplexStream,
    fail_writes: Arc<AtomicBool>,
}

struct ServerConnector {
    dispatcher: Arc<Dispatcher>,
    fail_writes: Arc<AtomicBool>,
    dials: AtomicUsize,
    completed: mpsc::UnboundedSender<io::Result<()>>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Handler for SecretHost {
    fn handle(&self, request: ControlRequest) -> Response {
        match request {
            ControlRequest::Capabilities => {
                let capabilities = Capabilities {
                    root_disk_grow: false,
                    cpu_resize: false,
                    memory_resize: false,
                    secrets_update: true,
                };
                Response {
                    json: JsonControlResponse {
                        ok: true,
                        capabilities: Some(capabilities),
                        control_protocols: self.framed.then(|| vec!["json".into(), "cbor".into()]),
                        ..Default::default()
                    },
                    framed: Reply::Capabilities(capabilities),
                }
            }
            ControlRequest::SecretsUpdate { changes } => {
                self.mutations.fetch_add(1, Ordering::SeqCst);
                let response = apply_secret_changes(Some(&self.secrets), changes);
                // Fail only after the real store has applied the accepted prefix.
                // Welcome/discovery writes therefore complete normally.
                self.fail_writes.store(true, Ordering::SeqCst);
                response
            }
            _ => panic!("unexpected fixture operation"),
        }
    }
}

impl AsyncRead for FaultStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for FaultStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.fail_writes.load(Ordering::SeqCst) {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else {
            Pin::new(&mut this.inner).poll_write(cx, bytes)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Connector for ServerConnector {
    fn connect(&self, _: Instant) -> BoxFuture<'_, ClientResult<BoxTransport>> {
        Box::pin(async move {
            self.dials.fetch_add(1, Ordering::SeqCst);
            let (client, inner) = tokio::io::duplex(4096);
            let mut server = FaultStream {
                inner,
                fail_writes: Arc::clone(&self.fail_writes),
            };
            let dispatcher = Arc::clone(&self.dispatcher);
            let completed = self.completed.clone();
            tokio::spawn(async move {
                let result = super::server::serve(&mut server, dispatcher).await;
                // Drop the transport before acknowledging completion, so the
                // client can observe EOF and the test can verify full teardown.
                drop(server);
                completed.send(result).unwrap();
            });
            Ok(Box::new(client) as BoxTransport)
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn lost_secret_reply(framed: bool, partial: bool) {
    timeout(Duration::from_secs(5), async {
        let fail_writes = Arc::new(AtomicBool::new(false));
        let host = Arc::new(SecretHost {
            secrets: SecretsHandle::new(SecretsConfig {
                secrets: vec![SecretEntry {
                    env_var: "TOKEN".into(),
                    value: zeroize::Zeroizing::new("before".into()),
                    source: None,
                    placeholder: "$MSB_TOKEN".into(),
                    allowed_hosts: vec![HostPattern::Exact("example.invalid".into())],
                    substitution: Default::default(),
                    passthrough_hosts: vec![],
                    violation_action: None,
                    require_tls_identity: true,
                }],
                ..Default::default()
            }),
            mutations: AtomicUsize::new(0),
            fail_writes: Arc::clone(&fail_writes),
            framed,
        });
        let dispatcher = Dispatcher::new(host.clone());
        let worker = tokio::spawn(Arc::clone(&dispatcher).run());
        let (completed, mut completions) = mpsc::unbounded_channel();
        let connector = Arc::new(ServerConnector {
            dispatcher: Arc::clone(&dispatcher),
            fail_writes: Arc::clone(&fail_writes),
            dials: AtomicUsize::new(0),
            completed,
        });
        let client = ControlConnection::connect_connector(connector.clone())
            .await
            .unwrap();
        assert_eq!(
            client.mode(),
            if framed {
                ControlMode::Framed
            } else {
                ControlMode::Json
            }
        );
        assert_eq!(host.mutations.load(Ordering::SeqCst), 0);
        let mut changes = vec![SecretChange::Rotate {
            name: "TOKEN".into(),
            value: SecretValue("accepted-material".into()),
        }];
        if partial {
            changes.extend([
                SecretChange::SetAllowedHosts {
                    name: "TOKEN".into(),
                    hosts: vec![],
                },
                SecretChange::Rotate {
                    name: "TOKEN".into(),
                    value: SecretValue("must-not-run".into()),
                },
            ]);
        }
        let request = UpdateSecrets::new(changes);
        let error = client.request_typed(&request).await.unwrap_err();
        assert!(matches!(&error, ControlClientError::Client(error) if error.kind == ErrorKind::PeerClosed));
        assert_eq!(error.delivery(), Delivery::Unknown);
        assert!(client.is_closed());
        assert!(!format!("{error:?}").contains("accepted-material"));
        assert_eq!(
            host.secrets.load().secrets[0].value.as_str(),
            "accepted-material"
        );
        assert_eq!(host.mutations.load(Ordering::SeqCst), 1);
        let dials_after_loss = connector.dials.load(Ordering::SeqCst);

        // An old handle stays closed even when the caller asks again. A new
        // connection may read state; it must not carry the failed batch with it.
        let retry = client.request_typed(&request).await.unwrap_err();
        assert!(matches!(&retry, ControlClientError::Client(error) if error.kind == ErrorKind::Closed));
        assert_eq!(retry.delivery(), Delivery::NotSent);
        assert_eq!(connector.dials.load(Ordering::SeqCst), dials_after_loss);
        fail_writes.store(false, Ordering::SeqCst);
        let fresh = ControlConnection::connect_connector(connector.clone())
            .await
            .unwrap();
        assert!(
            fresh
                .request_typed(&GetCapabilities)
                .await
                .unwrap()
                .secrets_update
        );
        assert_eq!(host.mutations.load(Ordering::SeqCst), 1);
        assert_eq!(
            host.secrets.load().secrets[0].value.as_str(),
            "accepted-material"
        );
        fresh.close().await;
        client.close().await;

        let total_dials = connector.dials.load(Ordering::SeqCst);
        let mut failed_writes = 0;
        for _ in 0..total_dials {
            if let Err(error) = completions.recv().await.unwrap() {
                assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
                failed_writes += 1;
            }
        }
        assert_eq!(failed_writes, 1);
        // A reply can reach the client before the blocking dispatcher drops its
        // input budget. Transport completion alone does not fence that cleanup.
        // Reclaim every permit under the outer deadline so a real leak still fails.
        let reclaimed = Arc::clone(&dispatcher.bytes)
            .acquire_many_owned(RUNTIME_BYTES as u32)
            .await
            .unwrap();
        drop(reclaimed);
        assert_eq!(dispatcher.bytes.available_permits(), RUNTIME_BYTES);
        worker.abort();
        let _ = worker.await;
    })
    .await
    .expect("lost-reply test deadline");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn framed_lost_complete_secret_reply_is_unknown_and_never_replayed() {
    lost_secret_reply(true, false).await;
}

#[tokio::test]
async fn framed_lost_partial_secret_reply_is_unknown_and_never_replayed() {
    lost_secret_reply(true, true).await;
}

#[tokio::test]
async fn json_lost_complete_secret_reply_is_unknown_and_never_replayed() {
    lost_secret_reply(false, false).await;
}

#[tokio::test]
async fn json_lost_partial_secret_reply_is_unknown_and_never_replayed() {
    lost_secret_reply(false, true).await;
}
