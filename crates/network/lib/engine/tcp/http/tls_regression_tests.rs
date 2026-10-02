//! Regression coverage for TLS over the guest-facing HTTP proxy.

use std::{
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};

use tokio::io::ReadBuf;
use tokio::net::TcpListener;

use crate::secrets::{
    config::{HostPattern, SecretEntry, SecretSubstitution},
    handle::SecretsHandle,
};
use crate::tcp::connection::ProxyConnectStatus;

use super::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct BrokenGuest {
    dropped: Arc<AtomicBool>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl AsyncRead for BrokenGuest {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for BrokenGuest {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for BrokenGuest {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn client_hello(host: &str) -> Vec<u8> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let mut client = rustls::ClientConnection::new(
        Arc::new(config),
        rustls::pki_types::ServerName::try_from(host.to_owned()).unwrap(),
    )
    .unwrap();
    let mut data = Vec::new();
    client.write_tls(&mut data).unwrap();
    data
}

fn tls_state() -> Arc<TlsState> {
    tls_state_with_config(
        microsandbox_types::TlsConfig::default(),
        SecretsConfig::default(),
    )
}

fn tls_state_with_config(
    config: microsandbox_types::TlsConfig,
    secrets: SecretsConfig,
) -> Arc<TlsState> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    Arc::new(TlsState::new(config, SecretsHandle::new(secrets)).unwrap())
}

fn blocking_secrets(action: SecretViolationAction) -> SecretsConfig {
    SecretsConfig {
        secrets: vec![SecretEntry {
            env_var: "API_KEY".into(),
            value: zeroize::Zeroizing::new("real-value".into()),
            source: None,
            placeholder: "$TOKEN".into(),
            allowed_hosts: vec![HostPattern::Exact("secret.example".into())],
            substitution: SecretSubstitution::default(),
            passthrough_hosts: Vec::new(),
            violation_action: Some(action),
            require_tls_identity: false,
        }],
        ..Default::default()
    }
}

async fn upstream_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (client, server) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    (client.unwrap(), server.unwrap().0)
}

async fn ip_connect_policy_result(policy: NetworkPolicy, denied: bool) {
    let shared = Arc::new(SharedState::new(32));
    let address: SocketAddr = "203.0.113.10:443".parse().unwrap();
    let (upstream, _server) = upstream_pair().await;
    let (_input, receiver) = mpsc::channel(32);
    let (sender, mut output) = mpsc::channel(32);
    let status = Arc::new(ProxyConnectState::new());
    let proxy = TlsProxy::new(
        address,
        UpstreamTcpTarget::direct(address),
        receiver,
        sender,
        shared,
        tls_state(),
        Arc::new(policy),
        true,
        status.clone(),
        None,
    )
    .with_upstream(upstream)
    .with_initial_buf(client_hello("blocked.example"))
    .with_proxy_dns_address();
    let task = tokio::spawn(proxy.run());
    if denied {
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.status(), ProxyConnectStatus::PolicyDenied);
        assert!(output.recv().await.is_none());
    } else {
        let bytes = tokio::time::timeout(Duration::from_secs(3), output.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!bytes.is_empty());
        assert_ne!(status.status(), ProxyConnectStatus::PolicyDenied);
        task.abort();
        let _ = task.await;
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn ip_connect_enforces_sni_hostname_denies() {
    for destination in [
        serde_json::json!({"domain": "blocked.example"}),
        serde_json::json!({"domain_suffix": "example"}),
        serde_json::json!({"cidr": "203.0.113.0/24"}),
    ] {
        let policy = serde_json::from_value(serde_json::json!({
            "default_egress": "allow", "default_ingress": "allow", "rules": [{
                "direction": "egress", "destination": destination, "action": "deny"
            }]
        }))
        .unwrap();
        ip_connect_policy_result(policy, true).await;
    }
    ip_connect_policy_result(NetworkPolicy::allow_all(), false).await;
}

#[tokio::test]
async fn ip_connect_retains_strict_hostname_bypass_checks() {
    let shared = Arc::new(SharedState::new(32));
    let address: SocketAddr = "203.0.113.10:443".parse().unwrap();
    shared.cache_resolved_hostname(
        "blocked.example",
        crate::netstack::shared::ResolvedHostnameFamily::Ipv4,
        [address.ip()],
        Duration::from_secs(30),
    );
    let policy = serde_json::from_value(serde_json::json!({
        "default_egress": "deny", "default_ingress": "allow", "rules": [{
            "direction": "egress", "destination": {"domain": "blocked.example"}, "action": "allow"
        }]
    }))
    .unwrap();
    let (upstream, mut server) = upstream_pair().await;
    let (_input, receiver) = mpsc::channel(32);
    let (sender, mut output) = mpsc::channel(32);
    let status = Arc::new(ProxyConnectState::new());
    let _ = tls_state();
    let tls = Arc::new(
        TlsState::new(
            microsandbox_types::TlsConfig {
                bypass: vec!["blocked.example".into()],
                ..Default::default()
            },
            SecretsHandle::new(SecretsConfig::default()),
        )
        .unwrap(),
    );
    let proxy = TlsProxy::new(
        address,
        UpstreamTcpTarget::direct(address),
        receiver,
        sender,
        shared,
        tls,
        Arc::new(policy),
        true,
        status.clone(),
        None,
    )
    .with_upstream(upstream)
    .with_initial_buf(client_hello("blocked.example"))
    .with_proxy_dns_address();
    tokio::time::timeout(Duration::from_secs(3), proxy.run())
        .await
        .unwrap();
    assert_eq!(status.status(), ProxyConnectStatus::PolicyDenied);
    assert!(output.recv().await.is_none());
    let mut bytes = Vec::new();
    server.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.is_empty());
}

#[tokio::test]
async fn secrets_reject_unchecked_connect_before_opening_upstream() {
    for action in [
        SecretViolationAction::Block,
        SecretViolationAction::BlockAndTerminate,
    ] {
        let secrets = blocking_secrets(action);
        let intercept =
            tls_state_with_config(microsandbox_types::TlsConfig::default(), secrets.clone());
        let bypass = tls_state_with_config(
            microsandbox_types::TlsConfig {
                bypass: vec!["example.com".into(), "*.example".into()],
                ..Default::default()
            },
            secrets.clone(),
        );
        for (tls, port) in [(None, 443), (Some(intercept), 80), (Some(bypass), 443)] {
            for host in ["example.com", "secret.example", "203.0.113.10"] {
                for buffered_payload in [false, true] {
                    // IP authorities select hostname bypasses later by SNI.
                    if host == "203.0.113.10" && tls.is_some() && port == 443 {
                        continue;
                    }
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let address = listener.local_addr().unwrap();
                    let (mut client, server) = tokio::io::duplex(4096);
                    let proxy = tokio::spawn(serve(
                        server,
                        address,
                        Arc::new(NetworkPolicy::allow_all()),
                        None,
                        tls.clone(),
                        Arc::new(secrets.clone()),
                        true,
                        Arc::new(SharedState::new(32)),
                    ));
                    let request =
                        format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
                    let mut request = request.into_bytes();
                    if buffered_payload {
                        request.extend_from_slice(b"$TOKEN");
                    }
                    client.write_all(&request).await.unwrap();
                    let mut response = Vec::new();
                    tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut response))
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(response.starts_with(b"HTTP/1.1 403"));
                    assert!(
                        String::from_utf8_lossy(&response)
                            .contains("CONNECT tunnels require TLS interception")
                    );
                    proxy.await.unwrap().unwrap();
                    assert!(listener.accept().now_or_never().is_none());
                    let _ = client.write_all(b"$TOKEN").await;
                    assert!(listener.accept().now_or_never().is_none());
                }
            }
        }
    }
}

#[tokio::test]
async fn secrets_reject_ip_connect_sni_bypass() {
    let shared = Arc::new(SharedState::new(32));
    let address: SocketAddr = "203.0.113.10:443".parse().unwrap();
    let (upstream, mut server) = upstream_pair().await;
    let (_input, receiver) = mpsc::channel(32);
    let (sender, mut output) = mpsc::channel(32);
    let status = Arc::new(ProxyConnectState::new());
    let tls = tls_state_with_config(
        microsandbox_types::TlsConfig {
            bypass: vec!["blocked.example".into()],
            ..Default::default()
        },
        blocking_secrets(SecretViolationAction::BlockAndTerminate),
    );
    let proxy = TlsProxy::new(
        address,
        UpstreamTcpTarget::direct(address),
        receiver,
        sender,
        shared,
        tls,
        Arc::new(NetworkPolicy::allow_all()),
        true,
        status.clone(),
        None,
    )
    .with_upstream(upstream)
    .with_initial_buf(client_hello("blocked.example"))
    .with_proxy_dns_address();
    tokio::time::timeout(Duration::from_secs(3), proxy.run())
        .await
        .unwrap();
    assert_eq!(status.status(), ProxyConnectStatus::PolicyDenied);
    assert!(output.recv().await.is_none());
    let mut bytes = Vec::new();
    server.read_to_end(&mut bytes).await.unwrap();
    assert!(bytes.is_empty());
}

#[tokio::test]
async fn tls_output_failure_returns_error_and_cleans_up_guest() {
    let (upstream, _server) = upstream_pair().await;
    let dropped = Arc::new(AtomicBool::new(false));
    let task = tokio::spawn(run_tls_mitm(
        BrokenGuest {
            dropped: dropped.clone(),
        },
        upstream,
        "example.com".into(),
        443,
        client_hello("example.com"),
        Arc::new(NetworkPolicy::allow_all()),
        tls_state(),
        true,
        Arc::new(SharedState::new(32)),
    ));
    let error = tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn tls_input_eof_returns_error_without_polling_completed_output_twice() {
    for _ in 0..16 {
        let (upstream, _server) = upstream_pair().await;
        let (mut client, guest) = tokio::io::duplex(4096);
        client.shutdown().await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            run_tls_mitm(
                guest,
                upstream,
                "example.com".into(),
                443,
                client_hello("example.com"),
                Arc::new(NetworkPolicy::allow_all()),
                tls_state(),
                true,
                Arc::new(SharedState::new(32)),
            ),
        )
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(!response.is_empty());
    }
}

#[tokio::test]
async fn intercepted_connect_substitutes_secrets_and_finishes_tasks() {
    let host = "secret.example";
    let tls = tls_state_with_config(
        microsandbox_types::TlsConfig {
            enabled: true,
            verify_upstream: false,
            ..Default::default()
        },
        blocking_secrets(SecretViolationAction::BlockAndTerminate),
    );
    let server_config = tls
        .get_or_generate_cert(host)
        .unwrap()
        .server_config
        .clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_headers(&mut stream).await.unwrap();
        assert!(request.starts_with(b"CONNECT secret.example:443 HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let mut stream = tokio_rustls::TlsAcceptor::from(server_config)
            .accept(stream)
            .await
            .unwrap();
        let request = read_headers(&mut stream).await.unwrap();
        assert!(String::from_utf8_lossy(&request).contains("Authorization: Bearer real-value\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    let (mut client, guest) = tokio::io::duplex(128 * 1024);
    let proxy = tokio::spawn(serve(
        guest,
        address,
        Arc::new(NetworkPolicy::allow_all()),
        None,
        Some(tls.clone()),
        tls.secrets.load(),
        true,
        Arc::new(SharedState::new(32)),
    ));
    client
        .write_all(b"CONNECT secret.example:443 HTTP/1.1\r\nHost: secret.example:443\r\n\r\n")
        .await
        .unwrap();
    let response = read_headers(&mut client).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 Connection Established"));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(tls.intercept_ca.cert_der.clone()).unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let mut client = tokio_rustls::TlsConnector::from(Arc::new(client_config))
        .connect(
            rustls::pki_types::ServerName::try_from(host).unwrap(),
            client,
        )
        .await
        .unwrap();
    client
        .write_all(
            b"GET / HTTP/1.1\r\nHost: secret.example\r\nAuthorization: Bearer $TOKEN\r\n\r\n",
        )
        .await
        .unwrap();
    client.flush().await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(3), read_headers(&mut client))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    tokio::time::timeout(Duration::from_secs(3), proxy)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    upstream.await.unwrap();
}
