//! Integration tests for TLS interception.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]` attribute
//! marks them `#[ignore]`, so plain `cargo test --workspace` skips them. Run
//! them via:
//!
//!     cargo nextest run -p microsandbox --tests --run-ignored=only
//!
//! Set `MSB_TEST_ISOLATE_HOME=1` (CI does this) to give each test its own
//! `~/.microsandbox` so they can run in parallel without sharing the sqlite
//! db, image cache, or sandbox namespace.

#![cfg(feature = "net")]

use std::sync::Arc;
use std::time::Duration;

use microsandbox::{NetworkPolicy, Sandbox};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use test_utils::msb_test;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct SelfSignedHttps {
    port: u16,
    listener: JoinHandle<()>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SelfSignedHttps {
    async fn start() -> Self {
        let key = rcgen::KeyPair::generate().expect("fixture key");
        let cert = rcgen::CertificateParams::new(vec!["host.microsandbox.internal".into()])
            .expect("fixture SAN")
            .self_signed(&key)
            .expect("fixture certificate");
        // Select the fixture provider explicitly: workspace features enable both providers.
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("fixture protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("fixture TLS config");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("fixture listener");
        let port = listener.local_addr().unwrap().port();
        let listener = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    // Rejected certificate handshakes are expected in the control case.
                    let _ = tokio::time::timeout(Duration::from_secs(10), async move {
                        let mut stream = acceptor.accept(socket).await?;
                        let mut header = Vec::new();
                        while header.len() < 8192 && !header.ends_with(b"\r\n\r\n") {
                            header.push(stream.read_u8().await?);
                        }
                        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nself-signed").await?;
                        stream.shutdown().await
                    }).await;
                });
            }
        });
        Self { port, listener }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for SelfSignedHttps {
    fn drop(&mut self) {
        self.listener.abort();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn stop_and_remove(name: &str) {
    let handle = Sandbox::get(name).await.expect("get");
    handle.stop().await.expect("failed to stop");
    Sandbox::remove(name).await.expect("failed to remove");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Covers the default TLS-interception path:
/// - Node.js fetch over TLS 1.3: guards against a past deadlock where
///   application data piggybacked on the TLS Finished message was never
///   drained from the handshake buffer.
/// - wget (busybox, typically TLS 1.2) as a non-Node baseline.
///
/// Both probes run against a single sandbox to avoid paying two image-pull
/// and VM-boot costs in CI.
#[msb_test]
async fn tls_intercept_handshake() {
    let name = "tls-test-intercept";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/node:alpine")
        .cpus(1)
        .memory(512)
        .network(|n| n.tls(|t| t))
        .replace()
        .create()
        .await
        .expect("failed to create sandbox");

    let node_fetch = sandbox
        .shell(concat!(
            "node -e \"",
            "setTimeout(() => { process.exit(1); }, 15000);",
            "fetch('https://example.com')",
            ".then(r => { console.log(r.status); process.exit(0); })",
            ".catch(e => { console.error(e.message); process.exit(1); });",
            "\""
        ))
        .await
        .expect("node fetch shell failed");
    let node_stdout = node_fetch.stdout().expect("invalid utf8");
    assert_eq!(
        node_stdout.trim(),
        "200",
        "node fetch via TLS intercept failed: {node_stdout} (stderr: {})",
        node_fetch.stderr().unwrap_or_default()
    );

    let wget = sandbox
        .shell("wget -q -O /dev/null --timeout=10 https://example.com && echo OK || echo FAIL")
        .await
        .expect("wget shell failed");
    let wget_stdout = wget.stdout().expect("invalid utf8");
    assert_eq!(
        wget_stdout.trim(),
        "OK",
        "wget via TLS intercept failed: {wget_stdout} (stderr: {})",
        wget.stderr().unwrap_or_default()
    );

    stop_and_remove(name).await;
}

/// Verify TLS bypass domains skip interception and still connect.
#[msb_test]
async fn tls_bypass_domain_connects() {
    let name = "tls-test-bypass";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/node:alpine")
        .cpus(1)
        .memory(512)
        .network(|n| n.tls(|t| t.bypass("example.com")))
        .replace()
        .create()
        .await
        .expect("failed to create sandbox");

    let output = sandbox
        .shell(concat!(
            "node -e \"",
            "setTimeout(() => process.exit(1), 15000);",
            "fetch('https://example.com')",
            ".then(r => { console.log(r.status); process.exit(0); })",
            ".catch(e => { console.error(e.message); process.exit(1); });",
            "\""
        ))
        .await
        .expect("shell failed");

    let stdout = output.stdout().expect("invalid utf8");
    assert_eq!(
        stdout.trim(),
        "200",
        "bypass domain fetch failed: {stdout} (stderr: {})",
        output.stderr().unwrap_or_default()
    );

    stop_and_remove(name).await;
}

/// Verify a host-scoped upstream no-verify override keeps TLS interception
/// active while allowing a live self-signed upstream certificate.
#[msb_test]
async fn tls_scoped_no_verify_accepts_live_self_signed_upstream() {
    // A controlled upstream removes public DNS/service availability from the
    // certificate-verification assertion while preserving the real VM/TLS path.
    let server = SelfSignedHttps::start().await;
    let host = "host.microsandbox.internal";
    let port = server.port;
    // Pin the injected CA explicitly; minimal curl images can use a different
    // default trust bundle. Do not disable guest certificate verification.
    let curl_script = format!(
        concat!(
            "set +e\n",
            "curl --cacert /.msb/tls/ca.pem --http1.1 -m 30 -sS -o /tmp/self-signed-body ",
            "-w 'status=%{{http_code}}\\n' https://{host}:{port}/\n",
            "status=$?\n",
            "echo \"exit=$status\"\n",
            "if [ \"$status\" -eq 0 ] && grep -q self-signed /tmp/self-signed-body; then\n",
            "  echo body=ok\n",
            "else\n",
            "  echo body=missing\n",
            "fi\n"
        ),
        host = host,
        port = port
    );

    let control_name = "tls-test-live-self-signed-control";
    let control = Sandbox::builder(control_name)
        .image("mirror.gcr.io/curlimages/curl")
        .cpus(1)
        .memory(512)
        .user("0")
        .network(|n| {
            n.policy(NetworkPolicy::allow_all())
                .tls(|t| t.intercepted_ports(vec![port]))
        })
        .replace()
        .create()
        .await
        .expect("failed to create control sandbox");
    let control_output = control
        .shell(curl_script.as_str())
        .await
        .expect("control curl shell failed");
    let control_stdout = control_output.stdout().expect("invalid utf8");
    stop_and_remove(control_name).await;

    assert!(
        control_stdout.contains("exit=")
            && !control_stdout.contains("exit=0")
            && !control_stdout.contains("exit=28"),
        "expected self-signed upstream to fail without scoped no-verify, stdout: {control_stdout}"
    );

    let scoped_name = "tls-test-live-self-signed-scoped";
    let scoped = Sandbox::builder(scoped_name)
        .image("mirror.gcr.io/curlimages/curl")
        .cpus(1)
        .memory(512)
        .user("0")
        .network(|n| {
            n.policy(NetworkPolicy::allow_all()).tls(|t| {
                t.intercepted_ports(vec![port])
                    .verify_upstream_for(host, false)
            })
        })
        .replace()
        .create()
        .await
        .expect("failed to create scoped sandbox");
    let scoped_output = scoped
        .shell(curl_script.as_str())
        .await
        .expect("scoped curl shell failed");
    let scoped_stdout = scoped_output.stdout().expect("invalid utf8");
    stop_and_remove(scoped_name).await;

    assert!(
        scoped_stdout.contains("exit=0"),
        "expected scoped no-verify curl to succeed, stdout: {scoped_stdout}, stderr: {}",
        scoped_output.stderr().unwrap_or_default()
    );
    assert!(
        scoped_stdout.contains("status=200"),
        "expected scoped no-verify upstream to return 200, stdout: {scoped_stdout}"
    );
    assert!(
        scoped_stdout.contains("body=ok"),
        "expected live self-signed response body, stdout: {scoped_stdout}"
    );
}
