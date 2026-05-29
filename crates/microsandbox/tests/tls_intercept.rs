//! Integration tests for TLS interception.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use microsandbox::{NetworkPolicy, Sandbox};
use rcgen::CertificateParams;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use test_utils::msb_test;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const LARGE_POST_BODY_LEN: usize = 135_000; // 135 kb, above the old ~128 kib failure threshold.

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Minimal HTTPS server bound to `127.0.0.1` and `::1` on the same port.
struct HostHttps {
    port: u16,
    handle: Option<JoinHandle<io::Result<Vec<u8>>>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HostHttps {
    async fn start() -> io::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let v4_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = v4_listener.local_addr()?.port();
        let v6_listener = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await?;
        let acceptor = TlsAcceptor::from(test_server_config());

        let handle = tokio::spawn(async move {
            let (stream, _) = tokio::select! {
                accept = v4_listener.accept() => accept?,
                accept = v6_listener.accept() => accept?,
            };
            let tls = acceptor.accept(stream).await?;
            handle_https_request(tls).await
        });

        Ok(Self {
            port,
            handle: Some(handle),
        })
    }

    fn port(&self) -> u16 {
        self.port
    }

    async fn received_body(&mut self) -> io::Result<Vec<u8>> {
        self.handle
            .take()
            .expect("https fixture already consumed")
            .await
            .map_err(io::Error::other)?
    }
}

impl Drop for HostHttps {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Boot a curl sandbox with TLS interception enabled on the fixture port.
async fn spawn_curl_sandbox(name: &str, port: u16) -> Sandbox {
    Sandbox::builder(name)
        .image("curlimages/curl")
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .network(|n| {
            n.policy(NetworkPolicy::allow_all())
                .tls(|t| t.intercepted_ports(vec![port]).verify_upstream(false))
        })
        .create()
        .await
        .expect("create sandbox")
}

/// Boot a curl sandbox with one body-injected secret and TLS interception on the fixture port.
async fn spawn_secret_curl_sandbox(name: &str, port: u16, allowed_host: &str) -> Sandbox {
    let allowed_host = allowed_host.to_string();
    Sandbox::builder(name)
        .image("curlimages/curl")
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .secret(|s| {
            s.env("API_KEY")
                .value("real-secret")
                .allow_host(allowed_host)
                .inject_body(true)
        })
        .network(|n| {
            n.policy(NetworkPolicy::allow_all())
                .tls(|t| t.intercepted_ports(vec![port]).verify_upstream(false))
        })
        .create()
        .await
        .expect("create sandbox")
}

/// Stop the sandbox and remove it.
async fn teardown(sb: Sandbox, name: &str) {
    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}

async fn handle_https_request(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
) -> io::Result<Vec<u8>> {
    let mut request = Vec::new();
    let header_end = loop {
        let mut buf = [0; 8192];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before headers",
            ));
        }
        request.extend_from_slice(&buf[..n]);
        if let Some(pos) = find_header_end(&request) {
            break pos;
        }
    };

    let content_length = parse_content_length(&request[..header_end])?;
    let body_start = header_end + 4;
    let mut body = request[body_start..].to_vec();
    while body.len() < content_length {
        let mut buf = [0; 8192];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before body",
            ));
        }
        body.extend_from_slice(&buf[..n]);
    }
    body.truncate(content_length);

    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await?;
    stream.shutdown().await?;

    Ok(body)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &[u8]) -> io::Result<usize> {
    let headers =
        std::str::from_utf8(headers).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>())
        })
        .transpose()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing content-length"))
}

fn test_server_config() -> Arc<rustls::ServerConfig> {
    let key_pair = rcgen::KeyPair::generate().expect("generate test key");
    let params = CertificateParams::new(vec!["host.microsandbox.internal".to_string()])
        .expect("test certificate params");
    let cert = params.self_signed(&key_pair).expect("self-sign test cert");
    let chain = vec![CertificateDer::from(cert.der().to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("test server config"),
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn tls_intercept_large_post_to_host_https_server() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "tls-intercept-large-post";
    let sb = spawn_curl_sandbox(name, port).await;

    let out = sb
        .shell(format!(
            r#"set -eu
body=/tmp/large-post-body
head -c {LARGE_POST_BODY_LEN} /dev/zero | tr '\000' a > "$body"
curl -k --http1.1 -m 30 -sS -o /tmp/response \
  -w 'code=%{{http_code}} upload=%{{size_upload}} download=%{{size_download}}' \
  -H 'content-type: text/plain' \
  --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/post
"#
        ))
        .await
        .expect("curl host https fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        stdout.contains("code=200"),
        "expected curl to receive 200, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );
    assert!(
        stdout.contains(&format!("upload={LARGE_POST_BODY_LEN}")),
        "expected curl to upload full body, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    let received = server.received_body().await.expect("read fixture body");
    assert_eq!(received.len(), LARGE_POST_BODY_LEN);
    assert!(received.iter().all(|b| *b == b'a'));

    teardown(sb, name).await;
}

#[msb_test]
async fn tls_intercept_rejects_http_host_sni_mismatch() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "tls-intercept-host-sni-mismatch";
    let sb = spawn_curl_sandbox(name, port).await;

    let out = sb
        .shell(format!(
            r#"set +e
curl -k --http1.1 -m 10 -sS -o /tmp/response \
  -w 'code=%{{http_code}}' \
  -H 'Host: target.example.test' \
  https://host.microsandbox.internal:{port}/fronted
status=$?
echo "status=$status"
"#
        ))
        .await
        .expect("curl host mismatch fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        !stdout.contains("status=0"),
        "expected curl to fail, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    let received = tokio::time::timeout(Duration::from_secs(5), server.received_body()).await;
    assert!(
        received.is_err() || received.expect("timeout checked").is_err(),
        "upstream fixture should not receive a valid HTTP request"
    );

    teardown(sb, name).await;
}

#[msb_test]
async fn tls_intercept_substitutes_secret_for_host_alias() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "tls-intercept-secret-host-alias";
    let sb = spawn_secret_curl_sandbox(name, port, "host.microsandbox.internal").await;

    let out = sb
        .shell(format!(
            r#"set -eu
body=/tmp/secret-body
printf 'token=%s' "$API_KEY" > "$body"
curl -k --http1.1 -m 30 -sS -o /tmp/response \
  -w 'code=%{{http_code}} upload=%{{size_upload}}' \
  -H 'content-type: text/plain' \
  --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/secret
"#
        ))
        .await
        .expect("curl secret host alias fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        stdout.contains("code=200"),
        "expected curl to receive 200, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    let received = server.received_body().await.expect("read fixture body");
    assert_eq!(received, b"token=real-secret");

    teardown(sb, name).await;
}

#[msb_test]
async fn tls_intercept_denies_secret_without_dns_pin() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "tls-intercept-secret-dns-pin";
    let sb = spawn_secret_curl_sandbox(name, port, "api.allowed.test").await;

    let out = sb
        .shell(format!(
            r#"set +e
host_ip="$(getent ahostsv4 host.microsandbox.internal | awk '{{print $1; exit}}')"
body=/tmp/secret-body
printf 'token=%s' "$API_KEY" > "$body"
curl -k --http1.1 -m 10 -sS -o /tmp/response \
  -w 'code=%{{http_code}}' \
  --resolve "api.allowed.test:{port}:$host_ip" \
  -H 'content-type: text/plain' \
  --data-binary @"$body" \
  https://api.allowed.test:{port}/secret
status=$?
echo "status=$status"
"#
        ))
        .await
        .expect("curl secret dns pin fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        !stdout.contains("status=0"),
        "expected curl to fail without DNS pin, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    let received = tokio::time::timeout(Duration::from_secs(5), server.received_body()).await;
    assert!(
        received.is_err() || received.expect("timeout checked").is_err(),
        "upstream fixture should not receive a valid HTTP request"
    );

    teardown(sb, name).await;
}
