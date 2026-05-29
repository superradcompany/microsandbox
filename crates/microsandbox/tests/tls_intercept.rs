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
const LARGE_SECRET_PAD_LEN: usize = 1024 * 1024; // 1 MiB on each side of the placeholder.
const REAL_SECRET: &[u8] = b"real-secret";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Minimal HTTPS server bound to `127.0.0.1` and `::1` on the same port.
struct HostHttps {
    port: u16,
    handle: Option<JoinHandle<io::Result<ReceivedRequest>>>,
}

struct ReceivedRequest {
    headers: Vec<u8>,
    body: Vec<u8>,
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

    async fn received_request(&mut self) -> io::Result<ReceivedRequest> {
        self.handle
            .take()
            .expect("https fixture already consumed")
            .await
            .map_err(io::Error::other)?
    }

    async fn received_body(&mut self) -> io::Result<Vec<u8>> {
        self.received_request().await.map(|request| request.body)
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
) -> io::Result<ReceivedRequest> {
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

    let body_start = header_end + 4;
    let headers = request[..header_end].to_vec();
    let body = if is_transfer_chunked(&headers)? {
        read_chunked_body(&mut stream, request[body_start..].to_vec()).await?
    } else {
        let content_length = parse_content_length(&headers)?;
        read_content_length_body(&mut stream, request[body_start..].to_vec(), content_length)
            .await?
    };

    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await?;
    stream.shutdown().await?;

    Ok(ReceivedRequest { headers, body })
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

fn is_transfer_chunked(headers: &[u8]) -> io::Result<bool> {
    let headers =
        std::str::from_utf8(headers).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(headers.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .next_back()
                .is_some_and(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
    }))
}

async fn read_content_length_body(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    mut body: Vec<u8>,
    content_length: usize,
) -> io::Result<Vec<u8>> {
    while body.len() < content_length {
        read_more(stream, &mut body, "connection closed before body").await?;
    }
    body.truncate(content_length);
    Ok(body)
}

async fn read_chunked_body(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    mut raw: Vec<u8>,
) -> io::Result<Vec<u8>> {
    let mut cursor = 0;
    let mut decoded = Vec::new();

    loop {
        let line_end = read_until_crlf(stream, &mut raw, cursor, "chunk size line").await?;
        let size = parse_chunk_size(&raw[cursor..line_end])?;
        cursor = line_end + 2;

        if size == 0 {
            loop {
                let trailer_end =
                    read_until_crlf(stream, &mut raw, cursor, "chunk trailer").await?;
                let empty = trailer_end == cursor;
                cursor = trailer_end + 2;
                if empty {
                    return Ok(decoded);
                }
            }
        }

        while raw.len() < cursor + size + 2 {
            read_more(stream, &mut raw, "connection closed before chunk data").await?;
        }
        decoded.extend_from_slice(&raw[cursor..cursor + size]);
        cursor += size;
        if raw.get(cursor..cursor + 2) != Some(b"\r\n") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk data missing CRLF",
            ));
        }
        cursor += 2;
    }
}

async fn read_until_crlf(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    raw: &mut Vec<u8>,
    start: usize,
    context: &str,
) -> io::Result<usize> {
    loop {
        if let Some(pos) = raw[start..].windows(2).position(|window| window == b"\r\n") {
            return Ok(start + pos);
        }
        read_more(stream, raw, context).await?;
    }
}

async fn read_more(
    stream: &mut tokio_rustls::server::TlsStream<TcpStream>,
    buf: &mut Vec<u8>,
    context: &str,
) -> io::Result<()> {
    let mut chunk = [0; 8192];
    let n = stream.read(&mut chunk).await?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, context));
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(())
}

fn parse_chunk_size(line: &[u8]) -> io::Result<usize> {
    let size = line
        .split(|byte| *byte == b';')
        .next()
        .unwrap_or_default()
        .trim_ascii();
    let size =
        std::str::from_utf8(size).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    usize::from_str_radix(size, 16).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn assert_large_secret_body(body: &[u8]) {
    assert_eq!(body.len(), LARGE_SECRET_PAD_LEN * 2 + REAL_SECRET.len());
    assert!(body[..LARGE_SECRET_PAD_LEN].iter().all(|b| *b == b'a'));
    assert_eq!(
        &body[LARGE_SECRET_PAD_LEN..LARGE_SECRET_PAD_LEN + REAL_SECRET.len()],
        REAL_SECRET,
    );
    assert!(
        body[LARGE_SECRET_PAD_LEN + REAL_SECRET.len()..]
            .iter()
            .all(|b| *b == b'b')
    );
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
async fn tls_intercept_substitutes_secret_in_chunked_body() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "tls-intercept-secret-chunked-body";
    let sb = spawn_secret_curl_sandbox(name, port, "host.microsandbox.internal").await;

    let out = sb
        .shell(format!(
            r#"set -eu
body=/tmp/chunked-secret-body
printf 'prefix-%s-suffix' "$API_KEY" > "$body"
curl -k --http1.1 -m 30 -sS -o /tmp/response \
  -w 'code=%{{http_code}} upload=%{{size_upload}}' \
  -H 'content-type: text/plain' \
  -H 'Transfer-Encoding: chunked' \
  --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/chunked-secret
"#
        ))
        .await
        .expect("curl chunked secret fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        stdout.contains("code=200"),
        "expected curl to receive 200, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    let received = server.received_request().await.expect("read fixture body");
    assert!(
        is_transfer_chunked(&received.headers).expect("headers are utf8"),
        "expected upstream fixture to receive a chunked request, headers: {}",
        String::from_utf8_lossy(&received.headers)
    );
    assert_eq!(received.body, b"prefix-real-secret-suffix");

    teardown(sb, name).await;
}

#[msb_test]
async fn tls_intercept_substitutes_secret_in_large_content_length_body() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "tls-intercept-large-secret-cl";
    let sb = spawn_secret_curl_sandbox(name, port, "host.microsandbox.internal").await;

    let out = sb
        .shell(format!(
            r#"set -eu
body=/tmp/large-secret-cl-body
head -c {LARGE_SECRET_PAD_LEN} /dev/zero | tr '\000' a > "$body"
printf '%s' "$API_KEY" >> "$body"
head -c {LARGE_SECRET_PAD_LEN} /dev/zero | tr '\000' b >> "$body"
curl -k --http1.1 -m 60 -sS -o /tmp/response \
  -w 'code=%{{http_code}} upload=%{{size_upload}}' \
  -H 'content-type: text/plain' \
  --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/large-secret-cl
"#
        ))
        .await
        .expect("curl large content-length secret fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    assert!(
        stdout.contains("code=200"),
        "expected curl to receive 200, stdout: {stdout}, stderr: {}",
        out.stderr().unwrap_or_default()
    );

    let received = server.received_request().await.expect("read fixture body");
    assert!(
        !is_transfer_chunked(&received.headers).expect("headers are utf8"),
        "expected upstream fixture to receive a fixed-length request, headers: {}",
        String::from_utf8_lossy(&received.headers)
    );
    assert_large_secret_body(&received.body);

    teardown(sb, name).await;
}

#[msb_test]
async fn tls_intercept_substitutes_secret_in_large_chunked_body() {
    let mut server = HostHttps::start().await.expect("https fixture");
    let port = server.port();
    let name = "tls-intercept-large-secret-chunked";
    let sb = spawn_secret_curl_sandbox(name, port, "host.microsandbox.internal").await;

    let out = sb
        .shell(format!(
            r#"set -eu
body=/tmp/large-secret-chunked-body
head -c {LARGE_SECRET_PAD_LEN} /dev/zero | tr '\000' a > "$body"
printf '%s' "$API_KEY" >> "$body"
head -c {LARGE_SECRET_PAD_LEN} /dev/zero | tr '\000' b >> "$body"
curl -k --http1.1 -m 60 -sS -o /tmp/response \
  -w 'code=%{{http_code}} upload=%{{size_upload}}' \
  -H 'content-type: text/plain' \
  -H 'Transfer-Encoding: chunked' \
  --data-binary @"$body" \
  https://host.microsandbox.internal:{port}/large-secret-chunked
"#
        ))
        .await
        .expect("curl large chunked secret fixture");

    let stdout = out.stdout().expect("utf8 stdout");
    if !stdout.contains("code=200") {
        let server_status =
            tokio::time::timeout(Duration::from_secs(5), server.received_request()).await;
        let server_status = match server_status {
            Ok(Ok(request)) => format!(
                "server received headers={} body={}",
                request.headers.len(),
                request.body.len()
            ),
            Ok(Err(e)) => format!("server error: {e}"),
            Err(_) => "server timed out".to_string(),
        };
        panic!(
            "expected curl to receive 200, stdout: {stdout}, stderr: {}, {server_status}",
            out.stderr().unwrap_or_default()
        );
    }

    let received = server.received_request().await.expect("read fixture body");
    assert!(
        is_transfer_chunked(&received.headers).expect("headers are utf8"),
        "expected upstream fixture to receive a chunked request, headers: {}",
        String::from_utf8_lossy(&received.headers)
    );
    assert_large_secret_body(&received.body);

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
