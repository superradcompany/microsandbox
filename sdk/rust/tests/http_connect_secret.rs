//! Integration tests for secret substitution through HTTP CONNECT tunnels.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use microsandbox::{NetworkPolicy, Sandbox};
use rcgen::CertificateParams;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use test_utils::msb_test;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

// Constants

const CURL_IMAGE: &str = "mirror.gcr.io/curlimages/curl";
const REAL_SECRET: &str = "real-secret-connect";
const PLACEHOLDER: &str = "MSB_API_KEY";

/// Distinct from the proxy (`host.microsandbox.internal`) so proxy IP and target IP
/// are separate DNS cache entries, matching the corporate proxy topology.
const FAKE_TARGET_HOST: &str = "target.msb-test.internal";

// Types

/// Minimal HTTP CONNECT proxy that splices one tunnelled connection.
struct ConnectProxy {
    port: u16,
    handle: Option<JoinHandle<io::Result<()>>>,
}

/// Minimal HTTPS server that records the Authorization header of one request.
struct TargetHttps {
    port: u16,
    handle: Option<JoinHandle<io::Result<String>>>,
}

/// Minimal proxy fixture that records a `Proxy-Authorization` CONNECT header.
struct ProxyAuthCapture {
    port: u16,
    handle: Option<JoinHandle<io::Result<Option<String>>>>,
}

// Methods

impl ConnectProxy {
    async fn start(target_port: u16) -> io::Result<Self> {
        let v4 = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = v4.local_addr()?.port();
        let v6 = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await?;

        let handle = tokio::spawn(async move {
            let (client, _) = tokio::select! {
                a = v4.accept() => a?,
                a = v6.accept() => a?,
            };
            handle_connect(client, target_port).await
        });

        Ok(Self {
            port,
            handle: Some(handle),
        })
    }

    fn port(&self) -> u16 {
        self.port
    }

    async fn join(&mut self) -> io::Result<()> {
        self.handle
            .take()
            .expect("proxy fixture already consumed")
            .await
            .map_err(io::Error::other)?
    }
}

impl Drop for ConnectProxy {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

impl TargetHttps {
    async fn start() -> io::Result<Self> {
        let v4 = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = v4.local_addr()?.port();
        let v6 = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await?;
        let acceptor = TlsAcceptor::from(test_server_tls_config());

        let handle = tokio::spawn(async move {
            let (stream, _) = tokio::select! {
                a = v4.accept() => a?,
                a = v6.accept() => a?,
            };
            let tls = acceptor.accept(stream).await?;
            received_auth_header(tls).await
        });

        Ok(Self {
            port,
            handle: Some(handle),
        })
    }

    fn port(&self) -> u16 {
        self.port
    }

    async fn received_auth(&mut self) -> io::Result<String> {
        self.handle
            .take()
            .expect("target fixture already consumed")
            .await
            .map_err(io::Error::other)?
    }
}

impl Drop for TargetHttps {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

impl ProxyAuthCapture {
    async fn start() -> io::Result<Self> {
        let v4 = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = v4.local_addr()?.port();
        let v6 = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await?;

        let handle = tokio::spawn(async move {
            let (client, _) = tokio::select! {
                a = v4.accept() => a?,
                a = v6.accept() => a?,
            };
            read_proxy_auth_header(client).await
        });

        Ok(Self {
            port,
            handle: Some(handle),
        })
    }

    fn port(&self) -> u16 {
        self.port
    }

    async fn try_received_auth(&mut self, timeout: std::time::Duration) -> Option<String> {
        let handle = self.handle.take().expect("proxy fixture already consumed");
        match tokio::time::timeout(timeout, handle).await {
            Ok(joined) => joined.ok().and_then(|res| res.ok()).flatten(),
            Err(_) => None,
        }
    }
}

impl Drop for ProxyAuthCapture {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

// Functions

async fn handle_connect(client: TcpStream, target_port: u16) -> io::Result<()> {
    let (read_half, write_half) = client.into_split();
    let mut reader = BufReader::new(read_half);

    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let target = parse_connect_target(&request_line).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected CONNECT request, got: {request_line:?}"),
        )
    })?;

    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }

    // These hostnames only resolve inside the VM; rewrite to loopback.
    let connect_addr = if target.starts_with("host.microsandbox.internal:")
        || target.starts_with(FAKE_TARGET_HOST)
    {
        format!("127.0.0.1:{target_port}")
    } else {
        target
    };

    let mut upstream = TcpStream::connect(&connect_addr).await?;
    let buffered_client_bytes = reader.buffer().to_vec();

    let mut client_write = write_half;
    client_write
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    if !buffered_client_bytes.is_empty() {
        upstream.write_all(&buffered_client_bytes).await?;
    }

    let mut client_read = reader.into_inner();
    let (mut up_read, mut up_write) = upstream.into_split();

    let client_to_upstream = tokio::io::copy(&mut client_read, &mut up_write);
    let upstream_to_client = tokio::io::copy(&mut up_read, &mut client_write);
    tokio::pin!(client_to_upstream);
    tokio::pin!(upstream_to_client);

    tokio::select! {
        result = &mut client_to_upstream => {
            result?;
        }
        result = &mut upstream_to_client => {
            result?;
        }
    }

    Ok(())
}

fn parse_connect_target(line: &str) -> Option<String> {
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    Some(target.to_string())
}

async fn read_proxy_auth_header(client: TcpStream) -> io::Result<Option<String>> {
    let mut reader = BufReader::new(client);
    let mut proxy_auth = None;

    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':')
            && name.eq_ignore_ascii_case("proxy-authorization")
        {
            proxy_auth = Some(value.trim().to_string());
        }
    }

    reader
        .into_inner()
        .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
        .await?;

    Ok(proxy_auth)
}

async fn received_auth_header(
    mut stream: tokio_rustls::server::TlsStream<TcpStream>,
) -> io::Result<String> {
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let headers = String::from_utf8_lossy(&buf);
    let auth = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then(|| value.trim().to_string())
        })
        .unwrap_or_default();

    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await?;
    stream.shutdown().await?;

    Ok(auth)
}

fn test_server_tls_config() -> Arc<rustls::ServerConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key_pair = rcgen::KeyPair::generate().expect("generate key");
    let params = CertificateParams::new(vec!["host.microsandbox.internal".to_string()])
        .expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-sign cert");
    let chain = vec![CertificateDer::from(cert.der().to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server config"),
    )
}

async fn teardown(sb: Sandbox, name: &str) {
    let _ = sb.stop().await;
    let _ = Sandbox::remove(name).await;
}

// Tests

#[msb_test]
async fn https_connect_proxy_substitutes_secret_in_authorization_header() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut target = TargetHttps::start().await.expect("target fixture");
    let target_port = target.port();
    let mut proxy = ConnectProxy::start(target_port)
        .await
        .expect("proxy fixture");
    let proxy_port = proxy.port();
    let name = "http-connect-secret-auth";

    let sb = Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .secret(|s| {
            s.env("API_KEY")
                .value(REAL_SECRET)
                .allow_host("host.microsandbox.internal")
        })
        .network(|n| {
            n.policy(NetworkPolicy::allow_all()).tls(|t| {
                t.intercepted_ports(vec![target_port])
                    .verify_upstream(false)
            })
        })
        .create()
        .await
        .expect("create sandbox");

    let out = sb
        .shell(format!(
            r#"curl -k --http1.1 -m 30 -sS -o /dev/null \
  -w 'code=%{{http_code}}' \
  -H "Authorization: Bearer $API_KEY" \
  --proxytunnel \
  --proxy http://host.microsandbox.internal:{proxy_port} \
  https://host.microsandbox.internal:{target_port}/api"#
        ))
        .await
        .expect("curl through connect proxy");

    let stdout = out.stdout().unwrap_or_default();
    if !stdout.contains("code=200") {
        let proxy_status = tokio::time::timeout(std::time::Duration::from_secs(3), proxy.join())
            .await
            .map_err(|_| "proxy timed out".to_string())
            .and_then(|res| res.map_err(|err| err.to_string()));
        let target_auth =
            tokio::time::timeout(std::time::Duration::from_secs(3), target.received_auth())
                .await
                .map_err(|_| "target timed out".to_string())
                .and_then(|res| res.map_err(|err| err.to_string()));
        panic!(
            "expected 200 from target, got: {stdout} (stderr: {}), proxy={proxy_status:?}, target={target_auth:?}",
            out.stderr().unwrap_or_default()
        );
    }

    let auth = target.received_auth().await.expect("target auth");
    assert_eq!(
        auth,
        format!("Bearer {REAL_SECRET}"),
        "proxy must substitute placeholder in tunnelled HTTPS request; got: {auth:?}"
    );

    let _ = proxy.join().await;
    teardown(sb, name).await;
}

#[msb_test]
async fn https_connect_proxy_blocks_secret_for_wrong_host() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut target = TargetHttps::start().await.expect("target fixture");
    let target_port = target.port();
    let proxy = ConnectProxy::start(target_port)
        .await
        .expect("proxy fixture");
    let proxy_port = proxy.port();
    let name = "http-connect-secret-wrong-host";

    let sb = Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .secret(|s| {
            s.env("API_KEY")
                .value(REAL_SECRET)
                .allow_host("api.allowed.test")
        })
        .network(|n| {
            n.policy(NetworkPolicy::allow_all()).tls(|t| {
                t.intercepted_ports(vec![target_port])
                    .verify_upstream(false)
            })
        })
        .create()
        .await
        .expect("create sandbox");

    let out = sb
        .shell(format!(
            r#"set +e
curl -k --http1.1 -m 10 -sS -o /dev/null \
  -w 'code=%{{http_code}}' \
  -H "Authorization: Bearer $API_KEY" \
  --proxytunnel \
  --proxy http://host.microsandbox.internal:{proxy_port} \
  https://host.microsandbox.internal:{target_port}/api
echo "status=$?"
"#
        ))
        .await
        .expect("curl wrong host");

    let stdout = out.stdout().unwrap_or_default();
    if stdout.trim_end().ends_with("status=0") {
        let auth =
            tokio::time::timeout(std::time::Duration::from_secs(5), target.received_auth()).await;
        let auth_val = match auth {
            Ok(Ok(a)) => a,
            _ => String::new(),
        };
        panic!(
            "expected curl to fail when secret host does not match tunnel target; got: {stdout:?}; target auth: {auth_val:?}"
        );
    }

    let auth =
        tokio::time::timeout(std::time::Duration::from_secs(5), target.received_auth()).await;
    let auth_val = match auth {
        Ok(Ok(a)) => a,
        _ => String::new(),
    };
    assert!(
        !auth_val.contains(REAL_SECRET) && !auth_val.contains(PLACEHOLDER),
        "real secret must not reach target when host does not match; got: {auth_val:?}"
    );

    drop(proxy);
    teardown(sb, name).await;
}

#[msb_test]
async fn https_connect_proxy_leaves_non_intercepted_target_port_opaque() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut target = TargetHttps::start().await.expect("target fixture");
    let target_port = target.port();
    let mut proxy = ConnectProxy::start(target_port)
        .await
        .expect("proxy fixture");
    let proxy_port = proxy.port();
    let intercepted_port = if target_port == 443 { 444 } else { 443 };
    let name = "http-connect-secret-non-intercepted";

    let sb = Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .secret(|s| {
            s.env("API_KEY")
                .value(REAL_SECRET)
                .allow_host("host.microsandbox.internal")
        })
        .network(|n| {
            n.policy(NetworkPolicy::allow_all()).tls(|t| {
                t.intercepted_ports(vec![intercepted_port])
                    .verify_upstream(false)
            })
        })
        .create()
        .await
        .expect("create sandbox");

    let out = sb
        .shell(format!(
            r#"curl -k --http1.1 -m 30 -sS -o /dev/null \
  -w 'code=%{{http_code}}' \
  -H "Authorization: Bearer $API_KEY" \
  --proxytunnel \
  --proxy http://host.microsandbox.internal:{proxy_port} \
  https://host.microsandbox.internal:{target_port}/api"#
        ))
        .await
        .expect("curl through connect proxy");

    let stdout = out.stdout().unwrap_or_default();
    if !stdout.contains("code=200") {
        let proxy_status = tokio::time::timeout(std::time::Duration::from_secs(3), proxy.join())
            .await
            .map_err(|_| "proxy timed out".to_string())
            .and_then(|res| res.map_err(|err| err.to_string()));
        let target_auth =
            tokio::time::timeout(std::time::Duration::from_secs(3), target.received_auth())
                .await
                .map_err(|_| "target timed out".to_string())
                .and_then(|res| res.map_err(|err| err.to_string()));
        panic!(
            "expected 200 from opaque target tunnel, got: {stdout} (stderr: {}), proxy={proxy_status:?}, target={target_auth:?}",
            out.stderr().unwrap_or_default()
        );
    }

    let auth = target.received_auth().await.expect("target auth");
    assert!(
        auth.contains(PLACEHOLDER),
        "non-intercepted target port must receive the placeholder unchanged; got: {auth:?}"
    );
    assert!(
        !auth.contains(REAL_SECRET),
        "non-intercepted target port must not receive the real secret; got: {auth:?}"
    );

    let _ = proxy.join().await;
    teardown(sb, name).await;
}

#[msb_test]
async fn https_connect_proxy_blocks_secret_in_outer_connect_headers() {
    let mut proxy = ProxyAuthCapture::start()
        .await
        .expect("proxy capture fixture");
    let proxy_port = proxy.port();
    let name = "http-connect-secret-outer-header";

    let sb = Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .secret(|s| {
            s.env("API_KEY")
                .value(REAL_SECRET)
                .allow_host("host.microsandbox.internal")
        })
        .network(|n| n.policy(NetworkPolicy::allow_all()))
        .create()
        .await
        .expect("create sandbox");

    let out = sb
        .shell(format!(
            r#"set +e
curl -k --http1.1 -m 10 -sS -o /dev/null \
  --proxytunnel \
  --proxy http://host.microsandbox.internal:{proxy_port} \
  --proxy-header "Proxy-Authorization: Bearer $API_KEY" \
  https://example.com/
echo "status=$?"
"#
        ))
        .await
        .expect("curl through connect proxy");

    let stdout = out.stdout().unwrap_or_default();
    assert!(
        !stdout.trim_end().ends_with("status=0"),
        "expected curl to fail when the outer CONNECT header carries a protected placeholder; got: {stdout:?}"
    );

    let proxy_auth = proxy
        .try_received_auth(std::time::Duration::from_secs(5))
        .await
        .unwrap_or_default();
    assert!(
        !proxy_auth.contains(PLACEHOLDER) && !proxy_auth.contains(REAL_SECRET),
        "CONNECT proxy must not receive a raw placeholder or real secret in outer headers; got: {proxy_auth:?}"
    );

    teardown(sb, name).await;
}

/// Corporate proxy topology where the target is never DNS-resolved by the guest.
/// curl sends `CONNECT target:PORT` raw; the DNS cache has no entry for the target.
#[msb_test]
async fn https_connect_proxy_substitutes_secret_when_target_not_in_dns_cache() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut target = TargetHttps::start().await.expect("target fixture");
    let target_port = target.port();
    let mut proxy = ConnectProxy::start(target_port)
        .await
        .expect("proxy fixture");
    let proxy_port = proxy.port();
    let name = "http-connect-secret-no-dns-cache";

    let sb = Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .secret(|s| {
            s.env("API_KEY")
                .value(REAL_SECRET)
                .allow_host(FAKE_TARGET_HOST)
        })
        .network(|n| {
            n.policy(NetworkPolicy::allow_all()).tls(|t| {
                t.intercepted_ports(vec![target_port])
                    .verify_upstream(false)
            })
        })
        .create()
        .await
        .expect("create sandbox");

    // Inject the fake target into /etc/hosts so the OS can reach it,
    // but do NOT resolve it via DNS first; the DNS cache stays empty.
    let out = sb
        .shell(format!(
            r#"GATEWAY_IP=$(awk '/^nameserver/{{print $2; exit}}' /etc/resolv.conf)
echo "$GATEWAY_IP {FAKE_TARGET_HOST}" >> /etc/hosts
curl -k --http1.1 -m 30 -sS -o /dev/null \
  -w 'code=%{{http_code}}' \
  -H "Authorization: Bearer $API_KEY" \
  --proxytunnel \
  --proxy http://host.microsandbox.internal:{proxy_port} \
  https://{FAKE_TARGET_HOST}:{target_port}/api"#
        ))
        .await
        .expect("curl through connect proxy");

    let stdout = out.stdout().unwrap_or_default();
    if !stdout.contains("code=200") {
        let proxy_status = tokio::time::timeout(std::time::Duration::from_secs(3), proxy.join())
            .await
            .map_err(|_| "proxy timed out".to_string())
            .and_then(|res| res.map_err(|err| err.to_string()));
        let target_auth =
            tokio::time::timeout(std::time::Duration::from_secs(3), target.received_auth())
                .await
                .map_err(|_| "target timed out".to_string())
                .and_then(|res| res.map_err(|err| err.to_string()));
        panic!(
            "expected 200, got: {stdout} (stderr: {}), proxy={proxy_status:?}, target={target_auth:?}",
            out.stderr().unwrap_or_default()
        );
    }

    let auth = target.received_auth().await.expect("target auth");
    assert_eq!(
        auth,
        format!("Bearer {REAL_SECRET}"),
        "secret must be substituted even when the target was never in the DNS cache; got: {auth:?}"
    );

    let _ = proxy.join().await;
    teardown(sb, name).await;
}

/// Same corporate proxy topology, but the guest DNS-resolves the target before
/// the proxied request. Cache is seeded with target → gateway IP, which differs
/// from the proxy IP.
#[msb_test]
async fn https_connect_proxy_substitutes_secret_after_prior_dns_lookup() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut target = TargetHttps::start().await.expect("target fixture");
    let target_port = target.port();
    let mut proxy = ConnectProxy::start(target_port)
        .await
        .expect("proxy fixture");
    let proxy_port = proxy.port();
    let name = "http-connect-secret-dns-pre-resolved";

    let sb = Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .secret(|s| {
            s.env("API_KEY")
                .value(REAL_SECRET)
                .allow_host(FAKE_TARGET_HOST)
        })
        .network(|n| {
            n.policy(NetworkPolicy::allow_all()).tls(|t| {
                t.intercepted_ports(vec![target_port])
                    .verify_upstream(false)
            })
        })
        .create()
        .await
        .expect("create sandbox");

    // Inject the fake target into /etc/hosts then resolve it via
    // nslookup so the sandbox DNS cache is seeded with
    // FAKE_TARGET_HOST → gateway IP before the proxied request.
    let out = sb
        .shell(format!(
            r#"GATEWAY_IP=$(awk '/^nameserver/{{print $2; exit}}' /etc/resolv.conf)
echo "$GATEWAY_IP {FAKE_TARGET_HOST}" >> /etc/hosts
nslookup {FAKE_TARGET_HOST} >/dev/null 2>&1
curl -k --http1.1 -m 30 -sS -o /dev/null \
  -w 'code=%{{http_code}}' \
  -H "Authorization: Bearer $API_KEY" \
  --proxytunnel \
  --proxy http://host.microsandbox.internal:{proxy_port} \
  https://{FAKE_TARGET_HOST}:{target_port}/api"#
        ))
        .await
        .expect("curl after dns pre-resolve");

    let stdout = out.stdout().unwrap_or_default();
    if !stdout.contains("code=200") {
        let proxy_status = tokio::time::timeout(std::time::Duration::from_secs(3), proxy.join())
            .await
            .map_err(|_| "proxy timed out".to_string())
            .and_then(|res| res.map_err(|err| err.to_string()));
        let target_auth =
            tokio::time::timeout(std::time::Duration::from_secs(3), target.received_auth())
                .await
                .map_err(|_| "target timed out".to_string())
                .and_then(|res| res.map_err(|err| err.to_string()));
        panic!(
            "expected 200, got: {stdout} (stderr: {}), proxy={proxy_status:?}, target={target_auth:?}",
            out.stderr().unwrap_or_default()
        );
    }

    let auth = target.received_auth().await.expect("target auth");
    assert_eq!(
        auth,
        format!("Bearer {REAL_SECRET}"),
        "secret must be substituted when target was DNS-resolved before the proxied request; got: {auth:?}"
    );

    let _ = proxy.join().await;
    teardown(sb, name).await;
}
