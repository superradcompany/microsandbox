//! Integration tests for plain-HTTP secret substitution.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use microsandbox::{NetworkPolicy, Sandbox};
use test_utils::msb_test;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

// Constants

const ALPINE_IMAGE: &str = "alpine";
const REAL_SECRET: &str = "real-secret-plain-http";
/// Placeholder the guest sees for the `API_KEY` secret: the env var name with
/// the `MSB_` prefix the runtime injects.
const PLACEHOLDER: &str = "MSB_API_KEY";

// Types

/// Minimal HTTP server that accepts one connection and returns the Authorization header value.
struct HostHttp {
    port: u16,
    handle: Option<JoinHandle<io::Result<String>>>,
}

// Methods

impl HostHttp {
    async fn start() -> io::Result<Self> {
        let v4_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = v4_listener.local_addr()?.port();
        let v6_listener = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await?;

        let handle = tokio::spawn(async move {
            let (stream, _) = tokio::select! {
                accept = v4_listener.accept() => accept?,
                accept = v6_listener.accept() => accept?,
            };

            let mut reader = BufReader::new(stream);
            let mut auth = String::new();

            loop {
                let mut line = String::new();
                reader.read_line(&mut line).await?;
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    break;
                }
                if trimmed.to_ascii_lowercase().starts_with("authorization:") {
                    auth = trimmed
                        .splitn(2, ':')
                        .nth(1)
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                }
            }

            reader
                .into_inner()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await?;

            Ok(auth)
        });

        // Wait until someone actually connected before returning, so the caller
        // knows the port is live.
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
            .expect("http fixture already consumed")
            .await
            .map_err(io::Error::other)?
    }

    /// Like [`received_auth`], but returns `None` if no usable request arrived
    /// within the timeout (e.g. the proxy blocked the connection).
    async fn try_received_auth(&mut self, timeout: std::time::Duration) -> Option<String> {
        let handle = self.handle.take().expect("http fixture already consumed");
        match tokio::time::timeout(timeout, handle).await {
            Ok(joined) => joined.ok().and_then(|res| res.ok()),
            Err(_) => None,
        }
    }
}

impl Drop for HostHttp {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

// Functions

async fn teardown(sb: Sandbox, name: &str) {
    // Best-effort: a dropped proxy connection can break the agent pipe, so a
    // stop error here is cleanup noise, not a test failure.
    let _ = sb.stop().await;
    let _ = Sandbox::remove(name).await;
}

// Tests

#[msb_test]
async fn plain_http_substitutes_secret_in_authorization_header() {
    let mut server = HostHttp::start().await.expect("http fixture");
    let port = server.port();
    let name = "plain-http-secret-auth-header";

    let sb = Sandbox::builder(name)
        .image(ALPINE_IMAGE)
        .cpus(1)
        .memory(256)
        .replace()
        .secret(|s| {
            s.env("API_KEY")
                .value(REAL_SECRET)
                .allow_any_host_dangerous(true)
                .require_tls_identity(false)
        })
        .network(|n| n.policy(NetworkPolicy::allow_all()))
        .create()
        .await
        .expect("create sandbox");

    sb.shell(format!(
        r#"wget -O - --header="Authorization: Bearer $API_KEY" http://host.microsandbox.internal:{port}/ 2>/dev/null"#
    ))
    .await
    .expect("wget");

    let auth = server.received_auth().await.expect("read fixture auth");
    assert_eq!(
        auth,
        format!("Bearer {REAL_SECRET}"),
        "proxy must substitute placeholder before forwarding; got: {auth:?}"
    );

    teardown(sb, name).await;
}

#[msb_test]
async fn plain_http_does_not_substitute_secret_without_opt_in() {
    let mut server = HostHttp::start().await.expect("http fixture");
    let port = server.port();
    let name = "plain-http-secret-no-opt-in";

    let sb = Sandbox::builder(name)
        .image(ALPINE_IMAGE)
        .cpus(1)
        .memory(256)
        .replace()
        .secret(|s| {
            s.env("API_KEY")
                .value(REAL_SECRET)
                .allow_any_host_dangerous(true)
        })
        .network(|n| n.policy(NetworkPolicy::allow_all()))
        .create()
        .await
        .expect("create sandbox");

    sb.shell(format!(
        r#"wget -O - --header="Authorization: Bearer $API_KEY" http://host.microsandbox.internal:{port}/ 2>/dev/null"#
    ))
    .await
    .expect("wget");

    let auth = server.received_auth().await.expect("read fixture auth");
    assert!(
        auth.contains(PLACEHOLDER),
        "placeholder must be forwarded unchanged when require_tls_identity is not opted out; got: {auth:?}"
    );
    assert!(
        !auth.contains(REAL_SECRET),
        "real secret must not reach server over plain HTTP without require_tls_identity(false); got: {auth:?}"
    );

    teardown(sb, name).await;
}

#[msb_test]
async fn plain_http_invalid_host_blocks_host_bound_secret() {
    // A host-bound secret is only substituted when the proxy can prove the
    // destination host. Two requests with the same secret isolate that: one
    // with a Host header (provable → substituted), one without (unprovable →
    // withheld).
    let mut control_server = HostHttp::start().await.expect("control fixture");
    let control_port = control_server.port();
    let mut test_server = HostHttp::start().await.expect("test fixture");
    let test_port = test_server.port();
    let name = "plain-http-secret-invalid-host";

    // Host-bound secret (Exact, not Any), opted into plain-HTTP substitution.
    let sb = Sandbox::builder(name)
        .image(ALPINE_IMAGE)
        .cpus(1)
        .memory(256)
        .replace()
        .secret(|s| {
            s.env("API_KEY")
                .value(REAL_SECRET)
                .allow_host("host.microsandbox.internal")
                .require_tls_identity(false)
        })
        .network(|n| n.policy(NetworkPolicy::allow_all()))
        .create()
        .await
        .expect("create sandbox");

    // Control: Host present, so the host is provable. `$API_KEY` is a printf
    // arg so the shell expands it while the \r\n stay literal.
    sb.shell(format!(
        "printf 'GET / HTTP/1.0\\r\\nHost: host.microsandbox.internal\\r\\n\
         Authorization: Bearer %s\\r\\n\\r\\n' \"$API_KEY\" \
         | nc host.microsandbox.internal {control_port}"
    ))
    .await
    .expect("control nc");

    let control_auth = control_server.received_auth().await.expect("control auth");
    assert_eq!(
        control_auth,
        format!("Bearer {REAL_SECRET}"),
        "host-bound secret must be substituted when the Host is provable; got: {control_auth:?}"
    );

    // Test: no Host header. The exec outcome is irrelevant (the proxy drops the
    // connection, which can break the guest pipe) — only what the server sees.
    let _ = sb
        .shell(format!(
            "printf 'GET / HTTP/1.0\\r\\nAuthorization: Bearer %s\\r\\n\\r\\n' \"$API_KEY\" \
             | nc host.microsandbox.internal {test_port} || true"
        ))
        .await;

    // With the host unprovable the secret is ineligible, so the request is
    // blocked and the server receives nothing. Reject both the real value and
    // the placeholder: either one reaching the server means the request was
    // relayed instead of blocked.
    let test_auth = test_server
        .try_received_auth(std::time::Duration::from_secs(5))
        .await
        .unwrap_or_default();
    assert!(
        !test_auth.contains(REAL_SECRET) && !test_auth.contains(PLACEHOLDER),
        "no secret material must reach the server when the host is unprovable; got: {test_auth:?}"
    );

    teardown(sb, name).await;
}
