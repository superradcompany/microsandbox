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
    sb.stop_and_wait().await.expect("stop");
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
        auth.contains("MSB_API_KEY"),
        "placeholder must be forwarded unchanged when require_tls_identity is not opted out; got: {auth:?}"
    );
    assert!(
        !auth.contains(REAL_SECRET),
        "real secret must not reach server over plain HTTP without require_tls_identity(false); got: {auth:?}"
    );

    teardown(sb, name).await;
}
