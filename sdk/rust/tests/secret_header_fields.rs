//! Real-guest coverage for header restrictions and persisted policy updates.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use microsandbox::{NetworkPolicy, Sandbox, SecretSubstitution};
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use test_utils::msb_test;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, server::TlsStream};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const HOST: &str = "host.microsandbox.internal";
const SECRET: &str = "synthetic-header-secret";
const PLACEHOLDER: &str = "MSB_HEADER_TOKEN";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type Headers = BTreeMap<String, String>;

/// Records upstream requests independently and reflects only X-Reflected.
struct HeaderServer {
    port: u16,
    requests: mpsc::Receiver<Result<Headers>>,
    task: JoinHandle<()>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HeaderServer {
    async fn start(http2: bool) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let v4 = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = v4.local_addr()?.port();
        let v6 = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await?;

        let cert = generate_simple_self_signed(vec![HOST.into()])?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)?;

        tls.alpn_protocols = vec![if http2 {
            b"h2".to_vec()
        } else {
            b"http/1.1".to_vec()
        }];

        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let (tx, requests) = mpsc::channel(8);

        let task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    accepted = v4.accept() => accepted,
                    accepted = v6.accept() => accepted,
                };

                let result = async {
                    let (stream, _) = accepted?;
                    let tls = acceptor.accept(stream).await?;

                    if http2 {
                        receive_http2(tls).await
                    } else {
                        receive_http1(tls).await
                    }
                };

                let result = tokio::time::timeout(Duration::from_secs(40), result)
                    .await
                    .context("upstream request timed out")
                    .and_then(|result| result);

                if tx.send(result).await.is_err() {
                    break;
                }
            }
        });

        Ok(Self {
            port,
            requests,
            task,
        })
    }

    async fn received(&mut self) -> Result<Headers> {
        tokio::time::timeout(Duration::from_secs(45), self.requests.recv())
            .await?
            .context("upstream fixture stopped")?
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for HeaderServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn receive_http1(mut tls: TlsStream<TcpStream>) -> Result<Headers> {
    let mut bytes = Vec::new();

    loop {
        let mut chunk = [0; 4096];
        let count = tls.read(&mut chunk).await?;
        ensure!(count > 0, "connection closed before request headers");

        bytes.extend_from_slice(&chunk[..count]);
        if bytes.windows(4).any(|part| part == b"\r\n\r\n") {
            break;
        }

        ensure!(bytes.len() < 64 * 1024, "fixture headers too large");
    }

    let request = std::str::from_utf8(&bytes)?;
    ensure!(
        request
            .lines()
            .next()
            .unwrap_or_default()
            .ends_with("HTTP/1.1")
    );

    let headers: Headers = request
        .lines()
        .skip(1)
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().into()))
        })
        .collect();

    let reflected = headers
        .get("x-reflected")
        .context("missing reflected header")?;

    tls.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reflected}",
            reflected.len()
        )
        .as_bytes(),
    )
    .await?;
    tls.shutdown().await?;

    Ok(headers)
}

async fn receive_http2(tls: TlsStream<TcpStream>) -> Result<Headers> {
    // The interception proxy does not negotiate ALPN. The guest uses explicit
    // HTTP/2 prior knowledge; this handshake independently verifies real h2 bytes.
    let mut connection = h2::server::handshake(tls).await?;
    let (request, mut response) = connection
        .accept()
        .await
        .context("missing HTTP/2 request")??;

    let headers = request
        .headers()
        .iter()
        .map(|(name, value)| Ok((name.as_str().to_owned(), value.to_str()?.to_owned())))
        .collect::<Result<Headers>>()?;

    let reflected = headers
        .get("x-reflected")
        .context("missing reflected header")?;
    let mut body =
        response.send_response(http::Response::builder().status(200).body(())?, false)?;
    body.send_data(reflected.clone().into(), true)?;

    // Drive the connection until curl receives the response and closes it.
    connection.graceful_shutdown();
    if let Some(next) = connection.accept().await {
        let _ = next?;
        anyhow::bail!("unexpected second request on fixture connection");
    }

    Ok(headers)
}

async fn probe(
    sb: &Sandbox,
    server: &mut HeaderServer,
    http2: bool,
    basic: bool,
    fields: &[&str],
) -> Result<()> {
    let protocol = if http2 {
        "--http2-prior-knowledge --no-alpn"
    } else {
        "--http1.1"
    };
    let auth = if basic {
        "-u \"user:$API_KEY\""
    } else {
        "-H \"Authorization: Bearer $API_KEY\""
    };

    let output = sb
        .shell(format!(
            "curl -k {protocol} --fail-with-body --max-time 30 --silent --show-error \
         {auth} -H \"X-API-Key: $API_KEY\" -H \"X-Reflected: $API_KEY\" \
         https://{HOST}:{}/headers",
            server.port
        ))
        .await?;

    ensure!(
        output.status().success,
        "guest curl failed: {}",
        output.stderr()?
    );

    let headers = server.received().await?;
    let value_for = |name: &str| {
        if fields.is_empty() || fields.iter().any(|field| field.eq_ignore_ascii_case(name)) {
            SECRET
        } else {
            PLACEHOLDER
        }
    };
    let expected_auth = if basic {
        format!(
            "Basic {}",
            STANDARD.encode(format!("user:{}", value_for("authorization")))
        )
    } else {
        format!("Bearer {}", value_for("authorization"))
    };

    ensure!(
        headers.get("authorization") == Some(&expected_auth),
        "wrong upstream Authorization"
    );
    ensure!(
        headers.get("x-api-key").map(String::as_str) == Some(value_for("x-api-key")),
        "wrong upstream API key"
    );
    ensure!(
        headers.get("x-reflected").map(String::as_str) == Some(value_for("x-reflected")),
        "wrong upstream reflected header"
    );

    ensure!(
        output.stdout()? == value_for("x-reflected"),
        "unexpected guest response: {:?}",
        output.stderr()?
    );

    Ok(())
}

async fn exercise_header_policy(http2: bool) -> Result<()> {
    let mut server = HeaderServer::start(http2).await?;
    let name = if http2 {
        "header-fields-http2"
    } else {
        "header-fields-http1"
    };

    let sb = Sandbox::builder(name)
        .image("mirror.gcr.io/curlimages/curl")
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .secret(|secret| {
            secret
                .env("API_KEY")
                .value(SECRET)
                .placeholder(PLACEHOLDER)
                .allow(HOST)
                .substitute_in_header_fields(["Authorization", "X-API-Key"])
        })
        .network(|network| {
            network.policy(NetworkPolicy::allow_all()).tls(|tls| {
                tls.intercepted_ports(vec![server.port])
                    .verify_upstream(false)
            })
        })
        .create()
        .await?;

    let result = async {
        let fields = ["Authorization", "X-API-Key"];

        probe(&sb, &mut server, http2, false, &fields).await?;
        probe(&sb, &mut server, http2, true, &fields).await?;
        drop(sb);

        // Change only the header names, preserving material and the other scopes.
        // Reopen/start the persisted sandbox to verify actual runtime enforcement.
        for fields in [vec!["x-api-key"], Vec::new()] {
            let handle = Sandbox::get(name).await?;
            handle.stop().await?;

            let plan = handle
                .modify()
                .secret(|secret| {
                    secret.env("API_KEY").substitution(SecretSubstitution {
                        header_fields: fields.iter().map(|field| (*field).to_string()).collect(),
                        ..SecretSubstitution::default()
                    })
                })
                .apply()
                .await?;

            ensure!(
                plan.applied && !plan.changes.is_empty(),
                "header-only update was not applied"
            );

            let restarted = Sandbox::get(name).await?.start().await?;

            probe(&restarted, &mut server, http2, false, &fields).await?;
            probe(&restarted, &mut server, http2, true, &fields).await?;

            drop(restarted);
        }

        Ok(())
    }
    .await;

    // Always attempt cleanup, preserving the test failure if both fail.
    let cleanup: Result<()> = async {
        let handle = Sandbox::get(name).await?;
        handle.stop().await?;
        Sandbox::remove(name).await?;

        Ok(())
    }
    .await;

    result.and(cleanup)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn header_fields_http1_survive_policy_updates_and_restart() {
    exercise_header_policy(false).await.unwrap();
}

#[msb_test]
async fn header_fields_http2_survive_policy_updates_and_restart() {
    exercise_header_policy(true).await.unwrap();
}
