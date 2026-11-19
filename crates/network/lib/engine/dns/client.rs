//! Upstream DNS client builders.
//!
//! The forwarder is responsible for *policy and routing* — this module
//! is responsible for *construction*. Given a `(SocketAddr, Transport)`
//! pair (plus an optional SNI hint for DoT), produce a hickory
//! [`Client`] ready to send queries. The forwarder imports these
//! functions to build its configured-upstream client(s) at startup
//! and per-query clients on the direct path.
//!
//! These functions operate in the **forwarder → upstream resolver**
//! direction — distinct from `dns/udp.rs` and `dns/tcp/` which handle
//! the **guest → forwarder** direction.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use hickory_net::client::Client as GenericClient;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;
use rustls::ClientConfig;
#[cfg(windows)]
use rustls_platform_verifier::BuilderVerifierExt;

use super::common::transport::Transport;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Upstream DNS client over the Tokio runtime. hickory 0.26 made
/// [`GenericClient`] generic over the runtime provider; every upstream
/// client in this crate runs on Tokio, so the concrete type is fixed
/// here once and the rest of the DNS code keeps using plain `Client`.
pub(super) type Client = GenericClient<TokioRuntimeProvider>;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build a hickory UDP client connected to `addr` with the given
/// per-query timeout. Logs and returns `None` on connect error.
pub(super) async fn build_udp_client(addr: SocketAddr, timeout: Duration) -> Option<Client> {
    // Since hickory 0.26 the UDP stream is handed to the client as a
    // request sender; socket errors surface per-query instead of at
    // build time, so this constructor is infallible.
    let stream = UdpClientStream::builder(addr, TokioRuntimeProvider::new())
        .with_timeout(Some(timeout))
        .build();
    let (client, bg) = Client::from_sender(stream);
    tokio::spawn(bg);
    Some(client)
}

/// Build a hickory TCP client connected to `addr` with the given
/// connect+query timeout. Logs and returns `None` on connect error.
pub(super) async fn build_tcp_client(addr: SocketAddr, timeout: Duration) -> Option<Client> {
    let (stream_future, sender) =
        TcpClientStream::new(addr, None, Some(timeout), TokioRuntimeProvider::new());
    let stream = match stream_future.await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!(upstream = %addr, error = %e, "failed to build TCP DNS client");
            return None;
        }
    };
    // `with_timeout` (not `new`) so the per-query response timeout honors the
    // configured `query_timeout`; `Client::new` silently falls back to
    // hickory's 5s default, unlike the UDP/DoT builders above/below.
    let (client, bg) = Client::with_timeout(stream, sender, timeout);
    tokio::spawn(bg);
    Some(client)
}

/// Build a hickory DoT (DNS over TLS) client connected to `addr`.
/// `sni` is the server name the upstream TLS handshake validates the
/// cert against. Uses the host's native trust roots for verification.
pub(super) async fn build_dot_client(
    addr: SocketAddr,
    sni: String,
    timeout: Duration,
) -> Option<Client> {
    use hickory_net::tls::tls_client_connect;
    use rustls::pki_types::ServerName;

    let server_name = match ServerName::try_from(sni.clone()) {
        Ok(name) => name,
        Err(e) => {
            tracing::warn!(upstream = %addr, sni = %sni, error = %e, "invalid SNI for DoT");
            return None;
        }
    };
    let client_config = match dot_upstream_client_config() {
        Ok(config) => config,
        Err(error) => {
            tracing::warn!(upstream = %addr, %error, "failed to configure DoT certificate verification");
            return None;
        }
    };
    let (stream_future, sender) = tls_client_connect(
        addr,
        server_name,
        client_config,
        TokioRuntimeProvider::new(),
    );
    let stream = match stream_future.await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::warn!(upstream = %addr, error = %e, "failed to build DoT client");
            return None;
        }
    };
    let (client, bg) = Client::with_timeout(stream, sender, timeout);
    tokio::spawn(bg);
    Some(client)
}

/// Build a one-shot upstream client to a guest-chosen `@target`
/// resolver. `sni` is consulted only for [`Transport::Dot`] — it's the
/// server name the upstream TLS client validates the certificate
/// against. `None` falls back to the target IP as a string, which some
/// DoT resolvers may reject.
pub(super) async fn build_direct_client(
    addr: SocketAddr,
    transport: Transport,
    sni: Option<&str>,
    timeout: Duration,
) -> Option<Client> {
    match transport {
        Transport::Udp => build_udp_client(addr, timeout).await,
        Transport::Tcp => build_tcp_client(addr, timeout).await,
        Transport::Dot => {
            let sni = sni
                .map(|s| s.to_string())
                .unwrap_or_else(|| addr.ip().to_string());
            build_dot_client(addr, sni, timeout).await
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Internal
//--------------------------------------------------------------------------------------------------

/// Build the rustls `ClientConfig` for upstream DoT connections.
/// Uses native Windows chain validation, including automatic trusted-root retrieval.
/// Other platforms retain the existing native-root snapshot. Cache only successful
/// initialization; a verifier setup error must fail closed without poisoning later calls.
fn dot_upstream_client_config() -> Result<Arc<ClientConfig>, rustls::Error> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if let Some(config) = CONFIG.get() {
        return Ok(Arc::clone(config));
    }

    // Enumerating Windows' root store sees only cached roots. The native chain engine
    // can retrieve an approved root on first use while still enforcing host trust policy.
    #[cfg(windows)]
    let client_config = ClientConfig::builder()
        .with_platform_verifier()?
        .with_no_client_auth();

    #[cfg(not(windows))]
    let client_config = {
        let mut root_store = rustls::RootCertStore::empty();
        let certs = rustls_native_certs::load_native_certs();
        if !certs.errors.is_empty() {
            tracing::warn!(
                count = certs.errors.len(),
                "errors loading native certificates for DoT upstream"
            );
        }
        for cert in certs.certs {
            let _ = root_store.add(cert);
        }
        if root_store.is_empty() {
            tracing::error!(
                "no native root certificates loaded — DoT upstream will fail to verify any resolver"
            );
        }

        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };
    Ok(Arc::clone(CONFIG.get_or_init(|| Arc::new(client_config))))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use hickory_net::proto::op::{DnsRequest, Message, MessageType, OpCode, Query};
    use hickory_net::proto::rr::{Name, RecordType};
    use hickory_net::xfer::DnsHandle;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use std::time::Instant;
    use tokio::io::AsyncReadExt;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    #[tokio::test]
    async fn dot_upstream_rejects_untrusted_certificate() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            TlsAcceptor::from(Arc::new(server_config))
                .accept(socket)
                .await
        });
        let socket = tokio::net::TcpStream::connect(address).await.unwrap();
        let connector = TlsConnector::from(dot_upstream_client_config().unwrap());
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            connector.connect(ServerName::try_from("localhost").unwrap(), socket),
        )
        .await
        .expect("local TLS handshake must finish");
        // The socket connected and the server presented a certificate for the right name.
        // Reject its untrusted issuer without modifying the machine's trusted root store.
        assert!(result.is_err(), "DoT must reject an untrusted certificate");
        assert!(
            tokio::time::timeout(Duration::from_secs(10), server)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires access to the public DoT resolver at 1.1.1.1:853"]
    async fn dot_upstream_verifies_live_resolver_hostname() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let address = "1.1.1.1:853".parse().unwrap();
        let timeout = Duration::from_secs(15);
        // First establish that this exact resolver is reachable and its chain is trusted,
        // so the negative assertion cannot pass merely because the network is unavailable.
        let accepted = tokio::time::timeout(
            timeout,
            build_dot_client(address, "1.1.1.1".to_owned(), timeout),
        )
        .await
        .unwrap();
        assert!(accepted.is_some(), "valid resolver certificate must verify");
        let rejected = tokio::time::timeout(
            timeout,
            build_dot_client(address, "wrong-resolver.invalid".to_owned(), timeout),
        )
        .await
        .unwrap();
        assert!(rejected.is_none(), "DoT must reject a mismatched hostname");
    }

    fn example_query() -> Message {
        let mut msg = Message::new(0x4242, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        msg
    }

    /// Black-hole TCP server: accept + drain the query, never send a reply.
    async fn blackhole_tcp() -> SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while s.read(&mut buf).await.unwrap_or(0) > 0 {}
                });
            }
        });
        addr
    }

    /// Black-hole UDP server: recv the query, never send a reply.
    async fn blackhole_udp() -> SocketAddr {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = s.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 4096];
            loop {
                let _ = s.recv_from(&mut b).await;
            }
        });
        addr
    }

    /// A stalled upstream must time out at the *configured* `query_timeout`,
    /// not hang and not fall back to hickory's 5s default. `build_tcp_client`
    /// regressed to the default when it used `Client::new`; this guards the
    /// `Client::with_timeout` fix.
    async fn assert_upstream_honors_timeout(
        label: &str,
        addr: SocketAddr,
        build: impl std::future::Future<Output = Option<Client>>,
    ) {
        let client = build.await.unwrap_or_else(|| panic!("{label} client"));
        let mut send = client.send(DnsRequest::from(example_query()));
        let start = Instant::now();
        let outcome = tokio::time::timeout(Duration::from_secs(20), send.next()).await;
        let el = start.elapsed();
        assert!(
            outcome.is_ok(),
            "{label} send.next() HUNG > 20s (no per-request timeout); elapsed {el:?}"
        );
        // Configured timeout is 2s; honoring it lands well under 4s. The old
        // `Client::new` default (5s) would blow this bound.
        assert!(
            el < Duration::from_secs(4),
            "{label} did not honor the 2s query_timeout (elapsed {el:?}); \
             likely fell back to hickory's 5s default"
        );
        let _ = addr;
    }

    #[tokio::test]
    async fn tcp_upstream_honors_query_timeout() {
        let addr = blackhole_tcp().await;
        assert_upstream_honors_timeout("TCP", addr, build_tcp_client(addr, Duration::from_secs(2)))
            .await;
    }

    #[tokio::test]
    async fn udp_upstream_honors_query_timeout() {
        let addr = blackhole_udp().await;
        assert_upstream_honors_timeout("UDP", addr, build_udp_client(addr, Duration::from_secs(2)))
            .await;
    }
}
