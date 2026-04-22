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

use hickory_client::client::Client;
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::tcp::TcpClientStream;
use hickory_client::proto::udp::UdpClientStream;
use rustls::ClientConfig;

use super::common::transport::Transport;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build a hickory UDP client connected to `addr` with the given
/// per-query timeout. Logs and returns `None` on connect error.
pub(super) async fn build_udp_client(addr: SocketAddr, timeout: Duration) -> Option<Client> {
    let stream =
        UdpClientStream::<TokioRuntimeProvider>::builder(addr, TokioRuntimeProvider::new())
            .with_timeout(Some(timeout))
            .build();
    let (client, bg) = match Client::connect(stream).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(upstream = %addr, error = %e, "failed to build UDP DNS client");
            return None;
        }
    };
    tokio::spawn(bg);
    Some(client)
}

/// Build a hickory TCP client connected to `addr` with the given
/// connect+query timeout. Logs and returns `None` on connect error.
pub(super) async fn build_tcp_client(addr: SocketAddr, timeout: Duration) -> Option<Client> {
    let (stream, sender) =
        TcpClientStream::new(addr, None, Some(timeout), TokioRuntimeProvider::new());
    let (client, bg) = match Client::new(stream, sender, None).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(upstream = %addr, error = %e, "failed to build TCP DNS client");
            return None;
        }
    };
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
    use hickory_proto::rustls::tls_client_connect;

    let client_config = dot_upstream_client_config();
    let (stream_future, sender) =
        tls_client_connect(addr, sni, client_config, TokioRuntimeProvider::new());
    let (client, bg) = match Client::with_timeout(stream_future, sender, timeout, None).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(upstream = %addr, error = %e, "failed to build DoT client");
            return None;
        }
    };
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
/// Loads the host's native root certificates so we validate public DoT
/// resolvers (Cloudflare, Google, Quad9, etc.) against the same trust
/// anchors the host uses. Cached in a `OnceLock` — cert parsing is
/// non-trivial and the config is immutable once built.
fn dot_upstream_client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
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

            let client_config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            Arc::new(client_config)
        })
        .clone()
}
