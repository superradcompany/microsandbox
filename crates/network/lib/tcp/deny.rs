//! Responder for TCP flows egress policy already denied at SYN time.
//!
//! The poll loop accepts the handshake only for HTTP-answerable ports so
//! the guest's client receives `403 Forbidden` instead of a reset. Nothing
//! here ever dials upstream.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc;

use super::connection::ProxyConnectState;
use super::proxy::{PEEK_BUDGET, PEEK_BUF_SIZE, deny_http_or_close, peek_for_http_request};
use crate::netstack::shared::SharedState;
use crate::tls::proxy::{extract_sni_from_channel, serve_tls_deny};
use crate::tls::state::TlsState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Plain HTTP port the gateway answers with 403 when policy denies it.
const HTTP_PORT: u16 = 80;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Whether a denied SYN to `port` should still be accepted so the client
/// can be answered over HTTP: port 80, or a TLS-intercepted port when
/// interception is configured (the gateway can then answer in-tunnel).
pub(crate) fn answers_denied_http(port: u16, tls_state: Option<&TlsState>) -> bool {
    port == HTTP_PORT || tls_state.is_some_and(|tls| tls.config.intercepted_ports.contains(&port))
}

/// Spawn the responder for a policy-denied connection.
pub(crate) fn spawn_deny_responder(
    handle: &tokio::runtime::Handle,
    guest_dst: SocketAddr,
    from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    tls_state: Option<Arc<TlsState>>,
    proxy_connect: Arc<ProxyConnectState>,
) {
    handle.spawn(async move {
        if let Err(error) = respond(
            guest_dst,
            from_smoltcp,
            to_smoltcp,
            &shared,
            tls_state.as_deref(),
            &proxy_connect,
        )
        .await
        {
            tracing::debug!(dst = %guest_dst, %error, "policy deny response not delivered");
        }
        proxy_connect.mark_policy_denied();
        shared.proxy_wake.wake();
    });
}

async fn respond(
    guest_dst: SocketAddr,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: &SharedState,
    tls_state: Option<&TlsState>,
    proxy_connect: &ProxyConnectState,
) -> std::io::Result<()> {
    let intercepted =
        tls_state.filter(|tls| tls.config.intercepted_ports.contains(&guest_dst.port()));

    let Some(tls) = intercepted else {
        // Plain port: peek the first flight and answer if it is HTTP.
        let initial_buf =
            peek_for_http_request(&mut from_smoltcp, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        return deny_http_or_close(
            guest_dst,
            None,
            &initial_buf,
            to_smoltcp,
            shared,
            proxy_connect,
        )
        .await;
    };

    // Intercepted port: the ClientHello names the host; answer in-tunnel
    // unless the name is bypassed (we cannot terminate TLS for it).
    let (sni_name, initial_buf) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        extract_sni_from_channel(&mut from_smoltcp, Vec::new()),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "SNI extraction timed out"))??;
    let sni_name = sni_name.trim_end_matches('.').to_ascii_lowercase();
    tracing::debug!(sni = %sni_name, dst = %guest_dst, "TLS egress denied by default policy");
    if tls.should_bypass(&sni_name) {
        return Ok(());
    }
    serve_tls_deny(
        &sni_name,
        initial_buf,
        &mut from_smoltcp,
        &to_smoltcp,
        shared,
        tls,
    )
    .await
}
