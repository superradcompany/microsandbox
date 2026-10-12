//! Channel-based TLS proxy task.
//!
//! Intercepts TLS connections by terminating the guest's TLS with a
//! generated per-domain certificate (MITM) and re-originating a TLS
//! connection to the real server. Bypass mode replays buffered bytes and
//! splices the connection without termination.

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use super::sni;
use super::state::TlsState;
use crate::engine::http_deny::classify_http_request;
use crate::netstack::shared::SharedState;
use crate::policy::{EgressEvaluation, HostnameSource, NetworkPolicy, Protocol};
use crate::proxy::ResolvedOutboundProxy;
use crate::secrets::config::SecretViolationAction;
use crate::secrets::handler::SecretsHandler;
use crate::tcp::{connection::ProxyConnectState, upstream::UpstreamTcpTarget};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Max bytes to buffer while waiting for the ClientHello.
const CLIENT_HELLO_BUF_SIZE: usize = 16384;

/// Buffer size for bidirectional relay.
const RELAY_BUF_SIZE: usize = 16384;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Per-connection TLS proxy task and the state it owns.
pub(crate) struct TlsProxy {
    guest_dst: SocketAddr,
    connect_target: UpstreamTcpTarget,
    from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    tls_state: Arc<TlsState>,
    network_policy: Arc<NetworkPolicy>,
    strict: bool,
    proxy_connect: Arc<ProxyConnectState>,
    outbound_proxy: Option<Arc<ResolvedOutboundProxy>>,
    /// Pre-connected upstream; when `Some`, skips dialing `connect_target`.
    upstream_stream: Option<TcpStream>,
    /// Hostname from a CONNECT authority that must match the ClientHello SNI.
    expected_sni: Option<String>,
    /// `true` when the connection arrived via HTTP CONNECT; skips the DNS-cache pin check.
    via_connect: bool,
    /// ClientHello bytes already consumed from the guest stream.
    initial_buf: Vec<u8>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TlsProxy {
    /// Build a proxy for a newly established guest TLS connection.
    /// `upstream_stream` is reused when present; otherwise, dial after policy checks.
    /// Policy uses `guest_dst`; host connections use the resolved `connect_target`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        upstream_stream: Option<TcpStream>,
        guest_dst: SocketAddr,
        connect_target: UpstreamTcpTarget,
        from_smoltcp: mpsc::Receiver<Bytes>,
        to_smoltcp: mpsc::Sender<Bytes>,
        shared: Arc<SharedState>,
        tls_state: Arc<TlsState>,
        network_policy: Arc<NetworkPolicy>,
        strict: bool,
        proxy_connect: Arc<ProxyConnectState>,
        outbound_proxy: Option<Arc<ResolvedOutboundProxy>>,
    ) -> Self {
        Self {
            guest_dst,
            connect_target,
            from_smoltcp,
            to_smoltcp,
            shared,
            tls_state,
            network_policy,
            strict,
            proxy_connect,
            outbound_proxy,
            upstream_stream,
            expected_sni: None,
            via_connect: false,
            initial_buf: Vec::new(),
        }
    }

    /// Require the ClientHello SNI to match an HTTP CONNECT authority.
    pub(crate) fn with_expected_sni(mut self, expected_sni: Option<String>) -> Self {
        self.via_connect = expected_sni.is_some();
        self.expected_sni = expected_sni;
        self
    }

    /// Seed the proxy with ClientHello bytes already read from the guest.
    pub(crate) fn with_initial_buf(mut self, initial_buf: Vec<u8>) -> Self {
        self.initial_buf = initial_buf;
        self
    }

    /// Run the TLS proxy task to completion.
    ///
    /// See [`crate::tcp::proxy::spawn_tcp_proxy`] for the `proxy_connect`
    /// contract.
    pub(crate) async fn run(self) {
        let guest_dst = self.guest_dst;
        let connect_dst = self.connect_target.primary();

        if let Err(error) = self.try_run().await {
            tracing::debug!(
                dst = %connect_dst,
                %guest_dst,
                %error,
                "TLS proxy task ended",
            );
        }
    }

    /// Drive the TLS proxy to completion, returning operational failures.
    pub(crate) async fn try_run(self) -> io::Result<()> {
        let Self {
            guest_dst,
            connect_target,
            mut from_smoltcp,
            to_smoltcp,
            shared,
            tls_state,
            network_policy,
            strict,
            proxy_connect,
            upstream_stream,
            outbound_proxy,
            expected_sni,
            via_connect,
            initial_buf,
        } = self;
        let connect_dst = connect_target.primary();

        // Buffer a complete ClientHello. Timeout prevents a
        // slow/malicious guest from holding a proxy slot indefinitely.
        let sni_name = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            read_client_hello(&mut from_smoltcp, initial_buf),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ClientHello timed out"))?;
        let (sni_name, initial_buf) = sni_name?;

        // Without SNI, authenticate the original destination IP, never a cached
        // DNS name or the host-side address used for gateway forwarding.
        // Canonicalize so byte equality against rule destinations works.
        let has_sni = sni_name.is_some();
        let sni_name = sni_name.unwrap_or_else(|| guest_dst.ip().to_string());
        let sni_name = sni_name.trim_end_matches('.').to_ascii_lowercase();

        if let Some(expected) = expected_sni.as_deref()
            && !sni_name.eq_ignore_ascii_case(expected.trim_end_matches('.'))
        {
            tracing::debug!(
                sni = %sni_name,
                expected = %expected,
                dst = %connect_dst,
                "TLS SNI did not match CONNECT authority",
            );
            proxy_connect.mark_policy_denied();
            shared.proxy_wake.wake();
            return Ok(());
        }

        // Policy uses cached DNS evidence when the client supplied no hostname.
        // Certificate and secret identity remain bound to the destination IP.
        let hostname_source = if has_sni {
            HostnameSource::Sni(&sni_name)
        } else {
            HostnameSource::CacheOnly
        };
        let eval = network_policy.evaluate_egress_with_source(
            guest_dst,
            Protocol::Tcp,
            &shared,
            hostname_source,
        );
        if !matches!(eval, EgressEvaluation::Allow) {
            tracing::debug!(
                sni = %sni_name,
                dst = %guest_dst,
                "TLS egress denied by domain policy",
            );
            // Bypassed names cannot be answered in-tunnel (the guest expects
            // the real server's certificate); they still get a plain close.
            if !tls_state.should_bypass(&sni_name) {
                let denied = serve_tls_deny(
                    &sni_name,
                    initial_buf,
                    &mut from_smoltcp,
                    &to_smoltcp,
                    &shared,
                    &tls_state,
                )
                .await;
                if let Err(error) = denied {
                    tracing::debug!(sni = %sni_name, %error, "TLS deny response not delivered");
                }
            }
            proxy_connect.mark_policy_denied();
            shared.proxy_wake.wake();
            return Ok(());
        }

        let should_bypass = tls_state.should_bypass(&sni_name);
        if strict
            && should_bypass
            && network_policy.allows_egress_via_hostname(
                guest_dst,
                Protocol::Tcp,
                &shared,
                hostname_source,
            )
        {
            tracing::debug!(
                sni = %sni_name,
                dst = %guest_dst,
                "TLS bypass denied by strict hostname policy",
            );
            proxy_connect.mark_policy_denied();
            shared.proxy_wake.wake();
            return Ok(());
        }

        if should_bypass {
            tracing::debug!(sni = %sni_name, dst = %connect_dst, guest_dst = %guest_dst, "TLS bypass");
            bypass_relay(
                connect_target,
                initial_buf,
                from_smoltcp,
                to_smoltcp,
                shared,
                proxy_connect,
                upstream_stream,
                outbound_proxy,
            )
            .await
        } else {
            tracing::debug!(sni = %sni_name, dst = %connect_dst, guest_dst = %guest_dst, "TLS intercept");
            intercept_relay(
                guest_dst,
                connect_target,
                &sni_name,
                via_connect,
                initial_buf,
                from_smoltcp,
                to_smoltcp,
                shared,
                tls_state,
                proxy_connect,
                upstream_stream,
                outbound_proxy,
            )
            .await
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Answer a policy-denied HTTPS connection with `403 Forbidden`.
///
/// Terminates the guest's TLS with the intercept cert for `sni_name`, reads
/// the first request so the client is not mid-write when the close lands,
/// then writes the deny body and a `close_notify`. No upstream connection
/// is ever opened.
pub(crate) async fn serve_tls_deny(
    sni_name: &str,
    initial_buf: Vec<u8>,
    from_smoltcp: &mut mpsc::Receiver<Bytes>,
    to_smoltcp: &mpsc::Sender<Bytes>,
    shared: &SharedState,
    tls_state: &TlsState,
) -> io::Result<()> {
    if !shared.http_deny_response_enabled() {
        return Ok(());
    }

    let domain_cert = tls_state
        .get_or_generate_cert(sni_name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut guest_tls = rustls::ServerConnection::new(domain_cert.server_config.clone())
        .map_err(io::Error::other)?;
    let mut tls_buf = Vec::with_capacity(RELAY_BUF_SIZE + 256);

    complete_guest_handshake(
        &mut guest_tls,
        initial_buf,
        from_smoltcp,
        to_smoltcp,
        shared,
        &mut tls_buf,
    )
    .await?;

    // Only HTTP/1.x can receive our HTTP/1.1 response. Buffer across TLS
    // records; EOF, malformed input, and timeout are not evidence of HTTP.
    let is_http = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut request = Vec::new();
        let mut scratch = [0u8; RELAY_BUF_SIZE];
        loop {
            match guest_tls.reader().read(&mut scratch) {
                Ok(0) => return false,
                Ok(n) => {
                    let remaining = RELAY_BUF_SIZE - request.len();
                    request.extend_from_slice(&scratch[..n.min(remaining)]);
                    if let Some(is_http) = classify_http_request(&request) {
                        return is_http;
                    }
                    if request.len() == RELAY_BUF_SIZE {
                        return false;
                    }
                    continue;
                }
                Err(ref error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return false,
            }
            let Some(data) = from_smoltcp.recv().await else {
                return false;
            };
            let mut remaining = &data[..];
            while !remaining.is_empty() {
                if !matches!(guest_tls.read_tls(&mut remaining), Ok(n) if n > 0)
                    || guest_tls.process_new_packets().is_err()
                {
                    return false;
                }
            }
        }
    })
    .await
    .unwrap_or(false);
    if !is_http {
        return Ok(());
    }

    guest_tls
        .writer()
        .write_all(&shared.network_denial_response(sni_name))
        .map_err(io::Error::other)?;
    guest_tls.send_close_notify();
    flush_to_guest(&mut guest_tls, to_smoltcp, shared, &mut tls_buf).await
}

/// Feed the buffered ClientHello and drive the guest-facing handshake to
/// completion, bounded by a 10s timeout.
async fn complete_guest_handshake(
    guest_tls: &mut rustls::ServerConnection,
    initial_buf: Vec<u8>,
    from_smoltcp: &mut mpsc::Receiver<Bytes>,
    to_smoltcp: &mpsc::Sender<Bytes>,
    shared: &SharedState,
    tls_buf: &mut Vec<u8>,
) -> io::Result<()> {
    {
        let mut remaining = &initial_buf[..];
        while !remaining.is_empty() {
            guest_tls
                .read_tls(&mut remaining)
                .map_err(io::Error::other)?;
            guest_tls.process_new_packets().map_err(io::Error::other)?;
        }
    }

    // Send ServerHello etc. back to guest.
    flush_to_guest(guest_tls, to_smoltcp, shared, tls_buf).await?;

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while guest_tls.is_handshaking() {
            let data = from_smoltcp
                .recv()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed"))?;
            let mut remaining = &data[..];
            while !remaining.is_empty() {
                guest_tls
                    .read_tls(&mut remaining)
                    .map_err(io::Error::other)?;
                guest_tls.process_new_packets().map_err(io::Error::other)?;
            }
            flush_to_guest(guest_tls, to_smoltcp, shared, tls_buf).await?;
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))?
}

/// Bypass mode: plain TCP splice, no TLS termination.
#[allow(clippy::too_many_arguments)]
async fn bypass_relay(
    connect_target: UpstreamTcpTarget,
    initial_buf: Vec<u8>,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    proxy_connect: Arc<ProxyConnectState>,
    upstream_stream: Option<TcpStream>,
    outbound_proxy: Option<Arc<ResolvedOutboundProxy>>,
) -> io::Result<()> {
    let mut server = match upstream_stream {
        Some(s) => s,
        None => {
            connect_target
                .connect(&proxy_connect, &shared, outbound_proxy.as_deref())
                .await?
        }
    };
    server.write_all(&initial_buf).await?;

    let (mut server_rx, mut server_tx) = server.into_split();
    let mut buf = vec![0u8; RELAY_BUF_SIZE];

    let mut guest_eof = false;
    loop {
        tokio::select! {
            data = from_smoltcp.recv(), if !guest_eof => {
                match data {
                    Some(bytes) => server_tx.write_all(&bytes).await?,
                    // Guest half-closed (FIN): stop sending upstream but
                    // keep relaying server → guest until the server closes.
                    None => {
                        guest_eof = true;
                        if server_tx.shutdown().await.is_err() {
                            break;
                        }
                    }
                }
            }
            result = server_rx.read(&mut buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        if to_smoltcp.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                            break;
                        }
                        shared.proxy_wake.wake();
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    Ok(())
}

/// Intercept mode: MITM with guest-facing rustls + server-facing tokio_rustls.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn intercept_relay(
    guest_dst: SocketAddr,
    connect_target: UpstreamTcpTarget,
    sni_name: &str,
    via_connect: bool,
    initial_buf: Vec<u8>,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    tls_state: Arc<TlsState>,
    proxy_connect: Arc<ProxyConnectState>,
    upstream_stream: Option<TcpStream>,
    outbound_proxy: Option<Arc<ResolvedOutboundProxy>>,
) -> io::Result<()> {
    // Per-connection snapshot: live secret updates apply to later connections.
    let secrets = tls_state.secrets.load();
    let mut secrets_handler = if via_connect {
        SecretsHandler::new_tls_intercepted_via_connect(&secrets, sni_name)
    } else {
        SecretsHandler::new_tls_intercepted(&secrets, sni_name, guest_dst.ip(), &shared)
    }
    .with_guest_dst(guest_dst);

    // Get or generate per-domain certificate (includes cached ServerConfig).
    let domain_cert = tls_state
        .get_or_generate_cert(sni_name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // Reuse cached ServerConfig — avoids cert chain clone + key clone + rebuild per connection.
    let mut guest_tls = rustls::ServerConnection::new(domain_cert.server_config.clone())
        .map_err(io::Error::other)?;

    // Reusable buffer for TLS output — avoids per-flush heap allocation.
    let mut tls_buf = Vec::with_capacity(RELAY_BUF_SIZE + 256);

    // Feed the buffered ClientHello and complete the guest-facing handshake
    // (bounded, to prevent resource exhaustion).
    complete_guest_handshake(
        &mut guest_tls,
        initial_buf,
        &mut from_smoltcp,
        &to_smoltcp,
        &shared,
        &mut tls_buf,
    )
    .await?;

    // Connect to real server with TLS.
    let server_stream = match upstream_stream {
        Some(s) => s,
        None => {
            connect_target
                .connect(&proxy_connect, &shared, outbound_proxy.as_deref())
                .await?
        }
    };
    let server_name = ServerName::try_from(sni_name.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut server_tls = tls_state
        .upstream_connector_for(sni_name)
        .connect(server_name, server_stream)
        .await
        .map_err(io::Error::other)?;

    // Phase 2: Bidirectional plaintext relay.
    let mut server_buf = vec![0u8; RELAY_BUF_SIZE];
    let mut plaintext_buf = vec![0u8; RELAY_BUF_SIZE];

    // Drain any application data already buffered during the TLS handshake.
    // In TLS 1.3, the client sends Finished + application data in the same
    // flight, so process_new_packets() during the handshake loop may have
    // already decrypted the first HTTP request into the plaintext buffer.
    if let Err(error) = forward_plaintext(
        &mut guest_tls,
        &mut server_tls,
        &mut secrets_handler,
        &shared,
        &mut plaintext_buf,
        false,
    )
    .await
    {
        flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;
        return Err(error);
    }

    let mut upstream_response_started = false;
    let mut guest_eof = false;
    loop {
        tokio::select! {
            // Guest → server: receive encrypted, decrypt, forward plaintext.
            data = from_smoltcp.recv(), if !guest_eof => {
                let data = match data {
                    Some(d) => d,
                    // Guest half-closed (TCP FIN): propagate as a TLS
                    // close_notify + FIN upstream, but keep relaying
                    // server → guest until the server closes. (A TLS 1.3
                    // server may keep sending; a TLS 1.2 server responds
                    // with its own close_notify, ending the relay.)
                    None => {
                        guest_eof = true;
                        if server_tls.shutdown().await.is_err() {
                            break;
                        }
                        continue;
                    }
                };
                // Feed all data to rustls.
                let mut remaining = &data[..];
                while !remaining.is_empty() {
                    guest_tls
                        .read_tls(&mut remaining)
                        .map_err(io::Error::other)?;
                    guest_tls
                        .process_new_packets()
                        .map_err(io::Error::other)?;
                    if let Err(error) = forward_plaintext(
                        &mut guest_tls,
                        &mut server_tls,
                        &mut secrets_handler,
                        &shared,
                        &mut plaintext_buf,
                        upstream_response_started,
                    )
                    .await
                    {
                        flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;
                        return Err(error);
                    }
                }
            }

            // Server → guest: read plaintext, encrypt, send via channel.
            result = server_tls.read(&mut server_buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        upstream_response_started = true;
                        guest_tls
                            .writer()
                            .write_all(&server_buf[..n])
                            .map_err(io::Error::other)?;
                        flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    Ok(())
}

/// Read a ClientHello, preserving its bytes for the TLS relay.
/// A complete hello without SNI is distinct from malformed or incomplete TLS.
pub(crate) async fn read_client_hello(
    from_smoltcp: &mut mpsc::Receiver<Bytes>,
    seed: Vec<u8>,
) -> io::Result<(Option<String>, Vec<u8>)> {
    let mut initial_buf = seed;
    let mut acceptor = rustls::server::Acceptor::default();
    let mut consumed = 0;
    loop {
        if initial_buf.len() > CLIENT_HELLO_BUF_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello too large",
            ));
        }

        // Bypass must remain usable for TLS clients rustls cannot terminate
        // (for example TLS 1.1 without signature_algorithms). Preserve the
        // existing wire-level SNI peek before asking rustls to validate TLS.
        if let Some(hello) = sni::parse_client_hello(&initial_buf) {
            // Match rustls: IP literals and invalid DNS names are absent SNI.
            let name = hello.server_name.filter(|name| {
                matches!(
                    ServerName::try_from(name.as_str()),
                    Ok(ServerName::DnsName(_))
                )
            });
            return Ok((name, initial_buf));
        }

        while consumed < initial_buf.len() {
            let read = acceptor.read_tls(&mut &initial_buf[consumed..])?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "incomplete ClientHello",
                ));
            }
            consumed += read;
            match acceptor.accept() {
                Ok(Some(accepted)) => {
                    let name = accepted.client_hello().server_name().map(str::to_owned);
                    return Ok((name, initial_buf));
                }
                Ok(None) => {}
                Err((error, _)) => return Err(io::Error::new(io::ErrorKind::InvalidData, error)),
            }
        }
        let data = from_smoltcp
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed"))?;
        initial_buf.extend_from_slice(&data);
    }
}

/// Read all available decrypted plaintext from the guest-facing TLS
/// connection and forward it to the upstream server, applying secret
/// substitution when configured.
async fn forward_plaintext(
    guest_tls: &mut rustls::ServerConnection,
    server_tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
    secrets_handler: &mut SecretsHandler,
    shared: &SharedState,
    buf: &mut [u8],
    upstream_response_started: bool,
) -> io::Result<()> {
    let mut wrote_plaintext = false;

    loop {
        let n = match guest_tls.reader().read(buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        };

        if secrets_handler.is_empty() {
            server_tls.write_all(&buf[..n]).await?;
            wrote_plaintext = true;
            continue;
        }

        match secrets_handler.substitute(&buf[..n]) {
            Ok(data) => {
                if !data.is_empty() {
                    server_tls.write_all(&data).await?;
                    wrote_plaintext = true;
                }
            }
            Err(action) => {
                // Stop upstream forwarding. Only answer before any upstream
                // response bytes have reached the guest; the caller flushes
                // the denial and close_notify before dropping the connection.
                if matches!(action, SecretViolationAction::BlockAndTerminate) {
                    shared.trigger_termination();
                } else if shared.secret_deny_response_enabled()
                    && !upstream_response_started
                    && let Some(response) =
                        secrets_handler.http1_violation_response(shared.secret_deny_message())
                {
                    guest_tls.writer().write_all(&response)?;
                    guest_tls.send_close_notify();
                }
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "secret violation: request blocked by secret policy",
                ));
            }
        }
    }

    // tokio-rustls buffers writes; flush each drained plaintext batch so
    // upstream servers waiting for the full request body can respond.
    if wrote_plaintext {
        server_tls.flush().await?;
    }

    Ok(())
}

/// Flush pending TLS output from the guest-facing rustls connection
/// to the smoltcp channel.
///
/// Reuses `buf` across calls to avoid per-flush heap allocation. The
/// buffer grows to steady-state capacity on the first call and stays there.
async fn flush_to_guest(
    guest_tls: &mut rustls::ServerConnection,
    to_smoltcp: &mpsc::Sender<Bytes>,
    shared: &SharedState,
    buf: &mut Vec<u8>,
) -> io::Result<()> {
    if guest_tls.wants_write() {
        buf.clear();
        guest_tls.write_tls(buf)?;
        if !buf.is_empty() {
            to_smoltcp
                .send(Bytes::copy_from_slice(buf))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))?;
            shared.proxy_wake.wake();
        }
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::secrets::config::{HostPattern, SecretEntry, SecretSubstitution};
    use crate::secrets::{config::SecretsConfig, handle::SecretsHandle};
    use microsandbox_types::TlsConfig;

    fn isolated_tls_state(mut config: TlsConfig, secrets: SecretsHandle) -> TlsState {
        static NEXT_CA: AtomicUsize = AtomicUsize::new(0);
        // Parallel fixtures must not load or overwrite a shared persisted CA pair. Create an
        // exclusive, disposable directory; an old directory or symlink is never reused.
        let directory = loop {
            let directory = std::env::temp_dir().join(format!(
                "msb-proxy-ca-{}-{}",
                std::process::id(),
                NEXT_CA.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&directory) {
                Ok(()) => break directory,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot create test CA directory: {error}"),
            }
        };
        let ca = crate::engine::tls::ca::CertAuthority::generate();
        let cert_path = directory.join("ca.crt");
        let key_path = directory.join("ca.key");
        std::fs::write(&cert_path, ca.cert_pem()).unwrap();
        std::fs::write(&key_path, ca.key_pem()).unwrap();
        config.intercept_ca.cert_path = Some(cert_path);
        config.intercept_ca.key_path = Some(key_path);
        let state = TlsState::new(config, secrets);
        // Construction reads both files synchronously and retains the CA material in memory.
        std::fs::remove_dir_all(directory).unwrap();
        state.unwrap()
    }

    async fn tls_denial_response(chunks: &[&[u8]], close_input: bool, enabled: bool) -> Vec<u8> {
        let state = isolated_tls_state(
            microsandbox_types::TlsConfig::default(),
            SecretsHandle::new(SecretsConfig::default()),
        );
        let mut roots = rustls::RootCertStore::empty();
        roots.add(state.intercept_ca.cert_der.clone()).unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("blocked.example").unwrap(),
        )
        .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        let (from_tx, mut from_rx) = mpsc::channel(16);
        let (to_tx, mut to_rx) = mpsc::channel(16);
        let server = tokio::spawn(async move {
            let shared = SharedState::new(16);
            shared.set_http_config(microsandbox_types::HttpConfig {
                deny_response: enabled,
                deny_response_format: microsandbox_types::HttpDenyResponseFormat::Json,
                ..Default::default()
            });
            serve_tls_deny(
                "blocked.example",
                hello,
                &mut from_rx,
                &to_tx,
                &shared,
                &state,
            )
            .await
            .unwrap();
        });
        let mut sent = false;
        let mut sender = Some(from_tx);
        let mut response = Vec::new();
        while let Some(data) = to_rx.recv().await {
            assert!(
                enabled,
                "disabled responses must not complete a TLS handshake"
            );
            let mut remaining = &data[..];
            while !remaining.is_empty() {
                client.read_tls(&mut remaining).unwrap();
                client.process_new_packets().unwrap();
            }
            let mut wire = Vec::new();
            client.write_tls(&mut wire).unwrap();
            if !wire.is_empty() {
                sender
                    .as_ref()
                    .unwrap()
                    .send(Bytes::from(wire))
                    .await
                    .unwrap();
            }
            if !client.is_handshaking() && !sent {
                for chunk in chunks {
                    client.writer().write_all(chunk).unwrap();
                    let mut wire = Vec::new();
                    client.write_tls(&mut wire).unwrap();
                    sender
                        .as_ref()
                        .unwrap()
                        .send(Bytes::from(wire))
                        .await
                        .unwrap();
                }
                sent = true;
                if close_input {
                    sender.take();
                }
            }
            let mut plain = [0; 4096];
            loop {
                match client.reader().read(&mut plain) {
                    Ok(0) => break,
                    Ok(n) => response.extend_from_slice(&plain[..n]),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("unexpected TLS read error: {error}"),
                }
            }
        }
        server.await.unwrap();
        response
    }

    #[tokio::test]
    async fn tls_denial_is_silent_without_opt_in() {
        assert!(
            tls_denial_response(&[b"GET / HTTP/1.1\r\n\r\n"], true, false)
                .await
                .is_empty()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn tls_denial_answers_fragmented_http1() {
        let response = tls_denial_response(
            &[
                b"\r",
                b"\nGE",
                b"T / HTTP/1.1\r",
                b"\nHost: blocked.example\r\n\r\n",
            ],
            true,
            true,
        )
        .await;
        assert!(response.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
        let text = std::str::from_utf8(&response).unwrap();
        let (_, body) = text.split_once("\r\n\r\n").unwrap();
        let error: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(error["code"], "network_policy_denied");
        assert_eq!(error["domain"], "blocked.example");
        assert_eq!(error["message"], "Request blocked by network policy.");
    }

    #[tokio::test(start_paused = true)]
    async fn tls_denial_closes_non_http_and_incomplete_streams_silently() {
        for chunks in [
            vec![b"SSH-2.0-OpenSSH\r\n".as_slice()],
            vec![b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice()],
            vec![b"GE".as_slice()],
            vec![],
        ] {
            assert!(tls_denial_response(&chunks, true, true).await.is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn tls_denial_does_not_answer_after_timeout() {
        assert!(
            tls_denial_response(&[b"GET /"], false, true)
                .await
                .is_empty()
        );
    }

    async fn accept_with_deadline(listener: TcpListener) -> io::Result<TcpStream> {
        tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fixture accept timed out"))?
            .map(|(stream, _)| stream)
    }

    fn test_tls_state(secrets: SecretsConfig) -> Arc<TlsState> {
        Arc::new(isolated_tls_state(
            TlsConfig {
                verify_upstream: false,
                ..Default::default()
            },
            SecretsHandle::new(secrets),
        ))
    }

    fn host_bound_secret_config() -> SecretsConfig {
        SecretsConfig {
            secrets: vec![SecretEntry {
                env_var: "API_KEY".into(),
                value: zeroize::Zeroizing::new("real-secret-value".into()),
                source: None,
                placeholder: "$MSB_KEY".into(),
                allowed_hosts: vec![HostPattern::Exact("example.com".into())],
                substitution: SecretSubstitution {
                    headers: true,
                    header_fields: Vec::new(),
                    query: false,
                    body: false,
                },
                passthrough_hosts: Vec::new(),
                violation_action: None,
                require_tls_identity: true,
            }],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn client_hello_preserves_fragmented_records_with_and_without_sni() {
        for name in ["example.com", "192.0.2.1", "2001:db8::1"] {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            let mut client = rustls::ClientConnection::new(
                Arc::new(config),
                ServerName::try_from(name.to_owned()).unwrap(),
            )
            .unwrap();
            let mut hello = Vec::new();
            client.write_tls(&mut hello).unwrap();
            // Fragment the handshake over TLS records as well as channel messages.
            let mut wire = Vec::new();
            for fragment in hello[5..].chunks(31) {
                wire.extend_from_slice(&hello[..3]);
                wire.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
                wire.extend_from_slice(fragment);
            }
            let (tx, mut rx) = mpsc::channel(wire.len());
            for fragment in wire.chunks(7) {
                tx.send(Bytes::copy_from_slice(fragment)).await.unwrap();
            }
            drop(tx);
            let (sni, buffered) = read_client_hello(&mut rx, Vec::new()).await.unwrap();
            assert_eq!(sni.as_deref(), (name == "example.com").then_some(name));
            assert_eq!(buffered, wire);
        }
    }

    #[tokio::test]
    async fn client_hello_rejects_invalid_and_truncated_tls() {
        for wire in [
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            vec![0x16, 3, 1, 0, 10, 1],
        ] {
            let (tx, mut rx) = mpsc::channel(1);
            tx.send(Bytes::from(wire)).await.unwrap();
            drop(tx);
            assert!(read_client_hello(&mut rx, Vec::new()).await.is_err());
        }
    }

    #[tokio::test]
    async fn no_sni_policy_uses_cached_hostname_for_allow_and_deny() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        for (allowed, strict) in [(true, false), (false, false), (true, true), (false, true)] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let upstream = listener.local_addr().unwrap();
            let shared = Arc::new(SharedState::new(8));
            shared.set_http_config(microsandbox_types::HttpConfig {
                deny_response: false,
                ..Default::default()
            });
            shared.cache_resolved_hostname(
                "example.com",
                crate::netstack::shared::ResolvedHostnameFamily::Ipv4,
                [upstream.ip()],
                Duration::from_secs(60),
            );
            let policy = if allowed {
                NetworkPolicy::none().allow_domain("example.com").unwrap()
            } else {
                NetworkPolicy::allow_all()
                    .deny_domain("example.com")
                    .unwrap()
            };
            let state = Arc::new(isolated_tls_state(
                TlsConfig {
                    bypass: vec![upstream.ip().to_string()],
                    ..Default::default()
                },
                SecretsHandle::new(SecretsConfig::default()),
            ));
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();
            let mut client = rustls::ClientConnection::new(
                Arc::new(config),
                ServerName::IpAddress(upstream.ip().into()),
            )
            .unwrap();
            let mut hello = Vec::new();
            client.write_tls(&mut hello).unwrap();
            let received =
                run_bypass_probe(listener, state, shared, policy, strict, hello.clone()).await;
            assert_eq!(
                received,
                if allowed && !strict {
                    hello
                } else {
                    Vec::new()
                }
            );
        }
    }

    #[tokio::test]
    async fn no_sni_interception_allows_cached_domain_policy() {
        let check = async {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let (address, request_rx, server) = spawn_upstream_request_sink().await;
            let shared = Arc::new(SharedState::new(8));
            shared.cache_resolved_hostname(
                "example.com",
                crate::netstack::shared::ResolvedHostnameFamily::Ipv4,
                [address.ip()],
                Duration::from_secs(60),
            );
            let state = test_tls_state(SecretsConfig::default());
            let mut roots = rustls::RootCertStore::empty();
            roots.add(state.intercept_ca.cert_der.clone()).unwrap();
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let mut client = rustls::ClientConnection::new(
                Arc::new(config),
                ServerName::IpAddress(address.ip().into()),
            )
            .unwrap();
            let (from_tx, from_rx) = mpsc::channel(8);
            let (to_tx, mut to_rx) = mpsc::channel(8);
            let proxy = TlsProxy::new(
                None,
                address,
                UpstreamTcpTarget::direct(address),
                from_rx,
                to_tx,
                shared,
                state,
                Arc::new(NetworkPolicy::none().allow_domain("example.com").unwrap()),
                true,
                Arc::new(ProxyConnectState::new()),
                None,
            );
            let relay = tokio::spawn(proxy.try_run());
            send_client_tls_output(&mut client, &from_tx).await;
            complete_relay_handshake(&mut client, &from_tx, &mut to_rx).await;
            let request = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
            client.writer().write_all(request).unwrap();
            send_client_tls_output(&mut client, &from_tx).await;
            assert_eq!(request_rx.await.unwrap(), request);
            drop(from_tx);
            while to_rx.recv().await.is_some() {}
            relay.await.unwrap().unwrap();
            server.await.unwrap().unwrap();
        };
        tokio::time::timeout(Duration::from_secs(5), check)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn bypass_preserves_legacy_tls_without_signature_algorithms() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        for (name, fragmented) in [
            (Some("example.com"), false),
            (None, false),
            (Some("example.com"), true),
            (None, true),
        ] {
            let mut hello = legacy_client_hello(name);
            if fragmented {
                let mut wire = Vec::new();
                for fragment in hello[5..].chunks(17) {
                    wire.extend_from_slice(&hello[..3]);
                    wire.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
                    wire.extend_from_slice(fragment);
                }
                hello = wire;
            }
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let state = Arc::new(isolated_tls_state(
                TlsConfig {
                    bypass: vec![name.unwrap_or("127.0.0.1").into()],
                    ..Default::default()
                },
                SecretsHandle::new(SecretsConfig::default()),
            ));
            let received = run_bypass_probe(
                listener,
                state,
                Arc::new(SharedState::new(8)),
                NetworkPolicy::allow_all(),
                false,
                hello.clone(),
            )
            .await;
            assert_eq!(received, hello);
        }
    }

    #[tokio::test]
    async fn client_hello_treats_invalid_dns_names_as_absent() {
        for name in [
            "",
            "a..b",
            "-example.com",
            "example.123",
            "é.example",
            &"a".repeat(254),
        ] {
            let (tx, mut rx) = mpsc::channel(1);
            let hello = legacy_client_hello(Some(name));
            tx.send(Bytes::from(hello.clone())).await.unwrap();
            drop(tx);
            let (name, buffered) = read_client_hello(&mut rx, Vec::new()).await.unwrap();
            assert_eq!(name, None);
            assert_eq!(buffered, hello);
        }
    }

    #[tokio::test]
    async fn duplicate_sni_cannot_replace_the_policy_hostname() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut client = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("blocked.example").unwrap(),
        )
        .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        // Skip record/handshake headers, version/random, session ID, ciphers,
        // and compression methods to find the extensions length.
        let mut extensions_offset = 9 + 34;
        extensions_offset += 1 + hello[extensions_offset] as usize;
        let length = u16::from_be_bytes([hello[extensions_offset], hello[extensions_offset + 1]]);
        extensions_offset += 2 + length as usize;
        extensions_offset += 1 + hello[extensions_offset] as usize;
        let other = legacy_client_hello(Some("allowed.example"));
        let mut sni_offset = extensions_offset + 2;
        while hello[sni_offset..sni_offset + 2] != [0, 0] {
            let size = u16::from_be_bytes([hello[sni_offset + 2], hello[sni_offset + 3]]);
            sni_offset += 4 + size as usize;
        }

        // Preserve the first policy hostname while rejecting malformed lists
        // and duplicate names, whether inside one extension or across two.
        for (same_extension, malformed) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let mut wire = hello.clone();
            if same_extension {
                let old_length =
                    u16::from_be_bytes([wire[sni_offset + 2], wire[sni_offset + 3]]) as usize;
                let end = sni_offset + 4 + old_length;
                let mut entry = other[58..].to_vec();
                if malformed {
                    entry[1..3].copy_from_slice(&u16::MAX.to_be_bytes());
                }
                wire.splice(end..end, entry.iter().copied());
                let size = (old_length + entry.len()) as u16;
                wire[sni_offset + 2..sni_offset + 4].copy_from_slice(&size.to_be_bytes());
                wire[sni_offset + 4..sni_offset + 6].copy_from_slice(&(size - 2).to_be_bytes());
            } else {
                let second = wire.len();
                wire.extend_from_slice(&other[52..]);
                if malformed {
                    wire[second + 2..second + 4].copy_from_slice(&u16::MAX.to_be_bytes());
                }
            }
            let size = (wire.len() - 5) as u16;
            wire[3..5].copy_from_slice(&size.to_be_bytes());
            let size = (wire.len() - 9) as u32;
            wire[6..9].copy_from_slice(&size.to_be_bytes()[1..]);
            let size = (wire.len() - extensions_offset - 2) as u16;
            wire[extensions_offset..extensions_offset + 2].copy_from_slice(&size.to_be_bytes());
            assert_eq!(sni::extract_sni(&wire).as_deref(), Some("blocked.example"));
            let (tx, mut rx) = mpsc::channel(1);
            tx.send(Bytes::from(wire)).await.unwrap();
            drop(tx);
            assert!(
                read_client_hello(&mut rx, Vec::new()).await.is_err(),
                "same_extension={same_extension}, malformed={malformed}"
            );
        }
    }

    fn legacy_client_hello(name: Option<&str>) -> Vec<u8> {
        // TLS 1.1: RSA cipher and null compression, without signature_algorithms.
        let mut body = vec![3, 2];
        body.extend_from_slice(&[0; 32]);
        body.extend_from_slice(&[0, 0, 2, 0, 0x2f, 1, 0]);
        if let Some(name) = name {
            let name = name.as_bytes();
            body.extend_from_slice(&((name.len() + 9) as u16).to_be_bytes());
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
            body.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
            body.push(0);
            body.extend_from_slice(&(name.len() as u16).to_be_bytes());
            body.extend_from_slice(name);
        }
        let mut hello = vec![0x16, 3, 2];
        hello.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        hello.push(1);
        hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hello.extend_from_slice(&body);
        hello
    }

    async fn run_bypass_probe(
        listener: TcpListener,
        state: Arc<TlsState>,
        shared: Arc<SharedState>,
        policy: NetworkPolicy,
        strict: bool,
        hello: Vec<u8>,
    ) -> Vec<u8> {
        let address = listener.local_addr().unwrap();
        let stream = TcpStream::connect(address).await.unwrap();
        let server = tokio::spawn(async move {
            let mut stream = accept_with_deadline(listener).await.unwrap();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            received
        });
        let (tx, rx) = mpsc::channel(hello.len());
        let (to_tx, _to_rx) = mpsc::channel(1);
        for fragment in hello.chunks(7) {
            tx.send(Bytes::copy_from_slice(fragment)).await.unwrap();
        }
        drop(tx);
        let proxy = TlsProxy::new(
            Some(stream),
            address,
            UpstreamTcpTarget::direct(address),
            rx,
            to_tx,
            shared,
            state,
            Arc::new(policy),
            strict,
            Arc::new(ProxyConnectState::new()),
            None,
        );
        tokio::time::timeout(Duration::from_secs(2), proxy.try_run())
            .await
            .unwrap()
            .unwrap();
        server.await.unwrap()
    }

    fn guest_client(tls_state: &TlsState) -> rustls::ClientConnection {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(tls_state.intercept_ca.cert_der.clone()).unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("example.com".to_owned()).unwrap(),
        )
        .unwrap()
    }

    fn upstream_server_config() -> Arc<rustls::ServerConfig> {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["example.com".to_owned()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let chain = vec![CertificateDer::from(cert.der().to_vec())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap(),
        )
    }

    async fn send_client_tls_output(
        client: &mut rustls::ClientConnection,
        to_relay: &mpsc::Sender<Bytes>,
    ) {
        while client.wants_write() {
            let mut encrypted = Vec::new();
            client.write_tls(&mut encrypted).unwrap();
            to_relay.send(Bytes::from(encrypted)).await.unwrap();
        }
    }

    async fn complete_relay_handshake(
        client: &mut rustls::ClientConnection,
        to_relay: &mpsc::Sender<Bytes>,
        from_relay: &mut mpsc::Receiver<Bytes>,
    ) {
        for _ in 0..8 {
            if !client.is_handshaking() {
                return;
            }
            let encrypted =
                tokio::time::timeout(std::time::Duration::from_secs(1), from_relay.recv())
                    .await
                    .expect("guest handshake record timed out")
                    .expect("relay closed during guest handshake");
            let mut input = encrypted.as_ref();
            client.read_tls(&mut input).unwrap();
            client.process_new_packets().unwrap();
            send_client_tls_output(client, to_relay).await;
        }
        assert!(
            !client.is_handshaking(),
            "guest TLS handshake did not finish"
        );
    }

    async fn spawn_upstream_request_sink() -> (
        SocketAddr,
        oneshot::Receiver<Vec<u8>>,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let stream = accept_with_deadline(listener).await?;
            let mut stream = TlsAcceptor::from(upstream_server_config())
                .accept(stream)
                .await?;
            let mut buf = [0; RELAY_BUF_SIZE];
            let request = match stream.read(&mut buf).await {
                Ok(read) => buf[..read].to_vec(),
                // Fail-closed relay outcomes drop the upstream connection without
                // reading queued-but-unsent bytes (e.g. TLS 1.3 session tickets the
                // server sends unsolicited right after the handshake). Depending on
                // scheduling, the kernel may report that abrupt drop as a reset
                // rather than a clean EOF; both mean "no request bytes arrived".
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    Vec::new()
                }
                Err(error) => return Err(error),
            };
            let _ = request_tx.send(request);
            match stream.shutdown().await {
                Ok(()) => Ok(()),
                // Fail-closed relay outcomes may drop the upstream socket before
                // the fixture can send its TLS close notification.
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    Ok(())
                }
                Err(error) => Err(error),
            }
        });
        (address, request_rx, server)
    }

    #[tokio::test]
    async fn secret_denial_is_delivered_inside_the_existing_tls_connection() {
        let check = async {
            for (enabled, streamed, response_started) in [
                (true, false, false),
                (false, false, false),
                (true, true, false),
                (true, true, true),
            ] {
                let _ = rustls::crypto::ring::default_provider().install_default();
                let mut secrets = host_bound_secret_config();
                secrets.secrets[0].allowed_hosts = vec![HostPattern::Exact("github.com".into())];
                let tls_state = test_tls_state(secrets);
                let shared = Arc::new(SharedState::new(8));
                shared.set_http_config(microsandbox_types::HttpConfig {
                    deny_response: enabled,
                    deny_response_format: microsandbox_types::HttpDenyResponseFormat::Json,
                    ..Default::default()
                });
                let headers = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 8\r\n\r\n";
                let early_response = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nhello";
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let upstream = listener.local_addr().unwrap();
                let (headers_tx, headers_rx) = oneshot::channel();
                let server = tokio::spawn(async move {
                    let stream = accept_with_deadline(listener).await.unwrap();
                    let mut stream = TlsAcceptor::from(upstream_server_config())
                        .accept(stream)
                        .await
                        .unwrap();
                    if streamed {
                        let mut received = vec![0; headers.len()];
                        stream.read_exact(&mut received).await.unwrap();
                        assert_eq!(received, headers);
                    }
                    let _ = headers_tx.send(());
                    if response_started {
                        stream.write_all(early_response).await.unwrap();
                        stream.flush().await.unwrap();
                    }
                    let mut rejected = Vec::new();
                    match stream.read_to_end(&mut rejected).await {
                        Ok(_) => {}
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset
                            ) => {}
                        Err(error) => panic!("upstream read failed: {error}"),
                    }
                    assert!(
                        rejected.is_empty(),
                        "blocked TLS request bytes reached upstream"
                    );
                });
                let (from_tx, from_rx) = mpsc::channel(8);
                let (to_tx, mut to_rx) = mpsc::channel(8);
                let mut client = guest_client(&tls_state);
                send_client_tls_output(&mut client, &from_tx).await;
                let relay = tokio::spawn(intercept_relay(
                    "203.0.113.10:443".parse().unwrap(),
                    UpstreamTcpTarget::direct(upstream),
                    "example.com",
                    true,
                    Vec::new(),
                    from_rx,
                    to_tx,
                    shared,
                    tls_state,
                    Arc::new(ProxyConnectState::new()),
                    None,
                    None,
                ));
                if streamed {
                    complete_relay_handshake(&mut client, &from_tx, &mut to_rx).await;
                    // Fragment the headers across TLS records before delivering the body.
                    client.writer().write_all(&headers[..12]).unwrap();
                    send_client_tls_output(&mut client, &from_tx).await;
                    client.writer().write_all(&headers[12..]).unwrap();
                    send_client_tls_output(&mut client, &from_tx).await;
                    headers_rx.await.unwrap();
                    if response_started {
                        let mut received = Vec::new();
                        while received.len() < early_response.len() {
                            let bytes = to_rx.recv().await.unwrap();
                            client.read_tls(&mut bytes.as_ref()).unwrap();
                            client.process_new_packets().unwrap();
                            let mut buf = [0; 1024];
                            while let Ok(n) = client.reader().read(&mut buf) {
                                if n == 0 {
                                    break;
                                }
                                received.extend_from_slice(&buf[..n]);
                            }
                        }
                        assert_eq!(received, early_response);
                    }
                    client.writer().write_all(b"$MSB_KEY").unwrap();
                    send_client_tls_output(&mut client, &from_tx).await;
                } else {
                    // Coalesce the request with the guest's TLS Finished flight,
                    // exercising plaintext already buffered during the handshake.
                    while client.is_handshaking() {
                        let bytes = to_rx.recv().await.unwrap();
                        client.read_tls(&mut bytes.as_ref()).unwrap();
                        client.process_new_packets().unwrap();
                        if !client.is_handshaking() {
                            client.writer().write_all(headers).unwrap();
                            client.writer().write_all(b"$MSB_KEY").unwrap();
                        }
                        send_client_tls_output(&mut client, &from_tx).await;
                    }
                }
                let mut response = Vec::new();
                let mut clean_close = false;
                while let Some(bytes) = to_rx.recv().await {
                    client.read_tls(&mut bytes.as_ref()).unwrap();
                    clean_close |= client.process_new_packets().unwrap().peer_has_closed();
                    let mut buf = [0; 1024];
                    loop {
                        match client.reader().read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => response.extend_from_slice(&buf[..n]),
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                            Err(error) => panic!("denial TLS read failed: {error}"),
                        }
                    }
                }
                assert!(
                    relay.await.unwrap().is_err(),
                    "secret request must remain blocked"
                );
                server.await.unwrap();
                if enabled && !response_started {
                    assert!(
                        response.starts_with(b"HTTP/1.1 403 Forbidden\r\n"),
                        "{response:?}"
                    );
                    let body = String::from_utf8(response).unwrap();
                    let (_, json) = body.split_once("\r\n\r\n").unwrap();
                    let error: serde_json::Value = serde_json::from_str(json).unwrap();
                    assert_eq!(error["code"], "secret_policy_denied");
                    assert_eq!(error["domain"], "example.com");
                    assert!(!body.contains("real-secret-value") && !body.contains("$MSB_KEY"));
                    assert!(
                        clean_close,
                        "guest must receive TLS close_notify after the denial"
                    );
                } else {
                    assert!(
                        response.is_empty(),
                        "must not append a denial: {response:?}"
                    );
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), check)
            .await
            .expect("TLS secret denial fixture timed out");
    }

    #[tokio::test]
    async fn intercept_relay_rejects_a_truncated_h2_header_block_without_forwarding() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // A non-empty secret makes the relay install the HTTP/2 secret handler;
        // a truncated HPACK representation must then fail the connection closed
        // instead of reaching httlib-hpack's out-of-bounds indexing.
        let tls_state = test_tls_state(host_bound_secret_config());
        let (upstream, upstream_request, server) = spawn_upstream_request_sink().await;
        let guest_destination: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let (from_tx, from_rx) = mpsc::channel(4);
        let (to_tx, mut to_rx) = mpsc::channel(4);
        let mut client = guest_client(&tls_state);
        send_client_tls_output(&mut client, &from_tx).await;
        let relay = tokio::spawn(intercept_relay(
            guest_destination,
            UpstreamTcpTarget::direct(upstream),
            "example.com",
            true,
            Vec::new(),
            from_rx,
            to_tx,
            Arc::new(SharedState::new(4)),
            tls_state,
            Arc::new(ProxyConnectState::new()),
            None,
            None,
        ));

        complete_relay_handshake(&mut client, &from_tx, &mut to_rx).await;
        // h2 preface + empty SETTINGS + HEADERS(stream 1, END_HEADERS|END_STREAM)
        // whose entire header block is the truncated representation `ff`.
        let mut payload = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        payload.extend_from_slice(&[0, 0, 0, 0x04, 0x00, 0, 0, 0, 0]);
        payload.extend_from_slice(&[0, 0, 1, 0x01, 0x05, 0, 0, 0, 1, 0xff]);
        client.writer().write_all(&payload).unwrap();
        send_client_tls_output(&mut client, &from_tx).await;

        // The relay must fail closed on the malformed block...
        let result = tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("relay did not close after a truncated header block")
            .unwrap();
        assert!(
            result.is_err(),
            "relay must close on a truncated header block"
        );
        drop(from_tx);
        // ...and the rejected flight must not reach the upstream at all.
        let received = tokio::time::timeout(Duration::from_secs(1), upstream_request)
            .await
            .expect("upstream sink did not finish")
            .expect("upstream sink task failed");
        assert!(
            received.is_empty(),
            "a rejected header flight must forward nothing upstream, got {received:02x?}"
        );
        server.await.unwrap().unwrap();
    }
}
