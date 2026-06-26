//! Bidirectional TCP proxy: smoltcp socket ↔ channels ↔ tokio socket.
//!
//! Each outbound guest TCP connection gets a proxy task that opens a real
//! TCP connection to the destination via tokio and relays data between the
//! channel pair (connected to the smoltcp socket in the poll loop) and the
//! real server.

use std::borrow::Cow;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::conn::ProxyConnectState;
use crate::policy::{EgressEvaluation, HostnameSource, NetworkPolicy, Protocol};
use crate::secrets::config::{SecretsConfig, ViolationAction};
use crate::secrets::handler::{
    SecretsHandler, first_line_is_not_http_request, looks_like_http_request_prefix,
};
use crate::shared::SharedState;
use crate::tls::proxy::{TlsProxyContext, tls_proxy_task};
use crate::tls::sni;
use crate::tls::state::TlsState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Buffer size for reading from the real server.
const SERVER_READ_BUF_SIZE: usize = 16384;

/// Max bytes buffered while reading the proxy's CONNECT response headers.
const CONNECT_RESP_LIMIT: usize = 8192;

/// Max bytes to buffer while peeking for the ClientHello's SNI.
const PEEK_BUF_SIZE: usize = 16384;

/// Upper bound on time spent buffering the first flight before
/// falling back to a cache-only egress decision.
const PEEK_BUDGET: Duration = Duration::from_secs(5);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug)]
struct ConnectRequest {
    bytes: Vec<u8>,
    header_end: usize,
    target: ConnectTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectTarget {
    host: String,
    port: u16,
    expected_sni: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ConnectRequest {
    fn header_bytes(&self) -> &[u8] {
        &self.bytes[..self.header_end]
    }

    fn post_header_bytes(&self) -> &[u8] {
        &self.bytes[self.header_end..]
    }
}

impl ConnectTarget {
    fn is_intercepted(&self, tls_state: &TlsState) -> bool {
        tls_state.config.intercepted_ports.contains(&self.port)
    }

    fn guest_dst(&self, fallback: SocketAddr, shared: &SharedState) -> SocketAddr {
        if let Ok(ip) = self.host.parse::<IpAddr>() {
            return SocketAddr::new(ip, self.port);
        }

        if self.host.eq_ignore_ascii_case(crate::HOST_ALIAS) {
            match fallback.ip() {
                IpAddr::V4(_) => {
                    if let Some(ip) = shared.gateway_ipv4() {
                        return SocketAddr::new(IpAddr::V4(ip), self.port);
                    }
                }
                IpAddr::V6(_) => {
                    if let Some(ip) = shared.gateway_ipv6() {
                        return SocketAddr::new(IpAddr::V6(ip), self.port);
                    }
                }
            }
            if let Some(ip) = shared.gateway_ipv4() {
                return SocketAddr::new(IpAddr::V4(ip), self.port);
            }
            if let Some(ip) = shared.gateway_ipv6() {
                return SocketAddr::new(IpAddr::V6(ip), self.port);
            }
        }

        SocketAddr::new(fallback.ip(), self.port)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Dial `dst` and update proxy state; wakes the poll thread on failure.
pub(crate) async fn connect_upstream(
    dst: SocketAddr,
    proxy_connect: &ProxyConnectState,
    shared: &SharedState,
) -> io::Result<TcpStream> {
    match TcpStream::connect(dst).await {
        Ok(s) => {
            proxy_connect.mark_connected();
            Ok(s)
        }
        Err(e) => {
            proxy_connect.mark_upstream_connect_failed();
            shared.proxy_wake.wake();
            Err(e)
        }
    }
}

/// Spawn a TCP proxy task for a newly established connection.
///
/// `guest_dst` is what the guest dialed — the address policy rules
/// match against. `connect_dst` is the host-side address tokio actually
/// dials; for host-alias connections it's loopback (gateway rewritten).
/// For everything else the two are identical.
///
/// `proxy_connect` is updated before the task exits so the connection
/// tracker can decide between FIN (clean close) and RST (upstream
/// connect failure).
#[allow(clippy::too_many_arguments)]
pub fn spawn_tcp_proxy(
    handle: &tokio::runtime::Handle,
    guest_dst: SocketAddr,
    connect_dst: SocketAddr,
    from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    network_policy: Arc<NetworkPolicy>,
    secrets: Arc<SecretsConfig>,
    tls_state: Option<Arc<TlsState>>,
    proxy_connect: Arc<ProxyConnectState>,
) {
    handle.spawn(async move {
        if let Err(e) = tcp_proxy_task(
            guest_dst,
            connect_dst,
            from_smoltcp,
            to_smoltcp,
            shared,
            network_policy,
            secrets,
            tls_state,
            proxy_connect,
        )
        .await
        {
            tracing::debug!(dst = %connect_dst, error = %e, "TCP proxy task ended");
        }
    });
}

/// Core TCP proxy: peek for SNI, evaluate egress policy, then either
/// connect and relay or drop the channels.
#[allow(clippy::too_many_arguments)]
async fn tcp_proxy_task(
    guest_dst: SocketAddr,
    connect_dst: SocketAddr,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    network_policy: Arc<NetworkPolicy>,
    secrets: Arc<SecretsConfig>,
    tls_state: Option<Arc<TlsState>>,
    proxy_connect: Arc<ProxyConnectState>,
) -> io::Result<()> {
    // Pre-connect peek is only for domain policy: the hostname has to be known
    // before we dial upstream so a Deny never opens a connection. Secrets do
    // *not* gate the connect, so they no longer force a peek here — that work is
    // deferred to `classify_first_flight` after the socket is open, where it can
    // run without stalling server-first protocols (see below).
    let (mut initial_buf, sni) = if network_policy.has_domain_rules() {
        peek_for_sni(&mut from_smoltcp, PEEK_BUF_SIZE, PEEK_BUDGET).await
    } else {
        (Vec::new(), None)
    };

    // Re-evaluate egress against the *guest* dst — the address the
    // guest dialed, not the post-rewrite host-side address. SNI
    // refines over-allow when the cache matched a shared CDN IP;
    // CacheOnly is the non-TLS fallback path so Domain rules still
    // gate plain HTTP / SSH / etc.
    if network_policy.has_domain_rules() {
        let source = match sni.as_deref() {
            Some(name) => HostnameSource::Sni(name),
            None => HostnameSource::CacheOnly,
        };
        match network_policy.evaluate_egress_with_source(guest_dst, Protocol::Tcp, &shared, source)
        {
            EgressEvaluation::Allow => {}
            EgressEvaluation::Deny => {
                tracing::debug!(
                    dst = %guest_dst,
                    source = source.label(),
                    "TCP egress denied by domain policy",
                );
                proxy_connect.mark_policy_denied();
                shared.proxy_wake.wake();
                return Ok(());
            }
            EgressEvaluation::DeferUntilHostname => {
                debug_assert!(false, "DeferUntilHostname leaked into TCP proxy task");
                proxy_connect.mark_policy_denied();
                shared.proxy_wake.wake();
                return Ok(());
            }
        }
    }

    // Peek for HTTP CONNECT before dialing upstream; hand off if detected.
    if let Some(tls_state) = tls_state.clone() {
        if initial_buf.is_empty() {
            let (peeked, _) = peek_for_sni(&mut from_smoltcp, PEEK_BUF_SIZE, PEEK_BUDGET).await;
            initial_buf = peeked;
        }
        if could_be_connect_request(&initial_buf) {
            return handle_connect_tunnel(
                guest_dst,
                connect_dst,
                initial_buf,
                from_smoltcp,
                to_smoltcp,
                shared,
                network_policy,
                tls_state,
                proxy_connect,
                None,
            )
            .await;
        }
    }

    // Connect upstream *before* finishing the secrets-side classification. A
    // server-first protocol (SSH, SMTP, a database) sends nothing until it has
    // seen the server's banner; with the socket already open we can relay that
    // banner while we wait, instead of burning the peek budget pre-connect.
    let stream = connect_upstream(connect_dst, &proxy_connect, &shared).await?;
    let (mut server_rx, mut server_tx) = stream.into_split();

    // Finish classifying the first flight (TLS vs plain HTTP) and, for
    // plain-HTTP candidates, gather a full header block — without blocking the
    // server→guest direction. When domain rules already peeked, `initial_buf`
    // is reused and this is cheap; with no secrets it is skipped entirely
    // (`is_tls` only matters for deciding whether to build the handler).
    let want_headers = secrets.has_plain_http_candidates() || secrets.has_host_scoped_secrets();
    let (initial_buf, is_tls) = if !secrets.secrets.is_empty() {
        classify_first_flight(
            initial_buf,
            &mut from_smoltcp,
            &mut server_rx,
            &to_smoltcp,
            &shared,
            want_headers,
            PEEK_BUF_SIZE,
            PEEK_BUDGET,
        )
        .await?
    } else {
        (initial_buf, false)
    };

    if let Some(tls_state) = tls_state.clone()
        && could_be_connect_request(&initial_buf)
    {
        // The pre-connect CONNECT peek can miss a client whose first bytes arrive
        // after we dial upstream. Once classify_first_flight has captured that
        // request, rejoin the already-open proxy socket and use the CONNECT path
        // so intercepted tunnels still get TLS substitution and policy checks.
        let proxy_stream = server_rx
            .reunite(server_tx)
            .map_err(|_| io::Error::other("failed to reunite proxy stream halves"))?;
        return handle_connect_tunnel(
            guest_dst,
            connect_dst,
            initial_buf,
            from_smoltcp,
            to_smoltcp,
            shared,
            network_policy,
            tls_state,
            proxy_connect,
            Some(proxy_stream),
        )
        .await;
    }

    let mut late_connect_state = tls_state;
    let mut secrets_handler: Option<SecretsHandler> = if !secrets.secrets.is_empty() && !is_tls {
        Some(match extract_http_host(&initial_buf) {
            Some(host) => SecretsHandler::new_plain_http(&secrets, &host, guest_dst.ip(), &shared),
            None => SecretsHandler::new_plain_http_invalid_host(&secrets),
        })
    } else {
        None
    };

    // Replay the buffered first flight — run through secrets handler first.
    if !initial_buf.is_empty() {
        let out: Cow<[u8]> = match secrets_handler.as_mut() {
            Some(h) => match h.substitute(&initial_buf) {
                // Borrow the input when nothing was substituted; only a chunk
                // that actually carries a placeholder is reallocated.
                Ok(cow) => cow,
                Err(action) => {
                    tracing::warn!(dst = %connect_dst, violation = ?action, "secret violation in first flight");
                    if matches!(action, ViolationAction::BlockAndTerminate) {
                        shared.trigger_termination();
                    }
                    return Ok(());
                }
            },
            None => Cow::Borrowed(&initial_buf),
        };
        if !out.is_empty() {
            if let Err(e) = server_tx.write_all(&out).await {
                tracing::debug!(dst = %connect_dst, error = %e, "replay of buffered first flight failed");
                return Ok(());
            }
            if let Err(e) = server_tx.flush().await {
                tracing::debug!(dst = %connect_dst, error = %e, "flush after first flight failed");
                return Ok(());
            }
        }
    }

    let mut server_buf = vec![0u8; SERVER_READ_BUF_SIZE];

    // Bidirectional relay using tokio::select!.
    //
    // guest → server: receive from channel, write to server socket.
    // server → guest: read from server socket, send via channel + wake poll.
    loop {
        tokio::select! {
            // Guest → server: substitute placeholders before forwarding.
            data = from_smoltcp.recv() => {
                match data {
                    Some(bytes) => {
                        if let Some(tls_state) = late_connect_state.take()
                            && could_be_connect_request(&bytes)
                        {
                            // The first guest bytes can arrive after both peek
                            // windows have completed. Nothing has been written
                            // to the proxy socket yet, so this is still a valid
                            // point to switch into CONNECT tunnel handling.
                            let proxy_stream = server_rx
                                .reunite(server_tx)
                                .map_err(|_| io::Error::other("failed to reunite proxy stream halves"))?;
                            return handle_connect_tunnel(
                                guest_dst,
                                connect_dst,
                                bytes.to_vec(),
                                from_smoltcp,
                                to_smoltcp,
                                shared,
                                network_policy,
                                tls_state,
                                proxy_connect,
                                Some(proxy_stream),
                            )
                            .await;
                        }
                        // No handler (no secrets / TLS) is the common path: forward
                        // the chunk borrowed, with no per-chunk allocation or copy.
                        let out: Cow<[u8]> = match secrets_handler.as_mut() {
                            Some(h) => match h.substitute(&bytes) {
                                Ok(cow) => cow,
                                Err(action) => {
                                    tracing::warn!(dst = %connect_dst, violation = ?action, "secret violation");
                                    if matches!(action, ViolationAction::BlockAndTerminate) {
                                        shared.trigger_termination();
                                    }
                                    break;
                                }
                            },
                            None => Cow::Borrowed(&bytes),
                        };
                        if !out.is_empty() {
                            if let Err(e) = server_tx.write_all(&out).await {
                                tracing::debug!(dst = %connect_dst, error = %e, "write to server failed");
                                break;
                            }
                            if let Err(e) = server_tx.flush().await {
                                tracing::debug!(dst = %connect_dst, error = %e, "flush to server failed");
                                break;
                            }
                        }
                    }
                    // Channel closed — smoltcp socket was closed by guest.
                    None => break,
                }
            }

            // Server → guest: no substitution — server never sends placeholders.
            result = server_rx.read(&mut server_buf) => {
                match result {
                    Ok(0) => break, // Server closed connection.
                    Ok(n) => {
                        // A server-first byte means this is not an HTTP CONNECT
                        // tunnel to a proxy. Keep relaying normally afterward.
                        late_connect_state = None;
                        let data = Bytes::copy_from_slice(&server_buf[..n]);
                        if to_smoltcp.send(data).await.is_err() {
                            // Channel closed — poll loop dropped the receiver.
                            break;
                        }
                        // Wake the poll thread so it writes data to the
                        // smoltcp socket.
                        shared.proxy_wake.wake();
                    }
                    Err(e) => {
                        tracing::debug!(dst = %connect_dst, error = %e, "read from server failed");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Forward an HTTP CONNECT tunnel: dial the proxy, splice the handshake,
/// then hand the established stream to `tls_proxy_task` for TLS MITM.
///
/// `guest_dst` is what the guest dialed; `proxy_dst` is the rewritten
/// loopback address the gateway actually connects to.
#[allow(clippy::too_many_arguments)]
async fn handle_connect_tunnel(
    guest_dst: SocketAddr,
    proxy_dst: SocketAddr,
    initial_buf: Vec<u8>,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    network_policy: Arc<NetworkPolicy>,
    tls_state: Arc<TlsState>,
    proxy_connect: Arc<ProxyConnectState>,
    preconnected_proxy: Option<TcpStream>,
) -> io::Result<()> {
    let connect_req =
        parse_connect_request(buffer_connect_request(initial_buf, &mut from_smoltcp).await?)?;

    let connect_headers = match sanitize_connect_headers(
        connect_req.header_bytes(),
        &tls_state.secrets,
    ) {
        Ok(headers) => headers,
        Err(action) => {
            tracing::warn!(dst = %proxy_dst, violation = ?action, "secret violation in CONNECT headers");
            if matches!(action, ViolationAction::BlockAndTerminate) {
                shared.trigger_termination();
            }
            return Ok(());
        }
    };

    // Dial the proxy and forward the CONNECT request so it opens the tunnel.
    let mut proxy_stream = match preconnected_proxy {
        Some(stream) => stream,
        None => match TcpStream::connect(proxy_dst).await {
            Ok(s) => s,
            Err(e) => {
                proxy_connect.mark_upstream_connect_failed();
                shared.proxy_wake.wake();
                return Err(e);
            }
        },
    };

    if !connect_req.target.is_intercepted(&tls_state) {
        proxy_stream.write_all(&connect_headers).await?;
        proxy_stream.flush().await?;
        let (proxy_resp, header_end) = read_connect_response_headers(&mut proxy_stream).await?;
        if to_smoltcp
            .send(Bytes::copy_from_slice(&proxy_resp[..header_end]))
            .await
            .is_err()
        {
            return Ok(());
        }
        if !proxy_resp[header_end..].is_empty()
            && to_smoltcp
                .send(Bytes::copy_from_slice(&proxy_resp[header_end..]))
                .await
                .is_err()
        {
            return Ok(());
        }
        shared.proxy_wake.wake();
        if !connect_response_is_success(&proxy_resp[..header_end]) {
            proxy_connect.mark_connected();
            return Ok(());
        }
        if !connect_req.post_header_bytes().is_empty() {
            proxy_stream
                .write_all(connect_req.post_header_bytes())
                .await?;
        }
        proxy_stream.flush().await?;
        proxy_connect.mark_connected();
        return relay_connected_stream(proxy_stream, from_smoltcp, to_smoltcp, shared).await;
    }

    proxy_stream.write_all(&connect_headers).await?;
    proxy_stream.flush().await?;

    let (proxy_resp, header_end) = read_connect_response_headers(&mut proxy_stream).await?;
    if !connect_response_is_success(&proxy_resp[..header_end]) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "proxy rejected CONNECT",
        ));
    }
    if !proxy_resp[header_end..].is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy sent unexpected bytes after CONNECT response headers",
        ));
    }
    proxy_connect.mark_connected();

    if to_smoltcp
        .send(Bytes::copy_from_slice(&proxy_resp[..header_end]))
        .await
        .is_err()
    {
        return Ok(());
    }
    shared.proxy_wake.wake();

    let tls_seed = connect_req.post_header_bytes().to_vec();
    let tls_guest_dst = connect_req.target.guest_dst(guest_dst, &shared);
    let expected_sni = connect_req.target.expected_sni.clone();

    tls_proxy_task(
        TlsProxyContext {
            guest_dst: tls_guest_dst,
            connect_dst: proxy_dst,
            shared,
            tls_state,
            network_policy,
            proxy_connect,
            upstream_stream: Some(proxy_stream),
            expected_sni,
        },
        from_smoltcp,
        to_smoltcp,
        tls_seed,
    )
    .await
}

/// Relay an established TCP stream without inspecting or substituting bytes.
async fn relay_connected_stream(
    stream: TcpStream,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
) -> io::Result<()> {
    let (mut server_rx, mut server_tx) = stream.into_split();
    let mut server_buf = vec![0u8; SERVER_READ_BUF_SIZE];

    loop {
        tokio::select! {
            data = from_smoltcp.recv() => {
                match data {
                    Some(bytes) => {
                        server_tx.write_all(&bytes).await?;
                        server_tx.flush().await?;
                    }
                    None => break,
                }
            }
            result = server_rx.read(&mut server_buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        if to_smoltcp
                            .send(Bytes::copy_from_slice(&server_buf[..n]))
                            .await
                            .is_err()
                        {
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

async fn buffer_connect_request(
    mut buf: Vec<u8>,
    from_smoltcp: &mut mpsc::Receiver<Bytes>,
) -> io::Result<Vec<u8>> {
    let timeout_fut = tokio::time::sleep(PEEK_BUDGET);
    tokio::pin!(timeout_fut);

    loop {
        if !could_be_connect_request(&buf) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed CONNECT request prefix",
            ));
        }
        if headers_end(&buf).is_some() {
            return Ok(buf);
        }
        if buf.len() >= PEEK_BUF_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CONNECT request headers too large",
            ));
        }

        tokio::select! {
            biased;
            _ = &mut timeout_fut => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for complete CONNECT request headers",
                ));
            }
            data = from_smoltcp.recv() => match data {
                Some(bytes) => {
                    buf.extend_from_slice(&bytes);
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "channel closed before complete CONNECT request headers",
                    ));
                }
            }
        }
    }
}

async fn read_connect_response_headers(stream: &mut TcpStream) -> io::Result<(Vec<u8>, usize)> {
    tokio::time::timeout(PEEK_BUDGET, async {
        let mut proxy_resp = Vec::with_capacity(256);
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "proxy closed before sending CONNECT response",
                ));
            }
            proxy_resp.extend_from_slice(&buf[..n]);
            if let Some(end) = headers_end(&proxy_resp) {
                return Ok((proxy_resp, end));
            }
            if proxy_resp.len() > CONNECT_RESP_LIMIT {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy CONNECT response too large",
                ));
            }
        }
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out waiting for proxy CONNECT response",
        )
    })?
}

fn sanitize_connect_headers<'a>(
    header_bytes: &'a [u8],
    secrets: &SecretsConfig,
) -> Result<Cow<'a, [u8]>, ViolationAction> {
    if secrets.secrets.is_empty() {
        return Ok(Cow::Borrowed(header_bytes));
    }

    let mut handler = SecretsHandler::new_plain_http_untrusted_metadata(secrets);
    handler.substitute(header_bytes)
}

/// Returns the byte offset just past the `\r\n\r\n` header terminator, or `None`.
fn headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn could_be_connect_request(buf: &[u8]) -> bool {
    const PREFIX: &[u8] = b"CONNECT ";
    if buf.is_empty() {
        return false;
    }
    let n = buf.len().min(PREFIX.len());
    buf[..n].eq_ignore_ascii_case(&PREFIX[..n])
}

fn parse_connect_request(bytes: Vec<u8>) -> io::Result<ConnectRequest> {
    let header_end = headers_end(&bytes).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete CONNECT request headers",
        )
    })?;
    let target = {
        let request_line = bytes[..header_end]
            .split(|&b| b == b'\n')
            .next()
            .unwrap_or(&[]);
        let request_line = std::str::from_utf8(request_line)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "CONNECT line is not UTF-8"))?
            .trim_end_matches('\r');
        let mut parts = request_line.split_ascii_whitespace();
        let method = parts.next().unwrap_or_default();
        let authority = parts.next().unwrap_or_default();
        let version = parts.next().unwrap_or_default();
        if !method.eq_ignore_ascii_case("CONNECT")
            || authority.is_empty()
            || !is_http_version(version)
            || parts.next().is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed CONNECT request line",
            ));
        }
        parse_connect_target(authority)?
    };

    Ok(ConnectRequest {
        bytes,
        header_end,
        target,
    })
}

fn parse_connect_target(authority: &str) -> io::Result<ConnectTarget> {
    let authority = authority.trim();
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, rest) = rest.split_once(']').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed CONNECT IPv6 authority",
            )
        })?;
        let port = rest.strip_prefix(':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "CONNECT authority missing port")
        })?;
        (host, port)
    } else {
        let (host, port) = authority.rsplit_once(':').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "CONNECT authority missing port")
        })?;
        if host.contains(':') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "CONNECT IPv6 authority must be bracketed",
            ));
        }
        (host, port)
    };
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CONNECT authority missing host",
        ));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid CONNECT port"))?;
    let expected_sni = host
        .parse::<IpAddr>()
        .is_err()
        .then(|| host.to_ascii_lowercase());

    Ok(ConnectTarget {
        host: host.to_ascii_lowercase(),
        port,
        expected_sni,
    })
}

fn is_http_version(version: &str) -> bool {
    let Some(version) = version.strip_prefix("HTTP/") else {
        return false;
    };
    let Some((major, minor)) = version.split_once('.') else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|b| b.is_ascii_digit())
        && minor.bytes().all(|b| b.is_ascii_digit())
}

fn connect_response_is_success(headers: &[u8]) -> bool {
    let Some(status_line) = headers.split(|&b| b == b'\n').next() else {
        return false;
    };
    let Ok(status_line) = std::str::from_utf8(status_line) else {
        return false;
    };
    let mut parts = status_line.trim_end_matches('\r').split_ascii_whitespace();
    let version = parts.next().unwrap_or_default();
    let status = parts.next().unwrap_or_default();
    is_http_version(version)
        && status.len() == 3
        && status
            .parse::<u16>()
            .is_ok_and(|code| (200..300).contains(&code))
}

/// Extract the `Host:` header value from an already-buffered HTTP header block.
///
/// Returns `None` if:
/// - The first byte is `0x16` (TLS — not HTTP)
/// - The buffer does not yet contain `\r\n\r\n` (headers incomplete)
/// - No `Host:` header is present
///
/// Strips port suffix, lowercases, and trims whitespace. Result is
/// ready for byte-equal matching against `SecretEntry::allowed_hosts`.
fn extract_http_host(buf: &[u8]) -> Option<String> {
    if buf.first() == Some(&0x16) {
        return None;
    }
    // Size the header pool to the buffer rather than a fixed array: a header
    // line is at least four bytes (`a:\r\n`), so `len / 4` always covers the
    // real header count, and `httparse` never reports `TooManyHeaders` (which
    // would make a request with many headers look hostless). The first flight
    // is capped at PEEK_BUF_SIZE, so this stays bounded.
    let mut headers = vec![httparse::EMPTY_HEADER; (buf.len() / 4).max(16)];
    let mut req = httparse::Request::new(&mut headers);
    req.parse(buf).ok()?;
    req.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .map(|v| {
            let host = v.trim();
            // Strip port suffix.
            host.rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(host)
                .to_ascii_lowercase()
        })
        .filter(|h| !h.is_empty())
}

/// Finish classifying the guest's first flight after the upstream socket is
/// open, returning the (possibly extended) first-flight buffer and whether it
/// is a TLS record.
///
/// `buf` carries whatever a pre-connect domain-rule peek already captured; when
/// it is non-empty the TLS/plain decision is already settled and only header
/// top-up runs. `want_headers` is set when at least one secret can be
/// substituted over plain HTTP (`SecretsConfig::has_plain_http_candidates`); it
/// makes the peek keep reading a non-TLS flight until `\r\n\r\n` so
/// [`extract_http_host`] sees a complete header block.
///
/// Crucially, this relays server→guest while it waits. Server-first protocols
/// (SSH, SMTP, databases) send nothing until they have seen the server's
/// banner; draining the server side here lets the banner reach the guest
/// immediately, so the guest's eventual first flight — not a 5s timeout — is
/// what ends the peek.
#[allow(clippy::too_many_arguments)]
async fn classify_first_flight(
    mut buf: Vec<u8>,
    from_smoltcp: &mut mpsc::Receiver<Bytes>,
    server_rx: &mut tokio::net::tcp::OwnedReadHalf,
    to_smoltcp: &mpsc::Sender<Bytes>,
    shared: &SharedState,
    want_headers: bool,
    max: usize,
    budget: Duration,
) -> io::Result<(Vec<u8>, bool)> {
    let mut server_buf = vec![0u8; SERVER_READ_BUF_SIZE];
    let timeout_fut = tokio::time::sleep(budget);
    tokio::pin!(timeout_fut);

    loop {
        // Stop as soon as the protocol class is known and — for plain-HTTP
        // candidates — a full header block has arrived. Bail the moment a
        // non-TLS flight stops looking like an HTTP request so non-HTTP
        // protocols (SSH, Postgres) aren't withheld from upstream for the
        // whole budget while we wait for a `\r\n\r\n` that never comes.
        if !buf.is_empty() {
            let is_tls = buf.first() == Some(&0x16);
            let not_http = !is_tls
                && (!looks_like_http_request_prefix(&buf) || first_line_is_not_http_request(&buf));
            let done = !want_headers
                || is_tls
                || not_http
                || buf.len() >= max
                || buf.windows(4).any(|w| w == b"\r\n\r\n");
            if done {
                return Ok((buf, is_tls));
            }
        }

        tokio::select! {
            biased;
            _ = &mut timeout_fut => {
                let is_tls = buf.first() == Some(&0x16);
                return Ok((buf, is_tls));
            }
            // Guest → buffer (not forwarded here; the caller replays it once the
            // handler is built, so substitution applies to the first flight too).
            guest = from_smoltcp.recv() => match guest {
                Some(bytes) => buf.extend_from_slice(&bytes),
                None => {
                    let is_tls = buf.first() == Some(&0x16);
                    return Ok((buf, is_tls));
                }
            },
            // Server → guest: relay immediately so a server-first banner is never
            // held hostage by the peek.
            server = server_rx.read(&mut server_buf) => match server {
                Ok(0) => {
                    let is_tls = buf.first() == Some(&0x16);
                    return Ok((buf, is_tls));
                }
                Ok(n) => {
                    let data = Bytes::copy_from_slice(&server_buf[..n]);
                    if to_smoltcp.send(data).await.is_err() {
                        let is_tls = buf.first() == Some(&0x16);
                        return Ok((buf, is_tls));
                    }
                    shared.proxy_wake.wake();
                }
                Err(e) => return Err(e),
            },
        }
    }
}

/// Buffer the first flight until SNI can be extracted, or until one
/// of the bail-out conditions hits (channel close, buffer cap,
/// timeout). Never errors; non-TLS / slow / malformed input all
/// fall through to `None`.
///
/// On hit, the SNI is canonicalized (lowercase + trim trailing dot)
/// for byte-equal matching against rule destinations. The returned
/// buffer must be replayed verbatim to upstream before the caller
/// starts its relay loop.
async fn peek_for_sni(
    rx: &mut mpsc::Receiver<Bytes>,
    max: usize,
    budget: Duration,
) -> (Vec<u8>, Option<String>) {
    let mut buf = Vec::with_capacity(PEEK_BUF_SIZE.min(8192));
    let timeout_fut = tokio::time::sleep(budget);
    tokio::pin!(timeout_fut);

    let raw_sni = loop {
        tokio::select! {
            biased;
            _ = &mut timeout_fut => break None,
            data = rx.recv() => {
                match data {
                    Some(bytes) => {
                        buf.extend_from_slice(&bytes);
                        // First byte of a TLS record is the ContentType;
                        // 0x16 is handshake. Anything else can't be a
                        // ClientHello, so don't burn the full budget on
                        // plain HTTP / SSH / etc.
                        if buf.first() != Some(&0x16) {
                            break None;
                        }
                        if let Some(name) = sni::extract_sni(&buf) {
                            break Some(name);
                        }
                        if buf.len() >= max {
                            break None;
                        }
                    }
                    None => break None,
                }
            }
        }
    };

    let canonical = raw_sni.map(|s| s.trim_end_matches('.').to_ascii_lowercase());
    (buf, canonical)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic TLS ClientHello carrying SNI `example.com`. Bytes
    /// borrowed from `tls::sni` test fixtures so the parser sees a
    /// well-formed record.
    fn synthetic_client_hello(sni: &str) -> Vec<u8> {
        // Minimal but valid TLS 1.2 ClientHello with one SNI entry.
        // Layout: record header (5) + handshake header (4) + body.
        let host_bytes = sni.as_bytes();
        let host_len = host_bytes.len() as u16;
        let server_name_list_len = 3 + host_len; // type(1) + len(2) + host
        let extension_data_len = 2 + server_name_list_len; // list-len(2) + list
        let extensions_total = 4 + extension_data_len; // type(2) + len(2) + data

        let mut body = Vec::new();
        // Client version
        body.extend_from_slice(&[0x03, 0x03]);
        // Random (32 bytes)
        body.extend_from_slice(&[0u8; 32]);
        // Session id length + (empty)
        body.push(0);
        // Cipher suites length + one cipher
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
        // Compression methods length + null
        body.extend_from_slice(&[0x01, 0x00]);
        // Extensions length
        body.extend_from_slice(&extensions_total.to_be_bytes());
        // SNI extension: type 0x0000
        body.extend_from_slice(&[0x00, 0x00]);
        body.extend_from_slice(&extension_data_len.to_be_bytes());
        body.extend_from_slice(&server_name_list_len.to_be_bytes());
        body.push(0x00); // host_name type
        body.extend_from_slice(&host_len.to_be_bytes());
        body.extend_from_slice(host_bytes);

        let handshake_len = body.len() as u32;
        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        hs.extend_from_slice(&handshake_len.to_be_bytes()[1..]); // 24-bit length
        hs.extend_from_slice(&body);

        let record_len = hs.len() as u16;
        let mut record = Vec::new();
        record.extend_from_slice(&[0x16, 0x03, 0x01]); // Handshake, TLS 1.0
        record.extend_from_slice(&record_len.to_be_bytes());
        record.extend_from_slice(&hs);

        record
    }

    #[test]
    fn could_be_connect_request_matches_split_prefixes_only() {
        assert!(could_be_connect_request(b"C"));
        assert!(could_be_connect_request(b"connect "));
        assert!(could_be_connect_request(b"CONNECT example.com:443"));
        assert!(!could_be_connect_request(b"CLIENT"));
        assert!(!could_be_connect_request(b"GET / HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn buffer_connect_request_reads_split_headers() {
        let (tx, mut rx) = mpsc::channel(4);
        tx.send(Bytes::from_static(b"NECT example.com:443 HTTP/1.1\r\n"))
            .await
            .unwrap();
        tx.send(Bytes::from_static(b"Host: example.com\r\n\r\n"))
            .await
            .unwrap();
        drop(tx);

        let buffered = buffer_connect_request(b"CON".to_vec(), &mut rx)
            .await
            .unwrap();
        let parsed = parse_connect_request(buffered).unwrap();

        assert_eq!(parsed.target.host, "example.com");
        assert_eq!(parsed.target.port, 443);
        assert_eq!(parsed.target.expected_sni.as_deref(), Some("example.com"));
        assert!(parsed.post_header_bytes().is_empty());
    }

    #[test]
    fn parse_connect_request_preserves_post_header_tls_seed() {
        let mut request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        request.extend_from_slice(b"\x16\x03\x01client-hello");

        let parsed = parse_connect_request(request).unwrap();

        assert_eq!(
            parsed.header_bytes(),
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        );
        assert_eq!(parsed.post_header_bytes(), b"\x16\x03\x01client-hello");
    }

    #[test]
    fn parse_connect_target_requires_authority_port() {
        assert!(parse_connect_target("example.com").is_err());
        assert!(parse_connect_target("2001:db8::1:443").is_err());

        let target = parse_connect_target("[2001:db8::1]:8443").unwrap();
        assert_eq!(target.host, "2001:db8::1");
        assert_eq!(target.port, 8443);
        assert_eq!(target.expected_sni, None);
    }

    #[test]
    fn connect_response_success_requires_exact_2xx_status_code() {
        assert!(connect_response_is_success(
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        ));
        assert!(connect_response_is_success(
            b"HTTP/1.1 204 Connection Established\r\n\r\n"
        ));
        assert!(!connect_response_is_success(b"HTTP/1.1 2000 Weird\r\n\r\n"));
        assert!(!connect_response_is_success(b"HTTP/1.1 199 Nope\r\n\r\n"));
        assert!(!connect_response_is_success(b"NOTHTTP 200 OK\r\n\r\n"));
    }

    #[tokio::test]
    async fn peek_for_sni_extracts_and_canonicalizes() {
        let (tx, mut rx) = mpsc::channel(4);
        let hello = synthetic_client_hello("Example.COM");
        tx.send(Bytes::from(hello.clone())).await.unwrap();
        drop(tx); // close so peek returns even if SNI didn't satisfy

        let (buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        assert_eq!(sni.as_deref(), Some("example.com"));
        assert_eq!(buf, hello);
    }

    #[tokio::test]
    async fn peek_for_sni_returns_none_on_channel_close_without_data() {
        let (tx, mut rx) = mpsc::channel::<Bytes>(1);
        drop(tx);
        let (buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        assert!(buf.is_empty());
        assert_eq!(sni, None);
    }

    #[tokio::test]
    async fn peek_for_sni_returns_none_on_non_tls_data() {
        let (tx, mut rx) = mpsc::channel(4);
        // Plaintext HTTP request; not a TLS record so extract_sni returns None.
        tx.send(Bytes::from_static(
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        ))
        .await
        .unwrap();
        drop(tx);
        let (buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        assert!(
            !buf.is_empty(),
            "buffered bytes must be returned for replay"
        );
        assert_eq!(sni, None);
    }

    #[tokio::test]
    async fn peek_for_sni_falls_back_on_timeout() {
        let (tx, mut rx) = mpsc::channel::<Bytes>(1);
        // Hold the sender open but send nothing — peek must time out.
        let (buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, Duration::from_millis(50)).await;
        drop(tx);
        assert!(buf.is_empty());
        assert_eq!(sni, None);
    }

    #[tokio::test]
    async fn peek_for_sni_caps_at_max_bytes() {
        let (tx, mut rx) = mpsc::channel(4);
        // First byte 0x16 keeps the peek collecting past the early
        // non-TLS bail. Padding bytes are zero so the SNI parser never
        // matches and the loop drives to the size cap.
        let mut first = vec![0u8; 8192];
        first[0] = 0x16;
        tx.send(Bytes::from(first)).await.unwrap();
        tx.send(Bytes::from(vec![0u8; 8192])).await.unwrap();
        tx.send(Bytes::from(vec![0u8; 8192])).await.unwrap();
        drop(tx);

        let (buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        assert_eq!(sni, None, "no SNI in non-TLS data");
        assert!(
            buf.len() >= PEEK_BUF_SIZE,
            "buffer must hit the cap before bail-out: got {}",
            buf.len()
        );
    }

    #[tokio::test]
    async fn peek_for_sni_bails_immediately_on_non_tls_first_byte() {
        let (tx, mut rx) = mpsc::channel(4);
        // Plain HTTP request: first byte 'G' (0x47) — clearly not TLS.
        tx.send(Bytes::from_static(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
            .await
            .unwrap();
        drop(tx);

        // 5-second nominal budget; assert we returned in well under
        // that — the early-bail must not wait for the full window.
        let started = std::time::Instant::now();
        let (buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        let elapsed = started.elapsed();
        assert_eq!(sni, None);
        assert!(buf.starts_with(b"GET"));
        assert!(
            elapsed < Duration::from_millis(500),
            "non-TLS bail must be fast: took {elapsed:?}"
        );
    }

    //----------------------------------------------------------------------------------------------
    // peek_for_sni × evaluate_egress_with_source — combined integration tests
    //----------------------------------------------------------------------------------------------

    use std::net::IpAddr;
    use std::time::Duration as StdDuration;

    use crate::policy::{Action, Destination, NetworkPolicy, PortRange, Rule};
    use crate::shared::{ResolvedHostnameFamily, SharedState};

    const SHARED_FASTLY_IP: &str = "151.101.0.223";

    fn shared_with(host: &str, ip: &str) -> SharedState {
        let shared = SharedState::new(4);
        shared.cache_resolved_hostname(
            host,
            ResolvedHostnameFamily::Ipv4,
            [ip.parse::<IpAddr>().unwrap()],
            StdDuration::from_secs(60),
        );
        shared
    }

    fn allow_https(domain: &str) -> Rule {
        Rule {
            direction: crate::policy::Direction::Egress,
            destination: Destination::Domain(domain.parse().unwrap()),
            protocols: vec![Protocol::Tcp],
            ports: vec![PortRange::single(443)],
            action: Action::Allow,
        }
    }

    /// Over-allow case: cache says IP X is `pypi.org` (allowed); SNI
    /// is `evil.com`. SNI must override the cache and deny.
    #[tokio::test]
    async fn integration_sni_overrides_cache_for_over_allow() {
        let shared = shared_with("pypi.org", SHARED_FASTLY_IP);
        let policy = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![allow_https("pypi.org")],
        };
        let dst = SocketAddr::new(SHARED_FASTLY_IP.parse().unwrap(), 443);

        let (tx, mut rx) = mpsc::channel(4);
        tx.send(Bytes::from(synthetic_client_hello("evil.com")))
            .await
            .unwrap();
        drop(tx);

        let (initial_buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        assert_eq!(sni.as_deref(), Some("evil.com"));
        assert!(!initial_buf.is_empty());

        let source = sni
            .as_deref()
            .map(HostnameSource::Sni)
            .unwrap_or(HostnameSource::CacheOnly);
        let eval = policy.evaluate_egress_with_source(dst, Protocol::Tcp, &shared, source);
        assert_eq!(
            eval,
            EgressEvaluation::Deny,
            "SNI=evil.com must not piggy-back on the cached pypi.org match",
        );
    }

    /// Over-block case: cache says IP X is `ads.example.com` (denied);
    /// SNI is `api.example.com`. SNI must override the cache and allow.
    #[tokio::test]
    async fn integration_sni_overrides_cache_for_over_block() {
        let shared = shared_with("ads.example.com", SHARED_FASTLY_IP);
        let policy = NetworkPolicy {
            default_egress: Action::Allow,
            default_ingress: Action::Allow,
            rules: vec![Rule::deny_egress(Destination::Domain(
                "ads.example.com".parse().unwrap(),
            ))],
        };
        let dst = SocketAddr::new(SHARED_FASTLY_IP.parse().unwrap(), 443);

        let (tx, mut rx) = mpsc::channel(4);
        tx.send(Bytes::from(synthetic_client_hello("api.example.com")))
            .await
            .unwrap();
        drop(tx);

        let (_initial_buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        assert_eq!(sni.as_deref(), Some("api.example.com"));

        let source = sni
            .as_deref()
            .map(HostnameSource::Sni)
            .unwrap_or(HostnameSource::CacheOnly);
        let eval = policy.evaluate_egress_with_source(dst, Protocol::Tcp, &shared, source);
        assert_eq!(
            eval,
            EgressEvaluation::Allow,
            "SNI=api.example.com must not be caught by the deny on ads.example.com",
        );
    }

    /// Non-TLS first-flight falls back to `CacheOnly`; the cache
    /// match decides.
    #[tokio::test]
    async fn integration_non_tls_falls_back_to_cache() {
        let shared = shared_with("pypi.org", SHARED_FASTLY_IP);
        let policy = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![allow_https("pypi.org")],
        };
        let dst = SocketAddr::new(SHARED_FASTLY_IP.parse().unwrap(), 443);

        let (tx, mut rx) = mpsc::channel(4);
        // Plain HTTP request; not a TLS record.
        tx.send(Bytes::from_static(
            b"GET / HTTP/1.1\r\nHost: pypi.org\r\n\r\n",
        ))
        .await
        .unwrap();
        drop(tx);

        let (initial_buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        assert_eq!(sni, None, "non-TLS data → no SNI");
        assert!(
            !initial_buf.is_empty(),
            "buffered bytes must survive for replay"
        );

        let source = sni
            .as_deref()
            .map(HostnameSource::Sni)
            .unwrap_or(HostnameSource::CacheOnly);
        let eval = policy.evaluate_egress_with_source(dst, Protocol::Tcp, &shared, source);
        assert_eq!(
            eval,
            EgressEvaluation::Allow,
            "cache-only fallback must still allow the cached hostname's IP",
        );
    }

    /// SNI matches a `DomainSuffix` rule with a cache binding for the
    /// claimed name. Genuine pre-resolved traffic passes.
    #[tokio::test]
    async fn integration_sni_matches_domain_suffix_with_cache_binding() {
        let shared = shared_with("files.pythonhosted.org", SHARED_FASTLY_IP);
        let policy = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![Rule {
                direction: crate::policy::Direction::Egress,
                destination: Destination::DomainSuffix(".pythonhosted.org".parse().unwrap()),
                protocols: vec![Protocol::Tcp],
                ports: vec![PortRange::single(443)],
                action: Action::Allow,
            }],
        };
        let dst = SocketAddr::new(SHARED_FASTLY_IP.parse().unwrap(), 443);

        let (tx, mut rx) = mpsc::channel(4);
        tx.send(Bytes::from(synthetic_client_hello(
            "files.pythonhosted.org",
        )))
        .await
        .unwrap();
        drop(tx);

        let (_buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        let source = sni
            .as_deref()
            .map(HostnameSource::Sni)
            .unwrap_or(HostnameSource::CacheOnly);
        let eval = policy.evaluate_egress_with_source(dst, Protocol::Tcp, &shared, source);
        assert_eq!(eval, EgressEvaluation::Allow);
    }

    /// Spoofed SNI on an IP with no cache binding for any matching
    /// name: byte-equality with the suffix passes, but no DNS lookup
    /// ever tied a `*.pythonhosted.org` name to the destination, so
    /// the AND-check fails and the connection is denied.
    #[tokio::test]
    async fn integration_sni_denies_domain_suffix_without_cache_binding() {
        let shared = SharedState::new(4); // empty cache
        let policy = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![Rule {
                direction: crate::policy::Direction::Egress,
                destination: Destination::DomainSuffix(".pythonhosted.org".parse().unwrap()),
                protocols: vec![Protocol::Tcp],
                ports: vec![PortRange::single(443)],
                action: Action::Allow,
            }],
        };
        let dst = SocketAddr::new(SHARED_FASTLY_IP.parse().unwrap(), 443);

        let (tx, mut rx) = mpsc::channel(4);
        tx.send(Bytes::from(synthetic_client_hello(
            "files.pythonhosted.org",
        )))
        .await
        .unwrap();
        drop(tx);

        let (_buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        let source = sni
            .as_deref()
            .map(HostnameSource::Sni)
            .unwrap_or(HostnameSource::CacheOnly);
        let eval = policy.evaluate_egress_with_source(dst, Protocol::Tcp, &shared, source);
        assert_eq!(eval, EgressEvaluation::Deny);
    }

    // ── extract_http_host ──────────────────────────────────────────────────────

    #[test]
    fn extract_http_host_basic() {
        let buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_http_host(buf), Some("example.com".into()));
    }

    #[test]
    fn extract_http_host_strips_port() {
        let buf = b"POST /api HTTP/1.1\r\nHost: api.company.com:8080\r\n\r\n";
        assert_eq!(extract_http_host(buf), Some("api.company.com".into()));
    }

    #[test]
    fn extract_http_host_case_insensitive_lowercased() {
        let buf = b"GET / HTTP/1.1\r\nhost: Example.COM\r\n\r\n";
        assert_eq!(extract_http_host(buf), Some("example.com".into()));
    }

    #[test]
    fn extract_http_host_no_host_header() {
        let buf = b"GET / HTTP/1.1\r\nX-Other: foo\r\n\r\n";
        assert_eq!(extract_http_host(buf), None);
    }

    #[test]
    fn extract_http_host_incomplete_headers() {
        let buf = b"GET / HTTP/1.1\r\nHost: x";
        assert_eq!(extract_http_host(buf), None);
    }

    #[test]
    fn extract_http_host_tls_first_byte() {
        let buf = [0x16u8, 0x03, 0x01, 0x00, 0x01];
        assert_eq!(extract_http_host(&buf), None);
    }

    #[test]
    fn extract_http_host_with_many_headers() {
        // Far more headers than a small fixed parse array would hold: the Host
        // must still be found rather than the request looking hostless.
        let mut req = Vec::from(&b"GET / HTTP/1.1\r\n"[..]);
        for i in 0..100 {
            req.extend_from_slice(format!("X-Pad-{i}: v\r\n").as_bytes());
        }
        req.extend_from_slice(b"Host: example.com\r\n\r\n");
        assert_eq!(extract_http_host(&req), Some("example.com".into()));
    }

    // ── plain-HTTP secret substitution ────────────────────────────────────────

    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use crate::secrets::config::{HostPattern, SecretEntry, SecretInjection, SecretsConfig};

    fn make_plain_http_secret(placeholder: &str, value: &str, require_tls: bool) -> SecretsConfig {
        SecretsConfig {
            secrets: vec![SecretEntry {
                env_var: "API_KEY".into(),
                value: value.into(),
                placeholder: placeholder.into(),
                allowed_hosts: vec![HostPattern::Any],
                injection: SecretInjection {
                    headers: true,
                    basic_auth: false,
                    query_params: false,
                    body: false,
                },
                on_violation: None,
                require_tls_identity: require_tls,
            }],
            ..Default::default()
        }
    }

    fn make_host_bound_secret(placeholder: &str, value: &str, host: &str) -> SecretsConfig {
        SecretsConfig {
            secrets: vec![SecretEntry {
                env_var: "API_KEY".into(),
                value: value.into(),
                placeholder: placeholder.into(),
                allowed_hosts: vec![HostPattern::Exact(host.into())],
                injection: SecretInjection::default(),
                on_violation: None,
                require_tls_identity: true,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn sanitize_connect_headers_blocks_placeholder_metadata_header_by_default() {
        let secrets = make_host_bound_secret("$MSB_KEY", "real-secret-value", "example.com");
        let headers = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Bearer $MSB_KEY\r\nUser-Agent: curl\r\n\r\n";

        assert_eq!(
            sanitize_connect_headers(headers, &secrets),
            Err(ViolationAction::BlockAndLog)
        );
    }

    #[test]
    fn sanitize_connect_headers_respects_block_and_terminate() {
        let mut secrets = make_host_bound_secret("$MSB_KEY", "real-secret-value", "example.com");
        secrets.on_violation = ViolationAction::BlockAndTerminate;
        let headers = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Bearer $MSB_KEY\r\n\r\n";

        assert_eq!(
            sanitize_connect_headers(headers, &secrets),
            Err(ViolationAction::BlockAndTerminate)
        );
    }

    #[test]
    fn sanitize_connect_headers_respects_explicit_passthrough() {
        let mut secrets = make_host_bound_secret("$MSB_KEY", "real-secret-value", "example.com");
        secrets.on_violation = ViolationAction::Passthrough(vec![HostPattern::Any]);
        let headers = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Bearer $MSB_KEY\r\n\r\n";

        let sanitized = sanitize_connect_headers(headers, &secrets).unwrap();

        assert_eq!(sanitized.as_ref(), headers);
        assert!(
            !String::from_utf8_lossy(sanitized.as_ref()).contains("real-secret-value"),
            "passthrough must never substitute real secrets into CONNECT metadata"
        );
    }

    #[test]
    fn sanitize_connect_headers_keeps_safe_metadata_headers() {
        let secrets = make_host_bound_secret("$MSB_KEY", "real-secret-value", "example.com");
        let headers =
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nUser-Agent: curl\r\n\r\n";

        let sanitized = sanitize_connect_headers(headers, &secrets).unwrap();

        assert_eq!(sanitized.as_ref(), headers);
    }

    #[test]
    fn sanitize_connect_headers_blocks_placeholder_in_request_line() {
        let secrets = make_host_bound_secret("$MSB_KEY", "real-secret-value", "example.com");
        let headers = b"CONNECT $MSB_KEY:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";

        assert_eq!(
            sanitize_connect_headers(headers, &secrets),
            Err(ViolationAction::BlockAndLog)
        );
    }

    async fn spawn_sink() -> (SocketAddr, JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let mut buf = vec![0u8; 4096];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => received.extend_from_slice(&buf[..n]),
                }
            }
            received
        });
        (addr, handle)
    }

    async fn relay_through_proxy(
        request: Vec<u8>,
        secrets: SecretsConfig,
        handle: JoinHandle<Vec<u8>>,
        server_addr: SocketAddr,
    ) -> Vec<u8> {
        let (from_tx, from_rx) = mpsc::channel::<Bytes>(8);
        let (to_tx, _to_rx) = mpsc::channel::<Bytes>(8);
        let shared = SharedState::new(4);
        let policy = Arc::new(NetworkPolicy::default());
        let secrets = Arc::new(secrets);
        let proxy_connect = Arc::new(ProxyConnectState::new());

        from_tx.send(Bytes::from(request)).await.unwrap();
        drop(from_tx);

        tcp_proxy_task(
            server_addr,
            server_addr,
            from_rx,
            to_tx,
            Arc::new(shared),
            policy,
            secrets,
            None,
            proxy_connect,
        )
        .await
        .unwrap();

        handle.await.unwrap()
    }

    #[tokio::test]
    async fn plain_http_substitutes_placeholder_when_host_arrives_in_second_segment() {
        // Host header split across TCP segments — classify_first_flight must keep
        // reading until \r\n\r\n before extract_http_host is called.
        let (addr, sink) = spawn_sink().await;
        let secrets = make_plain_http_secret("$MSB_KEY", "real-secret-value", false);

        let (from_tx, from_rx) = mpsc::channel::<Bytes>(8);
        let (to_tx, _to_rx) = mpsc::channel::<Bytes>(8);
        let proxy_connect = Arc::new(ProxyConnectState::new());

        from_tx
            .send(Bytes::from_static(b"GET /api HTTP/1.1\r\n"))
            .await
            .unwrap();
        from_tx
            .send(Bytes::from_static(
                b"Host: example.com\r\nAuthorization: Bearer $MSB_KEY\r\n\r\n",
            ))
            .await
            .unwrap();
        drop(from_tx);

        tcp_proxy_task(
            addr,
            addr,
            from_rx,
            to_tx,
            Arc::new(SharedState::new(4)),
            Arc::new(NetworkPolicy::default()),
            Arc::new(secrets),
            None,
            proxy_connect,
        )
        .await
        .unwrap();

        let wire = String::from_utf8(sink.await.unwrap()).unwrap();
        assert!(wire.contains("real-secret-value"), "got: {wire:?}");
        assert!(!wire.contains("$MSB_KEY"), "got: {wire:?}");
    }

    #[tokio::test]
    async fn plain_http_forwards_placeholder_to_allowed_host_with_split_headers() {
        // A default (require_tls_identity = true) host-bound secret is never
        // substituted over plain HTTP, but a request to its allowed host must
        // have the placeholder forwarded unchanged — not blocked as a violation
        // — even when the Host arrives in a later segment than the request line.
        let (addr, sink) = spawn_sink().await;

        let shared = SharedState::new(4);
        shared.cache_resolved_hostname(
            "example.com",
            ResolvedHostnameFamily::Ipv4,
            ["127.0.0.1".parse::<IpAddr>().unwrap()],
            StdDuration::from_secs(60),
        );

        let secrets = SecretsConfig {
            secrets: vec![SecretEntry {
                env_var: "API_KEY".into(),
                value: "real-secret-value".into(),
                placeholder: "$MSB_KEY".into(),
                allowed_hosts: vec![HostPattern::Exact("example.com".into())],
                injection: SecretInjection {
                    headers: true,
                    basic_auth: false,
                    query_params: false,
                    body: false,
                },
                on_violation: None,
                require_tls_identity: true,
            }],
            ..Default::default()
        };

        let (from_tx, from_rx) = mpsc::channel::<Bytes>(8);
        let (to_tx, _to_rx) = mpsc::channel::<Bytes>(8);
        let proxy_connect = Arc::new(ProxyConnectState::new());

        from_tx
            .send(Bytes::from_static(b"GET /api HTTP/1.1\r\n"))
            .await
            .unwrap();
        from_tx
            .send(Bytes::from_static(
                b"Host: example.com\r\nAuthorization: Bearer $MSB_KEY\r\n\r\n",
            ))
            .await
            .unwrap();
        drop(from_tx);

        tcp_proxy_task(
            addr,
            addr,
            from_rx,
            to_tx,
            Arc::new(shared),
            Arc::new(NetworkPolicy::default()),
            Arc::new(secrets),
            None,
            proxy_connect,
        )
        .await
        .unwrap();

        let wire = String::from_utf8(sink.await.unwrap()).unwrap();
        assert!(
            wire.contains("Host: example.com"),
            "request must reach the allowed host, got: {wire:?}"
        );
        assert!(
            wire.contains("$MSB_KEY"),
            "placeholder must be forwarded unchanged for a require_tls_identity secret, got: {wire:?}"
        );
        assert!(
            !wire.contains("real-secret-value"),
            "secret must never be substituted over plain HTTP, got: {wire:?}"
        );
    }

    #[tokio::test]
    async fn plain_http_substitutes_placeholder_in_first_flight() {
        let (addr, sink) = spawn_sink().await;

        let request =
            b"GET /api HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer $MSB_KEY\r\n\r\n"
                .to_vec();
        let secrets = make_plain_http_secret("$MSB_KEY", "real-secret-value", false);

        let wire =
            String::from_utf8(relay_through_proxy(request, secrets, sink, addr).await).unwrap();
        assert!(
            wire.contains("real-secret-value"),
            "real value must reach server, got: {wire:?}"
        );
        assert!(
            !wire.contains("$MSB_KEY"),
            "placeholder must not reach server, got: {wire:?}"
        );
    }

    #[tokio::test]
    async fn plain_http_no_substitution_when_require_tls_identity_true() {
        let (addr, sink) = spawn_sink().await;

        let request =
            b"GET /api HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer $MSB_KEY\r\n\r\n"
                .to_vec();
        let secrets = make_plain_http_secret("$MSB_KEY", "real-secret-value", true);

        let wire =
            String::from_utf8_lossy(&relay_through_proxy(request, secrets, sink, addr).await)
                .into_owned();
        assert!(
            wire.contains("$MSB_KEY"),
            "placeholder must be forwarded unchanged when require_tls_identity=true, got: {wire:?}"
        );
        assert!(
            !wire.contains("real-secret-value"),
            "real value must not leak when require_tls_identity=true, got: {wire:?}"
        );
    }

    #[tokio::test]
    async fn plain_http_large_body_forwarded_verbatim_in_relay_loop() {
        // Body arrives in a separate segment after headers — flows through the relay
        // loop, not the peek path. Ensures no bytes are dropped and header substitution
        // still happens.
        let (addr, sink) = spawn_sink().await;
        let secrets = make_plain_http_secret("$MSB_KEY", "real-value", false);

        let body = "x".repeat(32_000);
        let header = format!(
            "POST /upload HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer $MSB_KEY\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );

        let (from_tx, from_rx) = mpsc::channel::<Bytes>(8);
        let (to_tx, _to_rx) = mpsc::channel::<Bytes>(8);
        let proxy_connect = Arc::new(ProxyConnectState::new());

        from_tx
            .send(Bytes::from(header.into_bytes()))
            .await
            .unwrap();
        from_tx
            .send(Bytes::from(body.clone().into_bytes()))
            .await
            .unwrap();
        drop(from_tx);

        tcp_proxy_task(
            addr,
            addr,
            from_rx,
            to_tx,
            Arc::new(SharedState::new(4)),
            Arc::new(NetworkPolicy::default()),
            Arc::new(secrets),
            None,
            proxy_connect,
        )
        .await
        .unwrap();

        let wire = String::from_utf8_lossy(&sink.await.unwrap()).into_owned();
        assert!(wire.contains(&body), "got {} bytes", wire.len());
        assert!(!wire.contains("$MSB_KEY"), "got: {wire:?}");
    }
}
