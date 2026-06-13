//! Bidirectional TCP proxy: smoltcp socket ↔ channels ↔ tokio socket.
//!
//! Each outbound guest TCP connection gets a proxy task that opens a real
//! TCP connection to the destination via tokio and relays data between the
//! channel pair (connected to the smoltcp socket in the poll loop) and the
//! real server.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::conn::ProxyConnectState;
use crate::policy::{EgressEvaluation, HostnameSource, NetworkPolicy, Protocol};
use crate::secrets::config::{SecretsConfig, ViolationAction};
use crate::secrets::handler::SecretsHandler;
use crate::shared::SharedState;
use crate::tls::sni;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Buffer size for reading from the real server.
const SERVER_READ_BUF_SIZE: usize = 16384;

/// Max bytes to buffer while peeking for the ClientHello's SNI.
const PEEK_BUF_SIZE: usize = 16384;

/// Upper bound on time spent buffering the first flight before
/// falling back to a cache-only egress decision.
const PEEK_BUDGET: Duration = Duration::from_secs(5);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

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
    proxy_connect: Arc<ProxyConnectState>,
) -> io::Result<()> {
    // Peek when:
    // - there are Domain/DomainSuffix rules that need SNI to refine egress, OR
    // - secrets are configured (we need the Host header for plain-HTTP substitution)
    let needs_peek = network_policy.has_domain_rules() || !secrets.secrets.is_empty();
    let (mut initial_buf, sni) = if needs_peek {
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

    let is_tls = initial_buf.first() == Some(&0x16);

    // For plain-HTTP connections with secrets, peek_for_sni bails on the first
    // non-TLS byte and may return before headers are complete. Keep reading until
    // \r\n\r\n so extract_http_host always sees a full header block.
    if !is_tls && secrets.has_plain_http_candidates() {
        initial_buf =
            peek_for_http_headers(initial_buf, &mut from_smoltcp, PEEK_BUF_SIZE, PEEK_BUDGET).await;
    }

    let mut secrets_handler: Option<SecretsHandler> = if !secrets.secrets.is_empty() && !is_tls {
        Some(match extract_http_host(&initial_buf) {
            Some(host) => SecretsHandler::new_plain_http(&secrets, &host, guest_dst.ip(), &shared),
            None => SecretsHandler::new_plain_http_invalid_host(&secrets),
        })
    } else {
        None
    };

    let stream = match TcpStream::connect(connect_dst).await {
        Ok(stream) => {
            proxy_connect.mark_connected();
            stream
        }
        Err(e) => {
            proxy_connect.mark_upstream_connect_failed();
            shared.proxy_wake.wake();
            return Err(e);
        }
    };
    let (mut server_rx, mut server_tx) = stream.into_split();

    // Replay the buffered first flight — run through secrets handler first.
    if !initial_buf.is_empty() {
        let out = match secrets_handler.as_mut() {
            Some(h) => match h.substitute(&initial_buf) {
                Ok(cow) => cow.into_owned(),
                Err(action) => {
                    tracing::warn!(dst = %connect_dst, violation = ?action, "secret violation in first flight");
                    if matches!(action, ViolationAction::BlockAndTerminate) {
                        shared.trigger_termination();
                    }
                    return Ok(());
                }
            },
            None => initial_buf,
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
                        let out = match secrets_handler.as_mut() {
                            Some(h) => match h.substitute(&bytes) {
                                Ok(cow) => cow.into_owned(),
                                Err(action) => {
                                    tracing::warn!(dst = %connect_dst, violation = ?action, "secret violation");
                                    if matches!(action, ViolationAction::BlockAndTerminate) {
                                        shared.trigger_termination();
                                    }
                                    break;
                                }
                            },
                            None => bytes.to_vec(),
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
    let mut headers = [httparse::EMPTY_HEADER; 32];
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

/// Buffer chunks from `rx` into `buf` until `\r\n\r\n` is seen, the cap is
/// reached, or the budget expires.
async fn peek_for_http_headers(
    mut buf: Vec<u8>,
    rx: &mut mpsc::Receiver<Bytes>,
    max: usize,
    budget: Duration,
) -> Vec<u8> {
    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
        return buf;
    }
    let timeout_fut = tokio::time::sleep(budget);
    tokio::pin!(timeout_fut);
    loop {
        tokio::select! {
            biased;
            _ = &mut timeout_fut => break,
            data = rx.recv() => {
                match data {
                    Some(bytes) => {
                        buf.extend_from_slice(&bytes);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                        if buf.len() >= max {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
    buf
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
            proxy_connect,
        )
        .await
        .unwrap();

        handle.await.unwrap()
    }

    #[tokio::test]
    async fn plain_http_substitutes_placeholder_when_host_arrives_in_second_segment() {
        // Host header split across TCP segments — peek_for_http_headers must keep
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
            proxy_connect,
        )
        .await
        .unwrap();

        let wire = String::from_utf8(sink.await.unwrap()).unwrap();
        assert!(wire.contains("real-secret-value"), "got: {wire:?}");
        assert!(!wire.contains("$MSB_KEY"), "got: {wire:?}");
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
            proxy_connect,
        )
        .await
        .unwrap();

        let wire = String::from_utf8_lossy(&sink.await.unwrap()).into_owned();
        assert!(wire.contains(&body), "got {} bytes", wire.len());
        assert!(!wire.contains("$MSB_KEY"), "got: {wire:?}");
    }
}
