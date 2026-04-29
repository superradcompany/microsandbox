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

use crate::policy::{EgressEvaluation, HostnameSource, NetworkPolicy, Protocol};
use crate::shared::SharedState;
use crate::tls::sni;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Buffer size for reading from the real server.
const SERVER_READ_BUF_SIZE: usize = 16384;

/// Max bytes to buffer while peeking for the ClientHello's SNI.
/// Matches the TLS proxy's [`tls::proxy::CLIENT_HELLO_BUF_SIZE`].
const PEEK_BUF_SIZE: usize = 16384;

/// Upper bound on time spent buffering the first flight before falling
/// back to a cache-only egress decision. Smaller than the TLS proxy's
/// own 10 s SNI timeout because we're only waiting for the guest's
/// first write, not a full TLS handshake.
const PEEK_BUDGET: Duration = Duration::from_secs(5);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Spawn a TCP proxy task for a newly established connection.
///
/// Connects to `dst` via tokio, then bidirectionally relays data between
/// the smoltcp socket (via channels) and the real server. Wakes the poll
/// thread via `shared.proxy_wake` whenever data is sent toward the guest.
pub fn spawn_tcp_proxy(
    handle: &tokio::runtime::Handle,
    dst: SocketAddr,
    from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    network_policy: Arc<NetworkPolicy>,
) {
    handle.spawn(async move {
        if let Err(e) = tcp_proxy_task(dst, from_smoltcp, to_smoltcp, shared, network_policy).await
        {
            tracing::debug!(dst = %dst, error = %e, "TCP proxy task ended");
        }
    });
}

/// Core TCP proxy: peek for SNI, evaluate egress policy with the
/// resulting hostname source, then either connect and relay or drop the
/// channels.
async fn tcp_proxy_task(
    dst: SocketAddr,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    network_policy: Arc<NetworkPolicy>,
) -> io::Result<()> {
    // Phase 0: peek for SNI. Returns the buffered first-flight bytes
    // (replayed verbatim to upstream below) and the canonicalized SNI
    // string when present.
    let (initial_buf, sni) = peek_for_sni(&mut from_smoltcp, PEEK_BUF_SIZE, PEEK_BUDGET).await;

    // Map peek result to a hostname source. SNI is authoritative when
    // present; otherwise fall back to the resolved-hostname cache.
    let source = match sni.as_deref() {
        Some(name) => HostnameSource::Sni(name),
        None => HostnameSource::CacheOnly,
    };

    match network_policy.evaluate_egress_with_source(dst, Protocol::Tcp, &shared, source) {
        EgressEvaluation::Allow => {}
        EgressEvaluation::Deny => {
            tracing::debug!(
                dst = %dst,
                source = %hostname_source_label(source),
                "TCP egress denied by domain policy",
            );
            return Ok(());
        }
        EgressEvaluation::DeferUntilHostname => {
            // The proxy task never asks for deferral — only the SYN
            // handler does. Treat as Deny defensively.
            debug_assert!(
                false,
                "EgressEvaluation::DeferUntilHostname leaked into the TCP proxy task",
            );
            return Ok(());
        }
    }

    let stream = TcpStream::connect(dst).await?;
    let (mut server_rx, mut server_tx) = stream.into_split();

    // Replay the buffered first flight before entering the relay loop.
    if !initial_buf.is_empty()
        && let Err(e) = server_tx.write_all(&initial_buf).await
    {
        tracing::debug!(dst = %dst, error = %e, "replay of buffered first flight failed");
        return Ok(());
    }

    let mut server_buf = vec![0u8; SERVER_READ_BUF_SIZE];

    // Bidirectional relay using tokio::select!.
    //
    // guest → server: receive from channel, write to server socket.
    // server → guest: read from server socket, send via channel + wake poll.
    loop {
        tokio::select! {
            // Guest → server.
            data = from_smoltcp.recv() => {
                match data {
                    Some(bytes) => {
                        if let Err(e) = server_tx.write_all(&bytes).await {
                            tracing::debug!(dst = %dst, error = %e, "write to server failed");
                            break;
                        }
                    }
                    // Channel closed — smoltcp socket was closed by guest.
                    None => break,
                }
            }

            // Server → guest.
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
                        tracing::debug!(dst = %dst, error = %e, "read from server failed");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Buffer the first flight from the guest until the TLS ClientHello's
/// SNI extension can be extracted, or one of the bail-out conditions is
/// hit (channel close, buffer cap, timeout). Never errors — non-TLS
/// traffic and slow / malformed clients all fall through to a `None`
/// SNI, leaving the caller to decide whether to fall back.
///
/// On success, the SNI string is canonicalized (lowercase ASCII +
/// trailing-dot trim) so byte equality against rule destinations
/// (validated `DomainName` values) works directly.
///
/// The returned buffer holds whatever bytes were consumed from the
/// channel and must be replayed to upstream verbatim before the
/// caller's relay loop starts — otherwise the upstream sees a
/// truncated TLS record (or, for non-TLS traffic, missing leading
/// bytes).
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

/// Short label for tracing tags, identifying which hostname source was
/// used for an egress decision.
fn hostname_source_label(source: HostnameSource<'_>) -> &'static str {
    match source {
        HostnameSource::Sni(_) => "sni",
        HostnameSource::CacheOnly => "cache",
        HostnameSource::Deferred => "deferred",
    }
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
        body.extend_from_slice(&(extensions_total as u16).to_be_bytes());
        // SNI extension: type 0x0000
        body.extend_from_slice(&[0x00, 0x00]);
        body.extend_from_slice(&(extension_data_len as u16).to_be_bytes());
        body.extend_from_slice(&(server_name_list_len as u16).to_be_bytes());
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
        // Hand over more than the cap with no SNI in sight.
        let chunk = vec![0u8; 8192];
        tx.send(Bytes::from(chunk.clone())).await.unwrap();
        tx.send(Bytes::from(chunk.clone())).await.unwrap();
        tx.send(Bytes::from(chunk)).await.unwrap();
        drop(tx);

        let (buf, sni) = peek_for_sni(&mut rx, PEEK_BUF_SIZE, PEEK_BUDGET).await;
        assert_eq!(sni, None, "no SNI in non-TLS data");
        assert!(
            buf.len() >= PEEK_BUF_SIZE,
            "buffer must hit the cap before bail-out: got {}",
            buf.len()
        );
    }
}
