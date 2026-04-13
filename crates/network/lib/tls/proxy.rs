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
use crate::secrets::handler::SecretsHandler;
use crate::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Max bytes to buffer while waiting for the ClientHello.
const CLIENT_HELLO_BUF_SIZE: usize = 16384;

/// Buffer size for bidirectional relay.
const RELAY_BUF_SIZE: usize = 16384;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Spawn a TLS proxy task for a connection to an intercepted port.
pub fn spawn_tls_proxy(
    handle: &tokio::runtime::Handle,
    dst: SocketAddr,
    from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    tls_state: Arc<TlsState>,
) {
    handle.spawn(async move {
        if let Err(e) = tls_proxy_task(dst, from_smoltcp, to_smoltcp, shared, tls_state).await {
            tracing::debug!(dst = %dst, error = %e, "TLS proxy task ended");
        }
    });
}

/// Core TLS proxy task.
async fn tls_proxy_task(
    dst: SocketAddr,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    tls_state: Arc<TlsState>,
) -> io::Result<()> {
    // Phase 0: Buffer initial data to extract SNI from ClientHello.
    // Timeout prevents a slow/malicious guest from holding a proxy slot indefinitely.
    let sni_name = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        extract_sni_from_channel(&mut from_smoltcp),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SNI extraction timed out"))?;
    let (sni_name, initial_buf) = sni_name?;

    if tls_state.should_bypass(&sni_name) {
        tracing::debug!(sni = %sni_name, dst = %dst, "TLS bypass");
        bypass_relay(dst, initial_buf, from_smoltcp, to_smoltcp, shared).await
    } else {
        tracing::debug!(sni = %sni_name, dst = %dst, "TLS intercept");
        intercept_relay(
            dst,
            &sni_name,
            initial_buf,
            from_smoltcp,
            to_smoltcp,
            shared,
            tls_state,
        )
        .await
    }
}

/// Bypass mode: plain TCP splice, no TLS termination.
async fn bypass_relay(
    dst: SocketAddr,
    initial_buf: Vec<u8>,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
) -> io::Result<()> {
    let mut server = TcpStream::connect(dst).await?;
    server.write_all(&initial_buf).await?;

    let (mut server_rx, mut server_tx) = server.into_split();
    let mut buf = vec![0u8; RELAY_BUF_SIZE];

    loop {
        tokio::select! {
            data = from_smoltcp.recv() => {
                match data {
                    Some(bytes) => server_tx.write_all(&bytes).await?,
                    None => break,
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
async fn intercept_relay(
    dst: SocketAddr,
    sni_name: &str,
    initial_buf: Vec<u8>,
    mut from_smoltcp: mpsc::Receiver<Bytes>,
    to_smoltcp: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
    tls_state: Arc<TlsState>,
) -> io::Result<()> {
    // Create secrets handler for this connection (filters by SNI).
    // tls_intercepted = true because we're in intercept_relay (not bypass).
    let secrets_handler = SecretsHandler::new(&tls_state.secrets, sni_name, true);

    // Get or generate per-domain certificate (includes cached ServerConfig).
    let domain_cert = tls_state.get_or_generate_cert(sni_name);

    // Reuse cached ServerConfig — avoids cert chain clone + key clone + rebuild per connection.
    let mut guest_tls = rustls::ServerConnection::new(domain_cert.server_config.clone())
        .map_err(io::Error::other)?;

    // Feed the buffered ClientHello.
    {
        let mut remaining = &initial_buf[..];
        while !remaining.is_empty() {
            guest_tls
                .read_tls(&mut remaining)
                .map_err(io::Error::other)?;
            guest_tls.process_new_packets().map_err(io::Error::other)?;
        }
    }

    // Reusable buffer for TLS output — avoids per-flush heap allocation.
    let mut tls_buf = Vec::with_capacity(RELAY_BUF_SIZE + 256);

    // Send ServerHello etc. back to guest.
    flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;

    // Complete guest-facing TLS handshake with timeout to prevent resource exhaustion.
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
            flush_to_guest(&mut guest_tls, &to_smoltcp, &shared, &mut tls_buf).await?;
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;

    // Connect to real server with TLS.
    let server_stream = TcpStream::connect(dst).await?;
    let server_name = ServerName::try_from(sni_name.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut server_tls = tls_state
        .connector
        .connect(server_name, server_stream)
        .await
        .map_err(io::Error::other)?;

    // Phase 2: Bidirectional plaintext relay.
    let mut server_buf = vec![0u8; RELAY_BUF_SIZE];
    let mut plaintext_buf = vec![0u8; RELAY_BUF_SIZE];

    loop {
        tokio::select! {
            // Guest → server: receive encrypted, decrypt, forward plaintext.
            data = from_smoltcp.recv() => {
                let data = match data {
                    Some(d) => d,
                    None => break,
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
                }

                // Read all available decrypted plaintext and substitute secrets.
                loop {
                    match guest_tls.reader().read(&mut plaintext_buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if secrets_handler.is_empty() {
                                server_tls.write_all(&plaintext_buf[..n]).await?;
                            } else {
                                match secrets_handler.substitute(&plaintext_buf[..n]) {
                                    Some(substituted) => {
                                        server_tls.write_all(&substituted).await?;
                                    }
                                    None => {
                                        // Violation: placeholder going to disallowed host.
                                        if secrets_handler.terminates_on_violation() {
                                            shared.trigger_termination();
                                        }
                                        // Drop the connection.
                                        return Err(io::Error::new(
                                            io::ErrorKind::PermissionDenied,
                                            "secret violation: placeholder sent to disallowed host",
                                        ));
                                    }
                                }
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    }
                }
            }

            // Server → guest: read plaintext, encrypt, send via channel.
            result = server_tls.read(&mut server_buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
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

/// Buffer channel data until a complete ClientHello with SNI is received.
async fn extract_sni_from_channel(
    from_smoltcp: &mut mpsc::Receiver<Bytes>,
) -> io::Result<(String, Vec<u8>)> {
    let mut initial_buf = Vec::with_capacity(CLIENT_HELLO_BUF_SIZE);
    loop {
        let data = from_smoltcp
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed"))?;
        initial_buf.extend_from_slice(&data);

        if let Some(name) = sni::extract_sni(&initial_buf) {
            return Ok((name, initial_buf));
        }
        if initial_buf.len() >= CLIENT_HELLO_BUF_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello too large or no SNI found",
            ));
        }
    }
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
