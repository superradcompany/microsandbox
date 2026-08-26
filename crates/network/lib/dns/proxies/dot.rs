//! DNS-over-TLS (DoT) proxy: terminate guest TLS on TCP/853, parse the
//! inner RFC 1035 §4.2.2 length-prefixed DNS frames, and route each
//! query through the shared [`DnsForwarder`].
//!
//! DoT (RFC 7858) is plain DNS-over-TCP wrapped in TLS — the inner
//! wire format is identical to what the plain [`super::tcp`] proxy
//! handles. This module reuses that framing (via the sibling
//! [`super::framing`] module) after terminating the TLS session with a
//! per-domain cert from the sandbox's intercept CA
//! ([`crate::tls::state::TlsState`]).
//!
//! Why proxy DoT instead of just refusing it? A guest that picks DoT
//! for privacy/encryption reasons would otherwise bypass the block
//! list and rebind protection — the gateway couldn't see query names
//! or response IPs. Terminating TLS at the gateway keeps the same
//! policy surface as plain DNS, at the cost of requiring the sandbox
//! CA to be trusted inside the guest (same requirement the existing
//! HTTPS TLS interception imposes).
//!
//! Upstream: when the guest aimed at the gateway IP, the forwarder
//! sends the inner query to the configured upstream over plain DNS.
//! When the guest aimed at a non-gateway `@target`, the forwarder
//! re-encrypts and sends to `@target:853` over DoT — see
//! `build_direct_client` in `dns::client`. The SNI extracted from the
//! guest's ClientHello is threaded through as the upstream cert server
//! name.
//!
//! [`DnsForwarder`]: super::super::forwarder::DnsForwarder

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::super::common::transport::Transport;
use super::super::forwarder::{DnsForwarder, DnsForwarderHandle};
use super::framing::{frame, take_message};
use crate::netstack::shared::SharedState;
use crate::tls::state::TlsState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Max bytes to buffer while waiting for the ClientHello. Matches
/// `tls/proxy.rs` for consistent sizing across both TLS entry points.
const CLIENT_HELLO_BUF_SIZE: usize = 16384;

/// Guest-facing TLS handshake timeout. Matches `tls/proxy.rs`.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Idle timeout once TLS is established and DNS framing starts. Same
/// value as the plain TCP proxy (sibling `mod.rs`) — RFC 7858 §3.4
/// suggests servers keep DoT connections open for pipelining but
/// impose a reasonable ceiling.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Capacity of the internal channel that carries forwarder responses
/// back to the TLS write side. Bounded to prevent unbounded fan-in
/// from pipelined queries.
const RESPONSE_CHANNEL_CAPACITY: usize = 32;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Per-connection DoT proxy task.
pub(crate) struct DotProxy {
    /// The (resolver-IP, 853) the guest aimed at.
    dst: SocketAddr,
    /// Encrypted bytes from the smoltcp TCP stream.
    from_smoltcp: mpsc::Receiver<Bytes>,
    /// Encrypted bytes to the smoltcp TCP stream.
    to_smoltcp: mpsc::Sender<Bytes>,
    /// Handle that resolves to the shared DNS forwarder.
    forwarder: DnsForwarderHandle,
    /// TLS state used to build the guest-facing session.
    tls_state: Arc<TlsState>,
    /// Shared wake handle for poking the smoltcp poll loop after send.
    shared: Arc<SharedState>,
}

/// Initialized DoT session owned by a running [`DotProxy`].
struct DotSession {
    /// Guest-facing TLS session. Only touched from the proxy task so
    /// rustls' non-Send/non-Sync state stays on one thread.
    guest_tls: rustls::ServerConnection,
    /// Encrypted bytes from the smoltcp TCP stream.
    from_smoltcp: mpsc::Receiver<Bytes>,
    /// Encrypted bytes to the smoltcp TCP stream.
    to_smoltcp: mpsc::Sender<Bytes>,
    /// Plaintext buffer: decrypted bytes pending frame extraction.
    plaintext_buf: Vec<u8>,
    /// Scratch buffer for `write_tls` output. Reused across flushes.
    tls_out_buf: Vec<u8>,
    /// Shared wake handle for poking the smoltcp poll loop after send.
    shared: Arc<SharedState>,
    /// The (resolver-IP, 853) the guest aimed at — passed to the
    /// forwarder for upstream selection.
    dst: SocketAddr,
    /// Server name chosen from the guest's ClientHello (or the dst IP
    /// fallback). Threaded into the upstream DoT client for cert
    /// validation when the forwarder takes the direct path.
    sni: String,
    /// Shared forwarder handle used by every inner query.
    forwarder: Arc<DnsForwarder>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DotProxy {
    /// Build a DoT proxy task from a freshly accepted TCP/853 connection.
    pub(crate) fn new(
        dst: SocketAddr,
        from_smoltcp: mpsc::Receiver<Bytes>,
        to_smoltcp: mpsc::Sender<Bytes>,
        forwarder: DnsForwarderHandle,
        tls_state: Arc<TlsState>,
        shared: Arc<SharedState>,
    ) -> Self {
        Self {
            dst,
            from_smoltcp,
            to_smoltcp,
            forwarder,
            tls_state,
            shared,
        }
    }

    /// Run the DoT proxy task to completion.
    pub(crate) async fn run(self) {
        let Self {
            dst,
            from_smoltcp,
            to_smoltcp,
            forwarder,
            tls_state,
            shared,
        } = self;

        let Some(forwarder) = DnsForwarder::wait(forwarder).await else {
            tracing::debug!(%dst, "DoT: forwarder unavailable; closing connection");
            return;
        };
        let proxy = match DotSession::new(
            dst,
            from_smoltcp,
            to_smoltcp,
            forwarder,
            tls_state,
            shared,
        )
        .await
        {
            Ok(proxy) => proxy,
            Err(error) => {
                tracing::debug!(%dst, %error, "DoT proxy setup failed");
                return;
            }
        };
        if let Err(error) = proxy.run().await {
            tracing::debug!(%dst, %error, "DoT proxy task ended");
        }
    }
}

impl DotSession {
    /// Initialize a DoT session from a freshly accepted TCP/853 connection.
    ///
    /// Buffers guest bytes until the ClientHello is available, picks a
    /// server name (or falls back to the dst IP), builds the
    /// guest-facing rustls session with the per-domain intercept cert,
    /// and primes the rustls state machine with the ClientHello bytes
    /// so [`Self::run`] starts at a clean handshake-pump entry.
    async fn new(
        dst: SocketAddr,
        mut from_smoltcp: mpsc::Receiver<Bytes>,
        to_smoltcp: mpsc::Sender<Bytes>,
        forwarder: Arc<DnsForwarder>,
        tls_state: Arc<TlsState>,
        shared: Arc<SharedState>,
    ) -> io::Result<Self> {
        // Phase 0: buffer guest bytes until we can extract SNI.
        let fallback_sni = dst.ip().to_string();
        let (sni, initial_buf) = timeout(
            TLS_HANDSHAKE_TIMEOUT,
            extract_sni(&mut from_smoltcp, &fallback_sni),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DoT SNI extraction timed out"))??;

        // Build the guest-facing TLS session with the per-domain
        // intercept cert.
        let domain_cert = tls_state
            .get_or_generate_cert(&sni)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let guest_tls = rustls::ServerConnection::new(domain_cert.server_config.clone())
            .map_err(io::Error::other)?;

        let mut proxy = Self {
            guest_tls,
            from_smoltcp,
            to_smoltcp,
            plaintext_buf: Vec::new(),
            tls_out_buf: Vec::with_capacity(CLIENT_HELLO_BUF_SIZE),
            shared,
            dst,
            sni,
            forwarder,
        };

        // Feed the ClientHello bytes we already consumed while sniffing
        // SNI, and flush the resulting ServerHello / certs so `run`
        // starts with a handshake that's strictly pump-more-bytes.
        proxy.feed_tls(&initial_buf)?;
        proxy.flush_to_guest().await?;
        Ok(proxy)
    }

    /// Drive the proxy to completion. Consumes `self`: the guest-facing
    /// rustls session is owned by this task for its lifetime.
    async fn run(mut self) -> io::Result<()> {
        self.drive_handshake().await?;
        self.dispatch_loop().await
    }

    /// Pump the rustls state machine with further bytes from the guest
    /// until the handshake completes. Assumes [`Self::new`] has already
    /// fed the initial ClientHello.
    async fn drive_handshake(&mut self) -> io::Result<()> {
        timeout(TLS_HANDSHAKE_TIMEOUT, async {
            while self.guest_tls.is_handshaking() {
                let data = self.from_smoltcp.recv().await.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "guest closed during DoT handshake",
                    )
                })?;
                self.feed_tls(&data)?;
                self.flush_to_guest().await?;
            }
            Ok::<_, io::Error>(())
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DoT handshake timed out"))?
    }

    /// Framed DNS dispatch loop. Guest-facing TLS state stays in this
    /// task; per-query forwarding runs in sub-tasks that funnel
    /// responses back through an internal channel.
    async fn dispatch_loop(&mut self) -> io::Result<()> {
        let (resp_tx, mut resp_rx) = mpsc::channel::<Bytes>(RESPONSE_CHANNEL_CAPACITY);

        // Any plaintext already decrypted during the handshake (TLS 1.3
        // 0-RTT / early-data flight) must be drained before the select
        // loop starts — otherwise we might block waiting for the next
        // record and miss an in-flight query.
        self.drain_plaintext()?;
        self.dispatch_ready_queries(&resp_tx);

        loop {
            tokio::select! {
                // Incoming encrypted bytes from the guest.
                incoming = timeout(IDLE_TIMEOUT, self.from_smoltcp.recv()) => {
                    match incoming {
                        Ok(Some(chunk)) => {
                            self.feed_tls(&chunk)?;
                            self.drain_plaintext()?;
                            self.dispatch_ready_queries(&resp_tx);
                        }
                        Ok(None) => break,
                        Err(_) => {
                            tracing::debug!(dst = %self.dst, "DoT: idle timeout, closing connection");
                            return Ok(());
                        }
                    }
                }

                // A forwarded DNS response is ready. Frame + encrypt + send.
                Some(response) = resp_rx.recv() => {
                    self.write_plaintext(&frame(&response))?;
                    self.flush_to_guest().await?;
                }
            }
        }

        // Stop accepting queries from the guest. Dropping the root sender lets
        // `resp_rx` close after all in-flight tasks drop their cloned senders.
        drop(resp_tx);
        while let Some(response) = resp_rx.recv().await {
            self.write_plaintext(&frame(&response))?;
            self.flush_to_guest().await?;
        }

        self.guest_tls.send_close_notify();
        self.flush_to_guest().await
    }

    /// Drain all complete DNS frames from the plaintext buffer and
    /// spawn a forwarder sub-task for each.
    fn dispatch_ready_queries(&mut self, resp_tx: &mpsc::Sender<Bytes>) {
        let original_dst: Option<IpAddr> = Some(self.dst.ip());
        while let Some(query) = take_message(&mut self.plaintext_buf) {
            let forwarder = self.forwarder.clone();
            let resp_tx = resp_tx.clone();
            let sni = self.sni.clone();
            tokio::spawn(async move {
                let Some(response) = forwarder
                    .forward(&query, original_dst, Transport::Dot, Some(&sni))
                    .await
                else {
                    return;
                };
                // Ignore send error: the proxy task is shutting down.
                let _ = resp_tx.send(response).await;
            });
        }
    }

    /// Feed encrypted bytes from the guest into the rustls state machine.
    fn feed_tls(&mut self, data: &[u8]) -> io::Result<()> {
        let mut remaining = data;
        while !remaining.is_empty() {
            self.guest_tls
                .read_tls(&mut remaining)
                .map_err(io::Error::other)?;
            self.guest_tls
                .process_new_packets()
                .map_err(io::Error::other)?;
        }
        Ok(())
    }

    /// Pull all available decrypted plaintext out of the TLS state
    /// machine and append it to `self.plaintext_buf`.
    fn drain_plaintext(&mut self) -> io::Result<()> {
        let mut buf = [0u8; 4096];
        loop {
            match self.guest_tls.reader().read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => self.plaintext_buf.extend_from_slice(&buf[..n]),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    /// Write plaintext bytes into the guest-facing TLS writer. The
    /// caller is responsible for flushing with [`Self::flush_to_guest`].
    fn write_plaintext(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.guest_tls
            .writer()
            .write_all(bytes)
            .map_err(io::Error::other)
    }

    /// Flush any pending guest-facing TLS output to the smoltcp channel.
    /// Reuses `self.tls_out_buf` across calls to avoid per-flush allocation.
    async fn flush_to_guest(&mut self) -> io::Result<()> {
        while self.guest_tls.wants_write() {
            self.tls_out_buf.clear();
            self.guest_tls.write_tls(&mut self.tls_out_buf)?;
            if self.tls_out_buf.is_empty() {
                break;
            }
            self.to_smoltcp
                .send(Bytes::copy_from_slice(&self.tls_out_buf))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "channel closed"))?;
            self.shared.proxy_wake.wake();
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Internal
//--------------------------------------------------------------------------------------------------

/// Buffer channel data until the ClientHello is available, then extract
/// SNI or fall back to `fallback_sni` if the (complete) ClientHello
/// carries no SNI extension. Returns the chosen server name and the
/// buffered bytes (which still need to be fed to the rustls state
/// machine by the caller).
///
/// DoT clients that target an IP literal (`dig +tls @1.1.1.1`) typically
/// omit SNI — RFC 6066 §3 forbids IP literals there — so the fallback
/// kicks in when the ClientHello is complete but carries no SNI
/// extension. Both rustls and rcgen accept IP-literal server names, so
/// the same fallback feeds guest-facing cert generation and the
/// upstream TLS server name.
async fn extract_sni(
    from_smoltcp: &mut mpsc::Receiver<Bytes>,
    fallback_sni: &str,
) -> io::Result<(String, Vec<u8>)> {
    let mut initial_buf = Vec::with_capacity(CLIENT_HELLO_BUF_SIZE);
    loop {
        let data = from_smoltcp
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed"))?;
        initial_buf.extend_from_slice(&data);
        if let Some(name) = crate::tls::sni::extract_sni(&initial_buf) {
            return Ok((name, initial_buf));
        }
        if is_complete_client_hello(&initial_buf) {
            // ClientHello is complete but has no SNI — typical for
            // `dig +tls @<ip>`. Fall back rather than hang waiting for
            // more bytes that will never arrive.
            return Ok((fallback_sni.to_string(), initial_buf));
        }
        if initial_buf.len() >= CLIENT_HELLO_BUF_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ClientHello too large or malformed",
            ));
        }
    }
}

/// Returns `true` once `buf` contains the full TLS Handshake record
/// that carries the ClientHello. Used to decide "keep buffering vs
/// accept the hello as-is" when SNI parsing yields nothing.
fn is_complete_client_hello(buf: &[u8]) -> bool {
    // TLS record header: type(1) + version(2) + length(2). The
    // Handshake ContentType is `0x16`. The length is the body length,
    // so total = 5 + length.
    if buf.len() < 5 || buf[0] != 0x16 {
        return false;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    buf.len() >= 5 + record_len
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use hickory_net::proto::op::{Message, MessageType, OpCode, Query};
    use hickory_net::proto::rr::{Name, RecordType};
    use hickory_net::proto::serialize::binary::{BinDecodable, BinEncodable};
    use rustls::pki_types::ServerName;

    use super::*;
    use crate::dns::forwarder::DnsForwarder;
    use crate::netstack::poll::GatewayIps;
    use crate::tls::ca::CertAuthority;
    use crate::tls::certgen::generate_domain_cert;

    const TEST_DOMAIN: &str = "dns.test";

    #[tokio::test(flavor = "current_thread")]
    async fn guest_eof_preserves_pending_response() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let shared = Arc::new(SharedState::new(8));
        let gateway = GatewayIps {
            ipv4: Some("100.96.0.1".parse().unwrap()),
            ipv6: None,
        };
        let forwarder = DnsForwarder::for_proxy_test(shared.clone(), gateway).await;
        let (guest_tls, mut client_tls) = connected_tls_pair();
        let (from_guest_tx, from_smoltcp) = mpsc::channel(1);
        let (to_smoltcp, mut to_guest_rx) = mpsc::channel(8);

        let mut query = Message::new(0x4242, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(
            Name::from_ascii(crate::HOST_ALIAS).unwrap(),
            RecordType::A,
        ));

        let mut proxy = DotSession {
            guest_tls,
            from_smoltcp,
            to_smoltcp,
            plaintext_buf: frame(&query.to_bytes().unwrap()),
            tls_out_buf: Vec::with_capacity(CLIENT_HELLO_BUF_SIZE),
            shared,
            dst: SocketAddr::from(([100, 96, 0, 1], 853)),
            sni: TEST_DOMAIN.to_string(),
            forwarder,
        };

        // The guest half-closes after its complete query. On a current-thread
        // runtime, the spawned forwarder cannot run until dispatch_loop yields.
        drop(from_guest_tx);
        proxy.dispatch_loop().await.unwrap();

        let mut encrypted = Vec::new();
        while let Ok(chunk) = to_guest_rx.try_recv() {
            encrypted.extend_from_slice(&chunk);
        }
        assert!(
            !encrypted.is_empty(),
            "pending DoT response must survive guest EOF",
        );

        let mut encrypted = encrypted.as_slice();
        while !encrypted.is_empty() {
            client_tls.read_tls(&mut encrypted).unwrap();
            client_tls.process_new_packets().unwrap();
        }

        let mut plaintext = Vec::new();
        loop {
            let mut buf = [0u8; 4096];
            match client_tls.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => plaintext.extend_from_slice(&buf[..n]),
                Err(ref error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("failed to read DoT response: {error}"),
            }
        }
        let response = take_message(&mut plaintext).expect("framed DoT response");
        let response = Message::from_bytes(&response).expect("valid DNS response");
        assert_eq!(response.metadata.id, 0x4242);
        assert_eq!(response.answers.len(), 1);
    }

    fn connected_tls_pair() -> (rustls::ServerConnection, rustls::ClientConnection) {
        let ca = CertAuthority::generate();
        let domain_cert = generate_domain_cert(TEST_DOMAIN, &ca, 1).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_der.clone()).unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client = rustls::ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from(TEST_DOMAIN.to_string()).unwrap(),
        )
        .unwrap();
        let mut server = rustls::ServerConnection::new(domain_cert.server_config.clone()).unwrap();

        for _ in 0..8 {
            let mut client_bytes = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut client_bytes).unwrap();
            }
            if !client_bytes.is_empty() {
                server.read_tls(&mut client_bytes.as_slice()).unwrap();
                server.process_new_packets().unwrap();
            }

            let mut server_bytes = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut server_bytes).unwrap();
            }
            if !server_bytes.is_empty() {
                client.read_tls(&mut server_bytes.as_slice()).unwrap();
                client.process_new_packets().unwrap();
            }

            if !client.is_handshaking()
                && !server.is_handshaking()
                && !client.wants_write()
                && !server.wants_write()
            {
                return (server, client);
            }
        }

        panic!("TLS handshake did not complete");
    }
}
