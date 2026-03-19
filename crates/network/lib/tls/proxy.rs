//! Transparent TLS proxy listener.
//!
//! Accepts redirected TCP connections, recovers the original destination,
//! extracts SNI from the ClientHello, and dispatches to either the intercept
//! path (MITM with generated cert) or the bypass path (raw TCP splice).

use std::{io, net::SocketAddr, sync::Arc};

use rustls::ServerConfig;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;

use super::{BypassMatcher, CertCache, InterceptHandler, NoopHandler};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum bytes to buffer from the guest for ClientHello parsing.
const MAX_CLIENT_HELLO_BUF: usize = 16384;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A TLS proxy listener that has been bound but not yet started.
///
/// Created in the privileged phase (before privilege drop) and started in the
/// unprivileged phase, mirroring the `PortPublisher` two-phase pattern.
pub struct PendingTlsProxy {
    /// The bound TCP listener.
    pub listener: TcpListener,

    /// The actual port the listener is bound to.
    pub port: u16,
}

/// A running TLS proxy that accepts and processes intercepted connections.
pub struct TlsProxy {
    _handle: JoinHandle<()>,
    _redirect_guard: Option<RedirectGuard>,
}

/// RAII guard that removes kernel redirect rules on drop.
///
/// Handles graceful shutdown cleanup. Note: if the process is SIGKILL'd, this
/// destructor does not run — stale rules are cleaned up on next startup
/// by the redirect install function (which deletes any existing table first).
pub struct RedirectGuard {
    sandbox_id: u32,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RedirectGuard {
    /// Creates a new redirect guard for the given sandbox.
    pub fn new(sandbox_id: u32) -> Self {
        Self { sandbox_id }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for RedirectGuard {
    fn drop(&mut self) {
        if let Err(e) = super::redirect::remove(self.sandbox_id) {
            tracing::warn!(
                sandbox_id = self.sandbox_id,
                "failed to remove TLS redirect rules: {e}"
            );
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Binds the TLS proxy listener on an OS-assigned port.
///
/// Must be called in the privileged phase before dropping privileges.
pub async fn bind_proxy() -> io::Result<PendingTlsProxy> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tracing::info!(port, "TLS proxy listener bound");
    Ok(PendingTlsProxy { listener, port })
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TlsProxy {
    /// Starts the TLS proxy from a pending (pre-bound) listener.
    ///
    /// Takes ownership of the `RedirectGuard` so that redirect rules are
    /// cleaned up when the proxy is dropped.
    pub fn start(
        pending: PendingTlsProxy,
        cert_cache: Arc<CertCache>,
        bypass: BypassMatcher,
        client_config: Arc<rustls::ClientConfig>,
        handler: Arc<dyn InterceptHandler>,
        redirect_guard: RedirectGuard,
    ) -> Self {
        let bypass = Arc::new(bypass);

        let handle = tokio::spawn(async move {
            accept_loop(pending.listener, cert_cache, bypass, client_config, handler).await;
        });

        Self {
            _handle: handle,
            _redirect_guard: Some(redirect_guard),
        }
    }

    /// Starts a TLS proxy with a no-op intercept handler.
    pub fn start_noop(
        pending: PendingTlsProxy,
        cert_cache: Arc<CertCache>,
        bypass: BypassMatcher,
        client_config: Arc<rustls::ClientConfig>,
        redirect_guard: RedirectGuard,
    ) -> Self {
        Self::start(
            pending,
            cert_cache,
            bypass,
            client_config,
            Arc::new(NoopHandler),
            redirect_guard,
        )
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Internal
//--------------------------------------------------------------------------------------------------

/// Main accept loop for the TLS proxy.
async fn accept_loop(
    listener: TcpListener,
    cert_cache: Arc<CertCache>,
    bypass: Arc<BypassMatcher>,
    client_config: Arc<rustls::ClientConfig>,
    handler: Arc<dyn InterceptHandler>,
) {
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("TLS proxy accept error: {e}");
                continue;
            }
        };

        let cache = Arc::clone(&cert_cache);
        let bypass = Arc::clone(&bypass);
        let client_cfg = Arc::clone(&client_config);
        let handler = Arc::clone(&handler);

        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(stream, peer_addr, cache, bypass, client_cfg, handler).await
            {
                tracing::debug!(%peer_addr, "TLS proxy connection ended: {e}");
            }
        });
    }
}

/// Handles a single redirected connection.
async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    cert_cache: Arc<CertCache>,
    bypass: Arc<BypassMatcher>,
    client_config: Arc<rustls::ClientConfig>,
    handler: Arc<dyn InterceptHandler>,
) -> io::Result<()> {
    // Recover the original destination (pre-redirect address).
    let original_dst = get_original_dst(&stream)?;
    tracing::debug!(%peer_addr, %original_dst, "TLS proxy: recovered original dst");

    // Buffer the ClientHello. TCP may deliver it across multiple segments,
    // so we loop until we have the full TLS record.
    let mut buf = vec![0u8; MAX_CLIENT_HELLO_BUF];
    let mut total = 0;
    loop {
        let n = stream.read(&mut buf[total..]).await?;
        if n == 0 {
            if total == 0 {
                return Ok(());
            }
            break;
        }
        total += n;

        // Once we have the 5-byte TLS record header, check if we have the
        // full record. If so, stop reading.
        if total >= 5 {
            let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if total >= 5 + record_len {
                break;
            }
        }

        if total >= MAX_CLIENT_HELLO_BUF {
            break;
        }
    }
    let client_hello = &buf[..total];

    // Extract SNI.
    let sni = super::sni::extract_sni(client_hello);
    let sni_str = sni.as_deref().unwrap_or("<no SNI>");
    tracing::debug!(%peer_addr, %original_dst, sni = sni_str, "TLS proxy: extracted SNI");

    // Bypass decision.
    if let Some(ref sni) = sni {
        if bypass.is_bypassed(sni) {
            tracing::debug!(sni, "TLS proxy: bypassing");
            return bypass_connection(stream, original_dst, client_hello).await;
        }
    }

    // Intercept path.
    let domain = match sni.as_deref() {
        Some(d) => d,
        None => {
            tracing::warn!(%peer_addr, %original_dst, "TLS proxy: no SNI in ClientHello, intercepting with dst IP");
            // Use the original destination IP as fallback — "localhost" would
            // fail upstream TLS since the server doesn't serve that hostname.
            return intercept_connection(
                stream,
                original_dst,
                client_hello,
                &original_dst.ip().to_string(),
                cert_cache,
                client_config,
                handler,
            )
            .await;
        }
    };
    tracing::debug!(domain, "TLS proxy: intercepting");
    intercept_connection(
        stream,
        original_dst,
        client_hello,
        domain,
        cert_cache,
        client_config,
        handler,
    )
    .await
}

/// Bypass path: splice raw bytes to the real server without TLS termination.
async fn bypass_connection(
    mut guest_stream: TcpStream,
    original_dst: SocketAddr,
    buffered: &[u8],
) -> io::Result<()> {
    let mut server_stream = TcpStream::connect(original_dst).await?;

    // Replay the buffered ClientHello to the real server.
    server_stream.write_all(buffered).await?;

    // Bidirectional splice.
    tokio::io::copy_bidirectional(&mut guest_stream, &mut server_stream).await?;
    Ok(())
}

/// Intercept path: terminate guest TLS, connect upstream, relay plaintext.
async fn intercept_connection(
    guest_stream: TcpStream,
    original_dst: SocketAddr,
    buffered_client_hello: &[u8],
    domain: &str,
    cert_cache: Arc<CertCache>,
    client_config: Arc<rustls::ClientConfig>,
    handler: Arc<dyn InterceptHandler>,
) -> io::Result<()> {
    // Get or generate a certificate for this domain.
    let certified_key = cert_cache.get_or_generate(domain)?;

    // Build a server config that always returns this domain's cert.
    let resolver = Arc::new(FixedCertResolver(certified_key));
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    // Create a duplex stream that replays the buffered ClientHello first,
    // then reads from the real guest stream.
    let replay_stream = ReplayStream::new(buffered_client_hello.to_vec(), guest_stream);

    // Accept TLS from the guest (replaying the ClientHello).
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let guest_tls = acceptor
        .accept(replay_stream)
        .await
        .map_err(|e| io::Error::other(format!("guest TLS handshake failed: {e}")))?;

    // Connect upstream to the real server.
    let server_tls = super::upstream::connect(original_dst, domain, client_config).await?;

    // Relay plaintext bidirectionally through the InterceptHandler.
    // This allows the secrets layer to inspect/modify HTTP request/response bytes.
    let domain = domain.to_string();
    let handler_out = Arc::clone(&handler);
    let dst_out = original_dst;
    let domain_out = domain.clone();

    let (mut guest_read, mut guest_write) = tokio::io::split(guest_tls);
    let (mut server_read, mut server_write) = tokio::io::split(server_tls);

    let outbound = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = guest_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let data = handler_out.on_request(&dst_out, &domain_out, &buf[..n]);
            server_write.write_all(&data).await?;
        }
        server_write.shutdown().await?;
        Ok::<_, io::Error>(())
    });

    let inbound = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = server_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let data = handler.on_response(&original_dst, &domain, &buf[..n]);
            guest_write.write_all(&data).await?;
        }
        guest_write.shutdown().await?;
        Ok::<_, io::Error>(())
    });

    // Wait for both directions to complete.
    let (out_result, in_result) = tokio::join!(outbound, inbound);
    out_result.map_err(|e| io::Error::other(e))??;
    in_result.map_err(|e| io::Error::other(e))??;
    Ok(())
}

/// Recovers the original destination address from a redirected connection.
///
/// Uses `SO_ORIGINAL_DST` on Linux and `DIOCNATLOOK` on macOS.
fn get_original_dst(stream: &TcpStream) -> io::Result<SocketAddr> {
    #[cfg(target_os = "linux")]
    {
        get_original_dst_linux(stream)
    }

    #[cfg(target_os = "macos")]
    {
        // macOS pf redirect requires DIOCNATLOOK ioctl on /dev/pf to recover
        // the original destination. This is not yet implemented. TLS
        // interception is gated to Linux-only until this is done — the
        // redirect_macos module refuses to install rules when DIOCNATLOOK is
        // unavailable.
        let _ = stream;
        Err(io::Error::other(
            "TLS interception not yet supported on macOS — DIOCNATLOOK not implemented",
        ))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = stream;
        Err(io::Error::other("platform not supported"))
    }
}

#[cfg(target_os = "linux")]
fn get_original_dst_linux(stream: &TcpStream) -> io::Result<SocketAddr> {
    use std::{mem, os::unix::io::AsRawFd};

    let fd = stream.as_raw_fd();

    // Try IPv4 first: SO_ORIGINAL_DST = 80
    const SO_ORIGINAL_DST: libc::c_int = 80;
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut len: libc::socklen_t = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            (&raw mut addr).cast(),
            &mut len,
        )
    };

    if ret == 0 {
        let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        return Ok(SocketAddr::new(ip.into(), port));
    }

    // Try IPv6: IP6T_SO_ORIGINAL_DST = 80
    const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;
    let mut addr6: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    let mut len6: libc::socklen_t = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            IP6T_SO_ORIGINAL_DST,
            (&raw mut addr6).cast(),
            &mut len6,
        )
    };

    if ret == 0 {
        let ip = std::net::Ipv6Addr::from(addr6.sin6_addr.s6_addr);
        let port = u16::from_be(addr6.sin6_port);
        return Ok(SocketAddr::new(ip.into(), port));
    }

    Err(io::Error::last_os_error())
}

//--------------------------------------------------------------------------------------------------
// Types: Internal
//--------------------------------------------------------------------------------------------------

/// A cert resolver that always returns a fixed `CertifiedKey`.
#[derive(Debug)]
struct FixedCertResolver(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for FixedCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// A stream that replays buffered bytes before reading from the underlying stream.
///
/// Used to replay the ClientHello to the TLS acceptor after we've already read
/// it for SNI extraction.
struct ReplayStream {
    buffer: Vec<u8>,
    pos: usize,
    inner: TcpStream,
}

impl ReplayStream {
    fn new(buffer: Vec<u8>, inner: TcpStream) -> Self {
        Self {
            buffer,
            pos: 0,
            inner,
        }
    }
}

impl tokio::io::AsyncRead for ReplayStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // First, drain the replay buffer.
        if self.pos < self.buffer.len() {
            let remaining = &self.buffer[self.pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.pos += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }

        // Then delegate to the inner stream.
        let inner = &mut self.inner;
        tokio::pin!(inner);
        inner.poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for ReplayStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let inner = &mut self.inner;
        tokio::pin!(inner);
        inner.poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let inner = &mut self.inner;
        tokio::pin!(inner);
        inner.poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let inner = &mut self.inner;
        tokio::pin!(inner);
        inner.poll_shutdown(cx)
    }
}
