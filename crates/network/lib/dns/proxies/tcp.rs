//! DNS-over-TCP proxy: terminate guest TCP/53 connections at the gateway,
//! parse RFC 1035 §4.2.2 length-prefixed messages, and route each query
//! through the same [`DnsForwarder`] the UDP path uses.
//!
//! This makes `dig +tcp @<resolver>` and the standard truncation retry
//! (RFC 7766) subject to the same domain block list, rebind protection,
//! and per-query upstream selection (configured upstream vs guest-chosen
//! `@target`) that the UDP path uses. Upstream transport for a guest TCP query is
//! also TCP — anything else would re-truncate large responses and
//! defeat the stub's reason for switching transports.
//!
//! Pipelined queries (RFC 7766 §6.2.1.1) are dispatched concurrently;
//! responses go back as they complete, in arrival order from the
//! forwarder. The DNS transaction id in each response identifies which
//! query it answers, so out-of-order responses are wire-legal.
//!
//! [`DnsForwarder`]: super::super::forwarder::DnsForwarder

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::super::common::transport::Transport;
use super::super::forwarder::{DnsForwarder, DnsForwarderHandle};
use super::framing::{take_message, write_framed};
use crate::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Idle timeout per TCP/53 connection. RFC 7766 recommends servers
/// support a few seconds of idle for pipelining; 30s is a generous
/// upper bound that still bounds resource use under attack.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Per-connection DNS-over-TCP proxy. Buffers incoming bytes from the
/// guest, extracts length-prefixed DNS messages, dispatches each
/// through the shared [`DnsForwarder`] in its own sub-task, and writes
/// length-prefixed responses back as they arrive.
pub(crate) struct TcpProxy {
    /// The (resolver-IP, 53) the guest aimed at — passed to the
    /// forwarder for upstream selection.
    dst: SocketAddr,
    /// Bytes from the smoltcp TCP stream.
    from_smoltcp: mpsc::Receiver<Bytes>,
    /// Bytes to the smoltcp TCP stream.
    to_smoltcp: mpsc::Sender<Bytes>,
    /// Framing buffer: incoming bytes pending message extraction.
    frame_buf: Vec<u8>,
    /// Shared forwarder handle used by every inner query.
    forwarder: Arc<DnsForwarder>,
    /// Shared wake handle for poking the smoltcp poll loop after send.
    shared: Arc<SharedState>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TcpProxy {
    /// Spawn a DNS-over-TCP proxy task for a newly established TCP/53
    /// connection. Waits for the forwarder, constructs a [`TcpProxy`],
    /// and drives it to completion.
    ///
    /// `dst` is the (resolver-IP, 53) the guest aimed at — passed to
    /// the forwarder so the per-query upstream selector can route to
    /// the right place (configured upstream if `dst.ip()` is a gateway
    /// IP, direct forward otherwise).
    pub(crate) fn spawn(
        handle: &tokio::runtime::Handle,
        dst: SocketAddr,
        from_smoltcp: mpsc::Receiver<Bytes>,
        to_smoltcp: mpsc::Sender<Bytes>,
        forwarder: DnsForwarderHandle,
        shared: Arc<SharedState>,
    ) {
        handle.spawn(async move {
            let Some(forwarder) = DnsForwarder::wait(forwarder).await else {
                tracing::debug!(%dst, "dns/tcp: upstream forwarder unavailable; closing connection");
                return;
            };
            Self::new(dst, from_smoltcp, to_smoltcp, forwarder, shared)
                .run()
                .await;
        });
    }

    /// Build a TCP proxy from a freshly accepted TCP/53 connection.
    fn new(
        dst: SocketAddr,
        from_smoltcp: mpsc::Receiver<Bytes>,
        to_smoltcp: mpsc::Sender<Bytes>,
        forwarder: Arc<DnsForwarder>,
        shared: Arc<SharedState>,
    ) -> Self {
        Self {
            dst,
            from_smoltcp,
            to_smoltcp,
            frame_buf: Vec::new(),
            forwarder,
            shared,
        }
    }

    /// Drive the proxy to completion. Consumes `self`: the framing
    /// buffer and channels are owned by this task for its lifetime.
    async fn run(mut self) {
        let original_dst = Some(self.dst.ip());
        loop {
            let next = match timeout(IDLE_TIMEOUT, self.from_smoltcp.recv()).await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => return, // guest closed
                Err(_) => {
                    tracing::debug!(dst = %self.dst, "dns/tcp: idle timeout, closing connection");
                    return;
                }
            };
            self.frame_buf.extend_from_slice(&next);

            // Drain all complete messages currently in the buffer. Each
            // query is forwarded in its own task so a slow upstream
            // doesn't block subsequent pipelined queries on the same
            // connection.
            while let Some(query) = take_message(&mut self.frame_buf) {
                let forwarder = self.forwarder.clone();
                let to_smoltcp = self.to_smoltcp.clone();
                let shared = self.shared.clone();
                tokio::spawn(async move {
                    let Some(response) = forwarder
                        .forward(&query, original_dst, Transport::Tcp, None)
                        .await
                    else {
                        // Forwarder couldn't even synthesize an error
                        // response — query bytes were too malformed.
                        // Skip; the guest's stub will time out or
                        // pipeline more.
                        return;
                    };
                    if write_framed(&to_smoltcp, &response).await.is_err() {
                        return;
                    }
                    shared.proxy_wake.wake();
                });
            }
        }
    }
}
