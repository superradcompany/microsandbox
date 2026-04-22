//! DNS-over-UDP proxy: drain queries from the interceptor channel,
//! route each through the shared [`DnsForwarder`], and send responses
//! back via the response channel.
//!
//! Mirrors [`super::tcp`] for the connectionless side. The interceptor
//! ([`crate::dns::interceptor::DnsInterceptor`]) handles smoltcp UDP
//! socket I/O and packet metadata; this module is the per-query
//! forwarding loop. Per-query parallelism is via `tokio::spawn` so a
//! slow upstream doesn't head-of-line block other in-flight queries.
//!
//! [`DnsForwarder`]: super::super::forwarder::DnsForwarder

use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::mpsc;

use super::super::common::transport::Transport;
use super::super::forwarder::{DnsForwarder, DnsForwarderHandle};
use super::super::interceptor::{DnsQuery, DnsResponse};
use crate::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// DNS-over-UDP proxy. Drains [`DnsQuery`] records the interceptor
/// pushed onto `query_rx`, dispatches each through the shared
/// forwarder, and sends [`DnsResponse`]s back on `response_tx` for the
/// interceptor to write to the smoltcp socket.
pub(crate) struct UdpProxy {
    /// Queries pushed by the interceptor's smoltcp read loop.
    query_rx: mpsc::Receiver<DnsQuery>,
    /// Responses the interceptor will pop and write back to the socket.
    response_tx: mpsc::Sender<DnsResponse>,
    /// Shared forwarder handle used by every inner query.
    forwarder: Arc<DnsForwarder>,
    /// Shared wake handle for poking the smoltcp poll loop after send.
    shared: Arc<SharedState>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl UdpProxy {
    /// Spawn the DNS-over-UDP proxy task. Waits for the forwarder,
    /// constructs a [`UdpProxy`], and drives it to completion.
    pub(crate) fn spawn(
        handle: &tokio::runtime::Handle,
        query_rx: mpsc::Receiver<DnsQuery>,
        response_tx: mpsc::Sender<DnsResponse>,
        forwarder: DnsForwarderHandle,
        shared: Arc<SharedState>,
    ) {
        handle.spawn(async move {
            let Some(forwarder) = DnsForwarder::wait(forwarder).await else {
                tracing::debug!(
                    "dns/udp: upstream forwarder unavailable; UDP queries will be dropped"
                );
                return;
            };
            Self::new(query_rx, response_tx, forwarder, shared)
                .run()
                .await;
        });
    }

    /// Build a UDP proxy bound to the interceptor's channel pair.
    fn new(
        query_rx: mpsc::Receiver<DnsQuery>,
        response_tx: mpsc::Sender<DnsResponse>,
        forwarder: Arc<DnsForwarder>,
        shared: Arc<SharedState>,
    ) -> Self {
        Self {
            query_rx,
            response_tx,
            forwarder,
            shared,
        }
    }

    /// Drive the per-query dispatch loop. Consumes `self`: the channels
    /// are owned by this task for its lifetime.
    async fn run(mut self) {
        while let Some(query) = self.query_rx.recv().await {
            let response_tx = self.response_tx.clone();
            let shared = self.shared.clone();
            let forwarder = self.forwarder.clone();
            // Two views of the same address: smoltcp's IpAddress for
            // the outgoing source-IP stamp on the response, and std's
            // IpAddr for the forwarder's policy lookup.
            let original_dst_smoltcp = query.original_dst;
            let original_dst = original_dst_smoltcp.map(smoltcp_ip_to_std);

            tokio::spawn(async move {
                let Some(data) = forwarder
                    .forward(&query.data, original_dst, Transport::Udp, None)
                    .await
                else {
                    return;
                };
                let response = DnsResponse {
                    data,
                    dest: query.source,
                    source_addr: original_dst_smoltcp,
                };
                if response_tx.send(response).await.is_ok() {
                    shared.proxy_wake.wake();
                }
            });
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Internal
//--------------------------------------------------------------------------------------------------

/// Convert smoltcp's `IpAddress` to std's `IpAddr`. smoltcp 0.13 aliases
/// its `Ipv4Address` / `Ipv6Address` to `core::net::Ipv{4,6}Addr`, so
/// this is a thin variant unwrap.
fn smoltcp_ip_to_std(addr: smoltcp::wire::IpAddress) -> IpAddr {
    match addr {
        smoltcp::wire::IpAddress::Ipv4(a) => IpAddr::V4(a),
        smoltcp::wire::IpAddress::Ipv6(a) => IpAddr::V6(a),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn smoltcp_ip_to_std_v4_round_trip() {
        let smoltcp = smoltcp::wire::IpAddress::Ipv4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(
            smoltcp_ip_to_std(smoltcp),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn smoltcp_ip_to_std_v6_round_trip() {
        let smoltcp = smoltcp::wire::IpAddress::Ipv6("fd42::1".parse().unwrap());
        assert_eq!(
            smoltcp_ip_to_std(smoltcp),
            IpAddr::V6("fd42::1".parse::<Ipv6Addr>().unwrap())
        );
    }
}
