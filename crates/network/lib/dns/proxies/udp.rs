//! DNS-over-UDP proxy: drain queries from the interceptor channel,
//! route each through the shared [`DnsForwarder`], and inject responses
//! back into the guest RX ring.
//!
//! Mirrors [`super::tcp`] for the connectionless side. The interceptor
//! ([`crate::dns::interceptor::DnsInterceptor`]) handles smoltcp UDP
//! socket I/O and packet metadata; this module is the per-query
//! forwarding loop. Per-query parallelism is via `tokio::spawn` so a
//! slow upstream doesn't head-of-line block other in-flight queries.
//!
//! [`DnsForwarder`]: super::super::forwarder::DnsForwarder

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use smoltcp::wire::{EthernetAddress, IpEndpoint};
use tokio::sync::mpsc;

use super::super::common::transport::Transport;
use super::super::forwarder::{DnsForwarder, DnsForwarderHandle};
use super::super::interceptor::DnsQuery;
use crate::shared::SharedState;
use crate::udp_relay::construct_udp_response;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// DNS port.
const DNS_PORT: u16 = 53;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// DNS-over-UDP proxy. Drains [`DnsQuery`] records the interceptor
/// pushed onto `query_rx`, dispatches each through the shared
/// forwarder, and injects response frames directly into the guest RX ring.
pub(crate) struct UdpProxy {
    /// Queries pushed by the interceptor's smoltcp read loop.
    query_rx: mpsc::Receiver<DnsQuery>,
    /// Shared forwarder handle used by every inner query.
    forwarder: Arc<DnsForwarder>,
    /// Shared rings and wake handles for guest delivery.
    shared: Arc<SharedState>,
    /// Source MAC on synthesized response frames.
    gateway_mac: EthernetAddress,
    /// Destination MAC on synthesized response frames.
    guest_mac: EthernetAddress,
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
        forwarder: DnsForwarderHandle,
        shared: Arc<SharedState>,
        gateway_mac: [u8; 6],
        guest_mac: [u8; 6],
    ) {
        handle.spawn(async move {
            let Some(forwarder) = DnsForwarder::wait(forwarder).await else {
                tracing::debug!(
                    "dns/udp: upstream forwarder unavailable; UDP queries will be dropped"
                );
                return;
            };
            Self::new(query_rx, forwarder, shared, gateway_mac, guest_mac)
                .run()
                .await;
        });
    }

    /// Build a UDP proxy bound to the interceptor's channel pair.
    fn new(
        query_rx: mpsc::Receiver<DnsQuery>,
        forwarder: Arc<DnsForwarder>,
        shared: Arc<SharedState>,
        gateway_mac: [u8; 6],
        guest_mac: [u8; 6],
    ) -> Self {
        Self {
            query_rx,
            forwarder,
            shared,
            gateway_mac: EthernetAddress(gateway_mac),
            guest_mac: EthernetAddress(guest_mac),
        }
    }

    /// Drive the per-query dispatch loop. Consumes `self`: the channels
    /// are owned by this task for its lifetime.
    async fn run(mut self) {
        while let Some(query) = self.query_rx.recv().await {
            let shared = self.shared.clone();
            let forwarder = self.forwarder.clone();
            let gateway_mac = self.gateway_mac;
            let guest_mac = self.guest_mac;
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
                inject_dns_response(
                    query.source,
                    original_dst_smoltcp,
                    &data,
                    shared,
                    gateway_mac,
                    guest_mac,
                );
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

fn smoltcp_endpoint_to_std(endpoint: IpEndpoint) -> SocketAddr {
    SocketAddr::new(smoltcp_ip_to_std(endpoint.addr), endpoint.port)
}

fn inject_dns_response(
    response_dest: IpEndpoint,
    response_source: Option<smoltcp::wire::IpAddress>,
    payload: &[u8],
    shared: Arc<SharedState>,
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
) {
    let Some(response_source) = response_source else {
        tracing::debug!("dns/udp: response dropped because original destination is missing");
        return;
    };

    let response_source = SocketAddr::new(smoltcp_ip_to_std(response_source), DNS_PORT);
    let response_dest = smoltcp_endpoint_to_std(response_dest);

    let Some(frame) = construct_udp_response(
        response_source,
        response_dest,
        payload,
        gateway_mac,
        guest_mac,
    ) else {
        tracing::debug!("dns/udp: response dropped because address families differ");
        return;
    };

    if shared.rx_ring.push(frame).is_ok() {
        shared.rx_wake.wake();
    } else {
        tracing::debug!("dns/udp: response dropped because rx_ring is full");
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

    #[test]
    fn smoltcp_endpoint_to_std_preserves_port() {
        let endpoint = IpEndpoint {
            addr: smoltcp::wire::IpAddress::Ipv4(Ipv4Addr::new(10, 0, 0, 2)),
            port: 4242,
        };

        assert_eq!(
            smoltcp_endpoint_to_std(endpoint),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 4242)
        );
    }
}
