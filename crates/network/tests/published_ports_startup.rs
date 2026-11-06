//! Synchronous published-port startup failures through the public network interface.
//!
//! Keep port reclamation in its own integration binary: parallel socket unit tests
//! can claim a candidate port between releasing its reservation and starting the network.

#![cfg(feature = "engine")]

use std::net::{Ipv4Addr, TcpListener, UdpSocket};

use microsandbox_network::config::{
    EnvNetworkSecretResolver, NetworkConfig, PortProtocol, PublishedPort,
};
use microsandbox_network::network::SmoltcpNetwork;
use microsandbox_network::policy::NetworkPolicy;
use microsandbox_types::DeploymentProfile;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn published_port_bind_failure_reports_endpoint_and_releases_reservations() {
    for blocked_protocol in [PortProtocol::Tcp, PortProtocol::Udp] {
        let tcp_blocker = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let udp_blocker = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let blocked = match blocked_protocol {
            PortProtocol::Tcp => tcp_blocker.local_addr().unwrap(),
            PortProtocol::Udp => udp_blocker.local_addr().unwrap(),
        };
        let tcp_reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let udp_reservation = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let tcp_address = tcp_reservation.local_addr().unwrap();
        let udp_address = udp_reservation.local_addr().unwrap();
        let mut config = NetworkConfig::default();
        config.tls.enabled = false;
        // Port rollback must not depend on the host's external address families.
        config.interface.ipv4_address = Some(Ipv4Addr::new(172, 16, 0, 2));
        config.policy = NetworkPolicy::allow_all();
        for (address, protocol) in [
            (tcp_address, PortProtocol::Tcp),
            (udp_address, PortProtocol::Udp),
            (blocked, blocked_protocol),
        ] {
            config.ports.push(PublishedPort {
                host_port: address.port(),
                guest_port: 8000,
                protocol,
                host_bind: address.ip(),
            });
        }
        let mut network = SmoltcpNetwork::new(
            config.resolve(&EnvNetworkSecretResolver).unwrap(),
            7,
            DeploymentProfile::SingleTenant,
        )
        .unwrap();
        // Keep the free endpoints owned until the synchronous bind attempt.
        drop((tcp_reservation, udp_reservation));
        let error = network
            .start(tokio::runtime::Handle::current())
            .expect_err("occupied published endpoint must fail startup");
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        assert!(
            error.to_string().contains(&blocked.to_string()),
            "expected failure at {blocked_protocol:?} {blocked}, with TCP prefix \
             {tcp_address} and UDP prefix {udp_address}, got: {error}",
        );
        let protocol = match blocked_protocol {
            PortProtocol::Tcp => "TCP",
            PortProtocol::Udp => "UDP",
        };
        assert!(
            error.to_string().contains(protocol),
            "bind failure must identify its protocol: {error}",
        );
        let _tcp_rebound = TcpListener::bind(tcp_address).unwrap_or_else(|rebind| {
            panic!("rebind TCP prefix {tcp_address} after {error}: {rebind}")
        });
        let _udp_rebound = UdpSocket::bind(udp_address).unwrap_or_else(|rebind| {
            panic!("rebind UDP prefix {udp_address} after {error}: {rebind}")
        });
    }
}
