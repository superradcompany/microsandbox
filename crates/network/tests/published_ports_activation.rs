//! Failed socket replacement must remain a startup failure without enabling traffic.

#![cfg(all(feature = "engine", unix))]

use std::net::{Ipv4Addr, TcpListener, UdpSocket};

use microsandbox_network::config::{
    EnvNetworkSecretResolver, NetworkConfig, PortProtocol, PublishedPort,
};
use microsandbox_network::network::SmoltcpNetwork;
use microsandbox_types::DeploymentProfile;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct RestoreDescriptorLimit(libc::rlimit);

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for RestoreDescriptorLimit {
    fn drop(&mut self) {
        // SAFETY: restore the saved limit in the same isolated child process.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.0) }, 0);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn failed_activation_releases_reservations_and_remains_failed() {
    // Descriptor limits are process-wide; never change the parent test runner's limits.
    const CHILD_ENV: &str = "MSB_TEST_FAILED_NETWORK_ACTIVATION";
    if std::env::var_os(CHILD_ENV).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "failed_activation_releases_reservations_and_remains_failed",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "failed-activation child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        for first_protocol in [PortProtocol::Tcp, PortProtocol::Udp] {
            let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let tcp_address = tcp.local_addr().unwrap();
            let udp_address = udp.local_addr().unwrap();
            let mut config = NetworkConfig::default();
            config.tls.enabled = false;
            config.interface.ipv4_address = Some(Ipv4Addr::new(172, 16, 0, 2));
            let mut ports = [
                (tcp_address, PortProtocol::Tcp),
                (udp_address, PortProtocol::Udp),
            ];
            if first_protocol == PortProtocol::Udp {
                ports.reverse();
            }
            for (address, protocol) in ports {
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
            let activation = network.defer_activation();
            drop((tcp, udp));
            network.start(tokio::runtime::Handle::current()).unwrap();

            let mut original = std::mem::MaybeUninit::<libc::rlimit>::uninit();
            // SAFETY: getrlimit writes a complete rlimit into valid storage on success.
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, original.as_mut_ptr()) },
                0
            );
            // SAFETY: the preceding successful getrlimit initialized the value.
            let original = unsafe { original.assume_init() };
            let exhausted = libc::rlimit {
                rlim_cur: 3,
                rlim_max: original.rlim_max,
            };
            // SAFETY: the limit pointer is valid; only this isolated child's soft limit changes.
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &exhausted) },
                0
            );
            let restore_limit = RestoreDescriptorLimit(original);
            let result = activation.activate();
            drop(restore_limit);

            let error =
                result.expect_err("activation must fail when replacement cannot open sockets");
            let first_address = match first_protocol {
                PortProtocol::Tcp => tcp_address,
                PortProtocol::Udp => udp_address,
            };
            assert!(
                error.to_string().contains(&first_address.to_string()),
                "activation error must identify its endpoint: {error}",
            );
            activation
                .activate()
                .expect_err("failed activation must not become success on a later call");
            let _tcp_rebound = TcpListener::bind(tcp_address)
                .expect("failed activation must release the TCP reservation");
            let _udp_rebound = UdpSocket::bind(udp_address)
                .expect("failed activation must release the UDP reservation");
        }
    });
}
