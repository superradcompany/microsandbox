//! Published ports through the real network engine and virtio-net frame boundary.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use msb_krun::backends::net::{NetBackend, ReadError};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{HostRoutes, SmoltcpNetwork};
use crate::config::{EnvNetworkSecretResolver, NetworkConfig, PortProtocol, PublishedPort};
use crate::policy::NetworkPolicy;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct GuestDevice(Box<dyn NetBackend + Send>);

struct GuestRx(Vec<u8>);

struct GuestTx<'a>(&'a mut GuestDevice);

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Device for GuestDevice {
    type RxToken<'a> = GuestRx;
    type TxToken<'a> = GuestTx<'a>;

    fn receive(&mut self, _: Instant) -> Option<(GuestRx, GuestTx<'_>)> {
        let mut frame = vec![0; 2048];
        match self.0.read_frame(&mut frame) {
            Ok(len) => Some((GuestRx(frame[12..len].to_vec()), GuestTx(self))),
            Err(ReadError::NothingRead) => None,
            Err(error) => panic!("reading guest frame: {error:?}"),
        }
    }

    fn transmit(&mut self, _: Instant) -> Option<GuestTx<'_>> {
        Some(GuestTx(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = 1514;
        capabilities
    }
}

impl RxToken for GuestRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for GuestTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0; 12 + len];
        let result = f(&mut frame[12..]);
        self.0.0.write_frame(12, &mut frame).unwrap();
        result
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn published_ports_work_without_host_routes() {
    // The real poll thread has no shutdown API. Keep it and its listeners in a child process.
    const CHILD_ENV: &str = "MSB_TEST_PUBLISHED_PORTS_WITHOUT_ROUTES";
    if std::env::var_os(CHILD_ENV).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "engine::network::published_ports_tests::published_ports_work_without_host_routes",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "published-port child failed:\n{}\n{}",
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
        for protocol in [PortProtocol::Tcp, PortProtocol::Udp] {
            for bind in [
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ] {
                tokio::time::timeout(Duration::from_secs(5), check_published_port(protocol, bind))
                    .await
                    .unwrap_or_else(|_| panic!("published {protocol:?} on {bind} timed out"));
            }
        }
    });
}

async fn check_published_port(protocol: PortProtocol, bind: IpAddr) {
    let host_address = match protocol {
        PortProtocol::Tcp => {
            std::net::TcpListener::bind((bind, 0)).and_then(|listener| listener.local_addr())
        }
        PortProtocol::Udp => {
            std::net::UdpSocket::bind((bind, 0)).and_then(|socket| socket.local_addr())
        }
    };
    let host_port = match host_address {
        Ok(address) => address.port(),
        Err(error) if bind.is_ipv6() && ipv6_loopback_unavailable(&error) => {
            eprintln!("skipping published {protocol:?} on {bind}: host cannot bind IPv6: {error}");
            return;
        }
        Err(error) => panic!("binding published {protocol:?} on {bind}: {error}"),
    };
    let mut config = NetworkConfig::default();
    config.tls.enabled = false;
    config.policy = NetworkPolicy::allow_all();
    config.ports.push(PublishedPort {
        host_port,
        guest_port: 8000,
        protocol,
        host_bind: bind,
    });
    let mut network = SmoltcpNetwork::build(
        config.resolve(&EnvNetworkSecretResolver).unwrap(),
        7,
        microsandbox_types::DeploymentProfile::SingleTenant,
        HostRoutes {
            ipv4: false,
            ipv6: false,
        },
    )
    .unwrap();
    let bootstrap = network.guest_bootstrap_network();
    assert!(
        bootstrap.ipv4.is_some() || bootstrap.ipv6.is_some(),
        "published port needs a guest address without host routes"
    );
    let mut device = GuestDevice(network.take_backend());
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ethernet(EthernetAddress(bootstrap.mac))),
        &mut device,
        Instant::from_millis(0),
    );
    iface.update_ip_addrs(|ips| {
        if let Some(ipv4) = &bootstrap.ipv4 {
            ips.push(IpCidr::new(ipv4.address.into(), ipv4.prefix_len))
                .unwrap();
        }
        if let Some(ipv6) = &bootstrap.ipv6 {
            ips.push(IpCidr::new(ipv6.address.into(), ipv6.prefix_len))
                .unwrap();
        }
    });
    let mut sockets = SocketSet::new(vec![]);
    let socket = match protocol {
        PortProtocol::Tcp => {
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 1024]),
                tcp::SocketBuffer::new(vec![0; 1024]),
            );
            let address = bootstrap
                .ipv4
                .map(|ip| IpAddress::from(ip.address))
                .or_else(|| bootstrap.ipv6.map(|ip| IpAddress::from(ip.address)))
                .unwrap();
            socket.listen((address, 8000)).unwrap();
            sockets.add(socket)
        }
        PortProtocol::Udp => {
            let mut socket = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 1024]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 1024]),
            );
            socket.bind(8000).unwrap();
            sockets.add(socket)
        }
    };
    network.start(tokio::runtime::Handle::current());
    let client = tokio::spawn(async move {
        let client_ip = if bind.is_unspecified() {
            Ipv4Addr::LOCALHOST.into()
        } else {
            bind
        };
        let address = SocketAddr::new(client_ip, host_port);
        let mut response = [0; 4];
        match protocol {
            PortProtocol::Tcp => {
                let mut stream = loop {
                    match tokio::net::TcpStream::connect(address).await {
                        Ok(stream) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                        Err(error) => panic!("connecting published port: {error}"),
                    }
                };
                stream.write_all(b"ping").await.unwrap();
                stream.read_exact(&mut response).await.unwrap();
            }
            PortProtocol::Udp => {
                let socket = tokio::net::UdpSocket::bind((client_ip, 0)).await.unwrap();
                loop {
                    socket.send_to(b"ping", address).await.unwrap();
                    if let Ok(result) = tokio::time::timeout(
                        Duration::from_millis(20),
                        socket.recv_from(&mut response),
                    )
                    .await
                    {
                        let (len, peer) = result.unwrap();
                        assert_eq!(len, 4);
                        assert_eq!(peer, address);
                        break;
                    }
                }
            }
        }
        assert_eq!(&response, b"pong");
    });
    let started = std::time::Instant::now();
    let mut request = Vec::new();
    while !client.is_finished() {
        iface.poll(
            Instant::from_millis(started.elapsed().as_millis() as i64),
            &mut device,
            &mut sockets,
        );
        match protocol {
            PortProtocol::Tcp => {
                let socket = sockets.get_mut::<tcp::Socket>(socket);
                if socket.can_recv() {
                    socket
                        .recv(|bytes| {
                            request.extend_from_slice(bytes);
                            (bytes.len(), ())
                        })
                        .unwrap();
                    if request.len() == 4 {
                        assert_eq!(request, b"ping");
                        assert_eq!(socket.send_slice(b"pong").unwrap(), 4);
                    }
                }
            }
            PortProtocol::Udp => {
                let socket = sockets.get_mut::<udp::Socket>(socket);
                if socket.can_recv() {
                    let (bytes, peer) = socket.recv().unwrap();
                    assert_eq!(bytes, b"ping");
                    socket.send_slice(b"pong", peer.endpoint).unwrap();
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    client.await.unwrap();
}

fn ipv6_loopback_unavailable(error: &std::io::Error) -> bool {
    match error.raw_os_error() {
        #[cfg(unix)]
        Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT) => true,
        // Winsock WSAEPROTONOSUPPORT / WSAEAFNOSUPPORT. Keep this test-only check
        // independent of the optional windows-sys WinSock feature.
        #[cfg(windows)]
        Some(10043 | 10047) => true,
        _ => error.kind() == std::io::ErrorKind::AddrNotAvailable,
    }
}
