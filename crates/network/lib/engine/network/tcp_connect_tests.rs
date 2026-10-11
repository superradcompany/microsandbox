//! Guest TCP success must reflect the host-side connection outcome.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use super::test_support::{GuestDevice, ipv6_loopback_unavailable};
use super::{HostRoutes, SmoltcpNetwork};
use crate::config::{EnvNetworkSecretResolver, NetworkConfig};
use crate::policy::NetworkPolicy;
use crate::proxy::OutboundProxy;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn guest_tcp_connect_reflects_upstream_outcome() {
    const CHILD_ENV: &str = "MSB_TEST_TCP_CONNECT_OUTCOME";
    if std::env::var_os(CHILD_ENV).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "engine::network::tcp_connect_tests::guest_tcp_connect_reflects_upstream_outcome",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), check_stalled_ipv6_fallback())
            .await
            .expect("stalled IPv6 fallback or cancellation timed out");
        for ipv6 in [false, true] {
            for listening in [false, true] {
                tokio::time::timeout(Duration::from_secs(5), check_connect(ipv6, listening))
                    .await
                    .unwrap_or_else(|_| {
                        panic!("TCP outcome timed out: ipv6={ipv6}, listening={listening}")
                    });
            }
        }
    });
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn check_connect(ipv6: bool, listening: bool) {
    // Pick a port available in both host families so loopback fallback cannot
    // accidentally reach a listener from the other case.
    let v4 = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
    v4.bind(&SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0).into())
        .unwrap();
    let port = v4.local_addr().unwrap().as_socket().unwrap().port();
    let v6 = (|| -> std::io::Result<Socket> {
        let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_only_v6(true)?;
        socket.bind(&SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port).into())?;
        Ok(socket)
    })();
    let v6 = match v6 {
        Ok(socket) => Some(socket),
        Err(error) if ipv6_loopback_unavailable(&error) => None,
        Err(error) => panic!("reserving IPv6 loopback port: {error}"),
    };
    if ipv6 && v6.is_none() {
        eprintln!("IPv6 loopback unavailable; IPv4 connect outcomes still checked");
        return;
    }
    let server = if listening {
        let socket = if ipv6 { v6.as_ref().unwrap() } else { &v4 };
        socket.listen(4).unwrap();
        socket.set_nonblocking(true).unwrap();
        let listener =
            tokio::net::TcpListener::from_std(socket.try_clone().unwrap().into()).unwrap();
        Some(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"ready").await.unwrap();
            let mut response = [0; 4];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"done");
            // The successful host connection must be reused, not dialed again.
            assert!(
                tokio::time::timeout(Duration::from_millis(30), listener.accept())
                    .await
                    .is_err()
            );
        }))
    } else {
        None
    };

    // Reserve the ports even when not listening. Depending on the host, a
    // connection to a bound, non-listening socket is reset or stays pending.
    let _listeners = (v4, v6);

    let config = NetworkConfig {
        policy: NetworkPolicy::allow_all(),
        ..Default::default()
    };
    let mut network = SmoltcpNetwork::build(
        config.resolve(&EnvNetworkSecretResolver).unwrap(),
        2,
        Default::default(),
        HostRoutes {
            ipv4: true,
            ipv6: true,
        },
    )
    .unwrap();
    let bootstrap = network.guest_bootstrap_network();
    let (guest, gateway): (IpAddress, IpAddress) = if ipv6 {
        let ip = bootstrap.ipv6.unwrap();
        (ip.address.into(), ip.gateway.into())
    } else {
        let ip = bootstrap.ipv4.unwrap();
        (ip.address.into(), ip.gateway.into())
    };
    let mut device = GuestDevice(network.take_backend());
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ethernet(EthernetAddress(
            network.guest_mac(),
        ))),
        &mut device,
        Instant::from_millis(0),
    );
    iface.update_ip_addrs(|ips| {
        ips.push(IpCidr::new(guest, if ipv6 { 64 } else { 30 }))
            .unwrap();
    });
    let mut sockets = SocketSet::new(vec![]);
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 1024]),
        tcp::SocketBuffer::new(vec![0; 1024]),
    );
    socket
        .connect(iface.context(), (gateway, port), (guest, 49152))
        .unwrap();
    let handle = sockets.add(socket);
    network.start(tokio::runtime::Handle::current());
    let started = std::time::Instant::now();
    let mut received = Vec::new();
    let mut replied = false;
    loop {
        // One ingress packet at a time makes a transient ESTABLISHED state
        // observable even when a later reset is already queued.
        let now = Instant::from_millis(started.elapsed().as_millis() as i64);
        iface.poll_ingress_single(now, &mut device, &mut sockets);
        iface.poll_egress(now, &mut device, &mut sockets);
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        if !listening {
            assert!(
                !socket.may_send(),
                "guest connected before upstream: ipv6={ipv6}, state={:?}",
                socket.state()
            );
            if socket.state() == tcp::State::Closed
                || started.elapsed() >= Duration::from_millis(250)
            {
                break;
            }
        } else {
            if socket.can_recv() {
                socket
                    .recv(|bytes| {
                        received.extend_from_slice(bytes);
                        (bytes.len(), ())
                    })
                    .unwrap();
            }
            if received.len() >= 5 && !replied {
                assert_eq!(received, b"ready");
                socket.send_slice(b"done").unwrap();
                replied = true;
            }
            if replied && server.as_ref().unwrap().is_finished() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    if let Some(server) = server {
        server.await.unwrap();
    }
}

async fn check_stalled_ipv6_fallback() {
    // Withhold the IPv6 CONNECT response to keep the real host dial pending
    // without depending on external routes, firewall rules, or host IPv6 support.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let config = NetworkConfig {
        policy: NetworkPolicy::allow_all(),
        outbound_proxy: Some(OutboundProxy::HttpConnect {
            address: listener.local_addr().unwrap(),
        }),
        ..Default::default()
    };
    let (pending_tx, mut pending_rx) = oneshot::channel();
    let (fallback_tx, mut fallback_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stalled, _) = listener.accept().await.unwrap();
        assert_eq!(
            read_connect_request(&mut stalled).await,
            "[2001:db8::122]:8080"
        );
        pending_tx.send(()).unwrap();

        tokio::select! {
            result = stalled.read_u8() => {
                panic!("IPv6 dial ended before guest cancellation: {result:?}");
            }
            _ = async {
                let (mut ready, _) = listener.accept().await.unwrap();
                assert_eq!(read_connect_request(&mut ready).await, "192.0.2.122:8080");
                ready.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nready").await.unwrap();
                let mut response = [0; 4];
                ready.read_exact(&mut response).await.unwrap();
                assert_eq!(&response, b"done");
            } => {}
        }
        fallback_tx.send(()).unwrap();
        assert_eq!(
            stalled.read(&mut [0; 1]).await.unwrap(),
            0,
            "guest reset must cancel the pending host dial"
        );
    });

    let mut network = SmoltcpNetwork::build(
        config.resolve(&EnvNetworkSecretResolver).unwrap(),
        2,
        Default::default(),
        HostRoutes {
            ipv4: true,
            ipv6: true,
        },
    )
    .unwrap();
    let bootstrap = network.guest_bootstrap_network();
    let v4 = bootstrap.ipv4.unwrap();
    let v6 = bootstrap.ipv6.unwrap();
    let mut device = GuestDevice(network.take_backend());
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ethernet(EthernetAddress(
            network.guest_mac(),
        ))),
        &mut device,
        Instant::from_millis(0),
    );
    iface.update_ip_addrs(|ips| {
        ips.push(IpCidr::new(v4.address.into(), 30)).unwrap();
        ips.push(IpCidr::new(v6.address.into(), 64)).unwrap();
    });
    iface
        .routes_mut()
        .add_default_ipv4_route(v4.gateway)
        .unwrap();
    iface
        .routes_mut()
        .add_default_ipv6_route(v6.gateway)
        .unwrap();
    let mut sockets = SocketSet::new(vec![]);
    let v6_handle = sockets.add(tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 1024]),
        tcp::SocketBuffer::new(vec![0; 1024]),
    ));
    let v4_handle = sockets.add(tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 1024]),
        tcp::SocketBuffer::new(vec![0; 1024]),
    ));
    sockets
        .get_mut::<tcp::Socket>(v6_handle)
        .connect(
            iface.context(),
            ("2001:db8::122".parse::<Ipv6Addr>().unwrap(), 8080),
            (v6.address, 49152),
        )
        .unwrap();
    network.start(tokio::runtime::Handle::current());
    let started = std::time::Instant::now();
    let mut fallback_started = false;
    let mut cancelled = false;
    let mut received = Vec::new();
    let mut replied = false;
    loop {
        let now = Instant::from_millis(started.elapsed().as_millis() as i64);
        iface.poll_ingress_single(now, &mut device, &mut sockets);
        iface.poll_egress(now, &mut device, &mut sockets);
        if !cancelled {
            assert_eq!(
                sockets.get::<tcp::Socket>(v6_handle).state(),
                tcp::State::SynSent,
                "stalled IPv6 must not complete the guest handshake"
            );
        }
        if !fallback_started && pending_rx.try_recv().is_ok() {
            sockets
                .get_mut::<tcp::Socket>(v4_handle)
                .connect(
                    iface.context(),
                    (Ipv4Addr::new(192, 0, 2, 122), 8080),
                    (v4.address, 49153),
                )
                .unwrap();
            fallback_started = true;
        }
        let socket = sockets.get_mut::<tcp::Socket>(v4_handle);
        if socket.can_recv() {
            socket
                .recv(|bytes| {
                    received.extend_from_slice(bytes);
                    (bytes.len(), ())
                })
                .unwrap();
        }
        if received.len() >= 5 && !replied {
            assert_eq!(received, b"ready");
            socket.send_slice(b"done").unwrap();
            replied = true;
        }
        if !cancelled && fallback_rx.try_recv().is_ok() {
            sockets.get_mut::<tcp::Socket>(v6_handle).abort();
            cancelled = true;
        }
        if server.is_finished() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    server.await.unwrap();
    assert!(fallback_started && replied && cancelled);
}

async fn read_connect_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        assert!(request.len() < 1024, "oversized CONNECT request");
        request.push(stream.read_u8().await.unwrap());
    }
    let request = std::str::from_utf8(&request).unwrap();
    let mut words = request.split_whitespace();
    assert_eq!(words.next(), Some("CONNECT"));
    words.next().unwrap().to_owned()
}
