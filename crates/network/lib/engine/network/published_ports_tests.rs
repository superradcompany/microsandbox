//! Published ports through the real network engine and virtio-net frame boundary.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::test_support::{GuestDevice, ipv6_loopback_unavailable};
use super::{HostRoutes, SmoltcpNetwork};
use crate::config::{EnvNetworkSecretResolver, NetworkConfig, PortProtocol, PublishedPort};
use crate::policy::NetworkPolicy;

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

#[test]
fn deferred_tcp_publication_discards_stale_connections() {
    check_deferred_published_port(PortProtocol::Tcp, false);
}

#[test]
fn deferred_udp_publication_discards_stale_datagrams() {
    check_deferred_published_port(PortProtocol::Udp, false);
}

#[test]
fn deferred_busy_tcp_publication_forwards_fresh_connections() {
    check_deferred_published_port(PortProtocol::Tcp, true);
}

#[test]
fn deferred_busy_udp_publication_forwards_fresh_datagrams() {
    check_deferred_published_port(PortProtocol::Udp, true);
}

fn check_deferred_published_port(protocol: PortProtocol, busy: bool) {
    // The poll thread and its listeners live until process exit.
    const CHILD_ENV: &str = "MSB_TEST_DEFERRED_PUBLICATION";
    if std::env::var_os(CHILD_ENV).is_none() {
        let test = match (protocol, busy) {
            (PortProtocol::Tcp, false) => "deferred_tcp_publication_discards_stale_connections",
            (PortProtocol::Udp, false) => "deferred_udp_publication_discards_stale_datagrams",
            (PortProtocol::Tcp, true) => "deferred_busy_tcp_publication_forwards_fresh_connections",
            (PortProtocol::Udp, true) => "deferred_busy_udp_publication_forwards_fresh_datagrams",
        };
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("engine::network::published_ports_tests::{test}"),
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "deferred {protocol:?} publication child failed:\n{}\n{}",
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
        tokio::time::timeout(
            Duration::from_secs(5),
            check_published_port_with_activation(protocol, Ipv4Addr::LOCALHOST.into(), true, busy),
        )
        .await
        .unwrap_or_else(|_| panic!("deferred published {protocol:?} (busy={busy}) timed out"));
    });
}

async fn check_published_port(protocol: PortProtocol, bind: IpAddr) {
    check_published_port_with_activation(protocol, bind, false, false).await;
}

async fn check_published_port_with_activation(
    protocol: PortProtocol,
    bind: IpAddr,
    deferred: bool,
    busy: bool,
) {
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
    let client_ip = if bind.is_unspecified() {
        Ipv4Addr::LOCALHOST.into()
    } else {
        bind
    };
    let address = SocketAddr::new(client_ip, host_port);
    let activation = deferred.then(|| network.defer_activation());
    network.start(tokio::runtime::Handle::current()).unwrap();
    let (busy_done_tx, busy_done_rx) = tokio::sync::oneshot::channel();
    let busy_client = if let Some(activation) = activation {
        let conflict = match protocol {
            PortProtocol::Tcp => std::net::TcpListener::bind(address).map(|_| ()),
            PortProtocol::Udp => std::net::UdpSocket::bind(address).map(|_| ()),
        }
        .expect_err("deferred publication must reserve its host endpoint");
        assert_eq!(conflict.kind(), std::io::ErrorKind::AddrInUse);

        // Queue stale traffic in the reserved kernel socket without polling this
        // runtime's reactor; activation must reset that queue before opening the gate.
        let mut stale_tcp = None;
        match protocol {
            PortProtocol::Tcp => {
                for attempt in 0..96 {
                    let mut stale = match std::net::TcpStream::connect_timeout(
                        &address,
                        Duration::from_millis(50),
                    ) {
                        Ok(stream) => stream,
                        Err(error)
                            if attempt > 0
                                && matches!(
                                    error.kind(),
                                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                                ) =>
                        {
                            // Hosts may clamp the listen backlog below the requested size.
                            break;
                        }
                        Err(error) => panic!("queue stale TCP connection: {error}"),
                    };
                    stale
                        .set_write_timeout(Some(Duration::from_millis(50)))
                        .unwrap();
                    stale.write_all(b"stale-tcp-before-activation").unwrap();
                    if attempt == 0 {
                        // Keep one caller open to check that activation closes
                        // the old listener before it returns.
                        stale_tcp = Some(stale);
                    } else {
                        // Model callers that gave up while restore was deferred.
                        drop(stale);
                    }
                }
            }
            PortProtocol::Udp => {
                let stale = std::net::UdpSocket::bind((client_ip, 0)).unwrap();
                for _ in 0..96 {
                    stale
                        .send_to(b"stale-udp-before-activation", address)
                        .unwrap();
                }
            }
        }
        let mut frame = [0; 2048];
        let deferred_started = std::time::Instant::now();
        while deferred_started.elapsed() < Duration::from_millis(25) {
            assert!(
                matches!(
                    device.0.read_frame(&mut frame),
                    Err(msb_krun::backends::net::ReadError::NothingRead),
                ),
                "published traffic reached the guest before activation",
            );
            // Let the independent poll thread run, but not this runtime's reactor.
            std::thread::sleep(Duration::from_millis(1));
        }
        // Run the producer on an OS thread so it keeps sending while this
        // current-thread Tokio runtime is blocked in activate().
        let busy_client = busy.then(|| {
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let client = std::thread::spawn(move || {
                check_busy_published_client(protocol, address, started_tx);
                let _ = busy_done_tx.send(());
            });
            started_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("busy producer did not start before activation");
            client
        });
        activation
            .activate()
            .expect("reset reserved published sockets before activation");
        if let Some(mut stale) = stale_tcp {
            stale.set_nonblocking(true).unwrap();
            let mut response = [0; 1];
            let deadline = std::time::Instant::now() + Duration::from_millis(100);
            let closed = loop {
                match stale.read(&mut response) {
                    Ok(0) => break true,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        break true;
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        // Do not poll Tokio here: the old listener must have
                        // closed before activation returns.
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    _ => break false,
                }
            };
            assert!(
                closed,
                "activation returned before closing the old TCP listener"
            );
        }
        busy_client
    } else {
        None
    };
    // Start fresh traffic immediately after activation resets the reserved kernel queues.
    let client = tokio::spawn(async move {
        if busy {
            busy_done_rx
                .await
                .expect("busy producer stopped without a guest response");
            return;
        }
        let mut response = [0; 4];
        match protocol {
            PortProtocol::Tcp => loop {
                let attempt = async {
                    let mut stream = tokio::net::TcpStream::connect(address).await?;
                    stream.write_all(b"ping").await?;
                    stream.read_exact(&mut response).await?;
                    Ok::<(), std::io::Error>(())
                }
                .await;
                match attempt {
                    Ok(()) => break,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::ConnectionRefused
                            || deferred
                                && matches!(
                                    error.kind(),
                                    std::io::ErrorKind::ConnectionReset
                                        | std::io::ErrorKind::ConnectionAborted
                                        | std::io::ErrorKind::BrokenPipe
                                        | std::io::ErrorKind::UnexpectedEof
                                ) =>
                    {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    Err(error) => panic!("using published TCP port: {error}"),
                }
            },
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
    let mut tail_started = None;
    let mut received_while_busy = false;
    loop {
        if client.is_finished() {
            if !deferred {
                break;
            }
            let tail_started = tail_started.get_or_insert_with(std::time::Instant::now);
            if tail_started.elapsed() >= Duration::from_millis(100) {
                break;
            }
        }
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
                    assert!(
                        b"ping".starts_with(&request),
                        "guest received stale or unexpected TCP payload: {request:?}",
                    );
                    if request.len() == 4 {
                        assert_eq!(request, b"ping");
                        received_while_busy |= busy && !client.is_finished();
                        assert_eq!(socket.send_slice(b"pong").unwrap(), 4);
                    }
                }
                if deferred {
                    if socket.state() == tcp::State::CloseWait {
                        socket.close();
                    }
                    if !socket.is_open() {
                        request.clear();
                        socket.listen(8000).unwrap();
                    }
                }
            }
            PortProtocol::Udp => {
                let socket = sockets.get_mut::<udp::Socket>(socket);
                if socket.can_recv() {
                    let (bytes, peer) = socket.recv().unwrap();
                    assert_eq!(
                        bytes, b"ping",
                        "guest received stale or unexpected UDP payload",
                    );
                    received_while_busy |= busy && !client.is_finished();
                    socket.send_slice(b"pong", peer.endpoint).unwrap();
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    client.await.unwrap();
    if let Some(busy_client) = busy_client {
        busy_client.join().unwrap();
    }
    assert!(
        !busy || received_while_busy,
        "guest must receive a fresh request while the producer is still running",
    );
}

fn check_busy_published_client(
    protocol: PortProtocol,
    address: SocketAddr,
    started: std::sync::mpsc::Sender<()>,
) {
    // Keep sending across activation until the guest answers. A Tokio task on
    // this test's current-thread runtime would not run during activate().
    match protocol {
        PortProtocol::Udp => {
            let socket = std::net::UdpSocket::bind((address.ip(), 0)).unwrap();
            socket.set_nonblocking(true).unwrap();
            let mut started = Some(started);
            loop {
                for _ in 0..128 {
                    assert_eq!(socket.send_to(b"ping", address).unwrap(), 4);
                }
                if let Some(started) = started.take() {
                    started.send(()).unwrap();
                }
                let mut response = [0; 32];
                match socket.recv_from(&mut response) {
                    Ok((len, peer)) => {
                        assert_eq!(peer, address);
                        assert_eq!(&response[..len], b"pong");
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("receiving busy published UDP response: {error}"),
                }
                std::thread::yield_now();
            }
        }
        PortProtocol::Tcp => {
            struct Pending {
                stream: std::net::TcpStream,
                response: [u8; 4],
                received: usize,
            }

            let mut pending = Vec::<Pending>::with_capacity(256);
            let mut started = Some(started);
            loop {
                let mut got_pong = false;
                pending.retain_mut(|request| {
                    match request
                        .stream
                        .read(&mut request.response[request.received..])
                    {
                        Ok(0) => false,
                        Ok(len) => {
                            request.received += len;
                            if request.received == request.response.len() {
                                assert_eq!(&request.response, b"pong");
                                got_pong = true;
                                false
                            } else {
                                true
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => true,
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::ConnectionAborted
                                    | std::io::ErrorKind::BrokenPipe
                            ) =>
                        {
                            false
                        }
                        Err(error) => panic!("receiving busy published TCP response: {error}"),
                    }
                });
                if got_pong {
                    return;
                }
                for _ in 0..128 {
                    // A full/clamped backlog ends this batch, not the producer.
                    // Both the batch length and every blocking operation are bounded.
                    let mut stream = match std::net::TcpStream::connect_timeout(
                        &address,
                        Duration::from_millis(2),
                    ) {
                        Ok(stream) => stream,
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::TimedOut
                                    | std::io::ErrorKind::WouldBlock
                                    | std::io::ErrorKind::ConnectionRefused
                                    | std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::ConnectionAborted
                            ) =>
                        {
                            break;
                        }
                        Err(error) => panic!("connecting busy published TCP request: {error}"),
                    };
                    stream
                        .set_write_timeout(Some(Duration::from_millis(2)))
                        .unwrap();
                    if let Err(error) = stream.write_all(b"ping") {
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::BrokenPipe
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::WouldBlock
                        ) {
                            continue;
                        }
                        panic!("sending busy published TCP request: {error}");
                    }
                    stream.set_nonblocking(true).unwrap();
                    if pending.len() < 256 {
                        pending.push(Pending {
                            stream,
                            response: [0; 4],
                            received: 0,
                        });
                    }
                    // At the cap, dropping this already-written stream still
                    // queues traffic while preserving earlier response candidates.
                }
                if let Some(started) = started.take() {
                    started.send(()).unwrap();
                }
                std::thread::yield_now();
            }
        }
    }
}
