//! A running sandbox's network policy, changed live through the real network engine.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use hickory_net::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_net::proto::rr::{DNSClass, Name, RecordType};
use hickory_net::proto::serialize::binary::{BinDecodable, BinEncodable};
use msb_krun::backends::net::{NetBackend, ReadError};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};
use tokio::io::AsyncWriteExt;

use super::{HostRoutes, SmoltcpNetwork};
use crate::config::{EnvNetworkSecretResolver, NetworkConfig};
use crate::engine::tls::sni::tests::build_client_hello;
use crate::netstack::shared::ResolvedHostnameFamily;
use crate::policy::NetworkPolicy;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct GuestDevice(Box<dyn NetBackend + Send>);

struct GuestRx(Vec<u8>);

struct GuestTx<'a>(&'a mut GuestDevice);

/// The guest side of a sandbox's network: its own TCP/IP stack on the virtio-net backend.
struct Guest {
    device: GuestDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    gateway: Ipv4Addr,
    started: std::time::Instant,
    next_port: u16,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Guest {
    fn attach(network: &mut SmoltcpNetwork) -> Self {
        let bootstrap = network.guest_bootstrap_network();
        let ipv4 = bootstrap.ipv4.expect("an IPv4 guest address");
        let mut device = GuestDevice(network.take_backend());
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ethernet(EthernetAddress(bootstrap.mac))),
            &mut device,
            Instant::from_millis(0),
        );
        iface.update_ip_addrs(|ips| {
            ips.push(IpCidr::new(ipv4.address.into(), ipv4.prefix_len))
                .unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(ipv4.gateway)
            .unwrap();
        Self {
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            gateway: ipv4.gateway,
            started: std::time::Instant::now(),
            next_port: 49152,
        }
    }

    /// Whether a new TCP connection from the guest to the host's `port` is established.
    async fn connects_to_host(&mut self, port: u16) -> bool {
        self.open_to_host(port).await.is_some()
    }

    /// A new TCP connection from the guest to the host's `port`, once established.
    async fn open_to_host(&mut self, port: u16) -> Option<SocketHandle> {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 1024]),
            tcp::SocketBuffer::new(vec![0; 1024]),
        );
        socket
            .connect(
                self.iface.context(),
                (IpAddress::from(self.gateway), port),
                self.next_port,
            )
            .unwrap();
        self.next_port += 1;
        let handle = self.sockets.add(socket);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let now = Instant::from_millis(self.started.elapsed().as_millis() as i64);
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            match self.sockets.get::<tcp::Socket>(handle).state() {
                tcp::State::Established => return Some(handle),
                tcp::State::Closed | tcp::State::TimeWait => return None,
                _ if tokio::time::Instant::now() >= deadline => return None,
                _ => tokio::time::sleep(Duration::from_millis(1)).await,
            }
        }
    }

    /// The response code the network's resolver gives this guest for an A query on `name`.
    async fn dns_rcode(&mut self, name: &str) -> Option<ResponseCode> {
        let mut query = Message::new(0x5151, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        let mut question = Query::new();
        question.set_name(Name::from_ascii(name).unwrap());
        question.set_query_type(RecordType::A);
        question.set_query_class(DNSClass::IN);
        query.add_query(question);
        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 4096]),
        );
        socket.bind(self.next_port).unwrap();
        self.next_port += 1;
        socket
            .send_slice(
                &query.to_bytes().unwrap(),
                (IpAddress::from(self.gateway), 53),
            )
            .unwrap();
        let handle = self.sockets.add(socket);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            let now = Instant::from_millis(self.started.elapsed().as_millis() as i64);
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            if socket.can_recv() {
                let (bytes, _) = socket.recv().unwrap();
                return Some(Message::from_bytes(bytes).unwrap().metadata.response_code);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        None
    }

    /// Write `data` on an established connection and poll until it has left the guest.
    async fn send(&mut self, handle: SocketHandle, data: &[u8]) {
        self.sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(data)
            .unwrap();
        for _ in 0..500 {
            let now = Instant::from_millis(self.started.elapsed().as_millis() as i64);
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            if self.sockets.get::<tcp::Socket>(handle).send_queue() == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("the guest could not send its data");
    }

    fn state(&mut self, handle: SocketHandle) -> tcp::State {
        let now = Instant::from_millis(self.started.elapsed().as_millis() as i64);
        self.iface.poll(now, &mut self.device, &mut self.sockets);
        self.sockets.get::<tcp::Socket>(handle).state()
    }

    /// Whether the network ends this established connection within a few seconds.
    async fn ends(&mut self, handle: SocketHandle) -> bool {
        self.ended(&[handle]).await[0]
    }

    /// For each of these established connections, whether the network ends it within a few
    /// seconds.
    async fn ended(&mut self, handles: &[SocketHandle]) -> Vec<bool> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let now = Instant::from_millis(self.started.elapsed().as_millis() as i64);
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            let ended: Vec<bool> = handles
                .iter()
                .map(|&handle| {
                    self.sockets.get::<tcp::Socket>(handle).state() != tcp::State::Established
                })
                .collect();
            if ended.iter().all(|&ended| ended) || tokio::time::Instant::now() >= deadline {
                return ended;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}

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
// Functions
//--------------------------------------------------------------------------------------------------

/// A host service the guest can dial through its gateway; it accepts every connection.
async fn host_service() -> u16 {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = stream.write_all(b"ok").await;
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });
    port
}

fn running_network(policy: NetworkPolicy) -> SmoltcpNetwork {
    let mut config = NetworkConfig::default();
    config.tls.enabled = false;
    config.policy = policy;
    SmoltcpNetwork::build(
        config.resolve(&EnvNetworkSecretResolver).unwrap(),
        7,
        microsandbox_types::DeploymentProfile::SingleTenant,
        HostRoutes {
            ipv4: true,
            ipv6: false,
        },
    )
    .unwrap()
}

/// Opens one connection under `allow_all()` for each server name in `presented`, which it
/// sends in a ClientHello, then replaces the policy with `narrowed`. Only `example.com`
/// resolves to the address the guest dials, so every other name is judged by the server name
/// the connection recorded and never by the DNS cache. Returns the names whose connection the
/// new policy ended.
async fn ended_by_narrowing(presented: &[&str], narrowed: NetworkPolicy) -> Vec<String> {
    let port = host_service().await;
    let mut network = running_network(NetworkPolicy::allow_all());
    let policy = network.policy_handle();
    let mut guest = Guest::attach(&mut network);
    network.shared.cache_resolved_hostname(
        "example.com",
        ResolvedHostnameFamily::Ipv4,
        [IpAddr::V4(guest.gateway)],
        Duration::from_secs(60),
    );
    network.start(tokio::runtime::Handle::current());

    let mut opened = Vec::new();
    for name in presented {
        let handle = guest
            .open_to_host(port)
            .await
            .expect("the open policy refused it");
        guest.send(handle, &build_client_hello(name)).await;
        opened.push(handle);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    policy.set(narrowed);

    let ended = guest.ended(&opened).await;

    presented
        .iter()
        .zip(ended)
        .filter(|(_, ended)| *ended)
        .map(|(name, _)| name.to_string())
        .collect()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_policy_set_on_a_running_network_decides_its_next_connection() {
    let port = host_service().await;
    let mut network = running_network(NetworkPolicy::allow_all());
    let policy = network.policy_handle();
    let mut guest = Guest::attach(&mut network);
    network.start(tokio::runtime::Handle::current());

    assert!(
        guest.connects_to_host(port).await,
        "the open policy refused the first connection"
    );
    policy.set(NetworkPolicy::none());
    assert!(
        !guest.connects_to_host(port).await,
        "a connection opened after the policy was closed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closing_the_policy_ends_a_connection_it_now_denies() {
    let port = host_service().await;
    let mut network = running_network(NetworkPolicy::allow_all());
    let policy = network.policy_handle();
    let mut guest = Guest::attach(&mut network);
    network.start(tokio::runtime::Handle::current());

    let open = guest
        .open_to_host(port)
        .await
        .expect("the open policy refused it");
    policy.set(NetworkPolicy::none());
    assert!(
        guest.ends(open).await,
        "a connection the new policy denies stayed open"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn narrowing_leaves_open_a_connection_the_new_policy_still_allows() {
    let (kept_port, ended_port) = (host_service().await, host_service().await);
    let mut network = running_network(NetworkPolicy::allow_all());
    let policy = network.policy_handle();
    let mut guest = Guest::attach(&mut network);
    network.start(tokio::runtime::Handle::current());

    let kept = guest.open_to_host(kept_port).await.expect("refused");
    let ended = guest.open_to_host(ended_port).await.expect("refused");
    policy.set(
        NetworkPolicy::builder()
            .default_deny()
            .egress(|e| e.tcp().port(kept_port).allow_host())
            .build()
            .unwrap(),
    );
    assert!(guest.ends(ended).await, "the denied connection stayed open");
    assert_eq!(
        guest.state(kept),
        tcp::State::Established,
        "narrowing ended a connection the new policy still allows"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dns_query_after_the_policy_closes_is_refused() {
    let mut network = running_network(NetworkPolicy::allow_all());
    let policy = network.policy_handle();
    let mut guest = Guest::attach(&mut network);
    network.start(tokio::runtime::Handle::current());

    assert_eq!(
        guest.dns_rcode(crate::HOST_ALIAS).await,
        Some(ResponseCode::NoError),
        "the open policy did not answer the host alias"
    );
    policy.set(NetworkPolicy::none());
    assert_eq!(
        guest.dns_rcode(crate::HOST_ALIAS).await,
        Some(ResponseCode::NXDomain),
        "a query after the policy closed was answered"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hostname_denied_after_a_tls_connection_opened_ends_it() {
    let presented = ["blocked.test", "BLOCKED.test", "blocked.test."];

    let ended = ended_by_narrowing(
        &presented,
        NetworkPolicy::builder()
            .default_allow()
            .egress(|e| e.deny_domains(["blocked.test"]))
            .build()
            .unwrap(),
    )
    .await;

    assert_eq!(
        ended, presented,
        "a connection to a host the new policy denies by name stayed open"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn narrowing_keeps_a_tls_connection_whose_hostname_the_new_policy_allows() {
    let presented = ["example.com", "EXAMPLE.com", "example.com.", "blocked.test"];

    let ended = ended_by_narrowing(
        &presented,
        NetworkPolicy::builder()
            .default_deny()
            .egress(|e| e.allow_domains(["example.com"]))
            .build()
            .unwrap(),
    )
    .await;

    assert_eq!(
        ended,
        ["blocked.test"],
        "narrowing to allow only example.com ended the wrong connections"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hostname_denied_after_a_split_client_hello_ends_its_connection() {
    let port = host_service().await;
    let mut network = running_network(NetworkPolicy::allow_all());
    let policy = network.policy_handle();
    let mut guest = Guest::attach(&mut network);
    network.start(tokio::runtime::Handle::current());

    let open = guest
        .open_to_host(port)
        .await
        .expect("the open policy refused it");
    let hello = build_client_hello("blocked.test");
    guest.send(open, &hello[..10]).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    guest.send(open, &hello[10..]).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        guest.state(open),
        tcp::State::Established,
        "the connection ended before the policy changed"
    );
    policy.set(
        NetworkPolicy::builder()
            .default_allow()
            .egress(|e| e.deny_domains(["blocked.test"]))
            .build()
            .unwrap(),
    );

    assert!(
        guest.ends(open).await,
        "a connection whose ClientHello arrived in two segments stayed open after its name \
         was denied"
    );
}
