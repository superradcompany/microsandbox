//! Wire-level regressions for host-network information exposed through gateway DNS.

use std::io;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;

use hickory_net::proto::rr::rdata::{AAAA, NS, PTR};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn record(owner: &str, data: RData) -> Record {
    Record::from_rdata(Name::from_ascii(owner).unwrap(), 60, data)
}

fn reply(query: &Message, answers: Vec<Record>) -> Message {
    let mut response = Message::response(query.metadata.id, OpCode::Query);
    response.queries = query.queries.clone();
    response.metadata.recursion_available = true;
    response.answers = answers;
    response
}

/// The fixture serves both transports on one port, so the same response exercises
/// UDP and the TCP path also used after guest DoT interception.
async fn resolver(
    answer: impl Fn(&Message) -> Message + Send + Sync + 'static,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let (udp, tcp) = bind_resolver_sockets().await.unwrap();
    let address = udp.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let answer = Arc::new(answer);
    let udp_answer = answer.clone();
    let udp_hits = hits.clone();
    tokio::spawn(async move {
        let mut bytes = [0; 65535];
        while let Ok((len, peer)) = udp.recv_from(&mut bytes).await {
            let query = Message::from_bytes(&bytes[..len]).unwrap();
            udp_hits.fetch_add(1, Ordering::SeqCst);
            let response = udp_answer(&query).to_bytes().unwrap();
            udp.send_to(&response, peer).await.unwrap();
        }
    });
    let tcp_hits = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tcp.accept().await {
            let answer = answer.clone();
            let hits = tcp_hits.clone();
            tokio::spawn(async move {
                while let Ok(len) = stream.read_u16().await {
                    let mut bytes = vec![0; usize::from(len)];
                    if stream.read_exact(&mut bytes).await.is_err() {
                        break;
                    }
                    let query = Message::from_bytes(&bytes).unwrap();
                    hits.fetch_add(1, Ordering::SeqCst);
                    let response = answer(&query).to_bytes().unwrap();
                    if stream.write_u16(response.len() as u16).await.is_err()
                        || stream.write_all(&response).await.is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    (address, hits)
}

async fn bind_resolver_sockets() -> io::Result<(UdpSocket, TcpListener)> {
    // UDP and TCP allocate ports independently. Keep the UDP reservation while
    // trying TCP, and choose a fresh pair if that port is already used by TCP.
    for attempt in 0..16 {
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        match TcpListener::bind(udp.local_addr()?).await {
            Ok(tcp) => return Ok((udp, tcp)),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse && attempt < 15 => continue,
            Err(error) => return Err(error),
        }
    }
    unreachable!("the final bind attempt returns its error")
}

async fn protected_forwarder(upstream: SocketAddr) -> Arc<DnsForwarder> {
    let mut forwarder = forwarder_over(&[upstream]).await;
    let mutable = Arc::get_mut(&mut forwarder).unwrap();
    Arc::get_mut(&mut mutable.config).unwrap().rebind_protection = true;
    mutable.gateway.ipv6 = Some("fd42::1".parse().unwrap());
    let mut dot = crate::policy::Rule::allow_dns();
    dot.protocols = vec![crate::policy::Protocol::Tcp];
    dot.ports = vec![crate::policy::PortRange::single(853)];
    Arc::make_mut(&mut mutable.network_policy).rules.push(dot);
    mutable
        .shared
        .set_nat64_prefixes(vec!["64:ff9b::/96".parse().unwrap()]);
    forwarder
}

async fn query(
    forwarder: &DnsForwarder,
    name: &str,
    kind: RecordType,
    transport: Transport,
) -> Message {
    let mut request = make_query(name, kind);
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    request.edns = Some(edns);
    let response = forwarder
        .forward(&request.to_bytes().unwrap(), None, transport, None)
        .await
        .unwrap();
    Message::from_bytes(&response).unwrap()
}

fn public_answer(request: &Message) -> Message {
    reply(
        request,
        vec![Record::from_rdata(
            request.queries[0].name().clone(),
            60,
            RData::A(A::from(Ipv4Addr::new(8, 8, 8, 8))),
        )],
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn gateway_private_reverse_never_reaches_upstream() {
    let (upstream, hits) = resolver(|request| {
        reply(
            request,
            vec![Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                RData::PTR(PTR(Name::from_ascii("internal.example.").unwrap())),
            )],
        )
    })
    .await;
    let forwarder = protected_forwarder(upstream).await;
    for transport in [Transport::Udp, Transport::Tcp, Transport::Dot] {
        let result = query(
            &forwarder,
            "1.0.0.10.in-addr.arpa.",
            RecordType::PTR,
            transport,
        )
        .await;
        assert_eq!(result.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn one_private_range_does_not_authorize_local_discovery() {
    let (upstream, hits) = resolver(public_answer).await;
    let mut forwarder = protected_forwarder(upstream).await;
    Arc::make_mut(&mut Arc::get_mut(&mut forwarder).unwrap().network_policy)
        .rules
        .push(egress_rule("10.0.0.0/8", Action::Allow));
    for transport in [Transport::Udp, Transport::Tcp, Transport::Dot] {
        let result = query(&forwarder, "printer.local.", RecordType::A, transport).await;
        assert_eq!(result.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn reverse_zone_checks_denied_interior_not_just_endpoints() {
    let (upstream, hits) = resolver(public_answer).await;
    let mut forwarder = protected_forwarder(upstream).await;
    let policy = Arc::make_mut(&mut Arc::get_mut(&mut forwarder).unwrap().network_policy);
    policy.rules.push(egress_rule("10.1.0.0/16", Action::Deny));
    policy.rules.push(egress_rule("10.0.0.0/8", Action::Allow));
    for transport in [Transport::Udp, Transport::Tcp, Transport::Dot] {
        let result = query(&forwarder, "10.in-addr.arpa.", RecordType::PTR, transport).await;
        assert_eq!(result.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn mixed_reverse_zone_requires_its_private_addresses_too() {
    let (upstream, hits) = resolver(public_answer).await;
    let forwarder = protected_forwarder(upstream).await;
    for transport in [Transport::Udp, Transport::Tcp, Transport::Dot] {
        let result = query(&forwarder, "172.in-addr.arpa.", RecordType::PTR, transport).await;
        assert_eq!(result.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn public_alias_cannot_return_a_restricted_local_target() {
    let (upstream, _) = resolver(|request| {
        reply(
            request,
            vec![
                record(
                    "public.example.",
                    RData::CNAME(CNAME(Name::from_ascii("printer.local.").unwrap())),
                ),
                record(
                    "printer.local.",
                    RData::A(A::from(Ipv4Addr::new(8, 8, 8, 8))),
                ),
            ],
        )
    })
    .await;
    let forwarder = protected_forwarder(upstream).await;
    for transport in [Transport::Udp, Transport::Tcp, Transport::Dot] {
        let result = query(&forwarder, "public.example.", RecordType::A, transport).await;
        assert_eq!(result.metadata.response_code, ResponseCode::NXDomain);
        assert!(result.answers.is_empty());
    }
}

#[tokio::test]
async fn complete_public_answer_drops_restricted_extra_addresses() {
    let (upstream, _) = resolver(|request| {
        let mut response = public_answer(request);
        response.metadata.authentic_data = true;
        response.additionals.push(record(
            "internal.example.",
            RData::A(A::from(Ipv4Addr::new(10, 0, 0, 9))),
        ));
        response
    })
    .await;
    let forwarder = protected_forwarder(upstream).await;
    for transport in [Transport::Udp, Transport::Tcp, Transport::Dot] {
        let result = query(&forwarder, "public.example.", RecordType::A, transport).await;
        assert_eq!(result.metadata.response_code, ResponseCode::NoError);
        assert_eq!(result.answers.len(), 1);
        assert!(result.additionals.is_empty());
        assert!(!result.metadata.authentic_data);
    }
}

#[tokio::test]
async fn public_reverse_answer_survives_restricted_parent_authority() {
    let (upstream, _) = resolver(|request| {
        let mut response = reply(
            request,
            vec![Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                RData::PTR(PTR(Name::from_ascii("public.example.").unwrap())),
            )],
        );
        response.authorities.push(record(
            "172.in-addr.arpa.",
            RData::NS(NS(Name::from_ascii("ns.example.").unwrap())),
        ));
        response
    })
    .await;
    let forwarder = protected_forwarder(upstream).await;
    for transport in [Transport::Udp, Transport::Tcp, Transport::Dot] {
        let result = query(
            &forwarder,
            "1.1.1.172.in-addr.arpa.",
            RecordType::PTR,
            transport,
        )
        .await;
        assert_eq!(result.metadata.response_code, ResponseCode::NoError);
        assert_eq!(result.answers.len(), 1);
        assert!(result.authorities.is_empty());
    }
}

#[tokio::test]
async fn configured_nat64_cannot_hide_a_private_answer() {
    let (upstream, _) = resolver(|request| {
        reply(
            request,
            vec![Record::from_rdata(
                request.queries[0].name().clone(),
                60,
                RData::AAAA(AAAA("64:ff9b::a00:1".parse::<Ipv6Addr>().unwrap())),
            )],
        )
    })
    .await;
    let forwarder = protected_forwarder(upstream).await;
    for transport in [Transport::Udp, Transport::Tcp, Transport::Dot] {
        let result = query(&forwarder, "public.example.", RecordType::AAAA, transport).await;
        assert_eq!(result.metadata.response_code, ResponseCode::NXDomain);
        assert!(result.answers.is_empty());
    }
}

#[tokio::test]
async fn response_authorization_refreshes_bindings_changed_during_upstream_wait() {
    use crate::policy::{Destination, Direction, Rule};
    use std::sync::OnceLock;

    for remove_allow in [false, true] {
        let state = Arc::new(OnceLock::<Arc<SharedState>>::new());
        let resolver_state = state.clone();
        let (upstream, hits) = resolver(move |request| {
            let shared = resolver_state.get().unwrap();
            if remove_allow {
                shared.clear_resolved_hostname("binding.example", ResolvedHostnameFamily::Ipv4);
            } else {
                shared.cache_resolved_hostname(
                    "binding.example",
                    ResolvedHostnameFamily::Ipv4,
                    ["10.0.0.1".parse().unwrap()],
                    Duration::from_secs(60),
                );
            }
            reply(
                request,
                vec![Record::from_rdata(
                    request.queries[0].name().clone(),
                    30,
                    RData::PTR(PTR(Name::from_ascii("public.example.").unwrap())),
                )],
            )
        })
        .await;
        let mut forwarder = protected_forwarder(upstream).await;
        let mutable = Arc::get_mut(&mut forwarder).unwrap();
        Arc::make_mut(&mut mutable.network_policy)
            .rules
            .push(egress_rule("10.0.0.0/8", Action::Allow));
        let mut floor = if remove_allow {
            NetworkPolicy::none()
        } else {
            NetworkPolicy::allow_all()
        };
        floor.rules.push(Rule {
            direction: Direction::Egress,
            destination: Destination::Domain("binding.example".parse().unwrap()),
            protocols: vec![],
            ports: vec![],
            action: if remove_allow {
                Action::Allow
            } else {
                Action::Deny
            },
        });
        mutable.platform_policy = Some(Arc::new(floor));
        state.set(mutable.shared.clone()).ok().unwrap();
        if remove_allow {
            mutable.shared.cache_resolved_hostname(
                "binding.example",
                ResolvedHostnameFamily::Ipv4,
                ["10.0.0.1".parse().unwrap()],
                Duration::from_secs(60),
            );
        }
        let result = query(
            &forwarder,
            "1.0.0.10.in-addr.arpa.",
            RecordType::PTR,
            Transport::Udp,
        )
        .await;
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert_eq!(result.metadata.response_code, ResponseCode::NXDomain);
    }
}
