//! DNS interception engine.
//!
//! Intercepts DNS queries destined for the sandbox gateway, resolves
//! them via host nameservers using `hickory-resolver`, applies domain
//! and rebind filters, records A/AAAA answers in the pin set, and
//! synthesizes DNS response frames.

use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use etherparse::TransportSlice;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use hickory_resolver::TokioResolver;
use hickory_resolver::name_server::TokioConnectionProvider;

use crate::packet::ParsedFrame;
use crate::policy::DnsPinSet;

use super::DnsFilter;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const TCP_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum TCP DNS reassembly buffer size (max DNS message = 65535 + 2-byte length prefix).
const MAX_TCP_REQUEST_BUFFER: usize = 65537;

/// Maximum concurrent TCP DNS streams to prevent SYN-flood memory exhaustion.
const MAX_TCP_STREAMS: usize = 64;

/// Maximum number of out-of-order pending TCP segments per stream.
const MAX_PENDING_SEGMENTS: usize = 16;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// DNS interceptor that resolves queries via host nameservers.
pub struct DnsInterceptor {
    /// Host DNS resolver.
    resolver: TokioResolver,

    /// Domain and rebind filter.
    filter: DnsFilter,

    /// Shared pin set for recording resolved IPs.
    pin_set: Arc<RwLock<DnsPinSet>>,

    /// Gateway IP addresses — DNS queries to these IPs are intercepted.
    gateway_ips: Vec<IpAddr>,

    /// Reassembly and TCP session state for DNS-over-TCP interception.
    tcp_streams: Mutex<HashMap<TcpFlowKey, TcpStreamState>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsInterceptResult {
    Intercepted,
    NotIntercepted,
    Responses(Vec<DnsInterceptResponse>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsInterceptResponse {
    pub payload: Vec<u8>,
    pub tcp_sequence_number: Option<u32>,
    pub tcp_acknowledgment_number: Option<u32>,
    pub tcp_flags: Option<TcpResponseFlags>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpResponseFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
}

#[derive(Clone, Copy)]
enum DnsTransport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct TcpFlowKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
}

#[derive(Debug)]
struct TcpStreamState {
    request_buffer: Vec<u8>,
    pending_segments: BTreeMap<u32, BufferedTcpSegment>,
    next_client_sequence: u32,
    next_server_sequence: u32,
    last_activity: Instant,
}

#[derive(Debug)]
struct BufferedTcpSegment {
    payload: Vec<u8>,
    fin: bool,
}

struct NormalizedTcpSegment<'a> {
    sequence_number: u32,
    payload: &'a [u8],
    fin: bool,
}

struct TcpFrameInfo<'a> {
    flow: TcpFlowKey,
    payload: &'a [u8],
    sequence_number: u32,
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
}

enum ParsedDnsPayload<'a> {
    Tcp(TcpFrameInfo<'a>),
    Udp(&'a [u8]),
}

struct TcpInterceptWork {
    flow: TcpFlowKey,
    queries: Vec<Vec<u8>>,
    acknowledgment_number: u32,
    fin: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DnsInterceptor {
    /// Creates a new DNS interceptor.
    ///
    /// Returns an error if the system DNS resolver configuration cannot be read.
    pub fn new(
        filter: DnsFilter,
        pin_set: Arc<RwLock<DnsPinSet>>,
        gateway_ips: Vec<IpAddr>,
    ) -> std::io::Result<Self> {
        let resolver = TokioResolver::builder(TokioConnectionProvider::default())
            .map_err(|e| std::io::Error::other(format!("failed to read system DNS config: {e}")))?
            .build();

        Ok(Self {
            resolver,
            filter,
            pin_set,
            gateway_ips,
            tcp_streams: Mutex::new(HashMap::new()),
        })
    }

    /// Checks if a frame is a DNS query to the gateway and resolves it locally.
    ///
    /// Returns `NotIntercepted` if the frame should continue to the backend,
    /// `Intercepted` if the frame was consumed locally without a response yet,
    /// or one or more synthesized DNS responses.
    pub async fn maybe_intercept(&self, frame: &ParsedFrame<'_>) -> DnsInterceptResult {
        self.prune_expired_tcp_streams();

        if frame.dst_port() != Some(53) {
            return DnsInterceptResult::NotIntercepted;
        }

        let Some(dst_ip) = frame.dst_ip() else {
            return DnsInterceptResult::Intercepted;
        };
        if !self.gateway_ips.contains(&dst_ip) {
            return DnsInterceptResult::NotIntercepted;
        }

        match dns_query_payload(frame) {
            Some(ParsedDnsPayload::Udp(payload)) => match self.resolve_query(payload).await {
                Some(payload) => {
                    let payload = match encode_dns_response(DnsTransport::Udp, payload) {
                        Some(payload) => payload,
                        None => return DnsInterceptResult::Intercepted,
                    };

                    DnsInterceptResult::Responses(vec![DnsInterceptResponse {
                        payload,
                        tcp_sequence_number: None,
                        tcp_acknowledgment_number: None,
                        tcp_flags: None,
                    }])
                }
                None => DnsInterceptResult::Intercepted,
            },
            Some(ParsedDnsPayload::Tcp(info)) => self.handle_tcp_frame(info).await,
            None => DnsInterceptResult::Intercepted,
        }
    }

    /// Resolves a DNS query and applies rebind filtering.
    async fn resolve_and_filter(
        &self,
        query: &Message,
        domain: &str,
        record_type: RecordType,
    ) -> Vec<u8> {
        // For non-A/AAAA queries (MX, TXT, SRV, etc.), forward via the
        // general lookup API rather than synthesizing NXDOMAIN.
        if record_type != RecordType::A && record_type != RecordType::AAAA {
            return match self.resolver.lookup(domain, record_type).await {
                Ok(lookup) => {
                    let mut response = Message::new();
                    response.set_id(query.id());
                    response.set_message_type(MessageType::Response);
                    response.set_response_code(ResponseCode::NoError);
                    response.add_queries(query.queries().to_vec());
                    for record in lookup.record_iter() {
                        response.add_answer(record.clone());
                    }
                    response.to_vec().unwrap_or_default()
                }
                Err(_) => build_nxdomain_response(query),
            };
        }

        let lookup_result = match record_type {
            RecordType::A => self
                .resolver
                .ipv4_lookup(domain)
                .await
                .map(|l| l.iter().map(|ip| IpAddr::V4(ip.0)).collect::<Vec<_>>()),
            RecordType::AAAA => self
                .resolver
                .ipv6_lookup(domain)
                .await
                .map(|l| l.iter().map(|ip| IpAddr::V6(ip.0)).collect::<Vec<_>>()),
            _ => unreachable!(),
        };

        match lookup_result {
            Ok(ips) => {
                let ips: Vec<IpAddr> = ips
                    .into_iter()
                    .filter(|ip| !self.filter.is_rebind_blocked(*ip))
                    .collect();

                if let Ok(mut pin_set) = self.pin_set.write() {
                    for ip in &ips {
                        pin_set.pin(domain, *ip);
                    }
                }

                build_success_response(query, &ips, record_type)
            }
            Err(_) => build_nxdomain_response(query),
        }
    }

    async fn handle_tcp_frame(&self, info: TcpFrameInfo<'_>) -> DnsInterceptResult {
        if info.rst {
            self.remove_tcp_state(&info.flow);
            return DnsInterceptResult::Intercepted;
        }

        if info.syn && !info.ack {
            return self.handle_tcp_syn(info.flow, info.sequence_number);
        }

        let Some(work) = self.collect_tcp_queries(&info) else {
            return DnsInterceptResult::Intercepted;
        };

        if work.queries.is_empty() {
            if work.fin {
                let sequence_number = match self.remove_tcp_state(&work.flow) {
                    Some(state) => state.next_server_sequence,
                    None => return DnsInterceptResult::Intercepted,
                };

                return DnsInterceptResult::Responses(vec![DnsInterceptResponse {
                    payload: Vec::new(),
                    tcp_sequence_number: Some(sequence_number),
                    tcp_acknowledgment_number: Some(work.acknowledgment_number),
                    tcp_flags: Some(TcpResponseFlags {
                        syn: false,
                        ack: true,
                        fin: true,
                        rst: false,
                        psh: false,
                    }),
                }]);
            }

            return DnsInterceptResult::Intercepted;
        }

        let mut sequence_number = match self.current_server_sequence(&work.flow) {
            Some(sequence_number) => sequence_number,
            None => return DnsInterceptResult::Intercepted,
        };

        let mut responses = Vec::new();
        for query in &work.queries {
            let Some(payload) = self.resolve_query(query).await else {
                continue;
            };
            let response_len = payload.len();
            let payload = match encode_dns_response(DnsTransport::Tcp, payload) {
                Some(payload) => payload,
                None => continue,
            };

            responses.push(DnsInterceptResponse {
                payload,
                tcp_sequence_number: Some(sequence_number),
                tcp_acknowledgment_number: Some(work.acknowledgment_number),
                tcp_flags: Some(TcpResponseFlags {
                    syn: false,
                    ack: true,
                    fin: false,
                    rst: false,
                    psh: response_len > 0,
                }),
            });

            sequence_number =
                sequence_number.wrapping_add(u32::try_from(response_len + 2).unwrap_or(0));
        }

        self.update_server_sequence(&work.flow, sequence_number);

        if work.fin {
            self.remove_tcp_state(&work.flow);
            responses.push(DnsInterceptResponse {
                payload: Vec::new(),
                tcp_sequence_number: Some(sequence_number),
                tcp_acknowledgment_number: Some(work.acknowledgment_number),
                tcp_flags: Some(TcpResponseFlags {
                    syn: false,
                    ack: true,
                    fin: true,
                    rst: false,
                    psh: false,
                }),
            });
        }

        if responses.is_empty() {
            DnsInterceptResult::Intercepted
        } else {
            DnsInterceptResult::Responses(responses)
        }
    }

    fn handle_tcp_syn(&self, flow: TcpFlowKey, client_sequence_number: u32) -> DnsInterceptResult {
        let server_initial_sequence = initial_server_sequence(&flow, client_sequence_number);
        let next_client_sequence = client_sequence_number.wrapping_add(1);
        let next_server_sequence = server_initial_sequence.wrapping_add(1);

        {
            let mut streams = self.tcp_streams.lock().unwrap_or_else(|e| e.into_inner());

            // Enforce stream count cap to prevent SYN-flood memory exhaustion.
            if streams.len() >= MAX_TCP_STREAMS {
                return DnsInterceptResult::Intercepted;
            }

            streams.insert(
                flow,
                TcpStreamState {
                    request_buffer: Vec::new(),
                    pending_segments: BTreeMap::new(),
                    next_client_sequence,
                    next_server_sequence,
                    last_activity: Instant::now(),
                },
            );
        }

        DnsInterceptResult::Responses(vec![DnsInterceptResponse {
            payload: Vec::new(),
            tcp_sequence_number: Some(server_initial_sequence),
            tcp_acknowledgment_number: Some(next_client_sequence),
            tcp_flags: Some(TcpResponseFlags {
                syn: true,
                ack: true,
                fin: false,
                rst: false,
                psh: false,
            }),
        }])
    }

    async fn resolve_query(&self, payload: &[u8]) -> Option<Vec<u8>> {
        let query = Message::from_bytes(payload).ok()?;
        if query.message_type() != MessageType::Query {
            return None;
        }

        let question = query.queries().first()?;
        let domain = question.name().to_string();
        let record_type = question.query_type();

        let response_payload = if self.filter.is_domain_blocked(&domain) {
            build_refused_response(&query)
        } else {
            self.resolve_and_filter(&query, &domain, record_type).await
        };

        Some(response_payload)
    }

    fn collect_tcp_queries(&self, info: &TcpFrameInfo<'_>) -> Option<TcpInterceptWork> {
        let mut streams = self.tcp_streams.lock().unwrap_or_else(|e| e.into_inner());
        let state = streams.get_mut(&info.flow)?;
        state.last_activity = Instant::now();

        let Some(segment) = normalize_tcp_segment(
            info.sequence_number,
            info.payload,
            info.fin,
            state.next_client_sequence,
        ) else {
            return Some(TcpInterceptWork {
                flow: info.flow.clone(),
                queries: Vec::new(),
                acknowledgment_number: state.next_client_sequence,
                fin: false,
            });
        };

        if segment.sequence_number != state.next_client_sequence {
            store_pending_segment(state, segment.sequence_number, segment.payload, segment.fin)?;
            return Some(TcpInterceptWork {
                flow: info.flow.clone(),
                queries: Vec::new(),
                acknowledgment_number: state.next_client_sequence,
                fin: false,
            });
        }

        let mut close_after_queries = append_tcp_segment(state, segment.payload, segment.fin)?;
        close_after_queries |= drain_pending_segments(state)?;

        let mut queries = Vec::new();
        while state.request_buffer.len() >= 2 {
            let dns_len = usize::from(u16::from_be_bytes([
                state.request_buffer[0],
                state.request_buffer[1],
            ]));
            if dns_len == 0 {
                state.request_buffer.clear();
                break;
            }

            if state.request_buffer.len() < dns_len + 2 {
                break;
            }

            queries.push(state.request_buffer[2..dns_len + 2].to_vec());
            state.request_buffer.drain(..dns_len + 2);
        }

        Some(TcpInterceptWork {
            flow: info.flow.clone(),
            queries,
            acknowledgment_number: state.next_client_sequence,
            fin: close_after_queries,
        })
    }

    fn current_server_sequence(&self, flow: &TcpFlowKey) -> Option<u32> {
        let streams = self.tcp_streams.lock().unwrap_or_else(|e| e.into_inner());
        streams.get(flow).map(|state| state.next_server_sequence)
    }

    fn update_server_sequence(&self, flow: &TcpFlowKey, next_server_sequence: u32) {
        let mut streams = self.tcp_streams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = streams.get_mut(flow) {
            state.next_server_sequence = next_server_sequence;
        }
    }

    fn remove_tcp_state(&self, flow: &TcpFlowKey) -> Option<TcpStreamState> {
        let mut streams = self.tcp_streams.lock().unwrap_or_else(|e| e.into_inner());
        streams.remove(flow)
    }

    fn prune_expired_tcp_streams(&self) {
        let mut streams = self.tcp_streams.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        streams.retain(|_, state| {
            now.duration_since(state.last_activity) <= TCP_STREAM_IDLE_TIMEOUT
        });
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn dns_query_payload<'a>(frame: &'a ParsedFrame<'a>) -> Option<ParsedDnsPayload<'a>> {
    match &frame.sliced().transport {
        Some(TransportSlice::Udp(_)) => {
            let payload = frame.payload();
            if payload.is_empty() {
                None
            } else {
                Some(ParsedDnsPayload::Udp(payload))
            }
        }
        Some(TransportSlice::Tcp(tcp)) => Some(ParsedDnsPayload::Tcp(TcpFrameInfo {
            flow: TcpFlowKey {
                src_ip: frame.src_ip()?,
                dst_ip: frame.dst_ip()?,
                src_port: frame.src_port()?,
                dst_port: frame.dst_port()?,
            },
            payload: frame.payload(),
            sequence_number: tcp.sequence_number(),
            syn: tcp.syn(),
            ack: tcp.ack(),
            fin: tcp.fin(),
            rst: tcp.rst(),
        })),
        _ => None,
    }
}

fn initial_server_sequence(flow: &TcpFlowKey, client_sequence_number: u32) -> u32 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    flow.hash(&mut hasher);
    client_sequence_number.hash(&mut hasher);
    hasher.finish() as u32
}

fn append_tcp_segment(state: &mut TcpStreamState, payload: &[u8], fin: bool) -> Option<bool> {
    let advance = tcp_sequence_advance(payload.len(), fin, false)?;
    state.next_client_sequence = state.next_client_sequence.wrapping_add(advance);

    if !payload.is_empty() {
        // Enforce buffer cap to prevent guest-triggered OOM.
        if state.request_buffer.len() + payload.len() > MAX_TCP_REQUEST_BUFFER {
            return None;
        }
        state.request_buffer.extend_from_slice(payload);
    }

    Some(fin)
}

fn drain_pending_segments(state: &mut TcpStreamState) -> Option<bool> {
    let mut close_after_queries = false;

    loop {
        // Use direct key lookup instead of iter().next() to avoid BTreeMap
        // natural ordering issues at TCP sequence number wraparound.
        let segment = match state.pending_segments.remove(&state.next_client_sequence) {
            Some(seg) => seg,
            None => break,
        };
        close_after_queries |= append_tcp_segment(state, &segment.payload, segment.fin)?;
    }

    Some(close_after_queries)
}

fn normalize_tcp_segment<'a>(
    sequence_number: u32,
    payload: &'a [u8],
    fin: bool,
    next_client_sequence: u32,
) -> Option<NormalizedTcpSegment<'a>> {
    // Use wrapping subtraction + signed comparison to handle sequence
    // number wraparound at u32::MAX correctly (standard TCP practice).
    let diff = sequence_number.wrapping_sub(next_client_sequence) as i32;
    if diff >= 0 {
        return Some(NormalizedTcpSegment {
            sequence_number,
            payload,
            fin,
        });
    }

    let segment_advance = tcp_sequence_advance(payload.len(), fin, false)?;
    let duplicate_advance = next_client_sequence.wrapping_sub(sequence_number);
    if duplicate_advance >= segment_advance {
        return None;
    }

    let duplicate_bytes = usize::try_from(duplicate_advance).ok()?.min(payload.len());
    let fin_consumed = fin && duplicate_advance > payload.len() as u32;

    Some(NormalizedTcpSegment {
        sequence_number: next_client_sequence,
        payload: &payload[duplicate_bytes..],
        fin: fin && !fin_consumed,
    })
}

fn store_pending_segment(
    state: &mut TcpStreamState,
    sequence_number: u32,
    payload: &[u8],
    fin: bool,
) -> Option<()> {
    // Enforce pending segment cap to prevent guest-triggered OOM.
    if state.pending_segments.len() >= MAX_PENDING_SEGMENTS {
        return None;
    }

    let new_advance = tcp_sequence_advance(payload.len(), fin, false)?;

    match state.pending_segments.entry(sequence_number) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(BufferedTcpSegment {
                payload: payload.to_vec(),
                fin,
            });
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            let existing = entry.get();
            let existing_advance =
                tcp_sequence_advance(existing.payload.len(), existing.fin, false)?;
            if new_advance > existing_advance {
                entry.insert(BufferedTcpSegment {
                    payload: payload.to_vec(),
                    fin,
                });
            }
        }
    }

    Some(())
}

fn tcp_sequence_advance(payload_len: usize, fin: bool, syn: bool) -> Option<u32> {
    u32::try_from(payload_len).ok().map(|advance| {
        advance
            .wrapping_add(u32::from(fin))
            .wrapping_add(u32::from(syn))
    })
}

fn encode_dns_response(transport: DnsTransport, payload: Vec<u8>) -> Option<Vec<u8>> {
    match transport {
        DnsTransport::Udp => Some(payload),
        DnsTransport::Tcp => {
            let payload_len = u16::try_from(payload.len()).ok()?;
            let mut framed = Vec::with_capacity(payload.len() + 2);
            framed.extend_from_slice(&payload_len.to_be_bytes());
            framed.extend_from_slice(&payload);
            Some(framed)
        }
    }
}

/// Builds a DNS REFUSED response.
fn build_refused_response(query: &Message) -> Vec<u8> {
    let mut response = Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_response_code(ResponseCode::Refused);
    response.add_queries(query.queries().to_vec());

    response.to_vec().unwrap_or_default()
}

/// Builds a DNS NXDOMAIN response.
fn build_nxdomain_response(query: &Message) -> Vec<u8> {
    let mut response = Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_response_code(ResponseCode::NXDomain);
    response.add_queries(query.queries().to_vec());

    response.to_vec().unwrap_or_default()
}

/// Builds a DNS success response with the given IP addresses.
fn build_success_response(query: &Message, ips: &[IpAddr], record_type: RecordType) -> Vec<u8> {
    use hickory_proto::rr::{Name, Record};
    use std::str::FromStr;

    let mut response = Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_response_code(ResponseCode::NoError);
    response.add_queries(query.queries().to_vec());

    let name = query
        .queries()
        .first()
        .map(|q| q.name().clone())
        .unwrap_or_else(|| Name::from_str(".").unwrap());

    for ip in ips {
        let rdata = match (ip, record_type) {
            (IpAddr::V4(v4), RecordType::A) => RData::A((*v4).into()),
            (IpAddr::V6(v6), RecordType::AAAA) => RData::AAAA((*v6).into()),
            _ => continue,
        };

        let record = Record::from_rdata(name.clone(), 60, rdata);
        response.add_answer(record);
    }

    response.to_vec().unwrap_or_default()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    use etherparse::PacketBuilder;
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;

    use super::*;

    fn build_dns_query(domain: &str) -> Vec<u8> {
        let mut message = Message::new();
        message.set_id(7);
        message.set_message_type(MessageType::Query);
        message.add_query(Query::query(
            Name::from_ascii(domain).unwrap(),
            RecordType::A,
        ));
        message.to_vec().unwrap()
    }

    fn build_udp_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        PacketBuilder::ethernet2(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        )
        .ipv4([100, 96, 0, 2], [100, 96, 0, 1], 64)
        .udp(51000, 53)
        .write(&mut frame, payload)
        .unwrap();
        frame
    }

    fn build_tcp_frame(
        payload: &[u8],
        sequence_number: u32,
        acknowledgment_number: Option<u32>,
        syn: bool,
        fin: bool,
    ) -> Vec<u8> {
        let mut builder = PacketBuilder::ethernet2(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        )
        .ipv4([100, 96, 0, 2], [100, 96, 0, 1], 64)
        .tcp(51000, 53, sequence_number, 200);

        if let Some(acknowledgment_number) = acknowledgment_number {
            builder = builder.ack(acknowledgment_number);
        }
        if syn {
            builder = builder.syn();
        }
        if fin {
            builder = builder.fin();
        }
        if !payload.is_empty() {
            builder = builder.psh();
        }

        let mut frame = Vec::new();
        builder.write(&mut frame, payload).unwrap();
        frame
    }

    fn build_interceptor() -> DnsInterceptor {
        DnsInterceptor::new(
            DnsFilter::new(vec!["blocked.example.".to_string()], vec![], false),
            Arc::new(RwLock::new(DnsPinSet::new())),
            vec![IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1))],
        )
        .unwrap()
    }

    async fn establish_tcp_session(
        interceptor: &DnsInterceptor,
        client_sequence_number: u32,
    ) -> u32 {
        let syn = build_tcp_frame(&[], client_sequence_number, None, true, false);
        let parsed = ParsedFrame::parse(&syn).unwrap();

        let responses = match interceptor.maybe_intercept(&parsed).await {
            DnsInterceptResult::Responses(responses) => responses,
            other => panic!("expected SYN-ACK, got {other:?}"),
        };

        assert_eq!(responses.len(), 1);
        let response = &responses[0];
        let tcp_flags = response.tcp_flags.unwrap();
        assert!(tcp_flags.syn);
        assert!(tcp_flags.ack);
        assert_eq!(
            response.tcp_acknowledgment_number,
            Some(client_sequence_number.wrapping_add(1)),
        );
        response.tcp_sequence_number.unwrap().wrapping_add(1)
    }

    #[test]
    fn test_dns_query_payload_extracts_udp_message() {
        let query = build_dns_query("blocked.example.");
        let frame = build_udp_frame(&query);
        let parsed = ParsedFrame::parse(&frame).unwrap();

        match dns_query_payload(&parsed).unwrap() {
            ParsedDnsPayload::Udp(payload) => assert_eq!(payload, query.as_slice()),
            ParsedDnsPayload::Tcp(_) => panic!("expected UDP payload"),
        }
    }

    #[test]
    fn test_dns_query_payload_extracts_tcp_syn() {
        let frame = build_tcp_frame(&[], 10, None, true, false);
        let parsed = ParsedFrame::parse(&frame).unwrap();

        match dns_query_payload(&parsed).unwrap() {
            ParsedDnsPayload::Tcp(info) => {
                assert!(info.syn);
                assert!(!info.ack);
                assert_eq!(info.sequence_number, 10);
            }
            ParsedDnsPayload::Udp(_) => panic!("expected TCP payload"),
        }
    }

    #[tokio::test]
    async fn test_maybe_intercept_establishes_tcp_session_with_syn_ack() {
        let interceptor = build_interceptor();
        let server_next_sequence = establish_tcp_session(&interceptor, 10).await;
        assert_ne!(server_next_sequence, 0);
    }

    #[tokio::test]
    async fn test_maybe_intercept_returns_tcp_framed_response() {
        let query = build_dns_query("blocked.example.");
        let mut payload = Vec::with_capacity(query.len() + 2);
        payload.extend_from_slice(&(query.len() as u16).to_be_bytes());
        payload.extend_from_slice(&query);

        let interceptor = build_interceptor();
        let server_next_sequence = establish_tcp_session(&interceptor, 10).await;

        let frame = build_tcp_frame(&payload, 11, Some(server_next_sequence), false, false);
        let parsed = ParsedFrame::parse(&frame).unwrap();

        let responses = match interceptor.maybe_intercept(&parsed).await {
            DnsInterceptResult::Responses(responses) => responses,
            other => panic!("expected TCP response, got {other:?}"),
        };

        assert_eq!(responses.len(), 1);
        let response = &responses[0];
        let response_len = usize::from(u16::from_be_bytes([
            response.payload[0],
            response.payload[1],
        ]));
        let message = Message::from_bytes(&response.payload[2..]).unwrap();

        assert_eq!(response_len, response.payload.len() - 2);
        assert_eq!(message.response_code(), ResponseCode::Refused);
        assert_eq!(message.message_type(), MessageType::Response);
        assert_eq!(response.tcp_sequence_number, Some(server_next_sequence));
        assert_eq!(
            response.tcp_acknowledgment_number,
            Some(11u32.wrapping_add(payload.len() as u32)),
        );
    }

    #[tokio::test]
    async fn test_maybe_intercept_buffers_split_tcp_query() {
        let query = build_dns_query("blocked.example.");
        let mut full_payload = Vec::with_capacity(query.len() + 2);
        full_payload.extend_from_slice(&(query.len() as u16).to_be_bytes());
        full_payload.extend_from_slice(&query);

        let split_at = 5;
        let interceptor = build_interceptor();
        let server_next_sequence = establish_tcp_session(&interceptor, 10).await;

        let first = build_tcp_frame(
            &full_payload[..split_at],
            11,
            Some(server_next_sequence),
            false,
            false,
        );
        let second = build_tcp_frame(
            &full_payload[split_at..],
            11 + split_at as u32,
            Some(server_next_sequence),
            false,
            false,
        );

        let first_parsed = ParsedFrame::parse(&first).unwrap();
        assert_eq!(
            interceptor.maybe_intercept(&first_parsed).await,
            DnsInterceptResult::Intercepted,
        );

        let second_parsed = ParsedFrame::parse(&second).unwrap();
        let responses = match interceptor.maybe_intercept(&second_parsed).await {
            DnsInterceptResult::Responses(responses) => responses,
            other => panic!("expected buffered TCP response, got {other:?}"),
        };

        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].tcp_sequence_number, Some(server_next_sequence));
        assert_eq!(
            responses[0].tcp_acknowledgment_number,
            Some(11u32.wrapping_add(full_payload.len() as u32)),
        );
    }

    #[tokio::test]
    async fn test_maybe_intercept_recovers_after_out_of_order_tcp_segment() {
        let query = build_dns_query("blocked.example.");
        let mut full_payload = Vec::with_capacity(query.len() + 2);
        full_payload.extend_from_slice(&(query.len() as u16).to_be_bytes());
        full_payload.extend_from_slice(&query);

        let first_end = 5;
        let second_end = 10;

        let interceptor = build_interceptor();
        let server_next_sequence = establish_tcp_session(&interceptor, 10).await;

        let first = build_tcp_frame(
            &full_payload[..first_end],
            11,
            Some(server_next_sequence),
            false,
            false,
        );
        let third = build_tcp_frame(
            &full_payload[second_end..],
            11 + second_end as u32,
            Some(server_next_sequence),
            false,
            false,
        );
        let second = build_tcp_frame(
            &full_payload[first_end..second_end],
            11 + first_end as u32,
            Some(server_next_sequence),
            false,
            false,
        );

        let first_parsed = ParsedFrame::parse(&first).unwrap();
        assert_eq!(
            interceptor.maybe_intercept(&first_parsed).await,
            DnsInterceptResult::Intercepted,
        );

        let third_parsed = ParsedFrame::parse(&third).unwrap();
        assert_eq!(
            interceptor.maybe_intercept(&third_parsed).await,
            DnsInterceptResult::Intercepted,
        );

        let second_parsed = ParsedFrame::parse(&second).unwrap();
        let responses = match interceptor.maybe_intercept(&second_parsed).await {
            DnsInterceptResult::Responses(responses) => responses,
            other => panic!("expected reordered TCP response, got {other:?}"),
        };

        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].tcp_sequence_number, Some(server_next_sequence));
        assert_eq!(
            responses[0].tcp_acknowledgment_number,
            Some(11u32.wrapping_add(full_payload.len() as u32)),
        );
    }

    #[tokio::test]
    async fn test_maybe_intercept_recovers_after_overlapping_tcp_retransmit() {
        let query = build_dns_query("blocked.example.");
        let mut full_payload = Vec::with_capacity(query.len() + 2);
        full_payload.extend_from_slice(&(query.len() as u16).to_be_bytes());
        full_payload.extend_from_slice(&query);

        let first_end = 8;
        let overlap_start = 5;

        let interceptor = build_interceptor();
        let server_next_sequence = establish_tcp_session(&interceptor, 10).await;

        let first = build_tcp_frame(
            &full_payload[..first_end],
            11,
            Some(server_next_sequence),
            false,
            false,
        );
        let overlapping = build_tcp_frame(
            &full_payload[overlap_start..],
            11 + overlap_start as u32,
            Some(server_next_sequence),
            false,
            false,
        );

        let first_parsed = ParsedFrame::parse(&first).unwrap();
        assert_eq!(
            interceptor.maybe_intercept(&first_parsed).await,
            DnsInterceptResult::Intercepted,
        );

        let overlapping_parsed = ParsedFrame::parse(&overlapping).unwrap();
        let responses = match interceptor.maybe_intercept(&overlapping_parsed).await {
            DnsInterceptResult::Responses(responses) => responses,
            other => panic!("expected overlapping TCP response, got {other:?}"),
        };

        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].tcp_sequence_number, Some(server_next_sequence));
        assert_eq!(
            responses[0].tcp_acknowledgment_number,
            Some(11u32.wrapping_add(full_payload.len() as u32)),
        );
    }

    #[tokio::test]
    async fn test_maybe_intercept_handles_two_queries_in_one_tcp_segment() {
        let query = build_dns_query("blocked.example.");
        let framed_query = {
            let mut payload = Vec::with_capacity(query.len() + 2);
            payload.extend_from_slice(&(query.len() as u16).to_be_bytes());
            payload.extend_from_slice(&query);
            payload
        };

        let mut combined = Vec::with_capacity(framed_query.len() * 2);
        combined.extend_from_slice(&framed_query);
        combined.extend_from_slice(&framed_query);

        let interceptor = build_interceptor();
        let server_next_sequence = establish_tcp_session(&interceptor, 10).await;

        let frame = build_tcp_frame(&combined, 11, Some(server_next_sequence), false, false);
        let parsed = ParsedFrame::parse(&frame).unwrap();

        let responses = match interceptor.maybe_intercept(&parsed).await {
            DnsInterceptResult::Responses(responses) => responses,
            other => panic!("expected pipelined TCP responses, got {other:?}"),
        };

        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0].tcp_sequence_number, Some(server_next_sequence));
        assert!(
            responses[1].tcp_sequence_number.unwrap() > responses[0].tcp_sequence_number.unwrap()
        );
    }

    #[tokio::test]
    async fn test_maybe_intercept_closes_tcp_session_on_fin() {
        let interceptor = build_interceptor();
        let server_next_sequence = establish_tcp_session(&interceptor, 10).await;

        let fin = build_tcp_frame(&[], 11, Some(server_next_sequence), false, true);
        let parsed = ParsedFrame::parse(&fin).unwrap();

        let responses = match interceptor.maybe_intercept(&parsed).await {
            DnsInterceptResult::Responses(responses) => responses,
            other => panic!("expected FIN-ACK, got {other:?}"),
        };

        assert_eq!(responses.len(), 1);
        let response = &responses[0];
        let tcp_flags = response.tcp_flags.unwrap();
        assert!(tcp_flags.fin);
        assert!(tcp_flags.ack);
    }

    #[tokio::test]
    async fn test_maybe_intercept_answers_fin_with_query_before_closing() {
        let query = build_dns_query("blocked.example.");
        let mut payload = Vec::with_capacity(query.len() + 2);
        payload.extend_from_slice(&(query.len() as u16).to_be_bytes());
        payload.extend_from_slice(&query);

        let interceptor = build_interceptor();
        let server_next_sequence = establish_tcp_session(&interceptor, 10).await;

        let fin_with_query = build_tcp_frame(&payload, 11, Some(server_next_sequence), false, true);
        let parsed = ParsedFrame::parse(&fin_with_query).unwrap();

        let responses = match interceptor.maybe_intercept(&parsed).await {
            DnsInterceptResult::Responses(responses) => responses,
            other => panic!("expected DNS response and FIN-ACK, got {other:?}"),
        };

        assert_eq!(responses.len(), 2);

        let dns_response = &responses[0];
        let dns_message = Message::from_bytes(&dns_response.payload[2..]).unwrap();
        assert_eq!(dns_message.response_code(), ResponseCode::Refused);

        let fin_response = &responses[1];
        let fin_flags = fin_response.tcp_flags.unwrap();
        assert!(fin_flags.fin);
        assert!(fin_flags.ack);
        assert_eq!(
            fin_response.tcp_sequence_number,
            Some(
                dns_response
                    .tcp_sequence_number
                    .unwrap()
                    .wrapping_add(dns_response.payload.len() as u32)
            )
        );
    }

    #[tokio::test]
    async fn test_maybe_intercept_prunes_idle_tcp_sessions() {
        let interceptor = build_interceptor();
        establish_tcp_session(&interceptor, 10).await;

        {
            let mut streams = interceptor.tcp_streams.lock().unwrap();
            let stale_age = TCP_STREAM_IDLE_TIMEOUT + Duration::from_secs(1);
            for state in streams.values_mut() {
                state.last_activity = Instant::now() - stale_age;
            }
        }

        let query = build_dns_query("blocked.example.");
        let frame = build_udp_frame(&query);
        let parsed = ParsedFrame::parse(&frame).unwrap();
        let _ = interceptor.maybe_intercept(&parsed).await;

        let streams = interceptor.tcp_streams.lock().unwrap();
        assert!(streams.is_empty());
    }

    #[test]
    fn test_encode_dns_response_tcp_prefixes_length() {
        let encoded = encode_dns_response(DnsTransport::Tcp, vec![1, 2, 3]).unwrap();
        assert_eq!(encoded, vec![0, 3, 1, 2, 3]);
    }

    #[test]
    fn test_engine_tcp_flags_shape_is_serializable() {
        let flags = TcpResponseFlags {
            syn: true,
            ack: true,
            fin: false,
            rst: false,
            psh: false,
        };
        assert!(flags.syn && flags.ack);
    }
}
