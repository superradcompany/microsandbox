//! Bounded IPv4 UDP fragment reassembly for the userspace UDP relay.
//!
//! smoltcp is not the endpoint for arbitrary outbound UDP, so fragmented UDP
//! needs to be reassembled before the payload proxy can enforce policy and
//! forward the datagram through a host socket.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use smoltcp::wire::{
    EthernetFrame, EthernetProtocol, EthernetRepr, IpProtocol, Ipv4Packet, Ipv6Packet, UdpPacket,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum time an incomplete fragment set may stay buffered.
const FRAGMENT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum active IPv4 UDP fragment sets per sandbox network loop.
const MAX_FRAGMENT_SETS: usize = 64;

/// Maximum fragments accepted for one IPv4 datagram.
const MAX_FRAGMENTS_PER_SET: usize = 128;

/// Maximum IPv4 payload size after reassembly.
const MAX_IPV4_PAYLOAD_LEN: usize = 65_515;

/// Maximum IPv6 payload size after reassembly.
const MAX_IPV6_PAYLOAD_LEN: usize = 65_535;

/// Ethernet header length.
const ETH_HDR_LEN: usize = 14;

/// IPv4 header length emitted for reassembled datagrams.
const IPV4_HDR_LEN: usize = 20;

/// IPv6 header length emitted for reassembled datagrams.
const IPV6_HDR_LEN: usize = 40;

/// IPv6 Fragment extension header length.
const IPV6_FRAGMENT_HDR_LEN: usize = 8;

/// Maximum IPv6 extension headers to inspect before a Fragment header.
const MAX_IPV6_EXTENSION_HEADERS: usize = 4;

/// UDP header length.
const UDP_HDR_LEN: usize = 8;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A complete UDP datagram reconstructed from IPv4 fragments.
pub(crate) struct ReassembledUdpDatagram {
    /// Synthetic Ethernet + IPv4 + UDP frame with fragmentation cleared.
    pub(crate) frame: Vec<u8>,
    /// Guest UDP source address.
    pub(crate) src: SocketAddr,
    /// Guest UDP destination address.
    pub(crate) dst: SocketAddr,
}

/// Bounded reassembly state for outbound IPv4 UDP fragments.
#[derive(Default)]
pub(crate) struct Ipv4UdpFragmentReassembler {
    sets: HashMap<Ipv4FragmentKey, Ipv4FragmentSet>,
}

/// Bounded reassembly state for outbound IPv6 UDP fragments.
#[derive(Default)]
pub(crate) struct Ipv6UdpFragmentReassembler {
    sets: HashMap<Ipv6FragmentKey, Ipv6FragmentSet>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Ipv4FragmentKey {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ident: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Ipv6FragmentKey {
    src: Ipv6Addr,
    dst: Ipv6Addr,
    ident: u32,
}

struct Ipv4FragmentSet {
    created_at: Instant,
    last_active: Instant,
    first_fragment: Option<FirstFragment>,
    pieces: Vec<FragmentPiece>,
    total_payload_len: Option<usize>,
}

struct Ipv6FragmentSet {
    created_at: Instant,
    last_active: Instant,
    first_fragment: Option<FirstIpv6Fragment>,
    pieces: Vec<FragmentPiece>,
    total_payload_len: Option<usize>,
}

struct FirstFragment {
    eth_src: smoltcp::wire::EthernetAddress,
    eth_dst: smoltcp::wire::EthernetAddress,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ident: u16,
    hop_limit: u8,
}

struct FirstIpv6Fragment {
    eth_src: smoltcp::wire::EthernetAddress,
    eth_dst: smoltcp::wire::EthernetAddress,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    hop_limit: u8,
}

struct FragmentPiece {
    start: usize,
    end: usize,
    bytes: Vec<u8>,
}

struct Ipv4UdpFragment {
    eth_src: smoltcp::wire::EthernetAddress,
    eth_dst: smoltcp::wire::EthernetAddress,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ident: u16,
    hop_limit: u8,
    offset: usize,
    more_frags: bool,
    payload: Vec<u8>,
    end: usize,
    received_at: Instant,
}

struct Ipv6UdpFragment {
    eth_src: smoltcp::wire::EthernetAddress,
    eth_dst: smoltcp::wire::EthernetAddress,
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    ident: u32,
    hop_limit: u8,
    offset: usize,
    more_frags: bool,
    payload: Vec<u8>,
    end: usize,
    received_at: Instant,
}

struct Ipv6FragmentHeader {
    next_header: IpProtocol,
    offset: usize,
    more_frags: bool,
    ident: u32,
}

struct Ipv6FragmentInfo {
    header: Ipv6FragmentHeader,
    payload_offset: usize,
}

enum FragmentPush {
    Accepted,
    RejectSet,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Ipv4UdpFragmentReassembler {
    /// Build an empty IPv4 UDP fragment reassembler.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Add an outbound IPv4 UDP fragment and return a complete datagram once ready.
    pub(crate) fn push(&mut self, frame: &[u8]) -> Option<ReassembledUdpDatagram> {
        self.cleanup_expired();

        let fragment = parse_ipv4_udp_fragment(frame)?;
        let key = fragment.key();

        if !self.sets.contains_key(&key) && self.sets.len() >= MAX_FRAGMENT_SETS {
            self.evict_oldest();
        }

        let set = self
            .sets
            .entry(key)
            .or_insert_with(|| Ipv4FragmentSet::new(fragment.received_at));

        match set.push(fragment) {
            FragmentPush::Accepted => {}
            FragmentPush::RejectSet => {
                self.sets.remove(&key);
                return None;
            }
        }

        let result = self
            .sets
            .get(&key)
            .and_then(Ipv4FragmentSet::try_reassemble);
        if result.is_some() {
            self.sets.remove(&key);
        }

        result
    }

    /// Drop stale incomplete fragment sets.
    pub(crate) fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.sets.retain(|_, set| {
            now.duration_since(set.created_at) <= FRAGMENT_TIMEOUT
                && now.duration_since(set.last_active) <= FRAGMENT_TIMEOUT
        });
    }

    /// Number of incomplete fragment sets currently buffered.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.sets.len()
    }

    /// Evict the least recently active fragment set.
    fn evict_oldest(&mut self) {
        let Some(oldest_key) = self
            .sets
            .iter()
            .min_by_key(|(_, set)| (set.last_active, set.created_at))
            .map(|(key, _)| *key)
        else {
            return;
        };
        self.sets.remove(&oldest_key);
    }
}

impl Ipv6UdpFragmentReassembler {
    /// Build an empty IPv6 UDP fragment reassembler.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Add an outbound IPv6 UDP fragment and return a complete datagram once ready.
    pub(crate) fn push(&mut self, frame: &[u8]) -> Option<ReassembledUdpDatagram> {
        self.cleanup_expired();

        let fragment = parse_ipv6_udp_fragment(frame)?;
        let key = fragment.key();

        if !self.sets.contains_key(&key) && self.sets.len() >= MAX_FRAGMENT_SETS {
            self.evict_oldest();
        }

        let set = self
            .sets
            .entry(key)
            .or_insert_with(|| Ipv6FragmentSet::new(fragment.received_at));

        match set.push(fragment) {
            FragmentPush::Accepted => {}
            FragmentPush::RejectSet => {
                self.sets.remove(&key);
                return None;
            }
        }

        let result = self
            .sets
            .get(&key)
            .and_then(Ipv6FragmentSet::try_reassemble);
        if result.is_some() {
            self.sets.remove(&key);
        }

        result
    }

    /// Drop stale incomplete fragment sets.
    pub(crate) fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.sets.retain(|_, set| {
            now.duration_since(set.created_at) <= FRAGMENT_TIMEOUT
                && now.duration_since(set.last_active) <= FRAGMENT_TIMEOUT
        });
    }

    /// Number of incomplete fragment sets currently buffered.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.sets.len()
    }

    /// Evict the least recently active fragment set.
    fn evict_oldest(&mut self) {
        let Some(oldest_key) = self
            .sets
            .iter()
            .min_by_key(|(_, set)| (set.last_active, set.created_at))
            .map(|(key, _)| *key)
        else {
            return;
        };
        self.sets.remove(&oldest_key);
    }
}

impl Ipv4FragmentSet {
    /// Build an empty fragment set.
    fn new(now: Instant) -> Self {
        Self {
            created_at: now,
            last_active: now,
            first_fragment: None,
            pieces: Vec::new(),
            total_payload_len: None,
        }
    }

    /// Insert one fragment into this set.
    fn push(&mut self, fragment: Ipv4UdpFragment) -> FragmentPush {
        self.last_active = fragment.received_at;

        if fragment.payload.is_empty()
            || fragment.end > MAX_IPV4_PAYLOAD_LEN
            || self.pieces.len() >= MAX_FRAGMENTS_PER_SET
        {
            return FragmentPush::RejectSet;
        }

        if fragment.more_frags && !fragment.payload.len().is_multiple_of(8) {
            return FragmentPush::RejectSet;
        }

        let insert_at = match piece_insert_position(&self.pieces, fragment.offset, fragment.end) {
            Some(insert_at) => insert_at,
            None => return FragmentPush::RejectSet,
        };

        if !fragment.more_frags
            && self
                .total_payload_len
                .replace(fragment.end)
                .is_some_and(|len| len != fragment.end)
        {
            return FragmentPush::RejectSet;
        }

        if fragment.offset == 0 {
            if fragment.payload.len() < UDP_HDR_LEN || self.first_fragment.is_some() {
                return FragmentPush::RejectSet;
            }
            self.first_fragment = Some(FirstFragment {
                eth_src: fragment.eth_src,
                eth_dst: fragment.eth_dst,
                src_ip: fragment.src_ip,
                dst_ip: fragment.dst_ip,
                ident: fragment.ident,
                hop_limit: fragment.hop_limit,
            });
        }

        self.pieces.insert(
            insert_at,
            FragmentPiece {
                start: fragment.offset,
                end: fragment.end,
                bytes: fragment.payload,
            },
        );

        FragmentPush::Accepted
    }

    /// Reassemble a complete UDP datagram if all fragments have arrived.
    fn try_reassemble(&self) -> Option<ReassembledUdpDatagram> {
        let total_payload_len = self.total_payload_len?;
        let first = self.first_fragment.as_ref()?;
        if !self.has_contiguous_payload(total_payload_len) {
            return None;
        }

        let mut payload = vec![0u8; total_payload_len];
        for piece in &self.pieces {
            payload[piece.start..piece.end].copy_from_slice(&piece.bytes);
        }

        let udp = UdpPacket::new_checked(payload.as_slice()).ok()?;
        if usize::from(udp.len()) != total_payload_len {
            return None;
        }

        let src = SocketAddr::new(IpAddr::V4(first.src_ip), udp.src_port());
        let dst = SocketAddr::new(IpAddr::V4(first.dst_ip), udp.dst_port());
        let frame = construct_reassembled_frame(first, &payload);

        Some(ReassembledUdpDatagram { frame, src, dst })
    }

    /// Return true when buffered pieces cover `[0, total_payload_len)` exactly.
    fn has_contiguous_payload(&self, total_payload_len: usize) -> bool {
        let mut cursor = 0;
        for piece in &self.pieces {
            if piece.start != cursor || piece.end <= piece.start {
                return false;
            }
            cursor = piece.end;
        }

        cursor == total_payload_len
    }
}

impl Ipv6FragmentSet {
    /// Build an empty fragment set.
    fn new(now: Instant) -> Self {
        Self {
            created_at: now,
            last_active: now,
            first_fragment: None,
            pieces: Vec::new(),
            total_payload_len: None,
        }
    }

    /// Insert one fragment into this set.
    fn push(&mut self, fragment: Ipv6UdpFragment) -> FragmentPush {
        self.last_active = fragment.received_at;

        if fragment.payload.is_empty()
            || fragment.end > MAX_IPV6_PAYLOAD_LEN
            || self.pieces.len() >= MAX_FRAGMENTS_PER_SET
        {
            return FragmentPush::RejectSet;
        }

        if fragment.more_frags && !fragment.payload.len().is_multiple_of(8) {
            return FragmentPush::RejectSet;
        }

        let insert_at = match piece_insert_position(&self.pieces, fragment.offset, fragment.end) {
            Some(insert_at) => insert_at,
            None => return FragmentPush::RejectSet,
        };

        if !fragment.more_frags
            && self
                .total_payload_len
                .replace(fragment.end)
                .is_some_and(|len| len != fragment.end)
        {
            return FragmentPush::RejectSet;
        }

        if fragment.offset == 0 {
            if fragment.payload.len() < UDP_HDR_LEN || self.first_fragment.is_some() {
                return FragmentPush::RejectSet;
            }
            self.first_fragment = Some(FirstIpv6Fragment {
                eth_src: fragment.eth_src,
                eth_dst: fragment.eth_dst,
                src_ip: fragment.src_ip,
                dst_ip: fragment.dst_ip,
                hop_limit: fragment.hop_limit,
            });
        }

        self.pieces.insert(
            insert_at,
            FragmentPiece {
                start: fragment.offset,
                end: fragment.end,
                bytes: fragment.payload,
            },
        );

        FragmentPush::Accepted
    }

    /// Reassemble a complete UDP datagram if all fragments have arrived.
    fn try_reassemble(&self) -> Option<ReassembledUdpDatagram> {
        let total_payload_len = self.total_payload_len?;
        let first = self.first_fragment.as_ref()?;
        if !self.has_contiguous_payload(total_payload_len) {
            return None;
        }

        let mut payload = vec![0u8; total_payload_len];
        for piece in &self.pieces {
            payload[piece.start..piece.end].copy_from_slice(&piece.bytes);
        }

        let udp = UdpPacket::new_checked(payload.as_slice()).ok()?;
        if usize::from(udp.len()) != total_payload_len {
            return None;
        }

        let src = SocketAddr::new(IpAddr::V6(first.src_ip), udp.src_port());
        let dst = SocketAddr::new(IpAddr::V6(first.dst_ip), udp.dst_port());
        let frame = construct_reassembled_ipv6_frame(first, &payload);

        Some(ReassembledUdpDatagram { frame, src, dst })
    }

    /// Return true when buffered pieces cover `[0, total_payload_len)` exactly.
    fn has_contiguous_payload(&self, total_payload_len: usize) -> bool {
        let mut cursor = 0;
        for piece in &self.pieces {
            if piece.start != cursor || piece.end <= piece.start {
                return false;
            }
            cursor = piece.end;
        }

        cursor == total_payload_len
    }
}

impl Ipv4UdpFragment {
    /// Build the fragment-set key shared by all pieces of the datagram.
    fn key(&self) -> Ipv4FragmentKey {
        Ipv4FragmentKey {
            src: self.src_ip,
            dst: self.dst_ip,
            ident: self.ident,
        }
    }
}

impl Ipv6UdpFragment {
    /// Build the fragment-set key shared by all pieces of the datagram.
    fn key(&self) -> Ipv6FragmentKey {
        Ipv6FragmentKey {
            src: self.src_ip,
            dst: self.dst_ip,
            ident: self.ident,
        }
    }
}

impl Ipv6FragmentHeader {
    /// Parse the full 8-byte IPv6 Fragment extension header.
    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < IPV6_FRAGMENT_HDR_LEN {
            return None;
        }

        let raw = u16::from_be_bytes([bytes[2], bytes[3]]);
        if bytes[1] != 0 || raw & 0x0006 != 0 {
            return None;
        }

        let offset_units = raw >> 3;
        Some(Self {
            next_header: IpProtocol::from(bytes[0]),
            offset: usize::from(offset_units) * 8,
            more_frags: raw & 0x0001 != 0,
            ident: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Return true when an IPv4 packet is a UDP fragment handled by this reassembler.
pub(crate) fn is_ipv4_udp_fragment(packet: &Ipv4Packet<&[u8]>) -> bool {
    packet.next_header() == IpProtocol::Udp && (packet.more_frags() || packet.frag_offset() != 0)
}

/// Return true when an IPv6 packet is a UDP fragment handled by this reassembler.
pub(crate) fn is_ipv6_udp_fragment(packet: &Ipv6Packet<&[u8]>) -> bool {
    let Some(fragment) = parse_ipv6_fragment_info(packet) else {
        return false;
    };

    fragment.header.next_header == IpProtocol::Udp
}

/// Return true when an IPv6 packet contains a Fragment header.
pub(crate) fn is_ipv6_fragment(packet: &Ipv6Packet<&[u8]>) -> bool {
    parse_ipv6_fragment_info(packet).is_some()
}

/// Parse a guest Ethernet frame as one IPv4 UDP fragment.
fn parse_ipv4_udp_fragment(frame: &[u8]) -> Option<Ipv4UdpFragment> {
    let eth = EthernetFrame::new_checked(frame).ok()?;
    if eth.ethertype() != EthernetProtocol::Ipv4 {
        return None;
    }

    let ipv4 = Ipv4Packet::new_checked(eth.payload()).ok()?;
    if !is_ipv4_udp_fragment(&ipv4) {
        return None;
    }

    let offset = usize::from(ipv4.frag_offset());
    let payload = ipv4.payload().to_vec();
    let end = offset.checked_add(payload.len())?;

    Some(Ipv4UdpFragment {
        eth_src: eth.src_addr(),
        eth_dst: eth.dst_addr(),
        src_ip: ipv4.src_addr(),
        dst_ip: ipv4.dst_addr(),
        ident: ipv4.ident(),
        hop_limit: ipv4.hop_limit(),
        offset,
        more_frags: ipv4.more_frags(),
        payload,
        end,
        received_at: Instant::now(),
    })
}

/// Parse a guest Ethernet frame as one directly-fragmented IPv6 UDP datagram piece.
fn parse_ipv6_udp_fragment(frame: &[u8]) -> Option<Ipv6UdpFragment> {
    let eth = EthernetFrame::new_checked(frame).ok()?;
    if eth.ethertype() != EthernetProtocol::Ipv6 {
        return None;
    }

    let ipv6 = Ipv6Packet::new_checked(eth.payload()).ok()?;
    let fragment = parse_ipv6_fragment_info(&ipv6)?;
    if fragment.header.next_header != IpProtocol::Udp {
        return None;
    }

    let payload = ipv6.payload();
    let fragment_payload = payload.get(fragment.payload_offset..)?.to_vec();
    let end = fragment.header.offset.checked_add(fragment_payload.len())?;

    Some(Ipv6UdpFragment {
        eth_src: eth.src_addr(),
        eth_dst: eth.dst_addr(),
        src_ip: ipv6.src_addr(),
        dst_ip: ipv6.dst_addr(),
        ident: fragment.header.ident,
        hop_limit: ipv6.hop_limit(),
        offset: fragment.header.offset,
        more_frags: fragment.header.more_frags,
        payload: fragment_payload,
        end,
        received_at: Instant::now(),
    })
}

/// Parse the supported IPv6 path to a Fragment header.
fn parse_ipv6_fragment_info(packet: &Ipv6Packet<&[u8]>) -> Option<Ipv6FragmentInfo> {
    let payload = packet.payload();
    let mut next_header = packet.next_header();
    let mut offset = 0usize;

    for _ in 0..=MAX_IPV6_EXTENSION_HEADERS {
        if next_header == IpProtocol::Ipv6Frag {
            let header_end = offset.checked_add(IPV6_FRAGMENT_HDR_LEN)?;
            let header_bytes = payload.get(offset..header_end)?;
            let header = Ipv6FragmentHeader::parse(header_bytes)?;
            return Some(Ipv6FragmentInfo {
                header,
                payload_offset: header_end,
            });
        }

        if !is_ipv6_pre_fragment_extension(next_header) {
            return None;
        }

        let current_header = next_header;
        let extension = payload.get(offset..)?;
        if extension.len() < 2 {
            return None;
        }

        next_header = IpProtocol::from(extension[0]);
        let extension_len = ipv6_extension_header_len(current_header, extension)?;
        offset = offset.checked_add(extension_len)?;
    }

    None
}

/// Return true for extension headers this relay can safely skip before Fragment.
fn is_ipv6_pre_fragment_extension(protocol: IpProtocol) -> bool {
    matches!(
        protocol,
        IpProtocol::HopByHop | IpProtocol::Ipv6Route | IpProtocol::IpSecAh | IpProtocol::Ipv6Opts
    )
}

/// Return the byte length of a supported IPv6 extension header.
fn ipv6_extension_header_len(protocol: IpProtocol, bytes: &[u8]) -> Option<usize> {
    let payload_len = usize::from(*bytes.get(1)?);
    let len = match protocol {
        // AH's length unit is 32-bit words, not the 8-octet Hdr Ext Len used
        // by Hop-by-Hop, Routing, and Destination Options.
        IpProtocol::IpSecAh => payload_len.checked_add(2)?.checked_mul(4)?,
        _ => payload_len.checked_add(1)?.checked_mul(8)?,
    };
    (len <= bytes.len()).then_some(len)
}

/// Construct a normal, unfragmented Ethernet + IPv4 + UDP frame.
fn construct_reassembled_frame(first: &FirstFragment, payload: &[u8]) -> Vec<u8> {
    let ip_total_len = IPV4_HDR_LEN + payload.len();
    let mut frame = vec![0u8; ETH_HDR_LEN + ip_total_len];

    {
        let mut eth = EthernetFrame::new_unchecked(&mut frame);
        EthernetRepr {
            src_addr: first.eth_src,
            dst_addr: first.eth_dst,
            ethertype: EthernetProtocol::Ipv4,
        }
        .emit(&mut eth);
    }

    {
        let mut ip = Ipv4Packet::new_unchecked(&mut frame[ETH_HDR_LEN..]);
        ip.set_version(4);
        ip.set_header_len(IPV4_HDR_LEN as u8);
        ip.set_total_len(ip_total_len as u16);
        ip.set_ident(first.ident);
        ip.clear_flags();
        ip.set_hop_limit(first.hop_limit);
        ip.set_next_header(IpProtocol::Udp);
        ip.set_src_addr(first.src_ip);
        ip.set_dst_addr(first.dst_ip);
        ip.payload_mut().copy_from_slice(payload);
        ip.fill_checksum();
    }

    frame
}

/// Construct a normal, unfragmented Ethernet + IPv6 + UDP frame.
fn construct_reassembled_ipv6_frame(first: &FirstIpv6Fragment, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; ETH_HDR_LEN + IPV6_HDR_LEN + payload.len()];

    {
        let mut eth = EthernetFrame::new_unchecked(&mut frame);
        EthernetRepr {
            src_addr: first.eth_src,
            dst_addr: first.eth_dst,
            ethertype: EthernetProtocol::Ipv6,
        }
        .emit(&mut eth);
    }

    {
        let mut ip = Ipv6Packet::new_unchecked(&mut frame[ETH_HDR_LEN..]);
        ip.set_version(6);
        ip.set_payload_len(payload.len() as u16);
        ip.set_next_header(IpProtocol::Udp);
        ip.set_hop_limit(first.hop_limit);
        ip.set_src_addr(first.src_ip);
        ip.set_dst_addr(first.dst_ip);
        ip.payload_mut().copy_from_slice(payload);
    }

    frame
}

/// Return whether two half-open byte ranges overlap.
fn ranges_overlap(a_start: usize, a_end: usize, b_start: usize, b_end: usize) -> bool {
    a_start < b_end && b_start < a_end
}

/// Find the sorted insertion point for a new fragment piece.
fn piece_insert_position(pieces: &[FragmentPiece], start: usize, end: usize) -> Option<usize> {
    if end <= start {
        return None;
    }

    let insert_at = match pieces.binary_search_by_key(&start, |piece| piece.start) {
        Ok(_) => return None,
        Err(insert_at) => insert_at,
    };

    if insert_at > 0 {
        let previous = &pieces[insert_at - 1];
        if ranges_overlap(start, end, previous.start, previous.end) {
            return None;
        }
    }

    if let Some(next) = pieces.get(insert_at)
        && ranges_overlap(start, end, next.start, next.end)
    {
        return None;
    }

    Some(insert_at)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use smoltcp::wire::{EthernetAddress, UdpPacket};

    fn build_fragment(ident: u16, offset: usize, more_frags: bool, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; ETH_HDR_LEN + IPV4_HDR_LEN + payload.len()];

        {
            let mut eth = EthernetFrame::new_unchecked(&mut frame);
            EthernetRepr {
                src_addr: EthernetAddress([0x02, 0, 0, 0, 0, 2]),
                dst_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
                ethertype: EthernetProtocol::Ipv4,
            }
            .emit(&mut eth);
        }

        {
            let mut ip = Ipv4Packet::new_unchecked(&mut frame[ETH_HDR_LEN..]);
            ip.set_version(4);
            ip.set_header_len(IPV4_HDR_LEN as u8);
            ip.set_total_len((IPV4_HDR_LEN + payload.len()) as u16);
            ip.set_ident(ident);
            ip.clear_flags();
            ip.set_more_frags(more_frags);
            ip.set_frag_offset(offset as u16);
            ip.set_hop_limit(64);
            ip.set_next_header(IpProtocol::Udp);
            ip.set_src_addr(Ipv4Addr::new(100, 96, 0, 2));
            ip.set_dst_addr(Ipv4Addr::new(203, 0, 113, 10));
            ip.payload_mut().copy_from_slice(payload);
            ip.fill_checksum();
        }

        frame
    }

    fn build_ipv6_fragment(ident: u32, offset: usize, more_frags: bool, payload: &[u8]) -> Vec<u8> {
        let mut frame =
            vec![0u8; ETH_HDR_LEN + IPV6_HDR_LEN + IPV6_FRAGMENT_HDR_LEN + payload.len()];

        {
            let mut eth = EthernetFrame::new_unchecked(&mut frame);
            EthernetRepr {
                src_addr: EthernetAddress([0x02, 0, 0, 0, 0, 2]),
                dst_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
                ethertype: EthernetProtocol::Ipv6,
            }
            .emit(&mut eth);
        }

        {
            let mut ip = Ipv6Packet::new_unchecked(&mut frame[ETH_HDR_LEN..]);
            ip.set_version(6);
            ip.set_payload_len((IPV6_FRAGMENT_HDR_LEN + payload.len()) as u16);
            ip.set_next_header(IpProtocol::Ipv6Frag);
            ip.set_hop_limit(64);
            ip.set_src_addr("fd42:6d73:62::2".parse::<Ipv6Addr>().unwrap());
            ip.set_dst_addr("2001:db8::10".parse::<Ipv6Addr>().unwrap());
        }

        let fragment = &mut frame[ETH_HDR_LEN + IPV6_HDR_LEN..][..IPV6_FRAGMENT_HDR_LEN];
        fragment[0] = IpProtocol::Udp.into();
        let offset_units = (offset / 8) as u16;
        let raw = (offset_units << 3) | u16::from(more_frags);
        fragment[2..4].copy_from_slice(&raw.to_be_bytes());
        fragment[4..8].copy_from_slice(&ident.to_be_bytes());
        frame[ETH_HDR_LEN + IPV6_HDR_LEN + IPV6_FRAGMENT_HDR_LEN..].copy_from_slice(payload);

        frame
    }

    fn build_ipv6_fragment_after_hop_by_hop(
        ident: u32,
        offset: usize,
        more_frags: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        const HOP_BY_HOP_HDR_LEN: usize = 8;

        let mut frame = vec![
            0u8;
            ETH_HDR_LEN
                + IPV6_HDR_LEN
                + HOP_BY_HOP_HDR_LEN
                + IPV6_FRAGMENT_HDR_LEN
                + payload.len()
        ];

        {
            let mut eth = EthernetFrame::new_unchecked(&mut frame);
            EthernetRepr {
                src_addr: EthernetAddress([0x02, 0, 0, 0, 0, 2]),
                dst_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
                ethertype: EthernetProtocol::Ipv6,
            }
            .emit(&mut eth);
        }

        {
            let mut ip = Ipv6Packet::new_unchecked(&mut frame[ETH_HDR_LEN..]);
            ip.set_version(6);
            ip.set_payload_len((HOP_BY_HOP_HDR_LEN + IPV6_FRAGMENT_HDR_LEN + payload.len()) as u16);
            ip.set_next_header(IpProtocol::HopByHop);
            ip.set_hop_limit(64);
            ip.set_src_addr("fd42:6d73:62::2".parse::<Ipv6Addr>().unwrap());
            ip.set_dst_addr("2001:db8::10".parse::<Ipv6Addr>().unwrap());
        }

        let hop_by_hop = &mut frame[ETH_HDR_LEN + IPV6_HDR_LEN..][..HOP_BY_HOP_HDR_LEN];
        hop_by_hop[0] = IpProtocol::Ipv6Frag.into();
        hop_by_hop[1] = 0; // 8-byte extension header.

        let fragment_start = ETH_HDR_LEN + IPV6_HDR_LEN + HOP_BY_HOP_HDR_LEN;
        let fragment = &mut frame[fragment_start..][..IPV6_FRAGMENT_HDR_LEN];
        fragment[0] = IpProtocol::Udp.into();
        let offset_units = (offset / 8) as u16;
        let raw = (offset_units << 3) | u16::from(more_frags);
        fragment[2..4].copy_from_slice(&raw.to_be_bytes());
        fragment[4..8].copy_from_slice(&ident.to_be_bytes());
        frame[fragment_start + IPV6_FRAGMENT_HDR_LEN..].copy_from_slice(payload);

        frame
    }

    fn udp_payload(payload: &[u8]) -> Vec<u8> {
        let mut udp = vec![0u8; UDP_HDR_LEN + payload.len()];
        let mut packet = UdpPacket::new_unchecked(&mut udp);
        packet.set_src_port(12345);
        packet.set_dst_port(9999);
        packet.set_len((UDP_HDR_LEN + payload.len()) as u16);
        packet.set_checksum(0);
        packet.payload_mut().copy_from_slice(payload);
        udp
    }

    #[test]
    fn reassembles_two_ipv4_udp_fragments() {
        let full_payload = udp_payload(&[b'x'; 24]);
        let first = build_fragment(7, 0, true, &full_payload[..16]);
        let second = build_fragment(7, 16, false, &full_payload[16..]);

        let mut reassembler = Ipv4UdpFragmentReassembler::new();
        assert!(reassembler.push(&first).is_none());
        let datagram = reassembler.push(&second).expect("complete datagram");

        assert_eq!(
            datagram.src,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 96, 0, 2)), 12345)
        );
        assert_eq!(
            datagram.dst,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 9999)
        );

        let eth = EthernetFrame::new_checked(datagram.frame.as_slice()).unwrap();
        let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
        assert!(!ip.more_frags());
        assert_eq!(ip.frag_offset(), 0);

        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!(udp.payload(), &[b'x'; 24]);
        assert_eq!(reassembler.len(), 0);
    }

    #[test]
    fn rejects_overlapping_fragments() {
        let full_payload = udp_payload(&[b'x'; 24]);
        let first = build_fragment(7, 0, true, &full_payload[..16]);
        let overlap = build_fragment(7, 8, false, &full_payload[8..]);

        let mut reassembler = Ipv4UdpFragmentReassembler::new();
        assert!(reassembler.push(&first).is_none());
        assert!(reassembler.push(&overlap).is_none());
        assert_eq!(reassembler.len(), 0);
    }

    #[test]
    fn waits_for_missing_middle_fragment() {
        let full_payload = udp_payload(&[b'x'; 32]);
        let first = build_fragment(7, 0, true, &full_payload[..16]);
        let last = build_fragment(7, 24, false, &full_payload[24..]);

        let mut reassembler = Ipv4UdpFragmentReassembler::new();
        assert!(reassembler.push(&first).is_none());
        assert!(reassembler.push(&last).is_none());
        assert_eq!(reassembler.len(), 1);
    }

    #[test]
    fn reassembles_two_ipv6_udp_fragments() {
        let full_payload = udp_payload(&[b'x'; 24]);
        let first = build_ipv6_fragment(7, 0, true, &full_payload[..16]);
        let second = build_ipv6_fragment(7, 16, false, &full_payload[16..]);

        let mut reassembler = Ipv6UdpFragmentReassembler::new();
        assert!(reassembler.push(&first).is_none());
        let datagram = reassembler.push(&second).expect("complete datagram");

        assert_eq!(
            datagram.src,
            SocketAddr::new(IpAddr::V6("fd42:6d73:62::2".parse().unwrap()), 12345)
        );
        assert_eq!(
            datagram.dst,
            SocketAddr::new(IpAddr::V6("2001:db8::10".parse().unwrap()), 9999)
        );

        let eth = EthernetFrame::new_checked(datagram.frame.as_slice()).unwrap();
        assert_eq!(eth.ethertype(), EthernetProtocol::Ipv6);
        let ip = Ipv6Packet::new_checked(eth.payload()).unwrap();
        assert_eq!(ip.next_header(), IpProtocol::Udp);

        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!(udp.payload(), &[b'x'; 24]);
        assert_eq!(reassembler.len(), 0);
    }

    #[test]
    fn reassembles_ipv6_udp_fragment_after_hop_by_hop_header() {
        let full_payload = udp_payload(&[b'x'; 24]);
        let first = build_ipv6_fragment_after_hop_by_hop(7, 0, true, &full_payload[..16]);
        let second = build_ipv6_fragment_after_hop_by_hop(7, 16, false, &full_payload[16..]);

        let mut reassembler = Ipv6UdpFragmentReassembler::new();
        assert!(reassembler.push(&first).is_none());
        let datagram = reassembler.push(&second).expect("complete datagram");

        let eth = EthernetFrame::new_checked(datagram.frame.as_slice()).unwrap();
        assert_eq!(eth.ethertype(), EthernetProtocol::Ipv6);
        let ip = Ipv6Packet::new_checked(eth.payload()).unwrap();
        assert_eq!(ip.next_header(), IpProtocol::Udp);

        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!(udp.payload(), &[b'x'; 24]);
        assert_eq!(reassembler.len(), 0);
    }

    #[test]
    fn rejects_overlapping_ipv6_fragments() {
        let full_payload = udp_payload(&[b'x'; 24]);
        let first = build_ipv6_fragment(7, 0, true, &full_payload[..16]);
        let overlap = build_ipv6_fragment(7, 8, false, &full_payload[8..]);

        let mut reassembler = Ipv6UdpFragmentReassembler::new();
        assert!(reassembler.push(&first).is_none());
        assert!(reassembler.push(&overlap).is_none());
        assert_eq!(reassembler.len(), 0);
    }

    #[test]
    fn rejects_ipv6_fragment_reserved_bits() {
        let full_payload = udp_payload(&[b'x'; 8]);
        let mut fragment = build_ipv6_fragment(7, 0, false, &full_payload);
        fragment[ETH_HDR_LEN + IPV6_HDR_LEN + 1] = 1;

        let mut reassembler = Ipv6UdpFragmentReassembler::new();
        assert!(reassembler.push(&fragment).is_none());
        assert_eq!(reassembler.len(), 0);
    }

    #[test]
    fn cleanup_expires_sets_by_absolute_lifetime() {
        let full_payload = udp_payload(&[b'x'; 24]);
        let first = build_fragment(7, 0, true, &full_payload[..16]);

        let mut reassembler = Ipv4UdpFragmentReassembler::new();
        assert!(reassembler.push(&first).is_none());

        let key = Ipv4FragmentKey {
            src: Ipv4Addr::new(100, 96, 0, 2),
            dst: Ipv4Addr::new(203, 0, 113, 10),
            ident: 7,
        };
        let set = reassembler.sets.get_mut(&key).unwrap();
        set.created_at = Instant::now() - FRAGMENT_TIMEOUT - Duration::from_secs(1);
        set.last_active = Instant::now();

        reassembler.cleanup_expired();
        assert_eq!(reassembler.len(), 0);
    }
}
