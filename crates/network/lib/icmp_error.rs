//! Synthetic ICMP error frame construction for relay-owned IP edge behavior.
//!
//! The UDP relay strips guest IP framing before sending host UDP datagrams.
//! When the host reports a path-MTU problem, the relay must therefore act as
//! the IP edge and send the guest an ICMP too-big error itself.

use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, Icmpv4DstUnreachable,
    Icmpv4Message, Icmpv4Packet, Icmpv6Message, Icmpv6Packet, IpProtocol, Ipv4Packet, Ipv6Packet,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Ethernet header length.
const ETH_HDR_LEN: usize = 14;

/// IPv4 header length used for synthesized outer ICMP packets.
const IPV4_HDR_LEN: usize = 20;

/// IPv6 header length.
const IPV6_HDR_LEN: usize = 40;

/// ICMP error header length before the quoted offending packet.
const ICMP_ERROR_HDR_LEN: usize = 8;

/// IPv6 error packets must fit within the IPv6 minimum MTU.
const IPV6_MIN_MTU: usize = 1280;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Construct an ICMP Packet Too Big / Fragmentation Needed frame for the guest.
///
/// `original_ip_packet` is the guest packet as seen on the virtual wire, without the Ethernet
/// header. The returned frame is addressed from the gateway MAC to the guest MAC, while the IP
/// source is the original destination so the guest attributes the PMTU to the peer it dialed.
pub(crate) fn construct_packet_too_big(
    original_ip_packet: &[u8],
    next_hop_mtu: u32,
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
) -> Option<Vec<u8>> {
    match original_ip_packet.first()? >> 4 {
        4 => construct_icmpv4_fragmentation_needed(
            original_ip_packet,
            next_hop_mtu,
            gateway_mac,
            guest_mac,
        ),
        6 => construct_icmpv6_packet_too_big(
            original_ip_packet,
            next_hop_mtu,
            gateway_mac,
            guest_mac,
        ),
        _ => None,
    }
}

/// Return the IP packet payload from an Ethernet frame.
pub(crate) fn ethernet_ip_payload(frame: &[u8]) -> Option<&[u8]> {
    let eth = EthernetFrame::new_checked(frame).ok()?;
    match eth.ethertype() {
        EthernetProtocol::Ipv4 | EthernetProtocol::Ipv6 => Some(eth.payload()),
        _ => None,
    }
}

/// Construct an IPv4 Destination Unreachable / Fragmentation Needed frame.
fn construct_icmpv4_fragmentation_needed(
    original_ip_packet: &[u8],
    next_hop_mtu: u32,
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
) -> Option<Vec<u8>> {
    let original = Ipv4Packet::new_checked(original_ip_packet).ok()?;
    let original_header_len = original.header_len() as usize;
    if original_ip_packet.len() < original_header_len || original_header_len < IPV4_HDR_LEN {
        return None;
    }

    let original_total_len = usize::from(original.total_len());
    let quoted_len = original_ip_packet
        .len()
        .min(original_total_len)
        .min(original_header_len + 8);
    if quoted_len < original_header_len {
        return None;
    }

    let icmp_len = ICMP_ERROR_HDR_LEN + quoted_len;
    let ip_total_len = IPV4_HDR_LEN + icmp_len;
    let frame_len = ETH_HDR_LEN + ip_total_len;
    let mut buf = vec![0u8; frame_len];

    let mut eth_frame = EthernetFrame::new_unchecked(&mut buf);
    EthernetRepr {
        src_addr: gateway_mac,
        dst_addr: guest_mac,
        ethertype: EthernetProtocol::Ipv4,
    }
    .emit(&mut eth_frame);

    {
        let mut ip = Ipv4Packet::new_unchecked(&mut buf[ETH_HDR_LEN..]);
        ip.set_version(4);
        ip.set_header_len(IPV4_HDR_LEN as u8);
        ip.set_total_len(ip_total_len as u16);
        ip.clear_flags();
        ip.set_hop_limit(64);
        ip.set_next_header(IpProtocol::Icmp);
        ip.set_src_addr(original.dst_addr());
        ip.set_dst_addr(original.src_addr());
        ip.fill_checksum();
    }

    let icmp_buf = &mut buf[ETH_HDR_LEN + IPV4_HDR_LEN..];
    {
        let mut icmp = Icmpv4Packet::new_unchecked(&mut *icmp_buf);
        icmp.set_msg_type(Icmpv4Message::DstUnreachable);
        icmp.set_msg_code(Icmpv4DstUnreachable::FragRequired.into());
        icmp.set_checksum(0);
    }
    icmp_buf[4..6].copy_from_slice(&0u16.to_be_bytes());
    icmp_buf[6..8].copy_from_slice(&ipv4_next_hop_mtu_field(next_hop_mtu).to_be_bytes());
    icmp_buf[ICMP_ERROR_HDR_LEN..].copy_from_slice(&original_ip_packet[..quoted_len]);

    Icmpv4Packet::new_unchecked(icmp_buf).fill_checksum();

    Some(buf)
}

/// Construct an IPv6 ICMPv6 Packet Too Big frame.
fn construct_icmpv6_packet_too_big(
    original_ip_packet: &[u8],
    next_hop_mtu: u32,
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
) -> Option<Vec<u8>> {
    if original_ip_packet.len() < IPV6_HDR_LEN {
        return None;
    }

    let original = Ipv6Packet::new_checked(original_ip_packet).ok()?;
    let max_quote_len = IPV6_MIN_MTU - IPV6_HDR_LEN - ICMP_ERROR_HDR_LEN;
    let original_total_len = IPV6_HDR_LEN + usize::from(original.payload_len());
    let quoted_len = original_ip_packet
        .len()
        .min(original_total_len)
        .min(max_quote_len);

    let icmp_len = ICMP_ERROR_HDR_LEN + quoted_len;
    let frame_len = ETH_HDR_LEN + IPV6_HDR_LEN + icmp_len;
    let mut buf = vec![0u8; frame_len];

    let mut eth_frame = EthernetFrame::new_unchecked(&mut buf);
    EthernetRepr {
        src_addr: gateway_mac,
        dst_addr: guest_mac,
        ethertype: EthernetProtocol::Ipv6,
    }
    .emit(&mut eth_frame);

    {
        let mut ip = Ipv6Packet::new_unchecked(&mut buf[ETH_HDR_LEN..]);
        ip.set_version(6);
        ip.set_payload_len(icmp_len as u16);
        ip.set_next_header(IpProtocol::Icmpv6);
        ip.set_hop_limit(64);
        ip.set_src_addr(original.dst_addr());
        ip.set_dst_addr(original.src_addr());
    }

    let src_addr = original.dst_addr();
    let dst_addr = original.src_addr();
    let icmp_buf = &mut buf[ETH_HDR_LEN + IPV6_HDR_LEN..];
    {
        let mut icmp = Icmpv6Packet::new_unchecked(&mut *icmp_buf);
        icmp.set_msg_type(Icmpv6Message::PktTooBig);
        icmp.set_msg_code(0);
        icmp.set_pkt_too_big_mtu(next_hop_mtu);
        icmp.set_checksum(0);
    }
    icmp_buf[ICMP_ERROR_HDR_LEN..].copy_from_slice(&original_ip_packet[..quoted_len]);
    Icmpv6Packet::new_unchecked(icmp_buf).fill_checksum(&src_addr, &dst_addr);

    Some(buf)
}

/// Encode the RFC 1191 IPv4 next-hop MTU field.
fn ipv4_next_hop_mtu_field(next_hop_mtu: u32) -> u16 {
    next_hop_mtu.min(u32::from(u16::MAX)) as u16
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, Ipv6Addr};

    use smoltcp::wire::{
        Icmpv4DstUnreachable, Icmpv4Message, Icmpv6Message, IpProtocol, Ipv4Packet, Ipv6Packet,
        UdpPacket,
    };

    fn gateway_mac() -> EthernetAddress {
        EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    }

    fn guest_mac() -> EthernetAddress {
        EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02])
    }

    fn build_ipv4_udp_packet(payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let ip_total_len = IPV4_HDR_LEN + udp_len;
        let mut buf = vec![0u8; ip_total_len];

        {
            let mut ip = Ipv4Packet::new_unchecked(&mut buf);
            ip.set_version(4);
            ip.set_header_len(IPV4_HDR_LEN as u8);
            ip.set_total_len(ip_total_len as u16);
            ip.clear_flags();
            ip.set_dont_frag(true);
            ip.set_hop_limit(64);
            ip.set_next_header(IpProtocol::Udp);
            ip.set_src_addr(Ipv4Addr::new(100, 96, 0, 2));
            ip.set_dst_addr(Ipv4Addr::new(203, 0, 113, 10));
            ip.fill_checksum();
        }

        let mut udp = UdpPacket::new_unchecked(&mut buf[IPV4_HDR_LEN..]);
        udp.set_src_port(12345);
        udp.set_dst_port(443);
        udp.set_len(udp_len as u16);
        udp.set_checksum(0);
        udp.payload_mut().copy_from_slice(payload);

        buf
    }

    fn build_ipv6_udp_packet(payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut buf = vec![0u8; IPV6_HDR_LEN + udp_len];
        let src = "fd42:6d73:62::2".parse::<Ipv6Addr>().unwrap();
        let dst = "2001:db8::10".parse::<Ipv6Addr>().unwrap();

        {
            let mut ip = Ipv6Packet::new_unchecked(&mut buf);
            ip.set_version(6);
            ip.set_payload_len(udp_len as u16);
            ip.set_next_header(IpProtocol::Udp);
            ip.set_hop_limit(64);
            ip.set_src_addr(src);
            ip.set_dst_addr(dst);
        }

        let mut udp = UdpPacket::new_unchecked(&mut buf[IPV6_HDR_LEN..]);
        udp.set_src_port(12345);
        udp.set_dst_port(443);
        udp.set_len(udp_len as u16);
        udp.payload_mut().copy_from_slice(payload);
        udp.fill_checksum(
            &smoltcp::wire::IpAddress::from(src),
            &smoltcp::wire::IpAddress::from(dst),
        );

        buf
    }

    #[test]
    fn constructs_ipv4_fragmentation_needed_with_next_hop_mtu() {
        let original = build_ipv4_udp_packet(b"hello world");
        let frame = construct_packet_too_big(&original, 1280, gateway_mac(), guest_mac()).unwrap();

        let eth = EthernetFrame::new_checked(&frame).unwrap();
        assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);
        assert_eq!(eth.src_addr(), gateway_mac());
        assert_eq!(eth.dst_addr(), guest_mac());

        let ip = Ipv4Packet::new_checked(eth.payload()).unwrap();
        assert_eq!(ip.src_addr(), Ipv4Addr::new(203, 0, 113, 10));
        assert_eq!(ip.dst_addr(), Ipv4Addr::new(100, 96, 0, 2));
        assert_eq!(ip.next_header(), IpProtocol::Icmp);

        let icmp = Icmpv4Packet::new_checked(ip.payload()).unwrap();
        assert_eq!(icmp.msg_type(), Icmpv4Message::DstUnreachable);
        assert_eq!(
            icmp.msg_code(),
            u8::from(Icmpv4DstUnreachable::FragRequired)
        );
        assert!(icmp.verify_checksum());
        assert_eq!(u16::from_be_bytes([ip.payload()[6], ip.payload()[7]]), 1280);
        assert_eq!(
            &ip.payload()[ICMP_ERROR_HDR_LEN..],
            &original[..IPV4_HDR_LEN + 8]
        );
    }

    #[test]
    fn constructs_ipv6_packet_too_big_with_mtu() {
        let original = build_ipv6_udp_packet(b"hello ipv6");
        let frame = construct_packet_too_big(&original, 1280, gateway_mac(), guest_mac()).unwrap();

        let eth = EthernetFrame::new_checked(&frame).unwrap();
        assert_eq!(eth.ethertype(), EthernetProtocol::Ipv6);
        assert_eq!(eth.src_addr(), gateway_mac());
        assert_eq!(eth.dst_addr(), guest_mac());

        let ip = Ipv6Packet::new_checked(eth.payload()).unwrap();
        assert_eq!(ip.src_addr(), "2001:db8::10".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            ip.dst_addr(),
            "fd42:6d73:62::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(ip.next_header(), IpProtocol::Icmpv6);

        let icmp = Icmpv6Packet::new_checked(ip.payload()).unwrap();
        assert_eq!(icmp.msg_type(), Icmpv6Message::PktTooBig);
        assert_eq!(icmp.pkt_too_big_mtu(), 1280);
        assert!(icmp.verify_checksum(&ip.src_addr(), &ip.dst_addr()));
        assert_eq!(&icmp.payload()[..original.len()], original.as_slice());
    }
}
