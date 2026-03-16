//! Unified frame parser wrapping `etherparse::SlicedPacket`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use etherparse::{IpNumber, SlicedPacket};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// DNS port.
pub const DNS_PORT: u16 = 53;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A parsed ethernet frame with convenient accessors for policy matching.
///
/// Wraps `etherparse::SlicedPacket` for zero-copy header inspection.
/// Supports Ethernet II, ARP, IPv4, IPv6, TCP, UDP, ICMPv4, and
/// ICMPv6 (including NDP) via etherparse.
pub struct ParsedFrame<'a> {
    /// The raw frame bytes.
    raw: &'a [u8],

    /// Parsed header slices from etherparse.
    sliced: SlicedPacket<'a>,
}

/// IP protocol number for policy matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    /// TCP (6).
    Tcp,

    /// UDP (17).
    Udp,

    /// ICMPv4 (1).
    Icmpv4,

    /// ICMPv6 (58).
    Icmpv6,

    /// Other protocol number.
    Other(u8),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a> ParsedFrame<'a> {
    /// Parse an ethernet frame. Returns `None` if the frame is malformed.
    pub fn parse(raw: &'a [u8]) -> Option<Self> {
        let sliced = SlicedPacket::from_ethernet(raw).ok()?;
        Some(Self { raw, sliced })
    }

    /// Get the raw frame bytes.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Get the inner `SlicedPacket` for direct access to etherparse types.
    pub fn sliced(&self) -> &SlicedPacket<'a> {
        &self.sliced
    }

    /// Get the EtherType as a raw `u16`.
    pub fn ethertype(&self) -> Option<u16> {
        match &self.sliced.link {
            Some(etherparse::LinkSlice::Ethernet2(header)) => Some(header.ether_type().0),
            _ => None,
        }
    }

    /// Returns `true` if the frame is an ARP packet.
    pub fn is_arp(&self) -> bool {
        matches!(&self.sliced.net, Some(etherparse::NetSlice::Arp(_)))
    }

    /// Returns `true` if the frame is an IPv6 NDP (Neighbor Discovery) message.
    ///
    /// NDP uses ICMPv6 types 133–137: Router Solicitation, Router Advertisement,
    /// Neighbor Solicitation, Neighbor Advertisement, and Redirect.
    pub fn is_ndp(&self) -> bool {
        match &self.sliced.transport {
            Some(etherparse::TransportSlice::Icmpv6(icmpv6)) => {
                let icmp_type = icmpv6.type_u8();
                (133..=137).contains(&icmp_type)
            }
            _ => false,
        }
    }

    /// Get the source MAC address (6 bytes).
    pub fn src_mac(&self) -> Option<[u8; 6]> {
        match &self.sliced.link {
            Some(etherparse::LinkSlice::Ethernet2(header)) => Some(header.source()),
            _ => None,
        }
    }

    /// Get the destination MAC address (6 bytes).
    pub fn dst_mac(&self) -> Option<[u8; 6]> {
        match &self.sliced.link {
            Some(etherparse::LinkSlice::Ethernet2(header)) => Some(header.destination()),
            _ => None,
        }
    }

    /// Get the source IP address.
    pub fn src_ip(&self) -> Option<IpAddr> {
        match &self.sliced.net {
            Some(etherparse::NetSlice::Ipv4(h)) => {
                Some(IpAddr::V4(Ipv4Addr::from(h.header().source())))
            }
            Some(etherparse::NetSlice::Ipv6(h)) => {
                Some(IpAddr::V6(Ipv6Addr::from(h.header().source())))
            }
            _ => None,
        }
    }

    /// Get the destination IP address.
    pub fn dst_ip(&self) -> Option<IpAddr> {
        match &self.sliced.net {
            Some(etherparse::NetSlice::Ipv4(h)) => {
                Some(IpAddr::V4(Ipv4Addr::from(h.header().destination())))
            }
            Some(etherparse::NetSlice::Ipv6(h)) => {
                Some(IpAddr::V6(Ipv6Addr::from(h.header().destination())))
            }
            _ => None,
        }
    }

    /// Get the IP protocol.
    pub fn protocol(&self) -> Option<IpProtocol> {
        match &self.sliced.net {
            Some(etherparse::NetSlice::Ipv4(h)) => {
                Some(ip_number_to_protocol(h.header().protocol()))
            }
            Some(etherparse::NetSlice::Ipv6(h)) => {
                // The payload's ip_number reflects the final next-header after
                // all extension headers have been traversed.
                Some(ip_number_to_protocol(h.payload().ip_number))
            }
            _ => None,
        }
    }

    /// Get the source port (TCP or UDP).
    pub fn src_port(&self) -> Option<u16> {
        match &self.sliced.transport {
            Some(etherparse::TransportSlice::Tcp(h)) => Some(h.source_port()),
            Some(etherparse::TransportSlice::Udp(h)) => Some(h.source_port()),
            _ => None,
        }
    }

    /// Get the destination port (TCP or UDP).
    pub fn dst_port(&self) -> Option<u16> {
        match &self.sliced.transport {
            Some(etherparse::TransportSlice::Tcp(h)) => Some(h.destination_port()),
            Some(etherparse::TransportSlice::Udp(h)) => Some(h.destination_port()),
            _ => None,
        }
    }

    /// Returns `true` if this is a DNS packet (UDP or TCP to/from port 53).
    pub fn is_dns(&self) -> bool {
        self.dst_port() == Some(DNS_PORT) || self.src_port() == Some(DNS_PORT)
    }

    /// Get the transport-layer payload (e.g. DNS wire data).
    ///
    /// For TCP/UDP, returns the data after the transport header.
    /// For other protocols, returns the IP payload.
    pub fn payload(&self) -> &'a [u8] {
        match &self.sliced.transport {
            Some(etherparse::TransportSlice::Tcp(h)) => h.payload(),
            Some(etherparse::TransportSlice::Udp(h)) => h.payload(),
            _ => {
                // Fall back to IP payload for non-TCP/UDP.
                match &self.sliced.net {
                    Some(etherparse::NetSlice::Ipv4(h)) => h.payload().payload,
                    Some(etherparse::NetSlice::Ipv6(h)) => h.payload().payload,
                    _ => &[],
                }
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn ip_number_to_protocol(n: IpNumber) -> IpProtocol {
    match n {
        IpNumber::TCP => IpProtocol::Tcp,
        IpNumber::UDP => IpProtocol::Udp,
        IpNumber::ICMP => IpProtocol::Icmpv4,
        IpNumber::IPV6_ICMP => IpProtocol::Icmpv6,
        other => IpProtocol::Other(other.0),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid Ethernet + IPv4 + UDP frame.
    fn build_udp_frame(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use etherparse::PacketBuilder;

        let builder = PacketBuilder::ethernet2(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01], // src mac
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02], // dst mac
        )
        .ipv4(src_ip, dst_ip, 64)
        .udp(src_port, dst_port);

        let mut buf = Vec::new();
        builder.write(&mut buf, payload).unwrap();
        buf
    }

    /// Build a minimal valid Ethernet + IPv4 + TCP frame.
    fn build_tcp_frame(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        use etherparse::PacketBuilder;

        let builder = PacketBuilder::ethernet2(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        )
        .ipv4(src_ip, dst_ip, 64)
        .tcp(src_port, dst_port, 0, 65535);

        let mut buf = Vec::new();
        builder.write(&mut buf, &[]).unwrap();
        buf
    }

    #[test]
    fn test_parse_udp_frame() {
        let frame = build_udp_frame([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, b"hello");
        let parsed = ParsedFrame::parse(&frame).unwrap();

        assert_eq!(
            parsed.src_ip(),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            parsed.dst_ip(),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
        assert_eq!(parsed.src_port(), Some(12345));
        assert_eq!(parsed.dst_port(), Some(80));
        assert_eq!(parsed.protocol(), Some(IpProtocol::Udp));
        assert!(!parsed.is_dns());
        assert!(!parsed.is_arp());
        assert_eq!(parsed.payload(), b"hello");
    }

    #[test]
    fn test_parse_dns_frame() {
        let frame = build_udp_frame([10, 0, 0, 1], [10, 0, 0, 2], 50000, DNS_PORT, &[0; 12]);
        let parsed = ParsedFrame::parse(&frame).unwrap();

        assert!(parsed.is_dns());
        assert_eq!(parsed.dst_port(), Some(DNS_PORT));
    }

    #[test]
    fn test_parse_tcp_frame() {
        let frame = build_tcp_frame([192, 168, 1, 1], [93, 184, 216, 34], 45000, 443);
        let parsed = ParsedFrame::parse(&frame).unwrap();

        assert_eq!(parsed.protocol(), Some(IpProtocol::Tcp));
        assert_eq!(parsed.src_port(), Some(45000));
        assert_eq!(parsed.dst_port(), Some(443));
    }

    #[test]
    fn test_parse_mac_addresses() {
        let frame = build_udp_frame([10, 0, 0, 1], [10, 0, 0, 2], 1234, 5678, &[]);
        let parsed = ParsedFrame::parse(&frame).unwrap();

        assert_eq!(parsed.src_mac(), Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]));
        assert_eq!(parsed.dst_mac(), Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]));
    }

    #[test]
    fn test_parse_garbage_returns_none() {
        let garbage = [0xff; 5];
        assert!(ParsedFrame::parse(&garbage).is_none());
    }
}
