//! DNS port classification: tells `stack.rs` what to do with a packet
//! based on its destination port alone.
//!
//! Four classes:
//!
//! - **Dns** (port `53`) — plain DNS. Hand off to the DNS interceptor;
//!   block list and rebind protection apply at the application layer
//!   and the network egress policy is bypassed.
//! - **EncryptedDns** (port `853` over TCP — DoT) — DNS over TLS.
//!   Intercepted when TLS MITM is configured: terminate the guest's
//!   TLS with a per-domain cert, hand the inner plain-DNS frames to
//!   the same forwarder, re-encrypt the response. Without TLS MITM
//!   this class is treated like `AlternativeDns` — refused so the
//!   stub falls back to plain DNS.
//! - **AlternativeDns** (DoQ/mDNS/LLMNR/NetBIOS-NS) — alternative
//!   DNS-ish protocols on well-known ports that we can't proxy:
//!   DoQ needs a QUIC MITM library (none in-crate); the rest are
//!   local multicast/broadcast discovery protocols whose semantics
//!   don't map to unicast resolution. Refusing forces stub resolvers
//!   to fall back to plain DNS on port 53, which we do see.
//! - **Other** — not DNS-related. Network egress policy decides.
//!
//! DoH on TCP/443 is intentionally absent: it shares its port with
//! regular HTTPS and needs TLS interception (or an IP/SNI blocklist),
//! not a port match. See the project's bypass-surface docs.

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Classification of a destination port from the DNS layer's perspective.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DnsPortType {
    /// Plain DNS (port 53). The DNS interceptor handles the packet.
    Dns,
    /// DNS over TLS (TCP port 853). Intercepted when TLS MITM is
    /// configured; otherwise treated as `AlternativeDns` and refused.
    EncryptedDns,
    /// Alternative DNS-ish protocol on a well-known port — refuse outright.
    AlternativeDns,
    /// Not DNS-related; defer to the network egress policy.
    Other,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DnsPortType {
    /// Classify a TCP destination port.
    ///
    /// - `53`  — plain DNS over TCP (RFC 7766).
    /// - `853` — DoT (DNS over TLS, RFC 7858). Intercepted if TLS MITM
    ///   is configured; otherwise refused (the dispatch site checks).
    pub(crate) fn from_tcp(port: u16) -> Self {
        match port {
            53 => Self::Dns,
            853 => Self::EncryptedDns,
            _ => Self::Other,
        }
    }

    /// Classify a UDP destination port.
    ///
    /// - `53`   — plain DNS over UDP (RFC 1035).
    /// - `853`  — DoQ (DNS over QUIC, RFC 9250). Refused; QUIC-encrypted.
    /// - `5353` — mDNS (RFC 6762). Refused; would leak query names to
    ///   the local LAN via multicast if forwarded.
    /// - `5355` — LLMNR (RFC 4795). Refused; Microsoft mDNS-equivalent.
    /// - `137`  — NetBIOS Name Service (RFC 1002). Refused; legacy SMB
    ///   resolution.
    pub(crate) fn from_udp(port: u16) -> Self {
        match port {
            53 => Self::Dns,
            853 | 5353 | 5355 | 137 => Self::AlternativeDns,
            _ => Self::Other,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_tcp_plain_dns() {
        assert_eq!(DnsPortType::from_tcp(53), DnsPortType::Dns);
    }

    #[test]
    fn from_tcp_encrypted_dns() {
        assert_eq!(DnsPortType::from_tcp(853), DnsPortType::EncryptedDns, "DoT");
    }

    #[test]
    fn from_tcp_other() {
        assert_eq!(DnsPortType::from_tcp(443), DnsPortType::Other, "HTTPS");
        assert_eq!(DnsPortType::from_tcp(80), DnsPortType::Other, "HTTP");
        assert_eq!(DnsPortType::from_tcp(22), DnsPortType::Other, "SSH");
    }

    #[test]
    fn from_udp_plain_dns() {
        assert_eq!(DnsPortType::from_udp(53), DnsPortType::Dns);
    }

    #[test]
    fn from_udp_alternative_dns() {
        assert_eq!(
            DnsPortType::from_udp(853),
            DnsPortType::AlternativeDns,
            "DoQ"
        );
        assert_eq!(
            DnsPortType::from_udp(5353),
            DnsPortType::AlternativeDns,
            "mDNS"
        );
        assert_eq!(
            DnsPortType::from_udp(5355),
            DnsPortType::AlternativeDns,
            "LLMNR"
        );
        assert_eq!(
            DnsPortType::from_udp(137),
            DnsPortType::AlternativeDns,
            "NetBIOS-NS"
        );
    }

    #[test]
    fn from_udp_other() {
        assert_eq!(
            DnsPortType::from_udp(443),
            DnsPortType::Other,
            "QUIC HTTP/3"
        );
        assert_eq!(DnsPortType::from_udp(123), DnsPortType::Other, "NTP");
        assert_eq!(DnsPortType::from_udp(500), DnsPortType::Other, "IKE");
    }
}
