//! Transport vocabulary shared between the guest-facing proxies and
//! the forwarder.
//!
//! The three DNS proxies (`proxies::udp`, `proxies::tcp`, `proxies::dot`)
//! each produce a [`Transport`] value identifying the wire format they
//! received the query on; the forwarder consumes it to pick the matching
//! upstream transport, to evaluate egress policy against the correct
//! protocol/port, and (for UDP only) to gate the truncation logic.

use crate::policy::Protocol;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Transport the guest used to send the DNS query. Drives upstream
/// transport selection (so a TCP guest query forwards over TCP, a DoT
/// guest query forwards over DoT) and gates the UDP truncation logic.
///
/// `Dot` describes the transport *as seen by the guest*: plain DNS
/// framing wrapped in TLS. The DoT proxy terminates TLS at the gateway
/// and hands the inner framed bytes to the forwarder with
/// `Transport::Dot` so upstream selection targets port 853 and builds
/// a TLS client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Transport {
    Udp,
    Tcp,
    Dot,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Transport {
    /// Upstream port for this transport. Plain DNS (UDP/TCP) → 53;
    /// DoT → 853 (RFC 7858).
    pub(crate) fn upstream_port(self) -> u16 {
        match self {
            Transport::Udp | Transport::Tcp => 53,
            Transport::Dot => 853,
        }
    }

    /// Network policy protocol for this transport. DoT rides TCP so
    /// the egress policy is evaluated as TCP.
    pub(crate) fn policy_protocol(self) -> Protocol {
        match self {
            Transport::Udp => Protocol::Udp,
            Transport::Tcp | Transport::Dot => Protocol::Tcp,
        }
    }
}
