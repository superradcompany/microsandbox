//! Host-side observation of network policy denials.
//!
//! Policy denials are decided deep inside the network stack and, before
//! this module, were visible only as `tracing` records — and only on some
//! paths. Embedding code that wants to react to a denial (surface it in a
//! UI, offer a one-click allowlist entry, audit it) had no programmatic
//! way to see one.
//!
//! A [`PolicyObserver`] is installed on the shared network state and is
//! invoked from the evaluation choke points themselves rather than from
//! individual call sites, so a new caller of the policy API cannot forget
//! to report its denials.
//!
//! Observers run inline on the evaluation path. An implementation should
//! hand the denial to a channel or counter and return; blocking here
//! blocks guest traffic. Timestamps are left to the observer so the
//! evaluation path does not read the clock on every denied packet.

use std::net::IpAddr;

use super::types::{Direction, Protocol};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// What the denied traffic was addressed to.
///
/// Address-based paths (TCP, UDP, ICMP, ingress) carry a resolved peer.
/// A DNS query denied by name is refused before any address exists, so it
/// carries the queried name instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialTarget {
    /// Peer address the decision was evaluated against.
    Address(IpAddr),

    /// Queried name, for a DNS query denied before resolution.
    Domain(String),
}

/// A single denial produced by the policy engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDenial {
    /// Direction the denied traffic was travelling.
    pub direction: Direction,

    /// Protocol the decision was evaluated under.
    pub protocol: Protocol,

    /// Peer address, or queried name for a name-only DNS denial.
    pub target: DenialTarget,

    /// Guest-side port: destination port for egress, listening port for
    /// ingress. `None` on paths without ports, such as ICMP.
    pub port: Option<u16>,

    /// Hostname the peer address is known by, when the resolved-hostname
    /// index or the TLS handshake supplied one. `None` when the traffic
    /// was addressed numerically.
    pub hostname: Option<String>,
}

/// Host-side sink for policy denials.
///
/// Installed with `SharedState::set_policy_observer`. Implementations must
/// be cheap and non-blocking; see the module documentation.
pub trait PolicyObserver: Send + Sync {
    /// Called once per denied evaluation.
    fn on_denied(&self, denial: &PolicyDenial);
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PolicyDenial {
    /// Build a denial for traffic addressed to a peer address.
    pub fn to_address(
        direction: Direction,
        protocol: Protocol,
        addr: IpAddr,
        port: Option<u16>,
    ) -> Self {
        Self {
            direction,
            protocol,
            target: DenialTarget::Address(addr),
            port,
            hostname: None,
        }
    }

    /// Build a denial for a DNS query refused before resolution.
    pub fn to_domain(protocol: Protocol, domain: impl Into<String>, port: Option<u16>) -> Self {
        Self {
            direction: Direction::Egress,
            protocol,
            target: DenialTarget::Domain(domain.into()),
            port,
            hostname: None,
        }
    }

    /// Attach the hostname the peer address is known by.
    pub fn with_hostname(mut self, hostname: Option<String>) -> Self {
        self.hostname = hostname;
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::policy::{Action, NetworkPolicy};
    use crate::shared::SharedState;

    /// Observer that records every denial handed to it.
    #[derive(Default)]
    struct Recorder {
        denials: Mutex<Vec<PolicyDenial>>,
    }

    impl PolicyObserver for Recorder {
        fn on_denied(&self, denial: &PolicyDenial) {
            self.denials.lock().unwrap().push(denial.clone());
        }
    }

    impl Recorder {
        fn install(shared: &SharedState) -> Arc<Self> {
            let recorder = Arc::new(Self::default());
            shared.set_policy_observer(recorder.clone());
            recorder
        }

        fn taken(&self) -> Vec<PolicyDenial> {
            std::mem::take(&mut *self.denials.lock().unwrap())
        }
    }

    fn dst(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), port))
    }

    #[test]
    fn denied_egress_is_reported_with_destination_and_port() {
        let shared = SharedState::new(4);
        let recorder = Recorder::install(&shared);

        let action = NetworkPolicy::none().evaluate_egress(dst(443), Protocol::Tcp, &shared);

        assert_eq!(action, Action::Deny);
        let denials = recorder.taken();
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].direction, Direction::Egress);
        assert_eq!(denials[0].protocol, Protocol::Tcp);
        assert_eq!(
            denials[0].target,
            DenialTarget::Address(Ipv4Addr::new(1, 2, 3, 4).into())
        );
        assert_eq!(denials[0].port, Some(443));
        assert_eq!(denials[0].hostname, None);
    }

    #[test]
    fn allowed_egress_reports_nothing() {
        let shared = SharedState::new(4);
        let recorder = Recorder::install(&shared);

        let action = NetworkPolicy::allow_all().evaluate_egress(dst(443), Protocol::Tcp, &shared);

        assert_eq!(action, Action::Allow);
        assert!(recorder.taken().is_empty());
    }

    #[test]
    fn denied_egress_without_port_reports_none() {
        // The ICMP path evaluates an address with no port at all.
        let shared = SharedState::new(4);
        let recorder = Recorder::install(&shared);

        let action = NetworkPolicy::none().evaluate_egress_ip(
            Ipv4Addr::new(1, 2, 3, 4).into(),
            Protocol::Icmpv4,
            &shared,
        );

        assert_eq!(action, Action::Deny);
        let denials = recorder.taken();
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].port, None);
        assert_eq!(denials[0].protocol, Protocol::Icmpv4);
    }

    #[test]
    fn denied_ingress_reports_the_guest_listening_port() {
        let shared = SharedState::new(4);
        let recorder = Recorder::install(&shared);

        let action =
            NetworkPolicy::none().evaluate_ingress(dst(51234), 8080, Protocol::Tcp, &shared);

        assert_eq!(action, Action::Deny);
        let denials = recorder.taken();
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].direction, Direction::Ingress);
        assert_eq!(denials[0].port, Some(8080));
    }

    #[test]
    fn denial_without_an_observer_is_a_no_op() {
        let shared = SharedState::new(4);

        let action = NetworkPolicy::none().evaluate_egress(dst(443), Protocol::Tcp, &shared);

        assert_eq!(action, Action::Deny);
    }
}
