//! Fluent builder for [`NetworkPolicy`].
//!
//! Lets callers compose a policy via chained method calls inside
//! rule-batch closures:
//!
//! ```ignore
//! let policy = NetworkPolicy::builder()
//!     .default_deny()
//!     .egress(|e| e.tcp().port(443).allow_public().allow_private())
//!     .rule(|r| r.any().deny().ip("198.51.100.5"))
//!     .build()?;
//! ```
//!
//! ## Lazy parse
//!
//! Methods that take string inputs (`.ip(&str)`, `.cidr(&str)`,
//! `.domain(&str)`, `.domain_suffix(&str)`) **do not parse at the
//! method call**. They store the raw input along with intent, returning
//! a chain-friendly reference. At [`NetworkPolicyBuilder::build`] time,
//! the builder walks the accumulated entries, parses each, validates
//! invariants (direction set, ICMP-not-in-ingress, port range
//! ordering), and surfaces the first failure as [`BuildError`].
//!
//! ## State accumulation
//!
//! Inside a `.rule(|r| ...)`, `.egress(|e| ...)`, `.ingress(|i| ...)`,
//! or `.any(|a| ...)` closure, state setters (`.tcp()`, `.port(N)`,
//! etc.) accumulate eagerly. Each rule-adder commits a rule using the
//! current state. State is **not reset** between rule-adders — callers
//! who want different state per rule use separate `.rule()` calls.

use std::str::FromStr;

use ipnetwork::IpNetwork;

use super::{
    Action, Destination, DestinationGroup, Direction, DomainName, DomainNameError, NetworkPolicy,
    PortRange, Protocol, Rule,
};

//--------------------------------------------------------------------------------------------------
// Errors
//--------------------------------------------------------------------------------------------------

/// Errors surfaced by [`NetworkPolicyBuilder::build`] and the related
/// nested builders ([`crate::builder::DnsBuilder::build`],
/// [`crate::builder::NetworkBuilder::build`]).
///
/// All these builders accumulate errors lazily — string inputs are
/// stored raw and only parsed at `.build()` time, where the first
/// failure is returned. The same enum covers both rule-grammar
/// failures (with a `rule_index`) and DNS-block-list failures (no
/// rule index, since DNS blocks aren't rules).
#[derive(Debug, Clone, thiserror::Error)]
pub enum BuildError {
    /// A rule was committed without setting a direction first.
    #[error(
        "rule #{rule_index}: direction not set; call .egress(), .ingress(), or .any() before the rule-adder"
    )]
    DirectionNotSet { rule_index: usize },

    /// A rule was committed via `.allow()` / `.deny()` but no destination
    /// method was called on the resulting `RuleDestinationBuilder`.
    #[error(
        "rule #{rule_index}: destination not set; call .ip(), .cidr(), .domain(), .domain_suffix(), .group(), or .any() on the rule-destination builder"
    )]
    MissingDestination { rule_index: usize },

    /// `.ip(&str)` received a value that doesn't parse as an IPv4 or
    /// IPv6 address.
    #[error("rule #{rule_index}: invalid IP address `{raw}`")]
    InvalidIp { rule_index: usize, raw: String },

    /// `.cidr(&str)` received a value that doesn't parse as a CIDR.
    #[error("rule #{rule_index}: invalid CIDR `{raw}`")]
    InvalidCidr { rule_index: usize, raw: String },

    /// `.domain(&str)` or `.domain_suffix(&str)` received a value that
    /// doesn't parse as a [`DomainName`].
    #[error("rule #{rule_index}: invalid domain `{raw}`: {source}")]
    InvalidDomain {
        rule_index: usize,
        raw: String,
        #[source]
        source: DomainNameError,
    },

    /// `.port_range(lo, hi)` received `lo > hi`.
    #[error("rule #{rule_index}: invalid port range {lo}..{hi}; lo must be <= hi")]
    InvalidPortRange { rule_index: usize, lo: u16, hi: u16 },

    /// An ICMP protocol (`icmpv4` / `icmpv6`) appears in a rule whose
    /// direction is `Ingress` or `Any`. `publisher.rs` has no inbound
    /// ICMP path; ingress ICMP rules would be dead code.
    #[error(
        "rule #{rule_index}: ICMP protocols are egress-only; ingress and any-direction rules cannot include icmpv4 or icmpv6"
    )]
    IngressDoesNotSupportIcmp { rule_index: usize },
}

//--------------------------------------------------------------------------------------------------
// Top-level builder
//--------------------------------------------------------------------------------------------------

/// Fluent builder for [`NetworkPolicy`].
///
/// Construct via [`NetworkPolicy::builder`].
#[derive(Debug, Default)]
pub struct NetworkPolicyBuilder {
    default_egress: Option<Action>,
    default_ingress: Option<Action>,
    pending_rules: Vec<PendingRule>,
    errors: Vec<BuildError>,
}

impl NetworkPolicyBuilder {
    /// Create an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set both `default_egress` and `default_ingress` to `Allow`.
    pub fn default_allow(mut self) -> Self {
        self.default_egress = Some(Action::Allow);
        self.default_ingress = Some(Action::Allow);
        self
    }

    /// Set both `default_egress` and `default_ingress` to `Deny`.
    pub fn default_deny(mut self) -> Self {
        self.default_egress = Some(Action::Deny);
        self.default_ingress = Some(Action::Deny);
        self
    }

    /// Per-direction override for the egress default action.
    pub fn default_egress(mut self, action: Action) -> Self {
        self.default_egress = Some(action);
        self
    }

    /// Per-direction override for the ingress default action.
    pub fn default_ingress(mut self, action: Action) -> Self {
        self.default_ingress = Some(action);
        self
    }

    /// Open a multi-rule batch closure. Direction must be set inside
    /// via `.egress()`, `.ingress()`, or `.any()` before any rule-adder.
    pub fn rule<F>(self, f: F) -> Self
    where
        F: for<'a> FnOnce(&'a mut RuleBuilder) -> &'a mut RuleBuilder,
    {
        self.with_rule_builder(None, f)
    }

    /// Sugar for [`Self::rule`] with direction pre-set to `Egress`.
    pub fn egress<F>(self, f: F) -> Self
    where
        F: for<'a> FnOnce(&'a mut RuleBuilder) -> &'a mut RuleBuilder,
    {
        self.with_rule_builder(Some(Direction::Egress), f)
    }

    /// Sugar for [`Self::rule`] with direction pre-set to `Ingress`.
    pub fn ingress<F>(self, f: F) -> Self
    where
        F: for<'a> FnOnce(&'a mut RuleBuilder) -> &'a mut RuleBuilder,
    {
        self.with_rule_builder(Some(Direction::Ingress), f)
    }

    /// Sugar for [`Self::rule`] with direction pre-set to `Any`. Rules
    /// committed inside apply in both directions.
    pub fn any<F>(self, f: F) -> Self
    where
        F: for<'a> FnOnce(&'a mut RuleBuilder) -> &'a mut RuleBuilder,
    {
        self.with_rule_builder(Some(Direction::Any), f)
    }

    fn with_rule_builder<F>(mut self, initial_direction: Option<Direction>, f: F) -> Self
    where
        F: for<'a> FnOnce(&'a mut RuleBuilder) -> &'a mut RuleBuilder,
    {
        let mut rb = RuleBuilder {
            direction: initial_direction,
            protocols: Vec::new(),
            ports: Vec::new(),
            pending_rules: Vec::new(),
            errors: Vec::new(),
        };
        let _ = f(&mut rb);
        self.pending_rules.append(&mut rb.pending_rules);
        self.errors.append(&mut rb.errors);
        self
    }

    /// Consume the builder and produce a [`NetworkPolicy`].
    ///
    /// Lazy-parses every `.ip()` / `.cidr()` / `.domain()` /
    /// `.domain_suffix()` input, validates direction-set and
    /// ICMP-egress-only invariants, and emits a `tracing::warn!` for
    /// each shadowed rule pair detected.
    ///
    /// Returns the first [`BuildError`] encountered.
    pub fn build(self) -> Result<NetworkPolicy, BuildError> {
        if let Some(err) = self.errors.into_iter().next() {
            return Err(err);
        }

        let mut rules = Vec::with_capacity(self.pending_rules.len());
        for (idx, pending) in self.pending_rules.into_iter().enumerate() {
            let direction = pending
                .direction
                .ok_or(BuildError::DirectionNotSet { rule_index: idx })?;
            let destination = pending.destination.parse(idx)?;

            if matches!(direction, Direction::Ingress | Direction::Any)
                && pending
                    .protocols
                    .iter()
                    .any(|p| matches!(p, Protocol::Icmpv4 | Protocol::Icmpv6))
            {
                return Err(BuildError::IngressDoesNotSupportIcmp { rule_index: idx });
            }

            rules.push(Rule {
                direction,
                destination,
                protocols: pending.protocols,
                ports: pending.ports,
                action: pending.action,
            });
        }

        warn_about_shadows(&rules);

        Ok(NetworkPolicy {
            default_egress: self.default_egress.unwrap_or_else(default_egress_default),
            default_ingress: self.default_ingress.unwrap_or_else(default_ingress_default),
            rules,
        })
    }
}

/// Default for `default_egress` when neither
/// [`NetworkPolicyBuilder::default_allow`] nor
/// [`NetworkPolicyBuilder::default_deny`] is called.
fn default_egress_default() -> Action {
    Action::Deny
}

/// Default for `default_ingress` when neither
/// [`NetworkPolicyBuilder::default_allow`] nor
/// [`NetworkPolicyBuilder::default_deny`] is called.
fn default_ingress_default() -> Action {
    Action::Allow
}

//--------------------------------------------------------------------------------------------------
// RuleBuilder
//--------------------------------------------------------------------------------------------------

/// Per-closure state and rule accumulator.
///
/// Lives only within a `.rule()` / `.egress()` / `.ingress()` /
/// `.any()` closure; its accumulated rules and errors are drained into
/// the parent [`NetworkPolicyBuilder`] when the closure returns.
#[derive(Debug)]
pub struct RuleBuilder {
    direction: Option<Direction>,
    protocols: Vec<Protocol>,
    ports: Vec<PortRange>,
    pending_rules: Vec<PendingRule>,
    errors: Vec<BuildError>,
}

impl RuleBuilder {
    // -- direction setters -------------------------------------------

    /// Set direction to `Egress` for subsequent rule-adders. Last-write-wins.
    pub fn egress(&mut self) -> &mut Self {
        self.direction = Some(Direction::Egress);
        self
    }

    /// Set direction to `Ingress` for subsequent rule-adders. Last-write-wins.
    pub fn ingress(&mut self) -> &mut Self {
        self.direction = Some(Direction::Ingress);
        self
    }

    /// Set direction to `Any` for subsequent rule-adders.
    /// Rules committed after this apply in both directions. Last-write-wins.
    pub fn any(&mut self) -> &mut Self {
        self.direction = Some(Direction::Any);
        self
    }

    // -- protocol setters --------------------------------------------

    /// Add `Tcp` to the protocols set (set semantics; duplicates dedupe).
    pub fn tcp(&mut self) -> &mut Self {
        self.add_protocol(Protocol::Tcp)
    }

    /// Add `Udp` to the protocols set.
    pub fn udp(&mut self) -> &mut Self {
        self.add_protocol(Protocol::Udp)
    }

    /// Add `Icmpv4` to the protocols set. Egress-only at build-time
    /// (commits will record an [`BuildError::IngressDoesNotSupportIcmp`]
    /// if direction is `Ingress` or `Any`).
    pub fn icmpv4(&mut self) -> &mut Self {
        self.add_protocol(Protocol::Icmpv4)
    }

    /// Add `Icmpv6` to the protocols set. Egress-only.
    pub fn icmpv6(&mut self) -> &mut Self {
        self.add_protocol(Protocol::Icmpv6)
    }

    fn add_protocol(&mut self, p: Protocol) -> &mut Self {
        if !self.protocols.contains(&p) {
            self.protocols.push(p);
        }
        self
    }

    // -- port setters ------------------------------------------------

    /// Add a single port to the ports set.
    pub fn port(&mut self, port: u16) -> &mut Self {
        let pr = PortRange::single(port);
        if !self.ports.contains(&pr) {
            self.ports.push(pr);
        }
        self
    }

    /// Add an inclusive port range to the ports set. `lo > hi` records
    /// a [`BuildError::InvalidPortRange`] for `.build()` to surface.
    pub fn port_range(&mut self, lo: u16, hi: u16) -> &mut Self {
        if lo > hi {
            self.errors.push(BuildError::InvalidPortRange {
                rule_index: self.pending_rules.len(),
                lo,
                hi,
            });
            return self;
        }
        let pr = PortRange::range(lo, hi);
        if !self.ports.contains(&pr) {
            self.ports.push(pr);
        }
        self
    }

    /// Add multiple single ports to the ports set. Equivalent to calling
    /// [`Self::port`] once per element; duplicates dedupe via set semantics.
    pub fn ports<I: IntoIterator<Item = u16>>(&mut self, ports: I) -> &mut Self {
        for p in ports {
            self.port(p);
        }
        self
    }

    // -- atomic rule-adders (per-category shortcuts) -----------------

    /// Allow the `Public` group: any IP not in another named category.
    pub fn allow_public(&mut self) -> &mut Self {
        self.commit_group(Action::Allow, DestinationGroup::Public)
    }

    /// Deny the `Public` group.
    pub fn deny_public(&mut self) -> &mut Self {
        self.commit_group(Action::Deny, DestinationGroup::Public)
    }

    /// Allow the `Private` group (RFC1918 + ULA + CGN).
    pub fn allow_private(&mut self) -> &mut Self {
        self.commit_group(Action::Allow, DestinationGroup::Private)
    }

    /// Deny the `Private` group.
    pub fn deny_private(&mut self) -> &mut Self {
        self.commit_group(Action::Deny, DestinationGroup::Private)
    }

    /// Allow the `Loopback` group: `127.0.0.0/8` and `::1` — the
    /// **guest's own loopback interface, not the host machine**.
    /// Standard loopback traffic inside the guest stays in the guest
    /// kernel and never reaches this rule; it only fires for crafted
    /// packets that route loopback destinations out through the
    /// gateway (e.g. raw sockets bound to `eth0` with `dst=127.0.0.1`).
    /// To reach a service on the host's localhost, use
    /// [`Self::allow_host`] instead.
    pub fn allow_loopback(&mut self) -> &mut Self {
        self.commit_group(Action::Allow, DestinationGroup::Loopback)
    }

    /// Deny the `Loopback` group. Useful in `default_egress = Allow`
    /// configurations to block crafted-packet leaks where a process
    /// inside the guest binds a raw socket to `eth0` and writes a
    /// packet with `dst=127.0.0.1` directly. The packet bypasses the
    /// guest's routing table, smoltcp on the host parses the
    /// destination, and the connection lands on the host's loopback.
    /// `.deny_loopback()` blocks that vector.
    pub fn deny_loopback(&mut self) -> &mut Self {
        self.commit_group(Action::Deny, DestinationGroup::Loopback)
    }

    /// Allow the `LinkLocal` group (`169.254.0.0/16`, `fe80::/10`).
    /// Excludes the metadata IP `169.254.169.254` (categorized as
    /// `Metadata`).
    pub fn allow_link_local(&mut self) -> &mut Self {
        self.commit_group(Action::Allow, DestinationGroup::LinkLocal)
    }

    /// Deny the `LinkLocal` group.
    pub fn deny_link_local(&mut self) -> &mut Self {
        self.commit_group(Action::Deny, DestinationGroup::LinkLocal)
    }

    /// Allow the `Metadata` group (`169.254.169.254`). **Dangerous on
    /// cloud hosts** — exposes IAM credentials.
    pub fn allow_meta(&mut self) -> &mut Self {
        self.commit_group(Action::Allow, DestinationGroup::Metadata)
    }

    /// Deny the `Metadata` group.
    pub fn deny_meta(&mut self) -> &mut Self {
        self.commit_group(Action::Deny, DestinationGroup::Metadata)
    }

    /// Allow the `Multicast` group (`224.0.0.0/4`, `ff00::/8`).
    pub fn allow_multicast(&mut self) -> &mut Self {
        self.commit_group(Action::Allow, DestinationGroup::Multicast)
    }

    /// Deny the `Multicast` group.
    pub fn deny_multicast(&mut self) -> &mut Self {
        self.commit_group(Action::Deny, DestinationGroup::Multicast)
    }

    /// Allow the `Host` group: per-sandbox gateway IPs that back
    /// `host.microsandbox.internal`. This is the right shortcut for
    /// "let the sandbox reach my host's localhost" — not
    /// [`Self::allow_loopback`].
    pub fn allow_host(&mut self) -> &mut Self {
        self.commit_group(Action::Allow, DestinationGroup::Host)
    }

    /// Deny the `Host` group.
    pub fn deny_host(&mut self) -> &mut Self {
        self.commit_group(Action::Deny, DestinationGroup::Host)
    }

    // -- composite sugar --------------------------------------------

    /// Allow `Loopback + LinkLocal + Host` — the three "near the
    /// sandbox" groups a developer typically wants together when
    /// running locally. Adds **three rules** atomically, each using
    /// the closure's current state.
    ///
    /// **`Metadata` is explicitly NOT included** — even though
    /// `169.254.169.254` falls inside the link-local CIDR by raw
    /// address, the schema's `Metadata` carve-out is preserved here.
    /// Users wanting cloud metadata access add [`Self::allow_meta`]
    /// separately.
    pub fn allow_local(&mut self) -> &mut Self {
        self.allow_loopback();
        self.allow_link_local();
        self.allow_host();
        self
    }

    /// Deny `Loopback + LinkLocal + Host` (no `Metadata`). See
    /// [`Self::allow_local`] for the membership rationale.
    pub fn deny_local(&mut self) -> &mut Self {
        self.deny_loopback();
        self.deny_link_local();
        self.deny_host();
        self
    }

    // -- bulk-domain shortcuts --------------------------------------

    /// Allow each name as a `Destination::Domain` rule.
    pub fn allow_domains<I, S>(&mut self, names: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for name in names {
            self.commit_rule(Action::Allow, PendingDestination::Domain(name.into()));
        }
        self
    }

    /// Deny each name as a `Destination::Domain` rule.
    pub fn deny_domains<I, S>(&mut self, names: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for name in names {
            self.commit_rule(Action::Deny, PendingDestination::Domain(name.into()));
        }
        self
    }

    /// Allow each suffix as a `Destination::DomainSuffix` rule.
    pub fn allow_domain_suffixes<I, S>(&mut self, suffixes: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for suffix in suffixes {
            self.commit_rule(
                Action::Allow,
                PendingDestination::DomainSuffix(suffix.into()),
            );
        }
        self
    }

    /// Deny each suffix as a `Destination::DomainSuffix` rule.
    pub fn deny_domain_suffixes<I, S>(&mut self, suffixes: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for suffix in suffixes {
            self.commit_rule(
                Action::Deny,
                PendingDestination::DomainSuffix(suffix.into()),
            );
        }
        self
    }

    // -- explicit-rule entry ----------------------------------------

    /// Begin an explicit-destination rule with action `Allow`. Returns
    /// an [`RuleDestinationBuilder`] that requires a destination call
    /// (`.ip`, `.cidr`, `.domain`, `.domain_suffix`, `.group`, `.any`)
    /// to commit the rule.
    pub fn allow(&mut self) -> RuleDestinationBuilder<'_> {
        RuleDestinationBuilder {
            rule_builder: self,
            action: Action::Allow,
        }
    }

    /// Begin an explicit-destination rule with action `Deny`.
    pub fn deny(&mut self) -> RuleDestinationBuilder<'_> {
        RuleDestinationBuilder {
            rule_builder: self,
            action: Action::Deny,
        }
    }

    // -- internal commit helpers ------------------------------------

    fn commit_group(&mut self, action: Action, group: DestinationGroup) -> &mut Self {
        self.commit_rule(
            action,
            PendingDestination::Resolved(Destination::Group(group)),
        );
        self
    }

    fn commit_rule(&mut self, action: Action, destination: PendingDestination) {
        self.pending_rules.push(PendingRule {
            direction: self.direction,
            destination,
            protocols: self.protocols.clone(),
            ports: self.ports.clone(),
            action,
        });
    }
}

//--------------------------------------------------------------------------------------------------
// RuleDestinationBuilder
//--------------------------------------------------------------------------------------------------

/// Returned by [`RuleBuilder::allow`] / [`RuleBuilder::deny`]. Requires
/// exactly one destination method call to commit the rule.
///
/// Dropping without a destination call silently does nothing — no rule
/// is added. The `#[must_use]` attribute warns at compile time.
#[must_use = "RuleDestinationBuilder requires a destination method (.ip, .cidr, .domain, .domain_suffix, .group, .any) to commit the rule"]
pub struct RuleDestinationBuilder<'a> {
    rule_builder: &'a mut RuleBuilder,
    action: Action,
}

impl<'a> RuleDestinationBuilder<'a> {
    /// Commit the rule with destination `Ip(<addr>)`. The string is
    /// stored raw and parsed at [`NetworkPolicyBuilder::build`] time;
    /// invalid IPs surface as [`BuildError::InvalidIp`].
    pub fn ip(self, ip: impl Into<String>) -> &'a mut RuleBuilder {
        self.rule_builder
            .commit_rule(self.action, PendingDestination::Ip(ip.into()));
        self.rule_builder
    }

    /// Commit the rule with destination `Cidr(<network>)`.
    pub fn cidr(self, cidr: impl Into<String>) -> &'a mut RuleBuilder {
        self.rule_builder
            .commit_rule(self.action, PendingDestination::Cidr(cidr.into()));
        self.rule_builder
    }

    /// Commit the rule with destination `Domain(<name>)`. Matches only
    /// when a cached hostname for the remote IP equals this name
    /// (after canonicalization).
    pub fn domain(self, domain: impl Into<String>) -> &'a mut RuleBuilder {
        self.rule_builder
            .commit_rule(self.action, PendingDestination::Domain(domain.into()));
        self.rule_builder
    }

    /// Commit the rule with destination `DomainSuffix(<name>)`. Matches
    /// the apex domain itself and any subdomain.
    pub fn domain_suffix(self, suffix: impl Into<String>) -> &'a mut RuleBuilder {
        self.rule_builder
            .commit_rule(self.action, PendingDestination::DomainSuffix(suffix.into()));
        self.rule_builder
    }

    /// Commit the rule with destination `Group(<group>)`.
    pub fn group(self, group: DestinationGroup) -> &'a mut RuleBuilder {
        self.rule_builder.commit_rule(
            self.action,
            PendingDestination::Resolved(Destination::Group(group)),
        );
        self.rule_builder
    }

    /// Commit the rule with destination `Any` (matches every remote).
    pub fn any(self) -> &'a mut RuleBuilder {
        self.rule_builder
            .commit_rule(self.action, PendingDestination::Resolved(Destination::Any));
        self.rule_builder
    }
}

//--------------------------------------------------------------------------------------------------
// Pending data
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct PendingRule {
    direction: Option<Direction>,
    destination: PendingDestination,
    protocols: Vec<Protocol>,
    ports: Vec<PortRange>,
    action: Action,
}

#[derive(Debug, Clone)]
enum PendingDestination {
    /// Already a fully-formed `Destination` — nothing to parse later.
    Resolved(Destination),
    Ip(String),
    Cidr(String),
    Domain(String),
    DomainSuffix(String),
}

impl PendingDestination {
    fn parse(&self, idx: usize) -> Result<Destination, BuildError> {
        match self {
            PendingDestination::Resolved(d) => Ok(d.clone()),
            PendingDestination::Ip(raw) => {
                let ip = std::net::IpAddr::from_str(raw).map_err(|_| BuildError::InvalidIp {
                    rule_index: idx,
                    raw: raw.clone(),
                })?;
                // Express a single IP as a /32 (v4) or /128 (v6) CIDR so
                // it lives in `Destination::Cidr` alongside the rest.
                let prefix = if ip.is_ipv4() { 32 } else { 128 };
                let net = IpNetwork::new(ip, prefix).map_err(|_| BuildError::InvalidIp {
                    rule_index: idx,
                    raw: raw.clone(),
                })?;
                Ok(Destination::Cidr(net))
            }
            PendingDestination::Cidr(raw) => {
                let net = IpNetwork::from_str(raw).map_err(|_| BuildError::InvalidCidr {
                    rule_index: idx,
                    raw: raw.clone(),
                })?;
                Ok(Destination::Cidr(net))
            }
            PendingDestination::Domain(raw) => {
                let name =
                    DomainName::from_str(raw).map_err(|source| BuildError::InvalidDomain {
                        rule_index: idx,
                        raw: raw.clone(),
                        source,
                    })?;
                Ok(Destination::Domain(name))
            }
            PendingDestination::DomainSuffix(raw) => {
                let name =
                    DomainName::from_str(raw).map_err(|source| BuildError::InvalidDomain {
                        rule_index: idx,
                        raw: raw.clone(),
                        source,
                    })?;
                Ok(Destination::DomainSuffix(name))
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Shadow detection
//--------------------------------------------------------------------------------------------------

/// Walk the rules list and emit a `tracing::warn!` for each rule
/// whose match set is fully contained in an earlier rule's match set
/// in a compatible direction.
///
/// Coverage: `Ip` / `Cidr` / `Group` destinations only. `Domain` /
/// `DomainSuffix` shadowing is out of scope (depends on the runtime
/// DNS cache).
fn warn_about_shadows(rules: &[Rule]) {
    for (i, later) in rules.iter().enumerate() {
        for (j, earlier) in rules.iter().take(i).enumerate() {
            if shadows(earlier, later) {
                tracing::warn!(
                    shadowed_index = i,
                    shadowed_by = j,
                    "rule #{i} ({:?} {:?} {:?}) is shadowed by rule #{j} ({:?} {:?} {:?}); to narrow, place the more specific rule first",
                    later.direction,
                    later.action,
                    later.destination,
                    earlier.direction,
                    earlier.action,
                    earlier.destination,
                );
            }
        }
    }
}

/// Returns `true` if `earlier`'s match set covers all of `later`'s,
/// such that `later` will never fire when evaluated after `earlier`.
fn shadows(earlier: &Rule, later: &Rule) -> bool {
    direction_covers(earlier.direction, later.direction)
        && destination_covers(&earlier.destination, &later.destination)
        && protocol_set_covers(&earlier.protocols, &later.protocols)
        && port_set_covers(&earlier.ports, &later.ports)
}

fn direction_covers(earlier: Direction, later: Direction) -> bool {
    matches!(
        (earlier, later),
        (Direction::Any, _)
            | (Direction::Egress, Direction::Egress)
            | (Direction::Ingress, Direction::Ingress)
    )
}

fn destination_covers(earlier: &Destination, later: &Destination) -> bool {
    match (earlier, later) {
        (Destination::Any, _) => true,
        (Destination::Group(eg), Destination::Group(lg)) => eg == lg,
        (Destination::Cidr(en), Destination::Cidr(ln)) => cidr_contains(en, ln),
        // Domain shadowing is intentionally out of scope.
        _ => false,
    }
}

fn cidr_contains(outer: &IpNetwork, inner: &IpNetwork) -> bool {
    match (outer, inner) {
        (IpNetwork::V4(o), IpNetwork::V4(i)) => o.prefix() <= i.prefix() && o.contains(i.network()),
        (IpNetwork::V6(o), IpNetwork::V6(i)) => o.prefix() <= i.prefix() && o.contains(i.network()),
        _ => false,
    }
}

fn protocol_set_covers(earlier: &[Protocol], later: &[Protocol]) -> bool {
    if earlier.is_empty() {
        return true; // empty = any
    }
    if later.is_empty() {
        return false; // later matches all, earlier doesn't
    }
    later.iter().all(|p| earlier.contains(p))
}

fn port_set_covers(earlier: &[PortRange], later: &[PortRange]) -> bool {
    if earlier.is_empty() {
        return true;
    }
    if later.is_empty() {
        return false;
    }
    later.iter().all(|lp| {
        earlier
            .iter()
            .any(|ep| ep.start <= lp.start && lp.end <= ep.end)
    })
}

//--------------------------------------------------------------------------------------------------
// NetworkPolicy::builder() entry
//--------------------------------------------------------------------------------------------------

impl NetworkPolicy {
    /// Start building a [`NetworkPolicy`] via the fluent builder.
    pub fn builder() -> NetworkPolicyBuilder {
        NetworkPolicyBuilder::new()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Empty builder produces today's asymmetric default
    /// (`default_egress = Deny`, `default_ingress = Allow`, no rules).
    #[test]
    fn empty_builder_yields_asymmetric_default() {
        let p = NetworkPolicy::builder().build().unwrap();
        assert!(matches!(p.default_egress, Action::Deny));
        assert!(matches!(p.default_ingress, Action::Allow));
        assert!(p.rules.is_empty());
    }

    /// `.default_deny()` flips both directions to `Deny`; per-direction
    /// override can re-flip one of them.
    #[test]
    fn defaults_set_and_override() {
        let p = NetworkPolicy::builder()
            .default_deny()
            .default_ingress(Action::Allow)
            .build()
            .unwrap();
        assert!(matches!(p.default_egress, Action::Deny));
        assert!(matches!(p.default_ingress, Action::Allow));
    }

    /// Egress sub-builder commits one rule per category shortcut, with
    /// shared direction + protocols + ports state.
    #[test]
    fn egress_closure_commits_one_rule_per_shortcut() {
        let p = NetworkPolicy::builder()
            .egress(|e| e.tcp().port(443).allow_public().allow_private())
            .build()
            .unwrap();
        assert_eq!(p.rules.len(), 2);
        assert!(matches!(p.rules[0].direction, Direction::Egress));
        assert!(matches!(p.rules[0].action, Action::Allow));
        assert!(matches!(
            p.rules[0].destination,
            Destination::Group(DestinationGroup::Public)
        ));
        assert_eq!(p.rules[0].protocols, vec![Protocol::Tcp]);
        assert_eq!(p.rules[0].ports.len(), 1);
        assert!(matches!(
            p.rules[1].destination,
            Destination::Group(DestinationGroup::Private)
        ));
    }

    /// `.allow_local()` commits three rules: Loopback, LinkLocal, Host.
    #[test]
    fn allow_local_expands_to_three_groups() {
        let p = NetworkPolicy::builder()
            .egress(|e| e.allow_local())
            .build()
            .unwrap();
        assert_eq!(p.rules.len(), 3);
        let groups: Vec<_> = p
            .rules
            .iter()
            .map(|r| match &r.destination {
                Destination::Group(g) => *g,
                other => panic!("unexpected destination {other:?}"),
            })
            .collect();
        assert_eq!(
            groups,
            vec![
                DestinationGroup::Loopback,
                DestinationGroup::LinkLocal,
                DestinationGroup::Host,
            ]
        );
    }

    /// Explicit-rule builder takes a string IP and surfaces a parsed
    /// `Destination::Cidr(/32)` after `.build()`.
    #[test]
    fn explicit_ip_parses_at_build() {
        let p = NetworkPolicy::builder()
            .any(|a| a.deny().ip("198.51.100.5"))
            .build()
            .unwrap();
        assert_eq!(p.rules.len(), 1);
        assert!(matches!(p.rules[0].direction, Direction::Any));
        assert!(matches!(p.rules[0].action, Action::Deny));
        match &p.rules[0].destination {
            Destination::Cidr(net) => {
                assert_eq!(net.to_string(), "198.51.100.5/32");
            }
            other => panic!("expected Cidr, got {other:?}"),
        }
    }

    /// Invalid IP string surfaces as `BuildError::InvalidIp` at
    /// `.build()` time, not at the method call.
    #[test]
    fn invalid_ip_surfaces_at_build() {
        let result = NetworkPolicy::builder()
            .egress(|e| e.allow().ip("not-an-ip"))
            .build();
        match result {
            Err(BuildError::InvalidIp { raw, rule_index: 0 }) => {
                assert_eq!(raw, "not-an-ip");
            }
            other => panic!("expected InvalidIp, got {other:?}"),
        }
    }

    /// Domain string is parsed into a canonical `DomainName` at build time.
    #[test]
    fn domain_parses_to_canonical_form() {
        let p = NetworkPolicy::builder()
            .egress(|e| e.tcp().port(443).allow().domain("PyPI.Org."))
            .build()
            .unwrap();
        match &p.rules[0].destination {
            Destination::Domain(name) => assert_eq!(name.as_str(), "pypi.org"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    /// `.port_range(hi, lo)` records `BuildError::InvalidPortRange`.
    #[test]
    fn invalid_port_range_surfaces_at_build() {
        let result = NetworkPolicy::builder()
            .egress(|e| e.tcp().port_range(443, 80).allow_public())
            .build();
        match result {
            Err(BuildError::InvalidPortRange {
                lo: 443, hi: 80, ..
            }) => {}
            other => panic!("expected InvalidPortRange, got {other:?}"),
        }
    }

    /// Direction omitted entirely → DirectionNotSet at build time.
    #[test]
    fn missing_direction_surfaces_at_build() {
        let result = NetworkPolicy::builder()
            .rule(|r| r.tcp().port(443).allow_public())
            .build();
        match result {
            Err(BuildError::DirectionNotSet { rule_index: 0 }) => {}
            other => panic!("expected DirectionNotSet, got {other:?}"),
        }
    }

    /// ICMP in an ingress-direction rule is rejected at build time.
    #[test]
    fn icmp_in_ingress_rejected_at_build() {
        let result = NetworkPolicy::builder()
            .ingress(|i| i.icmpv4().allow_public())
            .build();
        match result {
            Err(BuildError::IngressDoesNotSupportIcmp { rule_index: 0 }) => {}
            other => panic!("expected IngressDoesNotSupportIcmp, got {other:?}"),
        }
    }

    /// ICMP in an any-direction rule is also rejected.
    #[test]
    fn icmp_in_any_direction_rejected_at_build() {
        let result = NetworkPolicy::builder()
            .any(|a| a.icmpv6().allow_public())
            .build();
        match result {
            Err(BuildError::IngressDoesNotSupportIcmp { rule_index: 0 }) => {}
            other => panic!("expected IngressDoesNotSupportIcmp, got {other:?}"),
        }
    }

    /// Set semantics: duplicate `.tcp().tcp()` collapses to one entry.
    #[test]
    fn duplicate_protocols_dedupe() {
        let p = NetworkPolicy::builder()
            .egress(|e| e.tcp().tcp().udp().tcp().allow_public())
            .build()
            .unwrap();
        assert_eq!(p.rules[0].protocols, vec![Protocol::Tcp, Protocol::Udp]);
    }

    /// Mixing the typed `Destination::Group` setter via `.group(...)`
    /// works for users who already have a `DestinationGroup` value.
    #[test]
    fn explicit_group_uses_typed_argument() {
        let p = NetworkPolicy::builder()
            .egress(|e| e.allow().group(DestinationGroup::Multicast))
            .build()
            .unwrap();
        assert!(matches!(
            p.rules[0].destination,
            Destination::Group(DestinationGroup::Multicast)
        ));
    }

    /// The closure return type lets a chain ending in a rule-adder
    /// satisfy the `FnOnce(&mut RuleBuilder) -> &mut RuleBuilder` bound
    /// without an explicit `r` return.
    #[test]
    fn chain_form_compiles_without_explicit_return() {
        let _ = NetworkPolicy::builder()
            .rule(|r| r.egress().tcp().allow_public())
            .build()
            .unwrap();
    }

    /// `shadows()`: a CIDR-narrower rule placed *after* a CIDR-broader
    /// rule with the same direction/action shape is shadowed.
    /// Building a shadowed policy succeeds (the warning is emitted via
    /// `tracing::warn!`, not an error).
    #[test]
    fn shadowed_rule_builds_and_is_detected() {
        let broader = Rule {
            direction: Direction::Egress,
            destination: Destination::Cidr("10.0.0.0/8".parse().unwrap()),
            protocols: vec![],
            ports: vec![],
            action: Action::Allow,
        };
        let narrower = Rule {
            direction: Direction::Egress,
            destination: Destination::Cidr("10.0.0.5/32".parse().unwrap()),
            protocols: vec![],
            ports: vec![],
            action: Action::Allow,
        };
        assert!(
            shadows(&broader, &narrower),
            "10.0.0.0/8 should shadow 10.0.0.5/32 in same direction"
        );
        assert!(
            !shadows(&narrower, &broader),
            "10.0.0.5/32 should NOT shadow 10.0.0.0/8"
        );

        // Build still succeeds; shadow detection is observability, not
        // an error path.
        let _ = NetworkPolicy::builder()
            .egress(|e| e.allow().cidr("10.0.0.0/8"))
            .egress(|e| e.allow().cidr("10.0.0.5/32"))
            .build()
            .unwrap();
    }

    /// `direction_covers`: `Any` covers every direction;
    /// `Egress`/`Ingress` only cover their own.
    #[test]
    fn direction_cover_relations() {
        use Direction::*;
        assert!(direction_covers(Any, Egress));
        assert!(direction_covers(Any, Ingress));
        assert!(direction_covers(Any, Any));
        assert!(direction_covers(Egress, Egress));
        assert!(!direction_covers(Egress, Ingress));
        assert!(!direction_covers(Egress, Any)); // Any has an ingress side Egress doesn't cover
        assert!(direction_covers(Ingress, Ingress));
        assert!(!direction_covers(Ingress, Egress));
        assert!(!direction_covers(Ingress, Any));
    }

    //----------------------------------------------------------------------------------------------
    // Bulk-domain shortcuts
    //----------------------------------------------------------------------------------------------

    /// `deny_domains` produces one deny-Domain rule per input name,
    /// inheriting the closure's direction, protocol, and port state.
    #[test]
    fn deny_domains_produces_one_rule_per_name() {
        let p = NetworkPolicy::builder()
            .default_allow()
            .egress(|e| e.deny_domains(["evil.com", "tracker.example"]))
            .build()
            .unwrap();
        assert_eq!(p.rules.len(), 2);
        for rule in &p.rules {
            assert_eq!(rule.action, Action::Deny);
            assert_eq!(rule.direction, Direction::Egress);
            assert!(rule.protocols.is_empty(), "no protocol filter");
            assert!(rule.ports.is_empty(), "no port filter");
        }
        assert!(matches!(
            &p.rules[0].destination,
            Destination::Domain(d) if d.as_str() == "evil.com",
        ));
        assert!(matches!(
            &p.rules[1].destination,
            Destination::Domain(d) if d.as_str() == "tracker.example",
        ));
    }

    /// `deny_domain_suffixes` mirrors `deny_domains` but produces
    /// `Destination::DomainSuffix` rules.
    #[test]
    fn deny_domain_suffixes_produces_one_rule_per_suffix() {
        let p = NetworkPolicy::builder()
            .default_allow()
            .egress(|e| e.deny_domain_suffixes([".ads.example", ".doubleclick.net"]))
            .build()
            .unwrap();
        assert_eq!(p.rules.len(), 2);
        assert!(matches!(
            &p.rules[0].destination,
            Destination::DomainSuffix(d) if d.as_str() == "ads.example",
        ));
        assert!(matches!(
            &p.rules[1].destination,
            Destination::DomainSuffix(d) if d.as_str() == "doubleclick.net",
        ));
    }

    /// Bulk shortcuts inherit the closure's protocol and port state, so
    /// users can narrow the bulk in the same call.
    #[test]
    fn deny_domains_inherits_protocol_and_port_filter() {
        let p = NetworkPolicy::builder()
            .default_allow()
            .egress(|e| e.tcp().port(443).deny_domains(["evil.com"]))
            .build()
            .unwrap();
        assert_eq!(p.rules[0].protocols, vec![Protocol::Tcp]);
        assert_eq!(p.rules[0].ports, vec![PortRange::single(443)]);
    }

    /// `allow_domains` symmetric with `deny_domains` — same shape,
    /// `Action::Allow`.
    #[test]
    fn allow_domains_produces_allow_rules() {
        let p = NetworkPolicy::builder()
            .default_deny()
            .egress(|e| e.allow_domains(["pypi.org", "files.pythonhosted.org"]))
            .build()
            .unwrap();
        assert_eq!(p.rules.len(), 2);
        for rule in &p.rules {
            assert_eq!(rule.action, Action::Allow);
        }
    }

    /// Empty input is a no-op — no rules pushed.
    #[test]
    fn deny_domains_empty_input_is_noop() {
        let p = NetworkPolicy::builder()
            .default_allow()
            .egress(|e| e.deny_domains(Vec::<&str>::new()))
            .build()
            .unwrap();
        assert!(p.rules.is_empty());
    }

    /// Invalid names accumulate as `BuildError::InvalidDomain` and the
    /// FIRST one surfaces from `.build()`. Mirrors the per-rule
    /// `.domain(...)` lazy-parse contract.
    #[test]
    fn deny_domains_invalid_input_surfaces_at_build() {
        let result = NetworkPolicy::builder()
            .default_allow()
            .egress(|e| e.deny_domains(["evil.com", "not a domain!"]))
            .build();
        match result {
            Err(BuildError::InvalidDomain {
                raw, rule_index, ..
            }) => {
                assert_eq!(raw, "not a domain!");
                // The valid evil.com is rule 0; the invalid one is
                // rule 1, which is what the parser reports.
                assert_eq!(rule_index, 1);
            }
            other => panic!("expected InvalidDomain, got {other:?}"),
        }
    }
}
