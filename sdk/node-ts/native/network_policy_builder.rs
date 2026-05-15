use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox_network::policy::{
    Action as RustAction, DestinationGroup as RustDestinationGroup,
    NetworkPolicy as RustNetworkPolicy, NetworkPolicyBuilder as RustNetworkPolicyBuilder,
    RuleBuilder as RustRuleBuilder,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder for `NetworkPolicy`.
///
/// Mirrors `microsandbox_network::policy::NetworkPolicyBuilder`. All
/// inputs are recorded eagerly; `.build()` replays them onto the Rust
/// builder, which lazily parses string IPs/CIDRs/domains and validates
/// `direction`-set + ICMP-egress-only invariants. The first error is
/// surfaced from `.build()`.
#[napi(js_name = "NetworkPolicyBuilder")]
pub struct JsNetworkPolicyBuilder {
    ops: Vec<TopOp>,
}

/// Per-rule-batch builder. Lives only inside the closure passed to
/// `.rule()` / `.egress()` / `.ingress()` / `.any()`. State (direction,
/// protocols, ports) accumulates across rule-adders within the closure
/// and is **not reset** between them — separate `.rule()` calls are how
/// you reset state.
#[napi(js_name = "RuleBuilder")]
pub struct JsRuleBuilder {
    ops: Vec<RuleOp>,
}

/// Terminal builder returned by `RuleBuilder.allow(d => ...)` /
/// `.deny(d => ...)`. Exactly one destination call (`.ip`, `.cidr`,
/// `.domain`, `.domainSuffix`, `.group`, `.any`) commits the rule;
/// dropping without a destination call silently does nothing.
#[napi(js_name = "RuleDestinationBuilder")]
pub struct JsRuleDestinationBuilder {
    dest: Option<DestKind>,
}

#[derive(Clone)]
enum TopOp {
    DefaultAllow,
    DefaultDeny,
    DefaultEgress(RustAction),
    DefaultIngress(RustAction),
    Rule {
        initial_direction: Option<RustDirectionTag>,
        ops: Vec<RuleOp>,
    },
}

#[derive(Clone, Copy)]
enum RustDirectionTag {
    Egress,
    Ingress,
    Any,
}

#[derive(Clone)]
enum RuleOp {
    DirEgress,
    DirIngress,
    DirAny,
    Tcp,
    Udp,
    Icmpv4,
    Icmpv6,
    Port(u16),
    PortRange(u16, u16),
    Ports(Vec<u16>),
    AllowGroup(RustDestinationGroup),
    DenyGroup(RustDestinationGroup),
    AllowLocal,
    DenyLocal,
    AllowDomains(Vec<String>),
    DenyDomains(Vec<String>),
    AllowDomainSuffixes(Vec<String>),
    DenyDomainSuffixes(Vec<String>),
    Commit { action: RustAction, dest: DestKind },
}

#[derive(Clone)]
enum DestKind {
    Ip(String),
    Cidr(String),
    Domain(String),
    DomainSuffix(String),
    Group(RustDestinationGroup),
    Any,
}

//--------------------------------------------------------------------------------------------------
// Methods: NetworkPolicyBuilder
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsNetworkPolicyBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }

    /// Set both `default_egress` and `default_ingress` to `Allow`.
    #[napi(js_name = "defaultAllow")]
    pub fn default_allow(&mut self) -> &Self {
        self.ops.push(TopOp::DefaultAllow);
        self
    }

    /// Set both `default_egress` and `default_ingress` to `Deny`.
    #[napi(js_name = "defaultDeny")]
    pub fn default_deny(&mut self) -> &Self {
        self.ops.push(TopOp::DefaultDeny);
        self
    }

    /// Per-direction override for the egress default action.
    /// `action` is `"allow"` or `"deny"`.
    #[napi(js_name = "defaultEgress")]
    pub fn default_egress(&mut self, action: String) -> Result<&Self> {
        self.ops.push(TopOp::DefaultEgress(parse_action(&action)?));
        Ok(self)
    }

    /// Per-direction override for the ingress default action.
    #[napi(js_name = "defaultIngress")]
    pub fn default_ingress(&mut self, action: String) -> Result<&Self> {
        self.ops.push(TopOp::DefaultIngress(parse_action(&action)?));
        Ok(self)
    }

    /// Open a multi-rule batch closure. Direction must be set inside via
    /// `.egress()` / `.ingress()` / `.any()` before any rule-adder.
    #[napi]
    pub fn rule(
        &mut self,
        env: &Env,
        configure: Function<ClassInstance<JsRuleBuilder>, ClassInstance<JsRuleBuilder>>,
    ) -> Result<&Self> {
        self.run_rule_closure(env, None, configure)
    }

    /// Sugar for `.rule()` with direction pre-set to `Egress`.
    #[napi]
    pub fn egress(
        &mut self,
        env: &Env,
        configure: Function<ClassInstance<JsRuleBuilder>, ClassInstance<JsRuleBuilder>>,
    ) -> Result<&Self> {
        self.run_rule_closure(env, Some(RustDirectionTag::Egress), configure)
    }

    /// Sugar for `.rule()` with direction pre-set to `Ingress`.
    #[napi]
    pub fn ingress(
        &mut self,
        env: &Env,
        configure: Function<ClassInstance<JsRuleBuilder>, ClassInstance<JsRuleBuilder>>,
    ) -> Result<&Self> {
        self.run_rule_closure(env, Some(RustDirectionTag::Ingress), configure)
    }

    /// Sugar for `.rule()` with direction pre-set to `Any`.
    #[napi]
    pub fn any(
        &mut self,
        env: &Env,
        configure: Function<ClassInstance<JsRuleBuilder>, ClassInstance<JsRuleBuilder>>,
    ) -> Result<&Self> {
        self.run_rule_closure(env, Some(RustDirectionTag::Any), configure)
    }

    /// Materialize into a `NetworkPolicy` (camelCase JS object). Lazily
    /// parses every recorded `.ip()` / `.cidr()` / `.domain()` /
    /// `.domainSuffix()` input, validates `direction`-set + ICMP-egress-
    /// only invariants, and surfaces the first failure.
    #[napi]
    pub fn build(&self) -> Result<NetworkPolicy> {
        let policy = self.build_rust_policy()?;
        Ok(rust_policy_to_js(policy))
    }
}

impl JsNetworkPolicyBuilder {
    fn run_rule_closure(
        &mut self,
        env: &Env,
        initial_direction: Option<RustDirectionTag>,
        configure: Function<ClassInstance<JsRuleBuilder>, ClassInstance<JsRuleBuilder>>,
    ) -> Result<&Self> {
        let initial = JsRuleBuilder { ops: Vec::new() }.into_instance(env)?;
        let mut returned = configure.call(initial)?;
        let inner_ops = std::mem::take(&mut returned.ops);
        self.ops.push(TopOp::Rule {
            initial_direction,
            ops: inner_ops,
        });
        Ok(self)
    }

    /// Build a `microsandbox_network::policy::NetworkPolicy` by
    /// replaying the recorded ops onto a real `NetworkPolicyBuilder`.
    /// Used both by `.build()` (returns JS shape) and by
    /// `JsNetworkBuilder` to set the policy directly.
    pub(crate) fn build_rust_policy(&self) -> Result<RustNetworkPolicy> {
        let mut npb = RustNetworkPolicyBuilder::new();
        for op in &self.ops {
            match op.clone() {
                TopOp::DefaultAllow => npb = npb.default_allow(),
                TopOp::DefaultDeny => npb = npb.default_deny(),
                TopOp::DefaultEgress(a) => npb = npb.default_egress(a),
                TopOp::DefaultIngress(a) => npb = npb.default_ingress(a),
                TopOp::Rule {
                    initial_direction,
                    ops,
                } => {
                    npb = match initial_direction {
                        None => npb.rule(move |rb| apply_rule_ops(rb, ops)),
                        Some(RustDirectionTag::Egress) => {
                            npb.egress(move |rb| apply_rule_ops(rb, ops))
                        }
                        Some(RustDirectionTag::Ingress) => {
                            npb.ingress(move |rb| apply_rule_ops(rb, ops))
                        }
                        Some(RustDirectionTag::Any) => npb.any(move |rb| apply_rule_ops(rb, ops)),
                    };
                }
            }
        }
        npb.build()
            .map_err(|e| napi::Error::from_reason(format!("{e}")))
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: RuleBuilder
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsRuleBuilder {
    /// Set direction to `Egress` for subsequent rule-adders. Last-write-wins.
    #[napi]
    pub fn egress(&mut self) -> &Self {
        self.ops.push(RuleOp::DirEgress);
        self
    }

    /// Set direction to `Ingress` for subsequent rule-adders.
    #[napi]
    pub fn ingress(&mut self) -> &Self {
        self.ops.push(RuleOp::DirIngress);
        self
    }

    /// Set direction to `Any` (rules apply in both directions).
    #[napi]
    pub fn any(&mut self) -> &Self {
        self.ops.push(RuleOp::DirAny);
        self
    }

    /// Add `Tcp` to the protocols set.
    #[napi]
    pub fn tcp(&mut self) -> &Self {
        self.ops.push(RuleOp::Tcp);
        self
    }

    /// Add `Udp` to the protocols set.
    #[napi]
    pub fn udp(&mut self) -> &Self {
        self.ops.push(RuleOp::Udp);
        self
    }

    /// Add `Icmpv4` to the protocols set. Egress-only.
    #[napi]
    pub fn icmpv4(&mut self) -> &Self {
        self.ops.push(RuleOp::Icmpv4);
        self
    }

    /// Add `Icmpv6` to the protocols set. Egress-only.
    #[napi]
    pub fn icmpv6(&mut self) -> &Self {
        self.ops.push(RuleOp::Icmpv6);
        self
    }

    /// Add a single port to the ports set. `0..=65535`.
    #[napi]
    pub fn port(&mut self, port: u32) -> Result<&Self> {
        let p = u16::try_from(port)
            .map_err(|_| napi::Error::from_reason("port out of range (0..=65535)"))?;
        self.ops.push(RuleOp::Port(p));
        Ok(self)
    }

    /// Add an inclusive port range. `lo > hi` records an error surfaced
    /// at `.build()` time.
    #[napi(js_name = "portRange")]
    pub fn port_range(&mut self, lo: u32, hi: u32) -> Result<&Self> {
        let lo = u16::try_from(lo)
            .map_err(|_| napi::Error::from_reason("lo out of range (0..=65535)"))?;
        let hi = u16::try_from(hi)
            .map_err(|_| napi::Error::from_reason("hi out of range (0..=65535)"))?;
        self.ops.push(RuleOp::PortRange(lo, hi));
        Ok(self)
    }

    /// Add multiple single ports.
    #[napi]
    pub fn ports(&mut self, ports: Vec<u32>) -> Result<&Self> {
        let mut converted = Vec::with_capacity(ports.len());
        for p in ports {
            let p = u16::try_from(p)
                .map_err(|_| napi::Error::from_reason("port out of range (0..=65535)"))?;
            converted.push(p);
        }
        self.ops.push(RuleOp::Ports(converted));
        Ok(self)
    }

    // -- atomic group shortcuts --------------------------------------

    #[napi(js_name = "allowPublic")]
    pub fn allow_public(&mut self) -> &Self {
        self.ops
            .push(RuleOp::AllowGroup(RustDestinationGroup::Public));
        self
    }
    #[napi(js_name = "denyPublic")]
    pub fn deny_public(&mut self) -> &Self {
        self.ops
            .push(RuleOp::DenyGroup(RustDestinationGroup::Public));
        self
    }
    #[napi(js_name = "allowPrivate")]
    pub fn allow_private(&mut self) -> &Self {
        self.ops
            .push(RuleOp::AllowGroup(RustDestinationGroup::Private));
        self
    }
    #[napi(js_name = "denyPrivate")]
    pub fn deny_private(&mut self) -> &Self {
        self.ops
            .push(RuleOp::DenyGroup(RustDestinationGroup::Private));
        self
    }
    #[napi(js_name = "allowLoopback")]
    pub fn allow_loopback(&mut self) -> &Self {
        self.ops
            .push(RuleOp::AllowGroup(RustDestinationGroup::Loopback));
        self
    }
    #[napi(js_name = "denyLoopback")]
    pub fn deny_loopback(&mut self) -> &Self {
        self.ops
            .push(RuleOp::DenyGroup(RustDestinationGroup::Loopback));
        self
    }
    #[napi(js_name = "allowLinkLocal")]
    pub fn allow_link_local(&mut self) -> &Self {
        self.ops
            .push(RuleOp::AllowGroup(RustDestinationGroup::LinkLocal));
        self
    }
    #[napi(js_name = "denyLinkLocal")]
    pub fn deny_link_local(&mut self) -> &Self {
        self.ops
            .push(RuleOp::DenyGroup(RustDestinationGroup::LinkLocal));
        self
    }
    #[napi(js_name = "allowMeta")]
    pub fn allow_meta(&mut self) -> &Self {
        self.ops
            .push(RuleOp::AllowGroup(RustDestinationGroup::Metadata));
        self
    }
    #[napi(js_name = "denyMeta")]
    pub fn deny_meta(&mut self) -> &Self {
        self.ops
            .push(RuleOp::DenyGroup(RustDestinationGroup::Metadata));
        self
    }
    #[napi(js_name = "allowMulticast")]
    pub fn allow_multicast(&mut self) -> &Self {
        self.ops
            .push(RuleOp::AllowGroup(RustDestinationGroup::Multicast));
        self
    }
    #[napi(js_name = "denyMulticast")]
    pub fn deny_multicast(&mut self) -> &Self {
        self.ops
            .push(RuleOp::DenyGroup(RustDestinationGroup::Multicast));
        self
    }
    #[napi(js_name = "allowHost")]
    pub fn allow_host(&mut self) -> &Self {
        self.ops
            .push(RuleOp::AllowGroup(RustDestinationGroup::Host));
        self
    }
    #[napi(js_name = "denyHost")]
    pub fn deny_host(&mut self) -> &Self {
        self.ops.push(RuleOp::DenyGroup(RustDestinationGroup::Host));
        self
    }

    /// Allow `Loopback + LinkLocal + Host` (no `Metadata`).
    #[napi(js_name = "allowLocal")]
    pub fn allow_local(&mut self) -> &Self {
        self.ops.push(RuleOp::AllowLocal);
        self
    }

    /// Deny `Loopback + LinkLocal + Host`.
    #[napi(js_name = "denyLocal")]
    pub fn deny_local(&mut self) -> &Self {
        self.ops.push(RuleOp::DenyLocal);
        self
    }

    // -- bulk-domain shortcuts --------------------------------------

    /// Allow `Destination::Domain(name)`. One rule per call.
    #[napi(js_name = "allowDomain")]
    pub fn allow_domain(&mut self, name: String) -> &Self {
        self.ops.push(RuleOp::AllowDomains(vec![name]));
        self
    }

    /// Deny `Destination::Domain(name)`. One rule per call.
    #[napi(js_name = "denyDomain")]
    pub fn deny_domain(&mut self, name: String) -> &Self {
        self.ops.push(RuleOp::DenyDomains(vec![name]));
        self
    }

    /// Allow each name as a `Destination::Domain` rule.
    #[napi(js_name = "allowDomains")]
    pub fn allow_domains(&mut self, names: Vec<String>) -> &Self {
        self.ops.push(RuleOp::AllowDomains(names));
        self
    }

    /// Deny each name as a `Destination::Domain` rule.
    #[napi(js_name = "denyDomains")]
    pub fn deny_domains(&mut self, names: Vec<String>) -> &Self {
        self.ops.push(RuleOp::DenyDomains(names));
        self
    }

    /// Allow `Destination::DomainSuffix(suffix)`. Matches the apex and
    /// any subdomain.
    #[napi(js_name = "allowDomainSuffix")]
    pub fn allow_domain_suffix(&mut self, suffix: String) -> &Self {
        self.ops.push(RuleOp::AllowDomainSuffixes(vec![suffix]));
        self
    }

    /// Deny `Destination::DomainSuffix(suffix)`. Matches the apex and
    /// any subdomain.
    #[napi(js_name = "denyDomainSuffix")]
    pub fn deny_domain_suffix(&mut self, suffix: String) -> &Self {
        self.ops.push(RuleOp::DenyDomainSuffixes(vec![suffix]));
        self
    }

    /// Allow each suffix as a `Destination::DomainSuffix` rule.
    #[napi(js_name = "allowDomainSuffixes")]
    pub fn allow_domain_suffixes(&mut self, suffixes: Vec<String>) -> &Self {
        self.ops.push(RuleOp::AllowDomainSuffixes(suffixes));
        self
    }

    /// Deny each suffix as a `Destination::DomainSuffix` rule.
    #[napi(js_name = "denyDomainSuffixes")]
    pub fn deny_domain_suffixes(&mut self, suffixes: Vec<String>) -> &Self {
        self.ops.push(RuleOp::DenyDomainSuffixes(suffixes));
        self
    }

    /// Begin an explicit-destination rule with action `Allow`. The
    /// closure receives a `RuleDestinationBuilder` and must call exactly
    /// one of `.ip()` / `.cidr()` / `.domain()` / `.domainSuffix()` /
    /// `.group()` / `.any()` to commit the rule.
    #[napi]
    pub fn allow(
        &mut self,
        env: &Env,
        configure: Function<
            ClassInstance<JsRuleDestinationBuilder>,
            ClassInstance<JsRuleDestinationBuilder>,
        >,
    ) -> Result<&Self> {
        self.run_dest_closure(env, RustAction::Allow, configure)
    }

    /// Begin an explicit-destination rule with action `Deny`.
    #[napi]
    pub fn deny(
        &mut self,
        env: &Env,
        configure: Function<
            ClassInstance<JsRuleDestinationBuilder>,
            ClassInstance<JsRuleDestinationBuilder>,
        >,
    ) -> Result<&Self> {
        self.run_dest_closure(env, RustAction::Deny, configure)
    }
}

impl JsRuleBuilder {
    fn run_dest_closure(
        &mut self,
        env: &Env,
        action: RustAction,
        configure: Function<
            ClassInstance<JsRuleDestinationBuilder>,
            ClassInstance<JsRuleDestinationBuilder>,
        >,
    ) -> Result<&Self> {
        let initial = JsRuleDestinationBuilder { dest: None }.into_instance(env)?;
        let mut returned = configure.call(initial)?;
        if let Some(dest) = returned.dest.take() {
            self.ops.push(RuleOp::Commit { action, dest });
        }
        Ok(self)
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: RuleDestinationBuilder
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsRuleDestinationBuilder {
    /// Commit the rule with destination `Ip(<addr>)`. Parsed at
    /// `.build()` time; invalid IPs surface as `InvalidIp` then.
    #[napi]
    pub fn ip(&mut self, ip: String) -> &Self {
        self.dest = Some(DestKind::Ip(ip));
        self
    }

    /// Commit the rule with destination `Cidr(<network>)`.
    #[napi]
    pub fn cidr(&mut self, cidr: String) -> &Self {
        self.dest = Some(DestKind::Cidr(cidr));
        self
    }

    /// Commit the rule with destination `Domain(<name>)`. Matches only
    /// when a cached hostname for the remote IP equals this name.
    #[napi]
    pub fn domain(&mut self, domain: String) -> &Self {
        self.dest = Some(DestKind::Domain(domain));
        self
    }

    /// Commit the rule with destination `DomainSuffix(<name>)`. Matches
    /// the apex domain itself and any subdomain.
    #[napi(js_name = "domainSuffix")]
    pub fn domain_suffix(&mut self, suffix: String) -> &Self {
        self.dest = Some(DestKind::DomainSuffix(suffix));
        self
    }

    /// Commit the rule with destination `Group(<group>)`. `group` is
    /// one of the `DestinationGroup` strings (`"public" | "private" |
    /// "loopback" | "link-local" | "metadata" | "multicast" | "host"`).
    #[napi]
    pub fn group(&mut self, group: String) -> Result<&Self> {
        self.dest = Some(DestKind::Group(parse_group(&group)?));
        Ok(self)
    }

    /// Commit the rule with destination `Any` (matches every remote).
    #[napi]
    pub fn any(&mut self) -> &Self {
        self.dest = Some(DestKind::Any);
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Types: JS-shape NetworkPolicy
//--------------------------------------------------------------------------------------------------

#[derive(Clone)]
#[napi(object)]
pub struct NetworkPolicy {
    pub default_egress: String,
    pub default_ingress: String,
    pub rules: Vec<NetworkPolicyRule>,
}

#[derive(Clone)]
#[napi(object)]
pub struct NetworkPolicyRule {
    pub direction: String,
    pub destination: NetworkPolicyDestination,
    pub protocols: Vec<String>,
    pub ports: Vec<NetworkPolicyPortRange>,
    pub action: String,
}

#[derive(Clone)]
#[napi(object)]
pub struct NetworkPolicyDestination {
    /// `"any" | "cidr" | "domain" | "domainSuffix" | "group"`.
    pub kind: String,
    pub cidr: Option<String>,
    pub domain: Option<String>,
    pub suffix: Option<String>,
    pub group: Option<String>,
}

#[derive(Clone)]
#[napi(object)]
pub struct NetworkPolicyPortRange {
    pub start: u32,
    pub end: u32,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn apply_rule_ops(rb: &mut RustRuleBuilder, ops: Vec<RuleOp>) -> &mut RustRuleBuilder {
    for op in ops {
        match op {
            RuleOp::DirEgress => {
                rb.egress();
            }
            RuleOp::DirIngress => {
                rb.ingress();
            }
            RuleOp::DirAny => {
                rb.any();
            }
            RuleOp::Tcp => {
                rb.tcp();
            }
            RuleOp::Udp => {
                rb.udp();
            }
            RuleOp::Icmpv4 => {
                rb.icmpv4();
            }
            RuleOp::Icmpv6 => {
                rb.icmpv6();
            }
            RuleOp::Port(p) => {
                rb.port(p);
            }
            RuleOp::PortRange(lo, hi) => {
                rb.port_range(lo, hi);
            }
            RuleOp::Ports(ports) => {
                rb.ports(ports);
            }
            RuleOp::AllowGroup(g) => {
                apply_group_shortcut(rb, RustAction::Allow, g);
            }
            RuleOp::DenyGroup(g) => {
                apply_group_shortcut(rb, RustAction::Deny, g);
            }
            RuleOp::AllowLocal => {
                rb.allow_local();
            }
            RuleOp::DenyLocal => {
                rb.deny_local();
            }
            RuleOp::AllowDomains(names) => {
                rb.allow_domains(names);
            }
            RuleOp::DenyDomains(names) => {
                rb.deny_domains(names);
            }
            RuleOp::AllowDomainSuffixes(suffixes) => {
                rb.allow_domain_suffixes(suffixes);
            }
            RuleOp::DenyDomainSuffixes(suffixes) => {
                rb.deny_domain_suffixes(suffixes);
            }
            RuleOp::Commit { action, dest } => {
                let dab = match action {
                    RustAction::Allow => rb.allow(),
                    RustAction::Deny => rb.deny(),
                };
                match dest {
                    DestKind::Ip(s) => {
                        dab.ip(s);
                    }
                    DestKind::Cidr(s) => {
                        dab.cidr(s);
                    }
                    DestKind::Domain(s) => {
                        dab.domain(s);
                    }
                    DestKind::DomainSuffix(s) => {
                        dab.domain_suffix(s);
                    }
                    DestKind::Group(g) => {
                        dab.group(g);
                    }
                    DestKind::Any => {
                        dab.any();
                    }
                }
            }
        }
    }
    rb
}

fn apply_group_shortcut(rb: &mut RustRuleBuilder, action: RustAction, g: RustDestinationGroup) {
    use RustDestinationGroup as G;
    match (action, g) {
        (RustAction::Allow, G::Public) => {
            rb.allow_public();
        }
        (RustAction::Deny, G::Public) => {
            rb.deny_public();
        }
        (RustAction::Allow, G::Private) => {
            rb.allow_private();
        }
        (RustAction::Deny, G::Private) => {
            rb.deny_private();
        }
        (RustAction::Allow, G::Loopback) => {
            rb.allow_loopback();
        }
        (RustAction::Deny, G::Loopback) => {
            rb.deny_loopback();
        }
        (RustAction::Allow, G::LinkLocal) => {
            rb.allow_link_local();
        }
        (RustAction::Deny, G::LinkLocal) => {
            rb.deny_link_local();
        }
        (RustAction::Allow, G::Metadata) => {
            rb.allow_meta();
        }
        (RustAction::Deny, G::Metadata) => {
            rb.deny_meta();
        }
        (RustAction::Allow, G::Multicast) => {
            rb.allow_multicast();
        }
        (RustAction::Deny, G::Multicast) => {
            rb.deny_multicast();
        }
        (RustAction::Allow, G::Host) => {
            rb.allow_host();
        }
        (RustAction::Deny, G::Host) => {
            rb.deny_host();
        }
    }
}

fn parse_action(s: &str) -> Result<RustAction> {
    match s {
        "allow" => Ok(RustAction::Allow),
        "deny" => Ok(RustAction::Deny),
        other => Err(napi::Error::from_reason(format!(
            "unknown action `{other}` (expected allow | deny)"
        ))),
    }
}

fn parse_group(s: &str) -> Result<RustDestinationGroup> {
    match s {
        "public" => Ok(RustDestinationGroup::Public),
        "private" => Ok(RustDestinationGroup::Private),
        "loopback" => Ok(RustDestinationGroup::Loopback),
        "link-local" => Ok(RustDestinationGroup::LinkLocal),
        "metadata" => Ok(RustDestinationGroup::Metadata),
        "multicast" => Ok(RustDestinationGroup::Multicast),
        "host" => Ok(RustDestinationGroup::Host),
        other => Err(napi::Error::from_reason(format!(
            "unknown destination group `{other}`"
        ))),
    }
}

fn action_to_str(a: RustAction) -> String {
    match a {
        RustAction::Allow => "allow".to_string(),
        RustAction::Deny => "deny".to_string(),
    }
}

fn group_to_str(g: RustDestinationGroup) -> String {
    match g {
        RustDestinationGroup::Public => "public".to_string(),
        RustDestinationGroup::Private => "private".to_string(),
        RustDestinationGroup::Loopback => "loopback".to_string(),
        RustDestinationGroup::LinkLocal => "link-local".to_string(),
        RustDestinationGroup::Metadata => "metadata".to_string(),
        RustDestinationGroup::Multicast => "multicast".to_string(),
        RustDestinationGroup::Host => "host".to_string(),
    }
}

fn rust_policy_to_js(p: RustNetworkPolicy) -> NetworkPolicy {
    use microsandbox_network::policy::{
        Destination as RustDestination, Direction as RustDirection, Protocol as RustProtocol,
    };
    let dir_to_str = |d: RustDirection| match d {
        RustDirection::Egress => "egress".to_string(),
        RustDirection::Ingress => "ingress".to_string(),
        RustDirection::Any => "any".to_string(),
    };
    let proto_to_str = |p: RustProtocol| match p {
        RustProtocol::Tcp => "tcp".to_string(),
        RustProtocol::Udp => "udp".to_string(),
        RustProtocol::Icmpv4 => "icmpv4".to_string(),
        RustProtocol::Icmpv6 => "icmpv6".to_string(),
    };
    let blank_dest = || NetworkPolicyDestination {
        kind: String::new(),
        cidr: None,
        domain: None,
        suffix: None,
        group: None,
    };
    let dest_to_js = |d: RustDestination| match d {
        RustDestination::Any => NetworkPolicyDestination {
            kind: "any".to_string(),
            ..blank_dest()
        },
        RustDestination::Cidr(net) => NetworkPolicyDestination {
            kind: "cidr".to_string(),
            cidr: Some(net.to_string()),
            ..blank_dest()
        },
        RustDestination::Domain(name) => NetworkPolicyDestination {
            kind: "domain".to_string(),
            domain: Some(name.as_str().to_string()),
            ..blank_dest()
        },
        RustDestination::DomainSuffix(name) => NetworkPolicyDestination {
            kind: "domainSuffix".to_string(),
            suffix: Some(name.as_str().to_string()),
            ..blank_dest()
        },
        RustDestination::Group(g) => NetworkPolicyDestination {
            kind: "group".to_string(),
            group: Some(group_to_str(g)),
            ..blank_dest()
        },
    };
    let rules = p
        .rules
        .into_iter()
        .map(|r| NetworkPolicyRule {
            direction: dir_to_str(r.direction),
            destination: dest_to_js(r.destination),
            protocols: r.protocols.into_iter().map(proto_to_str).collect(),
            ports: r
                .ports
                .into_iter()
                .map(|pr| NetworkPolicyPortRange {
                    start: pr.start as u32,
                    end: pr.end as u32,
                })
                .collect(),
            action: action_to_str(r.action),
        })
        .collect();
    NetworkPolicy {
        default_egress: action_to_str(p.default_egress),
        default_ingress: action_to_str(p.default_ingress),
        rules,
    }
}
