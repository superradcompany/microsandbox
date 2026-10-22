//! Select portable host-gateway policy without resolving endpoints or authorizing activation.

use std::collections::BTreeSet;
use std::fmt;

use microsandbox_types::snapshot::saved_config::{SavedNetworkConfig, SavedRateLimit, SavedValue};
use microsandbox_types::{
    DnsConfigPatch, HttpConfigPatch, NetworkPolicy, NetworkRateLimiterConfigPatch,
    NetworkSpecPatch, PortRange, RateLimiterConfig, Rule, TlsConfigPatch, TokenBucketConfig,
};

use crate::{MicrosandboxError, MicrosandboxResult};

use super::SnapshotConfigMode;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Destination-owned inspection baseline. Mandatory enforcement is checked separately
/// after binding resolution and final explicit/managed configuration assembly.
pub struct DestinationNetworkBaseline {
    /// Whether ordinary destination policy requires inspectable application authority.
    pub strict: bool,
    /// Whether the destination normally enables TLS interception.
    pub tls_enabled: bool,
    /// Ports normally inspected by the destination.
    pub intercepted_ports: Vec<u16>,
}

/// Optional portable policy defaults that may be discarded individually.
/// Resource bindings and captured network identity are deliberately not clear selectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetworkPolicyClear {
    /// NIC presence; cannot be cleared for full resume.
    Enabled,
    /// Complete ordered packet policy.
    Policy,
    /// Inspectable-authority policy.
    Strict,
    /// DNS rebinding policy, not resolver bindings.
    DnsRebindProtection,
    /// DNS query timeout.
    DnsQueryTimeout,
    /// TLS interception setting, not CA bindings.
    TlsEnabled,
    /// Entire intercepted-port list.
    TlsInterceptedPorts,
    /// Entire ordered bypass list.
    TlsBypass,
    /// Global upstream verification setting.
    TlsVerifyUpstream,
    /// QUIC bypass prevention.
    TlsBlockQuic,
    /// Entire ordered scoped verification list.
    TlsScopedVerification,
    /// Outbound TCP cap.
    MaxTcpConnections,
    /// Inbound TCP cap.
    MaxInboundTcpConnections,
    /// UDP cap.
    MaxUdpConnections,
    /// TCP accept queue depth.
    TcpAcceptQueueSize,
    /// Egress token buckets, not counters.
    EgressRateLimit,
    /// Ingress token buckets, not counters.
    IngressRateLimit,
    /// Entire ordered NAT64 prefix list.
    Nat64Prefixes,
    /// HTTP denial-response enablement.
    HttpDenyResponse,
    /// HTTP denial-response format.
    HttpDenyResponseFormat,
    /// Legacy denial template.
    HttpDenyMessage,
    /// Network denial message.
    HttpNetworkDenyMessage,
    /// Secret denial message.
    HttpSecretDenyMessage,
}

/// Selected saved behavior that needs explicit destination intent. An artifact
/// cannot grant these permissions; mandatory destination policy still applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetworkPolicyApproval {
    /// Disable inspectable-authority checks relative to the destination baseline.
    RelaxedAuthority,
    /// Disable DNS rebinding protection.
    DisabledDnsRebindProtection,
    /// Disable interception relative to the destination baseline.
    DisabledTlsInterception,
    /// Remove ports inspected by the destination baseline.
    ReducedTlsInterception,
    /// Bypass inspection for the selected ordered hostname list.
    TlsBypass,
    /// Disable global upstream certificate verification.
    DisabledUpstreamVerification,
    /// Disable scoped upstream certificate verification.
    DisabledScopedVerification,
    /// Allow QUIC to bypass interception.
    DisabledQuicProtection,
}

/// A lower-priority policy overlay, never a ready network configuration.
pub struct NetworkPolicySelection {
    /// Safe literal policy defaults only. Endpoints, credentials, CA paths, listeners,
    /// allocated guest identity and secret entries remain outside this overlay.
    pub defaults: NetworkSpecPatch,
    /// Explicit destination approval still needed for these selected saved settings.
    pub required_approvals: BTreeSet<NetworkPolicyApproval>,
    /// Unknown policy fields not individually overridden, cleared or discarded.
    pub unknown_fields: BTreeSet<&'static str>,
    /// Recorded builtin-default fields that must not be mistaken for unrecorded values.
    pub defaulted_fields: BTreeSet<&'static str>,
    /// Concrete absent optional values (for example, an unlimited rate direction).
    /// Final assembly must clear inherited values rather than silently retaining them.
    pub absent_fields: BTreeSet<&'static str>,
    /// Structural clears must also suppress older/image fallback during final assembly.
    pub cleared_fields: BTreeSet<NetworkPolicyClear>,
    /// Full resume needs authoritative NIC/trust/connection compatibility, independently
    /// of this policy overlay. Fresh mode cannot waive that obligation.
    pub requires_full_compatibility: bool,
}

#[derive(Default)]
struct Observations {
    unknown: BTreeSet<&'static str>,
    defaulted: BTreeSet<&'static str>,
    absent: BTreeSet<&'static str>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for NetworkPolicySelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkPolicySelection")
            .field("required_approvals", &self.required_approvals)
            .field("unknown_fields", &self.unknown_fields)
            .field("cleared_fields", &self.cleared_fields)
            .field("defaulted_fields", &self.defaulted_fields)
            .field("absent_fields", &self.absent_fields)
            .field(
                "requires_full_compatibility",
                &self.requires_full_compatibility,
            )
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Select reusable scalar/ordered gateway policy, preserving sparse explicit precedence.
///
/// Validate the complete saved document before calling individual selectors. This
/// stage validates its source section even when fresh mode or overrides mask it.
/// Bindings, keyed ports/secrets, guest trust and proxy routing require separate
/// selection/admission; no field in this result erases those source requirements.
/// After explicit/managed assembly, enforce mandatory destination policy before
/// first guest traffic and check authoritative full-state network compatibility.
pub fn select_network_policy_defaults(
    saved: &SavedNetworkConfig,
    explicit: &NetworkSpecPatch,
    clears: &[NetworkPolicyClear],
    mode: SnapshotConfigMode,
    full_resume: bool,
    baseline: &DestinationNetworkBaseline,
) -> MicrosandboxResult<NetworkPolicySelection> {
    saved
        .validate()
        .map_err(|e| MicrosandboxError::InvalidConfig(e.to_string()))?;
    if clears.len() > microsandbox_types::snapshot::saved_config::MAX_SAVED_CONFIG_ENTRIES {
        return Err(error("SCFG_LIMIT", "network", "too many clear selectors"));
    }
    if full_resume && clears.contains(&NetworkPolicyClear::Enabled) {
        return Err(error(
            "SCFG_FULL_STATE",
            "network.enabled",
            "captured NIC presence cannot be cleared",
        ));
    }
    if full_resume
        && let (Some(source), Some(target)) = (
            saved.enabled.as_ref().and_then(SavedValue::value),
            explicit.enabled,
        )
        && *source != target
    {
        return Err(error(
            "SCFG_FULL_STATE",
            "network.enabled",
            "full resume cannot change captured NIC presence",
        ));
    }
    // Exhaustive source classification: binding-bearing fields are not optional
    // policy defaults and remain inputs to the binding/resource stage.
    let SavedNetworkConfig {
        enabled,
        policy,
        strict,
        dns,
        tls,
        secrets: _,
        max_tcp_connections,
        max_inbound_tcp_connections,
        max_udp_connections,
        tcp_accept_queue_size,
        rate_limiter,
        nat64_prefixes,
        ports: _,
        guest_trust: _,
        http,
        outbound_proxy: _,
    } = saved;
    let mut selected = NetworkPolicySelection {
        defaults: NetworkSpecPatch::new(),
        required_approvals: BTreeSet::new(),
        unknown_fields: BTreeSet::new(),
        defaulted_fields: BTreeSet::new(),
        absent_fields: BTreeSet::new(),
        cleared_fields: clears.iter().copied().collect(),
        requires_full_compatibility: full_resume,
    };
    let keep = mode == SnapshotConfigMode::Saved;
    let mut observations = Observations::default();
    let mut choose = |field, path, explicit, retain, value| {
        select(
            value,
            path,
            explicit,
            retain && !clears.contains(&field),
            &mut observations,
        )
    };
    // Boolean fields share a closure; other types use the same generic helper below.
    selected.defaults.enabled = choose(
        NetworkPolicyClear::Enabled,
        "network.enabled",
        explicit.enabled.is_some(),
        keep || full_resume,
        enabled.as_ref(),
    );
    selected.defaults.strict = choose(
        NetworkPolicyClear::Strict,
        "network.strict",
        explicit.strict.is_some(),
        keep,
        strict.as_ref(),
    );
    let retain = |field| keep && !clears.contains(&field);
    selected.defaults.policy = select(
        policy.as_ref(),
        "network.policy",
        explicit.policy.is_some(),
        retain(NetworkPolicyClear::Policy),
        &mut observations,
    )
    .map(|p| NetworkPolicy {
        default_egress: p.default_egress,
        default_ingress: p.default_ingress,
        rules: p
            .rules
            .into_iter()
            .map(|r| Rule {
                direction: r.direction,
                destination: r.destination,
                protocols: r.protocols,
                ports: r
                    .ports
                    .into_iter()
                    .map(|p| PortRange {
                        start: p.start,
                        end: p.end,
                    })
                    .collect(),
                action: r.action,
            })
            .collect(),
    });
    selected.defaults.max_tcp_connections = capacity(
        max_tcp_connections.as_ref(),
        "network.max_tcp_connections",
        explicit.max_tcp_connections.is_some(),
        retain(NetworkPolicyClear::MaxTcpConnections),
        &mut observations,
    )?;
    selected.defaults.max_inbound_tcp_connections = capacity(
        max_inbound_tcp_connections.as_ref(),
        "network.max_inbound_tcp_connections",
        explicit.max_inbound_tcp_connections.is_some(),
        retain(NetworkPolicyClear::MaxInboundTcpConnections),
        &mut observations,
    )?;
    selected.defaults.max_udp_connections = capacity(
        max_udp_connections.as_ref(),
        "network.max_udp_connections",
        explicit.max_udp_connections.is_some(),
        retain(NetworkPolicyClear::MaxUdpConnections),
        &mut observations,
    )?;
    selected.defaults.tcp_accept_queue_size = select(
        tcp_accept_queue_size.as_ref(),
        "network.tcp_accept_queue_size",
        explicit.tcp_accept_queue_size.is_some(),
        retain(NetworkPolicyClear::TcpAcceptQueueSize),
        &mut observations,
    );
    selected.defaults.nat64_prefixes = select(
        nat64_prefixes.as_ref(),
        "network.nat64_prefixes",
        explicit.nat64_prefixes.is_some(),
        retain(NetworkPolicyClear::Nat64Prefixes),
        &mut observations,
    );

    let input_dns = explicit.dns.as_ref();
    let dns_patch = DnsConfigPatch {
        rebind_protection: project(
            dns.as_ref(),
            |v| v.rebind_protection,
            "network.dns.rebind_protection",
            input_dns.is_some_and(|v| v.rebind_protection.is_some()),
            retain(NetworkPolicyClear::DnsRebindProtection),
            &mut observations,
        ),
        query_timeout_ms: project(
            dns.as_ref(),
            |v| v.query_timeout_ms,
            "network.dns.query_timeout_ms",
            input_dns.is_some_and(|v| v.query_timeout_ms.is_some()),
            retain(NetworkPolicyClear::DnsQueryTimeout),
            &mut observations,
        ),
        // Nameservers are destination bindings, never saved endpoint fallbacks.
        nameservers: None,
    };
    if dns_patch.rebind_protection.is_some() || dns_patch.query_timeout_ms.is_some() {
        selected.defaults.dns = Some(dns_patch);
    }
    let input_tls = explicit.tls.as_ref();
    let tls_patch = TlsConfigPatch {
        enabled: project(
            tls.as_ref(),
            |v| v.enabled,
            "network.tls.enabled",
            input_tls.is_some_and(|v| v.enabled.is_some()),
            retain(NetworkPolicyClear::TlsEnabled),
            &mut observations,
        ),
        intercepted_ports: project(
            tls.as_ref(),
            |v| v.intercepted_ports.clone(),
            "network.tls.intercepted_ports",
            input_tls.is_some_and(|v| v.intercepted_ports.is_some()),
            retain(NetworkPolicyClear::TlsInterceptedPorts),
            &mut observations,
        ),
        bypass: project(
            tls.as_ref(),
            |v| v.bypass.clone(),
            "network.tls.bypass",
            input_tls.is_some_and(|v| v.bypass.is_some()),
            retain(NetworkPolicyClear::TlsBypass),
            &mut observations,
        ),
        verify_upstream: project(
            tls.as_ref(),
            |v| v.verify_upstream,
            "network.tls.verify_upstream",
            input_tls.is_some_and(|v| v.verify_upstream.is_some()),
            retain(NetworkPolicyClear::TlsVerifyUpstream),
            &mut observations,
        ),
        block_quic_on_intercept: project(
            tls.as_ref(),
            |v| v.block_quic_on_intercept,
            "network.tls.block_quic_on_intercept",
            input_tls.is_some_and(|v| v.block_quic_on_intercept.is_some()),
            retain(NetworkPolicyClear::TlsBlockQuic),
            &mut observations,
        ),
        scoped_verify_upstream: project(
            tls.as_ref(),
            |v| {
                v.scoped_verify_upstream
                    .iter()
                    .map(|s| microsandbox_types::ScopedVerifyUpstream {
                        pattern: s.pattern.clone(),
                        verify: s.verify,
                    })
                    .collect()
            },
            "network.tls.scoped_verify_upstream",
            input_tls.is_some_and(|v| v.scoped_verify_upstream.is_some()),
            retain(NetworkPolicyClear::TlsScopedVerification),
            &mut observations,
        ),
        // Trust paths, identity files and certificate-cache tuning are destination-owned.
        upstream_ca_cert: None,
        scoped_upstream_ca_cert: None,
        intercept_ca: None,
        cache: None,
    };
    if tls_patch.enabled.is_some()
        || tls_patch.intercepted_ports.is_some()
        || tls_patch.bypass.is_some()
        || tls_patch.verify_upstream.is_some()
        || tls_patch.block_quic_on_intercept.is_some()
        || tls_patch.scoped_verify_upstream.is_some()
    {
        selected.defaults.tls = Some(tls_patch);
    }
    let input_rate = explicit.rate_limiter.as_ref();
    let rate_patch = NetworkRateLimiterConfigPatch {
        egress: project_optional(
            rate_limiter.as_ref(),
            |v| v.egress.clone(),
            "network.rate_limiter.egress",
            input_rate.is_some_and(|v| v.egress.is_some()),
            retain(NetworkPolicyClear::EgressRateLimit),
            &mut observations,
        )
        .map(rate),
        ingress: project_optional(
            rate_limiter.as_ref(),
            |v| v.ingress.clone(),
            "network.rate_limiter.ingress",
            input_rate.is_some_and(|v| v.ingress.is_some()),
            retain(NetworkPolicyClear::IngressRateLimit),
            &mut observations,
        )
        .map(rate),
    };
    if rate_patch.egress.is_some() || rate_patch.ingress.is_some() {
        selected.defaults.rate_limiter = Some(rate_patch);
    }
    let input_http = &explicit.http;
    selected.defaults.http = HttpConfigPatch {
        deny_response: project(
            http.as_ref(),
            |v| v.deny_response,
            "network.http.deny_response",
            input_http.deny_response.is_some(),
            retain(NetworkPolicyClear::HttpDenyResponse),
            &mut observations,
        ),
        deny_response_format: project(
            http.as_ref(),
            |v| v.deny_response_format,
            "network.http.deny_response_format",
            input_http.deny_response_format.is_some(),
            retain(NetworkPolicyClear::HttpDenyResponseFormat),
            &mut observations,
        ),
        deny_message: project_optional(
            http.as_ref(),
            |v| v.deny_message.clone(),
            "network.http.deny_message",
            input_http.deny_message.is_some(),
            retain(NetworkPolicyClear::HttpDenyMessage),
            &mut observations,
        ),
        network_deny_message: project_optional(
            http.as_ref(),
            |v| v.network_deny_message.clone(),
            "network.http.network_deny_message",
            input_http.network_deny_message.is_some(),
            retain(NetworkPolicyClear::HttpNetworkDenyMessage),
            &mut observations,
        ),
        secret_deny_message: project_optional(
            http.as_ref(),
            |v| v.secret_deny_message.clone(),
            "network.http.secret_deny_message",
            input_http.secret_deny_message.is_some(),
            retain(NetworkPolicyClear::HttpSecretDenyMessage),
            &mut observations,
        ),
    };
    selected.unknown_fields = observations.unknown;
    selected.defaulted_fields = observations.defaulted;
    selected.absent_fields = observations.absent;
    selected.required_approvals = approvals(&selected.defaults, baseline);
    Ok(selected)
}

fn select<T: Clone>(
    source: Option<&SavedValue<T>>,
    path: &'static str,
    supplied: bool,
    keep: bool,
    observations: &mut Observations,
) -> Option<T> {
    project(source, Clone::clone, path, supplied, keep, observations)
}

fn project<T, U>(
    source: Option<&SavedValue<T>>,
    value: impl FnOnce(&T) -> U,
    path: &'static str,
    supplied: bool,
    keep: bool,
    observations: &mut Observations,
) -> Option<U> {
    if supplied || !keep {
        return None;
    }
    match source {
        Some(SavedValue::Value { value: source, .. }) => Some(value(source)),
        Some(SavedValue::Unknown { .. }) => {
            observations.unknown.insert(path);
            None
        }
        Some(SavedValue::Default {}) => {
            observations.defaulted.insert(path);
            None
        }
        None => None,
    }
}

// A native sparse patch cannot represent every explicit None. Preserve it as an
// operation for final assembly instead of flattening it into "leave unchanged".
fn project_optional<T, U>(
    source: Option<&SavedValue<T>>,
    value: impl FnOnce(&T) -> Option<U>,
    path: &'static str,
    supplied: bool,
    keep: bool,
    observations: &mut Observations,
) -> Option<U> {
    match project(source, value, path, supplied, keep, observations) {
        Some(None) => {
            observations.absent.insert(path);
            None
        }
        Some(Some(value)) => Some(value),
        None => None,
    }
}

fn capacity(
    source: Option<&SavedValue<u64>>,
    path: &'static str,
    supplied: bool,
    keep: bool,
    observations: &mut Observations,
) -> MicrosandboxResult<Option<usize>> {
    select(source, path, supplied, keep, observations)
        .map(|value| {
            usize::try_from(value).map_err(|_| {
                error(
                    "SCFG_VALUE",
                    path,
                    "saved capacity is not representable on this destination",
                )
            })
        })
        .transpose()
}

fn rate(value: SavedRateLimit) -> RateLimiterConfig {
    let bucket =
        |v: microsandbox_types::snapshot::saved_config::SavedTokenBucket| TokenBucketConfig {
            size: v.size,
            refill_time_ms: v.refill_time_ms,
            one_time_burst: v.one_time_burst,
        };
    RateLimiterConfig {
        bandwidth: value.bandwidth.map(bucket),
        ops: value.ops.map(bucket),
    }
}

pub(super) fn approvals(
    defaults: &NetworkSpecPatch,
    baseline: &DestinationNetworkBaseline,
) -> BTreeSet<NetworkPolicyApproval> {
    let mut approvals = BTreeSet::new();
    if baseline.strict && defaults.strict == Some(false) {
        approvals.insert(NetworkPolicyApproval::RelaxedAuthority);
    }
    if defaults
        .dns
        .as_ref()
        .is_some_and(|dns| dns.rebind_protection == Some(false))
    {
        approvals.insert(NetworkPolicyApproval::DisabledDnsRebindProtection);
    }
    if let Some(tls) = &defaults.tls {
        if baseline.tls_enabled && tls.enabled == Some(false) {
            approvals.insert(NetworkPolicyApproval::DisabledTlsInterception);
        }
        if baseline.tls_enabled
            && tls.intercepted_ports.as_ref().is_some_and(|ports| {
                baseline
                    .intercepted_ports
                    .iter()
                    .any(|p| !ports.contains(p))
            })
        {
            approvals.insert(NetworkPolicyApproval::ReducedTlsInterception);
        }
        if tls.bypass.as_ref().is_some_and(|v| !v.is_empty()) {
            approvals.insert(NetworkPolicyApproval::TlsBypass);
        }
        if tls.verify_upstream == Some(false) {
            approvals.insert(NetworkPolicyApproval::DisabledUpstreamVerification);
        }
        if tls.block_quic_on_intercept == Some(false) {
            approvals.insert(NetworkPolicyApproval::DisabledQuicProtection);
        }
        if tls
            .scoped_verify_upstream
            .as_ref()
            .is_some_and(|v| v.iter().any(|scope| !scope.verify))
        {
            approvals.insert(NetworkPolicyApproval::DisabledScopedVerification);
        }
    }
    approvals
}

fn error(code: &str, path: &str, reason: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!("{code}: {path}: {reason}"))
}
