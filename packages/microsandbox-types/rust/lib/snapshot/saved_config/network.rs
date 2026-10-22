//! Portable network policy and destination requirements, without host endpoints or credentials.

use ipnetwork::Ipv6Network;
use serde::{Deserialize, Serialize};

use crate::{
    Action, Destination, Direction, HostPattern, HttpDenyResponseFormat, PortProtocol, Protocol,
    SecretViolationAction,
};

use super::SavedValue;
use super::value::deserialize_present;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Normalized network settings. Recorded allocation identity belongs to capture provenance,
/// not this reusable policy: a destination must never allocate a source IP/MAC by fallback.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedNetworkConfig {
    /// Whether networking was enabled; activation still enforces destination policy.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub enabled: Option<SavedValue<bool>>,
    /// Resolved ordered policy, never source-host profile names.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub policy: Option<SavedValue<SavedNetworkPolicy>>,
    /// Inspectable-authority policy; a saved value is not permission to weaken a destination.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub strict: Option<SavedValue<bool>>,
    /// Resolver requirements and DNS policy, excluding source resolver endpoints.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub dns: Option<SavedValue<SavedDnsConfig>>,
    /// TLS policy and trust bindings, excluding certificate/key paths and credential bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub tls: Option<SavedValue<SavedTlsConfig>>,
    /// Placeholder/substitution policy and logical secret requirements only.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub secrets: Option<SavedValue<SavedSecretsConfig>>,
    /// TCP connection cap; explicit zero retains its unlimited meaning.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub max_tcp_connections: Option<SavedValue<u64>>,
    /// Inbound published-port cap, distinct from outbound TCP capacity.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub max_inbound_tcp_connections: Option<SavedValue<u64>>,
    /// UDP relay session cap; explicit zero retains its unlimited meaning.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub max_udp_connections: Option<SavedValue<u64>>,
    /// Published-port accept queue depth; no runtime counters are saved.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub tcp_accept_queue_size: Option<SavedValue<u32>>,
    /// Configured token buckets; host-side accounting starts fresh.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub rate_limiter: Option<SavedValue<SavedNetworkRateLimits>>,
    /// Resolved /96 NAT64 prefixes for policy classification.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub nat64_prefixes: Option<SavedValue<Vec<Ipv6Network>>>,
    /// Guest services with required destination listener bindings, never source host ports.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub ports: Option<SavedValue<Vec<SavedPublishedPort>>>,
    /// Trust material to install for disk boot, requiring explicit destination bindings.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub guest_trust: Option<SavedValue<Vec<SavedBindingReference>>>,
    /// Normalized denial-response configuration, excluding source logging settings.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub http: Option<SavedValue<SavedHttpConfig>>,
    /// Proxy protocol and destination bindings; no endpoint or credentials are embedded.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub outbound_proxy: Option<SavedValue<SavedProxy>>,
}

/// A logical requirement, not a host path, source env name, URL or resolved secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedBindingReference {
    /// Opaque binding identifier in the full configuration inventory.
    pub id: String,
}

/// Ordered first-match network policy, with both defaults recorded explicitly.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedNetworkPolicy {
    /// Action when no outbound rule matches.
    pub default_egress: Action,
    /// Action when no inbound rule matches.
    pub default_ingress: Action,
    /// Rules in their original evaluation order; never sorted during capture.
    pub rules: Vec<SavedNetworkRule>,
}

/// A strict portable rule; existing direction/action/destination vocabulary is preserved.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedNetworkRule {
    /// Traffic direction.
    pub direction: Direction,
    /// Guest-side destination classification, not a host resource binding.
    pub destination: Destination,
    /// Empty matches every protocol.
    pub protocols: Vec<Protocol>,
    /// Empty matches every port.
    pub ports: Vec<SavedPortRange>,
    /// Matched action.
    pub action: Action,
}

/// Inclusive port range, rejecting reversed endpoints.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedPortRange {
    /// First port.
    pub start: u16,
    /// Last port.
    pub end: u16,
}

/// DNS filtering/tuning and logical destination resolver requirements.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedDnsConfig {
    /// A false value needs explicit destination approval before reuse.
    pub rebind_protection: bool,
    /// DNS timeout in milliseconds.
    pub query_timeout_ms: u64,
    /// Empty uses destination discovery; never replays the source resolver configuration.
    pub resolvers: Vec<SavedBindingReference>,
}

/// TLS policy without private keys, certificate files or certificate cache state.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedTlsConfig {
    /// Whether interception was active.
    pub enabled: bool,
    /// Ports selected for interception.
    pub intercepted_ports: Vec<u16>,
    /// Ordered hostname bypass patterns; not saved consent to bypass inspection.
    pub bypass: Vec<String>,
    /// Global upstream verification policy; false is a recorded relaxation.
    pub verify_upstream: bool,
    /// Whether intercepted ports also block QUIC bypass.
    pub block_quic_on_intercept: bool,
    /// Destination bindings for additional upstream CA requirements.
    pub upstream_cas: Vec<SavedBindingReference>,
    /// Destination trust bindings restricted to hostname patterns.
    pub scoped_upstream_cas: Vec<SavedScopedTrust>,
    /// Ordered scoped verification overrides.
    pub scoped_verify_upstream: Vec<SavedScopedVerification>,
    /// Required compatible interception identity when recorded; no auto source-key lookup.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub intercept_ca: Option<SavedBindingReference>,
}

/// A host-pattern trust requirement without a certificate path.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedScopedTrust {
    /// Exact or wildcard hostname scope.
    pub pattern: String,
    /// Destination-provided certificate/trust requirement.
    pub binding: SavedBindingReference,
}

/// Recorded scoped verification; false still needs explicit destination consent.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedScopedVerification {
    /// Exact or wildcard hostname scope.
    pub pattern: String,
    /// Whether to verify matching upstream certificates.
    pub verify: bool,
}

/// Host substitution requirements, never resolved credentials or source-host lookup instructions.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedSecretsConfig {
    /// Historical global passthrough policy, distinct from an explicit empty list.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub passthrough_hosts: Option<Vec<HostPattern>>,
    /// Each placeholder has its own logical destination secret requirement.
    pub entries: Vec<SavedSecret>,
    /// Default response when a placeholder cannot be allowed.
    pub violation_action: SecretViolationAction,
}

/// A placeholder and its policy; neither secret value nor SecretSource is representable.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedSecret {
    /// Guest environment key holding the placeholder.
    pub env_var: String,
    /// Destination secret requirement.
    pub binding: SavedBindingReference,
    /// Exact non-secret placeholder already used by the guest.
    pub placeholder: String,
    /// Allowed substitution destinations.
    pub allowed_hosts: Vec<HostPattern>,
    /// Permitted request locations.
    pub substitution: SavedSecretSubstitution,
    /// Hosts that may receive the unchanged placeholder.
    pub passthrough_hosts: Vec<HostPattern>,
    /// Optional per-placeholder response override.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub violation_action: Option<SecretViolationAction>,
    /// False records a relaxation, never destination approval.
    pub require_tls_identity: bool,
}

/// Request-location policy without authorization header values or body content.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedSecretSubstitution {
    /// Whether header substitution is enabled.
    pub headers: bool,
    /// Allowed header names; no header values are saved.
    pub header_fields: Vec<String>,
    /// Whether query substitution is enabled.
    pub query: bool,
    /// Whether body substitution is enabled.
    pub body: bool,
}

/// Per-direction configured limits without elapsed time or bucket balances.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedNetworkRateLimits {
    /// Absent means no configured egress limit.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub egress: Option<SavedRateLimit>,
    /// Absent means no configured ingress limit.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub ingress: Option<SavedRateLimit>,
}

/// Independent bandwidth and frame-rate buckets.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedRateLimit {
    /// Byte-rate capacity.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub bandwidth: Option<SavedTokenBucket>,
    /// Frame-rate capacity.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub ops: Option<SavedTokenBucket>,
}

/// Portable token-bucket parameters, never a captured accounting balance.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedTokenBucket {
    /// Positive bucket capacity.
    pub size: u64,
    /// Positive refill interval in milliseconds.
    pub refill_time_ms: u64,
    /// Initial extra capacity, including an explicit zero.
    pub one_time_burst: u64,
}

/// Guest-side service and a logical destination listener binding.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedPublishedPort {
    /// Guest service port.
    pub guest_port: u16,
    /// Service transport protocol.
    pub protocol: PortProtocol,
    /// Destination host address/port binding; no source port ownership is transferred.
    pub binding: SavedBindingReference,
}

/// Configured denial responses; explicit empty messages remain distinct from absence.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedHttpConfig {
    /// Whether supported denied requests receive an HTTP response.
    pub deny_response: bool,
    /// Response format.
    pub deny_response_format: HttpDenyResponseFormat,
    /// Historical plain-text template, if explicitly set.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub deny_message: Option<String>,
    /// Literal network denial message, if set.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub network_deny_message: Option<String>,
    /// Literal placeholder denial message, if set.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub secret_deny_message: Option<String>,
}

/// Protocol intent with separate endpoint and credential requirements.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedProxy {
    /// Required proxy protocol.
    pub protocol: SavedProxyProtocol,
    /// Destination endpoint requirement; never a source endpoint fallback.
    pub endpoint: SavedBindingReference,
    /// Destination credentials or SOCKS4 user identity when required.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub credentials: Option<SavedBindingReference>,
}

/// Closed protocol vocabulary for a destination proxy binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedProxyProtocol {
    /// HTTP CONNECT tunnel.
    HttpConnect,
    /// SOCKS4 with optional destination user identity.
    Socks4,
    /// SOCKS5 with optional destination authentication.
    Socks5,
}
