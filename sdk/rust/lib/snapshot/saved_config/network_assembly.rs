//! Compose native gateway policy while retaining unknown, approval and full-state gates.

use std::fmt;

use microsandbox_types::snapshot::saved_config::SavedNetworkConfig;
use microsandbox_types::{
    DnsConfig, DnsConfigPatch, NetworkSpec, NetworkSpecPatch, TlsConfig, TlsConfigPatch,
};

use super::{
    DestinationNetworkBaseline, NetworkPolicyClear, NetworkPolicySelection, SnapshotConfigMode,
    select_network_policy_defaults,
};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Policy composition only. No endpoints, identities, credentials or permission to activate.
pub struct NetworkPolicyConfigurationPlan {
    policy: NetworkSpec,
    selection: NetworkPolicySelection,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl NetworkPolicyConfigurationPlan {
    /// Read remaining obligations without allowing callers to erase them after composition.
    pub fn selection(&self) -> &NetworkPolicySelection {
        &self.selection
    }

    /// Apply known policy to separately prepared destination resource inputs. This does not
    /// discharge approvals, mandatory destination policy or captured-network compatibility.
    /// Unknown policy refuses before mutating the destination; image defaults are no substitute.
    pub fn apply_policy_to(&self, destination: &mut NetworkSpec) -> MicrosandboxResult<()> {
        if !self.selection.unknown_fields.is_empty() {
            return Err(MicrosandboxError::InvalidConfig(
                "SCFG_UNKNOWN: network policy needs explicit resolution".into(),
            ));
        }
        copy_policy(&self.policy, destination);
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for NetworkPolicyConfigurationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkPolicyConfigurationPlan")
            .field("selection", &self.selection)
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Assemble only portable policy fields, in lower/default/explicit order. `lower` contains
/// resolved destination defaults, not source-host state. Endpoint and credential fields from
/// either input are intentionally excluded and must use their resource preparation paths.
pub fn prepare_network_policy_configuration(
    saved: &SavedNetworkConfig,
    lower: &NetworkSpec,
    explicit: &NetworkSpecPatch,
    clears: &[NetworkPolicyClear],
    mode: SnapshotConfigMode,
    full_resume: bool,
    baseline: &DestinationNetworkBaseline,
) -> MicrosandboxResult<NetworkPolicyConfigurationPlan> {
    let mut selection =
        select_network_policy_defaults(saved, explicit, clears, mode, full_resume, baseline)?;
    let mut policy = NetworkSpec::default();
    copy_policy(lower, &mut policy);
    for clear in &selection.cleared_fields {
        reset(*clear, &mut policy);
    }
    for path in selection
        .defaulted_fields
        .iter()
        .chain(&selection.absent_fields)
    {
        reset(field(path)?, &mut policy);
    }
    // A recorded builtin TLS default can weaken a stronger destination baseline just as
    // an explicit saved false can. Do not lose that approval because the sparse overlay
    // represents Default separately from Value. Explicit overrides have already masked it.
    let mut defaults = NetworkSpecPatch::new();
    let builtin_tls = TlsConfig::default();
    for path in &selection.defaulted_fields {
        match field(path)? {
            NetworkPolicyClear::Strict => defaults.strict = Some(policy.strict),
            NetworkPolicyClear::DnsRebindProtection => {
                defaults
                    .dns
                    .get_or_insert_with(DnsConfigPatch::new)
                    .rebind_protection = Some(DnsConfig::default().rebind_protection);
            }
            NetworkPolicyClear::TlsEnabled => {
                defaults.tls.get_or_insert_with(TlsConfigPatch::new).enabled =
                    Some(builtin_tls.enabled);
            }
            NetworkPolicyClear::TlsInterceptedPorts => {
                defaults
                    .tls
                    .get_or_insert_with(TlsConfigPatch::new)
                    .intercepted_ports = Some(builtin_tls.intercepted_ports.clone());
            }
            NetworkPolicyClear::TlsBypass => {
                defaults.tls.get_or_insert_with(TlsConfigPatch::new).bypass =
                    Some(builtin_tls.bypass.clone());
            }
            NetworkPolicyClear::TlsVerifyUpstream => {
                defaults
                    .tls
                    .get_or_insert_with(TlsConfigPatch::new)
                    .verify_upstream = Some(builtin_tls.verify_upstream);
            }
            NetworkPolicyClear::TlsBlockQuic => {
                defaults
                    .tls
                    .get_or_insert_with(TlsConfigPatch::new)
                    .block_quic_on_intercept = Some(builtin_tls.block_quic_on_intercept);
            }
            NetworkPolicyClear::TlsScopedVerification => {
                defaults
                    .tls
                    .get_or_insert_with(TlsConfigPatch::new)
                    .scoped_verify_upstream = Some(builtin_tls.scoped_verify_upstream.clone());
            }
            _ => {} // Non-inspection policy fields have no relaxation category here.
        }
    }
    selection
        .required_approvals
        .extend(super::network_policy::approvals(&defaults, baseline));
    selection.defaults.clone().apply_to(&mut policy);
    // A trust path, proxy credential or host listener in the explicit patch cannot enter
    // this policy-only plan. Those values retain their separate preparation/identity gates.
    policy_patch(explicit).apply_to(&mut policy);
    Ok(NetworkPolicyConfigurationPlan { policy, selection })
}

fn policy_patch(input: &NetworkSpecPatch) -> NetworkSpecPatch {
    NetworkSpecPatch {
        enabled: input.enabled,
        policy: input.policy.clone(),
        strict: input.strict,
        max_tcp_connections: input.max_tcp_connections,
        max_inbound_tcp_connections: input.max_inbound_tcp_connections,
        max_udp_connections: input.max_udp_connections,
        tcp_accept_queue_size: input.tcp_accept_queue_size,
        nat64_prefixes: input.nat64_prefixes.clone(),
        rate_limiter: input.rate_limiter.clone(),
        http: input.http.clone(),
        dns: input.dns.as_ref().map(|dns| DnsConfigPatch {
            rebind_protection: dns.rebind_protection,
            query_timeout_ms: dns.query_timeout_ms,
            nameservers: None,
        }),
        tls: input.tls.as_ref().map(|tls| TlsConfigPatch {
            enabled: tls.enabled,
            intercepted_ports: tls.intercepted_ports.clone(),
            bypass: tls.bypass.clone(),
            verify_upstream: tls.verify_upstream,
            block_quic_on_intercept: tls.block_quic_on_intercept,
            scoped_verify_upstream: tls.scoped_verify_upstream.clone(),
            ..TlsConfigPatch::new()
        }),
        ..NetworkSpecPatch::new()
    }
}

/// Preserve destination resource siblings even when the selected policy is the builtin
/// default. In particular, clearing TLS policy must not remove supplied CA/key paths.
fn copy_policy(source: &NetworkSpec, target: &mut NetworkSpec) {
    target.enabled = source.enabled;
    target.policy = source.policy.clone();
    target.strict = source.strict;
    target.max_tcp_connections = source.max_tcp_connections;
    target.max_inbound_tcp_connections = source.max_inbound_tcp_connections;
    target.max_udp_connections = source.max_udp_connections;
    target.tcp_accept_queue_size = source.tcp_accept_queue_size;
    target.rate_limiter = source.rate_limiter.clone();
    target.nat64_prefixes = source.nat64_prefixes.clone();
    target.http = source.http.clone();
    if source.dns.is_some() || target.dns.is_some() {
        let defaults = DnsConfig::default();
        let dns = source.dns.as_ref().unwrap_or(&defaults);
        let destination = target.dns.get_or_insert_with(DnsConfig::default);
        destination.rebind_protection = dns.rebind_protection;
        destination.query_timeout_ms = dns.query_timeout_ms;
    }
    if source.tls.is_some() || target.tls.is_some() {
        let defaults = TlsConfig::default();
        let tls = source.tls.as_ref().unwrap_or(&defaults);
        let destination = target.tls.get_or_insert_with(TlsConfig::default);
        destination.enabled = tls.enabled;
        destination.intercepted_ports = tls.intercepted_ports.clone();
        destination.bypass = tls.bypass.clone();
        destination.verify_upstream = tls.verify_upstream;
        destination.block_quic_on_intercept = tls.block_quic_on_intercept;
        destination.scoped_verify_upstream = tls.scoped_verify_upstream.clone();
    }
}

fn field(path: &str) -> MicrosandboxResult<NetworkPolicyClear> {
    use NetworkPolicyClear::*;
    Ok(match path {
        "network.enabled" => Enabled,
        "network.policy" => Policy,
        "network.strict" => Strict,
        "network.dns.rebind_protection" => DnsRebindProtection,
        "network.dns.query_timeout_ms" => DnsQueryTimeout,
        "network.tls.enabled" => TlsEnabled,
        "network.tls.intercepted_ports" => TlsInterceptedPorts,
        "network.tls.bypass" => TlsBypass,
        "network.tls.verify_upstream" => TlsVerifyUpstream,
        "network.tls.block_quic_on_intercept" => TlsBlockQuic,
        "network.tls.scoped_verify_upstream" => TlsScopedVerification,
        "network.max_tcp_connections" => MaxTcpConnections,
        "network.max_inbound_tcp_connections" => MaxInboundTcpConnections,
        "network.max_udp_connections" => MaxUdpConnections,
        "network.tcp_accept_queue_size" => TcpAcceptQueueSize,
        "network.rate_limiter.egress" => EgressRateLimit,
        "network.rate_limiter.ingress" => IngressRateLimit,
        "network.nat64_prefixes" => Nat64Prefixes,
        "network.http.deny_response" => HttpDenyResponse,
        "network.http.deny_response_format" => HttpDenyResponseFormat,
        "network.http.deny_message" => HttpDenyMessage,
        "network.http.network_deny_message" => HttpNetworkDenyMessage,
        "network.http.secret_deny_message" => HttpSecretDenyMessage,
        _ => {
            return Err(MicrosandboxError::InvalidConfig(
                "SCFG_SCHEMA: unclassified network policy operation".into(),
            ));
        }
    })
}

fn reset(field: NetworkPolicyClear, policy: &mut NetworkSpec) {
    use NetworkPolicyClear::*;
    let defaults = NetworkSpec::default();
    match field {
        Enabled => policy.enabled = defaults.enabled,
        Policy => policy.policy = defaults.policy,
        Strict => policy.strict = defaults.strict,
        DnsRebindProtection => {
            policy
                .dns
                .get_or_insert_with(DnsConfig::default)
                .rebind_protection = DnsConfig::default().rebind_protection
        }
        DnsQueryTimeout => {
            policy
                .dns
                .get_or_insert_with(DnsConfig::default)
                .query_timeout_ms = DnsConfig::default().query_timeout_ms
        }
        TlsEnabled => {
            policy.tls.get_or_insert_with(TlsConfig::default).enabled = TlsConfig::default().enabled
        }
        TlsInterceptedPorts => {
            policy
                .tls
                .get_or_insert_with(TlsConfig::default)
                .intercepted_ports = TlsConfig::default().intercepted_ports
        }
        TlsBypass => policy
            .tls
            .get_or_insert_with(TlsConfig::default)
            .bypass
            .clear(),
        TlsVerifyUpstream => {
            policy
                .tls
                .get_or_insert_with(TlsConfig::default)
                .verify_upstream = TlsConfig::default().verify_upstream
        }
        TlsBlockQuic => {
            policy
                .tls
                .get_or_insert_with(TlsConfig::default)
                .block_quic_on_intercept = TlsConfig::default().block_quic_on_intercept
        }
        TlsScopedVerification => policy
            .tls
            .get_or_insert_with(TlsConfig::default)
            .scoped_verify_upstream
            .clear(),
        MaxTcpConnections => policy.max_tcp_connections = defaults.max_tcp_connections,
        MaxInboundTcpConnections => {
            policy.max_inbound_tcp_connections = defaults.max_inbound_tcp_connections
        }
        MaxUdpConnections => policy.max_udp_connections = defaults.max_udp_connections,
        TcpAcceptQueueSize => policy.tcp_accept_queue_size = defaults.tcp_accept_queue_size,
        EgressRateLimit => {
            policy
                .rate_limiter
                .get_or_insert_with(Default::default)
                .egress = None
        }
        IngressRateLimit => {
            policy
                .rate_limiter
                .get_or_insert_with(Default::default)
                .ingress = None
        }
        Nat64Prefixes => policy.nat64_prefixes = defaults.nat64_prefixes,
        HttpDenyResponse => policy.http.deny_response = defaults.http.deny_response,
        HttpDenyResponseFormat => {
            policy.http.deny_response_format = defaults.http.deny_response_format
        }
        HttpDenyMessage => policy.http.deny_message = None,
        HttpNetworkDenyMessage => policy.http.network_deny_message = None,
        HttpSecretDenyMessage => policy.http.secret_deny_message = None,
    }
}
