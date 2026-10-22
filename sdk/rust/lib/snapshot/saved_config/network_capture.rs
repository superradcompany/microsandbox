//! Project guarded network intent without carrying host endpoints, keys or credentials.

use std::collections::BTreeMap;

use microsandbox_types::snapshot::saved_config::{
    SavedBindingReference, SavedDnsConfig, SavedHttpConfig, SavedNetworkConfig, SavedNetworkPolicy,
    SavedNetworkRateLimits, SavedNetworkRule, SavedOrigin, SavedPortRange, SavedProxy,
    SavedPublishedPort, SavedRateLimit, SavedSecretsConfig, SavedTlsCaptureBindings,
    SavedTlsConfig, SavedTokenBucket, SavedUnknownReason, SavedValue,
};
use microsandbox_types::{
    HttpConfig, NetworkPolicy, NetworkRateLimiterConfig, NetworkSpec, PortRange, RateLimiterConfig,
    Rule, TokenBucketConfig,
};
use serde_json::Value;

use super::RuntimeCaptureSource;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Logical replacements selected under the source capture guard. These are requirements,
/// not destination authorization or proof that captured external backing is complete.
#[derive(Default)]
pub struct NetworkCaptureBindings {
    /// One requirement per explicitly recorded resolver, in source order.
    pub resolvers: Vec<SavedBindingReference>,
    /// Trust requirements for a completely recorded TLS section.
    pub tls: Option<SavedTlsCaptureBindings>,
    /// Exact secret environment-key mapping; values and host source names are never copied.
    pub secrets: BTreeMap<String, SavedBindingReference>,
    /// One requirement per published listener, in source order.
    pub listeners: Vec<SavedBindingReference>,
    /// Complete independently established host-trust bundle requirements when host trust is enabled.
    /// Capture must establish the backing inventory; the boolean alone does not identify certificates.
    pub guest_trust: Vec<SavedBindingReference>,
    /// Endpoint and optional authentication requirements, never resolved source values.
    pub proxy: Option<ProxyCaptureBindings>,
}

/// Separate endpoint and authentication requirements for a recorded proxy.
pub struct ProxyCaptureBindings {
    /// Destination routing endpoint.
    pub endpoint: SavedBindingReference,
    /// Destination authentication, including a SOCKS4 user identity when present.
    pub credentials: Option<SavedBindingReference>,
}

/// Optional ordinary response text can be excluded before portable cloning or validation.
#[derive(Default)]
pub struct NetworkCaptureControls {
    /// Omit the entire optional HTTP-response default, including all custom messages.
    pub omit_http: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeCaptureSource<'_> {
    /// Project known policy and logical resource requirements. Missing fields, including
    /// nested fields supplied only by current serde defaults, remain unknown. Unused
    /// bindings fail rather than silently granting a different resource requirement.
    /// This does not establish runtime freshness, full-resume identity or destination consent.
    pub fn project_network(
        &self,
        bindings: NetworkCaptureBindings,
        controls: &NetworkCaptureControls,
    ) -> MicrosandboxResult<SavedNetworkConfig> {
        let NetworkSpec {
            enabled,
            interface: _,
            ports,
            policy,
            dns,
            tls,
            strict,
            secrets,
            max_tcp_connections,
            max_inbound_tcp_connections,
            max_udp_connections,
            tcp_accept_queue_size,
            rate_limiter,
            nat64_prefixes,
            trust_host_cas,
            http,
            outbound_proxy,
        } = &self.config.spec.network;
        let NetworkCaptureBindings {
            resolvers,
            tls: tls_bindings,
            secrets: secret_bindings,
            listeners,
            guest_trust,
            proxy: proxy_bindings,
        } = bindings;
        let raw = self.recorded.get("network").unwrap_or(&Value::Null);
        // Only a matching explicit absence may complete an omitted optional field. This
        // does not certify missing descendants of a present historical subdocument.
        let recorded_field = |field: &str| {
            raw.get(field).or_else(|| {
                (raw.is_object()
                    && self.config.field_presence.as_ref().is_some_and(|presence| {
                        presence.knows_absent_network(field, &self.config.spec)
                    }))
                .then_some(&Value::Null)
            })
        };

        let dns = project_optional(
            recorded_field("dns"),
            "dns",
            dns.as_ref(),
            self.complete_network_field("dns"),
            !resolvers.is_empty(),
            |source| SavedDnsConfig::from_source(source, resolvers).map_err(manifest_error),
        )?;
        let tls = project_optional(
            recorded_field("tls"),
            "tls",
            tls.as_ref(),
            self.complete_network_field("tls"),
            tls_bindings.is_some(),
            |source| {
                let bindings = tls_bindings.unwrap_or_default();
                // The shared constructor requires identities when needed; also reject an
                // extra identity when the source has no active/configured interception CA.
                if !source.enabled
                    && source.intercept_ca.cert_path.is_none()
                    && source.intercept_ca.key_path.is_none()
                    && bindings.intercept_ca.is_some()
                {
                    return Err(unused("tls"));
                }
                SavedTlsConfig::from_source(source, bindings).map_err(manifest_error)
            },
        )?;
        let secrets = project_optional(
            recorded_field("secrets"),
            "secrets",
            secrets.as_ref(),
            self.complete_network_field("secrets"),
            !secret_bindings.is_empty(),
            |source| {
                SavedSecretsConfig::from_source(source, &secret_bindings).map_err(manifest_error)
            },
        )?;
        let outbound_proxy = project_optional(
            recorded_field("outbound_proxy"),
            "outbound_proxy",
            outbound_proxy.as_ref(),
            self.complete_network_field("outbound_proxy"),
            proxy_bindings.is_some(),
            |source| {
                let bindings = proxy_bindings.ok_or_else(|| binding_error("outbound_proxy"))?;
                SavedProxy::from_source(source, bindings.endpoint, bindings.credentials)
                    .map_err(manifest_error)
            },
        )?;
        let ports = if self.complete_network_field("ports") {
            if ports.len() != listeners.len() {
                return Err(binding_error("ports"));
            }
            configured(
                ports
                    .iter()
                    .zip(listeners)
                    .map(|(source, binding)| {
                        SavedPublishedPort::from_source(source, binding).map_err(manifest_error)
                    })
                    .collect::<MicrosandboxResult<Vec<_>>>()?,
            )
        } else {
            if !listeners.is_empty() {
                return Err(unused("ports"));
            }
            unknown()
        };
        let guest_trust = if raw.get("trust_host_cas").is_some() {
            if *trust_host_cas == guest_trust.is_empty() {
                return Err(binding_error("guest_trust"));
            }
            configured(guest_trust)
        } else {
            if !guest_trust.is_empty() {
                return Err(unused("guest_trust"));
            }
            unknown()
        };
        let result = SavedNetworkConfig {
            enabled: Some(recorded(raw, "enabled", *enabled)),
            strict: Some(recorded(raw, "strict", *strict)),
            policy: Some(project_optional(
                recorded_field("policy"),
                "policy",
                policy.as_ref(),
                self.complete_network_field("policy"),
                false,
                |source| Ok(project_policy(source)),
            )?),
            dns: Some(dns),
            tls: Some(tls),
            secrets: Some(secrets),
            max_tcp_connections: Some(optional_scalar(
                recorded_field("max_connections").or_else(|| raw.get("max_tcp_connections")),
                max_tcp_connections.map(|value| value as u64),
            )),
            max_inbound_tcp_connections: Some(optional_scalar(
                recorded_field("max_inbound_tcp_connections"),
                max_inbound_tcp_connections.map(|value| value as u64),
            )),
            max_udp_connections: Some(optional_scalar(
                recorded_field("max_udp_connections"),
                max_udp_connections.map(|value| value as u64),
            )),
            tcp_accept_queue_size: Some(optional_scalar(
                recorded_field("tcp_accept_queue_size"),
                *tcp_accept_queue_size,
            )),
            rate_limiter: Some(project_optional(
                recorded_field("rate_limiter"),
                "rate_limiter",
                rate_limiter.as_ref(),
                self.complete_network_field("rate_limiter"),
                false,
                |source| Ok(project_rates(source)),
            )?),
            nat64_prefixes: Some(recorded(raw, "nat64_prefixes", nat64_prefixes.clone())),
            ports: Some(ports),
            guest_trust: Some(guest_trust),
            http: if controls.omit_http {
                None
            } else if self.complete_network_field("http") {
                Some(configured(project_http(http)))
            } else {
                Some(unknown())
            },
            outbound_proxy: Some(outbound_proxy),
        };
        result.validate().map_err(manifest_error)?;
        Ok(result)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn project_optional<S, T>(
    raw: Option<&Value>,
    field: &str,
    source: Option<&S>,
    complete: bool,
    supplied: bool,
    project: impl FnOnce(&S) -> MicrosandboxResult<T>,
) -> MicrosandboxResult<SavedValue<T>> {
    match raw {
        Some(Value::Null) => {
            if supplied {
                return Err(unused(field));
            }
            Ok(SavedValue::Default {})
        }
        Some(_) if complete => {
            let source = source.ok_or_else(|| binding_error(field))?;
            project(source).map(configured)
        }
        _ => {
            if supplied {
                return Err(unused(field));
            }
            Ok(unknown())
        }
    }
}

fn optional_scalar<T>(raw: Option<&Value>, value: Option<T>) -> SavedValue<T> {
    match (raw, value) {
        (None, _) => unknown(),
        (Some(_), Some(value)) => configured(value),
        (Some(_), None) => SavedValue::Default {},
    }
}

fn recorded<T>(raw: &Value, field: &str, value: T) -> SavedValue<T> {
    if raw.get(field).is_some() {
        configured(value)
    } else {
        unknown()
    }
}

fn configured<T>(value: T) -> SavedValue<T> {
    SavedValue::Value {
        value,
        origin: SavedOrigin::Configured,
    }
}

fn unknown<T>() -> SavedValue<T> {
    SavedValue::Unknown {
        reason: SavedUnknownReason::NotRecorded,
    }
}

fn manifest_error(error: impl std::fmt::Display) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(error.to_string())
}

fn unused(field: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!(
        "SCFG_BINDING: network.{field}: supplied requirement has no completely recorded source"
    ))
}

fn binding_error(field: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!(
        "SCFG_BINDING: network.{field}: destination requirements must match recorded source"
    ))
}

fn project_policy(source: &NetworkPolicy) -> SavedNetworkPolicy {
    let NetworkPolicy {
        default_egress,
        default_ingress,
        rules,
    } = source;
    SavedNetworkPolicy {
        default_egress: *default_egress,
        default_ingress: *default_ingress,
        rules: rules
            .iter()
            .map(|source| {
                let Rule {
                    direction,
                    destination,
                    protocols,
                    ports,
                    action,
                } = source;
                SavedNetworkRule {
                    direction: *direction,
                    destination: destination.clone(),
                    protocols: protocols.clone(),
                    ports: ports
                        .iter()
                        .map(|PortRange { start, end }| SavedPortRange {
                            start: *start,
                            end: *end,
                        })
                        .collect(),
                    action: *action,
                }
            })
            .collect(),
    }
}

fn project_rates(source: &NetworkRateLimiterConfig) -> SavedNetworkRateLimits {
    let NetworkRateLimiterConfig { egress, ingress } = source;
    SavedNetworkRateLimits {
        egress: egress.as_ref().map(project_rate),
        ingress: ingress.as_ref().map(project_rate),
    }
}

fn project_rate(source: &RateLimiterConfig) -> SavedRateLimit {
    let RateLimiterConfig { bandwidth, ops } = source;
    SavedRateLimit {
        bandwidth: bandwidth.as_ref().map(project_bucket),
        ops: ops.as_ref().map(project_bucket),
    }
}

fn project_bucket(source: &TokenBucketConfig) -> SavedTokenBucket {
    let TokenBucketConfig {
        size,
        refill_time_ms,
        one_time_burst,
    } = source;
    SavedTokenBucket {
        size: *size,
        refill_time_ms: *refill_time_ms,
        one_time_burst: *one_time_burst,
    }
}

fn project_http(source: &HttpConfig) -> SavedHttpConfig {
    let HttpConfig {
        deny_response,
        deny_response_format,
        deny_message,
        network_deny_message,
        secret_deny_message,
    } = source;
    SavedHttpConfig {
        deny_response: *deny_response,
        deny_response_format: *deny_response_format,
        deny_message: deny_message.clone(),
        network_deny_message: network_deny_message.clone(),
        secret_deny_message: secret_deny_message.clone(),
    }
}
