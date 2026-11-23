//! Value-bound evidence for a fixed set of serializer-omitted network defaults.

use std::collections::BTreeSet;

use microsandbox_types::{NetworkSpec, OutboundProxy, RateLimiterConfig, SecretEntry};
use serde::{Deserialize, Serialize};
use serde_json::Value;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RateDirection {
    Egress,
    Ingress,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RateBucket {
    Bandwidth,
    Ops,
}

/// Only absence/empty defaults are certified. Guest placeholder names identify policy
/// entries; host secret sources, endpoints, paths, credentials and their hashes are absent.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum NetworkDefault {
    HttpDenyMessage,
    HttpNetworkDenyMessage,
    HttpSecretDenyMessage,
    Socks4UserId,
    Socks5Credentials,
    SecretsPassthroughHosts,
    SecretViolationAction {
        guest_env: String,
    },
    SecretHeaderFields {
        guest_env: String,
    },
    RateDirection {
        direction: RateDirection,
    },
    RateBucket {
        direction: RateDirection,
        bucket: RateBucket,
    },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RateDirection {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Egress => "egress",
            Self::Ingress => "ingress",
        }
    }

    fn limiter(self, network: &NetworkSpec) -> Option<&RateLimiterConfig> {
        let rates = network.rate_limiter.as_ref()?;
        match self {
            Self::Egress => rates.egress.as_ref(),
            Self::Ingress => rates.ingress.as_ref(),
        }
    }
}

impl RateBucket {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Bandwidth => "bandwidth",
            Self::Ops => "ops",
        }
    }
}

impl NetworkDefault {
    pub(crate) fn declared(network: &NetworkSpec) -> BTreeSet<Self> {
        let mut known: BTreeSet<_> = [
            Self::HttpDenyMessage,
            Self::HttpNetworkDenyMessage,
            Self::HttpSecretDenyMessage,
            Self::Socks4UserId,
            Self::Socks5Credentials,
            Self::SecretsPassthroughHosts,
        ]
        .into_iter()
        .filter(|field| field.matches(network))
        .collect();
        if let Some(secrets) = &network.secrets {
            for secret in &secrets.secrets {
                for field in [
                    Self::SecretViolationAction {
                        guest_env: secret.env_var.clone(),
                    },
                    Self::SecretHeaderFields {
                        guest_env: secret.env_var.clone(),
                    },
                ] {
                    if field.matches(network) {
                        known.insert(field);
                    }
                }
            }
        }
        for direction in [RateDirection::Egress, RateDirection::Ingress] {
            let field = Self::RateDirection { direction };
            if field.matches(network) {
                known.insert(field);
            }
            for bucket in [RateBucket::Bandwidth, RateBucket::Ops] {
                let field = Self::RateBucket { direction, bucket };
                if field.matches(network) {
                    known.insert(field);
                }
            }
        }
        known
    }

    pub(crate) fn matches(&self, network: &NetworkSpec) -> bool {
        match self {
            Self::HttpDenyMessage => network.http.deny_message.is_none(),
            Self::HttpNetworkDenyMessage => network.http.network_deny_message.is_none(),
            Self::HttpSecretDenyMessage => network.http.secret_deny_message.is_none(),
            Self::Socks4UserId => matches!(
                network.outbound_proxy,
                Some(OutboundProxy::Socks4 { user_id: None, .. })
            ),
            Self::Socks5Credentials => matches!(
                network.outbound_proxy,
                Some(OutboundProxy::Socks5 {
                    credentials: None,
                    ..
                })
            ),
            Self::SecretsPassthroughHosts => network
                .secrets
                .as_ref()
                .is_some_and(|s| s.passthrough_hosts.is_none()),
            Self::SecretViolationAction { guest_env } => {
                unique_secret(network, guest_env).is_some_and(|s| s.violation_action.is_none())
            }
            Self::SecretHeaderFields { guest_env } => unique_secret(network, guest_env)
                .is_some_and(|s| s.substitution.header_fields.is_empty()),
            Self::RateDirection { direction } => {
                network.rate_limiter.is_some() && direction.limiter(network).is_none()
            }
            Self::RateBucket { direction, bucket } => {
                direction.limiter(network).is_some_and(|rate| match bucket {
                    RateBucket::Bandwidth => rate.bandwidth.is_none(),
                    RateBucket::Ops => rate.ops.is_none(),
                })
            }
        }
    }

    /// Retire evidence before decoding can manufacture a missing parent. Required
    /// surrounding fields must still be recorded; another default's hint proves no more.
    pub(crate) fn recorded_parent(&self, network: &Value) -> bool {
        match self {
            Self::HttpDenyMessage | Self::HttpNetworkDenyMessage | Self::HttpSecretDenyMessage => {
                network
                    .get("http")
                    .is_some_and(|v| fields(v, &["deny_response", "deny_response_format"]))
            }
            Self::Socks4UserId | Self::Socks5Credentials => {
                network.get("outbound_proxy").is_some_and(|v| {
                    v.get("address").is_some_and(Value::is_string)
                        && v.get("protocol").and_then(Value::as_str)
                            == Some(if matches!(self, Self::Socks4UserId) {
                                "socks4"
                            } else {
                                "socks5"
                            })
                })
            }
            Self::SecretsPassthroughHosts => network.get("secrets").is_some_and(|v| {
                v.get("secrets").is_some_and(Value::is_array) && v.get("violation_action").is_some()
            }),
            Self::SecretViolationAction { guest_env } | Self::SecretHeaderFields { guest_env } => {
                let Some(secrets) = network
                    .get("secrets")
                    // Entry-level omission hints cannot certify a missing enclosing
                    // policy. Retire them before serde supplies that policy's default.
                    .filter(|policy| policy.get("violation_action").is_some())
                    .and_then(|policy| policy.get("secrets"))
                    .and_then(Value::as_array)
                else {
                    return false;
                };
                let mut matches = secrets.iter().filter(|entry| {
                    entry.get("env_var").and_then(Value::as_str) == Some(guest_env)
                });
                let Some(entry) = matches.next() else {
                    return false;
                };
                matches.next().is_none()
                    && fields(
                        entry,
                        &[
                            "env_var",
                            "placeholder",
                            "allowed_hosts",
                            "passthrough_hosts",
                            "require_tls_identity",
                        ],
                    )
                    && entry
                        .get("substitution")
                        .is_some_and(|v| fields(v, &["headers", "query", "body"]))
            }
            Self::RateDirection { .. } | Self::RateBucket { .. } => {
                network.get("rate_limiter").is_some_and(|rates| {
                    recorded_rate_scalars(rates)
                        && match self {
                            Self::RateBucket { direction, .. } => {
                                rates.get(direction.key()).is_some_and(Value::is_object)
                            }
                            _ => true,
                        }
                })
            }
        }
    }

    pub(crate) fn is_proxy(&self) -> bool {
        matches!(self, Self::Socks4UserId | Self::Socks5Credentials)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn fields(value: &Value, names: &[&str]) -> bool {
    names.iter().all(|name| value.get(*name).is_some())
}

fn unique_secret<'a>(network: &'a NetworkSpec, guest_env: &str) -> Option<&'a SecretEntry> {
    let mut matches = network
        .secrets
        .as_ref()?
        .secrets
        .iter()
        .filter(|s| s.env_var == guest_env);
    let entry = matches.next()?;
    matches.next().is_none().then_some(entry)
}

/// A nullable-dimension hint cannot certify a sibling bucket's missing scalar.
/// Retire rate hints before serde fills that scalar and persistence hides the gap.
fn recorded_rate_scalars(rates: &Value) -> bool {
    rates.is_object()
        && ["egress", "ingress"].into_iter().all(|direction| {
            rates.get(direction).is_none_or(|rate| {
                rate.is_null()
                    || (rate.is_object()
                        && ["bandwidth", "ops"].into_iter().all(|bucket| {
                            rate.get(bucket).is_none_or(|value| {
                                value.is_null()
                                    || fields(value, &["size", "refill_time_ms", "one_time_burst"])
                            })
                        }))
            })
        })
}
