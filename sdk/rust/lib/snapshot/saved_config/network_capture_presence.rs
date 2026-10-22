//! Presence checks for raw retained network records; serde defaults are not capture evidence.

use serde_json::Value;

use super::RuntimeCaptureSource;
use crate::sandbox::network_presence::{NetworkDefault, RateBucket, RateDirection};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeCaptureSource<'_> {
    pub(super) fn complete_network_field(&self, field: &str) -> bool {
        if self
            .config
            .field_presence
            .as_ref()
            .is_some_and(|presence| presence.has_unrecorded_network_policy(Some(field)))
        {
            return false;
        }
        if field == "secrets"
            && self
                .config
                .field_presence
                .as_ref()
                .is_some_and(|presence| presence.secret_policy_was_unrecorded())
        {
            return false;
        }
        self.recorded
            .get("network")
            .and_then(|network| network.get(field))
            .is_some_and(|raw| {
                complete(raw, field, &|default| {
                    self.config.field_presence.as_ref().is_some_and(|presence| {
                        presence.knows_network_default(&default, &self.config.spec)
                    })
                })
            })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn complete(raw: &Value, field: &str, knows: &impl Fn(NetworkDefault) -> bool) -> bool {
    match field {
        "dns" => fields(
            raw,
            &["rebind_protection", "nameservers", "query_timeout_ms"],
        ),
        "policy" => {
            fields(raw, &["default_egress", "default_ingress", "rules"])
                && array(raw.get("rules"), |rule| {
                    fields(
                        rule,
                        &["direction", "destination", "protocols", "ports", "action"],
                    )
                })
        }
        "ports" => array(Some(raw), |port| fields(port, &["guest_port", "protocol"])),
        "tls" => {
            fields(
                raw,
                &[
                    "enabled",
                    "intercepted_ports",
                    "bypass",
                    "verify_upstream",
                    "block_quic_on_intercept",
                    "upstream_ca_cert",
                    "scoped_verify_upstream",
                ],
            ) && raw
                .get("scoped_upstream_ca_cert")
                .or_else(|| raw.get("scoped_upstream_ca_certs"))
                .is_some()
                && raw
                    .get("intercept_ca")
                    .or_else(|| raw.get("ca"))
                    .is_some_and(|ca| fields(ca, &["cert_path", "key_path"]))
        }
        "secrets" => {
            fields(raw, &["secrets", "violation_action"])
                && (raw.get("passthrough_hosts").is_some()
                    || knows(NetworkDefault::SecretsPassthroughHosts))
                && array(raw.get("secrets"), |secret| {
                    fields(
                        secret,
                        &[
                            "env_var",
                            "placeholder",
                            "allowed_hosts",
                            "substitution",
                            "passthrough_hosts",
                            "require_tls_identity",
                        ],
                    ) && secret
                        .get("env_var")
                        .and_then(Value::as_str)
                        .is_some_and(|guest_env| {
                            (secret.get("violation_action").is_some()
                                || knows(NetworkDefault::SecretViolationAction {
                                    guest_env: guest_env.into(),
                                }))
                                && secret.get("substitution").is_some_and(|substitution| {
                                    fields(substitution, &["headers", "query", "body"])
                                        && (substitution.get("header_fields").is_some()
                                            || knows(NetworkDefault::SecretHeaderFields {
                                                guest_env: guest_env.into(),
                                            }))
                                })
                        })
                })
        }
        "outbound_proxy" => match raw.get("protocol").and_then(Value::as_str) {
            Some("http_connect") => fields(raw, &["address"]),
            Some("socks4") => {
                fields(raw, &["address"])
                    && (raw.get("user_id").is_some() || knows(NetworkDefault::Socks4UserId))
            }
            Some("socks5") => {
                fields(raw, &["address"])
                    && (raw.get("credentials").is_some()
                        || knows(NetworkDefault::Socks5Credentials))
            }
            _ => false,
        },
        "http" => {
            fields(raw, &["deny_response", "deny_response_format"])
                && (raw.get("deny_message").is_some() || knows(NetworkDefault::HttpDenyMessage))
                && (raw.get("network_deny_message").is_some()
                    || knows(NetworkDefault::HttpNetworkDenyMessage))
                && (raw.get("secret_deny_message").is_some()
                    || knows(NetworkDefault::HttpSecretDenyMessage))
        }
        // Nullable dimensions require recorded values or matching private evidence.
        // Scalar burst values always require a recorded field, including explicit zero.
        "rate_limiter" => {
            raw.is_object()
                && [RateDirection::Egress, RateDirection::Ingress]
                    .into_iter()
                    .all(|direction| {
                        nullable(
                            raw.get(direction.key()),
                            || knows(NetworkDefault::RateDirection { direction }),
                            |rate| {
                                rate.is_object()
                                    && [RateBucket::Bandwidth, RateBucket::Ops].into_iter().all(
                                        |bucket| {
                                            nullable(
                                                rate.get(bucket.key()),
                                                || {
                                                    knows(NetworkDefault::RateBucket {
                                                        direction,
                                                        bucket,
                                                    })
                                                },
                                                |value| {
                                                    fields(
                                                        value,
                                                        &[
                                                            "size",
                                                            "refill_time_ms",
                                                            "one_time_burst",
                                                        ],
                                                    )
                                                },
                                            )
                                        },
                                    )
                            },
                        )
                    })
        }
        _ => false,
    }
}

fn fields(raw: &Value, names: &[&str]) -> bool {
    names.iter().all(|name| raw.get(*name).is_some())
}

fn array(raw: Option<&Value>, predicate: impl Fn(&Value) -> bool) -> bool {
    raw.and_then(Value::as_array)
        .is_some_and(|values| values.iter().all(predicate))
}

fn nullable(
    raw: Option<&Value>,
    known_absent: impl FnOnce() -> bool,
    predicate: impl FnOnce(&Value) -> bool,
) -> bool {
    raw.map_or_else(known_absent, |value| value.is_null() || predicate(value))
}
