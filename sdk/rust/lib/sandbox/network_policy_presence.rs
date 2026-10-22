//! Negative evidence for policy fields whose decoder supplies historical defaults.

use std::collections::BTreeSet;

use microsandbox_types::SandboxSpecPatch;
use serde::{Deserialize, Serialize};
use serde_json::Value;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const FIELDS: [NetworkPolicyField; 13] = [
    NetworkPolicyField::DnsRebindProtection,
    NetworkPolicyField::DnsNameservers,
    NetworkPolicyField::DnsQueryTimeoutMs,
    NetworkPolicyField::TlsEnabled,
    NetworkPolicyField::TlsInterceptedPorts,
    NetworkPolicyField::TlsBypass,
    NetworkPolicyField::TlsVerifyUpstream,
    NetworkPolicyField::TlsBlockQuicOnIntercept,
    NetworkPolicyField::TlsUpstreamCaCert,
    NetworkPolicyField::TlsScopedUpstreamCaCert,
    NetworkPolicyField::TlsScopedVerifyUpstream,
    NetworkPolicyField::TlsInterceptCaCertPath,
    NetworkPolicyField::TlsInterceptCaKeyPath,
];

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Only fixed schema names are retained, never host endpoints, paths or policy values.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NetworkPolicyField {
    DnsRebindProtection,
    DnsNameservers,
    DnsQueryTimeoutMs,
    TlsEnabled,
    TlsInterceptedPorts,
    TlsBypass,
    TlsVerifyUpstream,
    TlsBlockQuicOnIntercept,
    TlsUpstreamCaCert,
    TlsScopedUpstreamCaCert,
    TlsScopedVerifyUpstream,
    TlsInterceptCaCertPath,
    TlsInterceptCaKeyPath,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl NetworkPolicyField {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::DnsRebindProtection => "dns.rebind_protection",
            Self::DnsNameservers => "dns.nameservers",
            Self::DnsQueryTimeoutMs => "dns.query_timeout_ms",
            Self::TlsEnabled => "tls.enabled",
            Self::TlsInterceptedPorts => "tls.intercepted_ports",
            Self::TlsBypass => "tls.bypass",
            Self::TlsVerifyUpstream => "tls.verify_upstream",
            Self::TlsBlockQuicOnIntercept => "tls.block_quic_on_intercept",
            Self::TlsUpstreamCaCert => "tls.upstream_ca_cert",
            Self::TlsScopedUpstreamCaCert => "tls.scoped_upstream_ca_cert",
            Self::TlsScopedVerifyUpstream => "tls.scoped_verify_upstream",
            Self::TlsInterceptCaCertPath => "tls.intercept_ca.cert_path",
            Self::TlsInterceptCaKeyPath => "tls.intercept_ca.key_path",
        }
    }

    pub(crate) fn family(self) -> &'static str {
        match self {
            Self::DnsRebindProtection | Self::DnsNameservers | Self::DnsQueryTimeoutMs => "dns",
            _ => "tls",
        }
    }

    /// Inspect before decoding. Known optional absence remains reusable, but an unknown
    /// absent parent must not become known if an unrelated fluent edit expands defaults.
    pub(crate) fn missing(
        network: Option<&Value>,
        known_absent: impl Fn(&str) -> bool,
    ) -> BTreeSet<Self> {
        FIELDS
            .into_iter()
            .filter(|field| {
                let Some(section) = network
                    .and_then(|v| v.get(field.family()))
                    .filter(|v| v.is_object())
                else {
                    return !known_absent(field.family());
                };
                let key = field.key().split_once('.').unwrap().1;
                match field {
                    Self::TlsScopedUpstreamCaCert => section
                        .get(key)
                        .or_else(|| section.get("scoped_upstream_ca_certs"))
                        .is_none(),
                    Self::TlsInterceptCaCertPath | Self::TlsInterceptCaKeyPath => {
                        let child = key.split_once('.').unwrap().1;
                        section
                            .get("intercept_ca")
                            .or_else(|| section.get("ca"))
                            .and_then(|v| v.get(child))
                            .is_none()
                    }
                    _ => section.get(key).is_none(),
                }
            })
            .collect()
    }

    /// Preserve negative information even when another future hint makes the enclosing
    /// private record unreadable. Malformed markers conservatively cover this whitelist.
    pub(crate) fn retained(value: Option<&Value>) -> BTreeSet<Self> {
        let Some(value) = value else {
            return BTreeSet::new();
        };
        if value.as_array().is_none_or(|v| v.len() > FIELDS.len()) {
            return FIELDS.into_iter().collect();
        }
        serde_json::from_value(value.clone()).unwrap_or_else(|_| FIELDS.into_iter().collect())
    }

    pub(crate) fn explicitly_selected(self, patch: &SandboxSpecPatch) -> bool {
        match self {
            Self::DnsRebindProtection => patch
                .network
                .dns
                .as_ref()
                .is_some_and(|p| p.rebind_protection.is_some()),
            Self::DnsNameservers => patch
                .network
                .dns
                .as_ref()
                .is_some_and(|p| p.nameservers.is_some()),
            Self::DnsQueryTimeoutMs => patch
                .network
                .dns
                .as_ref()
                .is_some_and(|p| p.query_timeout_ms.is_some()),
            Self::TlsEnabled => patch
                .network
                .tls
                .as_ref()
                .is_some_and(|p| p.enabled.is_some()),
            Self::TlsInterceptedPorts => patch
                .network
                .tls
                .as_ref()
                .is_some_and(|p| p.intercepted_ports.is_some()),
            Self::TlsBypass => patch
                .network
                .tls
                .as_ref()
                .is_some_and(|p| p.bypass.is_some()),
            Self::TlsVerifyUpstream => patch
                .network
                .tls
                .as_ref()
                .is_some_and(|p| p.verify_upstream.is_some()),
            Self::TlsBlockQuicOnIntercept => patch
                .network
                .tls
                .as_ref()
                .is_some_and(|p| p.block_quic_on_intercept.is_some()),
            Self::TlsUpstreamCaCert => patch
                .network
                .tls
                .as_ref()
                .is_some_and(|p| p.upstream_ca_cert.is_some()),
            Self::TlsScopedUpstreamCaCert => patch
                .network
                .tls
                .as_ref()
                .is_some_and(|p| p.scoped_upstream_ca_cert.is_some()),
            Self::TlsScopedVerifyUpstream => patch
                .network
                .tls
                .as_ref()
                .is_some_and(|p| p.scoped_verify_upstream.is_some()),
            Self::TlsInterceptCaCertPath | Self::TlsInterceptCaKeyPath => patch
                .network
                .tls
                .as_ref()
                .is_some_and(|p| p.intercept_ca.is_some()),
        }
    }
}
