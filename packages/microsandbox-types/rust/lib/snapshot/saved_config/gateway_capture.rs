//! Portable gateway capture projections. Source host resources are never serialized or opened.

use crate::{
    DnsConfig, InterceptCaConfig, OutboundProxy, PublishedPortSpec, ScopedUpstreamCaCert,
    ScopedVerifyUpstream, SnapshotManifestResult, TlsConfig,
};

use super::validation::{count, invalid};
use super::{
    SavedBindingReference, SavedDnsConfig, SavedNetworkConfig, SavedOrigin, SavedProxy,
    SavedProxyProtocol, SavedPublishedPort, SavedScopedTrust, SavedScopedVerification,
    SavedTlsConfig, SavedValue,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Logical replacements selected under the same capture guard as the active TLS configuration.
/// This contains no source filenames, certificate material or permission to reuse a private key.
#[derive(Default)]
pub struct SavedTlsCaptureBindings {
    /// One replacement per upstream CA, in the source list's order.
    pub upstream_cas: Vec<SavedBindingReference>,
    /// One replacement per scoped CA, in the source list's order.
    pub scoped_upstream_cas: Vec<SavedBindingReference>,
    /// Active interception identity, including an automatically generated identity.
    /// Its actual backing and full-resume compatibility require independent capture evidence.
    pub intercept_ca: Option<SavedBindingReference>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SavedDnsConfig {
    /// Replace each explicit resolver with a logical destination requirement, preserving order.
    /// An empty source list means destination discovery; source-host discovery is not replayed.
    pub fn from_source(
        source: &DnsConfig,
        resolvers: Vec<SavedBindingReference>,
    ) -> SnapshotManifestResult<Self> {
        let DnsConfig {
            rebind_protection,
            nameservers,
            query_timeout_ms,
        } = source;
        count(nameservers.len(), "active.network.dns.resolvers")?;
        if resolvers.len() != nameservers.len() {
            return invalid(
                "SCFG_BINDING",
                "active.network.dns.resolvers",
                "each explicit resolver needs exactly one destination binding",
            );
        }
        let result = Self {
            rebind_protection: *rebind_protection,
            query_timeout_ms: *query_timeout_ms,
            resolvers,
        };
        SavedNetworkConfig {
            dns: Some(observed(result.clone())),
            ..Default::default()
        }
        .validate()?;
        Ok(result)
    }
}

impl SavedProxy {
    /// Preserve protocol/authentication requirements without copying endpoint or credential data.
    /// Empty source credentials are still configured credentials, not permission to omit a binding.
    pub fn from_source(
        source: &OutboundProxy,
        endpoint: SavedBindingReference,
        credentials: Option<SavedBindingReference>,
    ) -> SnapshotManifestResult<Self> {
        let (protocol, requires_credentials) = match source {
            OutboundProxy::HttpConnect { address: _ } => (SavedProxyProtocol::HttpConnect, false),
            OutboundProxy::Socks4 {
                address: _,
                user_id,
            } => (SavedProxyProtocol::Socks4, user_id.is_some()),
            OutboundProxy::Socks5 {
                address: _,
                credentials,
            } => (SavedProxyProtocol::Socks5, credentials.is_some()),
        };
        if requires_credentials != credentials.is_some() {
            return invalid(
                "SCFG_BINDING",
                "active.network.outbound_proxy.credentials",
                "destination credential requirement must match the source authentication mode",
            );
        }
        let result = Self {
            protocol,
            endpoint,
            credentials,
        };
        SavedNetworkConfig {
            outbound_proxy: Some(observed(result.clone())),
            ..Default::default()
        }
        .validate()?;
        Ok(result)
    }
}

impl SavedPublishedPort {
    /// Retain guest service/transport while replacing source listener ownership with a binding.
    /// The complete network document additionally rejects duplicate binding/transport identities.
    pub fn from_source(
        source: &PublishedPortSpec,
        binding: SavedBindingReference,
    ) -> SnapshotManifestResult<Self> {
        let PublishedPortSpec {
            host_port: _,
            guest_port,
            protocol,
            host_bind: _,
        } = source;
        let result = Self {
            guest_port: *guest_port,
            protocol: *protocol,
            binding,
        };
        SavedNetworkConfig {
            ports: Some(observed(vec![result.clone()])),
            ..Default::default()
        }
        .validate()?;
        Ok(result)
    }
}

impl SavedTlsConfig {
    /// Copy policy only, requiring logical replacements for every selected source trust resource.
    /// Capture supplies guarded active settings; this helper cannot establish runtime coherence.
    pub fn from_source(
        source: &TlsConfig,
        bindings: SavedTlsCaptureBindings,
    ) -> SnapshotManifestResult<Self> {
        // Exhaustive source destructuring forces a new source field to receive a
        // portability decision instead of slipping through a generic serializer.
        let TlsConfig {
            enabled,
            intercepted_ports,
            bypass,
            verify_upstream,
            block_quic_on_intercept,
            upstream_ca_cert,
            scoped_upstream_ca_cert,
            scoped_verify_upstream,
            intercept_ca,
            cache: _,
        } = source;
        let InterceptCaConfig {
            cert_path,
            key_path,
        } = intercept_ca;
        count(upstream_ca_cert.len(), "active.network.tls.upstream_cas")?;
        count(
            scoped_upstream_ca_cert.len(),
            "active.network.tls.scoped_upstream_cas",
        )?;
        count(
            intercepted_ports.len(),
            "active.network.tls.intercepted_ports",
        )?;
        count(bypass.len(), "active.network.tls.bypass")?;
        count(
            scoped_verify_upstream.len(),
            "active.network.tls.scoped_verify_upstream",
        )?;
        if bindings.upstream_cas.len() != upstream_ca_cert.len()
            || bindings.scoped_upstream_cas.len() != scoped_upstream_ca_cert.len()
        {
            return invalid(
                "SCFG_BINDING",
                "active.network.tls",
                "each upstream trust resource needs exactly one destination binding",
            );
        }
        // No configured paths does not mean no identity: enabled interception
        // may use a generated CA whose private backing must not enter metadata.
        if (*enabled || cert_path.is_some() || key_path.is_some())
            && bindings.intercept_ca.is_none()
        {
            return invalid(
                "SCFG_BINDING",
                "active.network.tls.intercept_ca",
                "source interception identity needs a destination binding",
            );
        }
        let scoped_upstream_cas = scoped_upstream_ca_cert
            .iter()
            .zip(bindings.scoped_upstream_cas)
            .map(|(source, binding)| {
                let ScopedUpstreamCaCert { pattern, path: _ } = source;
                SavedScopedTrust {
                    pattern: pattern.clone(),
                    binding,
                }
            })
            .collect();
        let scoped_verify_upstream = scoped_verify_upstream
            .iter()
            .map(|source| {
                let ScopedVerifyUpstream { pattern, verify } = source;
                SavedScopedVerification {
                    pattern: pattern.clone(),
                    verify: *verify,
                }
            })
            .collect();
        let result = Self {
            enabled: *enabled,
            intercepted_ports: intercepted_ports.clone(),
            bypass: bypass.clone(),
            verify_upstream: *verify_upstream,
            block_quic_on_intercept: *block_quic_on_intercept,
            upstream_cas: bindings.upstream_cas,
            scoped_upstream_cas,
            scoped_verify_upstream,
            intercept_ca: bindings.intercept_ca,
        };
        SavedNetworkConfig {
            tls: Some(observed(result.clone())),
            ..Default::default()
        }
        .validate()?;
        Ok(result)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn observed<T>(value: T) -> SavedValue<T> {
    SavedValue::Value {
        value,
        origin: SavedOrigin::Observed,
    }
}
