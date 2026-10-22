//! Validate portable network settings without opening sockets, files or credential sources.

use std::collections::BTreeSet;

use crate::{
    Destination, HostPattern, PortProtocol, SecretEntry, SecretSubstitution, SnapshotManifestResult,
};

use super::SavedValue;
use super::network::*;
use super::validation::{
    MAX_GUEST_PATH_BYTES, MAX_NAME_BYTES, MAX_TEXT_BYTES, binding, count, decode, encoded_size,
    error, invalid,
};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SavedBindingReference {
    /// Validate one logical reference without accepting host paths or endpoint syntax.
    pub fn validate(&self) -> SnapshotManifestResult<()> {
        binding(&self.id, "bindings")
    }
}

impl SavedNetworkConfig {
    /// Decode and validate one strict network section, without resolving any host bindings.
    pub fn from_bytes(bytes: &[u8]) -> SnapshotManifestResult<Self> {
        let config: Self = decode(bytes, "active.network")?;
        config.validate()?;
        Ok(config)
    }

    /// Validate typed construction before capture or resolution. This is not destination consent.
    pub fn validate(&self) -> SnapshotManifestResult<()> {
        encoded_size(self, "active.network")?;
        if let Some(policy) = self.policy.as_ref().and_then(SavedValue::value) {
            count(policy.rules.len(), "active.network.policy.rules")?;
            for rule in &policy.rules {
                if let Destination::Domain(name) | Destination::DomainSuffix(name) =
                    &rule.destination
                {
                    pattern(name, "active.network.policy.rules.destination")?;
                }
                count(
                    rule.protocols.len(),
                    "active.network.policy.rules.protocols",
                )?;
                count(rule.ports.len(), "active.network.policy.rules.ports")?;
                if rule.ports.iter().any(|range| range.start > range.end) {
                    return invalid(
                        "SCFG_VALUE",
                        "active.network.policy.rules.ports",
                        "port range is reversed",
                    );
                }
            }
        }
        if let Some(dns) = self.dns.as_ref().and_then(SavedValue::value) {
            references(&dns.resolvers, "active.network.dns.resolvers")?;
        }
        if let Some(tls) = self.tls.as_ref().and_then(SavedValue::value) {
            count(
                tls.intercepted_ports.len(),
                "active.network.tls.intercepted_ports",
            )?;
            strings(&tls.bypass, "active.network.tls.bypass")?;
            references(&tls.upstream_cas, "active.network.tls.upstream_cas")?;
            if let Some(reference) = &tls.intercept_ca {
                binding(&reference.id, "active.network.tls.intercept_ca")?;
            }
            count(
                tls.scoped_upstream_cas.len(),
                "active.network.tls.scoped_upstream_cas",
            )?;
            for scoped in &tls.scoped_upstream_cas {
                pattern(
                    &scoped.pattern,
                    "active.network.tls.scoped_upstream_cas.pattern",
                )?;
                binding(
                    &scoped.binding.id,
                    "active.network.tls.scoped_upstream_cas.binding",
                )?;
            }
            count(
                tls.scoped_verify_upstream.len(),
                "active.network.tls.scoped_verify_upstream",
            )?;
            for scoped in &tls.scoped_verify_upstream {
                pattern(
                    &scoped.pattern,
                    "active.network.tls.scoped_verify_upstream.pattern",
                )?;
            }
        }
        if let Some(secrets) = self.secrets.as_ref().and_then(SavedValue::value) {
            validate_secrets(secrets)?;
        }
        if let Some(queue) = self
            .tcp_accept_queue_size
            .as_ref()
            .and_then(SavedValue::value)
            && (*queue == 0 || *queue > i32::MAX as u32)
        {
            return invalid(
                "SCFG_VALUE",
                "active.network.tcp_accept_queue_size",
                "queue depth must be between 1 and 2147483647",
            );
        }
        if let Some(rate) = self.rate_limiter.as_ref().and_then(SavedValue::value) {
            for limit in [rate.egress.as_ref(), rate.ingress.as_ref()]
                .into_iter()
                .flatten()
            {
                if limit.bandwidth.is_none() && limit.ops.is_none() {
                    return invalid(
                        "SCFG_VALUE",
                        "active.network.rate_limiter",
                        "a configured direction needs at least one bucket",
                    );
                }
                for bucket in [limit.bandwidth.as_ref(), limit.ops.as_ref()]
                    .into_iter()
                    .flatten()
                {
                    if bucket.size == 0 || bucket.refill_time_ms == 0 {
                        return invalid(
                            "SCFG_VALUE",
                            "active.network.rate_limiter",
                            "bucket size and refill interval must be positive",
                        );
                    }
                }
            }
        }
        if let Some(prefixes) = self.nat64_prefixes.as_ref().and_then(SavedValue::value) {
            count(prefixes.len(), "active.network.nat64_prefixes")?;
            if prefixes.iter().any(|prefix| prefix.prefix() != 96) {
                return invalid(
                    "SCFG_VALUE",
                    "active.network.nat64_prefixes",
                    "NAT64 classification requires /96 prefixes",
                );
            }
        }
        if let Some(ports) = self.ports.as_ref().and_then(SavedValue::value) {
            count(ports.len(), "active.network.ports")?;
            let mut identities = BTreeSet::new();
            for port in ports {
                let protocol = match port.protocol {
                    PortProtocol::Tcp => 0,
                    PortProtocol::Udp => 1,
                };
                // Two distinct host listeners may forward to the same guest service.
                // The logical destination listener plus transport is the identity;
                // source host addresses/ports must not become portable authority.
                if !identities.insert((&port.binding.id, protocol)) {
                    return invalid(
                        "SCFG_IDENTITY",
                        "active.network.ports",
                        "duplicate listener binding and protocol",
                    );
                }
                binding(&port.binding.id, "active.network.ports.binding")?;
            }
        }
        if let Some(trust) = self.guest_trust.as_ref().and_then(SavedValue::value) {
            references(trust, "active.network.guest_trust")?;
        }
        if let Some(http) = self.http.as_ref().and_then(SavedValue::value) {
            for message in [
                &http.deny_message,
                &http.network_deny_message,
                &http.secret_deny_message,
            ]
            .into_iter()
            .flatten()
            {
                if message.len() > MAX_TEXT_BYTES {
                    return invalid(
                        "SCFG_LIMIT",
                        "active.network.http",
                        "denial message is too large",
                    );
                }
            }
        }
        if let Some(proxy) = self.outbound_proxy.as_ref().and_then(SavedValue::value) {
            binding(&proxy.endpoint.id, "active.network.outbound_proxy.endpoint")?;
            if let Some(credentials) = &proxy.credentials {
                if proxy.protocol == SavedProxyProtocol::HttpConnect {
                    return invalid(
                        "SCFG_VALUE",
                        "active.network.outbound_proxy.credentials",
                        "HTTP CONNECT authentication is not supported by this proxy contract",
                    );
                }
                binding(&credentials.id, "active.network.outbound_proxy.credentials")?;
            }
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn pattern(value: &str, field: &str) -> SnapshotManifestResult<()> {
    if value.is_empty() || value.len() > MAX_GUEST_PATH_BYTES || value.chars().any(char::is_control)
    {
        return invalid("SCFG_VALUE", field, "invalid or oversized host pattern");
    }
    Ok(())
}

fn strings(values: &[String], field: &str) -> SnapshotManifestResult<()> {
    count(values.len(), field)?;
    for value in values {
        pattern(value, field)?;
    }
    Ok(())
}

fn patterns(values: &[HostPattern], field: &str) -> SnapshotManifestResult<()> {
    count(values.len(), field)?;
    for value in values {
        match value {
            HostPattern::Exact(host) | HostPattern::Wildcard(host) => pattern(host, field)?,
            HostPattern::Any => {}
        }
    }
    Ok(())
}

fn references(values: &[SavedBindingReference], field: &str) -> SnapshotManifestResult<()> {
    count(values.len(), field)?;
    let mut identities = BTreeSet::new();
    for value in values {
        binding(&value.id, field)?;
        if !identities.insert(&value.id) {
            return invalid("SCFG_IDENTITY", field, "duplicate logical binding");
        }
    }
    Ok(())
}

pub(super) fn validate_secrets(secrets: &SavedSecretsConfig) -> SnapshotManifestResult<()> {
    if let Some(hosts) = &secrets.passthrough_hosts {
        patterns(hosts, "active.network.secrets.passthrough_hosts")?;
    }
    count(secrets.entries.len(), "active.network.secrets.entries")?;
    let mut names = BTreeSet::new();
    let mut placeholders = BTreeSet::new();
    for secret in &secrets.entries {
        if !names.insert(&secret.env_var) || !placeholders.insert(&secret.placeholder) {
            return invalid(
                "SCFG_IDENTITY",
                "active.network.secrets.entries",
                "duplicate environment or placeholder identity",
            );
        }
        if secret.env_var.len() > MAX_NAME_BYTES {
            return invalid(
                "SCFG_LIMIT",
                "active.network.secrets.entries.env_var",
                "environment name is too large",
            );
        }
        binding(&secret.binding.id, "active.network.secrets.entries.binding")?;
        patterns(
            &secret.allowed_hosts,
            "active.network.secrets.entries.allowed_hosts",
        )?;
        patterns(
            &secret.passthrough_hosts,
            "active.network.secrets.entries.passthrough_hosts",
        )?;
        count(
            secret.substitution.header_fields.len(),
            "active.network.secrets.entries.substitution.header_fields",
        )?;
        if secret
            .substitution
            .header_fields
            .iter()
            .any(|field| field.len() > MAX_NAME_BYTES)
        {
            return invalid(
                "SCFG_LIMIT",
                "active.network.secrets.entries.substitution.header_fields",
                "header name is too large",
            );
        }
        // Reuse the shared placeholder/substitution validator with no credential or
        // source attached. Never serialize a live SecretEntry to produce this record.
        let policy = SecretEntry {
            env_var: secret.env_var.clone(),
            value: Default::default(),
            source: None,
            placeholder: secret.placeholder.clone(),
            allowed_hosts: secret.allowed_hosts.clone(),
            substitution: SecretSubstitution {
                headers: secret.substitution.headers,
                header_fields: secret.substitution.header_fields.clone(),
                query: secret.substitution.query,
                body: secret.substitution.body,
            },
            passthrough_hosts: secret.passthrough_hosts.clone(),
            violation_action: secret.violation_action.clone(),
            require_tls_identity: secret.require_tls_identity,
        };
        policy.validate(0).map_err(|_| {
            error(
                "SCFG_VALUE",
                "active.network.secrets.entries",
                "invalid placeholder or substitution policy",
            )
        })?;
    }
    Ok(())
}
