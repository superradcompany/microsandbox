//! Fluent builder API for [`NetworkConfig`].
//!
//! Used by `SandboxBuilder::network(|n| n.port(8080, 80).policy(...))`.

use std::net::IpAddr;
use std::path::PathBuf;

use crate::config::{DnsConfig, InterfaceOverrides, NetworkConfig, PortProtocol, PublishedPort};
use crate::dns::Nameserver;
use crate::policy::{BuildError, DomainName, NetworkPolicy};
use crate::secrets::config::{HostPattern, SecretEntry, SecretInjection, ViolationAction};
use crate::tls::TlsConfig;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder for [`NetworkConfig`].
#[derive(Clone)]
pub struct NetworkBuilder {
    config: NetworkConfig,
    errors: Vec<BuildError>,
}

/// Fluent builder for [`DnsConfig`].
pub struct DnsBuilder {
    config: DnsConfig,
    errors: Vec<BuildError>,
}

/// Fluent builder for [`TlsConfig`].
pub struct TlsBuilder {
    config: TlsConfig,
}

/// Fluent builder for a single [`SecretEntry`].
///
/// ```ignore
/// SecretBuilder::new()
///     .env("OPENAI_API_KEY")
///     .value(api_key)
///     .allow_host("api.openai.com")
///     .build()
/// ```
pub struct SecretBuilder {
    env_var: Option<String>,
    value: Option<String>,
    placeholder: Option<String>,
    allowed_hosts: Vec<HostPattern>,
    injection: SecretInjection,
    require_tls_identity: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl NetworkBuilder {
    /// Start building a network configuration with defaults.
    pub fn new() -> Self {
        Self {
            config: NetworkConfig::default(),
            errors: Vec::new(),
        }
    }

    /// Start building from an existing network configuration.
    pub fn from_config(config: NetworkConfig) -> Self {
        Self {
            config,
            errors: Vec::new(),
        }
    }

    /// Enable or disable networking.
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    /// Publish a TCP port: `host_port` on the host maps to `guest_port` in the guest.
    pub fn port(self, host_port: u16, guest_port: u16) -> Self {
        self.add_port(host_port, guest_port, PortProtocol::Tcp)
    }

    /// Publish a UDP port.
    pub fn port_udp(self, host_port: u16, guest_port: u16) -> Self {
        self.add_port(host_port, guest_port, PortProtocol::Udp)
    }

    fn add_port(mut self, host_port: u16, guest_port: u16, protocol: PortProtocol) -> Self {
        self.config.ports.push(PublishedPort {
            host_port,
            guest_port,
            protocol,
            host_bind: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        });
        self
    }

    /// Set the network policy.
    pub fn policy(mut self, policy: NetworkPolicy) -> Self {
        self.config.policy = policy;
        self
    }

    /// Configure DNS interception via a closure.
    ///
    /// ```ignore
    /// .dns(|d| d
    ///     .block_domain("malware.example.com")
    ///     .block_domain_suffix(".tracking.com")
    ///     .nameservers(["1.1.1.1".parse::<Nameserver>()?])
    /// )
    /// ```
    pub fn dns(mut self, f: impl FnOnce(DnsBuilder) -> DnsBuilder) -> Self {
        let dns_builder = f(DnsBuilder::new());
        match dns_builder.build() {
            Ok(config) => self.config.dns = config,
            Err(err) => self.errors.push(err),
        }
        self
    }

    /// Configure TLS interception via a closure.
    pub fn tls(mut self, f: impl FnOnce(TlsBuilder) -> TlsBuilder) -> Self {
        self.config.tls = f(TlsBuilder::new()).build();
        self
    }

    /// Add a secret via a closure builder.
    ///
    /// ```ignore
    /// .secret(|s| s
    ///     .env("OPENAI_API_KEY")
    ///     .value(api_key)
    ///     .allow_host("api.openai.com")
    /// )
    /// ```
    pub fn secret(mut self, f: impl FnOnce(SecretBuilder) -> SecretBuilder) -> Self {
        self.config
            .secrets
            .secrets
            .push(f(SecretBuilder::new()).build());
        self
    }

    /// Shorthand: add a secret with env var, value, placeholder, and allowed host.
    pub fn secret_env(
        mut self,
        env_var: impl Into<String>,
        value: impl Into<String>,
        placeholder: impl Into<String>,
        allowed_host: impl Into<String>,
    ) -> Self {
        self.config.secrets.secrets.push(SecretEntry {
            env_var: env_var.into(),
            value: value.into(),
            placeholder: placeholder.into(),
            allowed_hosts: vec![HostPattern::Exact(allowed_host.into())],
            injection: SecretInjection::default(),
            require_tls_identity: true,
        });
        self
    }

    /// Set the violation action for secrets.
    pub fn on_secret_violation(mut self, action: ViolationAction) -> Self {
        self.config.secrets.on_violation = action;
        self
    }

    /// Set the maximum number of concurrent connections.
    pub fn max_connections(mut self, max: usize) -> Self {
        self.config.max_connections = Some(max);
        self
    }

    /// Set guest interface overrides.
    pub fn interface(mut self, overrides: InterfaceOverrides) -> Self {
        self.config.interface = overrides;
        self
    }

    /// Whether to ship the host's trusted root CAs into the guest at
    /// boot. Default: false. Opt in when running behind a corporate
    /// TLS-inspecting proxy (Cloudflare Warp Zero Trust, Zscaler,
    /// Netskope, ...) whose gateway CA is trusted on the host but
    /// unknown to the guest's stock Mozilla bundle.
    pub fn trust_host_cas(mut self, enabled: bool) -> Self {
        self.config.trust_host_cas = enabled;
        self
    }

    /// Consume the builder and return the configuration.
    ///
    /// Surfaces the first [`BuildError`] accumulated by any nested
    /// builder (currently [`DnsBuilder`]). Errors stored on the
    /// network builder itself flow through here too.
    pub fn build(mut self) -> Result<NetworkConfig, BuildError> {
        if let Some(err) = self.errors.drain(..).next() {
            return Err(err);
        }
        Ok(self.config)
    }
}

impl DnsBuilder {
    /// Start building DNS configuration with defaults.
    pub fn new() -> Self {
        Self {
            config: DnsConfig::default(),
            errors: Vec::new(),
        }
    }

    /// Block a specific domain via DNS interception (returns REFUSED).
    ///
    /// Accepts any string-like input. The string is stored raw and
    /// parsed via [`DomainName`] at [`Self::build`] time. Invalid
    /// names accumulate as
    /// [`BuildError::InvalidBlockedDomain`] and surface from the
    /// outermost `.build()` in the chain — the chain itself stays
    /// infallible (no `?` per call).
    pub fn block_domain(mut self, domain: impl Into<String>) -> Self {
        let raw: String = domain.into();
        match raw.parse::<DomainName>() {
            Ok(name) => self.config.blocked_domains.push(name.into()),
            Err(source) => self
                .errors
                .push(BuildError::InvalidBlockedDomain { raw, source }),
        }
        self
    }

    /// Block a domain suffix via DNS interception (returns REFUSED).
    ///
    /// Same string-input + lazy-parse + accumulate behavior as
    /// [`Self::block_domain`]. Invalid suffixes accumulate as
    /// [`BuildError::InvalidBlockedDomainSuffix`].
    pub fn block_domain_suffix(mut self, suffix: impl Into<String>) -> Self {
        let raw: String = suffix.into();
        match raw.parse::<DomainName>() {
            Ok(name) => self.config.blocked_suffixes.push(name.into()),
            Err(source) => self
                .errors
                .push(BuildError::InvalidBlockedDomainSuffix { raw, source }),
        }
        self
    }

    /// Enable or disable DNS rebinding protection. Default: true.
    pub fn rebind_protection(mut self, enabled: bool) -> Self {
        self.config.rebind_protection = enabled;
        self
    }

    /// Set the upstream nameservers to forward queries to. When one or
    /// more are set, the interceptor uses these instead of the
    /// nameservers in the host's `/etc/resolv.conf`. Replaces any
    /// previously-set nameservers. Each element is any type convertible
    /// into [`Nameserver`] (`SocketAddr`, `IpAddr`, or a parsed
    /// string via `"dns.google:53".parse::<Nameserver>()?`).
    pub fn nameservers<I>(mut self, nameservers: I) -> Self
    where
        I: IntoIterator,
        I::Item: Into<Nameserver>,
    {
        self.config.nameservers = nameservers.into_iter().map(Into::into).collect();
        self
    }

    /// Set the per-DNS-query timeout in milliseconds. Default: 5000.
    pub fn query_timeout_ms(mut self, ms: u64) -> Self {
        self.config.query_timeout_ms = ms;
        self
    }

    /// Consume the builder and return the configuration.
    ///
    /// Surfaces the first parse error accumulated by `block_domain` /
    /// `block_domain_suffix` (or any future lazy-parse method on this
    /// builder). Successful chains return the populated `DnsConfig`.
    pub fn build(mut self) -> Result<DnsConfig, BuildError> {
        if let Some(err) = self.errors.drain(..).next() {
            return Err(err);
        }
        Ok(self.config)
    }
}

impl Default for DnsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsBuilder {
    /// Start building TLS configuration.
    pub fn new() -> Self {
        Self {
            config: TlsConfig {
                enabled: true,
                ..TlsConfig::default()
            },
        }
    }

    /// Add a domain to the bypass list (no MITM). Supports `*.suffix` wildcards.
    pub fn bypass(mut self, pattern: impl Into<String>) -> Self {
        self.config.bypass.push(pattern.into());
        self
    }

    /// Enable or disable upstream server certificate verification.
    pub fn verify_upstream(mut self, verify: bool) -> Self {
        self.config.verify_upstream = verify;
        self
    }

    /// Set the ports to intercept.
    pub fn intercepted_ports(mut self, ports: Vec<u16>) -> Self {
        self.config.intercepted_ports = ports;
        self
    }

    /// Enable or disable QUIC blocking on intercepted ports.
    pub fn block_quic(mut self, block: bool) -> Self {
        self.config.block_quic_on_intercept = block;
        self
    }

    /// Add a CA certificate PEM file to trust for upstream server verification.
    ///
    /// Useful when the upstream server uses a self-signed or private CA certificate.
    /// Can be called multiple times to add several CAs.
    pub fn upstream_ca_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.upstream_ca_cert.push(path.into());
        self
    }

    /// Set a custom interception CA certificate PEM file path.
    pub fn intercept_ca_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.intercept_ca.cert_path = Some(path.into());
        self
    }

    /// Set a custom interception CA private key PEM file path.
    pub fn intercept_ca_key(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.intercept_ca.key_path = Some(path.into());
        self
    }

    /// Consume the builder and return the configuration.
    pub fn build(self) -> TlsConfig {
        self.config
    }
}

impl SecretBuilder {
    /// Start building a secret.
    pub fn new() -> Self {
        Self {
            env_var: None,
            value: None,
            placeholder: None,
            allowed_hosts: Vec::new(),
            injection: SecretInjection::default(),
            require_tls_identity: true,
        }
    }

    /// Set the environment variable to expose the placeholder as (required).
    pub fn env(mut self, var: impl Into<String>) -> Self {
        self.env_var = Some(var.into());
        self
    }

    /// Set the secret value (required).
    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }

    /// Set a custom placeholder string.
    /// If not set, auto-generated as `$MSB_<env_var>`.
    pub fn placeholder(mut self, placeholder: impl Into<String>) -> Self {
        self.placeholder = Some(placeholder.into());
        self
    }

    /// Add an allowed host (exact match).
    pub fn allow_host(mut self, host: impl Into<String>) -> Self {
        self.allowed_hosts.push(HostPattern::Exact(host.into()));
        self
    }

    /// Add an allowed host with wildcard pattern (e.g., `*.openai.com`).
    pub fn allow_host_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.allowed_hosts
            .push(HostPattern::Wildcard(pattern.into()));
        self
    }

    /// Allow for any host. **Dangerous**: secret can be exfiltrated to any
    /// destination. Requires explicit acknowledgment.
    pub fn allow_any_host_dangerous(mut self, i_understand_the_risk: bool) -> Self {
        if i_understand_the_risk {
            self.allowed_hosts.push(HostPattern::Any);
        }
        self
    }

    /// Require verified TLS identity before substituting (default: true).
    pub fn require_tls_identity(mut self, enabled: bool) -> Self {
        self.require_tls_identity = enabled;
        self
    }

    /// Configure header injection (default: true).
    pub fn inject_headers(mut self, enabled: bool) -> Self {
        self.injection.headers = enabled;
        self
    }

    /// Configure Basic Auth injection (default: true).
    pub fn inject_basic_auth(mut self, enabled: bool) -> Self {
        self.injection.basic_auth = enabled;
        self
    }

    /// Configure query parameter injection (default: false).
    pub fn inject_query(mut self, enabled: bool) -> Self {
        self.injection.query_params = enabled;
        self
    }

    /// Configure body injection (default: false).
    pub fn inject_body(mut self, enabled: bool) -> Self {
        self.injection.body = enabled;
        self
    }

    /// Consume the builder and return a [`SecretEntry`].
    ///
    /// # Panics
    /// Panics if `env` or `value` was not set.
    pub fn build(self) -> SecretEntry {
        let env_var = self.env_var.expect("SecretBuilder: .env() is required");
        let value = self.value.expect("SecretBuilder: .value() is required");
        let placeholder = self
            .placeholder
            .unwrap_or_else(|| format!("$MSB_{env_var}"));

        SecretEntry {
            env_var,
            value,
            placeholder,
            allowed_hosts: self.allowed_hosts,
            injection: self.injection,
            require_tls_identity: self.require_tls_identity,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for NetworkBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for TlsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SecretBuilder {
    fn default() -> Self {
        Self::new()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Valid block-domain entries land in the config. No errors on
    /// the happy path.
    #[test]
    fn block_domain_happy_path() {
        let cfg = DnsBuilder::new()
            .block_domain("evil.com")
            .block_domain_suffix(".tracking.example")
            .build()
            .unwrap();
        assert_eq!(cfg.blocked_domains.len(), 1);
        assert_eq!(cfg.blocked_suffixes.len(), 1);
    }

    /// Invalid block-domain accumulates as
    /// `BuildError::InvalidBlockedDomain`; surfaces from `.build()`.
    #[test]
    fn block_domain_invalid_surfaces_at_build() {
        let result = DnsBuilder::new().block_domain("not a domain!").build();
        match result {
            Err(BuildError::InvalidBlockedDomain { raw, .. }) => {
                assert_eq!(raw, "not a domain!");
            }
            other => panic!("expected InvalidBlockedDomain, got {other:?}"),
        }
    }

    /// Invalid suffix accumulates as
    /// `BuildError::InvalidBlockedDomainSuffix`.
    #[test]
    fn block_domain_suffix_invalid_surfaces_at_build() {
        let result = DnsBuilder::new()
            .block_domain_suffix("...invalid!!!")
            .build();
        match result {
            Err(BuildError::InvalidBlockedDomainSuffix { raw, .. }) => {
                assert_eq!(raw, "...invalid!!!");
            }
            other => panic!("expected InvalidBlockedDomainSuffix, got {other:?}"),
        }
    }

    /// First-error semantics: multiple bad inputs surface only the
    /// first one (matching `NetworkPolicyBuilder`).
    #[test]
    fn block_domain_first_error_wins() {
        let result = DnsBuilder::new()
            .block_domain("first bad!")
            .block_domain("second bad!")
            .build();
        match result {
            Err(BuildError::InvalidBlockedDomain { raw, .. }) => {
                assert_eq!(raw, "first bad!");
            }
            other => panic!("expected first-error InvalidBlockedDomain, got {other:?}"),
        }
    }

    /// Errors accumulated by a `DnsBuilder` cascade up through
    /// `NetworkBuilder::dns()` and surface from
    /// `NetworkBuilder::build()`.
    #[test]
    fn dns_error_cascades_through_network_builder() {
        let result = NetworkBuilder::new()
            .dns(|d| d.block_domain("not a domain!"))
            .build();
        match result {
            Err(BuildError::InvalidBlockedDomain { raw, .. }) => {
                assert_eq!(raw, "not a domain!");
            }
            other => panic!("expected cascaded InvalidBlockedDomain, got {other:?}"),
        }
    }

    /// Network builder happy path returns the config unchanged.
    #[test]
    fn network_builder_happy_path_returns_config() {
        let cfg = NetworkBuilder::new()
            .dns(|d| d.block_domain("evil.com"))
            .build()
            .unwrap();
        assert_eq!(cfg.dns.blocked_domains.len(), 1);
    }
}
