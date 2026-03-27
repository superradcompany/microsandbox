//! Fluent builder API for [`NetworkConfig`].
//!
//! Used by `SandboxBuilder::network(|n| n.port(8080, 80).policy(...))`.

use std::net::IpAddr;

use crate::config::{InterfaceOverrides, NetworkConfig, PortProtocol, PublishedPort};
use crate::policy::NetworkPolicy;
use crate::secrets::config::{HostPattern, SecretEntry, SecretInjection, ViolationAction};
use crate::tls::TlsConfig;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder for [`NetworkConfig`].
pub struct NetworkBuilder {
    config: NetworkConfig,
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
        }
    }

    /// Start building from an existing network configuration.
    pub fn from_config(config: NetworkConfig) -> Self {
        Self { config }
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

    /// Block a specific domain via DNS interception.
    pub fn block_domain(mut self, domain: impl Into<String>) -> Self {
        self.config.dns.blocked_domains.push(domain.into());
        self
    }

    /// Block a domain suffix via DNS interception.
    pub fn block_domain_suffix(mut self, suffix: impl Into<String>) -> Self {
        self.config.dns.blocked_suffixes.push(suffix.into());
        self
    }

    /// Enable or disable DNS rebinding protection.
    pub fn dns_rebind_protection(mut self, enabled: bool) -> Self {
        self.config.dns.rebind_protection = enabled;
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

    /// Consume the builder and return the configuration.
    pub fn build(self) -> NetworkConfig {
        self.config
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
