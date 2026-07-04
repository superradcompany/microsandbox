//! Fluent builder API for [`NetworkConfig`].
//!
//! Used by `SandboxBuilder::network(|n| n.port(8080, 80).policy(...))`.

use std::net::IpAddr;
use std::path::PathBuf;

use ipnetwork::{Ipv4Network, Ipv6Network};

use crate::config::{DnsConfig, InterfaceOverrides, NetworkConfig, PortProtocol, PublishedPort};
use crate::dns::Nameserver;
use crate::policy::{BuildError, NetworkPolicy};
use zeroize::Zeroizing;

use crate::secrets::config::{
    HostPattern, SecretEntry, SecretInjection, SecretSource, ViolationAction,
};
use crate::tls::{ScopedUpstreamCaCert, ScopedVerifyUpstream, TlsConfig};

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
    source: Option<SecretSource>,
    placeholder: Option<String>,
    allowed_hosts: Vec<HostPattern>,
    injection: SecretInjection,
    on_violation: Option<ViolationAction>,
    require_tls_identity: bool,
}

/// Fluent builder for a [`ViolationAction`].
#[derive(Default)]
pub struct ViolationActionBuilder {
    action: ViolationAction,
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
        self.port_bind(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            host_port,
            guest_port,
        )
    }

    /// Publish a UDP port.
    pub fn port_udp(self, host_port: u16, guest_port: u16) -> Self {
        self.port_udp_bind(
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            host_port,
            guest_port,
        )
    }

    /// Publish a TCP port on a specific host bind address.
    pub fn port_bind(self, host_bind: IpAddr, host_port: u16, guest_port: u16) -> Self {
        self.add_port(host_bind, host_port, guest_port, PortProtocol::Tcp)
    }

    /// Publish a UDP port on a specific host bind address.
    pub fn port_udp_bind(self, host_bind: IpAddr, host_port: u16, guest_port: u16) -> Self {
        self.add_port(host_bind, host_port, guest_port, PortProtocol::Udp)
    }

    fn add_port(
        mut self,
        host_bind: IpAddr,
        host_port: u16,
        guest_port: u16,
        protocol: PortProtocol,
    ) -> Self {
        self.config.ports.push(PublishedPort {
            host_port,
            guest_port,
            protocol,
            host_bind,
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
    ///     .nameservers(["1.1.1.1".parse::<Nameserver>()?])
    ///     .rebind_protection(false)
    /// )
    /// ```
    pub fn dns(mut self, f: impl FnOnce(DnsBuilder) -> DnsBuilder) -> Self {
        self.config.dns = f(DnsBuilder::new()).build();
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
    pub fn secret(self, f: impl FnOnce(SecretBuilder) -> SecretBuilder) -> Self {
        self.secret_entry(f(SecretBuilder::new()).build())
    }

    /// Add a materialized secret entry.
    pub fn secret_entry(mut self, entry: SecretEntry) -> Self {
        self.config.secrets.secrets.push(entry);
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
            value: Zeroizing::new(value.into()),
            source: None,
            placeholder: placeholder.into(),
            allowed_hosts: vec![HostPattern::Exact(allowed_host.into())],
            injection: SecretInjection::default(),
            on_violation: None,
            require_tls_identity: true,
        });
        self
    }

    /// Set the violation action for secrets.
    pub fn on_secret_violation(
        mut self,
        f: impl FnOnce(ViolationActionBuilder) -> ViolationActionBuilder,
    ) -> Self {
        self.config.secrets.on_violation = f(ViolationActionBuilder::default()).build();
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

    /// Set the IPv4 pool used to derive per-sandbox `/30` guest subnets.
    ///
    /// The default is `172.16.0.0/12`. Pools must be at least `/30`.
    pub fn ipv4_pool(mut self, pool: Ipv4Network) -> Self {
        if pool.prefix() > 30 {
            self.errors.push(BuildError::InvalidIpv4Pool {
                raw: pool.to_string(),
            });
        } else {
            self.config.interface.ipv4_pool = Some(pool);
        }
        self
    }

    /// Set the IPv6 pool used to derive per-sandbox `/64` guest prefixes.
    ///
    /// The default is `fd42:6d73:62::/48`. Pools must be at least `/64`.
    pub fn ipv6_pool(mut self, pool: Ipv6Network) -> Self {
        if pool.prefix() > 64 {
            self.errors.push(BuildError::InvalidIpv6Pool {
                raw: pool.to_string(),
            });
        } else {
            self.config.interface.ipv6_pool = Some(pool);
        }
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
        self.config.secrets.validate()?;
        Ok(self.config)
    }
}

impl DnsBuilder {
    /// Start building DNS configuration with defaults.
    pub fn new() -> Self {
        Self {
            config: DnsConfig::default(),
        }
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
    pub fn build(self) -> DnsConfig {
        self.config
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

    /// Enable or disable upstream server certificate verification only
    /// when the upstream SNI matches `pattern`.
    ///
    /// Pattern syntax matches [`Self::bypass`]: exact hosts and `*.suffix`
    /// wildcards are supported.
    pub fn verify_upstream_for(mut self, pattern: impl Into<String>, verify: bool) -> Self {
        self.config
            .scoped_verify_upstream
            .push(ScopedVerifyUpstream {
                pattern: pattern.into(),
                verify,
            });
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

    /// Add a CA certificate PEM file to trust for upstream server verification
    /// only when the upstream SNI matches `pattern`.
    ///
    /// Pattern syntax matches [`Self::bypass`]: exact hosts and `*.suffix`
    /// wildcards are supported. Can be called multiple times to add several
    /// CAs for the same host pattern.
    pub fn upstream_ca_cert_for(
        mut self,
        pattern: impl Into<String>,
        path: impl Into<PathBuf>,
    ) -> Self {
        self.config
            .scoped_upstream_ca_cert
            .push(ScopedUpstreamCaCert {
                pattern: pattern.into(),
                path: path.into(),
            });
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
            source: None,
            placeholder: None,
            allowed_hosts: Vec::new(),
            injection: SecretInjection::default(),
            on_violation: None,
            require_tls_identity: true,
        }
    }

    /// Set the environment variable to expose the placeholder as (required).
    ///
    /// Names must be non-empty and must not contain `=` or NUL. They are
    /// not restricted to shell-identifier syntax.
    pub fn env(mut self, var: impl Into<String>) -> Self {
        self.env_var = Some(var.into());
        self
    }

    /// Set the secret value inline (mutually exclusive with [`source`](Self::source)).
    ///
    /// Prefer [`source`](Self::source) for durable configs: an inline value is
    /// persisted verbatim in the sandbox spec, whereas a source reference is
    /// resolved host-side at spawn time and never stored at rest.
    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }

    /// Resolve the value from a host-side source reference at spawn time
    /// (mutually exclusive with [`value`](Self::value)).
    ///
    /// The durable config records only the reference; the plaintext is read
    /// from the host environment when the sandbox starts, so it never lands
    /// in the database.
    pub fn source(mut self, source: SecretSource) -> Self {
        self.source = Some(source);
        self
    }

    /// Set a custom placeholder string.
    ///
    /// Placeholders must be non-empty, at most 1024 bytes, and must not
    /// contain NUL, CR, or LF.
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

    /// Set the violation action for this secret.
    pub fn on_violation(
        mut self,
        f: impl FnOnce(ViolationActionBuilder) -> ViolationActionBuilder,
    ) -> Self {
        self.on_violation = Some(f(ViolationActionBuilder::default()).build());
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

    /// Configure HTTP/1 body injection (default: false).
    ///
    /// Fixed-length bodies up to 16 MiB update `Content-Length`; larger
    /// fixed-length bodies are blocked. Chunked bodies are decoded and
    /// re-encoded with fresh chunk sizes. Encoded bodies pass through
    /// unchanged.
    pub fn inject_body(mut self, enabled: bool) -> Self {
        self.injection.body = enabled;
        self
    }

    /// Consume the builder and return a [`SecretEntry`].
    ///
    /// Exactly one of [`value`](Self::value) or [`source`](Self::source) must
    /// be set. A source-backed entry carries an empty durable value; it is
    /// resolved host-side at spawn time.
    ///
    /// # Panics
    /// Panics if `env` or at least one allowed host was not set, or if neither
    /// (or both) of `value`/`source` was set.
    pub fn build(self) -> SecretEntry {
        let env_var = self.env_var.expect("SecretBuilder: .env() is required");
        assert!(
            self.value.is_some() ^ self.source.is_some(),
            "SecretBuilder: exactly one of .value() or .source() is required"
        );
        assert!(
            !self.allowed_hosts.is_empty(),
            "SecretBuilder: at least one allowed host is required; use .allow_any_host_dangerous(true) for an explicit any-host secret"
        );
        let placeholder = self
            .placeholder
            .unwrap_or_else(|| format!("$MSB_{env_var}"));

        SecretEntry {
            env_var,
            value: Zeroizing::new(self.value.unwrap_or_default()),
            source: self.source,
            placeholder,
            allowed_hosts: self.allowed_hosts,
            injection: self.injection,
            on_violation: self.on_violation,
            require_tls_identity: self.require_tls_identity,
        }
    }
}

impl ViolationActionBuilder {
    /// Start building a violation action.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start building from an existing action.
    pub fn from_action(action: ViolationAction) -> Self {
        action.into()
    }

    /// Block the request silently.
    pub fn block(mut self) -> Self {
        self.action = ViolationAction::Block;
        self
    }

    /// Block the request and emit a warning log.
    pub fn block_and_log(mut self) -> Self {
        self.action = ViolationAction::BlockAndLog;
        self
    }

    /// Block the request and terminate the sandbox.
    pub fn block_and_terminate(mut self) -> Self {
        self.action = ViolationAction::BlockAndTerminate;
        self
    }

    /// Allow a host to receive secret placeholders without substitution.
    pub fn passthrough_host(mut self, host: impl Into<String>) -> Self {
        self.push_passthrough_host(HostPattern::Exact(host.into()));
        self
    }

    /// Allow hosts matching a wildcard pattern to receive secret placeholders without substitution.
    pub fn passthrough_host_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.push_passthrough_host(HostPattern::Wildcard(pattern.into()));
        self
    }

    /// Allow any host to receive secret placeholders without substitution.
    pub fn passthrough_all_hosts(mut self, i_understand_the_risk: bool) -> Self {
        if i_understand_the_risk {
            self.push_passthrough_host(HostPattern::Any);
        }
        self
    }

    /// Helper to accumulate passthrough hosts into the current action.
    fn push_passthrough_host(&mut self, host: HostPattern) {
        match self.action {
            ViolationAction::Passthrough(ref mut hosts) => hosts.push(host),
            _ => self.action = ViolationAction::Passthrough(vec![host]),
        }
    }

    /// Consume the builder and return the action.
    pub fn build(self) -> ViolationAction {
        self.action
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
impl From<ViolationAction> for ViolationActionBuilder {
    fn from(action: ViolationAction) -> Self {
        Self { action }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Network builder happy path returns the config unchanged.
    #[test]
    fn network_builder_happy_path_returns_config() {
        let cfg = NetworkBuilder::new()
            .dns(|d| d.rebind_protection(false))
            .build()
            .unwrap();
        assert!(!cfg.dns.rebind_protection);
    }

    #[test]
    fn port_bind_sets_host_bind() {
        let bind = "0.0.0.0".parse().unwrap();
        let cfg = NetworkBuilder::new()
            .port_bind(bind, 8080, 80)
            .port_udp_bind(bind, 5353, 53)
            .build()
            .unwrap();

        assert_eq!(cfg.ports[0].host_bind, bind);
        assert_eq!(cfg.ports[0].host_port, 8080);
        assert_eq!(cfg.ports[0].guest_port, 80);
        assert_eq!(cfg.ports[0].protocol, PortProtocol::Tcp);
        assert_eq!(cfg.ports[1].host_bind, bind);
        assert_eq!(cfg.ports[1].protocol, PortProtocol::Udp);
    }

    #[test]
    fn port_helpers_default_to_loopback() {
        let cfg = NetworkBuilder::new()
            .port(8080, 80)
            .port_udp(5353, 53)
            .build()
            .unwrap();

        assert_eq!(
            cfg.ports[0].host_bind,
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_eq!(cfg.ports[0].protocol, PortProtocol::Tcp);
        assert_eq!(
            cfg.ports[1].host_bind,
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_eq!(cfg.ports[1].protocol, PortProtocol::Udp);
    }

    #[test]
    fn network_builder_sets_global_passthrough_action() {
        let cfg = NetworkBuilder::new()
            .on_secret_violation(|v| {
                v.passthrough_host("api.anthropic.com")
                    .passthrough_host_pattern("*.anthropic.com")
            })
            .build()
            .unwrap();

        assert_eq!(
            cfg.secrets.on_violation,
            ViolationAction::Passthrough(vec![
                HostPattern::Exact("api.anthropic.com".into()),
                HostPattern::Wildcard("*.anthropic.com".into()),
            ])
        );
    }

    #[test]
    fn secret_builder_sets_violation_action() {
        let secret = SecretBuilder::new()
            .env("TOKEN")
            .value("secret-value")
            .allow_host("api.github.com")
            .on_violation(|v| {
                v.passthrough_host("api.anthropic.com")
                    .passthrough_host_pattern("*.anthropic.com")
            })
            .build();

        assert_eq!(
            secret.on_violation,
            Some(ViolationAction::Passthrough(vec![
                HostPattern::Exact("api.anthropic.com".into()),
                HostPattern::Wildcard("*.anthropic.com".into()),
            ])),
        );
    }

    #[test]
    #[should_panic(expected = "SecretBuilder: at least one allowed host is required")]
    fn secret_builder_rejects_empty_allowed_hosts() {
        let _ = SecretBuilder::new()
            .env("TOKEN")
            .value("secret-value")
            .build();
    }

    #[test]
    fn secret_builder_source_yields_reference_and_empty_value() {
        let secret = SecretBuilder::new()
            .env("API_KEY")
            .source(SecretSource::Env {
                var: "HOST_API_KEY".into(),
            })
            .allow_host("api.example.com")
            .build();

        assert!(secret.value.is_empty());
        assert_eq!(
            secret.source,
            Some(SecretSource::Env {
                var: "HOST_API_KEY".into()
            })
        );

        // Serialized durable form carries the reference, not a value.
        let json = serde_json::to_string(&secret).unwrap();
        assert!(json.contains("\"var\":\"HOST_API_KEY\""));
    }

    #[test]
    #[should_panic(expected = "exactly one of .value() or .source()")]
    fn secret_builder_rejects_both_value_and_source() {
        let _ = SecretBuilder::new()
            .env("API_KEY")
            .value("inline")
            .source(SecretSource::Env {
                var: "HOST_API_KEY".into(),
            })
            .allow_host("api.example.com")
            .build();
    }

    #[test]
    fn network_builder_rejects_invalid_secret_config() {
        let err = NetworkBuilder::new()
            .secret_entry(SecretEntry {
                env_var: "API=KEY".into(),
                value: Zeroizing::new("secret-value".into()),
                source: None,
                placeholder: "$MSB_API_KEY".into(),
                allowed_hosts: vec![HostPattern::Exact("api.example.com".into())],
                injection: SecretInjection::default(),
                on_violation: None,
                require_tls_identity: true,
            })
            .build()
            .unwrap_err();

        assert!(err.to_string().contains("env_var must not contain `=`"));
    }

    #[test]
    fn violation_action_builder_blocking_call_replaces_passthrough_policy() {
        let action = ViolationActionBuilder::default()
            .passthrough_host("google.com")
            .block_and_terminate()
            .passthrough_host("facebook.com")
            .build();

        assert_eq!(
            action,
            ViolationAction::Passthrough(vec![HostPattern::Exact("facebook.com".into())])
        );
    }

    #[test]
    fn violation_action_builder_accumulates_passthrough_hosts() {
        let action = ViolationActionBuilder::default()
            .block()
            .passthrough_host("google.com")
            .passthrough_host("facebook.com")
            .build();

        assert_eq!(
            action,
            ViolationAction::Passthrough(vec![
                HostPattern::Exact("google.com".into()),
                HostPattern::Exact("facebook.com".into()),
            ]),
        );
    }
}
