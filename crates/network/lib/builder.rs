//! Fluent builder API for [`NetworkConfig`].
//!
//! Used by `SandboxBuilder::network(|n| n.port(8080, 80).policy(...))`.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use ipnetwork::{Ipv4Network, Ipv6Network};
use microsandbox_types::{
    NetworkRateLimitDirection, NetworkRateLimiterConfig, RateLimiterConfig, ScopedUpstreamCaCert,
    ScopedVerifyUpstream, TlsConfig, TokenBucketConfig,
};
use microsandbox_utils::size::Bytes;
use zeroize::Zeroizing;

use crate::config::{
    DnsConfig, InterfaceOverrides, MAX_NETWORK_CONNECTIONS, NetworkConfig, PortProtocol,
    PublishedPort,
};
use crate::dns::Nameserver;
use crate::policy::{BuildError, NetworkPolicy};
use crate::secrets::config::{
    HostPattern, SecretEntry, SecretInjection, SecretSource, ViolationAction,
};

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

/// Fluent builder for both directions of a [`NetworkRateLimiterConfig`].
///
/// ```ignore
/// .rate_limiter(|r| r
///     .egress(|r| r.bandwidth(1.mib(), Duration::from_secs(1)))
///     .ingress(|r| r.ops(1_000, Duration::from_secs(1)))
/// )
/// ```
#[derive(Default)]
pub struct NetworkRateLimiterBuilder {
    config: NetworkRateLimiterConfig,
    errors: Vec<BuildError>,
}

/// Fluent builder for one direction's [`RateLimiterConfig`].
///
/// ```ignore
/// .egress(|r| r
///     .bandwidth(1.mib(), Duration::from_secs(1))
///     .bandwidth_burst(512.kib())
///     .ops(1_000, Duration::from_secs(1))
///     .ops_burst(500)
/// )
/// ```
pub struct RateLimiterBuilder {
    direction: NetworkRateLimitDirection,
    bandwidth: Option<TokenBucketConfig>,
    ops: Option<TokenBucketConfig>,
    bandwidth_burst: Option<u64>,
    ops_burst: Option<u64>,
    /// First bucket whose refill interval cannot be represented on the wire.
    refill_error: Option<(&'static str, RefillTimeError)>,
}

#[derive(Clone, Copy, Debug)]
enum RefillTimeError {
    TooShort,
    Precision,
    TooLong,
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

    /// Configure DNS starting from the current values instead of defaults.
    #[doc(hidden)]
    pub fn dns_overlay(mut self, f: impl FnOnce(DnsBuilder) -> DnsBuilder) -> Self {
        self.config.dns = f(DnsBuilder::from_config(self.config.dns)).build();
        self
    }

    /// Configure TLS interception via a closure.
    pub fn tls(mut self, f: impl FnOnce(TlsBuilder) -> TlsBuilder) -> Self {
        self.config.tls = f(TlsBuilder::new()).build();
        self
    }

    /// Configure TLS interception starting from the current values instead of defaults.
    #[doc(hidden)]
    pub fn tls_overlay(mut self, f: impl FnOnce(TlsBuilder) -> TlsBuilder) -> Self {
        self.config.tls = f(TlsBuilder::from_config(self.config.tls)).build();
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
        if max > MAX_NETWORK_CONNECTIONS {
            self.errors.push(BuildError::MaxConnectionsExceeded {
                configured: max,
                limit: MAX_NETWORK_CONNECTIONS,
            });
        } else {
            self.config.max_connections = Some(max);
        }
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

    /// Configure egress and ingress traffic rate limits. Applies on the next
    /// sandbox start.
    ///
    /// ```ignore
    /// .rate_limiter(|r| r
    ///     .egress(|r| r
    ///         .bandwidth(1.mib(), Duration::from_secs(1))
    ///         .ops(1_000, Duration::from_secs(1)))
    /// )
    /// ```
    pub fn rate_limiter(
        mut self,
        f: impl FnOnce(NetworkRateLimiterBuilder) -> NetworkRateLimiterBuilder,
    ) -> Self {
        match f(NetworkRateLimiterBuilder::new()).build() {
            Ok(limiter) => self.config.rate_limiter = Some(limiter),
            Err(err) => self.errors.push(err),
        }
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
        if let Some(max) = self.config.max_connections
            && max > MAX_NETWORK_CONNECTIONS
        {
            return Err(BuildError::MaxConnectionsExceeded {
                configured: max,
                limit: MAX_NETWORK_CONNECTIONS,
            });
        }
        if self.config.tls.enabled
            && (self.config.tls.intercept_ca.cert_path.is_some()
                != self.config.tls.intercept_ca.key_path.is_some())
        {
            return Err(BuildError::IncompleteInterceptCaConfig);
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

    fn from_config(config: DnsConfig) -> Self {
        Self { config }
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

    fn from_config(config: TlsConfig) -> Self {
        Self { config }
    }

    /// Enable or disable TLS interception while retaining the remaining TLS settings.
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
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
            .unwrap_or_else(|| microsandbox_utils::secret::default_placeholder(&env_var));

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

impl NetworkRateLimiterBuilder {
    fn new() -> Self {
        Self::default()
    }

    /// Limit guest-to-runtime (egress) traffic.
    pub fn egress(mut self, f: impl FnOnce(RateLimiterBuilder) -> RateLimiterBuilder) -> Self {
        match f(RateLimiterBuilder::new(NetworkRateLimitDirection::Egress)).build() {
            Ok(limiter) => self.config.egress = Some(limiter),
            Err(err) => self.errors.push(err),
        }
        self
    }

    /// Limit runtime-to-guest (ingress) traffic.
    pub fn ingress(mut self, f: impl FnOnce(RateLimiterBuilder) -> RateLimiterBuilder) -> Self {
        match f(RateLimiterBuilder::new(NetworkRateLimitDirection::Ingress)).build() {
            Ok(limiter) => self.config.ingress = Some(limiter),
            Err(err) => self.errors.push(err),
        }
        self
    }

    /// Consume the builder and return both configured directions.
    pub fn build(mut self) -> Result<NetworkRateLimiterConfig, BuildError> {
        if let Some(error) = self.errors.drain(..).next() {
            return Err(error);
        }
        if self.config.egress.is_none() && self.config.ingress.is_none() {
            return Err(BuildError::EmptyNetworkRateLimiter);
        }
        Ok(self.config)
    }
}

impl RateLimiterBuilder {
    fn new(direction: NetworkRateLimitDirection) -> Self {
        Self {
            direction,
            bandwidth: None,
            ops: None,
            bandwidth_burst: None,
            ops_burst: None,
            refill_error: None,
        }
    }

    /// Cap bandwidth at `size` bytes per `refill_time`.
    ///
    /// `refill_time` must be at least one millisecond and exactly representable
    /// as a whole number of milliseconds.
    ///
    /// ```ignore
    /// .bandwidth(1.mib(), Duration::from_secs(1))
    /// ```
    pub fn bandwidth(mut self, size: impl Into<Bytes>, refill_time: Duration) -> Self {
        match refill_time_ms(refill_time) {
            Ok(refill_time_ms) => {
                self.bandwidth = Some(TokenBucketConfig {
                    size: size.into().as_u64(),
                    refill_time_ms,
                    one_time_burst: 0,
                });
            }
            Err(error) => {
                self.refill_error.get_or_insert(("bandwidth", error));
            }
        }
        self
    }

    /// Grant a one-time startup burst of `burst` bytes on top of the
    /// bandwidth bucket. Requires [`bandwidth`](Self::bandwidth).
    pub fn bandwidth_burst(mut self, burst: impl Into<Bytes>) -> Self {
        self.bandwidth_burst = Some(burst.into().as_u64());
        self
    }

    /// Cap packet rate at `count` frames per `refill_time`.
    ///
    /// `refill_time` must be at least one millisecond and exactly representable
    /// as a whole number of milliseconds.
    ///
    /// ```ignore
    /// .ops(1_000, Duration::from_secs(1))
    /// ```
    pub fn ops(mut self, count: u64, refill_time: Duration) -> Self {
        match refill_time_ms(refill_time) {
            Ok(refill_time_ms) => {
                self.ops = Some(TokenBucketConfig {
                    size: count,
                    refill_time_ms,
                    one_time_burst: 0,
                });
            }
            Err(error) => {
                self.refill_error.get_or_insert(("ops", error));
            }
        }
        self
    }

    /// Grant a one-time startup burst of `count` frames on top of the ops
    /// bucket. Requires [`ops`](Self::ops).
    pub fn ops_burst(mut self, count: u64) -> Self {
        self.ops_burst = Some(count);
        self
    }

    /// Consume the builder and return the validated configuration.
    pub fn build(self) -> Result<RateLimiterConfig, BuildError> {
        let direction = self.direction;
        if let Some((bucket, error)) = self.refill_error {
            return Err(match error {
                RefillTimeError::TooShort => {
                    BuildError::RateLimitRefillTooShort { direction, bucket }
                }
                RefillTimeError::Precision => {
                    BuildError::RateLimitRefillPrecision { direction, bucket }
                }
                RefillTimeError::TooLong => {
                    BuildError::RateLimitRefillTooLong { direction, bucket }
                }
            });
        }

        let mut config = RateLimiterConfig {
            bandwidth: self.bandwidth,
            ops: self.ops,
        };
        if let Some(burst) = self.bandwidth_burst {
            let Some(bandwidth) = &mut config.bandwidth else {
                return Err(BuildError::RateLimitBurstWithoutBucket {
                    direction,
                    bucket: "bandwidth",
                });
            };
            bandwidth.one_time_burst = burst;
        }
        if let Some(burst) = self.ops_burst {
            let Some(ops) = &mut config.ops else {
                return Err(BuildError::RateLimitBurstWithoutBucket {
                    direction,
                    bucket: "ops",
                });
            };
            ops.one_time_burst = burst;
        }

        config
            .validate()
            .map_err(|source| BuildError::InvalidRateLimitConfig { direction, source })?;
        Ok(config)
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
// Functions
//--------------------------------------------------------------------------------------------------

/// Convert a refill interval to its exact whole-millisecond wire value.
fn refill_time_ms(refill_time: Duration) -> Result<u64, RefillTimeError> {
    if refill_time < Duration::from_millis(1) {
        return Err(RefillTimeError::TooShort);
    }
    let refill_time_ms =
        u64::try_from(refill_time.as_millis()).map_err(|_| RefillTimeError::TooLong)?;
    if !refill_time.subsec_nanos().is_multiple_of(1_000_000) {
        return Err(RefillTimeError::Precision);
    }
    Ok(refill_time_ms)
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
    fn network_builder_rejects_excessive_max_connections() {
        let err = NetworkBuilder::new()
            .max_connections(MAX_NETWORK_CONNECTIONS + 1)
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            BuildError::MaxConnectionsExceeded {
                configured,
                limit: MAX_NETWORK_CONNECTIONS
            } if configured == MAX_NETWORK_CONNECTIONS + 1
        ));
    }

    #[test]
    fn network_builder_rejects_incomplete_intercept_ca_config() {
        let err = NetworkBuilder::new()
            .tls(|t| t.intercept_ca_cert("/tmp/ca.crt"))
            .build()
            .unwrap_err();

        assert!(matches!(err, BuildError::IncompleteInterceptCaConfig));
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
    fn rate_limiter_builder_sets_buckets_and_bursts() {
        use microsandbox_utils::size::SizeExt;

        let cfg = NetworkBuilder::new()
            .rate_limiter(|r| {
                r.egress(|r| {
                    r.bandwidth(1.mib(), Duration::from_secs(1))
                        .bandwidth_burst(512.kib())
                        .ops(1_000, Duration::from_secs(1))
                        .ops_burst(500)
                })
                .ingress(|r| r.bandwidth(2.mib(), Duration::from_millis(500)))
            })
            .build()
            .unwrap();

        let rate_limiter = cfg.rate_limiter.unwrap();
        let egress = rate_limiter.egress.unwrap();
        let bandwidth = egress.bandwidth.unwrap();
        assert_eq!(bandwidth.size, 1024 * 1024);
        assert_eq!(bandwidth.refill_time_ms, 1000);
        assert_eq!(bandwidth.one_time_burst, 512 * 1024);
        let ops = egress.ops.unwrap();
        assert_eq!(ops.size, 1_000);
        assert_eq!(ops.refill_time_ms, 1000);
        assert_eq!(ops.one_time_burst, 500);

        let ingress = rate_limiter.ingress.unwrap();
        assert_eq!(ingress.bandwidth.unwrap().refill_time_ms, 500);
        assert!(ingress.ops.is_none());
    }

    #[test]
    fn rate_limiters_default_to_unlimited() {
        let cfg = NetworkBuilder::new().build().unwrap();
        assert!(cfg.rate_limiter.is_none());
    }

    #[test]
    fn rate_limiter_builder_rejects_empty_limiter() {
        let err = NetworkBuilder::new()
            .rate_limiter(|r| r.egress(|r| r))
            .build()
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "egress rate limiter: rate limiter must configure at least one of bandwidth or ops"
        );
    }

    #[test]
    fn network_rate_limiter_builder_rejects_missing_directions() {
        let err = NetworkBuilder::new()
            .rate_limiter(|r| r)
            .build()
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "rate limiter must configure at least one of egress or ingress"
        );
    }

    #[test]
    fn rate_limiter_builder_rejects_zero_size_and_unrepresentable_refill() {
        let err = NetworkBuilder::new()
            .rate_limiter(|r| r.ingress(|r| r.bandwidth(0u64, Duration::from_secs(1))))
            .build()
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "ingress rate limiter: bandwidth bucket: size must be greater than zero"
        );

        let err = NetworkBuilder::new()
            .rate_limiter(|r| r.egress(|r| r.ops(10, Duration::ZERO)))
            .build()
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "egress rate limiter: ops refill interval must be at least one millisecond"
        );

        let err = NetworkBuilder::new()
            .rate_limiter(|r| r.egress(|r| r.ops(10, Duration::from_micros(1_500))))
            .build()
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "egress rate limiter: ops refill interval must be a whole number of milliseconds"
        );
    }

    #[test]
    fn rate_limiter_builder_rejects_burst_without_bucket() {
        use microsandbox_utils::size::SizeExt;

        let err = NetworkBuilder::new()
            .rate_limiter(|r| r.egress(|r| r.bandwidth_burst(512.kib())))
            .build()
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "egress rate limiter: bandwidth_burst requires the bandwidth bucket"
        );

        let err = NetworkBuilder::new()
            .rate_limiter(|r| {
                r.ingress(|r| r.bandwidth(1.mib(), Duration::from_secs(1)).ops_burst(5))
            })
            .build()
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "ingress rate limiter: ops_burst requires the ops bucket"
        );
    }

    #[test]
    fn rate_limiter_builder_rejects_refill_interval_overflow() {
        let err = NetworkBuilder::new()
            .rate_limiter(|r| r.egress(|r| r.ops(10, Duration::MAX)))
            .build()
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "egress rate limiter: ops refill interval overflows u64 milliseconds"
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
