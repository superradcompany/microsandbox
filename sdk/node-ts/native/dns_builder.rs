use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox_network::builder::DnsBuilder as RustDnsBuilder;
use microsandbox_network::dns::Nameserver;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// DNS interception configuration produced by `DnsBuilder.build()`.
#[derive(Clone)]
#[napi(object, js_name = "DnsConfig")]
pub struct JsDnsConfig {
    pub blocked_domains: Vec<String>,
    pub blocked_suffixes: Vec<String>,
    pub rebind_protection: bool,
    /// Nameservers serialized as their parse-roundtrippable string form
    /// (e.g. `"1.1.1.1:53"`, `"dns.google:53"`).
    pub nameservers: Vec<String>,
    /// Per-query timeout in milliseconds. Default: 5000.
    pub query_timeout_ms: u32,
}

/// Fluent builder for DNS interception settings.
///
/// Mirrors `microsandbox_network::builder::DnsBuilder` 1:1; setters
/// mutate in place and return `this`. Errors from invalid block-domain
/// strings accumulate and surface from the terminal `.build()` call.
#[napi(js_name = "DnsBuilder")]
pub struct JsDnsBuilder {
    inner: Option<RustDnsBuilder>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsDnsBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Some(RustDnsBuilder::new()),
        }
    }

    /// Block a specific FQDN (returns REFUSED at the resolver).
    #[napi(js_name = "blockDomain")]
    pub fn block_domain(&mut self, domain: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.block_domain(domain));
        self
    }

    /// Block any name ending in `suffix`.
    #[napi(js_name = "blockDomainSuffix")]
    pub fn block_domain_suffix(&mut self, suffix: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.block_domain_suffix(suffix));
        self
    }

    /// Enable or disable DNS rebinding protection. Default: true.
    #[napi(js_name = "rebindProtection")]
    pub fn rebind_protection(&mut self, enabled: bool) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.rebind_protection(enabled));
        self
    }

    /// Set the upstream nameservers. Replaces any previous set.
    /// Each entry accepts the same forms as Rust: `"1.1.1.1"`,
    /// `"1.1.1.1:53"`, `"dns.google"`, `"dns.google:53"`.
    #[napi]
    pub fn nameservers(&mut self, servers: Vec<String>) -> Result<&Self> {
        let parsed: std::result::Result<Vec<Nameserver>, _> =
            servers.iter().map(|s| s.parse::<Nameserver>()).collect();
        let parsed =
            parsed.map_err(|e| napi::Error::from_reason(format!("invalid nameserver: {e}")))?;
        let prev = self.take_inner();
        self.inner = Some(prev.nameservers(parsed));
        Ok(self)
    }

    /// Set the per-query timeout in milliseconds. Default: 5000.
    #[napi(js_name = "queryTimeoutMs")]
    pub fn query_timeout_ms(&mut self, ms: u32) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.query_timeout_ms(ms as u64));
        self
    }

    /// Materialize the accumulated state into a `DnsConfig`. Surfaces
    /// the first invalid-domain error accumulated by `blockDomain` /
    /// `blockDomainSuffix`, if any.
    #[napi]
    pub fn build(&mut self) -> Result<JsDnsConfig> {
        let b = self
            .inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("DnsBuilder.build() called more than once"))?;
        let cfg = b
            .build()
            .map_err(|e| napi::Error::from_reason(format!("{e}")))?;
        Ok(JsDnsConfig {
            blocked_domains: cfg.blocked_domains,
            blocked_suffixes: cfg.blocked_suffixes,
            rebind_protection: cfg.rebind_protection,
            nameservers: cfg.nameservers.iter().map(|n| n.to_string()).collect(),
            query_timeout_ms: cfg.query_timeout_ms.try_into().unwrap_or(u32::MAX),
        })
    }
}

impl JsDnsBuilder {
    fn take_inner(&mut self) -> RustDnsBuilder {
        self.inner
            .take()
            .expect("DnsBuilder used after .build() consumed it")
    }
}
