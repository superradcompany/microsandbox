use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox_network::builder::SecretBuilder as RustSecretBuilder;
use microsandbox_network::secrets::config::{HostPattern, SecretEntry as RustSecretEntry};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A secret entry produced by `SecretBuilder.build()`.
#[derive(Clone)]
#[napi(object, js_name = "SecretEntry")]
pub struct JsSecretEntry {
    /// Environment variable name exposed to the sandbox (holds the placeholder).
    pub env_var: String,
    /// Secret value (never enters the sandbox).
    pub value: String,
    /// Placeholder string the sandbox sees instead of the real value.
    pub placeholder: String,
    /// Exact host names allowed to receive this secret.
    pub allowed_hosts: Vec<String>,
    /// Wildcard host patterns (e.g. `*.openai.com`) allowed to receive this secret.
    pub allowed_host_patterns: Vec<String>,
    /// Allow any host. **Dangerous** — secret can be exfiltrated.
    pub allow_any_host: bool,
    /// Require verified TLS identity before substituting (default: true).
    pub require_tls_identity: bool,
    /// Where the secret may be injected into requests.
    pub injection: JsSecretInjection,
}

/// Injection sites for a secret value.
#[derive(Clone)]
#[napi(object, js_name = "SecretInjection")]
pub struct JsSecretInjection {
    pub headers: bool,
    pub basic_auth: bool,
    pub query_params: bool,
    pub body: bool,
}

/// Fluent builder for a single secret entry.
#[napi(js_name = "SecretBuilder")]
pub struct JsSecretBuilder {
    inner: Option<RustSecretBuilder>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[napi]
impl JsSecretBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Some(RustSecretBuilder::new()),
        }
    }

    /// Environment variable to expose the placeholder under (required).
    #[napi]
    pub fn env(&mut self, var: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.env(var));
        self
    }

    /// Secret value (required).
    #[napi]
    pub fn value(&mut self, value: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.value(value));
        self
    }

    /// Custom placeholder. Auto-generated as `$MSB_<env>` when unset.
    #[napi]
    pub fn placeholder(&mut self, placeholder: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.placeholder(placeholder));
        self
    }

    /// Add an allowed exact-match host.
    #[napi(js_name = "allowHost")]
    pub fn allow_host(&mut self, host: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.allow_host(host));
        self
    }

    /// Add an allowed wildcard host pattern (e.g. `*.openai.com`).
    #[napi(js_name = "allowHostPattern")]
    pub fn allow_host_pattern(&mut self, pattern: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.allow_host_pattern(pattern));
        self
    }

    /// Allow any host. **Dangerous** — secret can be exfiltrated.
    /// Pass `true` to opt in.
    #[napi(js_name = "allowAnyHostDangerous")]
    pub fn allow_any_host_dangerous(&mut self, i_understand: bool) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.allow_any_host_dangerous(i_understand));
        self
    }

    /// Require verified TLS identity before substituting (default: true).
    #[napi(js_name = "requireTlsIdentity")]
    pub fn require_tls_identity(&mut self, enabled: bool) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.require_tls_identity(enabled));
        self
    }

    /// Configure header injection (default: true).
    #[napi(js_name = "injectHeaders")]
    pub fn inject_headers(&mut self, enabled: bool) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.inject_headers(enabled));
        self
    }

    /// Configure Basic Auth injection (default: true).
    #[napi(js_name = "injectBasicAuth")]
    pub fn inject_basic_auth(&mut self, enabled: bool) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.inject_basic_auth(enabled));
        self
    }

    /// Configure URL query parameter injection (default: false).
    #[napi(js_name = "injectQuery")]
    pub fn inject_query(&mut self, enabled: bool) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.inject_query(enabled));
        self
    }

    /// Configure request body injection (default: false).
    #[napi(js_name = "injectBody")]
    pub fn inject_body(&mut self, enabled: bool) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.inject_body(enabled));
        self
    }

    /// Materialize into a `SecretEntry`. Panics if `env` or `value` weren't
    /// set (matches the underlying Rust builder's contract; surface as a
    /// typed error here).
    #[napi]
    pub fn build(&mut self) -> Result<JsSecretEntry> {
        let entry = self.take_built()?;
        Ok(to_js_secret_entry(entry))
    }
}

impl JsSecretBuilder {
    fn take_inner(&mut self) -> RustSecretBuilder {
        self.inner
            .take()
            .expect("SecretBuilder used after .build() consumed it")
    }

    /// Internal: extract the underlying Rust builder. Used by
    /// `NetworkBuilder.secret()` to route through the core SDK closure.
    #[allow(dead_code)]
    pub(crate) fn take_inner_builder(&mut self) -> Result<RustSecretBuilder> {
        self.inner
            .take()
            .ok_or_else(|| napi::Error::from_reason("SecretBuilder already consumed"))
    }

    /// Internal: extract the built `SecretEntry`. Used by parent builders.
    #[allow(dead_code)]
    pub(crate) fn take_built(&mut self) -> Result<RustSecretEntry> {
        let b = self.inner.take().ok_or_else(|| {
            napi::Error::from_reason("SecretBuilder.build() called more than once")
        })?;
        // Rust .build() panics if env/value missing; catch via unwind so
        // we can surface a typed error instead of crashing the process.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| b.build())).map_err(|p| {
            let msg = if let Some(s) = p.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = p.downcast_ref::<String>() {
                s.clone()
            } else {
                "SecretBuilder: missing required field".to_string()
            };
            napi::Error::from_reason(msg)
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn to_js_secret_entry(entry: RustSecretEntry) -> JsSecretEntry {
    let mut allowed_hosts = Vec::new();
    let mut allowed_host_patterns = Vec::new();
    let mut allow_any_host = false;
    for h in entry.allowed_hosts {
        match h {
            HostPattern::Exact(s) => allowed_hosts.push(s),
            HostPattern::Wildcard(s) => allowed_host_patterns.push(s),
            HostPattern::Any => allow_any_host = true,
        }
    }
    JsSecretEntry {
        env_var: entry.env_var,
        value: entry.value,
        placeholder: entry.placeholder,
        allowed_hosts,
        allowed_host_patterns,
        allow_any_host,
        require_tls_identity: entry.require_tls_identity,
        injection: JsSecretInjection {
            headers: entry.injection.headers,
            basic_auth: entry.injection.basic_auth,
            query_params: entry.injection.query_params,
            body: entry.injection.body,
        },
    }
}
