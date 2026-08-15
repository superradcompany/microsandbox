use napi::bindgen_prelude::*;
use napi_derive::napi;

use microsandbox_network::builder::SecretBuilder as RustSecretBuilder;
use microsandbox_network::secrets::config::SecretEntry as RustSecretEntry;

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
    /// Hosts allowed to receive the placeholder unchanged.
    pub passthrough_hosts: Vec<String>,
    /// Require verified TLS identity before substituting (default: true).
    pub require_tls_identity: bool,
    /// Where the secret may be injected into requests.
    pub substitution: JsSecretSubstitution,
}

/// Injection sites for a secret value.
#[derive(Clone)]
#[napi(object, js_name = "SecretSubstitution")]
pub struct JsSecretSubstitution {
    pub headers: bool,
    pub query: bool,
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
    pub fn env(&mut self, env_var: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.env(env_var));
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

    /// Add a host allowed to receive the substituted secret value.
    #[napi]
    pub fn allow(&mut self, host: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.allow(host));
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

    /// Allow a host to receive the unchanged placeholder.
    #[napi(js_name = "allowPassthroughFor")]
    pub fn allow_passthrough_for(&mut self, host: String) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.allow_passthrough_for(host));
        self
    }

    /// Configure header substitution (default: true).
    #[napi(js_name = "substituteInHeaders")]
    pub fn substitute_in_headers(&mut self, enabled: bool) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.substitute_in_headers(enabled));
        self
    }

    /// Configure URL query parameter substitution (default: false).
    #[napi(js_name = "substituteInQuery")]
    pub fn substitute_in_query(&mut self, enabled: bool) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.substitute_in_query(enabled));
        self
    }

    /// Configure request body substitution (default: false).
    #[napi(js_name = "substituteInBody")]
    pub fn substitute_in_body(&mut self, enabled: bool) -> &Self {
        let prev = self.take_inner();
        self.inner = Some(prev.substitute_in_body(enabled));
        self
    }

    /// Configure the blocking action for this secret.
    #[napi(js_name = "violationAction")]
    pub fn violation_action(&mut self, action: String) -> Result<&Self> {
        let action = parse_violation_action(&action)?;
        let prev = self.take_inner();
        self.inner = Some(prev.violation_action(action));
        Ok(self)
    }

    /// Materialize into a `SecretEntry`. Panics if required fields are not
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
            microsandbox_network::secrets::config::HostPattern::Exact(s) => allowed_hosts.push(s),
            microsandbox_network::secrets::config::HostPattern::Wildcard(s) => {
                allowed_host_patterns.push(s)
            }
            microsandbox_network::secrets::config::HostPattern::Any => allow_any_host = true,
        }
    }
    JsSecretEntry {
        env_var: entry.env_var,
        value: entry.value.to_string(),
        placeholder: entry.placeholder,
        allowed_hosts,
        allowed_host_patterns,
        allow_any_host,
        passthrough_hosts: entry
            .passthrough_hosts
            .into_iter()
            .map(host_pattern_string)
            .collect(),
        require_tls_identity: entry.require_tls_identity,
        substitution: JsSecretSubstitution {
            headers: entry.substitution.headers,
            query: entry.substitution.query,
            body: entry.substitution.body,
        },
    }
}

fn host_pattern_string(pattern: microsandbox_network::secrets::config::HostPattern) -> String {
    match pattern {
        microsandbox_network::secrets::config::HostPattern::Exact(value)
        | microsandbox_network::secrets::config::HostPattern::Wildcard(value) => value,
        microsandbox_network::secrets::config::HostPattern::Any => "*".to_string(),
    }
}

pub(crate) fn parse_violation_action(
    action: &str,
) -> Result<microsandbox_network::secrets::config::SecretViolationAction> {
    use microsandbox_network::secrets::config::SecretViolationAction;
    match action {
        "block" => Ok(SecretViolationAction::Block),
        "block-and-log" => Ok(SecretViolationAction::BlockAndLog),
        "block-and-terminate" => Ok(SecretViolationAction::BlockAndTerminate),
        other => Err(napi::Error::from_reason(format!(
            "invalid secret violation action: {other}"
        ))),
    }
}
