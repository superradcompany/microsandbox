//! Secret injection configuration types.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Configuration for secret injection in a sandbox.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// List of secrets to inject.
    #[serde(default)]
    pub secrets: Vec<SecretEntry>,

    /// Action on secret violation (placeholder leaked to disallowed host).
    #[serde(default)]
    pub on_violation: ViolationAction,
}

/// A single secret entry (serializable form passed to the network engine).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// Environment variable name exposed to the sandbox (holds the placeholder).
    pub env_var: String,

    /// The actual secret value (never enters the sandbox).
    pub value: String,

    /// Placeholder string the sandbox sees instead of the real value.
    pub placeholder: String,

    /// Hosts allowed to receive this secret.
    #[serde(default)]
    pub allowed_hosts: Vec<HostPattern>,

    /// Where the secret can be injected.
    #[serde(default)]
    pub injection: SecretInjection,

    /// Require verified TLS identity before substituting (default: true).
    /// When true, secret is only substituted if the connection uses TLS
    /// interception (not bypass) and the SNI matches an allowed host.
    #[serde(default = "default_true")]
    pub require_tls_identity: bool,
}

/// Host pattern for secret allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostPattern {
    /// Exact hostname match.
    Exact(String),
    /// Wildcard match (e.g., `*.openai.com`).
    Wildcard(String),
    /// Any host (dangerous — secret can be exfiltrated).
    Any,
}

/// Where in the HTTP request the secret can be injected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretInjection {
    /// Substitute in HTTP headers (default: true).
    #[serde(default = "default_true")]
    pub headers: bool,

    /// Substitute in HTTP Basic Auth (default: true).
    #[serde(default = "default_true")]
    pub basic_auth: bool,

    /// Substitute in URL query parameters (default: false).
    #[serde(default)]
    pub query_params: bool,

    /// Substitute in request body (default: false).
    #[serde(default)]
    pub body: bool,
}

/// Action when a secret placeholder is detected going to a disallowed host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum ViolationAction {
    /// Block the request silently.
    Block,
    /// Block and log (default).
    #[default]
    BlockAndLog,
    /// Block and terminate the sandbox.
    BlockAndTerminate,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HostPattern {
    /// Check if a hostname matches this pattern.
    pub fn matches(&self, hostname: &str) -> bool {
        let hostname = hostname.to_lowercase();
        match self {
            HostPattern::Exact(h) => hostname == h.to_lowercase(),
            HostPattern::Wildcard(pattern) => {
                let pattern = pattern.to_lowercase();
                if let Some(suffix) = pattern.strip_prefix("*.") {
                    hostname == suffix || hostname.ends_with(&format!(".{suffix}"))
                } else {
                    hostname == pattern
                }
            }
            HostPattern::Any => true,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for SecretInjection {
    fn default() -> Self {
        Self {
            headers: true,
            basic_auth: true,
            query_params: false,
            body: false,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_host_match() {
        let p = HostPattern::Exact("api.openai.com".into());
        assert!(p.matches("api.openai.com"));
        assert!(p.matches("API.OpenAI.com"));
        assert!(!p.matches("evil.com"));
    }

    #[test]
    fn wildcard_host_match() {
        let p = HostPattern::Wildcard("*.openai.com".into());
        assert!(p.matches("api.openai.com"));
        assert!(p.matches("openai.com"));
        assert!(!p.matches("evil.com"));
    }

    #[test]
    fn any_host_match() {
        let p = HostPattern::Any;
        assert!(p.matches("anything.com"));
    }

    #[test]
    fn default_injection_scopes() {
        let inj = SecretInjection::default();
        assert!(inj.headers);
        assert!(inj.basic_auth);
        assert!(!inj.query_params);
        assert!(!inj.body);
    }

    #[test]
    fn default_require_tls_identity() {
        let entry = SecretEntry {
            env_var: "K".into(),
            value: "v".into(),
            placeholder: "$K".into(),
            allowed_hosts: vec![],
            injection: SecretInjection::default(),
            require_tls_identity: true,
        };
        assert!(entry.require_tls_identity);
    }
}
