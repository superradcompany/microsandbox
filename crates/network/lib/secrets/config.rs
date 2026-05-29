//! Secret injection configuration types.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum supported secret placeholder length in bytes.
pub const MAX_SECRET_PLACEHOLDER_BYTES: usize = 1024;

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
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// Environment variable name exposed to the sandbox (holds the placeholder).
    ///
    /// Must be non-empty and must not contain `=` or NUL. microsandbox does
    /// not require shell-identifier syntax because Linux environment entries
    /// only require a `NAME=value` shape.
    pub env_var: String,

    /// The actual secret value (never enters the sandbox).
    pub value: String,

    /// Placeholder string the sandbox sees instead of the real value.
    ///
    /// Must be non-empty, no longer than 1024 bytes, and must not contain
    /// NUL, CR, or LF.
    pub placeholder: String,

    /// Hosts allowed to receive this secret.
    #[serde(default)]
    pub allowed_hosts: Vec<HostPattern>,

    /// Where the secret can be injected.
    #[serde(default)]
    pub injection: SecretInjection,

    /// Action on secret violation for this secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_violation: Option<ViolationAction>,

    /// Require verified TLS identity before substituting (default: true).
    /// When true, secret is only substituted if the connection uses TLS
    /// interception (not bypass) and the SNI matches an allowed host.
    #[serde(default = "default_true")]
    pub require_tls_identity: bool,
}

/// Host pattern for secret allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostPattern {
    /// Exact hostname match.
    #[serde(alias = "Exact")]
    Exact(String),
    /// Wildcard match (e.g., `*.openai.com`).
    #[serde(alias = "Wildcard")]
    Wildcard(String),
    /// Any host (dangerous — secret can be exfiltrated).
    #[serde(alias = "Any")]
    Any,
}

/// Invalid secret configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretConfigError {
    /// The environment variable name is empty.
    #[error("secret #{secret_index}: env_var must not be empty")]
    EmptyEnvVar {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// The environment variable name contains `=`.
    #[error("secret #{secret_index}: env_var must not contain `=`")]
    EnvVarContainsEquals {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// The environment variable name contains NUL.
    #[error("secret #{secret_index}: env_var must not contain NUL")]
    EnvVarContainsNul {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// No allowed hosts were configured for a secret.
    #[error("secret #{secret_index}: at least one allowed host is required")]
    MissingAllowedHosts {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// The placeholder is empty.
    #[error("secret #{secret_index}: placeholder must not be empty")]
    EmptyPlaceholder {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// The placeholder exceeds the supported byte length.
    #[error(
        "secret #{secret_index}: placeholder must be at most {max_bytes} bytes, got {actual_bytes}"
    )]
    PlaceholderTooLong {
        /// Index of the invalid secret entry.
        secret_index: usize,
        /// Actual placeholder length in bytes.
        actual_bytes: usize,
        /// Maximum supported placeholder length in bytes.
        max_bytes: usize,
    },

    /// The placeholder contains NUL.
    #[error("secret #{secret_index}: placeholder must not contain NUL")]
    PlaceholderContainsNul {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// The placeholder contains a line break.
    #[error("secret #{secret_index}: placeholder must not contain CR or LF")]
    PlaceholderContainsLineBreak {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },
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
    ///
    /// Fixed-length HTTP/1 bodies up to 16 MiB update `Content-Length`;
    /// larger fixed-length bodies are blocked. Chunked HTTP/1 bodies are
    /// decoded and re-encoded with fresh chunk sizes. Encoded bodies pass
    /// through unchanged. HTTP/2 DATA-frame body substitution is not
    /// supported; matching body placeholders are blocked.
    #[serde(default)]
    pub body: bool,
}

/// Action when a secret placeholder is detected going to a disallowed host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ViolationAction {
    /// Block the request silently.
    #[serde(alias = "Block")]
    Block,
    /// Block and log (default).
    #[default]
    #[serde(alias = "BlockAndLog", alias = "block_and_log")]
    BlockAndLog,
    /// Block and terminate the sandbox.
    #[serde(alias = "BlockAndTerminate", alias = "block_and_terminate")]
    BlockAndTerminate,
    /// Forward the request with the placeholder unchanged for matching hosts.
    #[serde(alias = "Passthrough")]
    Passthrough(Vec<HostPattern>),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SecretsConfig {
    /// Validate all configured secret entries.
    pub fn validate(&self) -> Result<(), SecretConfigError> {
        for (index, secret) in self.secrets.iter().enumerate() {
            secret.validate(index)?;
        }
        Ok(())
    }
}

impl SecretEntry {
    /// Validate this secret entry.
    pub fn validate(&self, secret_index: usize) -> Result<(), SecretConfigError> {
        validate_env_var(&self.env_var, secret_index)?;

        if self.allowed_hosts.is_empty() {
            return Err(SecretConfigError::MissingAllowedHosts { secret_index });
        }

        validate_placeholder(&self.placeholder, secret_index)
    }
}

impl std::fmt::Debug for SecretEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretEntry")
            .field("env_var", &self.env_var)
            .field("value", &"[REDACTED]")
            .field("placeholder", &self.placeholder)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("injection", &self.injection)
            .field("on_violation", &self.on_violation)
            .field("require_tls_identity", &self.require_tls_identity)
            .finish()
    }
}

impl HostPattern {
    /// Check if a hostname matches this pattern.
    ///
    /// Uses ASCII case-insensitive comparison to avoid `to_lowercase()`
    /// allocations (DNS hostnames are ASCII per RFC 4343).
    pub fn matches(&self, hostname: &str) -> bool {
        match self {
            HostPattern::Exact(h) => hostname.eq_ignore_ascii_case(h),
            HostPattern::Wildcard(pattern) => {
                if let Some(suffix) = pattern.strip_prefix("*.") {
                    hostname.eq_ignore_ascii_case(suffix)
                        || (hostname.len() > suffix.len() + 1
                            && hostname.as_bytes()[hostname.len() - suffix.len() - 1] == b'.'
                            && hostname[hostname.len() - suffix.len()..]
                                .eq_ignore_ascii_case(suffix))
                } else {
                    hostname.eq_ignore_ascii_case(pattern)
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

fn validate_env_var(env_var: &str, secret_index: usize) -> Result<(), SecretConfigError> {
    if env_var.is_empty() {
        return Err(SecretConfigError::EmptyEnvVar { secret_index });
    }
    if env_var.contains('=') {
        return Err(SecretConfigError::EnvVarContainsEquals { secret_index });
    }
    if env_var.contains('\0') {
        return Err(SecretConfigError::EnvVarContainsNul { secret_index });
    }
    Ok(())
}

fn validate_placeholder(placeholder: &str, secret_index: usize) -> Result<(), SecretConfigError> {
    if placeholder.is_empty() {
        return Err(SecretConfigError::EmptyPlaceholder { secret_index });
    }

    let actual_bytes = placeholder.len();
    if actual_bytes > MAX_SECRET_PLACEHOLDER_BYTES {
        return Err(SecretConfigError::PlaceholderTooLong {
            secret_index,
            actual_bytes,
            max_bytes: MAX_SECRET_PLACEHOLDER_BYTES,
        });
    }

    if placeholder.contains('\0') {
        return Err(SecretConfigError::PlaceholderContainsNul { secret_index });
    }
    if placeholder.contains('\r') || placeholder.contains('\n') {
        return Err(SecretConfigError::PlaceholderContainsLineBreak { secret_index });
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_secret() -> SecretEntry {
        SecretEntry {
            env_var: "API_KEY".into(),
            value: "secret".into(),
            placeholder: "$MSB_API_KEY".into(),
            allowed_hosts: vec![HostPattern::Exact("api.example.com".into())],
            injection: SecretInjection::default(),
            on_violation: None,
            require_tls_identity: true,
        }
    }

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
            on_violation: None,
            require_tls_identity: true,
        };
        assert!(entry.require_tls_identity);
    }

    #[test]
    fn secret_validation_accepts_linux_environment_name_shape() {
        let mut entry = valid_secret();
        entry.env_var = "1TOKEN.with-dashes".into();

        assert!(entry.validate(0).is_ok());
    }

    #[test]
    fn secret_validation_rejects_invalid_env_var_names() {
        let cases = [
            ("", SecretConfigError::EmptyEnvVar { secret_index: 0 }),
            (
                "API=KEY",
                SecretConfigError::EnvVarContainsEquals { secret_index: 0 },
            ),
            (
                "API\0KEY",
                SecretConfigError::EnvVarContainsNul { secret_index: 0 },
            ),
        ];

        for (env_var, expected) in cases {
            let mut entry = valid_secret();
            entry.env_var = env_var.into();
            assert_eq!(entry.validate(0), Err(expected));
        }
    }

    #[test]
    fn secret_validation_rejects_missing_allowed_hosts() {
        let mut entry = valid_secret();
        entry.allowed_hosts.clear();

        assert_eq!(
            entry.validate(0),
            Err(SecretConfigError::MissingAllowedHosts { secret_index: 0 })
        );
    }

    #[test]
    fn secret_validation_rejects_invalid_placeholders() {
        let too_long = "x".repeat(MAX_SECRET_PLACEHOLDER_BYTES + 1);
        let cases = [
            ("", SecretConfigError::EmptyPlaceholder { secret_index: 0 }),
            (
                too_long.as_str(),
                SecretConfigError::PlaceholderTooLong {
                    secret_index: 0,
                    actual_bytes: MAX_SECRET_PLACEHOLDER_BYTES + 1,
                    max_bytes: MAX_SECRET_PLACEHOLDER_BYTES,
                },
            ),
            (
                "abc\0def",
                SecretConfigError::PlaceholderContainsNul { secret_index: 0 },
            ),
            (
                "abc\rdef",
                SecretConfigError::PlaceholderContainsLineBreak { secret_index: 0 },
            ),
            (
                "abc\ndef",
                SecretConfigError::PlaceholderContainsLineBreak { secret_index: 0 },
            ),
        ];

        for (placeholder, expected) in cases {
            let mut entry = valid_secret();
            entry.placeholder = placeholder.into();
            assert_eq!(entry.validate(0), Err(expected));
        }
    }

    #[test]
    fn violation_action_serializes_with_sdk_casing() {
        let action = ViolationAction::Passthrough(vec![
            HostPattern::Exact("api.anthropic.com".into()),
            HostPattern::Wildcard("*.anthropic.com".into()),
            HostPattern::Any,
        ]);

        assert_eq!(
            serde_json::to_string(&action).unwrap(),
            r#"{"passthrough":[{"exact":"api.anthropic.com"},{"wildcard":"*.anthropic.com"},"any"]}"#
        );
        assert_eq!(
            serde_json::to_string(&ViolationAction::BlockAndLog).unwrap(),
            r#""block-and-log""#
        );
        assert_eq!(
            serde_json::to_string(&ViolationAction::BlockAndTerminate).unwrap(),
            r#""block-and-terminate""#
        );
    }

    #[test]
    fn violation_action_accepts_legacy_pascal_case() {
        let action: ViolationAction =
            serde_json::from_str(r#"{"Passthrough":[{"Exact":"api.anthropic.com"}]}"#).unwrap();

        assert_eq!(
            action,
            ViolationAction::Passthrough(vec![HostPattern::Exact("api.anthropic.com".into())])
        );
        assert_eq!(
            serde_json::from_str::<ViolationAction>(r#""BlockAndTerminate""#).unwrap(),
            ViolationAction::BlockAndTerminate
        );
    }
}
