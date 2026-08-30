//! Engine-specific queries over the shared secrets configuration model.

use crate::secrets::config::{HostPattern, SecretsConfig};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Queries that decide whether the plain-HTTP proxy must inspect headers.
pub(crate) trait SecretsConfigExt {
    /// Whether any secret can be substituted over plain HTTP.
    fn has_plain_http_candidates(&self) -> bool;

    /// Whether any secret restricts itself to specific hosts.
    fn has_host_scoped_secrets(&self) -> bool;
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl SecretsConfigExt for SecretsConfig {
    fn has_plain_http_candidates(&self) -> bool {
        self.secrets.iter().any(|secret| {
            !secret.require_tls_identity
                && (secret.injection.headers
                    || secret.injection.basic_auth
                    || secret.injection.query_params
                    || secret.injection.body)
        })
    }

    fn has_host_scoped_secrets(&self) -> bool {
        self.secrets.iter().any(|secret| {
            secret
                .allowed_hosts
                .iter()
                .any(|host| *host != HostPattern::Any)
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::secrets::config::{
        HostPattern, SecretEntry, SecretInjection, SecretsConfig, ViolationAction,
    };

    use super::SecretsConfigExt;

    fn secret(require_tls_identity: bool, hosts: Vec<HostPattern>) -> SecretEntry {
        SecretEntry {
            env_var: "API_KEY".into(),
            value: zeroize::Zeroizing::new("secret".into()),
            source: None,
            placeholder: "$MSB_API_KEY".into(),
            allowed_hosts: hosts,
            injection: SecretInjection::default(),
            on_violation: None,
            require_tls_identity,
        }
    }

    #[test]
    fn plain_http_candidates_require_tls_opt_out() {
        let tls_only = SecretsConfig {
            secrets: vec![secret(true, vec![HostPattern::Any])],
            on_violation: ViolationAction::default(),
        };
        assert!(!tls_only.has_plain_http_candidates());

        let plain = SecretsConfig {
            secrets: vec![secret(false, vec![HostPattern::Any])],
            on_violation: ViolationAction::default(),
        };
        assert!(plain.has_plain_http_candidates());
    }

    #[test]
    fn host_scoped_detects_non_any_pattern() {
        let any = SecretsConfig {
            secrets: vec![secret(true, vec![HostPattern::Any])],
            on_violation: ViolationAction::default(),
        };
        assert!(!any.has_host_scoped_secrets());

        let scoped = SecretsConfig {
            secrets: vec![secret(
                true,
                vec![HostPattern::Exact("api.example.com".into())],
            )],
            on_violation: ViolationAction::default(),
        };
        assert!(scoped.has_host_scoped_secrets());
    }
}
