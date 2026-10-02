//! Cloud secret-substitution wire contracts and domain conversions.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::compat;
use crate::domain::{
    HostPattern, SecretEntry, SecretSubstitution, SecretViolationAction, SecretsConfig,
};
use crate::modify::SecretSource;

//--------------------------------------------------------------------------------------------------
// Types: Secrets
//--------------------------------------------------------------------------------------------------

/// Secret-substitution config for the cloud API. Twin of domain [`SecretsConfig`].
#[derive(Debug, Clone, Default, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSecretsConfig {
    /// Secrets to inject.
    #[serde(default)]
    pub entries: Vec<CloudSecretEntry>,
    /// Default placeholder passthrough hosts, including for secrets added later.
    /// A per-secret violation action overrides this default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passthrough_hosts: Option<Vec<CloudHostPattern>>,
    /// Default action when a placeholder leaks to a disallowed host.
    #[serde(default)]
    pub violation_action: CloudViolationAction,
}

/// A single cloud secret entry. Twin of domain [`SecretEntry`].
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSecretEntry {
    /// Environment variable name exposed to the sandbox.
    pub env_var: String,
    /// The secret value (empty when `source` carries a reference instead).
    #[serde(default)]
    pub value: String,
    /// Host-side source resolved into `value` at spawn time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<CloudSecretSource>,
    /// Placeholder the sandbox sees instead of the real value.
    pub placeholder: String,
    /// Hosts allowed to receive this secret.
    #[serde(default)]
    pub allowed_hosts: Vec<CloudHostPattern>,
    /// Where the secret may be injected.
    #[serde(default)]
    pub substitution: SecretSubstitution,
    /// Hosts allowed to receive the placeholder unchanged.
    #[serde(default)]
    pub passthrough_hosts: Vec<CloudHostPattern>,
    /// Per-secret violation action overriding the config default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub violation_action: Option<CloudViolationAction>,
    /// Require verified TLS identity before substituting (default: true).
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(default = true))]
    pub require_tls_identity: bool,
}

/// Host-side source for a cloud secret. Twin of [`SecretSource`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CloudSecretSource {
    /// Read from a host environment variable at apply time.
    Env {
        /// Host environment variable name.
        var: String,
    },
    /// Read from a host-side secret store reference.
    Store {
        /// Store-specific secret reference.
        reference: String,
    },
}

/// Host allowlist pattern for cloud secrets. Twin of [`HostPattern`], with the
/// domain's scalar variants normalized to `{ value }` for a uniform union.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CloudHostPattern {
    /// Exact hostname match.
    Exact {
        /// Hostname to match exactly.
        value: String,
    },
    /// Wildcard match (e.g. `*.openai.com`).
    Wildcard {
        /// Wildcard pattern.
        value: String,
    },
    /// Any host (dangerous — the secret can be exfiltrated).
    Any,
}

/// Action on a cloud secret violation. Twin of [`SecretViolationAction`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CloudViolationAction {
    /// Block the request silently.
    Block,
    /// Block and log (default).
    #[default]
    BlockAndLog,
    /// Block and terminate the sandbox.
    BlockAndTerminate,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<'de> Deserialize<'de> for CloudSecretsConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        compat::cloud::deserialize_secrets_config(deserializer)
    }
}

impl<'de> Deserialize<'de> for CloudSecretEntry {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        compat::cloud::deserialize_secret_entry(deserializer)
    }
}

//--------------------------------------------------------------------------------------------------
// Conversions: Secrets
//--------------------------------------------------------------------------------------------------

impl From<HostPattern> for CloudHostPattern {
    fn from(pattern: HostPattern) -> Self {
        match pattern {
            HostPattern::Exact(value) => Self::Exact { value },
            HostPattern::Wildcard(value) => Self::Wildcard { value },
            HostPattern::Any => Self::Any,
        }
    }
}

impl From<CloudHostPattern> for HostPattern {
    fn from(pattern: CloudHostPattern) -> Self {
        match pattern {
            CloudHostPattern::Exact { value } => Self::Exact(value),
            CloudHostPattern::Wildcard { value } => Self::Wildcard(value),
            CloudHostPattern::Any => Self::Any,
        }
    }
}

impl From<SecretViolationAction> for CloudViolationAction {
    fn from(action: SecretViolationAction) -> Self {
        match action {
            SecretViolationAction::Block => Self::Block,
            SecretViolationAction::BlockAndLog => Self::BlockAndLog,
            SecretViolationAction::BlockAndTerminate => Self::BlockAndTerminate,
        }
    }
}

impl From<CloudViolationAction> for SecretViolationAction {
    fn from(action: CloudViolationAction) -> Self {
        match action {
            CloudViolationAction::Block => Self::Block,
            CloudViolationAction::BlockAndLog => Self::BlockAndLog,
            CloudViolationAction::BlockAndTerminate => Self::BlockAndTerminate,
        }
    }
}

impl From<SecretSource> for CloudSecretSource {
    fn from(source: SecretSource) -> Self {
        match source {
            SecretSource::Env { var } => Self::Env { var },
            SecretSource::Store { reference } => Self::Store { reference },
        }
    }
}

impl From<CloudSecretSource> for SecretSource {
    fn from(source: CloudSecretSource) -> Self {
        match source {
            CloudSecretSource::Env { var } => Self::Env { var },
            CloudSecretSource::Store { reference } => Self::Store { reference },
        }
    }
}

impl From<SecretEntry> for CloudSecretEntry {
    fn from(entry: SecretEntry) -> Self {
        Self {
            env_var: entry.env_var,
            value: entry.value.to_string(),
            source: entry.source.map(Into::into),
            placeholder: entry.placeholder,
            allowed_hosts: entry.allowed_hosts.into_iter().map(Into::into).collect(),
            substitution: entry.substitution,
            passthrough_hosts: entry
                .passthrough_hosts
                .into_iter()
                .map(Into::into)
                .collect(),
            violation_action: entry.violation_action.map(Into::into),
            require_tls_identity: entry.require_tls_identity,
        }
    }
}

impl From<CloudSecretEntry> for SecretEntry {
    fn from(entry: CloudSecretEntry) -> Self {
        Self {
            env_var: entry.env_var,
            value: Zeroizing::new(entry.value),
            source: entry.source.map(Into::into),
            placeholder: entry.placeholder,
            allowed_hosts: entry.allowed_hosts.into_iter().map(Into::into).collect(),
            substitution: entry.substitution,
            passthrough_hosts: entry
                .passthrough_hosts
                .into_iter()
                .map(Into::into)
                .collect(),
            violation_action: entry.violation_action.map(Into::into),
            require_tls_identity: entry.require_tls_identity,
        }
    }
}

impl From<SecretsConfig> for CloudSecretsConfig {
    fn from(config: SecretsConfig) -> Self {
        Self {
            entries: config.secrets.into_iter().map(Into::into).collect(),
            passthrough_hosts: config
                .passthrough_hosts
                .map(|hosts| hosts.into_iter().map(Into::into).collect()),
            violation_action: config.violation_action.into(),
        }
    }
}

impl From<CloudSecretsConfig> for SecretsConfig {
    fn from(config: CloudSecretsConfig) -> Self {
        Self {
            secrets: config.entries.into_iter().map(Into::into).collect(),
            passthrough_hosts: config
                .passthrough_hosts
                .map(|hosts| hosts.into_iter().map(Into::into).collect()),
            violation_action: config.violation_action.into(),
        }
    }
}
