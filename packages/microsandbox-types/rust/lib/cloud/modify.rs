//! Cloud sandbox-modification wire contracts.
//!
//! Plan requests are value-free; only the apply request carries plaintext,
//! inside [`CloudSecretValue`]. The server decides which changes it supports.

use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroizing;

use super::{CloudHostPattern, CloudViolationAction};
use crate::domain::{HostPattern, SecretConfigError, SecretEntry, SecretSubstitution};
use crate::modify::{
    ModificationPolicy, SandboxModificationPatch, SecretModificationPatch, SecretSource,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Error code: another modification of the sandbox holds its lock (409).
pub const CLOUD_MODIFICATION_IN_PROGRESS: &str = "modification_in_progress";

/// Error code: the plan cannot be applied; the message says why (409).
pub const CLOUD_MODIFICATION_REFUSED: &str = "modification_refused";

/// Error code: the server cannot modify this sandbox, or does not modify sandboxes (409).
pub const CLOUD_MODIFICATION_UNSUPPORTED: &str = "modification_unsupported";

/// Error code: the change did not complete as asked; it may be saved but not in effect, or
/// its result is unknown (503).
pub const CLOUD_MODIFICATION_NOT_CONFIRMED: &str = "modification_not_confirmed";

//--------------------------------------------------------------------------------------------------
// Types: Requests
//--------------------------------------------------------------------------------------------------

/// Request body for a Cloud modification dry run. It never carries a secret value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct CloudSandboxModificationPlanRequest {
    /// Policy the plan is classified under.
    #[serde(default)]
    pub policy: ModificationPolicy,
    /// Secret changes, in patch order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<CloudSecretPlanEntry>,
    /// Names of secrets to remove.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets_remove: Vec<String>,
}

/// A value-free change to one secret, the plan request's entry. Its apply
/// counterpart is [`CloudSecretApplyEntry`].
///
/// A `None` field keeps the current setting (the create default for a new
/// secret) and is omitted from the JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct CloudSecretPlanEntry {
    /// Name of the secret, the env var it is exposed as.
    pub name: String,
    /// New secret material: provided when the secret is added or rotated, absent for a
    /// metadata-only change.
    pub material: CloudSecretMaterial,
    /// New guest-visible placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// New hosts allowed to receive the secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_hosts: Option<Vec<CloudHostPattern>>,
    /// New substitution locations.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_strict_substitution"
    )]
    pub substitution: Option<SecretSubstitution>,
    /// New hosts allowed to receive the placeholder unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passthrough_hosts: Option<Vec<CloudHostPattern>>,
    /// New per-secret violation action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub violation_action: Option<CloudViolationAction>,
    /// New verified-TLS-identity requirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_tls_identity: Option<bool>,
}

/// Presence of new secret material in a change. It carries nothing derived
/// from the value, such as a hash, length, or source name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CloudSecretMaterial {
    /// New material is supplied, so the secret is added or rotated.
    Provided,
    /// No material is supplied; only metadata changes.
    Absent,
}

/// Body of a Cloud modification apply.
///
/// `Debug` redacts the secret value through [`CloudSecretValue`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct CloudSandboxModificationApplyRequest {
    /// Policy the change is applied under.
    #[serde(default)]
    pub policy: ModificationPolicy,
    /// Secret changes, in patch order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<CloudSecretApplyEntry>,
    /// Names of secrets to remove.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets_remove: Vec<String>,
}

/// A change to one secret, with its new value when the secret is added or rotated,
/// the apply request's entry. Its value-free plan counterpart is
/// [`CloudSecretPlanEntry`].
///
/// A `None` field keeps the current setting (the create default for a new
/// secret) and is omitted from the JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct CloudSecretApplyEntry {
    /// Name of the secret, the env var it is exposed as.
    pub name: String,
    /// New secret value. Present when the secret is added or rotated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<CloudSecretValue>,
    /// New guest-visible placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// New hosts allowed to receive the secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_hosts: Option<Vec<CloudHostPattern>>,
    /// New substitution locations.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_strict_substitution"
    )]
    pub substitution: Option<SecretSubstitution>,
    /// New hosts allowed to receive the placeholder unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passthrough_hosts: Option<Vec<CloudHostPattern>>,
    /// New per-secret violation action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub violation_action: Option<CloudViolationAction>,
    /// New verified-TLS-identity requirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_tls_identity: Option<bool>,
}

/// Secret plaintext carried by an apply request.
///
/// Zeroized on drop, redacted by `Debug`, and without `Display`. Serializes as
/// a plain string because the apply body carries it.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "utoipa", schema(value_type = String))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSecretValue(#[cfg_attr(feature = "ts", ts(type = "string"))] Zeroizing<String>);

/// [`SecretSubstitution`] as a modification request reads it. Unknown fields
/// are refused, so a misspelled restriction such as `header_field` cannot
/// fall back to the default and widen where the secret is substituted.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct StrictSecretSubstitution {
    headers: bool,
    header_fields: Vec<String>,
    query: bool,
    body: bool,
}

//--------------------------------------------------------------------------------------------------
// Types: Rejection
//--------------------------------------------------------------------------------------------------

/// Reason a modification patch cannot be sent as a Cloud request.
///
/// Each variant names the offending field so nothing is dropped silently.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CloudModificationRejection {
    /// The patch sets a field other than a secret.
    #[error("{field}: cloud modification supports only secret changes")]
    UnsupportedField {
        /// Offending field.
        field: &'static str,
    },

    /// The secret name is blank.
    #[error("{field}: secret name must not be blank")]
    BlankName {
        /// Offending field.
        field: &'static str,
    },

    /// The secret name breaks the rules create applies to it.
    #[error("{field}: {reason}")]
    InvalidName {
        /// Offending field.
        field: &'static str,
        /// The create rule it breaks. The reason's `secret_index` is the
        /// entry's position in `secrets`.
        reason: SecretConfigError,
    },

    /// The new secret value is empty.
    #[error("{field}: secret value must not be empty")]
    EmptyValue {
        /// Offending field.
        field: &'static str,
    },

    /// The host environment variable a source names is not set, or is not UTF-8.
    #[error("{field}: host environment variable {var} is not set")]
    UnresolvedSource {
        /// Offending field.
        field: &'static str,
        /// The variable the source names.
        var: String,
    },

    /// Both a value and a source were supplied.
    #[error("{field}: supply a secret value or a source, not both")]
    ValueAndSource {
        /// Offending field.
        field: &'static str,
    },

    /// The source is a host secret-store reference, which only a local host
    /// can resolve.
    #[error("{field}: a secret-store source can only be resolved by a local host")]
    StoreSource {
        /// Offending field.
        field: &'static str,
    },

    /// The placeholder breaks the rules create applies to it. An empty
    /// placeholder is refused here, so a placeholder cannot be removed.
    #[error("{field}: {reason}")]
    InvalidPlaceholder {
        /// Offending field.
        field: &'static str,
        /// The create rule it breaks. The reason's `secret_index` is the
        /// entry's position in `secrets`.
        reason: SecretConfigError,
    },
}

//--------------------------------------------------------------------------------------------------
// Types: Projection
//--------------------------------------------------------------------------------------------------

/// A patch a Cloud request can express: each secret with its metadata, and
/// the names to remove.
struct ProjectedPatch<'a> {
    secrets: Vec<(&'a SecretModificationPatch, SecretMetadata)>,
    secrets_remove: Vec<String>,
}

/// Metadata shared by the plan entry and the apply entry.
struct SecretMetadata {
    placeholder: Option<String>,
    allowed_hosts: Option<Vec<CloudHostPattern>>,
    substitution: Option<SecretSubstitution>,
    passthrough_hosts: Option<Vec<CloudHostPattern>>,
    violation_action: Option<CloudViolationAction>,
    require_tls_identity: Option<bool>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CloudSandboxModificationPlanRequest {
    /// Build the dry-run request from a patch.
    ///
    /// An inline value or `Env` source becomes [`CloudSecretMaterial::Provided`]
    /// without being read. Host strings parse as they do for create.
    pub fn from_patch(
        patch: &SandboxModificationPatch,
        policy: ModificationPolicy,
    ) -> Result<Self, CloudModificationRejection> {
        let projected = project_secrets(patch)?;
        let secrets = projected
            .secrets
            .into_iter()
            .map(|(spec, metadata)| {
                let material = if spec.value.is_empty() && spec.source.is_none() {
                    CloudSecretMaterial::Absent
                } else {
                    CloudSecretMaterial::Provided
                };
                metadata.into_plan_entry(spec.name.clone(), material)
            })
            .collect();

        Ok(Self {
            policy,
            secrets,
            secrets_remove: projected.secrets_remove,
        })
    }

    /// Check a deserialized request with the name and placeholder rules of
    /// [`Self::from_patch`]. Host patterns are accepted as create accepts them.
    pub fn validate(&self) -> Result<(), CloudModificationRejection> {
        for (index, secret) in self.secrets.iter().enumerate() {
            check_name("secrets.name", &secret.name, index)?;
            check_placeholder("secrets.placeholder", secret.placeholder.as_deref(), index)?;
        }
        Ok(())
    }
}

impl CloudSandboxModificationApplyRequest {
    /// Build the apply request from a patch.
    ///
    /// An inline value is carried as is. Each `Env` source is resolved by one
    /// call to `resolve_env`, so this crate never reads the environment.
    /// Refuses what [`CloudSandboxModificationPlanRequest::from_patch`] refuses,
    /// plus an empty or unresolved value.
    pub fn from_patch(
        patch: &SandboxModificationPatch,
        policy: ModificationPolicy,
        mut resolve_env: impl FnMut(&str) -> Option<CloudSecretValue>,
    ) -> Result<Self, CloudModificationRejection> {
        let projected = project_secrets(patch)?;
        let mut secrets = Vec::with_capacity(projected.secrets.len());
        for (spec, metadata) in projected.secrets {
            let value = match &spec.source {
                Some(SecretSource::Env { var }) => match resolve_env(var) {
                    Some(value) if !value.is_empty() => Some(value),
                    Some(_) => {
                        return Err(CloudModificationRejection::EmptyValue {
                            field: "secrets.source",
                        });
                    }
                    None => {
                        return Err(CloudModificationRejection::UnresolvedSource {
                            field: "secrets.source",
                            var: var.clone(),
                        });
                    }
                },
                _ if spec.value.is_empty() => None,
                _ => Some(CloudSecretValue(spec.value.clone())),
            };
            secrets.push(metadata.into_apply_entry(spec.name.clone(), value));
        }

        Ok(Self {
            policy,
            secrets,
            secrets_remove: projected.secrets_remove,
        })
    }

    /// Check a deserialized request with the name, placeholder, and value rules
    /// of [`Self::from_patch`]. Host patterns are accepted as create accepts them.
    pub fn validate(&self) -> Result<(), CloudModificationRejection> {
        for (index, secret) in self.secrets.iter().enumerate() {
            check_name("secrets.name", &secret.name, index)?;
            check_placeholder("secrets.placeholder", secret.placeholder.as_deref(), index)?;
            if secret
                .value
                .as_ref()
                .is_some_and(CloudSecretValue::is_empty)
            {
                return Err(CloudModificationRejection::EmptyValue {
                    field: "secrets.value",
                });
            }
        }
        Ok(())
    }
}

impl CloudSecretValue {
    /// Wrap secret plaintext.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The plaintext. Keep it out of logs and error messages.
    pub fn expose(&self) -> &str {
        &self.0
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl SecretMetadata {
    fn into_plan_entry(self, name: String, material: CloudSecretMaterial) -> CloudSecretPlanEntry {
        CloudSecretPlanEntry {
            name,
            material,
            placeholder: self.placeholder,
            allowed_hosts: self.allowed_hosts,
            substitution: self.substitution,
            passthrough_hosts: self.passthrough_hosts,
            violation_action: self.violation_action,
            require_tls_identity: self.require_tls_identity,
        }
    }

    fn into_apply_entry(
        self,
        name: String,
        value: Option<CloudSecretValue>,
    ) -> CloudSecretApplyEntry {
        CloudSecretApplyEntry {
            name,
            value,
            placeholder: self.placeholder,
            allowed_hosts: self.allowed_hosts,
            substitution: self.substitution,
            passthrough_hosts: self.passthrough_hosts,
            violation_action: self.violation_action,
            require_tls_identity: self.require_tls_identity,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for CloudSecretValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl From<Zeroizing<String>> for CloudSecretValue {
    fn from(value: Zeroizing<String>) -> Self {
        Self(value)
    }
}

/// Defaults come from [`SecretSubstitution`], so an omitted field means what
/// it means at create.
impl Default for StrictSecretSubstitution {
    fn default() -> Self {
        let SecretSubstitution {
            headers,
            header_fields,
            query,
            body,
        } = SecretSubstitution::default();
        Self {
            headers,
            header_fields,
            query,
            body,
        }
    }
}

impl From<StrictSecretSubstitution> for SecretSubstitution {
    fn from(strict: StrictSecretSubstitution) -> Self {
        let StrictSecretSubstitution {
            headers,
            header_fields,
            query,
            body,
        } = strict;
        Self {
            headers,
            header_fields,
            query,
            body,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Refuse any patch a Cloud request cannot express, then extract each secret's
/// metadata. The caller handles material, which differs for dry run and apply.
///
/// The destructuring names every field, so a field added to the patch fails
/// to compile here until it is refused or carried.
fn project_secrets(
    patch: &SandboxModificationPatch,
) -> Result<ProjectedPatch<'_>, CloudModificationRejection> {
    let unsupported = |field| Err(CloudModificationRejection::UnsupportedField { field });
    let SandboxModificationPatch {
        cpus,
        max_cpus,
        memory_mib,
        max_memory_mib,
        root_disk_size_mib,
        env,
        env_remove,
        labels,
        labels_remove,
        ports,
        ports_remove,
        workdir,
        secrets,
        secrets_remove,
    } = patch;

    if cpus.is_some() {
        return unsupported("cpus");
    }
    if max_cpus.is_some() {
        return unsupported("max_cpus");
    }
    if memory_mib.is_some() {
        return unsupported("memory_mib");
    }
    if max_memory_mib.is_some() {
        return unsupported("max_memory_mib");
    }
    if root_disk_size_mib.is_some() {
        return unsupported("root_disk_size_mib");
    }
    if !env.is_empty() {
        return unsupported("env");
    }
    if !env_remove.is_empty() {
        return unsupported("env_remove");
    }
    if !labels.is_empty() {
        return unsupported("labels");
    }
    if !labels_remove.is_empty() {
        return unsupported("labels_remove");
    }
    if !ports.is_empty() {
        return unsupported("ports");
    }
    if !ports_remove.is_empty() {
        return unsupported("ports_remove");
    }
    if workdir.is_some() {
        return unsupported("workdir");
    }

    let secrets = secrets
        .iter()
        .enumerate()
        .map(|(index, spec)| Ok((spec, project_secret(spec, index)?)))
        .collect::<Result<_, _>>()?;
    Ok(ProjectedPatch {
        secrets,
        secrets_remove: secrets_remove.clone(),
    })
}

/// Check one secret entry, at `index` in `secrets`, and extract its metadata.
fn project_secret(
    spec: &SecretModificationPatch,
    index: usize,
) -> Result<SecretMetadata, CloudModificationRejection> {
    let SecretModificationPatch {
        name,
        source,
        value,
        placeholder,
        allowed_hosts,
        substitution,
        passthrough_hosts,
        violation_action,
        require_tls_identity,
    } = spec;

    check_name("secrets.name", name, index)?;
    match source {
        Some(_) if !value.is_empty() => {
            return Err(CloudModificationRejection::ValueAndSource {
                field: "secrets.value",
            });
        }
        Some(SecretSource::Store { .. }) => {
            return Err(CloudModificationRejection::StoreSource {
                field: "secrets.source",
            });
        }
        Some(SecretSource::Env { .. }) | None => {}
    }
    check_placeholder("secrets.placeholder", placeholder.as_deref(), index)?;

    Ok(SecretMetadata {
        placeholder: placeholder.clone(),
        allowed_hosts: parse_hosts(allowed_hosts),
        substitution: substitution.clone(),
        passthrough_hosts: parse_hosts(passthrough_hosts),
        violation_action: violation_action.clone().map(Into::into),
        require_tls_identity: *require_tls_identity,
    })
}

/// Parse host strings as create does. An empty list means "unchanged".
fn parse_hosts(hosts: &[String]) -> Option<Vec<CloudHostPattern>> {
    (!hosts.is_empty()).then(|| {
        hosts
            .iter()
            .map(|host| HostPattern::parse(host).into())
            .collect()
    })
}

/// A name must not be blank, and must pass create's env-var rules.
fn check_name(
    field: &'static str,
    name: &str,
    index: usize,
) -> Result<(), CloudModificationRejection> {
    if name.trim().is_empty() {
        return Err(CloudModificationRejection::BlankName { field });
    }
    create_rules(name, "$MSB_SECRET", index)
        .map_err(|reason| CloudModificationRejection::InvalidName { field, reason })
}

/// A supplied placeholder must pass create's placeholder rules.
fn check_placeholder(
    field: &'static str,
    placeholder: Option<&str>,
    index: usize,
) -> Result<(), CloudModificationRejection> {
    let Some(placeholder) = placeholder else {
        return Ok(());
    };
    create_rules("MSB_SECRET", placeholder, index)
        .map_err(|reason| CloudModificationRejection::InvalidPlaceholder { field, reason })
}

/// Create's own entry check, applied to a name and a placeholder. Every other
/// field of the checked entry is valid, so only these two can fail it.
fn create_rules(name: &str, placeholder: &str, index: usize) -> Result<(), SecretConfigError> {
    SecretEntry {
        env_var: name.to_string(),
        value: Zeroizing::default(),
        source: None,
        placeholder: placeholder.to_string(),
        allowed_hosts: vec![HostPattern::Any],
        substitution: SecretSubstitution::default(),
        passthrough_hosts: Vec::new(),
        violation_action: None,
        require_tls_identity: true,
    }
    .validate(index)
}

fn deserialize_strict_substitution<'de, D>(
    deserializer: D,
) -> Result<Option<SecretSubstitution>, D::Error>
where
    D: Deserializer<'de>,
{
    let strict = Option::<StrictSecretSubstitution>::deserialize(deserializer)?;
    Ok(strict.map(SecretSubstitution::from))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sha2::Digest;

    use super::*;
    use crate::cloud::CloudSecretEntry;
    use crate::domain::{
        EnvVar, MAX_SECRET_PLACEHOLDER_BYTES, PublishedPortSpec, SecretViolationAction,
    };
    use crate::modify::PublishedPortKey;

    const MATERIAL: &str = "sk-live-do-not-log-me-0123456789abcdef";
    const SOURCE_VAR: &str = "MSB_TEST_ROTATION_SOURCE_VAR";

    fn secret(name: &str) -> SecretModificationPatch {
        SecretModificationPatch {
            name: name.to_string(),
            ..Default::default()
        }
    }

    fn with_value(name: &str) -> SecretModificationPatch {
        SecretModificationPatch {
            value: Zeroizing::new(MATERIAL.to_string()),
            ..secret(name)
        }
    }

    fn with_env(name: &str) -> SecretModificationPatch {
        SecretModificationPatch {
            source: Some(SecretSource::env(SOURCE_VAR)),
            ..secret(name)
        }
    }

    fn full(spec: SecretModificationPatch) -> SecretModificationPatch {
        SecretModificationPatch {
            placeholder: Some("$API_KEY".to_string()),
            allowed_hosts: vec![
                "api.example.com".to_string(),
                "*.example.org".to_string(),
                "*".to_string(),
            ],
            substitution: Some(SecretSubstitution {
                headers: true,
                header_fields: Vec::new(),
                query: true,
                body: false,
            }),
            passthrough_hosts: vec!["telemetry.example.com".to_string()],
            violation_action: Some(SecretViolationAction::BlockAndTerminate),
            require_tls_identity: Some(false),
            ..spec
        }
    }

    fn patch(spec: SecretModificationPatch) -> SandboxModificationPatch {
        SandboxModificationPatch {
            secrets: vec![spec],
            ..Default::default()
        }
    }

    fn plan(patch: &SandboxModificationPatch) -> CloudSandboxModificationPlanRequest {
        CloudSandboxModificationPlanRequest::from_patch(patch, ModificationPolicy::NextStart)
            .expect("patch projects")
    }

    fn apply(
        patch: &SandboxModificationPatch,
    ) -> Result<CloudSandboxModificationApplyRequest, CloudModificationRejection> {
        CloudSandboxModificationApplyRequest::from_patch(
            patch,
            ModificationPolicy::NextStart,
            |var| {
                assert_eq!(var, SOURCE_VAR);
                Some(CloudSecretValue::new(MATERIAL))
            },
        )
    }

    /// Dry run and apply must refuse the same patch the same way.
    fn rejection(patch: &SandboxModificationPatch) -> CloudModificationRejection {
        let planned =
            CloudSandboxModificationPlanRequest::from_patch(patch, ModificationPolicy::NoRestart)
                .expect_err("dry run refuses");
        let applied = apply(patch).expect_err("apply refuses");
        assert_eq!(planned, applied);
        planned
    }

    fn full_secret_json(key: &str, value: Value) -> Value {
        let mut secret = json!({
            "name": "API_KEY",
            "placeholder": "$API_KEY",
            "allowed_hosts": [
                {"type": "exact", "value": "api.example.com"},
                {"type": "wildcard", "value": "*.example.org"},
                {"type": "any"},
            ],
            "substitution": {"headers": true, "query": true, "body": false},
            "passthrough_hosts": [{"type": "exact", "value": "telemetry.example.com"}],
            "violation_action": {"type": "block_and_terminate"},
            "require_tls_identity": false,
        });
        secret[key] = value;
        secret
    }

    fn round_trips<T: Serialize + serde::de::DeserializeOwned>(value: &T) -> Value {
        let json = serde_json::to_value(value).expect("serializes");
        let parsed: T = serde_json::from_value(json.clone()).expect("deserializes");
        assert_eq!(serde_json::to_value(parsed).expect("reserializes"), json);
        json
    }

    //----------------------------------------------------------------------------------------------
    // Wire shape
    //----------------------------------------------------------------------------------------------

    #[test]
    fn plan_request_has_the_exact_wire_shape() {
        let request = plan(&patch(full(with_value("API_KEY"))));

        assert_eq!(
            round_trips(&request),
            json!({
                "policy": "next_start",
                "secrets": [full_secret_json("material", json!({"type": "provided"}))],
            })
        );
    }

    #[test]
    fn apply_request_has_the_exact_wire_shape() {
        let request = apply(&patch(full(with_value("API_KEY")))).expect("patch projects");

        assert_eq!(
            round_trips(&request),
            json!({
                "policy": "next_start",
                "secrets": [full_secret_json("value", json!(MATERIAL))],
            })
        );
    }

    #[test]
    fn material_is_a_bare_type_tag() {
        assert_eq!(
            round_trips(&CloudSecretMaterial::Provided),
            json!({"type": "provided"})
        );
        assert_eq!(
            round_trips(&CloudSecretMaterial::Absent),
            json!({"type": "absent"})
        );
    }

    #[test]
    fn omitted_metadata_stays_omitted() {
        let request = plan(&patch(secret("API_KEY")));
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({
                "policy": "next_start",
                "secrets": [{"name": "API_KEY", "material": {"type": "absent"}}],
            })
        );

        let request = apply(&patch(with_value("API_KEY"))).unwrap();
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({
                "policy": "next_start",
                "secrets": [{"name": "API_KEY", "value": MATERIAL}],
            })
        );

        let parsed: CloudSandboxModificationPlanRequest = serde_json::from_value(
            json!({"secrets": [{"name": "API_KEY", "material": {"type": "absent"}}]}),
        )
        .unwrap();
        assert_eq!(parsed.policy, ModificationPolicy::NoRestart);
        assert!(parsed.secrets_remove.is_empty());
        let [secret] = parsed.secrets.as_slice() else {
            panic!("one secret: {parsed:?}");
        };
        assert!(secret.placeholder.is_none());
        assert!(secret.allowed_hosts.is_none());
        assert!(secret.substitution.is_none());
        assert!(secret.passthrough_hosts.is_none());
        assert!(secret.violation_action.is_none());
        assert!(secret.require_tls_identity.is_none());

        let request = plan(&SandboxModificationPatch::default());
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({"policy": "next_start"})
        );

        let parsed: CloudSandboxModificationPlanRequest =
            serde_json::from_value(json!({})).unwrap();
        assert!(parsed.secrets.is_empty() && parsed.secrets_remove.is_empty());

        let parsed: CloudSandboxModificationApplyRequest =
            serde_json::from_value(json!({})).unwrap();
        assert!(parsed.secrets.is_empty() && parsed.secrets_remove.is_empty());
    }

    #[test]
    fn an_unknown_substitution_field_is_refused() {
        let misspelled = json!({"headers": true, "header_field": ["Authorization"]});

        let plan = serde_json::from_value::<CloudSandboxModificationPlanRequest>(json!({
            "secrets": [{
                "name": "API_KEY",
                "material": {"type": "absent"},
                "substitution": misspelled,
            }],
        }));
        let apply = serde_json::from_value::<CloudSandboxModificationApplyRequest>(json!({
            "secrets": [{"name": "API_KEY", "substitution": misspelled}],
        }));

        for error in [plan.unwrap_err(), apply.unwrap_err()] {
            assert!(error.to_string().contains("header_field"), "{error}");
        }
    }

    #[test]
    fn an_absent_null_or_empty_substitution_is_read_as_before() {
        let read = |substitution: Option<Value>| {
            let mut plan_secret = json!({"name": "API_KEY", "material": {"type": "absent"}});
            let mut apply_secret = json!({"name": "API_KEY"});
            if let Some(substitution) = substitution {
                plan_secret["substitution"] = substitution.clone();
                apply_secret["substitution"] = substitution;
            }

            let plan: CloudSandboxModificationPlanRequest =
                serde_json::from_value(json!({"secrets": [plan_secret]})).unwrap();
            let apply: CloudSandboxModificationApplyRequest =
                serde_json::from_value(json!({"secrets": [apply_secret]})).unwrap();

            let plan = serde_json::to_value(&plan.secrets[0].substitution).unwrap();
            let apply = serde_json::to_value(&apply.secrets[0].substitution).unwrap();
            assert_eq!(plan, apply);
            plan
        };

        assert_eq!(read(None), Value::Null);
        assert_eq!(read(Some(Value::Null)), Value::Null);
        assert_eq!(
            read(Some(json!({}))),
            serde_json::to_value(SecretSubstitution::default()).unwrap()
        );
    }

    #[test]
    fn an_omitted_substitution_field_takes_the_create_default() {
        let parsed: CloudSandboxModificationApplyRequest = serde_json::from_value(json!({
            "secrets": [{"name": "API_KEY", "substitution": {"query": true}}],
        }))
        .unwrap();

        let substitution = parsed.secrets[0].substitution.as_ref().unwrap();
        assert!(substitution.headers);
        assert!(substitution.header_fields.is_empty());
        assert!(substitution.query);
        assert!(!substitution.body);
    }

    //----------------------------------------------------------------------------------------------
    // Secret material
    //----------------------------------------------------------------------------------------------

    /// Two secrets, one inline and one from `Env`, plus a removal.
    fn several() -> SandboxModificationPatch {
        SandboxModificationPatch {
            secrets: vec![full(with_value("API_KEY")), with_env("OTHER_KEY")],
            secrets_remove: vec!["OLD_KEY".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn plan_request_carries_no_plaintext_or_value_derived_data() {
        let digest = hex::encode(sha2::Sha256::digest(MATERIAL.as_bytes()));

        for patch in [
            patch(with_value("API_KEY")),
            patch(with_env("API_KEY")),
            several(),
        ] {
            let json = serde_json::to_value(plan(&patch)).unwrap();
            let rendered = json.to_string();

            assert!(!rendered.contains(MATERIAL), "value leaked: {rendered}");
            assert!(!rendered.contains(SOURCE_VAR), "source leaked: {rendered}");
            assert!(!rendered.contains(&digest), "hash leaked: {rendered}");
            assert!(
                !rendered.contains(&MATERIAL.len().to_string()),
                "length leaked: {rendered}"
            );
            // Each secret's material is a bare tag.
            for secret in json["secrets"].as_array().unwrap() {
                assert_eq!(secret["material"], json!({"type": "provided"}));
                assert!(secret.get("value").is_none(), "{rendered}");
            }
        }
    }

    #[test]
    fn debug_redacts_the_value() {
        let request = apply(&patch(full(with_value("API_KEY")))).unwrap();

        for rendered in [
            format!("{request:?}"),
            format!("{request:#?}"),
            format!("{:?}", CloudSecretValue::new(MATERIAL)),
        ] {
            assert!(!rendered.contains(MATERIAL), "value leaked: {rendered}");
            assert!(rendered.contains("[REDACTED]"), "{rendered}");
        }
    }

    #[test]
    fn dry_run_and_apply_project_the_same_metadata() {
        for patch in [
            patch(full(with_value("API_KEY"))),
            patch(with_env("API_KEY")),
            patch(full(secret("API_KEY"))),
            several(),
        ] {
            let planned = plan(&patch);
            let applied = apply(&patch).unwrap();
            let mut planned_json = serde_json::to_value(&planned).unwrap();
            let mut applied_json = serde_json::to_value(&applied).unwrap();
            for (planned, applied) in planned.secrets.iter().zip(&applied.secrets) {
                assert_eq!(
                    planned.material == CloudSecretMaterial::Provided,
                    applied.value.is_some()
                );
            }
            for json in [&mut planned_json, &mut applied_json] {
                for secret in json["secrets"].as_array_mut().into_iter().flatten() {
                    let secret = secret.as_object_mut().unwrap();
                    secret.remove("material");
                    secret.remove("value");
                }
            }
            assert_eq!(planned_json, applied_json);
            applied.validate().expect("projection validates");
            planned.validate().expect("projection validates");
        }
    }

    #[test]
    fn apply_hands_env_resolution_to_the_caller() {
        let request = apply(&patch(with_env("API_KEY"))).unwrap();
        assert_eq!(
            request.secrets[0]
                .value
                .as_ref()
                .map(CloudSecretValue::expose),
            Some(MATERIAL)
        );
    }

    #[test]
    fn env_sources_resolve_once_each() {
        let patch = SandboxModificationPatch {
            secrets: vec![
                SecretModificationPatch {
                    source: Some(SecretSource::env("FIRST_VAR")),
                    ..secret("FIRST")
                },
                with_value("INLINE"),
                SecretModificationPatch {
                    source: Some(SecretSource::env("SECOND_VAR")),
                    ..secret("SECOND")
                },
            ],
            ..Default::default()
        };
        let mut calls = Vec::new();

        let request = CloudSandboxModificationApplyRequest::from_patch(
            &patch,
            ModificationPolicy::NoRestart,
            |var| {
                calls.push(var.to_string());
                Some(CloudSecretValue::new(format!("{var}-value")))
            },
        )
        .unwrap();

        assert_eq!(calls, ["FIRST_VAR", "SECOND_VAR"]);
        let values: Vec<_> = request
            .secrets
            .iter()
            .map(|secret| secret.value.as_ref().map(CloudSecretValue::expose))
            .collect();
        assert_eq!(
            values,
            [
                Some("FIRST_VAR-value"),
                Some(MATERIAL),
                Some("SECOND_VAR-value")
            ]
        );
    }

    //----------------------------------------------------------------------------------------------
    // Projection
    //----------------------------------------------------------------------------------------------

    #[test]
    fn projects_removals_and_several_secrets() {
        let empty = plan(&SandboxModificationPatch::default());
        assert!(empty.secrets.is_empty() && empty.secrets_remove.is_empty());

        let two = SandboxModificationPatch {
            secrets: vec![with_value("B"), with_value("A")],
            ..Default::default()
        };
        let names = |request: &CloudSandboxModificationPlanRequest| {
            request
                .secrets
                .iter()
                .map(|secret| secret.name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&plan(&two)), ["B", "A"]);
        assert_eq!(
            apply(&two)
                .unwrap()
                .secrets
                .iter()
                .map(|secret| secret.name.clone())
                .collect::<Vec<_>>(),
            ["B", "A"]
        );

        let removal = SandboxModificationPatch {
            secrets_remove: vec!["OLD".to_string(), "OLDER".to_string()],
            ..patch(with_value("API_KEY"))
        };
        assert_eq!(names(&plan(&removal)), ["API_KEY"]);
        assert_eq!(plan(&removal).secrets_remove, ["OLD", "OLDER"]);
        assert_eq!(apply(&removal).unwrap().secrets_remove, ["OLD", "OLDER"]);
    }

    #[test]
    fn secret_index_names_the_entry() {
        let patch = SandboxModificationPatch {
            secrets: vec![with_value("API_KEY"), with_value("BAD=KEY")],
            ..Default::default()
        };
        assert_eq!(
            rejection(&patch),
            CloudModificationRejection::InvalidName {
                field: "secrets.name",
                reason: SecretConfigError::EnvVarContainsEquals { secret_index: 1 },
            }
        );

        let parsed: CloudSandboxModificationPlanRequest = serde_json::from_value(json!({
            "secrets": [
                {"name": "API_KEY", "material": {"type": "absent"}},
                {"name": "OTHER_KEY", "material": {"type": "absent"}, "placeholder": ""},
            ],
        }))
        .unwrap();
        assert_eq!(
            parsed.validate(),
            Err(CloudModificationRejection::InvalidPlaceholder {
                field: "secrets.placeholder",
                reason: SecretConfigError::EmptyPlaceholder { secret_index: 1 },
            })
        );
    }

    #[test]
    fn removal_names_are_carried_unchecked() {
        // As in Local, removing a name no secret has is a no-op, so a removal
        // is never refused for its shape.
        let removals = vec![
            "OLD".to_string(),
            " ".to_string(),
            "OLD=KEY".to_string(),
            "OLD/KEY".to_string(),
        ];
        let removal = SandboxModificationPatch {
            secrets_remove: removals.clone(),
            ..Default::default()
        };
        assert_eq!(plan(&removal).secrets_remove, removals);
        assert_eq!(apply(&removal).unwrap().secrets_remove, removals);

        let parsed: CloudSandboxModificationPlanRequest =
            serde_json::from_value(json!({"secrets_remove": removals})).unwrap();
        assert_eq!(parsed.validate(), Ok(()));
        let parsed: CloudSandboxModificationApplyRequest =
            serde_json::from_value(json!({"secrets_remove": removals})).unwrap();
        assert_eq!(parsed.validate(), Ok(()));
    }

    //----------------------------------------------------------------------------------------------
    // Rejections
    //----------------------------------------------------------------------------------------------

    #[test]
    fn rejects_every_non_secret_field() {
        let base = || patch(with_value("API_KEY"));
        let cases = [
            (
                "cpus",
                SandboxModificationPatch {
                    cpus: Some(2),
                    ..base()
                },
            ),
            (
                "max_cpus",
                SandboxModificationPatch {
                    max_cpus: Some(4),
                    ..base()
                },
            ),
            (
                "memory_mib",
                SandboxModificationPatch {
                    memory_mib: Some(512),
                    ..base()
                },
            ),
            (
                "max_memory_mib",
                SandboxModificationPatch {
                    max_memory_mib: Some(1024),
                    ..base()
                },
            ),
            (
                "root_disk_size_mib",
                SandboxModificationPatch {
                    root_disk_size_mib: Some(2048),
                    ..base()
                },
            ),
            (
                "env",
                SandboxModificationPatch {
                    env: vec![EnvVar {
                        key: "A".into(),
                        value: "1".into(),
                    }],
                    ..base()
                },
            ),
            (
                "env_remove",
                SandboxModificationPatch {
                    env_remove: vec!["A".into()],
                    ..base()
                },
            ),
            (
                "labels",
                SandboxModificationPatch {
                    labels: vec![("a".into(), "1".into())],
                    ..base()
                },
            ),
            (
                "labels_remove",
                SandboxModificationPatch {
                    labels_remove: vec!["a".into()],
                    ..base()
                },
            ),
            (
                "ports",
                SandboxModificationPatch {
                    ports: vec![PublishedPortSpec {
                        host_port: 8080,
                        guest_port: 80,
                        ..Default::default()
                    }],
                    ..base()
                },
            ),
            (
                "ports_remove",
                SandboxModificationPatch {
                    ports_remove: vec![PublishedPortKey {
                        host_bind: "127.0.0.1".into(),
                        host_port: 8080,
                        protocol: Default::default(),
                    }],
                    ..base()
                },
            ),
            (
                "workdir",
                SandboxModificationPatch {
                    workdir: Some("/srv".into()),
                    ..base()
                },
            ),
        ];

        for (field, patch) in cases {
            assert_eq!(
                rejection(&patch),
                CloudModificationRejection::UnsupportedField { field }
            );
        }
    }

    #[test]
    fn rejects_a_blank_name() {
        assert_eq!(
            rejection(&patch(with_value(" "))),
            CloudModificationRejection::BlankName {
                field: "secrets.name"
            }
        );

        let parsed: CloudSandboxModificationPlanRequest = serde_json::from_value(
            json!({"secrets": [{"name": "", "material": {"type": "absent"}}]}),
        )
        .unwrap();
        assert_eq!(
            parsed.validate(),
            Err(CloudModificationRejection::BlankName {
                field: "secrets.name"
            })
        );
    }

    #[test]
    fn rejects_a_name_create_would_refuse() {
        for (name, reason) in [
            (
                "API=KEY",
                SecretConfigError::EnvVarContainsEquals { secret_index: 0 },
            ),
            (
                "API\0KEY",
                SecretConfigError::EnvVarContainsNul { secret_index: 0 },
            ),
        ] {
            assert_eq!(
                rejection(&patch(with_value(name))),
                CloudModificationRejection::InvalidName {
                    field: "secrets.name",
                    reason: reason.clone(),
                }
            );

            let parsed: CloudSandboxModificationPlanRequest = serde_json::from_value(
                json!({"secrets": [{"name": name, "material": {"type": "absent"}}]}),
            )
            .unwrap();
            assert_eq!(
                parsed.validate(),
                Err(CloudModificationRejection::InvalidName {
                    field: "secrets.name",
                    reason,
                })
            );
        }
    }

    #[test]
    fn a_whitespace_value_is_a_value_and_only_an_empty_or_unset_source_is_refused() {
        // As in Local, only an empty value or an unset variable is refused;
        // whitespace is a value.
        let spaces = patch(SecretModificationPatch {
            value: Zeroizing::new("  ".to_string()),
            ..secret("API_KEY")
        });
        let request = apply(&spaces).unwrap();
        assert_eq!(
            request.secrets[0]
                .value
                .as_ref()
                .map(CloudSecretValue::expose),
            Some("  ")
        );

        let unresolved = CloudModificationRejection::UnresolvedSource {
            field: "secrets.source",
            var: SOURCE_VAR.to_string(),
        };
        let empty = CloudModificationRejection::EmptyValue {
            field: "secrets.source",
        };
        for (resolved, refusal) in [
            (None, Some(unresolved)),
            (Some(""), Some(empty)),
            (Some(" \n"), None),
        ] {
            let result = CloudSandboxModificationApplyRequest::from_patch(
                &patch(with_env("API_KEY")),
                ModificationPolicy::NoRestart,
                |_| resolved.map(CloudSecretValue::new),
            );
            match refusal {
                Some(refusal) => assert_eq!(result.unwrap_err(), refusal),
                None => assert!(result.is_ok()),
            }
        }

        let parsed: CloudSandboxModificationApplyRequest = serde_json::from_value(json!({
            "secrets": [{"name": "API_KEY", "value": " "}],
        }))
        .unwrap();
        assert_eq!(parsed.validate(), Ok(()));
        let parsed: CloudSandboxModificationApplyRequest = serde_json::from_value(json!({
            "secrets": [{"name": "API_KEY", "value": ""}],
        }))
        .unwrap();
        assert_eq!(
            parsed.validate(),
            Err(CloudModificationRejection::EmptyValue {
                field: "secrets.value"
            })
        );
    }

    #[test]
    fn rejects_a_value_with_a_source() {
        let spec = SecretModificationPatch {
            source: Some(SecretSource::env(SOURCE_VAR)),
            ..with_value("API_KEY")
        };
        assert_eq!(
            rejection(&patch(spec)),
            CloudModificationRejection::ValueAndSource {
                field: "secrets.value"
            }
        );
    }

    #[test]
    fn rejects_a_secret_store_source() {
        let spec = SecretModificationPatch {
            source: Some(SecretSource::Store {
                reference: "vault://api-key".to_string(),
            }),
            ..secret("API_KEY")
        };
        assert_eq!(
            rejection(&patch(spec)),
            CloudModificationRejection::StoreSource {
                field: "secrets.source"
            }
        );
    }

    #[test]
    fn rejects_a_placeholder_create_would_refuse() {
        let too_long = "x".repeat(MAX_SECRET_PLACEHOLDER_BYTES + 1);
        for (placeholder, reason) in [
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
                "$API\0KEY",
                SecretConfigError::PlaceholderContainsNul { secret_index: 0 },
            ),
            (
                "$API\rKEY",
                SecretConfigError::PlaceholderContainsLineBreak { secret_index: 0 },
            ),
            (
                "$API\nKEY",
                SecretConfigError::PlaceholderContainsLineBreak { secret_index: 0 },
            ),
        ] {
            let spec = SecretModificationPatch {
                placeholder: Some(placeholder.to_string()),
                ..secret("API_KEY")
            };
            assert_eq!(
                rejection(&patch(spec)),
                CloudModificationRejection::InvalidPlaceholder {
                    field: "secrets.placeholder",
                    reason: reason.clone(),
                }
            );

            let parsed: CloudSandboxModificationApplyRequest = serde_json::from_value(json!({
                "secrets": [{"name": "API_KEY", "placeholder": placeholder}],
            }))
            .unwrap();
            assert_eq!(
                parsed.validate(),
                Err(CloudModificationRejection::InvalidPlaceholder {
                    field: "secrets.placeholder",
                    reason,
                })
            );
        }
    }

    /// Modify must accept exactly what create accepts, so restating a stored
    /// secret is never refused. These values are odd but pass create.
    #[test]
    fn restating_a_valid_create_entry_is_never_refused() {
        let hosts = [
            "",
            " ",
            "*.",
            "api.*.com",
            "**.example.com",
            "api example.com",
            "*",
        ];
        let entry = SecretEntry {
            env_var: "API_KEY".to_string(),
            value: Zeroizing::new(MATERIAL.to_string()),
            source: None,
            placeholder: " ".to_string(),
            allowed_hosts: hosts.iter().map(|host| HostPattern::parse(host)).collect(),
            substitution: SecretSubstitution::default(),
            passthrough_hosts: hosts.iter().map(|host| HostPattern::parse(host)).collect(),
            violation_action: None,
            require_tls_identity: true,
        };
        entry.validate(0).expect("create accepts the entry");

        let restated = patch(SecretModificationPatch {
            placeholder: Some(entry.placeholder.clone()),
            allowed_hosts: hosts.iter().map(|host| host.to_string()).collect(),
            passthrough_hosts: hosts.iter().map(|host| host.to_string()).collect(),
            ..with_value(&entry.env_var)
        });
        let planned = plan(&restated);
        planned.validate().expect("restatement validates");
        let applied = apply(&restated).expect("restatement projects");
        applied.validate().expect("restatement validates");

        let created = serde_json::to_value(CloudSecretEntry::from(entry)).unwrap();
        let plan_entry = serde_json::to_value(&planned.secrets[0]).unwrap();
        for field in ["placeholder", "allowed_hosts", "passthrough_hosts"] {
            assert_eq!(
                plan_entry[field], created[field],
                "{field} differs from create"
            );
        }

        // Deserialized patterns are taken as declared, as the Cloud-to-domain
        // conversion takes them.
        let parsed: CloudSandboxModificationPlanRequest = serde_json::from_value(json!({
            "secrets": [{
                "name": "API_KEY",
                "material": {"type": "absent"},
                "allowed_hosts": [
                    {"type": "exact", "value": "*"},
                    {"type": "exact", "value": ""},
                    {"type": "wildcard", "value": "example.com"},
                ],
            }],
        }))
        .unwrap();
        parsed.validate().expect("declared patterns validate");
    }

    #[test]
    fn rejections_name_their_field_and_reason() {
        let rendered = CloudModificationRejection::InvalidPlaceholder {
            field: "secrets.placeholder",
            reason: SecretConfigError::PlaceholderContainsLineBreak { secret_index: 0 },
        }
        .to_string();
        assert_eq!(
            rendered,
            "secrets.placeholder: secret #0: placeholder must not contain CR or LF"
        );

        let rendered = CloudModificationRejection::UnresolvedSource {
            field: "secrets.source",
            var: SOURCE_VAR.to_string(),
        }
        .to_string();
        assert_eq!(
            rendered,
            format!("secrets.source: host environment variable {SOURCE_VAR} is not set")
        );
    }

    /// Unknown fields are refused, never dropped: a stray `cpus` must not ride
    /// along with a rotation, a dry run must not accept a `value`, and neither
    /// the singular `secret` key nor an `idempotency_key` is read.
    #[test]
    fn requests_refuse_unknown_fields() {
        let plan = json!({
            "policy": "no_restart",
            "secrets": [{"name": "API_KEY", "material": {"type": "provided"}}],
        });
        serde_json::from_value::<CloudSandboxModificationPlanRequest>(plan.clone())
            .expect("the known shape parses");

        for (path, extra) in [("", "cpus"), ("secrets", "value")] {
            let mut request = plan.clone();
            let target = if path.is_empty() {
                &mut request
            } else {
                &mut request["secrets"][0]
            };
            target[extra] = json!(4);
            assert!(
                serde_json::from_value::<CloudSandboxModificationPlanRequest>(request).is_err(),
                "plan request accepted unknown `{extra}` at `{path}`"
            );
        }

        let apply = json!({
            "policy": "no_restart",
            "secrets": [{"name": "API_KEY", "value": "sk-new"}],
        });
        serde_json::from_value::<CloudSandboxModificationApplyRequest>(apply.clone())
            .expect("the known shape parses");

        for (path, extra) in [
            ("", "cpus"),
            ("", "idempotency_key"),
            ("secrets", "material"),
        ] {
            let mut request = apply.clone();
            let target = if path.is_empty() {
                &mut request
            } else {
                &mut request["secrets"][0]
            };
            target[extra] = json!(4);
            assert!(
                serde_json::from_value::<CloudSandboxModificationApplyRequest>(request).is_err(),
                "apply request accepted unknown `{extra}` at `{path}`"
            );
        }

        let singular_plan =
            json!({"secret": {"name": "API_KEY", "material": {"type": "provided"}}});
        assert!(
            serde_json::from_value::<CloudSandboxModificationPlanRequest>(singular_plan).is_err()
        );
        let singular_apply = json!({"secret": {"name": "API_KEY", "value": "sk-new"}});
        assert!(
            serde_json::from_value::<CloudSandboxModificationApplyRequest>(singular_apply).is_err()
        );
    }

    #[test]
    fn error_codes_are_the_wire_strings() {
        assert_eq!(CLOUD_MODIFICATION_IN_PROGRESS, "modification_in_progress");
        assert_eq!(CLOUD_MODIFICATION_REFUSED, "modification_refused");
        assert_eq!(CLOUD_MODIFICATION_UNSUPPORTED, "modification_unsupported");
        assert_eq!(
            CLOUD_MODIFICATION_NOT_CONFIRMED,
            "modification_not_confirmed"
        );
    }
}
