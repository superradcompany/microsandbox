//! Cloud sandbox-modification wire contracts.
//!
//! Stage 1 supports exactly one change to one existing secret per request, so
//! the request carries a single `secret` rather than a list; a later stage can
//! add a list beside it additively. Plan requests are value-free. Only the
//! apply request carries plaintext, inside [`CloudSecretValue`].

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{CloudErrorDetails, CloudHostPattern, CloudViolationAction};
use crate::domain::{
    HostPattern, SecretConfigError, SecretSubstitution, validate_env_var, validate_placeholder,
};
use crate::modify::{
    ModificationPolicy, SandboxModificationPatch, SandboxModificationPlan, SecretModificationPatch,
    SecretSource,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum length in bytes of an apply request's idempotency key.
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 255;

//--------------------------------------------------------------------------------------------------
// Types: Requests
//--------------------------------------------------------------------------------------------------

/// Body of a Cloud modification dry run. It is value-free by construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct CloudSandboxModificationPlanRequest {
    /// Policy the plan is classified under.
    #[serde(default)]
    pub policy: ModificationPolicy,
    /// The one secret change requested.
    pub secret: CloudSecretModificationIntent,
}

/// A value-free change to one existing secret.
///
/// Every `None` metadata field means "omitted: preserve the current setting",
/// and is left out of the JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct CloudSecretModificationIntent {
    /// Name of the existing secret, the env var it is exposed as.
    pub name: String,
    /// Whether the change supplies new secret material.
    pub material: CloudSecretMaterial,
    /// New guest-visible placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// New hosts allowed to receive the secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_hosts: Option<Vec<CloudHostPattern>>,
    /// New substitution locations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

/// Whether a secret change supplies new material. Carries nothing derived
/// from the value: no hash, length, or source name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CloudSecretMaterial {
    /// New material is supplied, so the secret is rotated.
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
    /// Client-generated opaque key. The server binds it to [`intent`], which
    /// carries no secret value: a retry cannot apply twice, and reusing the key
    /// with a different value returns the original operation, so use a new key
    /// for every change. It is distinct from the server-minted operation id.
    ///
    /// [`intent`]: Self::intent
    pub idempotency_key: String,
    /// Policy the change is applied under.
    #[serde(default)]
    pub policy: ModificationPolicy,
    /// The one secret change requested.
    pub secret: CloudSecretModificationApply,
}

/// A change to one existing secret, with its new value when rotating.
///
/// Every `None` field means "omitted: preserve the current setting", and is
/// left out of the JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(deny_unknown_fields)]
pub struct CloudSecretModificationApply {
    /// Name of the existing secret, the env var it is exposed as.
    pub name: String,
    /// New secret value. Present exactly when the secret is rotated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<CloudSecretValue>,
    /// New guest-visible placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// New hosts allowed to receive the secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_hosts: Option<Vec<CloudHostPattern>>,
    /// New substitution locations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
/// Zeroized on drop and printed as `[REDACTED]` by `Debug`. It serializes as a
/// plain string only because the apply body must carry it, and it has no
/// `Display`.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "utoipa", schema(value_type = String))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSecretValue(#[cfg_attr(feature = "ts", ts(type = "string"))] Zeroizing<String>);

//--------------------------------------------------------------------------------------------------
// Types: Operation
//--------------------------------------------------------------------------------------------------

/// The modification operation envelope. It is value-free.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSandboxModificationOperation {
    /// Server-minted operation id, distinct from the caller's idempotency key.
    pub id: String,
    /// Current operation status.
    pub status: CloudModificationOperationStatus,
    /// The applied plan. Present only when `status` is `succeeded`.
    #[serde(default)]
    pub plan: Option<SandboxModificationPlan>,
    /// Sanitized failure detail. Present only when `status` is `failed`.
    #[serde(default)]
    pub error: Option<CloudErrorDetails>,
}

/// Whether a modification operation has finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum CloudModificationOperationStatus {
    /// Still active; carries neither plan nor error.
    InProgress,
    /// Durably committed; carries the plan. Each change's disposition says how
    /// far it got toward the running sandbox.
    Succeeded,
    /// Could not be established as successful; carries only a sanitized error.
    Failed,
}

//--------------------------------------------------------------------------------------------------
// Types: Rejection
//--------------------------------------------------------------------------------------------------

/// Why a modification cannot be expressed as a Stage 1 Cloud request.
///
/// Each variant names the offending field so nothing is dropped silently.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CloudModificationRejection {
    /// The patch changes no secret.
    #[error("{field}: a cloud modification must change exactly one secret, and none was given")]
    NoSecretChange {
        /// Offending field.
        field: &'static str,
    },

    /// The patch changes more than one secret.
    #[error("{field}: a cloud modification changes one secret per request, {count} were given")]
    MultipleSecrets {
        /// Offending field.
        field: &'static str,
        /// Number of secrets in the patch.
        count: usize,
    },

    /// The patch removes a secret. Adding a secret is refused too, but only
    /// the server can tell a new secret from an existing one.
    #[error("{field}: cloud modification cannot add or remove secrets")]
    SecretRemoval {
        /// Offending field.
        field: &'static str,
    },

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
        /// The create rule it breaks. A modification carries one secret, so
        /// the reason's `secret_index` is always 0.
        reason: SecretConfigError,
    },

    /// The new secret value is blank.
    #[error("{field}: secret value must not be blank")]
    BlankValue {
        /// Offending field.
        field: &'static str,
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
        /// The create rule it breaks. A modification carries one secret, so
        /// the reason's `secret_index` is always 0.
        reason: SecretConfigError,
    },

    /// The idempotency key is not a usable opaque key.
    #[error("{field}: {reason}")]
    InvalidIdempotencyKey {
        /// Offending field.
        field: &'static str,
        /// What is wrong with the key.
        reason: CloudIdempotencyKeyError,
    },
}

/// Why an idempotency key is refused. Beyond these rules the key is opaque.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CloudIdempotencyKeyError {
    /// The key is empty or only whitespace.
    #[error("idempotency key must not be blank")]
    Blank,

    /// The key is longer than [`MAX_IDEMPOTENCY_KEY_BYTES`].
    #[error("idempotency key must be at most {max_bytes} bytes, got {actual_bytes}")]
    TooLong {
        /// Actual key length in bytes.
        actual_bytes: usize,
        /// Maximum key length in bytes.
        max_bytes: usize,
    },

    /// The key contains a control character.
    #[error("idempotency key must not contain control characters")]
    ControlCharacter,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CloudSandboxModificationPlanRequest {
    /// Project a neutral patch onto the value-free dry-run request.
    ///
    /// Inline value and `Env` source both become [`CloudSecretMaterial::Provided`],
    /// without reading either. Host strings parse as they do for create.
    pub fn from_patch(
        patch: &SandboxModificationPatch,
        policy: ModificationPolicy,
    ) -> Result<Self, CloudModificationRejection> {
        let (spec, metadata) = project_secret(patch)?;
        let material = if spec.value.is_empty() && spec.source.is_none() {
            CloudSecretMaterial::Absent
        } else {
            CloudSecretMaterial::Provided
        };

        Ok(Self {
            policy,
            secret: metadata.into_intent(spec.name.clone(), material),
        })
    }

    /// Check a deserialized request with the name and placeholder rules the
    /// dry-run projection applies. Host patterns are accepted as create
    /// accepts them.
    pub fn validate(&self) -> Result<(), CloudModificationRejection> {
        check_name("secret.name", &self.secret.name)?;
        check_placeholder("secret.placeholder", self.secret.placeholder.as_deref())
    }
}

impl CloudSandboxModificationApplyRequest {
    /// Project a neutral patch onto the apply request.
    ///
    /// An inline value is carried as is. An `Env` source is handed to
    /// `resolve_env`, so the caller resolves it and this crate never reads the
    /// environment. Refuses the same patches as the dry-run projection, plus a
    /// blank or unresolved value and an invalid idempotency key.
    pub fn from_patch(
        patch: &SandboxModificationPatch,
        policy: ModificationPolicy,
        idempotency_key: impl Into<String>,
        resolve_env: impl FnOnce(&str) -> Option<CloudSecretValue>,
    ) -> Result<Self, CloudModificationRejection> {
        let idempotency_key = idempotency_key.into();
        check_idempotency_key(&idempotency_key)?;
        let (spec, metadata) = project_secret(patch)?;
        let value = match &spec.source {
            Some(SecretSource::Env { var }) => match resolve_env(var) {
                Some(value) if !value.is_blank() => Some(value),
                _ => {
                    return Err(CloudModificationRejection::BlankValue {
                        field: "secrets.source",
                    });
                }
            },
            _ if spec.value.is_empty() => None,
            _ if spec.value.trim().is_empty() => {
                return Err(CloudModificationRejection::BlankValue {
                    field: "secrets.value",
                });
            }
            _ => Some(CloudSecretValue(spec.value.clone())),
        };

        Ok(Self {
            idempotency_key,
            policy,
            secret: metadata.into_apply(spec.name.clone(), value),
        })
    }

    /// The value-free request this apply performs, which the server binds the
    /// idempotency key to. Equal to the dry-run projection of the same patch.
    pub fn intent(&self) -> CloudSandboxModificationPlanRequest {
        let secret = &self.secret;
        CloudSandboxModificationPlanRequest {
            policy: self.policy,
            secret: CloudSecretModificationIntent {
                name: secret.name.clone(),
                material: if secret.value.is_some() {
                    CloudSecretMaterial::Provided
                } else {
                    CloudSecretMaterial::Absent
                },
                placeholder: secret.placeholder.clone(),
                allowed_hosts: secret.allowed_hosts.clone(),
                substitution: secret.substitution.clone(),
                passthrough_hosts: secret.passthrough_hosts.clone(),
                violation_action: secret.violation_action.clone(),
                require_tls_identity: secret.require_tls_identity,
            },
        }
    }

    /// Check a deserialized request with the idempotency key, name,
    /// placeholder and value rules the apply projection applies. Host patterns
    /// are accepted as create accepts them.
    pub fn validate(&self) -> Result<(), CloudModificationRejection> {
        let secret = &self.secret;
        check_idempotency_key(&self.idempotency_key)?;
        check_name("secret.name", &secret.name)?;
        check_placeholder("secret.placeholder", secret.placeholder.as_deref())?;
        if secret
            .value
            .as_ref()
            .is_some_and(CloudSecretValue::is_blank)
        {
            return Err(CloudModificationRejection::BlankValue {
                field: "secret.value",
            });
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

    fn is_blank(&self) -> bool {
        self.0.trim().is_empty()
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

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Metadata shared by the intent and the apply shapes.
struct SecretMetadata {
    placeholder: Option<String>,
    allowed_hosts: Option<Vec<CloudHostPattern>>,
    substitution: Option<SecretSubstitution>,
    passthrough_hosts: Option<Vec<CloudHostPattern>>,
    violation_action: Option<CloudViolationAction>,
    require_tls_identity: Option<bool>,
}

impl SecretMetadata {
    fn into_intent(
        self,
        name: String,
        material: CloudSecretMaterial,
    ) -> CloudSecretModificationIntent {
        CloudSecretModificationIntent {
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

    fn into_apply(
        self,
        name: String,
        value: Option<CloudSecretValue>,
    ) -> CloudSecretModificationApply {
        CloudSecretModificationApply {
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

/// Refuse everything Stage 1 cannot express, then project the one secret's
/// metadata. Material is left to the caller, which differs for dry run and
/// apply.
fn project_secret(
    patch: &SandboxModificationPatch,
) -> Result<(&SecretModificationPatch, SecretMetadata), CloudModificationRejection> {
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
    if workdir.is_some() {
        return unsupported("workdir");
    }
    if !secrets_remove.is_empty() {
        return Err(CloudModificationRejection::SecretRemoval {
            field: "secrets_remove",
        });
    }

    let spec = match secrets.as_slice() {
        [] => return Err(CloudModificationRejection::NoSecretChange { field: "secrets" }),
        [spec] => spec,
        _ => {
            return Err(CloudModificationRejection::MultipleSecrets {
                field: "secrets",
                count: secrets.len(),
            });
        }
    };

    check_name("secrets.name", &spec.name)?;
    match &spec.source {
        Some(_) if !spec.value.is_empty() => {
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
    check_placeholder("secrets.placeholder", spec.placeholder.as_deref())?;

    let metadata = SecretMetadata {
        placeholder: spec.placeholder.clone(),
        allowed_hosts: parse_hosts(&spec.allowed_hosts),
        substitution: spec.substitution.clone(),
        passthrough_hosts: parse_hosts(&spec.passthrough_hosts),
        violation_action: spec.violation_action.clone().map(Into::into),
        require_tls_identity: spec.require_tls_identity,
    };
    Ok((spec, metadata))
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
fn check_name(field: &'static str, name: &str) -> Result<(), CloudModificationRejection> {
    if name.trim().is_empty() {
        return Err(CloudModificationRejection::BlankName { field });
    }
    validate_env_var(name, 0)
        .map_err(|reason| CloudModificationRejection::InvalidName { field, reason })
}

/// A supplied placeholder must pass create's placeholder rules.
fn check_placeholder(
    field: &'static str,
    placeholder: Option<&str>,
) -> Result<(), CloudModificationRejection> {
    let Some(placeholder) = placeholder else {
        return Ok(());
    };
    validate_placeholder(placeholder, 0)
        .map_err(|reason| CloudModificationRejection::InvalidPlaceholder { field, reason })
}

fn check_idempotency_key(key: &str) -> Result<(), CloudModificationRejection> {
    let reason = if key.trim().is_empty() {
        CloudIdempotencyKeyError::Blank
    } else if key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        CloudIdempotencyKeyError::TooLong {
            actual_bytes: key.len(),
            max_bytes: MAX_IDEMPOTENCY_KEY_BYTES,
        }
    } else if key.chars().any(char::is_control) {
        CloudIdempotencyKeyError::ControlCharacter
    } else {
        return Ok(());
    };
    Err(CloudModificationRejection::InvalidIdempotencyKey {
        field: "idempotency_key",
        reason,
    })
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
    use crate::domain::{EnvVar, MAX_SECRET_PLACEHOLDER_BYTES, SecretEntry, SecretViolationAction};
    use crate::modify::{
        ModificationDisposition, PlannedChange, SecretChangeKind, SecretPlannedChange,
    };

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
            "idem-1",
            |var| {
                assert_eq!(var, SOURCE_VAR);
                Some(CloudSecretValue::new(MATERIAL))
            },
        )
    }

    /// Both projections must refuse the same patch the same way.
    fn rejection(patch: &SandboxModificationPatch) -> CloudModificationRejection {
        let planned =
            CloudSandboxModificationPlanRequest::from_patch(patch, ModificationPolicy::NoRestart)
                .expect_err("dry run refuses");
        let applied = apply(patch).expect_err("apply refuses");
        assert_eq!(planned, applied);
        planned
    }

    fn full_secret_json(material_or_value: (&str, Value)) -> Value {
        let (key, value) = material_or_value;
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
                "secret": full_secret_json(("material", json!({"kind": "provided"}))),
            })
        );
    }

    #[test]
    fn apply_request_has_the_exact_wire_shape() {
        let request = apply(&patch(full(with_value("API_KEY")))).expect("patch projects");

        assert_eq!(
            round_trips(&request),
            json!({
                "idempotency_key": "idem-1",
                "policy": "next_start",
                "secret": full_secret_json(("value", json!(MATERIAL))),
            })
        );
    }

    #[test]
    fn material_is_a_bare_kind_tag() {
        assert_eq!(
            round_trips(&CloudSecretMaterial::Provided),
            json!({"kind": "provided"})
        );
        assert_eq!(
            round_trips(&CloudSecretMaterial::Absent),
            json!({"kind": "absent"})
        );
    }

    #[test]
    fn operation_has_the_exact_wire_shape() {
        let succeeded = CloudSandboxModificationOperation {
            id: "op-1".to_string(),
            status: CloudModificationOperationStatus::Succeeded,
            plan: Some(SandboxModificationPlan {
                sandbox: "box".to_string(),
                status: "running".to_string(),
                applied: true,
                policy: ModificationPolicy::NoRestart,
                changes: vec![PlannedChange::Secret(SecretPlannedChange {
                    field: "secret".to_string(),
                    name: "API_KEY".to_string(),
                    change: SecretChangeKind::Rotated,
                    before_ref: None,
                    after_ref: None,
                    disposition: ModificationDisposition::Unconfirmed,
                    allow_hosts: Vec::new(),
                    reason: None,
                })],
                conflicts: Vec::new(),
                warnings: Vec::new(),
                resize_status: Vec::new(),
            }),
            error: None,
        };
        assert_eq!(
            round_trips(&succeeded),
            json!({
                "id": "op-1",
                "status": "succeeded",
                "plan": {
                    "sandbox": "box",
                    "status": "running",
                    "applied": true,
                    "policy": "no_restart",
                    "changes": [{
                        "kind": "secret",
                        "field": "secret",
                        "name": "API_KEY",
                        "change": "rotated",
                        "disposition": "unconfirmed",
                    }],
                    "conflicts": [],
                    "warnings": [],
                },
                "error": null,
            })
        );

        let failed = CloudSandboxModificationOperation {
            id: "op-2".to_string(),
            status: CloudModificationOperationStatus::Failed,
            plan: None,
            error: Some(CloudErrorDetails {
                code: Some("secret_store_unavailable".to_string()),
                message: Some("The secret store is unavailable.".to_string()),
            }),
        };
        assert_eq!(
            round_trips(&failed),
            json!({
                "id": "op-2",
                "status": "failed",
                "plan": null,
                "error": {
                    "code": "secret_store_unavailable",
                    "message": "The secret store is unavailable.",
                },
            })
        );

        let in_progress: CloudSandboxModificationOperation =
            serde_json::from_value(json!({"id": "op-3", "status": "in_progress"}))
                .expect("in-progress operation parses");
        assert_eq!(
            in_progress.status,
            CloudModificationOperationStatus::InProgress
        );
        assert!(in_progress.plan.is_none() && in_progress.error.is_none());
    }

    #[test]
    fn omitted_metadata_stays_omitted() {
        let request = plan(&patch(secret("API_KEY")));
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({
                "policy": "next_start",
                "secret": {"name": "API_KEY", "material": {"kind": "absent"}},
            })
        );

        let request = apply(&patch(with_value("API_KEY"))).unwrap();
        assert_eq!(
            serde_json::to_value(&request).unwrap()["secret"],
            json!({"name": "API_KEY", "value": MATERIAL})
        );

        let parsed: CloudSandboxModificationPlanRequest = serde_json::from_value(
            json!({"secret": {"name": "API_KEY", "material": {"kind": "absent"}}}),
        )
        .unwrap();
        assert_eq!(parsed.policy, ModificationPolicy::NoRestart);
        assert!(parsed.secret.placeholder.is_none());
        assert!(parsed.secret.allowed_hosts.is_none());
        assert!(parsed.secret.substitution.is_none());
        assert!(parsed.secret.passthrough_hosts.is_none());
        assert!(parsed.secret.violation_action.is_none());
        assert!(parsed.secret.require_tls_identity.is_none());
    }

    //----------------------------------------------------------------------------------------------
    // Secret material
    //----------------------------------------------------------------------------------------------

    #[test]
    fn plan_request_carries_no_plaintext_or_value_derived_data() {
        let digest = hex::encode(sha2::Sha256::digest(MATERIAL.as_bytes()));

        for spec in [with_value("API_KEY"), with_env("API_KEY")] {
            let json = serde_json::to_value(plan(&patch(spec))).unwrap();
            let rendered = json.to_string();

            assert!(!rendered.contains(MATERIAL), "value leaked: {rendered}");
            assert!(!rendered.contains(SOURCE_VAR), "source leaked: {rendered}");
            assert!(!rendered.contains(&digest), "hash leaked: {rendered}");
            assert!(
                !rendered.contains(&MATERIAL.len().to_string()),
                "length leaked: {rendered}"
            );
            // The whole secret is its name and a bare material tag.
            assert_eq!(
                json["secret"],
                json!({"name": "API_KEY", "material": {"kind": "provided"}})
            );
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
    fn intent_equals_the_dry_run_projection() {
        for spec in [
            full(with_value("API_KEY")),
            with_env("API_KEY"),
            full(secret("API_KEY")),
        ] {
            let patch = patch(spec);
            let applied = apply(&patch).unwrap();

            assert_eq!(
                serde_json::to_value(applied.intent()).unwrap(),
                serde_json::to_value(plan(&patch)).unwrap()
            );
            applied.validate().expect("projection validates");
            plan(&patch).validate().expect("projection validates");
        }
    }

    #[test]
    fn apply_hands_env_resolution_to_the_caller() {
        let request = apply(&patch(with_env("API_KEY"))).unwrap();
        assert_eq!(
            request.secret.value.as_ref().map(CloudSecretValue::expose),
            Some(MATERIAL)
        );
    }

    //----------------------------------------------------------------------------------------------
    // Rejections
    //----------------------------------------------------------------------------------------------

    #[test]
    fn rejects_a_patch_without_a_secret_change() {
        assert_eq!(
            rejection(&SandboxModificationPatch::default()),
            CloudModificationRejection::NoSecretChange { field: "secrets" }
        );
    }

    #[test]
    fn rejects_more_than_one_secret() {
        let patch = SandboxModificationPatch {
            secrets: vec![with_value("A"), with_value("B")],
            ..Default::default()
        };
        assert_eq!(
            rejection(&patch),
            CloudModificationRejection::MultipleSecrets {
                field: "secrets",
                count: 2
            }
        );
    }

    #[test]
    fn rejects_secret_removal() {
        let patch = SandboxModificationPatch {
            secrets_remove: vec!["OLD".to_string()],
            ..patch(with_value("API_KEY"))
        };
        assert_eq!(
            rejection(&patch),
            CloudModificationRejection::SecretRemoval {
                field: "secrets_remove"
            }
        );
    }

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

        let parsed: CloudSandboxModificationPlanRequest =
            serde_json::from_value(json!({"secret": {"name": "", "material": {"kind": "absent"}}}))
                .unwrap();
        assert_eq!(
            parsed.validate(),
            Err(CloudModificationRejection::BlankName {
                field: "secret.name"
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
                json!({"secret": {"name": name, "material": {"kind": "absent"}}}),
            )
            .unwrap();
            assert_eq!(
                parsed.validate(),
                Err(CloudModificationRejection::InvalidName {
                    field: "secret.name",
                    reason,
                })
            );
        }
    }

    #[test]
    fn rejects_a_blank_value_on_apply() {
        let blank_inline = patch(SecretModificationPatch {
            value: Zeroizing::new("  ".to_string()),
            ..secret("API_KEY")
        });
        assert_eq!(
            apply(&blank_inline).unwrap_err(),
            CloudModificationRejection::BlankValue {
                field: "secrets.value"
            }
        );

        for resolved in [None, Some(""), Some(" \n")] {
            let error = CloudSandboxModificationApplyRequest::from_patch(
                &patch(with_env("API_KEY")),
                ModificationPolicy::NoRestart,
                "idem-1",
                |_| resolved.map(CloudSecretValue::new),
            )
            .unwrap_err();
            assert_eq!(
                error,
                CloudModificationRejection::BlankValue {
                    field: "secrets.source"
                }
            );
        }

        let parsed: CloudSandboxModificationApplyRequest = serde_json::from_value(json!({
            "idempotency_key": "idem-1",
            "secret": {"name": "API_KEY", "value": " "},
        }))
        .unwrap();
        assert_eq!(
            parsed.validate(),
            Err(CloudModificationRejection::BlankValue {
                field: "secret.value"
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
                "idempotency_key": "idem-1",
                "secret": {"name": "API_KEY", "placeholder": placeholder},
            }))
            .unwrap();
            assert_eq!(
                parsed.validate(),
                Err(CloudModificationRejection::InvalidPlaceholder {
                    field: "secret.placeholder",
                    reason,
                })
            );
        }
    }

    #[test]
    fn rejects_an_unusable_idempotency_key() {
        let too_long = "k".repeat(MAX_IDEMPOTENCY_KEY_BYTES + 1);
        for (key, reason) in [
            ("", CloudIdempotencyKeyError::Blank),
            (" \t", CloudIdempotencyKeyError::Blank),
            (
                too_long.as_str(),
                CloudIdempotencyKeyError::TooLong {
                    actual_bytes: MAX_IDEMPOTENCY_KEY_BYTES + 1,
                    max_bytes: MAX_IDEMPOTENCY_KEY_BYTES,
                },
            ),
            ("idem\u{7f}1", CloudIdempotencyKeyError::ControlCharacter),
            ("idem\n1", CloudIdempotencyKeyError::ControlCharacter),
        ] {
            let expected = CloudModificationRejection::InvalidIdempotencyKey {
                field: "idempotency_key",
                reason,
            };

            let projected = CloudSandboxModificationApplyRequest::from_patch(
                &patch(with_value("API_KEY")),
                ModificationPolicy::NoRestart,
                key,
                |_| None,
            );
            assert_eq!(projected.unwrap_err(), expected);

            let parsed: CloudSandboxModificationApplyRequest = serde_json::from_value(json!({
                "idempotency_key": key,
                "secret": {"name": "API_KEY"},
            }))
            .unwrap();
            assert_eq!(parsed.validate(), Err(expected));
        }

        // Otherwise opaque: a UUID and a maximal key both pass.
        for key in [
            "0b6f2d3e-4c8a-4f7e-9a51-2d3c4b5a6f70".to_string(),
            "k".repeat(MAX_IDEMPOTENCY_KEY_BYTES),
        ] {
            let parsed: CloudSandboxModificationApplyRequest = serde_json::from_value(json!({
                "idempotency_key": key,
                "secret": {"name": "API_KEY"},
            }))
            .unwrap();
            parsed.validate().expect("key is usable");
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
        let intent = serde_json::to_value(&planned.secret).unwrap();
        for field in ["placeholder", "allowed_hosts", "passthrough_hosts"] {
            assert_eq!(intent[field], created[field], "{field} differs from create");
        }

        // Deserialized patterns are taken as declared, as the Cloud-to-domain
        // conversion takes them.
        let parsed: CloudSandboxModificationPlanRequest = serde_json::from_value(json!({
            "secret": {
                "name": "API_KEY",
                "material": {"kind": "absent"},
                "allowed_hosts": [
                    {"type": "exact", "value": "*"},
                    {"type": "exact", "value": ""},
                    {"type": "wildcard", "value": "example.com"},
                ],
            },
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

        let rendered = CloudModificationRejection::InvalidIdempotencyKey {
            field: "idempotency_key",
            reason: CloudIdempotencyKeyError::Blank,
        }
        .to_string();
        assert_eq!(
            rendered,
            "idempotency_key: idempotency key must not be blank"
        );
    }

    /// Unknown fields are refused, never dropped: a stray `cpus` must not ride
    /// along with a rotation, and a dry run must not accept a `value`.
    #[test]
    fn requests_refuse_unknown_fields() {
        let plan = json!({
            "policy": "no_restart",
            "secret": {"name": "API_KEY", "material": {"kind": "provided"}},
        });
        serde_json::from_value::<CloudSandboxModificationPlanRequest>(plan.clone())
            .expect("the known shape parses");

        for (path, extra) in [("", "cpus"), ("secret", "value")] {
            let mut request = plan.clone();
            let target = if path.is_empty() {
                &mut request
            } else {
                &mut request["secret"]
            };
            target[extra] = json!(4);
            assert!(
                serde_json::from_value::<CloudSandboxModificationPlanRequest>(request).is_err(),
                "plan request accepted unknown `{extra}` at `{path}`"
            );
        }

        let apply = json!({
            "idempotency_key": "key-1",
            "policy": "no_restart",
            "secret": {"name": "API_KEY", "value": "sk-new"},
        });
        serde_json::from_value::<CloudSandboxModificationApplyRequest>(apply.clone())
            .expect("the known shape parses");

        for (path, extra) in [("", "cpus"), ("secret", "material")] {
            let mut request = apply.clone();
            let target = if path.is_empty() {
                &mut request
            } else {
                &mut request["secret"]
            };
            target[extra] = json!(4);
            assert!(
                serde_json::from_value::<CloudSandboxModificationApplyRequest>(request).is_err(),
                "apply request accepted unknown `{extra}` at `{path}`"
            );
        }
    }
}
