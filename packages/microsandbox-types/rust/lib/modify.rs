//! Sandbox modification contract shared by the SDKs, the CLI, and future backends.
//!
//! These are the serializable request/response types behind `sandbox.modify()`:
//! the patch a caller submits, and the plan that classifies each change. The
//! builder and classification logic live in the SDK; this module owns only the
//! wire-shaped data so any backend (local today, cloud later) and any language
//! binding can speak the same contract.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::domain::{EnvVar, SecretSubstitution, SecretViolationAction};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A requested sandbox modification.
///
/// This type is serializable so SDKs and the CLI can share one canonical
/// contract. The only field that may carry raw secret material is the
/// per-secret `value` inside [`SecretModificationPatch`]; plans derived from
/// a patch are always value-free.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SandboxModificationPatch {
    /// Desired effective vCPU count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpus: Option<u8>,

    /// Desired boot-time maximum possible vCPU count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cpus: Option<u8>,

    /// Desired effective guest memory in MiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_mib: Option<u32>,

    /// Desired boot-time maximum hotpluggable memory in MiB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_memory_mib: Option<u32>,

    /// Desired root disk size in MiB. Managed kind: grow-only (the upper is a real ext4 image,
    /// so shrinking risks data loss and is rejected). Tmpfs kind: any direction, effective next
    /// boot. Disk-image kind: rejected (user-owned file). Accepts the legacy
    /// `oci_upper_size_mib` wire spelling.
    #[serde(alias = "oci_upper_size_mib", skip_serializing_if = "Option::is_none")]
    pub root_disk_size_mib: Option<u32>,

    /// Environment variables to set for future execs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvVar>,

    /// Environment variable keys to remove.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_remove: Vec<String>,

    /// Labels to set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<(String, String)>,

    /// Label keys to remove.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels_remove: Vec<String>,

    /// Desired working directory for future execs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,

    /// Desired secret specs, keyed by secret name. The planner diffs each
    /// spec against the existing config to infer what changes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretModificationPatch>,

    /// Secret names to remove. Removal is explicit: absence of a name from
    /// `secrets` never means removal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets_remove: Vec<String>,
}

/// Policy selected for applying or planning a modification.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ModificationPolicy {
    /// Apply only changes that can complete without restarting the running sandbox.
    #[default]
    NoRestart,

    /// Persist the desired config for the next start and leave any running VM unchanged.
    NextStart,

    /// Persist the patch and restart the sandbox if restart-required changes are present.
    Restart,
}

/// A desired secret spec inside a modification patch.
///
/// The spec is declarative: it states the target state for one secret (source
/// or value, placeholder, allowed hosts) and the planner infers the concrete
/// change — added, rotated, hosts updated, placeholder updated — by diffing
/// the spec against the existing config. Removal is explicit through
/// [`SandboxModificationPatch::secrets_remove`].
///
/// Only `value` may carry secret material, and only in-process: it is
/// [`Zeroizing`]-wrapped, redacted from `Debug` output, skipped by serde when
/// empty, and never copied into the plan.
#[derive(Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SecretModificationPatch {
    /// Stable secret identity, usually the environment variable name.
    pub name: String,

    /// Host-side source reference to resolve the value from. Mutually
    /// exclusive with `value`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SecretSource>,

    /// Raw secret value supplied by the caller, for embedders that hold only
    /// a value (e.g. from their own vault). Mutually exclusive with `source`.
    /// A value-based apply persists the value into the durable config until a
    /// later source-based rotate migrates the entry to a reference.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub value: Zeroizing<String>,

    /// Guest-visible placeholder/reference, if explicitly requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,

    /// Desired allowed host patterns. Empty means "leave unchanged" for an
    /// existing secret; a new secret needs at least one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_hosts: Vec<String>,

    /// Desired substitution locations. `None` leaves an existing policy unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub substitution: Option<SecretSubstitution>,

    /// Desired hosts allowed to receive the placeholder unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passthrough_hosts: Vec<String>,

    /// Per-secret blocking action. `None` leaves an existing policy unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violation_action: Option<SecretViolationAction>,

    /// Whether substitution requires verified TLS identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_tls_identity: Option<bool>,
}

/// Host-side source for secret material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretSource {
    /// Read the value from a host environment variable at apply time.
    Env {
        /// Host environment variable name.
        var: String,
    },

    /// Read the value from a host-side secret store reference.
    Store {
        /// Store-specific secret reference.
        reference: String,
    },
}

impl SecretSource {
    /// Creates a host environment-variable source.
    pub fn env(var: impl Into<String>) -> Self {
        Self::Env { var: var.into() }
    }
}

/// Serializable dry-run or apply plan for a sandbox modification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct SandboxModificationPlan {
    /// Sandbox being modified.
    pub sandbox: String,

    /// Sandbox status used for classification.
    pub status: String,

    /// Whether the changes were applied.
    pub applied: bool,

    /// Modification policy used to produce the plan.
    pub policy: ModificationPolicy,

    /// Planned changes.
    pub changes: Vec<PlannedChange>,

    /// Conflicts that must be resolved before the patch can apply.
    pub conflicts: Vec<ModificationConflict>,

    /// Non-fatal warnings about the patch or current runtime capabilities.
    pub warnings: Vec<ModificationWarning>,

    /// Live resource resize outcomes, populated by apply when a live change ran.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resize_status: Vec<ResourceResizeStatus>,
}

/// One planned modification entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlannedChange {
    /// Ordinary config change.
    Config(ConfigPlannedChange),

    /// Secret change. Values are omitted by construction.
    Secret(SecretPlannedChange),
}

/// Planned config change.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ConfigPlannedChange {
    /// Config field being changed.
    pub field: String,

    /// Natural change type for table rendering.
    pub change: ChangeKind,

    /// Previous safe visible state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,

    /// New safe visible state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,

    /// When or whether the change can take effect.
    pub disposition: ModificationDisposition,

    /// Human-readable reason for this classification, when useful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Planned secret change.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct SecretPlannedChange {
    /// Table field name. This is always `secret`.
    pub field: String,

    /// Stable secret identity, usually the environment variable name.
    pub name: String,

    /// Natural change type for table rendering.
    pub change: SecretChangeKind,

    /// Previous guest-visible reference or placeholder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_ref: Option<String>,

    /// New guest-visible reference or placeholder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_ref: Option<String>,

    /// When or whether the change can take effect.
    pub disposition: ModificationDisposition,

    /// Allowed hosts after the requested change.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_hosts: Vec<String>,

    /// Human-readable reason for this classification, when useful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Natural config change type for human output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    /// A field is being added.
    Added,

    /// A field is being updated.
    Updated,

    /// A field is being removed.
    Removed,
}

/// Natural secret change type for human output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum SecretChangeKind {
    /// A secret placeholder is being added.
    #[serde(rename = "added")]
    Added,

    /// A secret value is being rotated.
    #[serde(rename = "rotated")]
    Rotated,

    /// A secret is being removed.
    #[serde(rename = "removed")]
    Removed,

    /// A secret is being renamed.
    #[serde(rename = "renamed")]
    Renamed,

    /// Allowed hosts are being updated.
    #[serde(rename = "hosts updated")]
    HostsUpdated,

    /// The guest-visible placeholder is being updated.
    #[serde(rename = "placeholder updated")]
    PlaceholderUpdated,
}

/// When or whether a planned change can take effect.
///
/// Serialized as a plain string. Dispositions from newer backends decode as
/// [`Unknown`](Self::Unknown) and serialize back unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[non_exhaustive]
pub enum ModificationDisposition {
    /// Applies to the running VM now.
    #[cfg_attr(feature = "ts", ts(rename = "live"))]
    Live,

    /// Persists to desired config and applies the next time the sandbox starts.
    #[cfg_attr(feature = "ts", ts(rename = "next start"))]
    NextStart,

    /// Needs a restart before it can take effect.
    #[cfg_attr(feature = "ts", ts(rename = "requires restart"))]
    RequiresRestart,

    /// Cannot be changed by `modify`.
    #[cfg_attr(feature = "ts", ts(rename = "unsupported"))]
    Unsupported,

    /// Durably committed, but not confirmed on the running sandbox. Dry runs
    /// never report it.
    #[cfg_attr(feature = "ts", ts(rename = "unconfirmed"))]
    Unconfirmed,

    /// A disposition this release does not recognize, kept as its wire string.
    /// Deserialization never produces it for one of the known values above.
    #[cfg_attr(feature = "ts", ts(untagged))]
    Unknown(#[cfg_attr(feature = "ts", ts(type = "string & {}"))] String),
}

impl ModificationDisposition {
    /// The wire string for this disposition.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Live => "live",
            Self::NextStart => "next start",
            Self::RequiresRestart => "requires restart",
            Self::Unsupported => "unsupported",
            Self::Unconfirmed => "unconfirmed",
            Self::Unknown(value) => value,
        }
    }
}

/// Conflict that blocks applying a modification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ModificationConflict {
    /// Field with the conflict.
    pub field: String,

    /// Human-readable conflict description.
    pub message: String,
}

/// Warning emitted while planning a modification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ModificationWarning {
    /// Field associated with the warning.
    pub field: String,

    /// Human-readable warning description.
    pub message: String,
}

/// Resource kind used by live resize convergence reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// vCPU count.
    Cpus,

    /// Guest memory.
    Memory,
}

/// Runtime convergence state for an accepted resource resize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ResourceConvergenceState {
    /// The runtime accepted the request.
    Accepted,

    /// The guest and VMM are still converging on the requested state.
    Converging,

    /// Desired, actual, and enforced state match.
    Applied,

    /// The guest refused or failed to cooperate.
    GuestRefused,

    /// The resize failed.
    Failed,
}

/// Status for a live resource resize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ResourceResizeStatus {
    /// Resource being resized.
    pub resource: ResourceKind,

    /// Requested value.
    pub requested: String,

    /// Actual value observed in the guest/runtime.
    pub actual: String,

    /// Host/VMM-enforced value.
    pub enforced: String,

    /// Convergence state.
    pub state: ResourceConvergenceState,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Serialize for ModificationDisposition {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ModificationDisposition {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "live" => Self::Live,
            "next start" => Self::NextStart,
            "requires restart" => Self::RequiresRestart,
            "unsupported" => Self::Unsupported,
            "unconfirmed" => Self::Unconfirmed,
            _ => Self::Unknown(value),
        })
    }
}

// An enum schema would reject dispositions added by a newer server.
#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for ModificationDisposition {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::schema::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::Type::String)
            .description(Some(
                "When or whether a planned change can take effect. Known values are \
                 `live`, `next start`, `requires restart`, `unsupported`, and \
                 `unconfirmed`; clients must accept other values from newer servers.",
            ))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for ModificationDisposition {}

impl std::fmt::Debug for SecretModificationPatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretModificationPatch")
            .field("name", &self.name)
            .field("source", &self.source)
            .field("value", &"[REDACTED]")
            .field("placeholder", &self.placeholder)
            .field("allowed_hosts", &self.allowed_hosts)
            .finish()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_disposition_has_a_distinct_wire_value() {
        for (disposition, wire) in [
            (ModificationDisposition::Live, "live"),
            (ModificationDisposition::NextStart, "next start"),
            (ModificationDisposition::RequiresRestart, "requires restart"),
            (ModificationDisposition::Unsupported, "unsupported"),
            (ModificationDisposition::Unconfirmed, "unconfirmed"),
        ] {
            assert_eq!(disposition.as_str(), wire);
            assert_eq!(
                serde_json::to_value(&disposition).unwrap(),
                serde_json::json!(wire)
            );
            assert_eq!(
                serde_json::from_value::<ModificationDisposition>(serde_json::json!(wire)).unwrap(),
                disposition
            );
        }
    }

    #[test]
    fn unknown_disposition_round_trips_its_wire_string() {
        for wire in ["after migration", "Live", ""] {
            let disposition =
                serde_json::from_value::<ModificationDisposition>(serde_json::json!(wire)).unwrap();
            assert_eq!(
                disposition,
                ModificationDisposition::Unknown(wire.to_string())
            );
            assert_eq!(disposition.as_str(), wire);
            assert_eq!(
                serde_json::to_value(&disposition).unwrap(),
                serde_json::json!(wire)
            );
        }
        assert!(serde_json::from_value::<ModificationDisposition>(serde_json::json!(1)).is_err());
    }

    #[test]
    fn plan_keeps_unknown_dispositions() {
        let plan: SandboxModificationPlan = serde_json::from_value(serde_json::json!({
            "sandbox": "api",
            "status": "running",
            "applied": true,
            "policy": "no_restart",
            "changes": [{
                "kind": "secret",
                "field": "secret",
                "name": "API_KEY",
                "change": "rotated",
                "before_ref": null,
                "after_ref": null,
                "disposition": "after migration",
                "reason": null
            }],
            "conflicts": [],
            "warnings": []
        }))
        .unwrap();
        let PlannedChange::Secret(change) = &plan.changes[0] else {
            panic!("expected a secret change: {:?}", plan.changes[0]);
        };
        assert_eq!(
            change.disposition,
            ModificationDisposition::Unknown("after migration".into())
        );
        assert_eq!(
            serde_json::to_value(&plan).unwrap()["changes"][0]["disposition"],
            "after migration"
        );
    }

    #[cfg(feature = "utoipa")]
    #[test]
    fn disposition_schema_accepts_any_string() {
        use utoipa::PartialSchema;

        let schema = serde_json::to_value(ModificationDisposition::schema()).unwrap();
        assert_eq!(schema["type"], "string");
        assert!(schema.get("enum").is_none());
    }
}
