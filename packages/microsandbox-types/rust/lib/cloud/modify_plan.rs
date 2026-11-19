//! Cloud sandbox-modification response contracts.
//!
//! Both modification routes answer with a [`CloudSandboxModificationPlan`]. It
//! carries the same plan as [`SandboxModificationPlan`], spelled in snake_case
//! like the rest of the Cloud wire; each side converts to and from the local
//! plan at the Cloud boundary.

use serde::{Deserialize, Serialize};

use crate::modify::{
    ChangeKind, ConfigPlannedChange, ModificationConflict, ModificationDisposition,
    ModificationPolicy, ModificationWarning, PlannedChange, ResourceConvergenceState, ResourceKind,
    ResourceResizeStatus, SandboxModificationPlan, SecretChangeKind, SecretPlannedChange,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Response body of a Cloud modification dry run or apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSandboxModificationPlan {
    /// Sandbox being modified.
    pub sandbox: String,
    /// Sandbox status used for classification.
    pub status: String,
    /// Whether the changes were applied.
    pub applied: bool,
    /// Modification policy used to produce the plan.
    pub policy: ModificationPolicy,
    /// Planned changes.
    pub changes: Vec<CloudPlannedChange>,
    /// Conflicts that must be resolved before the patch can apply.
    pub conflicts: Vec<CloudModificationConflict>,
    /// Non-fatal warnings about the patch or current runtime capabilities.
    pub warnings: Vec<CloudModificationWarning>,
    /// Live resource resize outcomes, populated by apply when a live change ran.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resize_status: Vec<CloudResourceResizeStatus>,
}

/// One planned modification entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CloudPlannedChange {
    /// Ordinary config change.
    Config(CloudConfigPlannedChange),
    /// Secret change. Values are omitted by construction.
    Secret(CloudSecretPlannedChange),
}

/// Planned config change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudConfigPlannedChange {
    /// Config field being changed.
    pub field: String,
    /// Natural change type for table rendering.
    pub change: CloudChangeKind,
    /// Previous safe visible state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    /// New safe visible state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    /// When or whether the change can take effect.
    pub disposition: CloudModificationDisposition,
    /// Human-readable reason for this classification, when useful.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Planned secret change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSecretPlannedChange {
    /// Table field name. This is always `secret`.
    pub field: String,
    /// Stable secret identity, usually the environment variable name.
    pub name: String,
    /// Natural change type for table rendering.
    pub change: CloudSecretChangeKind,
    /// Previous guest-visible reference or placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_ref: Option<String>,
    /// New guest-visible reference or placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_ref: Option<String>,
    /// When or whether the change can take effect.
    pub disposition: CloudModificationDisposition,
    /// Allowed hosts after the requested change.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_hosts: Vec<String>,
    /// Human-readable reason for this classification, when useful.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Natural config change type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum CloudChangeKind {
    /// A field is being added.
    Added,
    /// A field is being updated.
    Updated,
    /// A field is being removed.
    Removed,
}

/// Natural secret change type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum CloudSecretChangeKind {
    /// A secret placeholder is being added.
    Added,
    /// A secret value is being rotated.
    Rotated,
    /// A secret is being removed.
    Removed,
    /// A secret is being renamed.
    Renamed,
    /// Allowed hosts are being updated.
    HostsUpdated,
    /// The guest-visible placeholder is being updated.
    PlaceholderUpdated,
}

/// When or whether a planned change can take effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum CloudModificationDisposition {
    /// Applies to the running sandbox now.
    Live,
    /// Persists and applies the next time the sandbox starts.
    NextStart,
    /// Needs a restart before it can take effect.
    RequiresRestart,
    /// Cannot be changed by `modify`.
    Unsupported,
}

/// Conflict that blocks applying a modification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudModificationConflict {
    /// Field with the conflict.
    pub field: String,
    /// Human-readable conflict description.
    pub message: String,
}

/// Warning emitted while planning a modification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudModificationWarning {
    /// Field associated with the warning.
    pub field: String,
    /// Human-readable warning description.
    pub message: String,
}

/// Status for a live resource resize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudResourceResizeStatus {
    /// Resource being resized.
    pub resource: CloudResourceKind,
    /// Requested value.
    pub requested: String,
    /// Actual value observed in the sandbox.
    pub actual: String,
    /// Enforced value.
    pub enforced: String,
    /// Convergence state.
    pub state: CloudResourceConvergenceState,
}

/// Resource kind used by live resize reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum CloudResourceKind {
    /// vCPU count.
    Cpus,
    /// Memory.
    Memory,
}

/// Convergence state for an accepted resource resize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum CloudResourceConvergenceState {
    /// The request was accepted.
    Accepted,
    /// The sandbox is still converging on the requested state.
    Converging,
    /// Desired, actual, and enforced state match.
    Applied,
    /// The guest refused or failed to cooperate.
    GuestRefused,
    /// The resize failed.
    Failed,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<SandboxModificationPlan> for CloudSandboxModificationPlan {
    fn from(plan: SandboxModificationPlan) -> Self {
        let SandboxModificationPlan {
            sandbox,
            status,
            applied,
            policy,
            changes,
            conflicts,
            warnings,
            resize_status,
        } = plan;
        Self {
            sandbox,
            status,
            applied,
            policy,
            changes: changes.into_iter().map(Into::into).collect(),
            conflicts: conflicts.into_iter().map(Into::into).collect(),
            warnings: warnings.into_iter().map(Into::into).collect(),
            resize_status: resize_status.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<CloudSandboxModificationPlan> for SandboxModificationPlan {
    fn from(plan: CloudSandboxModificationPlan) -> Self {
        let CloudSandboxModificationPlan {
            sandbox,
            status,
            applied,
            policy,
            changes,
            conflicts,
            warnings,
            resize_status,
        } = plan;
        Self {
            sandbox,
            status,
            applied,
            policy,
            changes: changes.into_iter().map(Into::into).collect(),
            conflicts: conflicts.into_iter().map(Into::into).collect(),
            warnings: warnings.into_iter().map(Into::into).collect(),
            resize_status: resize_status.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<PlannedChange> for CloudPlannedChange {
    fn from(change: PlannedChange) -> Self {
        match change {
            PlannedChange::Config(change) => Self::Config(change.into()),
            PlannedChange::Secret(change) => Self::Secret(change.into()),
        }
    }
}

impl From<CloudPlannedChange> for PlannedChange {
    fn from(change: CloudPlannedChange) -> Self {
        match change {
            CloudPlannedChange::Config(change) => Self::Config(change.into()),
            CloudPlannedChange::Secret(change) => Self::Secret(change.into()),
        }
    }
}

impl From<ConfigPlannedChange> for CloudConfigPlannedChange {
    fn from(change: ConfigPlannedChange) -> Self {
        let ConfigPlannedChange {
            field,
            change,
            before,
            after,
            disposition,
            reason,
        } = change;
        Self {
            field,
            change: change.into(),
            before,
            after,
            disposition: disposition.into(),
            reason,
        }
    }
}

impl From<CloudConfigPlannedChange> for ConfigPlannedChange {
    fn from(change: CloudConfigPlannedChange) -> Self {
        let CloudConfigPlannedChange {
            field,
            change,
            before,
            after,
            disposition,
            reason,
        } = change;
        Self {
            field,
            change: change.into(),
            before,
            after,
            disposition: disposition.into(),
            reason,
        }
    }
}

impl From<SecretPlannedChange> for CloudSecretPlannedChange {
    fn from(change: SecretPlannedChange) -> Self {
        let SecretPlannedChange {
            field,
            name,
            change,
            before_ref,
            after_ref,
            disposition,
            allow_hosts,
            reason,
        } = change;
        Self {
            field,
            name,
            change: change.into(),
            before_ref,
            after_ref,
            disposition: disposition.into(),
            allow_hosts,
            reason,
        }
    }
}

impl From<CloudSecretPlannedChange> for SecretPlannedChange {
    fn from(change: CloudSecretPlannedChange) -> Self {
        let CloudSecretPlannedChange {
            field,
            name,
            change,
            before_ref,
            after_ref,
            disposition,
            allow_hosts,
            reason,
        } = change;
        Self {
            field,
            name,
            change: change.into(),
            before_ref,
            after_ref,
            disposition: disposition.into(),
            allow_hosts,
            reason,
        }
    }
}

impl From<ChangeKind> for CloudChangeKind {
    fn from(kind: ChangeKind) -> Self {
        match kind {
            ChangeKind::Added => Self::Added,
            ChangeKind::Updated => Self::Updated,
            ChangeKind::Removed => Self::Removed,
        }
    }
}

impl From<CloudChangeKind> for ChangeKind {
    fn from(kind: CloudChangeKind) -> Self {
        match kind {
            CloudChangeKind::Added => Self::Added,
            CloudChangeKind::Updated => Self::Updated,
            CloudChangeKind::Removed => Self::Removed,
        }
    }
}

impl From<SecretChangeKind> for CloudSecretChangeKind {
    fn from(kind: SecretChangeKind) -> Self {
        match kind {
            SecretChangeKind::Added => Self::Added,
            SecretChangeKind::Rotated => Self::Rotated,
            SecretChangeKind::Removed => Self::Removed,
            SecretChangeKind::Renamed => Self::Renamed,
            SecretChangeKind::HostsUpdated => Self::HostsUpdated,
            SecretChangeKind::PlaceholderUpdated => Self::PlaceholderUpdated,
        }
    }
}

impl From<CloudSecretChangeKind> for SecretChangeKind {
    fn from(kind: CloudSecretChangeKind) -> Self {
        match kind {
            CloudSecretChangeKind::Added => Self::Added,
            CloudSecretChangeKind::Rotated => Self::Rotated,
            CloudSecretChangeKind::Removed => Self::Removed,
            CloudSecretChangeKind::Renamed => Self::Renamed,
            CloudSecretChangeKind::HostsUpdated => Self::HostsUpdated,
            CloudSecretChangeKind::PlaceholderUpdated => Self::PlaceholderUpdated,
        }
    }
}

impl From<ModificationDisposition> for CloudModificationDisposition {
    fn from(disposition: ModificationDisposition) -> Self {
        match disposition {
            ModificationDisposition::Live => Self::Live,
            ModificationDisposition::NextStart => Self::NextStart,
            ModificationDisposition::RequiresRestart => Self::RequiresRestart,
            ModificationDisposition::Unsupported => Self::Unsupported,
        }
    }
}

impl From<CloudModificationDisposition> for ModificationDisposition {
    fn from(disposition: CloudModificationDisposition) -> Self {
        match disposition {
            CloudModificationDisposition::Live => Self::Live,
            CloudModificationDisposition::NextStart => Self::NextStart,
            CloudModificationDisposition::RequiresRestart => Self::RequiresRestart,
            CloudModificationDisposition::Unsupported => Self::Unsupported,
        }
    }
}

impl From<ModificationConflict> for CloudModificationConflict {
    fn from(conflict: ModificationConflict) -> Self {
        let ModificationConflict { field, message } = conflict;
        Self { field, message }
    }
}

impl From<CloudModificationConflict> for ModificationConflict {
    fn from(conflict: CloudModificationConflict) -> Self {
        let CloudModificationConflict { field, message } = conflict;
        Self { field, message }
    }
}

impl From<ModificationWarning> for CloudModificationWarning {
    fn from(warning: ModificationWarning) -> Self {
        let ModificationWarning { field, message } = warning;
        Self { field, message }
    }
}

impl From<CloudModificationWarning> for ModificationWarning {
    fn from(warning: CloudModificationWarning) -> Self {
        let CloudModificationWarning { field, message } = warning;
        Self { field, message }
    }
}

impl From<ResourceResizeStatus> for CloudResourceResizeStatus {
    fn from(status: ResourceResizeStatus) -> Self {
        let ResourceResizeStatus {
            resource,
            requested,
            actual,
            enforced,
            state,
        } = status;
        Self {
            resource: resource.into(),
            requested,
            actual,
            enforced,
            state: state.into(),
        }
    }
}

impl From<CloudResourceResizeStatus> for ResourceResizeStatus {
    fn from(status: CloudResourceResizeStatus) -> Self {
        let CloudResourceResizeStatus {
            resource,
            requested,
            actual,
            enforced,
            state,
        } = status;
        Self {
            resource: resource.into(),
            requested,
            actual,
            enforced,
            state: state.into(),
        }
    }
}

impl From<ResourceKind> for CloudResourceKind {
    fn from(kind: ResourceKind) -> Self {
        match kind {
            ResourceKind::Cpus => Self::Cpus,
            ResourceKind::Memory => Self::Memory,
        }
    }
}

impl From<CloudResourceKind> for ResourceKind {
    fn from(kind: CloudResourceKind) -> Self {
        match kind {
            CloudResourceKind::Cpus => Self::Cpus,
            CloudResourceKind::Memory => Self::Memory,
        }
    }
}

impl From<ResourceConvergenceState> for CloudResourceConvergenceState {
    fn from(state: ResourceConvergenceState) -> Self {
        match state {
            ResourceConvergenceState::Accepted => Self::Accepted,
            ResourceConvergenceState::Converging => Self::Converging,
            ResourceConvergenceState::Applied => Self::Applied,
            ResourceConvergenceState::GuestRefused => Self::GuestRefused,
            ResourceConvergenceState::Failed => Self::Failed,
        }
    }
}

impl From<CloudResourceConvergenceState> for ResourceConvergenceState {
    fn from(state: CloudResourceConvergenceState) -> Self {
        match state {
            CloudResourceConvergenceState::Accepted => Self::Accepted,
            CloudResourceConvergenceState::Converging => Self::Converging,
            CloudResourceConvergenceState::Applied => Self::Applied,
            CloudResourceConvergenceState::GuestRefused => Self::GuestRefused,
            CloudResourceConvergenceState::Failed => Self::Failed,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn config_change(disposition: ModificationDisposition) -> PlannedChange {
        PlannedChange::Config(ConfigPlannedChange {
            field: "secret.API_KEY.policy".to_string(),
            change: ChangeKind::Updated,
            before: Some("before".to_string()),
            after: Some("after".to_string()),
            disposition,
            reason: Some("reason".to_string()),
        })
    }

    fn secret_change(change: SecretChangeKind) -> PlannedChange {
        PlannedChange::Secret(SecretPlannedChange {
            field: "secret".to_string(),
            name: "API_KEY".to_string(),
            change,
            before_ref: Some("$OLD".to_string()),
            after_ref: Some("$NEW".to_string()),
            disposition: ModificationDisposition::NextStart,
            allow_hosts: vec!["api.example.com".to_string()],
            reason: None,
        })
    }

    /// A plan that uses every variant of every enum the response carries.
    fn every_variant() -> SandboxModificationPlan {
        let dispositions = [
            ModificationDisposition::Live,
            ModificationDisposition::NextStart,
            ModificationDisposition::RequiresRestart,
            ModificationDisposition::Unsupported,
        ];
        let secret_kinds = [
            SecretChangeKind::Added,
            SecretChangeKind::Rotated,
            SecretChangeKind::Removed,
            SecretChangeKind::Renamed,
            SecretChangeKind::HostsUpdated,
            SecretChangeKind::PlaceholderUpdated,
        ];
        let mut changes: Vec<_> = dispositions.into_iter().map(config_change).collect();
        changes.extend(secret_kinds.into_iter().map(secret_change));
        for kind in [ChangeKind::Added, ChangeKind::Removed] {
            changes.push(PlannedChange::Config(ConfigPlannedChange {
                field: "label".to_string(),
                change: kind,
                before: None,
                after: None,
                disposition: ModificationDisposition::Live,
                reason: None,
            }));
        }
        let states = [
            ResourceConvergenceState::Accepted,
            ResourceConvergenceState::Converging,
            ResourceConvergenceState::Applied,
            ResourceConvergenceState::GuestRefused,
            ResourceConvergenceState::Failed,
        ];
        let resize_status = states
            .into_iter()
            .zip(
                [ResourceKind::Cpus, ResourceKind::Memory]
                    .into_iter()
                    .cycle(),
            )
            .map(|(state, resource)| ResourceResizeStatus {
                resource,
                requested: "2".to_string(),
                actual: "1".to_string(),
                enforced: "2".to_string(),
                state,
            })
            .collect();

        SandboxModificationPlan {
            sandbox: "worker".to_string(),
            status: "running".to_string(),
            applied: true,
            policy: ModificationPolicy::NextStart,
            changes,
            conflicts: vec![ModificationConflict {
                field: "secret".to_string(),
                message: "conflict".to_string(),
            }],
            warnings: vec![ModificationWarning {
                field: "secret".to_string(),
                message: "warning".to_string(),
            }],
            resize_status,
        }
    }

    #[test]
    fn the_plan_converts_both_ways_without_loss() {
        let plan = every_variant();
        let local = serde_json::to_value(&plan).unwrap();

        let cloud = CloudSandboxModificationPlan::from(plan);
        let back = SandboxModificationPlan::from(cloud.clone());

        assert_eq!(serde_json::to_value(&back).unwrap(), local);
        let reread: CloudSandboxModificationPlan =
            serde_json::from_value(serde_json::to_value(&cloud).unwrap()).unwrap();
        assert_eq!(reread, cloud);
    }

    #[test]
    fn every_wire_value_is_snake_case() {
        let cloud =
            serde_json::to_value(CloudSandboxModificationPlan::from(every_variant())).unwrap();
        let entries = cloud["changes"]
            .as_array()
            .unwrap()
            .iter()
            .chain(cloud["resize_status"].as_array().unwrap());

        for entry in entries {
            for key in ["kind", "change", "disposition", "resource", "state"] {
                if let Some(value) = entry.get(key).and_then(|value| value.as_str()) {
                    let snake = value.chars().all(|c| c.is_ascii_lowercase() || c == '_');
                    assert!(snake, "{key} = {value:?}");
                }
            }
        }
        assert_eq!(cloud["policy"], json!("next_start"));
        assert_eq!(cloud["changes"][1]["disposition"], json!("next_start"));
        assert_eq!(
            cloud["changes"][2]["disposition"],
            json!("requires_restart")
        );
        assert_eq!(cloud["changes"][8]["change"], json!("hosts_updated"));
        assert_eq!(cloud["changes"][9]["change"], json!("placeholder_updated"));
        assert_eq!(cloud["resize_status"][3]["state"], json!("guest_refused"));
    }
}
