//! Sandbox modification planning.

use std::sync::Arc;

use sea_orm::{ActiveModelTrait, Set};
use serde::{Deserialize, Serialize};

use crate::MicrosandboxResult;
use crate::backend::Backend;
use crate::db::entity::sandbox as sandbox_entity;
use crate::size::Mebibytes;

use super::{SandboxConfig, SandboxStatus};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const LIVE_RESIZE_UNAVAILABLE: &str =
    "live CPU and memory resize are not available in this runtime yet";
const LIVE_SECRET_RECONFIGURE_UNAVAILABLE: &str =
    "live secret reconfiguration is not available in this runtime yet";
const SECRET_FIELD: &str = "secret";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder returned by [`Sandbox::modify`](super::Sandbox::modify).
///
/// The builder is intentionally plan-first. Phase 3 exposes the canonical SDK
/// patch and dry-run contract; later phases can wire the same patch type into
/// persistence, live runtime mutation, and restart-backed apply.
#[derive(Clone)]
pub struct SandboxModificationBuilder {
    backend: Arc<dyn Backend>,
    name: String,
    patch: SandboxModificationPatch,
    policy: ModificationPolicy,
}

/// A requested sandbox modification.
///
/// This type is serializable so SDKs and the CLI can share one canonical
/// contract. It does not contain raw secret values.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

    /// Requested secret modifications.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretModificationPatch>,
}

/// Policy selected for applying or planning a modification.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
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

/// A requested secret modification.
///
/// The patch records identity, host-side source references, placeholders, and
/// allowed hosts. It must never carry the actual secret value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretModificationPatch {
    /// Stable secret identity, usually the environment variable name.
    pub name: String,

    /// Requested secret operation.
    pub operation: SecretPatchOperation,

    /// Host-side source reference for add or rotate operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SecretSource>,

    /// Guest-visible placeholder/reference, if explicitly requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,

    /// Allowed host patterns associated with this request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_hosts: Vec<String>,
}

/// Secret operation requested by a modification patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretPatchOperation {
    /// Add the secret if absent, or rotate it if already present.
    Upsert,

    /// Rotate an existing secret value.
    Rotate,

    /// Remove a secret.
    Remove,

    /// Update the allowed hosts for an existing secret.
    UpdateHosts,

    /// Update the guest-visible placeholder for an existing secret.
    UpdatePlaceholder,
}

/// Host-side source for secret material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Serializable dry-run or apply plan for a sandbox modification.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

struct DesiredResources {
    max_cpus: u8,
    max_memory_mib: u32,
}

/// One planned modification entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlannedChange {
    /// Ordinary config change.
    Config(ConfigPlannedChange),

    /// Secret change. Values are omitted by construction.
    Secret(SecretPlannedChange),
}

/// Planned config change.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModificationDisposition {
    /// Applies to the running VM now.
    #[serde(rename = "live")]
    Live,

    /// Persists to desired config and applies the next time the sandbox starts.
    #[serde(rename = "next start")]
    NextStart,

    /// Needs a restart before it can take effect.
    #[serde(rename = "requires restart")]
    RequiresRestart,

    /// Cannot be changed by `modify`.
    #[serde(rename = "unsupported")]
    Unsupported,
}

/// Conflict that blocks applying a modification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModificationConflict {
    /// Field with the conflict.
    pub field: String,

    /// Human-readable conflict description.
    pub message: String,
}

/// Warning emitted while planning a modification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModificationWarning {
    /// Field associated with the warning.
    pub field: String,

    /// Human-readable warning description.
    pub message: String,
}

/// Resource kind used by live resize convergence reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// vCPU count.
    Cpus,

    /// Guest memory.
    Memory,
}

/// Runtime convergence state for an accepted resource resize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

struct ExistingSecret {
    placeholder: String,
    allowed_hosts: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxModificationBuilder {
    pub(crate) fn new(backend: Arc<dyn Backend>, name: impl Into<String>) -> Self {
        Self {
            backend,
            name: name.into(),
            patch: SandboxModificationPatch::default(),
            policy: ModificationPolicy::NoRestart,
        }
    }

    /// Set the desired effective vCPU count.
    pub fn cpus(mut self, cpus: u8) -> Self {
        self.patch.cpus = Some(cpus);
        self
    }

    /// Set the desired boot-time maximum possible vCPU count.
    pub fn max_cpus(mut self, max_cpus: u8) -> Self {
        self.patch.max_cpus = Some(max_cpus);
        self
    }

    /// Set the desired effective guest memory.
    pub fn memory(mut self, size: impl Into<Mebibytes>) -> Self {
        self.patch.memory_mib = Some(size.into().as_u32());
        self
    }

    /// Set the desired effective guest memory in MiB.
    pub fn memory_mib(mut self, memory_mib: u32) -> Self {
        self.patch.memory_mib = Some(memory_mib);
        self
    }

    /// Set the desired boot-time maximum hotpluggable memory.
    pub fn max_memory(mut self, size: impl Into<Mebibytes>) -> Self {
        self.patch.max_memory_mib = Some(size.into().as_u32());
        self
    }

    /// Set the desired boot-time maximum hotpluggable memory in MiB.
    pub fn max_memory_mib(mut self, max_memory_mib: u32) -> Self {
        self.patch.max_memory_mib = Some(max_memory_mib);
        self
    }

    /// Persist the requested changes for the next start.
    pub fn next_start(mut self) -> Self {
        self.policy = ModificationPolicy::NextStart;
        self
    }

    /// Plan the requested changes under restart-backed apply semantics.
    pub fn restart(mut self) -> Self {
        self.policy = ModificationPolicy::Restart;
        self
    }

    /// Add or rotate a secret from a host environment variable.
    ///
    /// The environment variable name is recorded as a source reference only;
    /// its value is not read or stored by the plan.
    pub fn secret_from_env(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        self.patch.secrets.push(SecretModificationPatch {
            source: Some(SecretSource::Env { var: name.clone() }),
            name,
            operation: SecretPatchOperation::Upsert,
            placeholder: None,
            allowed_hosts: Vec::new(),
        });
        self
    }

    /// Rotate an existing secret from a host environment variable.
    ///
    /// The environment variable name is recorded as a source reference only;
    /// its value is not read or stored by the plan.
    pub fn rotate_secret_from_env(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        self.patch.secrets.push(SecretModificationPatch {
            source: Some(SecretSource::Env { var: name.clone() }),
            name,
            operation: SecretPatchOperation::Rotate,
            placeholder: None,
            allowed_hosts: Vec::new(),
        });
        self
    }

    /// Remove a secret.
    pub fn remove_secret(mut self, name: impl Into<String>) -> Self {
        self.patch.secrets.push(SecretModificationPatch {
            source: None,
            name: name.into(),
            operation: SecretPatchOperation::Remove,
            placeholder: None,
            allowed_hosts: Vec::new(),
        });
        self
    }

    /// Set the guest-visible placeholder for a secret.
    pub fn secret_placeholder(
        mut self,
        name: impl Into<String>,
        placeholder: impl Into<String>,
    ) -> Self {
        self.patch.secrets.push(SecretModificationPatch {
            source: None,
            name: name.into(),
            operation: SecretPatchOperation::UpdatePlaceholder,
            placeholder: Some(placeholder.into()),
            allowed_hosts: Vec::new(),
        });
        self
    }

    /// Add an allowed host to a secret modification.
    pub fn allow_secret_host(mut self, name: impl Into<String>, host: impl Into<String>) -> Self {
        let name = name.into();
        let host = host.into();
        if let Some(secret) =
            self.patch.secrets.iter_mut().rev().find(|secret| {
                secret.name == name && secret.operation != SecretPatchOperation::Remove
            })
        {
            secret.allowed_hosts.push(host);
            return self;
        }

        self.patch.secrets.push(SecretModificationPatch {
            source: None,
            name,
            operation: SecretPatchOperation::UpdateHosts,
            placeholder: None,
            allowed_hosts: vec![host],
        });
        self
    }

    /// Return the accumulated patch.
    pub fn patch(&self) -> &SandboxModificationPatch {
        &self.patch
    }

    /// Compute a modification plan without applying anything.
    pub async fn dry_run(self) -> MicrosandboxResult<SandboxModificationPlan> {
        crate::experimental::require_modify("sandbox modify")?;
        let handle = self
            .backend
            .sandboxes()
            .get(self.backend.clone(), &self.name)
            .await?;
        let status = handle.status_snapshot();
        let config = handle.config()?;
        let active = handle.active_config().ok().flatten();
        Ok(build_plan(
            self.name,
            status,
            &config,
            active.as_ref(),
            self.patch,
            self.policy,
        ))
    }

    /// Apply supported changes atomically.
    ///
    /// Live-capable changes apply to the running VM first (CPU count through
    /// guest CPU hotplug when the target fits inside the active `max_cpus`);
    /// the desired config is persisted only after the live step succeeds. For
    /// stopped sandboxes or `next_start` requests, changes persist for the next
    /// start. When the policy is `restart`, the existing stop/start lifecycle
    /// path makes restart-required changes active. Live memory resize waits on
    /// virtio-mem; secret store/runtime writes wait on the secret contract.
    pub async fn apply(self) -> MicrosandboxResult<SandboxModificationPlan> {
        crate::experimental::require_modify("sandbox modify")?;
        let handle = self
            .backend
            .sandboxes()
            .get(self.backend.clone(), &self.name)
            .await?;
        let status = handle.status_snapshot();
        let mut config = handle.config()?;
        let active = handle.active_config().ok().flatten();
        let mut plan = build_plan(
            self.name,
            status,
            &config,
            active.as_ref(),
            self.patch.clone(),
            self.policy,
        );

        validate_apply_supported(&plan)?;
        let restart_required = plan_requires_restart(&plan) && running_status(status);
        if restart_required {
            handle.stop().await?;
        }
        if !restart_required && let Some(target) = live_cpu_target(&plan, &self.patch) {
            let resized = handle.connect().await?.resize_cpus(target).await?;
            plan.resize_status.push(ResourceResizeStatus {
                resource: ResourceKind::Cpus,
                requested: target.to_string(),
                actual: resized.online.to_string(),
                enforced: target.to_string(),
                state: if resized.online == target {
                    ResourceConvergenceState::Applied
                } else {
                    ResourceConvergenceState::GuestRefused
                },
            });
            // The running VM changed: refresh the active snapshot with the CPU
            // count the guest converged to, so inspect does not report the
            // already-live change as pending for the next start.
            if let Some(mut active) = active.clone() {
                active.spec.resources.cpus = resized.online;
                persist_active_config(&self.backend, &handle, &active).await?;
            }
        }
        if !plan.changes.is_empty() {
            apply_patch_to_config(&mut config, &self.patch);
            persist_config(&self.backend, &handle, &config).await?;
        }
        if restart_required {
            start_after_modify(&handle).await?;
        }
        plan.applied = true;
        Ok(plan)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn build_plan(
    name: String,
    status: SandboxStatus,
    config: &SandboxConfig,
    active: Option<&SandboxConfig>,
    patch: SandboxModificationPatch,
    policy: ModificationPolicy,
) -> SandboxModificationPlan {
    let mut changes = Vec::new();
    let mut conflicts = Vec::new();
    let mut warnings = Vec::new();

    push_resource_changes(
        status,
        config,
        active,
        &patch,
        policy,
        &mut changes,
        &mut warnings,
    );
    push_secret_changes(status, config, &patch, policy, &mut changes, &mut warnings);
    push_resource_conflicts(config, &patch, &mut conflicts);

    SandboxModificationPlan {
        sandbox: name,
        status: status_name(status).to_string(),
        applied: false,
        policy,
        changes,
        conflicts,
        warnings,
        resize_status: Vec::new(),
    }
}

/// The live CPU target, when the plan classified the `cpus` change as live.
fn live_cpu_target(plan: &SandboxModificationPlan, patch: &SandboxModificationPatch) -> Option<u8> {
    let live_cpus = plan.changes.iter().any(|change| {
        matches!(
            change,
            PlannedChange::Config(change)
                if change.field == "cpus"
                    && matches!(change.disposition, ModificationDisposition::Live)
        )
    });
    if live_cpus { patch.cpus } else { None }
}

fn validate_apply_supported(plan: &SandboxModificationPlan) -> MicrosandboxResult<()> {
    if let Some(conflict) = plan.conflicts.first() {
        return Err(crate::MicrosandboxError::Custom(format!(
            "cannot apply modification: {}",
            conflict.message
        )));
    }

    for change in &plan.changes {
        match change {
            PlannedChange::Config(change) => {
                if matches!(change.disposition, ModificationDisposition::Unsupported) {
                    return Err(crate::MicrosandboxError::Custom(format!(
                        "cannot apply modification: {} is unsupported",
                        change.field
                    )));
                }
                if matches!(change.disposition, ModificationDisposition::RequiresRestart) {
                    if plan.policy == ModificationPolicy::Restart {
                        continue;
                    }
                    return Err(crate::MicrosandboxError::Custom(format!(
                        "cannot apply modification: {} requires restart",
                        change.field
                    )));
                }
            }
            PlannedChange::Secret(_) => {
                return Err(crate::MicrosandboxError::Unsupported {
                    feature: "modify apply for secrets".into(),
                    available_when: "after the secret runtime and store contract lands".into(),
                });
            }
        }
    }

    Ok(())
}

fn plan_requires_restart(plan: &SandboxModificationPlan) -> bool {
    plan.changes.iter().any(|change| match change {
        PlannedChange::Config(change) => {
            matches!(change.disposition, ModificationDisposition::RequiresRestart)
        }
        PlannedChange::Secret(change) => {
            matches!(change.disposition, ModificationDisposition::RequiresRestart)
        }
    })
}

fn apply_patch_to_config(config: &mut SandboxConfig, patch: &SandboxModificationPatch) {
    if let Some(cpus) = patch.cpus {
        config.spec.resources.cpus = cpus;
    }
    if let Some(max_cpus) = patch.max_cpus {
        config.spec.resources.max_cpus = max_cpus;
    }
    if config.spec.resources.max_cpus < config.spec.resources.cpus {
        config.spec.resources.max_cpus = config.spec.resources.cpus;
    }
    if let Some(memory_mib) = patch.memory_mib {
        config.spec.resources.memory_mib = memory_mib;
    }
    if let Some(max_memory_mib) = patch.max_memory_mib {
        config.spec.resources.max_memory_mib = max_memory_mib;
    }
    if config.spec.resources.max_memory_mib < config.spec.resources.memory_mib {
        config.spec.resources.max_memory_mib = config.spec.resources.memory_mib;
    }
}

async fn persist_config(
    backend: &Arc<dyn Backend>,
    handle: &super::SandboxHandle,
    config: &SandboxConfig,
) -> MicrosandboxResult<()> {
    let local = handle
        .local()
        .ok_or_else(|| crate::MicrosandboxError::Unsupported {
            feature: "modify apply on cloud".into(),
            available_when: "when cloud modify lands".into(),
        })?;
    let local_backend =
        backend
            .as_local()
            .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                feature: "modify apply on cloud".into(),
                available_when: "when cloud modify lands".into(),
            })?;

    let config_json = serde_json::to_string(config)?;
    sandbox_entity::ActiveModel {
        id: Set(local.db_id),
        config: Set(config_json),
        updated_at: Set(Some(chrono::Utc::now().naive_utc())),
        ..Default::default()
    }
    .update(local_backend.db().await?.write())
    .await?;

    Ok(())
}

async fn persist_active_config(
    backend: &Arc<dyn Backend>,
    handle: &super::SandboxHandle,
    active: &SandboxConfig,
) -> MicrosandboxResult<()> {
    let local = handle
        .local()
        .ok_or_else(|| crate::MicrosandboxError::Unsupported {
            feature: "modify apply on cloud".into(),
            available_when: "when cloud modify lands".into(),
        })?;
    let local_backend =
        backend
            .as_local()
            .ok_or_else(|| crate::MicrosandboxError::Unsupported {
                feature: "modify apply on cloud".into(),
                available_when: "when cloud modify lands".into(),
            })?;

    let active_json = serde_json::to_string(active)?;
    sandbox_entity::ActiveModel {
        id: Set(local.db_id),
        active_config: Set(Some(active_json)),
        updated_at: Set(Some(chrono::Utc::now().naive_utc())),
        ..Default::default()
    }
    .update(local_backend.db().await?.write())
    .await?;

    Ok(())
}

async fn start_after_modify(handle: &super::SandboxHandle) -> MicrosandboxResult<()> {
    let sandbox = handle.refresh().await?.start_detached().await?;
    sandbox.detach().await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_resource_changes(
    status: SandboxStatus,
    config: &SandboxConfig,
    active: Option<&SandboxConfig>,
    patch: &SandboxModificationPatch,
    policy: ModificationPolicy,
    changes: &mut Vec<PlannedChange>,
    warnings: &mut Vec<ModificationWarning>,
) {
    let resources = config.spec.resources;
    let desired = desired_resources(config, patch);

    if let Some(cpus) = patch.cpus
        && cpus != resources.cpus
    {
        // CPUs change live when the target fits inside the capacity the running
        // VM actually booted with. The active config snapshot is the authority;
        // older runtimes without one classify as restart-required.
        let active_max_cpus = active.map(|active| active.spec.resources.max_cpus);
        let live = active_max_cpus.is_some_and(|max| cpus <= max);
        let reason = match (resource_disposition(status, policy, live), active_max_cpus) {
            (ModificationDisposition::RequiresRestart, Some(max)) if cpus > max => Some(format!(
                "cpus {cpus} exceeds the active max capacity {max}; restart with a larger max_cpus"
            )),
            _ => resource_reason(status, policy, live),
        };
        changes.push(PlannedChange::Config(ConfigPlannedChange {
            field: "cpus".to_string(),
            change: ChangeKind::Updated,
            before: Some(resources.cpus.to_string()),
            after: Some(cpus.to_string()),
            disposition: resource_disposition(status, policy, live),
            reason,
        }));
        push_live_resize_warning("cpus", status, policy, live, warnings);
    }

    if desired.max_cpus != resources.max_cpus
        && (patch.max_cpus.is_some() || desired.max_cpus > resources.max_cpus)
    {
        changes.push(PlannedChange::Config(ConfigPlannedChange {
            field: "max_cpus".to_string(),
            change: ChangeKind::Updated,
            before: Some(resources.max_cpus.to_string()),
            after: Some(desired.max_cpus.to_string()),
            disposition: boot_capacity_disposition(status, policy),
            reason: boot_capacity_reason(status, policy, "max_cpus"),
        }));
    }

    if let Some(memory_mib) = patch.memory_mib
        && memory_mib != resources.memory_mib
    {
        changes.push(PlannedChange::Config(ConfigPlannedChange {
            field: "memory".to_string(),
            change: ChangeKind::Updated,
            before: Some(format_mib(resources.memory_mib)),
            after: Some(format_mib(memory_mib)),
            disposition: resource_disposition(status, policy, false),
            reason: resource_reason(status, policy, false),
        }));
        push_live_resize_warning("memory", status, policy, false, warnings);
    }

    if desired.max_memory_mib != resources.max_memory_mib
        && (patch.max_memory_mib.is_some() || desired.max_memory_mib > resources.max_memory_mib)
    {
        changes.push(PlannedChange::Config(ConfigPlannedChange {
            field: "max_memory".to_string(),
            change: ChangeKind::Updated,
            before: Some(format_mib(resources.max_memory_mib)),
            after: Some(format_mib(desired.max_memory_mib)),
            disposition: boot_capacity_disposition(status, policy),
            reason: boot_capacity_reason(status, policy, "max_memory"),
        }));
    }
}

fn push_secret_changes(
    status: SandboxStatus,
    config: &SandboxConfig,
    patch: &SandboxModificationPatch,
    policy: ModificationPolicy,
    changes: &mut Vec<PlannedChange>,
    warnings: &mut Vec<ModificationWarning>,
) {
    for secret in &patch.secrets {
        let existing = existing_secret(config, &secret.name);
        let change = secret_change_kind(secret.operation, existing.is_some());
        let before_ref = secret_before_ref(secret, existing.as_ref());
        let after_ref = secret_after_ref(secret, existing.as_ref());
        let disposition = secret_disposition(status, policy, change, false);
        let reason = secret_reason(status, policy, change, false);

        if matches!(disposition, ModificationDisposition::RequiresRestart)
            && running_status(status)
            && matches!(
                change,
                SecretChangeKind::Rotated
                    | SecretChangeKind::Removed
                    | SecretChangeKind::HostsUpdated
            )
        {
            warnings.push(ModificationWarning {
                field: SECRET_FIELD.to_string(),
                message: LIVE_SECRET_RECONFIGURE_UNAVAILABLE.to_string(),
            });
        }

        changes.push(PlannedChange::Secret(SecretPlannedChange {
            field: SECRET_FIELD.to_string(),
            name: secret.name.clone(),
            change,
            before_ref,
            after_ref,
            disposition,
            allow_hosts: if secret.allowed_hosts.is_empty() {
                existing
                    .as_ref()
                    .map(|secret| secret.allowed_hosts.clone())
                    .unwrap_or_default()
            } else {
                secret.allowed_hosts.clone()
            },
            reason,
        }));
    }
}

fn push_resource_conflicts(
    config: &SandboxConfig,
    patch: &SandboxModificationPatch,
    conflicts: &mut Vec<ModificationConflict>,
) {
    if matches!(patch.cpus, Some(0)) {
        conflicts.push(ModificationConflict {
            field: "cpus".to_string(),
            message: "cpus must be greater than 0".to_string(),
        });
    }
    if matches!(patch.memory_mib, Some(0)) {
        conflicts.push(ModificationConflict {
            field: "memory".to_string(),
            message: "memory must be greater than 0".to_string(),
        });
    }
    if matches!(patch.max_cpus, Some(0)) {
        conflicts.push(ModificationConflict {
            field: "max_cpus".to_string(),
            message: "max_cpus must be greater than 0".to_string(),
        });
    }
    if matches!(patch.max_memory_mib, Some(0)) {
        conflicts.push(ModificationConflict {
            field: "max_memory".to_string(),
            message: "max_memory must be greater than 0".to_string(),
        });
    }

    let desired_cpus = patch.cpus.unwrap_or(config.spec.resources.cpus);
    if let Some(max_cpus) = patch.max_cpus
        && max_cpus < desired_cpus
    {
        conflicts.push(ModificationConflict {
            field: "max_cpus".to_string(),
            message: format!("max_cpus {max_cpus} is lower than requested cpus {desired_cpus}"),
        });
    }

    let desired_memory_mib = patch.memory_mib.unwrap_or(config.spec.resources.memory_mib);
    if let Some(max_memory_mib) = patch.max_memory_mib
        && max_memory_mib < desired_memory_mib
    {
        conflicts.push(ModificationConflict {
            field: "max_memory".to_string(),
            message: format!(
                "max_memory {} is lower than requested memory {}",
                format_mib(max_memory_mib),
                format_mib(desired_memory_mib)
            ),
        });
    }
}

fn desired_resources(config: &SandboxConfig, patch: &SandboxModificationPatch) -> DesiredResources {
    let resources = config.spec.resources;
    let cpus = patch.cpus.unwrap_or(resources.cpus);
    let memory_mib = patch.memory_mib.unwrap_or(resources.memory_mib);
    let max_cpus = patch.max_cpus.unwrap_or(resources.max_cpus).max(cpus);
    let max_memory_mib = patch
        .max_memory_mib
        .unwrap_or(resources.max_memory_mib)
        .max(memory_mib);

    DesiredResources {
        max_cpus,
        max_memory_mib,
    }
}

fn resource_disposition(
    status: SandboxStatus,
    policy: ModificationPolicy,
    live_resize_supported: bool,
) -> ModificationDisposition {
    if policy == ModificationPolicy::NextStart || stopped_status(status) {
        return ModificationDisposition::NextStart;
    }
    if transitional_status(status) {
        return ModificationDisposition::Unsupported;
    }
    if running_status(status) && live_resize_supported {
        return ModificationDisposition::Live;
    }
    ModificationDisposition::RequiresRestart
}

fn resource_reason(
    status: SandboxStatus,
    policy: ModificationPolicy,
    live_resize_supported: bool,
) -> Option<String> {
    match resource_disposition(status, policy, live_resize_supported) {
        ModificationDisposition::RequiresRestart if running_status(status) => {
            Some(LIVE_RESIZE_UNAVAILABLE.to_string())
        }
        ModificationDisposition::Unsupported => Some(format!(
            "cannot modify while sandbox is {}",
            status_name(status)
        )),
        _ => None,
    }
}

fn boot_capacity_disposition(
    status: SandboxStatus,
    policy: ModificationPolicy,
) -> ModificationDisposition {
    if policy == ModificationPolicy::NextStart || stopped_status(status) {
        return ModificationDisposition::NextStart;
    }
    if transitional_status(status) {
        return ModificationDisposition::Unsupported;
    }
    ModificationDisposition::RequiresRestart
}

fn boot_capacity_reason(
    status: SandboxStatus,
    policy: ModificationPolicy,
    field: &str,
) -> Option<String> {
    match boot_capacity_disposition(status, policy) {
        ModificationDisposition::RequiresRestart => Some(format!(
            "{field} defines boot-time capacity and cannot be raised live"
        )),
        ModificationDisposition::Unsupported => Some(format!(
            "cannot modify while sandbox is {}",
            status_name(status)
        )),
        _ => None,
    }
}

fn secret_disposition(
    status: SandboxStatus,
    policy: ModificationPolicy,
    change: SecretChangeKind,
    live_secret_reconfigure_supported: bool,
) -> ModificationDisposition {
    if policy == ModificationPolicy::NextStart || stopped_status(status) {
        return ModificationDisposition::NextStart;
    }
    if transitional_status(status) {
        return ModificationDisposition::Unsupported;
    }
    if !running_status(status) {
        return ModificationDisposition::RequiresRestart;
    }

    match change {
        SecretChangeKind::Rotated | SecretChangeKind::Removed | SecretChangeKind::HostsUpdated
            if live_secret_reconfigure_supported =>
        {
            ModificationDisposition::Live
        }
        _ => ModificationDisposition::RequiresRestart,
    }
}

fn secret_reason(
    status: SandboxStatus,
    policy: ModificationPolicy,
    change: SecretChangeKind,
    live_secret_reconfigure_supported: bool,
) -> Option<String> {
    match secret_disposition(status, policy, change, live_secret_reconfigure_supported) {
        ModificationDisposition::RequiresRestart if running_status(status) => match change {
            SecretChangeKind::Added
            | SecretChangeKind::Renamed
            | SecretChangeKind::PlaceholderUpdated => Some(
                "guest-visible secret placeholders cannot be introduced into existing processes"
                    .to_string(),
            ),
            SecretChangeKind::Rotated
            | SecretChangeKind::Removed
            | SecretChangeKind::HostsUpdated => {
                Some(LIVE_SECRET_RECONFIGURE_UNAVAILABLE.to_string())
            }
        },
        ModificationDisposition::Unsupported => Some(format!(
            "cannot modify while sandbox is {}",
            status_name(status)
        )),
        _ => None,
    }
}

fn secret_change_kind(operation: SecretPatchOperation, existing: bool) -> SecretChangeKind {
    match operation {
        SecretPatchOperation::Upsert if existing => SecretChangeKind::Rotated,
        SecretPatchOperation::Upsert => SecretChangeKind::Added,
        SecretPatchOperation::Rotate => SecretChangeKind::Rotated,
        SecretPatchOperation::Remove => SecretChangeKind::Removed,
        SecretPatchOperation::UpdateHosts => SecretChangeKind::HostsUpdated,
        SecretPatchOperation::UpdatePlaceholder => SecretChangeKind::PlaceholderUpdated,
    }
}

fn secret_before_ref(
    patch: &SecretModificationPatch,
    existing: Option<&ExistingSecret>,
) -> Option<String> {
    match patch.operation {
        SecretPatchOperation::Upsert if existing.is_none() => None,
        _ => existing
            .map(|secret| secret.placeholder.clone())
            .or_else(|| Some(default_secret_ref(&patch.name))),
    }
}

fn secret_after_ref(
    patch: &SecretModificationPatch,
    existing: Option<&ExistingSecret>,
) -> Option<String> {
    match patch.operation {
        SecretPatchOperation::Remove => None,
        SecretPatchOperation::UpdatePlaceholder => patch.placeholder.clone(),
        _ => patch
            .placeholder
            .clone()
            .or_else(|| existing.map(|secret| secret.placeholder.clone()))
            .or_else(|| Some(default_secret_ref(&patch.name))),
    }
}

fn existing_secret(config: &SandboxConfig, name: &str) -> Option<ExistingSecret> {
    existing_secret_from_network_config(config, name)
}

#[cfg(feature = "net")]
fn existing_secret_from_network_config(
    config: &SandboxConfig,
    name: &str,
) -> Option<ExistingSecret> {
    let network = config.local_network_config().ok()?;
    network
        .secrets
        .secrets
        .into_iter()
        .find(|secret| secret.env_var == name)
        .map(|secret| ExistingSecret {
            placeholder: secret.placeholder,
            allowed_hosts: secret
                .allowed_hosts
                .into_iter()
                .map(format_host_pattern)
                .collect(),
        })
}

#[cfg(not(feature = "net"))]
fn existing_secret_from_network_config(
    _config: &SandboxConfig,
    _name: &str,
) -> Option<ExistingSecret> {
    None
}

#[cfg(feature = "net")]
fn format_host_pattern(host: microsandbox_network::secrets::config::HostPattern) -> String {
    match host {
        microsandbox_network::secrets::config::HostPattern::Exact(host) => host,
        microsandbox_network::secrets::config::HostPattern::Wildcard(host) => host,
        microsandbox_network::secrets::config::HostPattern::Any => "*".to_string(),
    }
}

fn push_live_resize_warning(
    field: &str,
    status: SandboxStatus,
    policy: ModificationPolicy,
    live_resize_supported: bool,
    warnings: &mut Vec<ModificationWarning>,
) {
    if running_status(status) && policy != ModificationPolicy::NextStart && !live_resize_supported {
        warnings.push(ModificationWarning {
            field: field.to_string(),
            message: LIVE_RESIZE_UNAVAILABLE.to_string(),
        });
    }
}

fn stopped_status(status: SandboxStatus) -> bool {
    matches!(
        status,
        SandboxStatus::Created | SandboxStatus::Stopped | SandboxStatus::Crashed
    )
}

fn running_status(status: SandboxStatus) -> bool {
    matches!(status, SandboxStatus::Running | SandboxStatus::Draining)
}

fn transitional_status(status: SandboxStatus) -> bool {
    matches!(status, SandboxStatus::Starting | SandboxStatus::Paused)
}

fn status_name(status: SandboxStatus) -> &'static str {
    match status {
        SandboxStatus::Created => "created",
        SandboxStatus::Starting => "starting",
        SandboxStatus::Running => "running",
        SandboxStatus::Draining => "draining",
        SandboxStatus::Paused => "paused",
        SandboxStatus::Stopped => "stopped",
        SandboxStatus::Crashed => "crashed",
    }
}

fn default_secret_ref(name: &str) -> String {
    format!("${name}")
}

fn format_mib(mib: u32) -> String {
    if mib >= 1024 && mib.is_multiple_of(1024) {
        format!("{} GiB", mib / 1024)
    } else {
        format!("{mib} MiB")
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn config(cpus: u8, memory_mib: u32) -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.spec.name = "api".to_string();
        config.spec.resources.cpus = cpus;
        config.spec.resources.memory_mib = memory_mib;
        config.spec.resources.max_cpus = cpus;
        config.spec.resources.max_memory_mib = memory_mib;
        config
    }

    #[test]
    fn running_resource_changes_require_restart_until_live_resize_lands() {
        let patch = SandboxModificationPatch {
            cpus: Some(4),
            memory_mib: Some(4096),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config(2, 1024),
            None,
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(plan.changes.len(), 4);
        for change in plan.changes {
            let PlannedChange::Config(change) = change else {
                panic!("expected config change");
            };
            assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
            match change.field.as_str() {
                "cpus" | "memory" => {
                    assert_eq!(change.reason.as_deref(), Some(LIVE_RESIZE_UNAVAILABLE));
                }
                "max_cpus" | "max_memory" => {
                    assert!(
                        change
                            .reason
                            .as_deref()
                            .is_some_and(|reason| { reason.contains("boot-time capacity") })
                    );
                }
                field => panic!("unexpected field {field}"),
            }
        }
    }

    #[test]
    fn running_cpus_within_active_capacity_classify_live() {
        // The sandbox booted with reserved capacity: desired and active agree
        // on max_cpus 8 while only 2 CPUs are online.
        let mut desired = config(2, 1024);
        desired.spec.resources.max_cpus = 8;
        let active = desired.clone();
        let patch = SandboxModificationPatch {
            cpus: Some(4),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &desired,
            Some(&active),
            patch.clone(),
            ModificationPolicy::NoRestart,
        );

        let PlannedChange::Config(change) = &plan.changes[0] else {
            panic!("expected config change");
        };
        assert_eq!(change.field, "cpus");
        assert_eq!(change.disposition, ModificationDisposition::Live);
        assert!(change.reason.is_none());
        assert!(validate_apply_supported(&plan).is_ok());
        assert_eq!(live_cpu_target(&plan, &patch), Some(4));
    }

    #[test]
    fn running_cpus_above_active_capacity_require_restart() {
        let mut active = config(2, 1024);
        active.spec.resources.max_cpus = 8;
        let patch = SandboxModificationPatch {
            cpus: Some(12),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config(2, 1024),
            Some(&active),
            patch.clone(),
            ModificationPolicy::NoRestart,
        );

        let PlannedChange::Config(change) = &plan.changes[0] else {
            panic!("expected config change");
        };
        assert_eq!(change.field, "cpus");
        assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
        assert!(
            change
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("exceeds the active max capacity 8"))
        );
        assert_eq!(live_cpu_target(&plan, &patch), None);
    }

    #[test]
    fn restart_policy_allows_restart_required_resource_apply() {
        let patch = SandboxModificationPatch {
            cpus: Some(4),
            memory_mib: Some(4096),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config(2, 1024),
            None,
            patch,
            ModificationPolicy::Restart,
        );

        assert!(validate_apply_supported(&plan).is_ok());
    }

    #[test]
    fn no_restart_policy_rejects_restart_required_resource_apply() {
        let patch = SandboxModificationPatch {
            cpus: Some(4),
            memory_mib: Some(4096),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config(2, 1024),
            None,
            patch,
            ModificationPolicy::NoRestart,
        );

        assert!(validate_apply_supported(&plan).is_err());
    }

    #[test]
    fn stopped_resource_changes_are_next_start() {
        let patch = SandboxModificationPatch {
            cpus: Some(4),
            memory_mib: Some(4096),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config(2, 1024),
            None,
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(plan.changes.len(), 4);
        for change in plan.changes {
            let PlannedChange::Config(change) = change else {
                panic!("expected config change");
            };
            assert_eq!(change.disposition, ModificationDisposition::NextStart);
            assert!(change.reason.is_none());
        }
    }

    #[test]
    fn max_capacity_conflicts_with_requested_effective_value() {
        let patch = SandboxModificationPatch {
            cpus: Some(8),
            max_cpus: Some(4),
            memory_mib: Some(8192),
            max_memory_mib: Some(4096),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config(2, 1024),
            None,
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(plan.conflicts.len(), 2);
        assert_eq!(plan.conflicts[0].field, "max_cpus");
        assert_eq!(plan.conflicts[1].field, "max_memory");
    }

    #[test]
    fn zero_resource_values_are_conflicts() {
        let patch = SandboxModificationPatch {
            cpus: Some(0),
            max_cpus: Some(0),
            memory_mib: Some(0),
            max_memory_mib: Some(0),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config(2, 1024),
            None,
            patch,
            ModificationPolicy::NoRestart,
        );

        assert!(
            plan.conflicts
                .iter()
                .any(|conflict| conflict.field == "cpus")
        );
        assert!(
            plan.conflicts
                .iter()
                .any(|conflict| conflict.field == "memory")
        );
        assert!(
            plan.conflicts
                .iter()
                .any(|conflict| conflict.field == "max_cpus")
        );
        assert!(
            plan.conflicts
                .iter()
                .any(|conflict| conflict.field == "max_memory")
        );
    }

    #[test]
    fn applying_effective_resource_change_raises_capacity_when_needed() {
        let mut config = config(2, 1024);
        let patch = SandboxModificationPatch {
            cpus: Some(4),
            memory_mib: Some(4096),
            ..SandboxModificationPatch::default()
        };

        apply_patch_to_config(&mut config, &patch);

        assert_eq!(config.spec.resources.cpus, 4);
        assert_eq!(config.spec.resources.max_cpus, 4);
        assert_eq!(config.spec.resources.memory_mib, 4096);
        assert_eq!(config.spec.resources.max_memory_mib, 4096);
    }

    #[test]
    fn secret_plan_never_contains_secret_values() {
        let patch = SandboxModificationPatch {
            secrets: vec![SecretModificationPatch {
                name: "API_KEY".to_string(),
                operation: SecretPatchOperation::Upsert,
                source: Some(SecretSource::Env {
                    var: "API_KEY".to_string(),
                }),
                placeholder: None,
                allowed_hosts: vec!["api.example.com".to_string()],
            }],
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config(2, 1024),
            None,
            patch,
            ModificationPolicy::NoRestart,
        );
        let json = serde_json::to_string(&plan).unwrap();

        assert!(json.contains("$API_KEY"));
        assert!(json.contains("api.example.com"));
        assert!(!json.contains("real-secret-value"));

        let PlannedChange::Secret(change) = &plan.changes[0] else {
            panic!("expected secret change");
        };
        assert_eq!(change.field, SECRET_FIELD);
        assert_eq!(change.change, SecretChangeKind::Added);
        assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
    }
}
