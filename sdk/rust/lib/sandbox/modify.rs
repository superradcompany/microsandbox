//! Sandbox modification planning.

use std::sync::Arc;

use microsandbox_types::EnvVar;
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
const LIVE_EXEC_DEFAULT_UPDATE_UNAVAILABLE: &str =
    "affects future execs only after restart; live exec-default updates are not available yet";
const LIVE_LABEL_UPDATE_UNAVAILABLE: &str =
    "live label updates are not available in this runtime yet";
const FUTURE_EXECS_ONLY: &str =
    "applies to future execs only; running processes keep their current environment";
#[cfg(not(feature = "net"))]
const SECRETS_UNAVAILABLE_WITHOUT_NET: &str =
    "secret modification requires a build with the net feature";
const SECRET_FIELD: &str = "secret";
const ENV_FIELD: &str = "env";
const LABEL_FIELD: &str = "label";
const WORKDIR_FIELD: &str = "workdir";

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

/// Live-control operations the running sandbox process actually serves,
/// discovered through the control socket's `capabilities` op.
#[derive(Debug, Clone, Copy, Default)]
struct LiveControl {
    /// CPU and memory resize targets are served.
    resize: bool,

    /// Secret rotation, removal, and allowed-host updates are served.
    secrets: bool,
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

    /// Set an environment variable for future execs.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.patch.env.push(EnvVar::new(key, value));
        self
    }

    /// Remove an environment variable.
    pub fn remove_env(mut self, key: impl Into<String>) -> Self {
        self.patch.env_remove.push(key.into());
        self
    }

    /// Set a sandbox label.
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.patch.labels.push((key.into(), value.into()));
        self
    }

    /// Remove a sandbox label.
    pub fn remove_label(mut self, key: impl Into<String>) -> Self {
        self.patch.labels_remove.push(key.into());
        self
    }

    /// Set the working directory for future execs.
    pub fn workdir(mut self, path: impl Into<String>) -> Self {
        self.patch.workdir = Some(path.into());
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

    /// Replace the accumulated patch wholesale. Language bindings deserialize the canonical [`SandboxModificationPatch`] and inject it here instead of replaying the fluent setters.
    pub fn with_patch(mut self, patch: SandboxModificationPatch) -> Self {
        self.patch = patch;
        self
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
        let live = live_control(&self.name, status).await;
        Ok(build_plan(
            self.name,
            status,
            &config,
            active.as_ref(),
            live,
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
    /// path makes restart-required changes active. Live secret rotation,
    /// removal, and allowed-host updates go through the runtime control
    /// socket; the durable config records host-side source references only.
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
        let live = live_control(&self.name, status).await;
        let mut plan = build_plan(
            self.name.clone(),
            status,
            &config,
            active.as_ref(),
            live,
            self.patch.clone(),
            self.policy,
        );

        validate_apply_supported(&plan)?;
        let restart_required = plan_requires_restart(&plan) && running_status(status);
        if restart_required {
            handle.stop().await?;
        }
        if !restart_required && let Some(target) = live_cpu_target(&plan, &self.patch) {
            let state = control_cpu_target(&self.name, u32::from(target)).await?;
            plan.resize_status.push(ResourceResizeStatus {
                resource: ResourceKind::Cpus,
                requested: target.to_string(),
                actual: state.actual_online.to_string(),
                enforced: state.enforced.to_string(),
                state: if state.actual_online == u32::from(target) {
                    ResourceConvergenceState::Applied
                } else {
                    ResourceConvergenceState::Converging
                },
            });
            // The running VM changed: refresh the active snapshot with the
            // enforced target so inspect does not report the already-live
            // change as pending. The guest driver converges asynchronously;
            // enforcement applies immediately either way.
            if let Some(mut active) = active.clone() {
                active.spec.resources.cpus = target;
                persist_active_config(&self.backend, &handle, &active).await?;
            }
        }
        if !restart_required && let Some(target_mib) = live_memory_target(&plan, &self.patch) {
            let state = control_memory_target(&self.name, u64::from(target_mib)).await?;
            plan.resize_status.push(ResourceResizeStatus {
                resource: ResourceKind::Memory,
                requested: format_mib(target_mib),
                actual: format_mib(state.current_mib as u32),
                enforced: format_mib(state.target_mib as u32),
                state: if state.current_mib >= state.target_mib {
                    ResourceConvergenceState::Applied
                } else {
                    ResourceConvergenceState::Converging
                },
            });
            // Refresh the active snapshot with the accepted target so inspect
            // does not report the already-live change as pending. Convergence
            // (plugging blocks) continues asynchronously in the guest.
            if let Some(mut active) = active.clone() {
                active.spec.resources.memory_mib = state.target_mib as u32;
                persist_active_config(&self.backend, &handle, &active).await?;
            }
        }
        if !restart_required {
            let updates = live_secret_updates(&plan, &self.patch)?;
            if !updates.is_empty() {
                control_secrets_update(&self.name, updates).await?;
                // The running network layer changed: mirror the secret patch
                // into the active snapshot so inspect does not report the
                // already-live change as pending.
                if let Some(mut active) = active.clone() {
                    apply_secret_patch_to_config(&mut active, &self.patch)?;
                    persist_active_config(&self.backend, &handle, &active).await?;
                }
            }
        }
        if !plan.changes.is_empty() {
            apply_patch_to_config(&mut config, &self.patch);
            apply_secret_patch_to_config(&mut config, &self.patch)?;
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

#[allow(clippy::too_many_arguments)]
fn build_plan(
    name: String,
    status: SandboxStatus,
    config: &SandboxConfig,
    active: Option<&SandboxConfig>,
    live: LiveControl,
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
        live.resize,
        &patch,
        policy,
        &mut changes,
        &mut warnings,
    );
    push_spec_changes(status, config, &patch, policy, &mut changes, &mut warnings);
    push_secret_changes(
        status,
        config,
        live.secrets,
        &patch,
        policy,
        &mut changes,
        &mut warnings,
    );
    push_resource_conflicts(config, &patch, &mut conflicts);
    push_spec_conflicts(&patch, &mut conflicts);
    push_secret_conflicts(config, &patch, &mut conflicts);

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

/// The live memory target in MiB, when the plan classified `memory` as live.
fn live_memory_target(
    plan: &SandboxModificationPlan,
    patch: &SandboxModificationPatch,
) -> Option<u32> {
    let live_memory = plan.changes.iter().any(|change| {
        matches!(
            change,
            PlannedChange::Config(change)
                if change.field == "memory"
                    && matches!(change.disposition, ModificationDisposition::Live)
        )
    });
    if live_memory { patch.memory_mib } else { None }
}

/// Path of the sandbox's host-side runtime control socket.
fn control_socket_path(name: &str) -> MicrosandboxResult<std::path::PathBuf> {
    Ok(microsandbox_runtime::control::control_socket_path_for(
        &crate::runtime::agent_socket_path(name)?,
    ))
}

/// Whether the running sandbox exposes the runtime control socket. Its absence
/// means the runtime predates live control or the VM booted without any
/// live-mutable capacity, so everything classifies as restart-required.
fn control_socket_exists(name: &str) -> bool {
    control_socket_path(name).is_ok_and(|path| path.exists())
}

/// Discover which live-control operations the running sandbox serves.
async fn live_control(name: &str, status: SandboxStatus) -> LiveControl {
    if !running_status(status) || !control_socket_exists(name) {
        return LiveControl::default();
    }
    match control_capabilities(name).await {
        Ok(caps) => LiveControl {
            resize: caps.cpu_resize || caps.memory_resize,
            secrets: caps.secrets_update,
        },
        // Runtimes that predate the capabilities op served the socket only
        // when they could resize; live secret ops did not exist yet.
        Err(_) => LiveControl {
            resize: true,
            secrets: false,
        },
    }
}

/// Ask the sandbox process which live-control operations it serves.
#[cfg(unix)]
async fn control_capabilities(
    name: &str,
) -> MicrosandboxResult<microsandbox_runtime::control::ControlCapabilities> {
    let response = control_request(name, "{\"op\":\"capabilities\"}\n".to_string()).await?;
    response.capabilities.ok_or_else(|| {
        crate::MicrosandboxError::Runtime("control response missing capabilities".to_string())
    })
}

#[cfg(not(unix))]
async fn control_capabilities(
    _name: &str,
) -> MicrosandboxResult<microsandbox_runtime::control::ControlCapabilities> {
    Err(crate::MicrosandboxError::Unsupported {
        feature: "live sandbox control".into(),
        available_when: "on unix hosts".into(),
    })
}

/// Send one control request line and parse the reply.
#[cfg(unix)]
async fn control_request(
    name: &str,
    request: String,
) -> MicrosandboxResult<microsandbox_runtime::control::ControlResponse> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let path = control_socket_path(name)?;
    let mut stream = tokio::net::UnixStream::connect(&path).await.map_err(|e| {
        crate::MicrosandboxError::Runtime(format!(
            "failed to reach the runtime control socket at {}: {e}",
            path.display()
        ))
    })?;
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| crate::MicrosandboxError::Runtime(format!("control request failed: {e}")))?;

    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .await
        .map_err(|e| crate::MicrosandboxError::Runtime(format!("control response failed: {e}")))?;
    let response: microsandbox_runtime::control::ControlResponse =
        serde_json::from_str(line.trim())?;
    if !response.ok {
        return Err(crate::MicrosandboxError::Runtime(format!(
            "live update refused: {}",
            response
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        )));
    }
    Ok(response)
}

/// Send the value-bearing live secret batch to the sandbox process. The
/// request travels only over the private per-sandbox unix socket and is never
/// logged; failures surface the runtime's error, which carries secret names
/// only.
#[cfg(unix)]
async fn control_secrets_update(
    name: &str,
    changes: Vec<microsandbox_runtime::control::SecretLiveChange>,
) -> MicrosandboxResult<()> {
    let request = microsandbox_runtime::control::ControlRequest::SecretsUpdate { changes };
    let mut line = serde_json::to_string(&request)?;
    line.push('\n');
    control_request(name, line).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn control_secrets_update(
    _name: &str,
    _changes: Vec<microsandbox_runtime::control::SecretLiveChange>,
) -> MicrosandboxResult<()> {
    Err(crate::MicrosandboxError::Unsupported {
        feature: "live secret reconfiguration".into(),
        available_when: "on unix hosts".into(),
    })
}

/// Ask the sandbox process to converge on `total_mib` of usable guest memory.
#[cfg(unix)]
async fn control_memory_target(
    name: &str,
    total_mib: u64,
) -> MicrosandboxResult<microsandbox_runtime::control::MemoryControlState> {
    let response = control_request(
        name,
        format!("{{\"op\":\"memory_target\",\"total_mib\":{total_mib}}}\n"),
    )
    .await?;
    response.memory.ok_or_else(|| {
        crate::MicrosandboxError::Runtime("control response missing memory state".to_string())
    })
}

/// Ask the sandbox process to converge on `online` CPUs. Enforcement applies
/// immediately in the VMM; the guest driver converges asynchronously.
#[cfg(unix)]
pub(crate) async fn control_cpu_target(
    name: &str,
    online: u32,
) -> MicrosandboxResult<microsandbox_runtime::control::CpuControlState> {
    let response = control_request(
        name,
        format!("{{\"op\":\"cpu_target\",\"online\":{online}}}\n"),
    )
    .await?;
    response.cpu.ok_or_else(|| {
        crate::MicrosandboxError::Runtime("control response missing cpu state".to_string())
    })
}

#[cfg(not(unix))]
async fn control_memory_target(
    _name: &str,
    _total_mib: u64,
) -> MicrosandboxResult<microsandbox_runtime::control::MemoryControlState> {
    Err(crate::MicrosandboxError::Unsupported {
        feature: "live memory resize".into(),
        available_when: "on unix hosts".into(),
    })
}

#[cfg(not(unix))]
pub(crate) async fn control_cpu_target(
    _name: &str,
    _online: u32,
) -> MicrosandboxResult<microsandbox_runtime::control::CpuControlState> {
    Err(crate::MicrosandboxError::Unsupported {
        feature: "live CPU resize".into(),
        available_when: "on unix hosts".into(),
    })
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
            PlannedChange::Secret(change) => {
                if matches!(change.disposition, ModificationDisposition::Unsupported) {
                    let reason = change
                        .reason
                        .as_deref()
                        .map(|reason| format!(" ({reason})"))
                        .unwrap_or_default();
                    return Err(crate::MicrosandboxError::Custom(format!(
                        "cannot apply modification: secret {} is unsupported{reason}",
                        change.name
                    )));
                }
                if matches!(change.disposition, ModificationDisposition::RequiresRestart) {
                    if plan.policy == ModificationPolicy::Restart {
                        continue;
                    }
                    return Err(crate::MicrosandboxError::Custom(format!(
                        "cannot apply modification: secret {} requires restart",
                        change.name
                    )));
                }
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
    for var in &patch.env {
        if let Some(existing) = config
            .spec
            .env
            .iter_mut()
            .find(|entry| entry.key == var.key)
        {
            existing.value = var.value.clone();
        } else {
            config.spec.env.push(var.clone());
        }
    }
    config
        .spec
        .env
        .retain(|entry| !patch.env_remove.contains(&entry.key));
    for (key, value) in &patch.labels {
        config.spec.labels.insert(key.clone(), value.clone());
    }
    for key in &patch.labels_remove {
        config.spec.labels.remove(key);
    }
    if let Some(workdir) = &patch.workdir {
        config.spec.runtime.workdir = Some(workdir.clone());
    }
}

/// Persist secret patches into the sandbox's network secrets config.
///
/// Upsert and rotate record the host-side source reference and drop any
/// previously inlined raw value: after a modify touches a secret, the durable
/// config carries only the reference, the guest-visible placeholder, and the
/// allowed hosts. Values are resolved from the source at spawn time.
#[cfg(feature = "net")]
fn apply_secret_patch_to_config(
    config: &mut SandboxConfig,
    patch: &SandboxModificationPatch,
) -> MicrosandboxResult<()> {
    if patch.secrets.is_empty() {
        return Ok(());
    }
    let mut network = config.local_network_config()?;
    for secret in &patch.secrets {
        apply_secret_patch_entry(&mut network.secrets, secret)?;
    }
    // Enforce env-var and placeholder shape rules before anything persists;
    // validation errors carry entry indexes and sizes, never values.
    network.secrets.validate().map_err(|err| {
        crate::MicrosandboxError::InvalidConfig(format!("invalid secret configuration: {err}"))
    })?;
    config.set_local_network_config(network)
}

#[cfg(not(feature = "net"))]
fn apply_secret_patch_to_config(
    _config: &mut SandboxConfig,
    patch: &SandboxModificationPatch,
) -> MicrosandboxResult<()> {
    if patch.secrets.is_empty() {
        return Ok(());
    }
    Err(crate::MicrosandboxError::Unsupported {
        feature: "secret modification".into(),
        available_when: "in builds with the net feature".into(),
    })
}

#[cfg(feature = "net")]
fn apply_secret_patch_entry(
    secrets: &mut microsandbox_network::secrets::config::SecretsConfig,
    patch: &SecretModificationPatch,
) -> MicrosandboxResult<()> {
    use microsandbox_network::secrets::config::{SecretEntry, SecretInjection};

    match patch.operation {
        SecretPatchOperation::Upsert | SecretPatchOperation::Rotate => {
            let source = durable_secret_source(&patch.name, patch.source.as_ref())?;
            if let Some(entry) = secrets
                .secrets
                .iter_mut()
                .find(|entry| entry.env_var == patch.name)
            {
                entry.value = zeroize::Zeroizing::new(String::new());
                entry.source = Some(source);
                if let Some(placeholder) = &patch.placeholder {
                    entry.placeholder = placeholder.clone();
                }
                if !patch.allowed_hosts.is_empty() {
                    entry.allowed_hosts = parse_host_patterns(&patch.allowed_hosts);
                }
            } else {
                if patch.operation == SecretPatchOperation::Rotate {
                    return Err(missing_secret_error(&patch.name));
                }
                secrets.secrets.push(SecretEntry {
                    env_var: patch.name.clone(),
                    value: zeroize::Zeroizing::new(String::new()),
                    source: Some(source),
                    placeholder: patch
                        .placeholder
                        .clone()
                        .unwrap_or_else(|| default_secret_ref(&patch.name)),
                    allowed_hosts: parse_host_patterns(&patch.allowed_hosts),
                    injection: SecretInjection::default(),
                    on_violation: None,
                    require_tls_identity: true,
                });
            }
        }
        SecretPatchOperation::Remove => {
            secrets.secrets.retain(|entry| entry.env_var != patch.name);
        }
        SecretPatchOperation::UpdateHosts => {
            let entry = secrets
                .secrets
                .iter_mut()
                .find(|entry| entry.env_var == patch.name)
                .ok_or_else(|| missing_secret_error(&patch.name))?;
            entry.allowed_hosts = parse_host_patterns(&patch.allowed_hosts);
        }
        SecretPatchOperation::UpdatePlaceholder => {
            let entry = secrets
                .secrets
                .iter_mut()
                .find(|entry| entry.env_var == patch.name)
                .ok_or_else(|| missing_secret_error(&patch.name))?;
            entry.placeholder = patch.placeholder.clone().ok_or_else(|| {
                crate::MicrosandboxError::Custom(format!(
                    "secret {} needs a placeholder",
                    patch.name
                ))
            })?;
        }
    }
    Ok(())
}

#[cfg(feature = "net")]
fn parse_host_patterns(
    hosts: &[String],
) -> Vec<microsandbox_network::secrets::config::HostPattern> {
    hosts
        .iter()
        .map(|host| microsandbox_network::secrets::config::HostPattern::parse(host))
        .collect()
}

/// Map a patch source to the reference persisted in durable config. Values
/// are never read here.
#[cfg(feature = "net")]
fn durable_secret_source(
    name: &str,
    source: Option<&SecretSource>,
) -> MicrosandboxResult<microsandbox_network::secrets::config::SecretSourceRef> {
    match source {
        Some(SecretSource::Env { var }) => {
            Ok(microsandbox_network::secrets::config::SecretSourceRef::Env { var: var.clone() })
        }
        Some(SecretSource::Store { .. }) => Err(crate::MicrosandboxError::Custom(format!(
            "secret {name}: store-backed secret sources are not supported yet"
        ))),
        None => Err(crate::MicrosandboxError::Custom(format!(
            "secret {name} needs a host-side source to add or rotate"
        ))),
    }
}

fn missing_secret_error(name: &str) -> crate::MicrosandboxError {
    crate::MicrosandboxError::Custom(format!("secret {name} does not exist"))
}

/// Build the value-bearing live batch for secret changes the plan classified
/// as live. Rotation resolves the host-side source here, in the caller's
/// process, so the value goes straight to the control socket and never into
/// the plan, logs, or durable config.
fn live_secret_updates(
    plan: &SandboxModificationPlan,
    patch: &SandboxModificationPatch,
) -> MicrosandboxResult<Vec<microsandbox_runtime::control::SecretLiveChange>> {
    use microsandbox_runtime::control::{SecretLiveChange, SecretValue};

    // Planned secret changes are emitted one per patch entry, in order.
    let planned = plan.changes.iter().filter_map(|change| match change {
        PlannedChange::Secret(change) => Some(change),
        PlannedChange::Config(_) => None,
    });

    let mut updates = Vec::new();
    for (planned, requested) in planned.zip(&patch.secrets) {
        if !matches!(planned.disposition, ModificationDisposition::Live) {
            continue;
        }
        match planned.change {
            SecretChangeKind::Rotated => {
                let value =
                    resolve_secret_source_value(&requested.name, requested.source.as_ref())?;
                updates.push(SecretLiveChange::Rotate {
                    name: requested.name.clone(),
                    value: SecretValue(value),
                });
                // A rotate request may carry new hosts (e.g. `--secret NAME@HOST`
                // on an existing secret); apply them in the same batch.
                if !requested.allowed_hosts.is_empty() {
                    updates.push(SecretLiveChange::SetAllowedHosts {
                        name: requested.name.clone(),
                        hosts: requested.allowed_hosts.clone(),
                    });
                }
            }
            SecretChangeKind::Removed => {
                updates.push(SecretLiveChange::Remove {
                    name: requested.name.clone(),
                });
            }
            SecretChangeKind::HostsUpdated => {
                updates.push(SecretLiveChange::SetAllowedHosts {
                    name: requested.name.clone(),
                    hosts: requested.allowed_hosts.clone(),
                });
            }
            // Added, renamed, and placeholder changes never classify live.
            SecretChangeKind::Added
            | SecretChangeKind::Renamed
            | SecretChangeKind::PlaceholderUpdated => {}
        }
    }
    Ok(updates)
}

/// Resolve a secret source into its value at apply time. Errors name the
/// secret and the source reference; they never carry values.
fn resolve_secret_source_value(
    name: &str,
    source: Option<&SecretSource>,
) -> MicrosandboxResult<String> {
    match source {
        Some(SecretSource::Env { var }) => {
            let value = std::env::var(var).map_err(|_| {
                crate::MicrosandboxError::InvalidConfig(format!(
                    "secret {name}: host environment variable {var} is not set"
                ))
            })?;
            if value.is_empty() {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "secret {name}: host environment variable {var} is empty"
                )));
            }
            Ok(value)
        }
        Some(SecretSource::Store { .. }) => Err(crate::MicrosandboxError::Custom(format!(
            "secret {name}: store-backed secret sources are not supported yet"
        ))),
        None => Err(crate::MicrosandboxError::Custom(format!(
            "secret {name} needs a host-side source to rotate"
        ))),
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
    live_control_supported: bool,
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
        let live = live_control_supported && active_max_cpus.is_some_and(|max| cpus <= max);
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
        // Memory changes live through virtio-mem when the target fits inside
        // the active hotpluggable capacity AND the running sandbox exposes a
        // runtime control socket (older runtimes and Windows do not).
        let active_max_memory = active.map(|active| active.spec.resources.max_memory_mib);
        let live = live_control_supported && active_max_memory.is_some_and(|max| memory_mib <= max);
        let reason = match (
            resource_disposition(status, policy, live),
            active_max_memory,
        ) {
            (ModificationDisposition::RequiresRestart, Some(max)) if memory_mib > max => {
                Some(format!(
                    "memory {} exceeds the active max capacity {}; restart with a larger max_memory",
                    format_mib(memory_mib),
                    format_mib(max)
                ))
            }
            _ => resource_reason(status, policy, live),
        };
        changes.push(PlannedChange::Config(ConfigPlannedChange {
            field: "memory".to_string(),
            change: ChangeKind::Updated,
            before: Some(format_mib(resources.memory_mib)),
            after: Some(format_mib(memory_mib)),
            disposition: resource_disposition(status, policy, live),
            reason,
        }));
        push_live_resize_warning("memory", status, policy, live, warnings);
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
    live_secret_reconfigure_supported: bool,
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
        let disposition =
            secret_disposition(status, policy, change, live_secret_reconfigure_supported);
        let reason = secret_reason(status, policy, change, live_secret_reconfigure_supported);

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

/// Plan env, label, and workdir changes.
///
/// These fields have no live path yet: they persist for the next start when
/// the sandbox is stopped (or under the next-start policy) and otherwise
/// require a restart before future execs or metadata queries observe them.
fn push_spec_changes(
    status: SandboxStatus,
    config: &SandboxConfig,
    patch: &SandboxModificationPatch,
    policy: ModificationPolicy,
    changes: &mut Vec<PlannedChange>,
    warnings: &mut Vec<ModificationWarning>,
) {
    for var in &patch.env {
        let existing = config.spec.env.iter().find(|entry| entry.key == var.key);
        if existing.is_some_and(|entry| entry.value == var.value) {
            continue;
        }
        changes.push(spec_change(
            ENV_FIELD,
            change_kind_for(existing.is_some()),
            existing.map(format_env_var),
            Some(format_env_var(var)),
            status,
            policy,
            LIVE_EXEC_DEFAULT_UPDATE_UNAVAILABLE,
        ));
        push_future_exec_warning(ENV_FIELD, status, policy, warnings);
    }

    for key in &patch.env_remove {
        let Some(existing) = config.spec.env.iter().find(|entry| entry.key == *key) else {
            continue;
        };
        changes.push(spec_change(
            ENV_FIELD,
            ChangeKind::Removed,
            Some(format_env_var(existing)),
            None,
            status,
            policy,
            LIVE_EXEC_DEFAULT_UPDATE_UNAVAILABLE,
        ));
        push_future_exec_warning(ENV_FIELD, status, policy, warnings);
    }

    for (key, value) in &patch.labels {
        let existing = config.spec.labels.get(key);
        if existing.is_some_and(|current| current == value) {
            continue;
        }
        changes.push(spec_change(
            LABEL_FIELD,
            change_kind_for(existing.is_some()),
            existing.map(|current| format!("{key}={current}")),
            Some(format!("{key}={value}")),
            status,
            policy,
            LIVE_LABEL_UPDATE_UNAVAILABLE,
        ));
    }

    for key in &patch.labels_remove {
        let Some(current) = config.spec.labels.get(key) else {
            continue;
        };
        changes.push(spec_change(
            LABEL_FIELD,
            ChangeKind::Removed,
            Some(format!("{key}={current}")),
            None,
            status,
            policy,
            LIVE_LABEL_UPDATE_UNAVAILABLE,
        ));
    }

    if let Some(workdir) = &patch.workdir {
        let before = config.spec.runtime.workdir.clone();
        if before.as_deref() != Some(workdir.as_str()) {
            changes.push(spec_change(
                WORKDIR_FIELD,
                change_kind_for(before.is_some()),
                before,
                Some(workdir.clone()),
                status,
                policy,
                LIVE_EXEC_DEFAULT_UPDATE_UNAVAILABLE,
            ));
            push_future_exec_warning(WORKDIR_FIELD, status, policy, warnings);
        }
    }
}

fn push_spec_conflicts(
    patch: &SandboxModificationPatch,
    conflicts: &mut Vec<ModificationConflict>,
) {
    for var in &patch.env {
        if patch.env_remove.contains(&var.key) {
            conflicts.push(ModificationConflict {
                field: ENV_FIELD.to_string(),
                message: format!(
                    "env {} is both set and removed in the same modification",
                    var.key
                ),
            });
        }
    }
    for (key, _) in &patch.labels {
        if patch.labels_remove.contains(key) {
            conflicts.push(ModificationConflict {
                field: LABEL_FIELD.to_string(),
                message: format!("label {key} is both set and removed in the same modification"),
            });
        }
    }
}

/// Reject secret patches that could never persist or apply: missing or
/// unsupported sources, operations on secrets that do not exist, and host or
/// placeholder updates without a payload. Without the net feature the whole
/// secret surface is already unsupported, so no per-entry checks run.
fn push_secret_conflicts(
    config: &SandboxConfig,
    patch: &SandboxModificationPatch,
    conflicts: &mut Vec<ModificationConflict>,
) {
    if cfg!(not(feature = "net")) {
        return;
    }

    let mut conflict = |message: String| {
        conflicts.push(ModificationConflict {
            field: SECRET_FIELD.to_string(),
            message,
        });
    };

    for secret in &patch.secrets {
        let name = &secret.name;
        let exists = existing_secret(config, name).is_some();
        let source_conflict = match (&secret.operation, &secret.source) {
            (SecretPatchOperation::Upsert | SecretPatchOperation::Rotate, None) => Some(format!(
                "secret {name} needs a host-side source to add or rotate"
            )),
            (
                SecretPatchOperation::Upsert | SecretPatchOperation::Rotate,
                Some(SecretSource::Store { .. }),
            ) => Some(format!(
                "secret {name}: store-backed secret sources are not supported yet"
            )),
            _ => None,
        };
        if let Some(message) = source_conflict {
            conflict(message);
        }

        match secret.operation {
            SecretPatchOperation::Upsert => {
                if !exists && secret.allowed_hosts.is_empty() {
                    conflict(format!("secret {name} needs at least one allowed host"));
                }
            }
            SecretPatchOperation::Rotate => {
                if !exists {
                    conflict(format!("secret {name} does not exist"));
                }
            }
            SecretPatchOperation::Remove => {}
            SecretPatchOperation::UpdateHosts => {
                if !exists {
                    conflict(format!("secret {name} does not exist"));
                } else if secret.allowed_hosts.is_empty() {
                    conflict(format!("secret {name} needs at least one allowed host"));
                }
            }
            SecretPatchOperation::UpdatePlaceholder => {
                if !exists {
                    conflict(format!("secret {name} does not exist"));
                } else if secret.placeholder.is_none() {
                    conflict(format!("secret {name} needs a placeholder"));
                }
            }
        }
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

fn spec_change(
    field: &str,
    change: ChangeKind,
    before: Option<String>,
    after: Option<String>,
    status: SandboxStatus,
    policy: ModificationPolicy,
    running_reason: &str,
) -> PlannedChange {
    PlannedChange::Config(ConfigPlannedChange {
        field: field.to_string(),
        change,
        before,
        after,
        disposition: spec_disposition(status, policy),
        reason: spec_reason(status, policy, running_reason),
    })
}

fn spec_disposition(status: SandboxStatus, policy: ModificationPolicy) -> ModificationDisposition {
    if policy == ModificationPolicy::NextStart || stopped_status(status) {
        return ModificationDisposition::NextStart;
    }
    if transitional_status(status) {
        return ModificationDisposition::Unsupported;
    }
    ModificationDisposition::RequiresRestart
}

fn spec_reason(
    status: SandboxStatus,
    policy: ModificationPolicy,
    running_reason: &str,
) -> Option<String> {
    match spec_disposition(status, policy) {
        ModificationDisposition::RequiresRestart if running_status(status) => {
            Some(running_reason.to_string())
        }
        ModificationDisposition::Unsupported => Some(format!(
            "cannot modify while sandbox is {}",
            status_name(status)
        )),
        _ => None,
    }
}

fn change_kind_for(existing: bool) -> ChangeKind {
    if existing {
        ChangeKind::Updated
    } else {
        ChangeKind::Added
    }
}

fn format_env_var(var: &EnvVar) -> String {
    format!("{}={}", var.key, var.value)
}

fn secret_disposition(
    status: SandboxStatus,
    policy: ModificationPolicy,
    change: SecretChangeKind,
    live_secret_reconfigure_supported: bool,
) -> ModificationDisposition {
    // Without the net feature there is no secrets layer to persist into or
    // reconfigure, so every secret change is unsupported.
    #[cfg(not(feature = "net"))]
    {
        let _ = (status, policy, change, live_secret_reconfigure_supported);
        return ModificationDisposition::Unsupported;
    }
    #[cfg(feature = "net")]
    secret_disposition_net(status, policy, change, live_secret_reconfigure_supported)
}

#[cfg(feature = "net")]
fn secret_disposition_net(
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
    #[cfg(not(feature = "net"))]
    {
        let _ = (status, policy, change, live_secret_reconfigure_supported);
        return Some(SECRETS_UNAVAILABLE_WITHOUT_NET.to_string());
    }
    #[cfg(feature = "net")]
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

/// Warn that a running-sandbox exec-default change (env, workdir) only reaches
/// future execs: even after a `--restart` apply or a persisted `--next-start`
/// patch, processes already running keep the environment they started with.
fn push_future_exec_warning(
    field: &str,
    status: SandboxStatus,
    policy: ModificationPolicy,
    warnings: &mut Vec<ModificationWarning>,
) {
    if !running_status(status)
        || !matches!(
            policy,
            ModificationPolicy::Restart | ModificationPolicy::NextStart
        )
    {
        return;
    }
    if warnings
        .iter()
        .any(|warning| warning.field == field && warning.message == FUTURE_EXECS_ONLY)
    {
        return;
    }
    warnings.push(ModificationWarning {
        field: field.to_string(),
        message: FUTURE_EXECS_ONLY.to_string(),
    });
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
            LiveControl::default(),
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
            LiveControl {
                resize: true,
                secrets: false,
            },
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
    fn running_memory_within_capacity_classifies_live_only_with_control_socket() {
        let mut desired = config(2, 512);
        desired.spec.resources.max_memory_mib = 2048;
        let active = desired.clone();
        let patch = SandboxModificationPatch {
            memory_mib: Some(1024),
            ..SandboxModificationPatch::default()
        };

        for (live_memory_supported, expected) in [
            (true, ModificationDisposition::Live),
            (false, ModificationDisposition::RequiresRestart),
        ] {
            let plan = build_plan(
                "api".to_string(),
                SandboxStatus::Running,
                &desired,
                Some(&active),
                LiveControl {
                    resize: live_memory_supported,
                    secrets: false,
                },
                patch.clone(),
                ModificationPolicy::NoRestart,
            );
            let PlannedChange::Config(change) = &plan.changes[0] else {
                panic!("expected config change");
            };
            assert_eq!(change.field, "memory");
            assert_eq!(change.disposition, expected);
            if live_memory_supported {
                assert_eq!(live_memory_target(&plan, &patch), Some(1024));
            } else {
                assert_eq!(live_memory_target(&plan, &patch), None);
            }
        }
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
            LiveControl {
                resize: true,
                secrets: false,
            },
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
            LiveControl::default(),
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
            LiveControl::default(),
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
            LiveControl::default(),
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
            LiveControl::default(),
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
            LiveControl::default(),
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
    fn running_env_label_workdir_changes_require_restart() {
        let patch = SandboxModificationPatch {
            env: vec![EnvVar::new("MODE", "prod")],
            labels: vec![("team".to_string(), "infra".to_string())],
            workdir: Some("/srv".to_string()),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config(2, 1024),
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(plan.changes.len(), 3);
        for change in plan.changes {
            let PlannedChange::Config(change) = change else {
                panic!("expected config change");
            };
            assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
            assert_eq!(change.change, ChangeKind::Added);
            match change.field.as_str() {
                "env" | "workdir" => {
                    assert_eq!(
                        change.reason.as_deref(),
                        Some(LIVE_EXEC_DEFAULT_UPDATE_UNAVAILABLE)
                    );
                }
                "label" => {
                    assert_eq!(
                        change.reason.as_deref(),
                        Some(LIVE_LABEL_UPDATE_UNAVAILABLE)
                    );
                }
                field => panic!("unexpected field {field}"),
            }
        }
    }

    #[test]
    fn stopped_env_label_workdir_changes_are_next_start() {
        let patch = SandboxModificationPatch {
            env: vec![EnvVar::new("MODE", "prod")],
            env_remove: vec!["EXTRA".to_string()],
            labels: vec![("team".to_string(), "infra".to_string())],
            labels_remove: vec!["old".to_string()],
            workdir: Some("/srv".to_string()),
            ..SandboxModificationPatch::default()
        };

        let mut current = config(2, 1024);
        current.spec.env.push(EnvVar::new("EXTRA", "1"));
        current
            .spec
            .labels
            .insert("old".to_string(), "x".to_string());

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &current,
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(plan.changes.len(), 5);
        assert!(plan.conflicts.is_empty());
        for change in plan.changes {
            let PlannedChange::Config(change) = change else {
                panic!("expected config change");
            };
            assert_eq!(change.disposition, ModificationDisposition::NextStart);
            assert!(change.reason.is_none());
        }
    }

    #[test]
    fn spec_change_kinds_follow_current_config() {
        let mut current = config(2, 1024);
        current.spec.env = vec![EnvVar::new("MODE", "dev"), EnvVar::new("EXTRA", "1")];
        current
            .spec
            .labels
            .insert("team".to_string(), "infra".to_string());
        current.spec.runtime.workdir = Some("/app".to_string());

        let patch = SandboxModificationPatch {
            env: vec![EnvVar::new("MODE", "prod"), EnvVar::new("NEW", "1")],
            env_remove: vec!["EXTRA".to_string(), "MISSING".to_string()],
            labels: vec![("tier".to_string(), "gold".to_string())],
            labels_remove: vec!["team".to_string()],
            workdir: Some("/srv".to_string()),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &current,
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        let rows: Vec<(&str, ChangeKind, Option<&str>, Option<&str>)> = plan
            .changes
            .iter()
            .map(|change| {
                let PlannedChange::Config(change) = change else {
                    panic!("expected config change");
                };
                (
                    change.field.as_str(),
                    change.change,
                    change.before.as_deref(),
                    change.after.as_deref(),
                )
            })
            .collect();

        assert_eq!(
            rows,
            vec![
                (
                    "env",
                    ChangeKind::Updated,
                    Some("MODE=dev"),
                    Some("MODE=prod")
                ),
                ("env", ChangeKind::Added, None, Some("NEW=1")),
                ("env", ChangeKind::Removed, Some("EXTRA=1"), None),
                ("label", ChangeKind::Added, None, Some("tier=gold")),
                ("label", ChangeKind::Removed, Some("team=infra"), None),
                ("workdir", ChangeKind::Updated, Some("/app"), Some("/srv")),
            ]
        );
    }

    #[test]
    fn running_spec_changes_warn_future_execs_only_under_restart_and_next_start() {
        let current = config(2, 1024);
        let patch = SandboxModificationPatch {
            env: vec![EnvVar::new("MODE", "prod"), EnvVar::new("NEW", "1")],
            workdir: Some("/srv".to_string()),
            labels: vec![("tier".to_string(), "gold".to_string())],
            ..SandboxModificationPatch::default()
        };

        for policy in [ModificationPolicy::Restart, ModificationPolicy::NextStart] {
            let plan = build_plan(
                "api".to_string(),
                SandboxStatus::Running,
                &current,
                None,
                LiveControl::default(),
                patch.clone(),
                policy,
            );

            let future_exec_fields: Vec<&str> = plan
                .warnings
                .iter()
                .filter(|warning| warning.message == FUTURE_EXECS_ONLY)
                .map(|warning| warning.field.as_str())
                .collect();
            // One warning per field: env is deduplicated, labels are excluded.
            assert_eq!(future_exec_fields, vec![ENV_FIELD, WORKDIR_FIELD]);
        }
    }

    #[test]
    fn future_exec_warning_skips_stopped_sandboxes_and_default_policy() {
        let current = config(2, 1024);
        let patch = SandboxModificationPatch {
            env: vec![EnvVar::new("MODE", "prod")],
            workdir: Some("/srv".to_string()),
            ..SandboxModificationPatch::default()
        };

        let cases = [
            (SandboxStatus::Stopped, ModificationPolicy::NextStart),
            (SandboxStatus::Stopped, ModificationPolicy::Restart),
            (SandboxStatus::Running, ModificationPolicy::NoRestart),
        ];
        for (status, policy) in cases {
            let plan = build_plan(
                "api".to_string(),
                status,
                &current,
                None,
                LiveControl::default(),
                patch.clone(),
                policy,
            );

            assert!(
                plan.warnings
                    .iter()
                    .all(|warning| warning.message != FUTURE_EXECS_ONLY),
                "unexpected future-exec warning for {status:?} under {policy:?}"
            );
        }
    }

    #[test]
    fn applying_env_label_workdir_patch_mutates_config() {
        let mut current = config(2, 1024);
        current.spec.env = vec![EnvVar::new("MODE", "dev"), EnvVar::new("EXTRA", "1")];
        current
            .spec
            .labels
            .insert("team".to_string(), "infra".to_string());
        let patch = SandboxModificationPatch {
            env: vec![EnvVar::new("MODE", "prod"), EnvVar::new("NEW", "1")],
            env_remove: vec!["EXTRA".to_string()],
            labels: vec![("tier".to_string(), "gold".to_string())],
            labels_remove: vec!["team".to_string()],
            workdir: Some("/srv".to_string()),
            ..SandboxModificationPatch::default()
        };

        apply_patch_to_config(&mut current, &patch);

        assert_eq!(
            current.spec.env,
            vec![EnvVar::new("MODE", "prod"), EnvVar::new("NEW", "1")]
        );
        assert_eq!(
            current.spec.labels.get("tier").map(String::as_str),
            Some("gold")
        );
        assert!(!current.spec.labels.contains_key("team"));
        assert_eq!(current.spec.runtime.workdir.as_deref(), Some("/srv"));
    }

    #[test]
    fn setting_and_removing_the_same_key_is_a_conflict() {
        let patch = SandboxModificationPatch {
            env: vec![EnvVar::new("MODE", "prod")],
            env_remove: vec!["MODE".to_string()],
            labels: vec![("team".to_string(), "infra".to_string())],
            labels_remove: vec!["team".to_string()],
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config(2, 1024),
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(plan.conflicts.len(), 2);
        assert_eq!(plan.conflicts[0].field, "env");
        assert!(plan.conflicts[0].message.contains("MODE"));
        assert_eq!(plan.conflicts[1].field, "label");
        assert!(plan.conflicts[1].message.contains("team"));
        assert!(validate_apply_supported(&plan).is_err());
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
            LiveControl::default(),
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

    //----------------------------------------------------------------------------------------------
    // Tests: Secrets
    //----------------------------------------------------------------------------------------------

    #[cfg(feature = "net")]
    const SECRET_SENTINEL: &str = "sentinel-secret-value";

    #[cfg(feature = "net")]
    fn config_with_secret(name: &str, value: &str) -> SandboxConfig {
        use microsandbox_network::secrets::config::{HostPattern, SecretEntry, SecretInjection};

        let mut config = config(2, 1024);
        let mut network = config.local_network_config().unwrap();
        network.secrets.secrets.push(SecretEntry {
            env_var: name.to_string(),
            value: zeroize::Zeroizing::new(value.to_string()),
            source: None,
            placeholder: format!("$MSB_{name}"),
            allowed_hosts: vec![HostPattern::Exact("api.example.com".into())],
            injection: SecretInjection::default(),
            on_violation: None,
            require_tls_identity: true,
        });
        config.set_local_network_config(network).unwrap();
        config
    }

    #[cfg(feature = "net")]
    fn secret_patch(
        name: &str,
        operation: SecretPatchOperation,
        hosts: &[&str],
    ) -> SandboxModificationPatch {
        let source = matches!(
            operation,
            SecretPatchOperation::Upsert | SecretPatchOperation::Rotate
        )
        .then(|| SecretSource::Env {
            var: name.to_string(),
        });
        SandboxModificationPatch {
            secrets: vec![SecretModificationPatch {
                name: name.to_string(),
                operation,
                source,
                placeholder: None,
                allowed_hosts: hosts.iter().map(ToString::to_string).collect(),
            }],
            ..SandboxModificationPatch::default()
        }
    }

    #[cfg(feature = "net")]
    fn secret_plan_dispositions(plan: &SandboxModificationPlan) -> Vec<ModificationDisposition> {
        plan.changes
            .iter()
            .map(|change| match change {
                PlannedChange::Secret(change) => change.disposition,
                PlannedChange::Config(_) => panic!("expected secret change"),
            })
            .collect()
    }

    #[cfg(feature = "net")]
    #[test]
    fn running_secret_rotate_remove_hosts_classify_live_with_runtime_support() {
        let config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let mut patch = secret_patch("API_KEY", SecretPatchOperation::Rotate, &[]);
        patch
            .secrets
            .extend(secret_patch("API_KEY", SecretPatchOperation::Remove, &[]).secrets);
        patch.secrets.extend(
            secret_patch(
                "API_KEY",
                SecretPatchOperation::UpdateHosts,
                &["*.example.org"],
            )
            .secrets,
        );

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                resize: false,
                secrets: true,
            },
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(
            secret_plan_dispositions(&plan),
            vec![ModificationDisposition::Live; 3]
        );
        assert!(plan.conflicts.is_empty());
        assert!(plan.warnings.is_empty());
        assert!(validate_apply_supported(&plan).is_ok());
    }

    #[cfg(feature = "net")]
    #[test]
    fn running_secret_add_and_placeholder_change_require_restart_even_with_live_support() {
        let config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let mut patch = secret_patch("NEW_KEY", SecretPatchOperation::Upsert, &["api.new.test"]);
        patch.secrets.push(SecretModificationPatch {
            name: "API_KEY".to_string(),
            operation: SecretPatchOperation::UpdatePlaceholder,
            source: None,
            placeholder: Some("$ROTATED_REF".to_string()),
            allowed_hosts: Vec::new(),
        });

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                resize: false,
                secrets: true,
            },
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(
            secret_plan_dispositions(&plan),
            vec![ModificationDisposition::RequiresRestart; 2]
        );
        assert!(validate_apply_supported(&plan).is_err());
    }

    #[cfg(feature = "net")]
    #[test]
    fn running_secret_rotate_requires_restart_without_runtime_support() {
        let config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let patch = secret_patch("API_KEY", SecretPatchOperation::Rotate, &[]);

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        let PlannedChange::Secret(change) = &plan.changes[0] else {
            panic!("expected secret change");
        };
        assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
        assert_eq!(
            change.reason.as_deref(),
            Some(LIVE_SECRET_RECONFIGURE_UNAVAILABLE)
        );
        assert!(
            plan.warnings
                .iter()
                .any(|warning| warning.field == SECRET_FIELD)
        );
        assert!(validate_apply_supported(&plan).is_err());
        // The restart policy unblocks the same plan shape.
        let restart_plan = SandboxModificationPlan {
            policy: ModificationPolicy::Restart,
            ..plan
        };
        assert!(validate_apply_supported(&restart_plan).is_ok());
    }

    #[cfg(feature = "net")]
    #[test]
    fn stopped_secret_changes_are_next_start_and_apply_supported() {
        let config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let patch = secret_patch("API_KEY", SecretPatchOperation::Rotate, &[]);

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config,
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(
            secret_plan_dispositions(&plan),
            vec![ModificationDisposition::NextStart]
        );
        assert!(validate_apply_supported(&plan).is_ok());
    }

    #[cfg(feature = "net")]
    #[test]
    fn secret_conflicts_reject_impossible_patches() {
        let config = config_with_secret("API_KEY", SECRET_SENTINEL);

        // Upserting a new secret without any allowed host.
        let patch = secret_patch("NEW_KEY", SecretPatchOperation::Upsert, &[]);
        let mut conflicts = Vec::new();
        push_secret_conflicts(&config, &patch, &mut conflicts);
        assert!(conflicts[0].message.contains("allowed host"));

        // Rotating a secret that does not exist.
        let patch = secret_patch("MISSING", SecretPatchOperation::Rotate, &[]);
        let mut conflicts = Vec::new();
        push_secret_conflicts(&config, &patch, &mut conflicts);
        assert!(conflicts[0].message.contains("does not exist"));

        // Store-backed sources are not implemented yet.
        let mut patch = secret_patch("API_KEY", SecretPatchOperation::Rotate, &[]);
        patch.secrets[0].source = Some(SecretSource::Store {
            reference: "vault://team/api-key".to_string(),
        });
        let mut conflicts = Vec::new();
        push_secret_conflicts(&config, &patch, &mut conflicts);
        assert!(conflicts[0].message.contains("store-backed"));

        // Rotating without any source.
        let mut patch = secret_patch("API_KEY", SecretPatchOperation::Rotate, &[]);
        patch.secrets[0].source = None;
        let mut conflicts = Vec::new();
        push_secret_conflicts(&config, &patch, &mut conflicts);
        assert!(conflicts[0].message.contains("source"));
    }

    #[cfg(feature = "net")]
    #[test]
    fn applying_secret_upsert_records_reference_not_value() {
        use microsandbox_network::secrets::config::{HostPattern, SecretSourceRef};

        let mut config = config(2, 1024);
        let patch = secret_patch(
            "API_KEY",
            SecretPatchOperation::Upsert,
            &["api.example.com"],
        );

        apply_secret_patch_to_config(&mut config, &patch).unwrap();

        let network = config.local_network_config().unwrap();
        let entry = &network.secrets.secrets[0];
        assert_eq!(entry.env_var, "API_KEY");
        assert!(entry.value.is_empty());
        assert_eq!(
            entry.source,
            Some(SecretSourceRef::Env {
                var: "API_KEY".into()
            })
        );
        assert_eq!(entry.placeholder, "$API_KEY");
        assert_eq!(
            entry.allowed_hosts,
            vec![HostPattern::Exact("api.example.com".into())]
        );
        assert!(entry.require_tls_identity);
    }

    #[cfg(feature = "net")]
    #[test]
    fn applying_secret_rotate_drops_inlined_value_and_keeps_placeholder() {
        use microsandbox_network::secrets::config::SecretSourceRef;

        let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let patch = secret_patch("API_KEY", SecretPatchOperation::Rotate, &[]);

        apply_secret_patch_to_config(&mut config, &patch).unwrap();

        let network = config.local_network_config().unwrap();
        let entry = &network.secrets.secrets[0];
        assert!(entry.value.is_empty());
        assert_eq!(
            entry.source,
            Some(SecretSourceRef::Env {
                var: "API_KEY".into()
            })
        );
        // Rotation keeps the guest-visible placeholder and host allow-list.
        assert_eq!(entry.placeholder, "$MSB_API_KEY");
        assert_eq!(entry.allowed_hosts.len(), 1);
    }

    #[cfg(feature = "net")]
    #[test]
    fn applying_secret_remove_deletes_entry() {
        let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let patch = secret_patch("API_KEY", SecretPatchOperation::Remove, &[]);

        apply_secret_patch_to_config(&mut config, &patch).unwrap();

        let network = config.local_network_config().unwrap();
        assert!(network.secrets.secrets.is_empty());
    }

    #[cfg(feature = "net")]
    #[test]
    fn applying_secret_hosts_update_replaces_allow_list() {
        use microsandbox_network::secrets::config::HostPattern;

        let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let patch = secret_patch(
            "API_KEY",
            SecretPatchOperation::UpdateHosts,
            &["*.example.org", "*"],
        );

        apply_secret_patch_to_config(&mut config, &patch).unwrap();

        let network = config.local_network_config().unwrap();
        assert_eq!(
            network.secrets.secrets[0].allowed_hosts,
            vec![
                HostPattern::Wildcard("*.example.org".into()),
                HostPattern::Any,
            ]
        );
    }

    #[cfg(feature = "net")]
    #[test]
    fn applying_secret_placeholder_update_renames_guest_reference() {
        let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let mut patch = secret_patch("API_KEY", SecretPatchOperation::UpdatePlaceholder, &[]);
        patch.secrets[0].placeholder = Some("$NEW_REF".to_string());

        apply_secret_patch_to_config(&mut config, &patch).unwrap();

        let network = config.local_network_config().unwrap();
        assert_eq!(network.secrets.secrets[0].placeholder, "$NEW_REF");
    }

    #[cfg(feature = "net")]
    #[test]
    fn rotate_flow_never_leaks_the_value_into_plans_configs_or_errors() {
        let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let patch = secret_patch("API_KEY", SecretPatchOperation::Rotate, &[]);

        // The plan for a live rotate is value-free even though the current
        // config carries an inlined value.
        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                resize: false,
                secrets: true,
            },
            patch.clone(),
            ModificationPolicy::NoRestart,
        );
        let plan_json = serde_json::to_string(&plan).unwrap();
        assert!(!plan_json.contains(SECRET_SENTINEL));

        // The persisted config drops the inlined value in favor of the
        // source reference.
        apply_secret_patch_to_config(&mut config, &patch).unwrap();
        let config_json = serde_json::to_string(&config).unwrap();
        assert!(!config_json.contains(SECRET_SENTINEL));
        assert!(config_json.contains("\"var\":\"API_KEY\""));

        // The live control batch carries the value only for socket transport;
        // any Debug-logged form of the request shows [redacted] instead.
        let rotated_value = format!("{SECRET_SENTINEL}-rotated");
        // SAFETY: unique variable name; no concurrent reader of this var.
        unsafe { std::env::set_var("API_KEY_MODIFY_LEAK_TEST", &rotated_value) };
        let mut live_patch = patch.clone();
        live_patch.secrets[0].source = Some(SecretSource::Env {
            var: "API_KEY_MODIFY_LEAK_TEST".to_string(),
        });
        let updates = live_secret_updates(&plan, &live_patch).unwrap();
        assert!(!updates.is_empty());
        let request =
            microsandbox_runtime::control::ControlRequest::SecretsUpdate { changes: updates };
        assert!(!format!("{request:?}").contains(SECRET_SENTINEL));
        unsafe { std::env::remove_var("API_KEY_MODIFY_LEAK_TEST") };

        // Resolution failures name the variable, never a value.
        let error = resolve_secret_source_value(
            "API_KEY",
            Some(&SecretSource::Env {
                var: "API_KEY_MODIFY_LEAK_TEST_MISSING".to_string(),
            }),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("API_KEY_MODIFY_LEAK_TEST_MISSING"));
        assert!(!message.contains(SECRET_SENTINEL));
    }

    #[cfg(feature = "net")]
    #[test]
    fn live_secret_updates_cover_only_live_dispositions() {
        use microsandbox_runtime::control::SecretLiveChange;

        let config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let mut patch = secret_patch("API_KEY", SecretPatchOperation::Remove, &[]);
        patch.secrets.extend(
            secret_patch(
                "API_KEY",
                SecretPatchOperation::UpdateHosts,
                &["api.example.com", "*.example.org"],
            )
            .secrets,
        );

        let live_plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                resize: false,
                secrets: true,
            },
            patch.clone(),
            ModificationPolicy::NoRestart,
        );
        let updates = live_secret_updates(&live_plan, &patch).unwrap();
        assert_eq!(updates.len(), 2);
        assert!(matches!(&updates[0], SecretLiveChange::Remove { name } if name == "API_KEY"));
        assert!(matches!(
            &updates[1],
            SecretLiveChange::SetAllowedHosts { name, hosts }
                if name == "API_KEY" && hosts.len() == 2
        ));

        // Next-start plans produce no live updates.
        let stopped_plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config,
            None,
            LiveControl::default(),
            patch.clone(),
            ModificationPolicy::NoRestart,
        );
        assert!(
            live_secret_updates(&stopped_plan, &patch)
                .unwrap()
                .is_empty()
        );
    }
}
