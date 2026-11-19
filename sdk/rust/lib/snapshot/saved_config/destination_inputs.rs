//! Keep composed destination inputs and their unresolved obligations in one owned value.

use std::fmt;

use microsandbox_types::{SandboxPolicy, SandboxSpec, SandboxSpecPatch};

use super::SavedConfigurationPlan;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Inputs for destination admission, not an admitted or launchable sandbox configuration.
///
/// Exact script backing, deferred command/init requirements, saved relaxations and captured
/// resource obligations remain in `plan()`. No serialization or conversion into a bare
/// SandboxSpec is provided: consumers must finish those checks before activation/persistence.
pub struct SavedDestinationInputs {
    config: crate::SandboxConfig,
    plan: SavedConfigurationPlan,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SavedDestinationInputs {
    pub(super) fn new(spec: SandboxSpec, plan: SavedConfigurationPlan) -> Self {
        let mut config = crate::SandboxConfig::from(spec);
        config.deferred_command_bindings = plan.runtime().inputs().deferred_command_bindings();
        config.restored_exec_limits = plan
            .execution()
            .selection()
            .exec_limits
            .filter(|policy| *policy != microsandbox_types::ExecLimits::default());
        Self { config, plan }
    }

    /// Install the selected disk-boot inputs only after checking all unresolved obligations.
    /// Keep host paths, runtime handles, replacement policy and source staging on the destination.
    #[cfg(feature = "local")]
    pub(crate) fn apply_disk(
        self,
        destination: &mut crate::SandboxConfig,
    ) -> crate::MicrosandboxResult<()> {
        let plan = &self.plan;
        if !plan
            .network_policy()
            .selection()
            .required_approvals
            .is_empty()
            || !plan.storage().selection().required_approvals.is_empty()
            || !plan.secrets().selection().tls_identity_approvals.is_empty()
        {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "SCFG_POLICY: restore needs explicit destination permission for a saved policy"
                    .into(),
            ));
        }
        if !plan.gateway().guest_trust_certificates()?.is_empty()
            || !plan.runtime().scripts().is_empty()
        {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "SCFG_BINDING: guest certificate or registered script backing requires preparation"
                    .into(),
            ));
        }
        let (cpu_default, memory_default) = plan.resources().destination_allocation();
        if cpu_default {
            tracing::warn!(
                cpus = self.config.spec.resources.cpus,
                "snapshot CPU allocation was unknown; using destination CPU count"
            );
        }
        if memory_default {
            tracing::warn!(
                memory_mib = self.config.spec.resources.memory_mib,
                "snapshot memory allocation was unknown; using destination memory size"
            );
        }
        destination.restore_resources.portable_defaults_applied = true;
        destination.spec = self.config.spec;
        destination.deferred_command_bindings = self.config.deferred_command_bindings;
        destination.restored_exec_limits = self.config.restored_exec_limits;
        Ok(())
    }

    /// Native inputs only. Known bindings for a future command remain on the destination
    /// and must be enforced by its runtime. Whole unknown command fields fail preparation.
    pub fn spec_inputs(&self) -> &SandboxSpec {
        &self.config.spec
    }

    /// The same immutable source/operation plan that produced these inputs. It retains exact
    /// scripts, original binding references and every materialization/admission obligation.
    pub fn plan(&self) -> &SavedConfigurationPlan {
        &self.plan
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for SavedDestinationInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Neither native values nor paths/credentials belong in preparation diagnostics.
        f.debug_struct("SavedDestinationInputs")
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn destination_fields(lower: &SandboxSpec, explicit: &SandboxSpecPatch) -> SandboxSpec {
    // These fields belong to the destination operation, never the saved source. Select
    // only them here: applying the whole patch after family assembly could revive cleared
    // CMD, overwrite bound mounts, or route exact scripts through the ordinary writer.
    SandboxSpec {
        name: explicit.name.clone().unwrap_or_else(|| lower.name.clone()),
        image: explicit
            .image
            .clone()
            .unwrap_or_else(|| lower.image.clone()),
        patches: explicit
            .patches
            .clone()
            .unwrap_or_else(|| lower.patches.clone()),
        pull_policy: explicit.pull_policy.unwrap_or(lower.pull_policy),
        deployment_profile: explicit
            .deployment_profile
            .unwrap_or(lower.deployment_profile),
        labels: lower
            .labels
            .iter()
            .filter(|(key, _)| crate::sandbox::reserved_label_prefix(key).is_some())
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        lifecycle: SandboxPolicy {
            ephemeral: explicit
                .lifecycle
                .ephemeral
                .unwrap_or(lower.lifecycle.ephemeral),
            ..Default::default()
        },
        ..Default::default()
    }
}
