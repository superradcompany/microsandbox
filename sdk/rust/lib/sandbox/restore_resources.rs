//! Operation-local resource authorization and captured agent state for snapshot restore.

use std::collections::BTreeSet;

#[cfg(feature = "local")]
use microsandbox_image::checkpoint::CheckpointGeometry;
use microsandbox_protocol::core::Ready;

#[cfg(feature = "local")]
use crate::MicrosandboxError;
use crate::{MicrosandboxResult, SandboxConfigPatch};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub(crate) struct RestoreResources {
    /// Descriptor admitted during archive inspection, checked again before child publication.
    #[cfg(feature = "local")]
    pub archive_manifest: Option<std::sync::Arc<crate::snapshot::Manifest>>,
    /// Full restore requires captured external filesystems and additional disks unless waived.
    /// Kept operation-local: older SDK launches and direct branches retain their contract.
    pub require_complete: bool,
    /// Explicitly waive missing backing independently of object compatibility checks.
    pub allow_missing: bool,
    /// Guest paths whose captured disk contents may be materialized privately.
    pub captured: BTreeSet<String>,
    /// Explicit destination mappings take precedence over captured disk inheritance.
    pub mapped: BTreeSet<String>,
    /// Fill unspecified choices only from validated local source records.
    pub inherit: bool,
    /// Immutable CPU and memory layout read from the checkpoint before config resolution.
    #[cfg(feature = "local")]
    pub geometry: Option<CheckpointGeometry>,
    /// Immutable nesting mode read from the checkpoint.
    pub nested_virt: Option<bool>,
    /// Captured agent advertisement; its policy remains authoritative on memory restore.
    pub agent_ready: Option<Ready>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RestoreResources {
    /// Discard every piece of captured guest state so a newly selected
    /// restore source cannot inherit stale inspection results.
    pub(crate) fn clear_captured(&mut self) {
        #[cfg(feature = "local")]
        {
            self.archive_manifest = None;
            self.geometry = None;
        }
        self.agent_ready = None;
        self.nested_virt = None;
    }

    /// Preserve the resumed guest's advertisement, without changing the captured
    /// guest configuration.
    #[cfg(feature = "local")]
    pub(crate) fn capture_agent_ready(
        &mut self,
        resources: &[microsandbox_image::checkpoint::ResourceDescriptor],
    ) -> MicrosandboxResult<()> {
        let agent = resources
            .iter()
            .find(|resource| resource.kind == "agent")
            .ok_or_else(|| {
                MicrosandboxError::SnapshotIntegrity("checkpoint has no captured agent".into())
            })?;

        let ready: Ready = serde_json::from_str(agent.binding.get("ready").ok_or_else(|| {
            MicrosandboxError::SnapshotIntegrity("checkpoint has no captured Ready".into())
        })?)
        .map_err(|error| {
            MicrosandboxError::SnapshotIntegrity(format!("invalid captured Ready: {error}"))
        })?;

        self.agent_ready = Some(ready);
        Ok(())
    }

    /// Validate explicit settings against the captured guest before merging defaults.
    #[cfg_attr(not(feature = "local"), allow(unused_variables))]
    pub(crate) fn validate_settings(
        &self,
        requested: &SandboxConfigPatch,
    ) -> MicrosandboxResult<()> {
        if let Some(nested) = self.nested_virt
            && requested
                .spec
                .resources
                .nested_virt
                .is_some_and(|value| value.unwrap_or(false) != nested)
        {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "a full snapshot must restore with its captured nested virtualization setting"
                    .into(),
            ));
        }
        #[cfg(feature = "local")]
        if let Some(geometry) = self.geometry {
            let resources = &requested.spec.resources;
            if resources.cpus.is_some_and(|value| value != geometry.vcpus)
                || resources
                    .max_cpus
                    .is_some_and(|value| value != geometry.max_vcpus)
                || resources
                    .memory_mib
                    .is_some_and(|value| value != geometry.memory_mib)
                || resources
                    .max_memory_mib
                    .is_some_and(|value| value != geometry.max_memory_mib)
            {
                return Err(MicrosandboxError::InvalidConfig(
                    "a full snapshot must restore with its captured CPU and memory geometry".into(),
                ));
            }
        }
        Ok(())
    }
}
