//! Operation-local resource authorization and captured agent state for snapshot restore.

use std::collections::BTreeSet;
#[cfg(feature = "local")]
use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(feature = "local")]
use microsandbox_image::GlobalCache;
#[cfg(feature = "local")]
use microsandbox_image::checkpoint::CheckpointGeometry;
use microsandbox_protocol::core::Ready;
#[cfg(feature = "local")]
use tempfile::TempDir;

#[cfg(feature = "local")]
use crate::MicrosandboxError;
use crate::{MicrosandboxResult, SandboxConfigPatch};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub(crate) struct RestoreResources {
    /// Validated archive files and cache leases retained until child publication.
    #[cfg(feature = "local")]
    pub archive: Option<Arc<PreparedArchive>>,
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
    /// Captured agent advertisement; its policy remains authoritative on memory restore.
    pub agent_ready: Option<Ready>,
}

/// Private archive staging retained by built configs without installing a snapshot.
#[cfg(feature = "local")]
pub(crate) struct PreparedArchive {
    /// Private decoded files; deleting the owner cleans up an unused build.
    pub stage: TempDir,
    /// Restore mode used when preparing the archive payload.
    pub mode: super::config::SnapshotRestoreMode,
    /// Archive selected when the retained files were decoded.
    pub source: PathBuf,
    /// Leases keep admitted cache entries alive through publication.
    pub cache_operation: GlobalCache,
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
            self.archive = None;
            self.geometry = None;
        }
        self.agent_ready = None;
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

#[cfg(feature = "local")]
impl PreparedArchive {
    /// Consume unique staging or copy it when another built config still owns the source.
    pub async fn into_stage(self: Arc<Self>, parent: &Path) -> MicrosandboxResult<TempDir> {
        let parent = parent.to_path_buf();
        let prepared = match Arc::try_unwrap(self) {
            Ok(prepared) if prepared.stage.path().parent() == Some(parent.as_path()) => {
                return Ok(prepared.stage);
            }
            Ok(prepared) => Arc::new(prepared),
            Err(prepared) => prepared,
        };
        tokio::task::spawn_blocking(move || {
            let stage = tempfile::Builder::new()
                .prefix(".archive-restore-")
                .tempdir_in(&parent)?;
            let mut directories = vec![(
                prepared.stage.path().to_path_buf(),
                stage.path().to_path_buf(),
            )];
            while let Some((source, target)) = directories.pop() {
                for entry in std::fs::read_dir(&source)? {
                    let entry = entry?;
                    let destination = target.join(entry.file_name());
                    let kind = entry.file_type()?;
                    if kind.is_dir() {
                        std::fs::create_dir(&destination)?;
                        directories.push((entry.path(), destination));
                    } else if kind.is_file() {
                        microsandbox_utils::copy::fast_copy(&entry.path(), &destination)?;
                        std::fs::set_permissions(&destination, entry.metadata()?.permissions())?;
                    } else {
                        return Err(MicrosandboxError::SnapshotIntegrity(
                            "archive staging contains a non-regular entry".into(),
                        ));
                    }
                }
            }
            Ok(stage)
        })
        .await
        .map_err(|error| MicrosandboxError::Custom(format!("copy archive staging: {error}")))?
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "local")]
impl fmt::Debug for PreparedArchive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedArchive")
            .field("stage", &self.stage)
            .finish_non_exhaustive()
    }
}
