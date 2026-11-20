//! Live inspection is independent of runtime preparation and ownership.

use super::{Sandbox, SandboxConfigInspection, SandboxId, SandboxStatus};
use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Outcomes captured by this receiver's most recent preparation, not persisted settings.
/// These describe that preparation only; they are not a live lifecycle observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxLaunchInfo {
    /// This launch handed the boot workload to init; do not execute it again via the agent.
    pub init_owns_boot_workload: bool,
    /// This launch resumed a full VM snapshot rather than booting a fresh workload.
    pub resumed_from_full_snapshot: bool,
}

/// One backend observation. Values may change after this lookup completes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SandboxInfo {
    /// Stable resource identity.
    #[serde(serialize_with = "serialize_identity")]
    pub id: SandboxId,
    /// Name reported by this observation.
    pub name: String,
    /// Lifecycle status at the time of observation.
    #[serde(serialize_with = "serialize_status")]
    pub status: SandboxStatus,
    /// Most recent failure reported by the provider, if available.
    pub last_failure_message: Option<String>,
    /// Creation timestamp, when available.
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Latest modification/activity timestamp reported by the provider.
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Return captured launch outcomes without I/O or runtime preparation.
    ///
    /// Unprepared lookups return `None`. These flags belong to the receiver's
    /// retained session and must not be inferred from fresh persisted `config()`.
    /// Connecting to another owner's run does not claim to have launched it.
    pub fn launch_info(&self) -> Option<SandboxLaunchInfo> {
        self.binding.current().map(|session| SandboxLaunchInfo {
            init_owns_boot_workload: session.config.init_owns_boot_workload(),
            resumed_from_full_snapshot: session.config.resumed_from_full_snapshot(),
        })
    }

    /// Capture this exact sandbox without replacing its captured destination or identity.
    pub async fn checkpoint(&self, name: &str) -> MicrosandboxResult<crate::Checkpoint> {
        let context = self.context().clone_shared();
        let config = context
            .checkpoints()
            .builder(name)
            .from_sandbox(self.name())
            .build()?;
        context
            .snapshot_ops()
            .create_from(context.clone(), config, &self.id())
            .await
    }

    /// Inspect local disk usage for this identity without preparing the runtime.
    pub async fn storage_usage(&self) -> MicrosandboxResult<crate::StorageItemUsage> {
        self.refresh_handle().await?.storage_usage().await
    }

    /// Wait until this exact resource is observed in `status`, without starting it.
    ///
    /// Returns completion only; call `info()` for a fresh observation afterward.
    /// Compose caller deadlines/cancellation around this future. Completion does
    /// not guarantee the resource will remain in that state.
    pub async fn wait_for_status(&self, status: SandboxStatus) -> MicrosandboxResult<()> {
        self.refresh_handle()
            .await?
            .wait_for_status(status)
            .await
            .map(|_| ())
    }

    /// Fetch related inspection fields together without starting the resource.
    pub async fn info(&self) -> MicrosandboxResult<SandboxInfo> {
        let record = self.refresh_handle().await?;
        Ok(SandboxInfo {
            id: record.id(),
            name: record.name().to_owned(),
            status: record.status_snapshot(),
            last_failure_message: record.last_failure_message_snapshot(),
            created_at: record.created_at(),
            updated_at: record.updated_at(),
        })
    }

    /// Fetch the latest persisted configuration, including other clients' changes.
    ///
    /// Persisted settings need not already be applied to the current runtime.
    /// Lookup failures are returned; this never substitutes a cached configuration.
    pub async fn config(&self) -> MicrosandboxResult<SandboxConfigInspection> {
        let record = self.refresh_handle().await?;
        if record.local_state().is_some() {
            return Ok(SandboxConfigInspection::local(record.config()?.spec));
        }
        #[cfg(feature = "cloud")]
        {
            let spec: Option<serde_json::Value> = serde_json::from_str(record.config_json())?;
            if let Some(spec) = spec {
                let inspection = serde_json::from_value(spec)?;
                return Ok(SandboxConfigInspection::remote(
                    record.name().to_owned(),
                    inspection,
                ));
            }
        }
        // An omitted provider spec is unavailable information, not a default config.
        Err(crate::MicrosandboxError::unsupported(
            crate::error::Operation::SandboxConfig,
            crate::error::UnsupportedReason::NotAvailable(
                "provider omitted the persisted sandbox configuration".into(),
            ),
        ))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

// SDK inspection uses opaque identities and stable lowercase lifecycle names,
// independently of the database enum and the local/remote identity representation.
fn serialize_identity<S: serde::Serializer>(
    id: &SandboxId,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(id)
}

fn serialize_status<S: serde::Serializer>(
    status: &SandboxStatus,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(match status {
        SandboxStatus::Created => "created",
        SandboxStatus::Starting => "starting",
        SandboxStatus::Running => "running",
        SandboxStatus::Draining => "draining",
        SandboxStatus::Paused => "paused",
        SandboxStatus::Stopped => "stopped",
        SandboxStatus::Crashed => "crashed",
    })
}
