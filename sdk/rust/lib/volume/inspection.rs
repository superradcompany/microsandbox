//! Fresh observations of the captured volume identity.

use chrono::{DateTime, Utc};
use serde::Serialize;

use super::{Volume, VolumeKind};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One backend observation. Missing usage/capacity is unknown, not zero.
#[derive(Clone, Debug, Serialize)]
pub struct VolumeInfo {
    /// Stable resource identity.
    pub id: String,
    /// Name observed in this lookup.
    pub name: String,
    /// Storage representation.
    pub kind: VolumeKind,
    /// Whether this is the provider default volume.
    pub is_default: bool,
    /// Persisted quota in MiB, when limited.
    pub quota_mib: Option<u32>,
    /// Provider-reported usage; absent when unavailable.
    pub used_bytes: Option<u64>,
    /// Provider-reported capacity, when known.
    pub capacity_bytes: Option<u64>,
    /// Disk container format, for disk volumes.
    pub disk_format: Option<String>,
    /// Filesystem type, when reported.
    pub disk_fstype: Option<String>,
    /// Persisted labels from this lookup.
    pub labels: Vec<(String, String)>,
    /// Creation time, when reported by the provider.
    pub created_at: Option<DateTime<Utc>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Volume {
    /// Fetch mutable metadata without falling back to this object's captured observation.
    pub async fn info(&self) -> MicrosandboxResult<VolumeInfo> {
        let context = self.context().clone_shared();
        let current = if self.is_default() {
            context.volume_ops().get_default(context.clone()).await?
        } else {
            context
                .volume_ops()
                .get(context.clone(), self.name())
                .await?
        };
        // Provider lookup is currently name-selected. Reject replacements before exposing data.
        if current.id() != self.id() {
            return Err(MicrosandboxError::VolumeNotFound(self.id().to_string()));
        }
        Ok(current.observation())
    }

    /// Internal provider/CLI projection of an already fetched record.
    #[doc(hidden)]
    pub fn observation(&self) -> VolumeInfo {
        let current = self;
        VolumeInfo {
            id: current.id().to_string(),
            name: current.name().to_owned(),
            kind: current.kind(),
            is_default: current.is_default(),
            quota_mib: current.quota_mib_snapshot(),
            used_bytes: current
                .remote_state()
                .map(|state| state.used_bytes)
                .unwrap_or_else(|| current.local_state().and_then(|state| state.used_bytes)),
            capacity_bytes: current.capacity_bytes_snapshot(),
            disk_format: current.disk_format().map(str::to_owned),
            disk_fstype: current.disk_fstype().map(str::to_owned),
            labels: current.labels_snapshot().to_vec(),
            created_at: current.created_at(),
        }
    }
    /// Fetch the current persisted quota. Use info() to observe several fields together.
    pub async fn quota_mib(&self) -> MicrosandboxResult<Option<u32>> {
        Ok(self.info().await?.quota_mib)
    }
    /// Fetch reported usage, leaving unavailable measurements unknown.
    pub async fn used_bytes(&self) -> MicrosandboxResult<Option<u64>> {
        Ok(self.info().await?.used_bytes)
    }
    /// Fetch current capacity, when supplied by the provider.
    pub async fn capacity_bytes(&self) -> MicrosandboxResult<Option<u64>> {
        Ok(self.info().await?.capacity_bytes)
    }
    /// Fetch the current persisted labels.
    pub async fn labels(&self) -> MicrosandboxResult<Vec<(String, String)>> {
        Ok(self.info().await?.labels)
    }
}
