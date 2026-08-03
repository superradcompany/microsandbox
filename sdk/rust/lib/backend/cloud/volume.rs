//! Cloud volume lifecycle: the [`VolumeBackend`] impl for [`CloudBackend`],
//! the volume wire shape, and its conversions into the SDK's volume state.

use std::sync::Arc;

use bytes::Bytes;
use futures::future::BoxFuture;
use serde::Deserialize;

use super::CloudBackend;
use crate::backend::{
    Backend,
    volume::{
        CloudVolumeKind, CloudVolumeStatus, VolumeBackend, VolumeCloudState, VolumeHandleCloudState,
    },
};
use crate::error::{Operation, UnsupportedReason};
use crate::sandbox::fs::{FsEntry, FsMetadata};
use crate::volume::{
    Volume, VolumeConfig, VolumeFsReadStream, VolumeFsWriteSink, VolumeHandle, VolumeKind,
};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Wire shape of the volume object returned by the cloud's volume routes.
#[derive(Debug, Clone, Deserialize)]
pub(in crate::backend) struct CloudVolume {
    /// Server-side UUID.
    pub id: String,
    /// User-facing name; the org's shared default volume has none.
    #[serde(default)]
    pub name: Option<String>,
    /// Whether this is the org's shared default volume or a named volume.
    pub kind: CloudVolumeKind,
    /// Lifecycle status at fetch time.
    pub status: CloudVolumeStatus,
    /// Bytes stored in the volume, when the cloud reports usage.
    #[serde(default)]
    pub used_bytes: Option<u64>,
    /// Per-volume storage limit in bytes; absent when the volume has none.
    #[serde(default)]
    pub capacity_bytes: Option<u64>,
    /// User-defined labels; empty when none are set.
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
    /// Creation timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last modification timestamp.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

//--------------------------------------------------------------------------------------------------
// Methods: CloudBackend (create-time validation)
//--------------------------------------------------------------------------------------------------

impl CloudBackend {
    /// Reject volume options the cloud's create contract does not accept.
    /// Cloud named volumes take only a name; storage sizing and placement
    /// are managed for you.
    fn reject_unsupported_volume_options(&self, config: &VolumeConfig) -> MicrosandboxResult<()> {
        if config.kind != VolumeKind::Directory {
            return Err(MicrosandboxError::unsupported(
                Operation::VolumeCreate,
                UnsupportedReason::ConfigField("disk"),
            ));
        }
        if config.capacity_mib.is_some() {
            return Err(MicrosandboxError::unsupported(
                Operation::VolumeCreate,
                UnsupportedReason::ConfigField("capacity"),
            ));
        }
        Ok(())
    }

    /// Convert the config's storage cap to the whole-GiB unit the cloud
    /// accepts. `None` when no cap is requested.
    fn volume_capacity_gib(&self, config: &VolumeConfig) -> MicrosandboxResult<Option<u32>> {
        let Some(quota_mib) = config.quota_mib else {
            return Ok(None);
        };
        if quota_mib == 0 || quota_mib % 1024 != 0 {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "cloud volume caps are whole GiB; got {quota_mib} MiB"
            )));
        }
        Ok(Some(quota_mib / 1024))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl VolumeBackend for CloudBackend {
    fn create<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: VolumeConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Volume>> {
        Box::pin(async move {
            self.reject_unsupported_volume_options(&config)?;
            let capacity_gib = self.volume_capacity_gib(&config)?;
            let cloud =
                CloudBackend::create_volume(self, &config.name, capacity_gib, &config.labels)
                    .await?;
            let name = cloud.name.clone().unwrap_or_default();
            Ok(Volume::from_cloud(backend, cloud.into(), name))
        })
    }

    fn get<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<VolumeHandle>> {
        Box::pin(async move {
            let cloud = CloudBackend::find_volume(self, name).await?;
            Ok(VolumeHandle::from_cloud(
                backend,
                cloud.into(),
                name.to_string(),
            ))
        })
    }

    fn list<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<VolumeHandle>>> {
        Box::pin(async move {
            let volumes = CloudBackend::list_volumes(self).await?;
            Ok(volumes
                .into_iter()
                .map(|cloud| {
                    // The org's shared default volume has no name; it lists
                    // with an empty one and is addressed by kind, not name.
                    let name = cloud.name.clone().unwrap_or_default();
                    VolumeHandle::from_cloud(backend.clone(), cloud.into(), name)
                })
                .collect())
        })
    }

    fn remove<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            let cloud = CloudBackend::find_volume(self, name).await?;
            CloudBackend::delete_volume(self, &cloud.id).await?;
            Ok(())
        })
    }

    fn fs_read<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Bytes>> {
        Box::pin(async move { Err(unsupported(Operation::VolumeFsRead)) })
    }

    fn fs_read_to_string<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<String>> {
        Box::pin(async move { Err(unsupported(Operation::VolumeFsReadToString)) })
    }

    fn fs_write<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
        _data: Vec<u8>,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported(Operation::VolumeFsWrite)) })
    }

    fn fs_list<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<FsEntry>>> {
        Box::pin(async move { Err(unsupported(Operation::VolumeFsList)) })
    }

    fn fs_stat<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<FsMetadata>> {
        Box::pin(async move { Err(unsupported(Operation::VolumeFsStat)) })
    }

    fn fs_mkdir<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported(Operation::VolumeFsMkdir)) })
    }

    fn fs_remove<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
        _recursive: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported(Operation::VolumeFsRemove)) })
    }

    fn fs_copy<'a>(
        &'a self,
        _name: &'a str,
        _from: &'a str,
        _to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported(Operation::VolumeFsCopy)) })
    }

    fn fs_rename<'a>(
        &'a self,
        _name: &'a str,
        _from: &'a str,
        _to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported(Operation::VolumeFsRename)) })
    }

    fn fs_exists<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<bool>> {
        Box::pin(async move { Err(unsupported(Operation::VolumeFsExists)) })
    }

    fn fs_read_stream<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<VolumeFsReadStream>> {
        Box::pin(async move { Err(unsupported(Operation::VolumeFsReadStream)) })
    }

    fn fs_write_stream<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<VolumeFsWriteSink>> {
        Box::pin(async move { Err(unsupported(Operation::VolumeFsWriteStream)) })
    }
}

impl From<CloudVolume> for VolumeCloudState {
    fn from(cloud: CloudVolume) -> Self {
        Self {
            id: cloud.id,
            used_bytes: cloud.used_bytes,
            capacity_bytes: cloud.capacity_bytes,
            labels: cloud.labels.clone().into_iter().collect(),
            kind: cloud.kind,
            status: cloud.status,
            created_at: cloud.created_at,
            updated_at: cloud.updated_at,
        }
    }
}

impl From<CloudVolume> for VolumeHandleCloudState {
    fn from(cloud: CloudVolume) -> Self {
        Self {
            id: cloud.id,
            used_bytes: cloud.used_bytes,
            capacity_bytes: cloud.capacity_bytes,
            labels: cloud.labels.clone().into_iter().collect(),
            kind: cloud.kind,
            status: cloud.status,
            created_at: cloud.created_at,
            updated_at: cloud.updated_at,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build a uniform `Unsupported` error for cloud volume filesystem ops, which
/// are not exposed by the cloud yet — volume contents are reached by mounting
/// the volume into a sandbox.
fn unsupported(op: Operation) -> MicrosandboxError {
    MicrosandboxError::unsupported(op, UnsupportedReason::MountIntoSandbox)
}
