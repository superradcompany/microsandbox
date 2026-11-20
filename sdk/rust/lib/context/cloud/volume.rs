//! Cloud volume lifecycle: the [`VolumeOps`] impl for [`RemoteContext`],
//! the volume wire shape, and its conversions into the SDK's volume state.

use std::io::Error as IoError;
use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use futures::{StreamExt, future::BoxFuture, stream};
use reqwest::Method;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_util::task::AbortOnDropHandle;

use super::{
    RemoteContext,
    http::{FileTransfer, volume_download_stream},
};
use crate::context::{
    Context,
    volume::{CloudVolumeKind, CloudVolumeStatus, VolumeOps, VolumeRemoteState},
};
use crate::error::{Operation, UnsupportedReason};
use crate::sandbox::fs::{FsEntry, FsEntryKind, FsMetadata};
use crate::volume::{Volume, VolumeConfig, VolumeFsReadStream, VolumeFsWriteSink, VolumeKind};
use crate::{MicrosandboxError, MicrosandboxResult};

const FILE_PATH_HEADER: &str = "x-msb-file-path";
const FILE_RECURSIVE_HEADER: &str = "x-msb-file-recursive";

fn encoded_path(path: &str) -> String {
    URL_SAFE_NO_PAD.encode(path.as_bytes())
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Wire shape of the volume object returned by the cloud's volume routes.
#[derive(Debug, Clone, Deserialize)]
pub(in crate::context) struct CloudVolume {
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CloudFileKind {
    File,
    Directory,
}

#[derive(Debug, Deserialize)]
struct CloudFileInfo {
    path: String,
    kind: CloudFileKind,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    readonly: bool,
    #[serde(default)]
    accessed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    modified_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    created_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Deserialize)]
struct CloudFileList {
    entries: Vec<CloudFileInfo>,
}

#[derive(Deserialize)]
struct CloudFileStat {
    metadata: CloudFileInfo,
}

#[derive(Deserialize)]
struct CloudFileExists {
    exists: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods: RemoteContext (create-time validation)
//--------------------------------------------------------------------------------------------------

impl RemoteContext {
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

    async fn volume_id_for_fs(&self, target: &str) -> MicrosandboxResult<String> {
        // Handles capture the immutable server UUID when fetched. This avoids
        // redirecting an existing handle if a named volume is deleted and a
        // new volume is later created with the same display name.
        if let Some(id) = target.strip_prefix("cloud-id:") {
            return Ok(id.to_string());
        }

        // The empty target is retained for language-binding shims that ask
        // for the default volume without holding the Rust handle itself.
        if target.is_empty() {
            return Ok(self.get_default_volume().await?.id);
        }

        Ok(self.find_volume(target).await?.id)
    }

    async fn file_json<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        id: &str,
        suffix: &str,
        query: &[(&str, String)],
        json: Option<serde_json::Value>,
    ) -> MicrosandboxResult<T> {
        self.volume_file_request(method, id, suffix, query, json, FileTransfer::Request)
            .await?
            .json()
            .await
            .map_err(|error| {
                MicrosandboxError::Custom(format!(
                    "volume filesystem response could not be decoded: {error}"
                ))
            })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl VolumeOps for RemoteContext {
    fn create<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        config: VolumeConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Volume>> {
        Box::pin(async move {
            self.reject_unsupported_volume_options(&config)?;
            let capacity_gib = self.volume_capacity_gib(&config)?;
            let cloud =
                RemoteContext::create_volume(self, &config.name, capacity_gib, &config.labels)
                    .await?;
            let name = cloud.name.clone().unwrap_or_default();
            Ok(Volume::from_cloud(backend, cloud.into(), name))
        })
    }

    fn get<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Volume>> {
        Box::pin(async move {
            let cloud = RemoteContext::find_volume(self, name).await?;
            Ok(Volume::from_cloud(backend, cloud.into(), name.to_string()))
        })
    }

    fn get_default(&self, backend: Arc<dyn Context>) -> BoxFuture<'_, MicrosandboxResult<Volume>> {
        Box::pin(async move {
            let cloud = RemoteContext::get_default_volume(self).await?;
            Ok(Volume::from_cloud(backend, cloud.into(), String::new()))
        })
    }

    fn list<'a>(
        &'a self,
        backend: Arc<dyn Context>,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<Volume>>> {
        Box::pin(async move {
            let volumes = RemoteContext::list_volumes(self).await?;
            Ok(volumes
                .into_iter()
                .map(|cloud| {
                    // The org's shared default volume has no name; it lists
                    // with an empty one and is addressed by kind, not name.
                    let name = cloud.name.clone().unwrap_or_default();
                    Volume::from_cloud(backend.clone(), cloud.into(), name)
                })
                .collect())
        })
    }

    fn remove<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            let cloud = RemoteContext::find_volume(self, name).await?;
            RemoteContext::delete_volume(self, &cloud.id).await?;
            Ok(())
        })
    }

    fn destroy<'a>(
        &'a self,
        _backend: Arc<dyn Context>,
        target: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            let id = target
                .strip_prefix("cloud-id:")
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    MicrosandboxError::InvalidConfig(
                        "volume destruction requires a captured remote identity".into(),
                    )
                })?;
            self.delete_volume(id).await?;
            Ok(())
        })
    }

    fn fs_read<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Bytes>> {
        Box::pin(async move {
            let volume_id = self.volume_id_for_fs(name).await?;
            let response = self
                .volume_file_request(
                    Method::GET,
                    &volume_id,
                    "/content",
                    &[(FILE_PATH_HEADER, encoded_path(path))],
                    None,
                    FileTransfer::Download,
                )
                .await?;
            let mut stream = volume_download_stream(response, self.inner.request_timeout);
            let mut data = Vec::new();
            while let Some(chunk) = stream.next().await {
                data.extend_from_slice(&chunk?);
            }
            Ok(Bytes::from(data))
        })
    }

    fn fs_read_to_string<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<String>> {
        Box::pin(async move {
            let bytes = self.fs_read(name, path).await?;
            String::from_utf8(bytes.to_vec()).map_err(|error| {
                MicrosandboxError::Custom(format!("volume file is not valid UTF-8: {error}"))
            })
        })
    }

    fn fs_write<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
        data: Vec<u8>,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            let volume_id = self.volume_id_for_fs(name).await?;
            self.volume_file_request(
                Method::PUT,
                &volume_id,
                "/content",
                &[(FILE_PATH_HEADER, encoded_path(path))],
                None,
                FileTransfer::Upload(reqwest::Body::from(data)),
            )
            .await?;
            Ok(())
        })
    }

    fn fs_list<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<FsEntry>>> {
        Box::pin(async move {
            let volume_id = self.volume_id_for_fs(name).await?;
            let response: CloudFileList = self
                .file_json(
                    Method::GET,
                    &volume_id,
                    "",
                    &[(FILE_PATH_HEADER, encoded_path(path))],
                    None,
                )
                .await?;
            Ok(response.entries.into_iter().map(Into::into).collect())
        })
    }

    fn fs_stat<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<FsMetadata>> {
        Box::pin(async move {
            let volume_id = self.volume_id_for_fs(name).await?;
            let response: CloudFileStat = self
                .file_json(
                    Method::GET,
                    &volume_id,
                    "/stat",
                    &[(FILE_PATH_HEADER, encoded_path(path))],
                    None,
                )
                .await?;
            Ok(response.metadata.into())
        })
    }

    fn fs_mkdir<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            let volume_id = self.volume_id_for_fs(name).await?;
            self.volume_file_request(
                Method::POST,
                &volume_id,
                "/mkdir",
                &[],
                Some(serde_json::json!({ "path": path })),
                FileTransfer::Request,
            )
            .await?;
            Ok(())
        })
    }

    fn fs_remove<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
        recursive: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            let volume_id = self.volume_id_for_fs(name).await?;
            self.volume_file_request(
                Method::DELETE,
                &volume_id,
                "",
                &[
                    (FILE_PATH_HEADER, encoded_path(path)),
                    (FILE_RECURSIVE_HEADER, recursive.to_string()),
                ],
                None,
                FileTransfer::Request,
            )
            .await?;
            Ok(())
        })
    }

    fn fs_copy<'a>(
        &'a self,
        name: &'a str,
        from: &'a str,
        to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            let volume_id = self.volume_id_for_fs(name).await?;
            self.volume_file_request(
                Method::POST,
                &volume_id,
                "/copy",
                &[],
                Some(serde_json::json!({ "from": from, "to": to })),
                FileTransfer::Request,
            )
            .await?;
            Ok(())
        })
    }

    fn fs_rename<'a>(
        &'a self,
        name: &'a str,
        from: &'a str,
        to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            let volume_id = self.volume_id_for_fs(name).await?;
            self.volume_file_request(
                Method::POST,
                &volume_id,
                "/rename",
                &[],
                Some(serde_json::json!({ "from": from, "to": to })),
                FileTransfer::Request,
            )
            .await?;
            Ok(())
        })
    }

    fn fs_exists<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<bool>> {
        Box::pin(async move {
            let volume_id = self.volume_id_for_fs(name).await?;
            let response: CloudFileExists = self
                .file_json(
                    Method::GET,
                    &volume_id,
                    "/exists",
                    &[(FILE_PATH_HEADER, encoded_path(path))],
                    None,
                )
                .await?;
            Ok(response.exists)
        })
    }

    fn fs_read_stream<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<VolumeFsReadStream>> {
        Box::pin(async move {
            let volume_id = self.volume_id_for_fs(name).await?;
            let response = self
                .volume_file_request(
                    Method::GET,
                    &volume_id,
                    "/content",
                    &[(FILE_PATH_HEADER, encoded_path(path))],
                    None,
                    FileTransfer::Download,
                )
                .await?;
            let stream = volume_download_stream(response, self.inner.request_timeout);
            Ok(VolumeFsReadStream::from_stream(stream))
        })
    }

    fn fs_write_stream<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<VolumeFsWriteSink>> {
        Box::pin(async move {
            let id = self.volume_id_for_fs(name).await?;
            let path = path.to_string();
            let backend = self.clone();
            let (tx, mut rx) = mpsc::channel::<Bytes>(8);
            let completion = tokio::spawn(async move {
                // Reqwest can retain a body while a socket write is blocked even
                // after its request times out. Own the caller's receiver here so
                // ending the request also releases any blocked sink.write().
                let (body_tx, body_rx) = mpsc::channel(1);
                let _pump = AbortOnDropHandle::new(tokio::spawn(async move {
                    while let Some(chunk) = rx.recv().await {
                        if body_tx.send(chunk).await.is_err() {
                            return;
                        }
                    }
                }));
                let body_stream = stream::unfold(body_rx, |mut rx| async {
                    rx.recv().await.map(|chunk| (Ok::<_, IoError>(chunk), rx))
                });
                backend
                    .volume_file_request(
                        Method::PUT,
                        &id,
                        "/content",
                        &[(FILE_PATH_HEADER, encoded_path(&path))],
                        None,
                        FileTransfer::Upload(reqwest::Body::wrap_stream(body_stream)),
                    )
                    .await?;
                Ok(())
            });
            Ok(VolumeFsWriteSink::from_channel(tx, completion))
        })
    }
}

impl From<CloudVolume> for VolumeRemoteState {
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

impl From<CloudFileKind> for FsEntryKind {
    fn from(kind: CloudFileKind) -> Self {
        match kind {
            CloudFileKind::File => Self::File,
            CloudFileKind::Directory => Self::Directory,
        }
    }
}

impl From<CloudFileInfo> for FsEntry {
    fn from(info: CloudFileInfo) -> Self {
        Self {
            path: info.path,
            kind: info.kind.into(),
            size: info.size,
            mode: info.mode,
            uid: info.uid,
            gid: info.gid,
            accessed: info.accessed_at,
            modified: info.modified_at,
        }
    }
}

impl From<CloudFileInfo> for FsMetadata {
    fn from(info: CloudFileInfo) -> Self {
        Self {
            kind: info.kind.into(),
            size: info.size,
            mode: info.mode,
            uid: info.uid,
            gid: info.gid,
            readonly: info.readonly,
            accessed: info.accessed_at,
            modified: info.modified_at,
            created: info.created_at,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------
