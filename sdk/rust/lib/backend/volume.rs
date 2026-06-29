//! Volume lifecycle backend trait.
//!
//! Per the SDK local-cloud parity plan (D6.4): `Volume` / `VolumeHandle` /
//! `VolumeFs` stay single types with no public variants. They hold
//! `Arc<dyn Backend>` plus a backend-private `VolumeInner` / `VolumeHandleInner`
//! enum. The trait returns the outer types — variant state is constructed
//! inside each backend's trait impl and wrapped with the `Arc<dyn Backend>`
//! the caller passes in.
//!
//! Cloud-side volume ops route to `Unsupported` until Phase 6 — see the plan's
//! D14 table.

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::future::BoxFuture;

use super::{Backend, CloudBackend, LocalBackend};
use crate::sandbox::fs::{FsEntry, FsMetadata};
use crate::volume::{
    Volume, VolumeConfig, VolumeFsReadStream, VolumeFsWriteSink, VolumeHandle, VolumeKind,
};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Backend-private state behind [`Volume`].
///
/// Users never see this enum directly — they get the outer `Volume` and reach
/// variant-specific data through the [`Volume::local`](crate::volume::Volume::local)
/// / [`Volume::cloud`](crate::volume::Volume::cloud) accessors.
pub enum VolumeInner {
    /// Local-disk-backed volume state.
    Local(VolumeLocalState),
    /// Cloud msb-cloud-backed volume state.
    Cloud(VolumeCloudState),
}

/// Local-disk-backed volume state held inside [`VolumeInner::Local`].
pub struct VolumeLocalState {
    /// Host directory rooted at `volumes_dir/<name>`.
    pub path: PathBuf,
    /// Storage kind.
    pub kind: VolumeKind,
    /// Disk capacity in bytes for disk volumes.
    pub capacity_bytes: Option<u64>,
    /// Disk image format for disk volumes.
    pub disk_format: Option<String>,
    /// Inner disk filesystem for disk volumes.
    pub disk_fstype: Option<String>,
}

/// Cloud msb-cloud-backed volume state held inside [`VolumeInner::Cloud`].
///
/// Placeholder shape — populated when cloud volumes ship in Phase 6.
pub struct VolumeCloudState {
    /// Server-side UUID.
    pub id: String,
    /// Owning org's UUID.
    pub org_id: String,
    /// Storage kind.
    pub kind: VolumeKind,
    /// Disk capacity in bytes for disk volumes.
    pub capacity_bytes: Option<u64>,
    /// Disk image format for disk volumes.
    pub disk_format: Option<String>,
    /// Inner disk filesystem for disk volumes.
    pub disk_fstype: Option<String>,
}

/// Backend-private state behind [`VolumeHandle`] — the lightweight DB-row view.
#[derive(Clone)]
pub enum VolumeHandleInner {
    /// Local persisted volume handle.
    Local(VolumeHandleLocalState),
    /// Cloud msb-cloud volume handle.
    Cloud(VolumeHandleCloudState),
}

/// Local handle state. Snapshot of the database row.
#[derive(Clone)]
pub struct VolumeHandleLocalState {
    /// SQLite row id for this volume.
    pub db_id: i32,
    /// Host directory rooted at `volumes_dir/<name>`.
    pub path: PathBuf,
    /// Configured quota in MiB, when set.
    pub quota_mib: Option<u32>,
    /// Storage kind.
    pub kind: VolumeKind,
    /// Disk usage snapshot at handle-creation time.
    pub used_bytes: u64,
    /// Disk capacity in bytes for disk volumes.
    pub capacity_bytes: Option<u64>,
    /// Disk image format for disk volumes.
    pub disk_format: Option<String>,
    /// Inner disk filesystem for disk volumes.
    pub disk_fstype: Option<String>,
    /// Key-value labels associated with the volume.
    pub labels: Vec<(String, String)>,
    /// When this volume was first recorded, if known.
    pub created_at: Option<DateTime<Utc>>,
}

/// Cloud handle state. Captures the snapshot msb-cloud returned at fetch time.
///
/// Placeholder shape — populated when cloud volumes ship in Phase 6.
#[derive(Clone)]
pub struct VolumeHandleCloudState {
    /// Server-side UUID.
    pub id: String,
    /// Owning org's UUID.
    pub org_id: String,
    /// Configured quota in MiB, when set.
    pub quota_mib: Option<u32>,
    /// Storage kind.
    pub kind: VolumeKind,
    /// Disk usage snapshot at handle-fetch time.
    pub used_bytes: u64,
    /// Disk capacity in bytes for disk volumes.
    pub capacity_bytes: Option<u64>,
    /// Disk image format for disk volumes.
    pub disk_format: Option<String>,
    /// Inner disk filesystem for disk volumes.
    pub disk_fstype: Option<String>,
    /// Key-value labels associated with the volume.
    pub labels: Vec<(String, String)>,
    /// When this volume was first recorded, if known.
    pub created_at: Option<DateTime<Utc>>,
}

/// Resource-specific backend for volume lifecycle + host-side filesystem ops.
///
/// Trait methods take the [`Arc<dyn Backend>`] that they should wrap any
/// returned [`Volume`] / [`VolumeHandle`] with. Callers (e.g. `Volume::create`)
/// resolve the backend via [`default_backend`](super::default_backend) and
/// forward it through.
///
/// Cloud-side `fs_*` ops ultimately route through msb-cloud HTTP per the plan's
/// D9, but in this commit cloud returns [`MicrosandboxError::Unsupported`] for
/// every method — cloud volumes ship in Phase 6.
pub trait VolumeBackend: Send + Sync {
    /// Create a volume. The returned outer [`Volume`] carries the supplied
    /// `backend` Arc and the variant-specific state inside [`VolumeInner`].
    fn create<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: VolumeConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Volume>>;

    /// Get a volume handle by name.
    fn get<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<VolumeHandle>>;

    /// List all volumes.
    fn list<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<VolumeHandle>>>;

    /// Remove a volume by name.
    fn remove<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Read an entire file into memory as raw bytes.
    fn fs_read<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Bytes>>;

    /// Read an entire file into memory as a UTF-8 string.
    fn fs_read_to_string<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<String>>;

    /// Write data to a file, creating parent directories as needed.
    fn fs_write<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
        data: Vec<u8>,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// List the immediate children of a directory (non-recursive).
    fn fs_list<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<FsEntry>>>;

    /// Get file/directory metadata.
    fn fs_stat<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<FsMetadata>>;

    /// Create a directory (and parents).
    fn fs_mkdir<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Remove a file or directory.
    ///
    /// When `recursive` is `false` only single files are removed; pointing at
    /// a directory yields an OS-level "is a directory" error. When `recursive`
    /// is `true` the path is removed along with all of its contents.
    fn fs_remove<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
        recursive: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Copy a file within the volume.
    fn fs_copy<'a>(
        &'a self,
        name: &'a str,
        from: &'a str,
        to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Rename / move a file or directory.
    fn fs_rename<'a>(
        &'a self,
        name: &'a str,
        from: &'a str,
        to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Check whether a path exists.
    fn fs_exists<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<bool>>;

    /// Open a streaming reader for a volume file.
    fn fs_read_stream<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<VolumeFsReadStream>>;

    /// Open a streaming writer for a volume file. Creates parent dirs.
    fn fs_write_stream<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<VolumeFsWriteSink>>;
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: LocalBackend
//--------------------------------------------------------------------------------------------------

impl VolumeBackend for LocalBackend {
    fn create<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: VolumeConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Volume>> {
        Box::pin(async move { crate::volume::create_local(backend, config).await })
    }

    fn get<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<VolumeHandle>> {
        Box::pin(async move { crate::volume::get_local(backend, name).await })
    }

    fn list<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<VolumeHandle>>> {
        Box::pin(async move { crate::volume::list_local(backend).await })
    }

    fn remove<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::volume::remove_local(backend, name).await })
    }

    fn fs_read<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Bytes>> {
        Box::pin(async move { crate::volume::fs::local::read(self, name, path).await })
    }

    fn fs_read_to_string<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<String>> {
        Box::pin(async move { crate::volume::fs::local::read_to_string(self, name, path).await })
    }

    fn fs_write<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
        data: Vec<u8>,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::volume::fs::local::write(self, name, path, &data).await })
    }

    fn fs_list<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<FsEntry>>> {
        Box::pin(async move { crate::volume::fs::local::list(self, name, path).await })
    }

    fn fs_stat<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<FsMetadata>> {
        Box::pin(async move { crate::volume::fs::local::stat(self, name, path).await })
    }

    fn fs_mkdir<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::volume::fs::local::mkdir(self, name, path).await })
    }

    fn fs_remove<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
        recursive: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::volume::fs::local::remove(self, name, path, recursive).await })
    }

    fn fs_copy<'a>(
        &'a self,
        name: &'a str,
        from: &'a str,
        to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::volume::fs::local::copy(self, name, from, to).await })
    }

    fn fs_rename<'a>(
        &'a self,
        name: &'a str,
        from: &'a str,
        to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::volume::fs::local::rename(self, name, from, to).await })
    }

    fn fs_exists<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<bool>> {
        Box::pin(async move { crate::volume::fs::local::exists(self, name, path).await })
    }

    fn fs_read_stream<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<VolumeFsReadStream>> {
        Box::pin(async move { crate::volume::fs::local::read_stream(self, name, path).await })
    }

    fn fs_write_stream<'a>(
        &'a self,
        name: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<VolumeFsWriteSink>> {
        Box::pin(async move { crate::volume::fs::local::write_stream(self, name, path).await })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations: CloudBackend
//--------------------------------------------------------------------------------------------------

impl VolumeBackend for CloudBackend {
    fn create<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _config: VolumeConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Volume>> {
        Box::pin(async move { Err(unsupported("Volume::create")) })
    }

    fn get<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<VolumeHandle>> {
        Box::pin(async move { Err(unsupported("Volume::get")) })
    }

    fn list<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<VolumeHandle>>> {
        Box::pin(async move { Err(unsupported("Volume::list")) })
    }

    fn remove<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported("Volume::remove")) })
    }

    fn fs_read<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Bytes>> {
        Box::pin(async move { Err(unsupported("VolumeFs::read")) })
    }

    fn fs_read_to_string<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<String>> {
        Box::pin(async move { Err(unsupported("VolumeFs::read_to_string")) })
    }

    fn fs_write<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
        _data: Vec<u8>,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported("VolumeFs::write")) })
    }

    fn fs_list<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<FsEntry>>> {
        Box::pin(async move { Err(unsupported("VolumeFs::list")) })
    }

    fn fs_stat<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<FsMetadata>> {
        Box::pin(async move { Err(unsupported("VolumeFs::stat")) })
    }

    fn fs_mkdir<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported("VolumeFs::mkdir")) })
    }

    fn fs_remove<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
        _recursive: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported("VolumeFs::remove")) })
    }

    fn fs_copy<'a>(
        &'a self,
        _name: &'a str,
        _from: &'a str,
        _to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported("VolumeFs::copy")) })
    }

    fn fs_rename<'a>(
        &'a self,
        _name: &'a str,
        _from: &'a str,
        _to: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { Err(unsupported("VolumeFs::rename")) })
    }

    fn fs_exists<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<bool>> {
        Box::pin(async move { Err(unsupported("VolumeFs::exists")) })
    }

    fn fs_read_stream<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<VolumeFsReadStream>> {
        Box::pin(async move { Err(unsupported("VolumeFs::read_stream")) })
    }

    fn fs_write_stream<'a>(
        &'a self,
        _name: &'a str,
        _path: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<VolumeFsWriteSink>> {
        Box::pin(async move { Err(unsupported("VolumeFs::write_stream")) })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build a uniform `Unsupported` error for cloud volume ops — all of them are
/// gated behind Phase 6.
fn unsupported(feature: &str) -> MicrosandboxError {
    MicrosandboxError::Unsupported {
        feature: feature.into(),
        available_when: "when cloud volumes ship".into(),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{LocalBackend, set_default_backend};
    use crate::volume::VolumeConfig;

    /// Regression test for the asymmetric-signature P1: `LocalBackend::remove`
    /// must operate on the passed-in `backend` Arc, not on the process-wide
    /// `default_backend()`. Two `LocalBackend` instances live in separate
    /// home dirs (so separate SQLite DBs). The default is installed on
    /// backend A; backend B's trait impl is invoked directly. The remove
    /// must hit B's DB (and fail because the volume doesn't exist there),
    /// not silently succeed by re-resolving the default.
    #[tokio::test]
    async fn local_backend_remove_uses_passed_backend_not_global_default() {
        let home_a = tempfile::tempdir().unwrap();
        let home_b = tempfile::tempdir().unwrap();

        let backend_a: Arc<dyn Backend> = Arc::new(
            LocalBackend::builder()
                .home(home_a.path())
                .build()
                .await
                .unwrap(),
        );
        let backend_b: Arc<dyn Backend> = Arc::new(
            LocalBackend::builder()
                .home(home_b.path())
                .build()
                .await
                .unwrap(),
        );

        // Create a volume only in backend A.
        backend_a
            .volumes()
            .create(
                backend_a.clone(),
                VolumeConfig {
                    name: "shared-name".into(),
                    kind: crate::volume::VolumeKind::Directory,
                    quota_mib: None,
                    capacity_mib: None,
                    labels: Vec::new(),
                },
            )
            .await
            .unwrap();

        // Install A as the process default. If the trait impl re-resolved
        // `default_backend()` (the bug we just fixed) it would find A and
        // successfully delete A's volume — even though we asked B.
        set_default_backend(backend_a.clone());

        // Call remove via backend B. Backend B has no such volume, so this
        // must error with `VolumeNotFound`.
        let err = backend_b
            .volumes()
            .remove(backend_b.clone(), "shared-name")
            .await
            .expect_err("remove should fail: volume does not exist in backend B");
        assert!(
            matches!(err, MicrosandboxError::VolumeNotFound(_)),
            "expected VolumeNotFound, got: {err:?}"
        );

        // Sanity check: A's volume is still there — the misrouted remove
        // would have deleted it.
        let handles = backend_a.volumes().list(backend_a.clone()).await.unwrap();
        assert!(
            handles.iter().any(|h| h.name() == "shared-name"),
            "backend A's volume should still exist after the (correctly-routed) B remove"
        );
    }
}
