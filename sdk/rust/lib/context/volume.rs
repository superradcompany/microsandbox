//! Volume lifecycle backend trait.
//!
//! Per the SDK local-cloud parity plan (D6.4): `Volume` /
//! `VolumeFs` stay single types with no public variants. They hold
//! `Arc<dyn Context>` plus a backend-private `VolumeInner`
//! enum. The trait returns the outer types — variant state is constructed
//! inside each backend's trait impl and wrapped with the `Arc<dyn Context>`
//! the caller passes in.
//!
//! Cloud volumes support create / get / list / remove plus direct filesystem
//! operations. Default-volume lookup is Cloud-only by design.

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::future::BoxFuture;

use super::Context;
#[cfg(feature = "local")]
use super::LocalContext;
use crate::MicrosandboxResult;
use crate::sandbox::fs::{FsEntry, FsMetadata};
use crate::volume::{Volume, VolumeConfig, VolumeFsReadStream, VolumeFsWriteSink, VolumeKind};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Kind of a cloud volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudVolumeKind {
    /// The org's always-present shared volume. It has no name and cannot be
    /// deleted.
    Host,
    /// A user-created named volume.
    Managed,
}

/// Lifecycle status of a cloud volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudVolumeStatus {
    /// Usable; mountable into sandboxes.
    Active,
    /// Scheduled for deletion.
    Deleting,
}

/// Context-private state behind [`Volume`] — the lightweight DB-row view.
#[derive(Clone)]
pub enum VolumeInner {
    /// Local persisted volume handle.
    Local(VolumeLocalState),
    /// Cloud msb-cloud volume handle.
    Cloud(VolumeRemoteState),
}

/// Local handle state. Snapshot of the database row.
#[derive(Clone)]
pub struct VolumeLocalState {
    /// SQLite row id for this volume.
    pub db_id: i32,
    /// Host directory rooted at `volumes_dir/<name>`.
    pub path: PathBuf,
    /// Configured quota in MiB, when set.
    pub quota_mib: Option<u32>,
    /// Storage kind.
    pub kind: VolumeKind,
    /// Disk usage snapshot at handle-creation time.
    pub used_bytes: Option<u64>,
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

/// Cloud handle state. Captures the snapshot the cloud API returned at fetch time.
#[derive(Clone)]
pub struct VolumeRemoteState {
    /// Server-side UUID.
    pub id: String,
    /// Bytes stored in the volume, when the cloud reports usage.
    pub used_bytes: Option<u64>,
    /// Per-volume storage limit in bytes; absent when the volume has none.
    pub capacity_bytes: Option<u64>,
    /// User-defined labels; empty when none are set.
    pub labels: Vec<(String, String)>,
    /// Whether this is the org's shared default volume or a named volume.
    pub kind: CloudVolumeKind,
    /// Lifecycle status at fetch time.
    pub status: CloudVolumeStatus,
    /// Creation timestamp returned by the cloud.
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp returned by the cloud.
    pub updated_at: DateTime<Utc>,
}

/// Resource-specific backend for volume lifecycle and filesystem operations.
///
/// Trait methods take the [`Arc<dyn Context>`] that they should wrap any
/// returned [`Volume`] with. Callers (e.g. `Volume::create`)
/// resolve the backend via [`configured_context`](super::configured_context) and
/// forward it through.
///
/// Cloud-side `fs_*` operations route through the cloud HTTP API while local
/// operations remain scoped to the configured local volume root.
pub trait VolumeOps: Send + Sync {
    /// Create a volume. The returned outer [`Volume`] carries the supplied
    /// `backend` Arc and the variant-specific state inside [`VolumeInner`].
    fn create<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        config: VolumeConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Volume>>;

    /// Get a volume handle by name.
    fn get<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Volume>>;

    /// Get the backend-provided default volume.
    fn get_default(&self, backend: Arc<dyn Context>) -> BoxFuture<'_, MicrosandboxResult<Volume>>;

    /// List all volumes.
    fn list<'a>(
        &'a self,
        backend: Arc<dyn Context>,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<Volume>>>;

    /// Remove a volume by name.
    fn remove<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Delete the captured identity, never a same-name replacement.
    fn destroy<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        target: &'a str,
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
// Trait Implementations: LocalContext
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "local")]
impl VolumeOps for LocalContext {
    fn create<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        config: VolumeConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Volume>> {
        Box::pin(async move { crate::volume::create_local(backend, config).await })
    }

    fn get<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Volume>> {
        Box::pin(async move { crate::volume::get_local(backend, name).await })
    }

    fn get_default(&self, _backend: Arc<dyn Context>) -> BoxFuture<'_, MicrosandboxResult<Volume>> {
        Box::pin(async move {
            Err(crate::MicrosandboxError::unsupported(
                crate::error::Operation::VolumeGetDefault,
                crate::error::UnsupportedReason::CloudOnly,
            ))
        })
    }

    fn list<'a>(
        &'a self,
        backend: Arc<dyn Context>,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<Volume>>> {
        Box::pin(async move { crate::volume::list_local(backend).await })
    }

    fn remove<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::volume::remove_local(backend, name).await })
    }

    fn destroy<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        target: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move { crate::volume::destroy_local(backend, target).await })
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
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "local"))]
mod tests {
    use super::*;
    use crate::MicrosandboxError;
    use crate::context::LocalContext;
    use crate::volume::VolumeConfig;

    #[tokio::test]
    async fn local_default_volume_lookup_fails_closed() {
        let home = tempfile::tempdir().unwrap();
        let backend: Arc<dyn Context> = Arc::new(
            LocalContext::builder()
                .config_path(home.path().join("config.json"))
                .managed_config_path(home.path().join("managed.json"))
                .home(home.path())
                .build()
                .unwrap(),
        );

        let error = backend
            .volume_ops()
            .get_default(backend.clone())
            .await
            .expect_err("Local must never expose a default host volume");
        assert!(matches!(
            error,
            MicrosandboxError::Unsupported {
                op: crate::error::Operation::VolumeGetDefault,
                reason: crate::error::UnsupportedReason::CloudOnly,
            }
        ));
    }

    /// Regression test for the asymmetric-signature P1: `LocalContext::remove`
    /// must operate on the passed-in `backend` Arc, not on the process-wide
    /// `configured_context()`. Two `LocalContext` instances live in separate
    /// home dirs (so separate SQLite DBs). The default is installed on
    /// backend A; backend B's trait impl is invoked directly. The remove
    /// must hit B's DB (and fail because the volume doesn't exist there),
    /// not silently succeed by re-resolving the default.
    #[tokio::test]
    async fn local_backend_remove_uses_passed_backend_not_global_default() {
        let home_a = tempfile::tempdir().unwrap();
        let home_b = tempfile::tempdir().unwrap();

        let backend_a: Arc<dyn Context> = Arc::new(
            LocalContext::builder()
                .config_path(home_a.path().join("config.json"))
                .managed_config_path(home_a.path().join("managed.json"))
                .home(home_a.path())
                .build()
                .unwrap(),
        );
        let backend_b: Arc<dyn Context> = Arc::new(
            LocalContext::builder()
                .config_path(home_b.path().join("config.json"))
                .managed_config_path(home_b.path().join("managed.json"))
                .home(home_b.path())
                .build()
                .unwrap(),
        );

        // Create a volume only in backend A.
        backend_a
            .volume_ops()
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
        // `configured_context()` (the bug we just fixed) it would find A and
        // successfully delete A's volume — even though we asked B.
        // Both destinations remain alive; explicit operations must retain B.
        let _other_destination = backend_a.clone();

        // Call remove via backend B. Context B has no such volume, so this
        // must error with `VolumeNotFound`.
        let err = backend_b
            .volume_ops()
            .remove(backend_b.clone(), "shared-name")
            .await
            .expect_err("remove should fail: volume does not exist in backend B");
        assert!(
            matches!(err, MicrosandboxError::VolumeNotFound(_)),
            "expected VolumeNotFound, got: {err:?}"
        );

        // Sanity check: A's volume is still there — the misrouted remove
        // would have deleted it.
        let handles = backend_a
            .volume_ops()
            .list(backend_a.clone())
            .await
            .unwrap();
        assert!(
            handles.iter().any(|h| h.name() == "shared-name"),
            "backend A's volume should still exist after the (correctly-routed) B remove"
        );
    }
}
