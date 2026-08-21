//! Backend-neutral snapshot lifecycle dispatch.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::future::BoxFuture;

use super::Backend;
use crate::MicrosandboxResult;
use crate::sandbox::SandboxConfig;
use crate::snapshot::{
    SaveOpts, Snapshot, SnapshotConfig, SnapshotHandle, SnapshotReference, SnapshotVerifyReport,
};

/// Backend implementation for snapshot lifecycle operations.
pub trait SnapshotBackend: Send + Sync {
    /// Create a snapshot and return the completed artifact/resource.
    fn create<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: SnapshotConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>>;

    /// Open a snapshot using a backend-neutral or automatically interpreted reference.
    fn open<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        reference: SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>>;

    /// Get a lightweight snapshot handle by the backend's public identifier.
    fn get<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        identifier: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotHandle>>;

    /// List snapshots visible through this backend.
    fn list(
        &self,
        backend: Arc<dyn Backend>,
    ) -> BoxFuture<'_, MicrosandboxResult<Vec<SnapshotHandle>>>;

    /// Remove a snapshot using a backend-neutral or automatically interpreted reference.
    fn remove<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        reference: SnapshotReference,
        force: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Resolve a snapshot reference into the backend-specific sandbox create
    /// configuration needed to restore it.
    fn prepare_restore<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: &'a mut SandboxConfig,
        reference: SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Verify a snapshot's stored payload integrity.
    fn verify<'a>(
        &'a self,
        snapshot: &'a Snapshot,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotVerifyReport>>;

    /// Enumerate snapshot artifacts in a backend-specific directory.
    fn list_dir(
        &self,
        backend: Arc<dyn Backend>,
        dir: PathBuf,
    ) -> BoxFuture<'_, MicrosandboxResult<Vec<Snapshot>>>;

    /// Rebuild a backend-specific snapshot index from a directory.
    fn reindex(&self, dir: Option<PathBuf>) -> BoxFuture<'_, MicrosandboxResult<usize>>;

    /// Export a snapshot through the selected backend.
    fn save<'a>(
        &'a self,
        reference: SnapshotReference,
        out: &'a Path,
        opts: SaveOpts,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Import a snapshot through the selected backend.
    fn load<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        archive: &'a Path,
        dest: Option<&'a Path>,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotHandle>>;
}
