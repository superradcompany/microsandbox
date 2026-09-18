//! Backend-neutral snapshot lifecycle dispatch.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::future::BoxFuture;

use super::Backend;
use crate::MicrosandboxResult;
use crate::sandbox::SandboxConfig;
use crate::snapshot::{
    HeadUpdate, LoadOpts, Manifest, SaveOpts, Snapshot, SnapshotArchive, SnapshotConfig,
    SnapshotHandle, SnapshotReference, SnapshotVerifyReport,
};

/// Backend implementation for snapshot lifecycle operations.
pub trait SnapshotBackend: Send + Sync {
    /// Capture directly to an archive; unsupported backends must reject before capture.
    fn create_archive<'a>(
        &'a self,
        _config: SnapshotConfig,
        _out: &'a Path,
        _plain_tar: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotArchive>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::local_only(
                crate::Operation::SnapshotOps,
            ))
        })
    }

    /// Validate and import one batch with explicit local dependency/head policy.
    fn load_many<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _archives: &'a [PathBuf],
        _opts: LoadOpts,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<SnapshotHandle>>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::local_only(
                crate::Operation::SnapshotOps,
            ))
        })
    }

    /// Read or select a local group head.
    fn group_head<'a>(
        &'a self,
        _selector: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<HeadUpdate>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::local_only(
                crate::Operation::SnapshotOps,
            ))
        })
    }

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

    /// Return the local artifact directory, or a typed unsupported error when
    /// this backend does not expose snapshot artifacts on the client host.
    fn path<'a>(&self, reference: &'a SnapshotReference) -> MicrosandboxResult<&'a Path>;

    /// Verify a snapshot's stored payload integrity.
    fn verify<'a>(
        &'a self,
        snapshot: &'a Snapshot,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotVerifyReport>>;

    /// Package a snapshot as a new archive with replacement metadata.
    fn copy<'a>(
        &'a self,
        snapshot: &'a Snapshot,
        output_archive_path: &'a Path,
        labels: BTreeMap<String, String>,
        record_integrity: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<Manifest>>;

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
