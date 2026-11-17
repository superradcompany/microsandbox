//! Context-neutral snapshot lifecycle dispatch.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::future::BoxFuture;

use super::Context;
use crate::MicrosandboxResult;
use crate::sandbox::SandboxConfig;
use crate::snapshot::{
    HeadUpdate, LoadOptions, Manifest, SaveOpts, Snapshot, SnapshotArchive, SnapshotConfig,
    SnapshotReference, SnapshotVerifyReport,
};

/// Context implementation for snapshot lifecycle operations.
pub trait SnapshotOps: Send + Sync {
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
        _backend: Arc<dyn Context>,
        _archives: &'a [PathBuf],
        _opts: LoadOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<Snapshot>>> {
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
        backend: Arc<dyn Context>,
        config: SnapshotConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>>;

    /// Capture an already selected sandbox identity. Providers must not substitute a reused name.
    fn create_from<'a>(
        &'a self,
        _context: Arc<dyn Context>,
        _config: SnapshotConfig,
        _expected: &'a crate::sandbox::SandboxId,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::unsupported(
                crate::Operation::SnapshotOps,
                crate::UnsupportedReason::NotAvailable(
                    "provider does not support identity-bound snapshot capture".into(),
                ),
            ))
        })
    }

    /// Open a snapshot using a backend-neutral or automatically interpreted reference.
    fn open<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        reference: SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>>;

    /// Get a lightweight snapshot handle by the backend's public identifier.
    fn get<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        identifier: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>>;

    /// List snapshots visible through this backend.
    fn list(&self, backend: Arc<dyn Context>) -> BoxFuture<'_, MicrosandboxResult<Vec<Snapshot>>>;

    /// Remove a snapshot using a backend-neutral or automatically interpreted reference.
    fn remove<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        reference: SnapshotReference,
        force: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Delete a captured resource without selecting a replacement by name or path.
    /// Backends must reject this operation if they cannot enforce the identity condition atomically.
    fn destroy<'a>(
        &'a self,
        backend: Arc<dyn Context>,
        reference: SnapshotReference,
        expected_digest: &'a str,
        force: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>>;

    /// Resolve a snapshot reference into the backend-specific sandbox create
    /// configuration needed to restore it.
    fn prepare_restore<'a>(
        &'a self,
        backend: Arc<dyn Context>,
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
        backend: Arc<dyn Context>,
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
}
