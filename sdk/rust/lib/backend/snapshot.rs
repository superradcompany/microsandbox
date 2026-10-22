//! Backend-neutral snapshot lifecycle dispatch.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::future::BoxFuture;

use super::Backend;
use crate::MicrosandboxResult;
use crate::sandbox::SandboxConfig;
use crate::snapshot::{
    Checkpoint as Snapshot, HeadUpdate, LoadOpts, Manifest, SaveOpts, SnapshotArchive,
    SnapshotConfig, SnapshotHandle, SnapshotReference, SnapshotVerifyReport,
};

/// Backend implementation for snapshot lifecycle operations.
pub trait SnapshotBackend: Send + Sync {
    /// Read one group's head, membership count and saved capture association.
    fn inspect_group<'a>(
        &'a self,
        _reference: &'a SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::snapshot::SnapshotGroupInfo>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::local_only(
                crate::Operation::SnapshotOps,
            ))
        })
    }

    /// Explicitly retire the entire history; surviving external dependents always prevent it.
    fn remove_group<'a>(
        &'a self,
        _reference: &'a SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::snapshot::SnapshotRemoveResult>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::local_only(
                crate::Operation::SnapshotOps,
            ))
        })
    }

    /// Remove an exact retained checkpoint and return this operation's head outcome.
    fn remove_checkpoint<'a>(
        &'a self,
        _checkpoint: &'a Snapshot,
        _options: crate::snapshot::CheckpointRemoveOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::snapshot::CheckpointRemoveResult>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::local_only(
                crate::Operation::SnapshotOps,
            ))
        })
    }

    /// Verify a pinned whole-group membership, preserving per-member failures in the error report.
    fn verify_group<'a>(
        &'a self,
        _group: &'a SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::snapshot::SnapshotGroupVerifyReport>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::local_only(
                crate::Operation::SnapshotOps,
            ))
        })
    }

    /// Explicitly set or clear a group's selected head.
    fn change_head<'a>(
        &'a self,
        _group: &'a SnapshotReference,
        _member: Option<&'a str>,
    ) -> BoxFuture<'a, MicrosandboxResult<HeadUpdate>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::local_only(
                crate::Operation::SnapshotOps,
            ))
        })
    }

    /// Group-oriented get group; unsupported backends refuse explicitly.
    fn get_group<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::Snapshot>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::local_only(
                crate::Operation::SnapshotOps,
            ))
        })
    }

    /// Group-oriented list groups; unsupported backends refuse explicitly.
    fn list_groups<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<crate::Snapshot>>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::local_only(
                crate::Operation::SnapshotOps,
            ))
        })
    }

    /// Group-oriented read head; unsupported backends refuse explicitly.
    fn read_head<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _group: &'a SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<Option<Snapshot>>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::local_only(
                crate::Operation::SnapshotOps,
            ))
        })
    }

    /// Group-oriented group members; unsupported backends refuse explicitly.
    fn group_members<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _group: &'a SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<SnapshotHandle>>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::local_only(
                crate::Operation::SnapshotOps,
            ))
        })
    }

    /// Group-oriented get checkpoint; unsupported backends refuse explicitly.
    fn get_checkpoint<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _group: &'a SnapshotReference,
        _member: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::local_only(
                crate::Operation::SnapshotOps,
            ))
        })
    }

    /// Group-oriented create group; unsupported backends refuse explicitly.
    fn create_group<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _config: SnapshotConfig,
        _source_id: crate::sandbox::SandboxId,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::local_only(
                crate::Operation::SnapshotOps,
            ))
        })
    }

    /// Append to an existing source-bound group. Group-only, source-only, or matching
    /// combined selectors are accepted; no missing group is created implicitly.
    fn checkpoint<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _config: SnapshotConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::local_only(
                crate::Operation::SnapshotOps,
            ))
        })
    }

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

    /// Atomically import an archive set and report the group, all members, and commit facts.
    fn load_group<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        _group: &'a str,
        _archives: &'a [PathBuf],
        _opts: LoadOpts,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::SnapshotImportResult>> {
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
