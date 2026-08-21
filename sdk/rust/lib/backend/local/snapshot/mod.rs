//! Local snapshot lifecycle and artifact operations.

pub(super) mod archive;
mod create;
pub mod downgrade;
pub(super) mod migration;
mod store;
mod verify;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::future::BoxFuture;

use super::LocalBackend;
use crate::backend::{Backend, SnapshotBackend};
use crate::error::{Operation, UnsupportedReason};
use crate::sandbox::{RootfsSource, SandboxConfig};
use crate::snapshot::{
    Manifest, SaveOpts, Snapshot, SnapshotConfig, SnapshotFormat, SnapshotHandle,
    SnapshotReference, SnapshotScope, SnapshotState, SnapshotVerifyReport,
};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Validated local snapshot artifact and its filesystem location.
#[derive(Debug, Clone)]
struct LocalSnapshotArtifact {
    path: PathBuf,
    digest: String,
    manifest: Manifest,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalSnapshotArtifact {
    fn new(path: PathBuf, digest: String, manifest: Manifest) -> Self {
        Self {
            path,
            digest,
            manifest,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn digest(&self) -> &str {
        &self.digest
    }

    fn manifest(&self) -> &Manifest {
        &self.manifest
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl SnapshotBackend for LocalBackend {
    fn create<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: SnapshotConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        Box::pin(async move {
            let artifact = self.create_snapshot(config).await?;
            Ok(snapshot_from_local(backend, artifact))
        })
    }

    fn open<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        reference: SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        Box::pin(async move {
            let reference = self.resolve_snapshot_reference(reference).await?;
            let artifact = self.open_snapshot_artifact(&reference).await?;
            Ok(snapshot_from_local(backend, artifact))
        })
    }

    fn get<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        identifier: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotHandle>> {
        Box::pin(async move {
            let model = self.find_snapshot_model(identifier).await?;
            Ok(snapshot_handle_from_model(backend, model))
        })
    }

    fn list(
        &self,
        backend: Arc<dyn Backend>,
    ) -> BoxFuture<'_, MicrosandboxResult<Vec<SnapshotHandle>>> {
        Box::pin(async move {
            Ok(self
                .list_snapshot_models()
                .await?
                .into_iter()
                .map(|model| snapshot_handle_from_model(backend.clone(), model))
                .collect())
        })
    }

    fn remove<'a>(
        &'a self,
        _backend: Arc<dyn Backend>,
        reference: SnapshotReference,
        force: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            let reference = match reference {
                SnapshotReference::Auto(reference)
                | SnapshotReference::Id(reference)
                | SnapshotReference::Path(reference) => reference,
            };
            self.remove_snapshot_artifact(&reference, force).await
        })
    }

    fn prepare_restore<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: &'a mut SandboxConfig,
        reference: SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            let snapshot = SnapshotBackend::open(self, backend, reference).await?;
            materialize_restore_config(config, &snapshot)?;
            Ok(())
        })
    }

    fn path<'a>(&self, reference: &'a SnapshotReference) -> MicrosandboxResult<&'a Path> {
        match reference {
            SnapshotReference::Path(path) => Ok(Path::new(path)),
            SnapshotReference::Auto(_) | SnapshotReference::Id(_) => {
                Err(MicrosandboxError::local_only(Operation::SnapshotOps))
            }
        }
    }

    fn verify<'a>(
        &'a self,
        snapshot: &'a Snapshot,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotVerifyReport>> {
        Box::pin(async move {
            let path = artifact_path(snapshot)?;
            verify::verify_snapshot(path, snapshot.digest(), snapshot.manifest()).await
        })
    }

    fn list_dir(
        &self,
        backend: Arc<dyn Backend>,
        dir: PathBuf,
    ) -> BoxFuture<'_, MicrosandboxResult<Vec<Snapshot>>> {
        Box::pin(async move {
            Ok(self
                .list_snapshot_artifacts(&dir)
                .await?
                .into_iter()
                .map(|artifact| snapshot_from_local(backend.clone(), artifact))
                .collect())
        })
    }

    fn reindex(&self, dir: Option<PathBuf>) -> BoxFuture<'_, MicrosandboxResult<usize>> {
        Box::pin(async move {
            let dir = dir.unwrap_or_else(|| self.snapshots_dir());
            self.reindex_snapshot_dir(&dir).await
        })
    }

    fn save<'a>(
        &'a self,
        reference: SnapshotReference,
        out: &'a Path,
        opts: SaveOpts,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            let reference = self.resolve_snapshot_reference(reference).await?;
            self.save_snapshot_archive(&reference, out, opts).await
        })
    }

    fn load<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        archive_path: &'a Path,
        dest: Option<&'a Path>,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotHandle>> {
        Box::pin(async move {
            let artifact = self.load_snapshot_archive(archive_path, dest).await?;
            Ok(snapshot_handle_from_artifact(backend, artifact))
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate a local disk snapshot and materialize its restore metadata onto a
/// sandbox config. The returned upper path remains backend-private and is
/// consumed immediately by local sandbox creation.
pub(crate) fn materialize_restore_config(
    config: &mut SandboxConfig,
    snapshot: &Snapshot,
) -> MicrosandboxResult<PathBuf> {
    if snapshot.manifest().scope != crate::snapshot::SnapshotScope::Disk {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable(
                "restoring non-disk snapshots requires resumable restore support".into(),
            ),
        ));
    }
    let unsupported = snapshot.manifest().unsupported_requires();
    if !unsupported.is_empty() {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable(format!(
                "snapshot requires unsupported runtime capabilities: {}",
                unsupported.join(", ")
            )),
        ));
    }
    let file_state = match &snapshot.manifest().state {
        crate::snapshot::SnapshotState::File(state) => state,
        crate::snapshot::SnapshotState::Checkpoint(_) => {
            return Err(MicrosandboxError::unsupported(
                Operation::SnapshotOps,
                UnsupportedReason::NotAvailable(
                    "checkpoint-state restore providers are not available".into(),
                ),
            ));
        }
    };
    if file_state.format != crate::snapshot::SnapshotFormat::Raw || file_state.fstype != "ext4" {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable(format!(
                "snapshot file state {:?}/{} is not qualified for restore",
                file_state.format, file_state.fstype
            )),
        ));
    }

    config.spec.image = RootfsSource::oci(snapshot.manifest().image.reference.clone());
    config.manifest_digest = Some(snapshot.manifest().image.manifest_digest.clone());
    config.snapshot_reference = Some(snapshot.reference());
    Ok(artifact_path(snapshot)?.join(&file_state.upper.file))
}

impl LocalBackend {
    async fn resolve_snapshot_reference(
        &self,
        reference: SnapshotReference,
    ) -> MicrosandboxResult<String> {
        match reference {
            SnapshotReference::Id(identifier) => {
                Ok(self.find_snapshot_model(&identifier).await?.artifact_path)
            }
            SnapshotReference::Auto(reference) | SnapshotReference::Path(reference) => {
                Ok(reference)
            }
        }
    }
}

fn artifact_path(snapshot: &Snapshot) -> MicrosandboxResult<&Path> {
    match &snapshot.reference {
        SnapshotReference::Path(path) => Ok(Path::new(path)),
        SnapshotReference::Auto(_) | SnapshotReference::Id(_) => {
            Err(MicrosandboxError::local_only(Operation::SnapshotOps))
        }
    }
}

fn snapshot_from_local(backend: Arc<dyn Backend>, artifact: LocalSnapshotArtifact) -> Snapshot {
    let reference = SnapshotReference::path(artifact.path.to_string_lossy());
    Snapshot {
        backend,
        reference,
        digest: artifact.digest,
        manifest: artifact.manifest,
        reported_size_bytes: None,
    }
}

fn snapshot_handle_from_model(
    backend: Arc<dyn Backend>,
    model: crate::db::entity::snapshot::Model,
) -> SnapshotHandle {
    let format = model.format.as_deref().map(|format| match format {
        "qcow2" => SnapshotFormat::Qcow2,
        _ => SnapshotFormat::Raw,
    });
    let scope = match model.scope.as_str() {
        "disk" => SnapshotScope::Disk,
        "resumable" => SnapshotScope::Resumable,
        other => {
            tracing::warn!(digest = %model.digest, scope = other, "unknown snapshot scope in index; treating as disk");
            SnapshotScope::Disk
        }
    };
    let reference = SnapshotReference::id(model.digest.clone());

    SnapshotHandle {
        backend,
        reference,
        local_path: Some(PathBuf::from(model.artifact_path)),
        digest: model.digest,
        name: model.name,
        parent_digest: model.parent_digest,
        scope,
        image_ref: model.image_ref,
        state_kind: model.state_kind,
        format,
        fstype: model.fstype,
        checkpoint_manifest_digest: model.checkpoint_manifest_digest,
        size_bytes: model.size_bytes.map(|size| size as u64),
        locality: model.locality,
        availability: model.availability,
        migration_state: model.migration_state,
        migration_error_code: model.migration_error_code,
        created_at: model.created_at,
    }
}

fn snapshot_handle_from_artifact(
    backend: Arc<dyn Backend>,
    artifact: LocalSnapshotArtifact,
) -> SnapshotHandle {
    let (state_kind, format, fstype, checkpoint_manifest_digest, size_bytes) =
        match &artifact.manifest.state {
            SnapshotState::File(state) => (
                "file".to_string(),
                Some(state.format),
                Some(state.fstype.clone()),
                None,
                Some(state.upper.size_bytes),
            ),
            SnapshotState::Checkpoint(state) => (
                "checkpoint".to_string(),
                None,
                None,
                Some(state.manifest.clone()),
                None,
            ),
        };
    let created_at = chrono::DateTime::parse_from_rfc3339(&artifact.manifest.created_at)
        .map(|date| date.naive_utc())
        .unwrap_or_else(|_| chrono::Utc::now().naive_utc());
    let name = artifact
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string);
    let reference = SnapshotReference::path(artifact.path.to_string_lossy());

    SnapshotHandle {
        backend,
        reference,
        local_path: Some(artifact.path),
        digest: artifact.digest,
        name,
        parent_digest: artifact.manifest.parent,
        scope: artifact.manifest.scope,
        image_ref: artifact.manifest.image.reference,
        state_kind,
        format,
        fstype,
        checkpoint_manifest_digest,
        size_bytes,
        locality: "embedded".into(),
        availability: "ready".into(),
        migration_state: "canonical".into(),
        migration_error_code: None,
        created_at,
    }
}
