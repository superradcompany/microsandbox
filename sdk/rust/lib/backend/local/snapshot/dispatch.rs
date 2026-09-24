//! Adapt the local artifact engine to backend-retaining public snapshot values.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::future::BoxFuture;

use super::{archive, artifact, copy, create, group, store, verify};
use crate::backend::{Backend, LocalBackend, SnapshotBackend};
use crate::sandbox::SandboxConfig;
use crate::snapshot::{
    HeadUpdate, LoadOpts, Manifest, SaveOpts, Snapshot, SnapshotArchive, SnapshotConfig,
    SnapshotHandle, SnapshotReference, SnapshotVerifyReport,
};
use crate::{MicrosandboxError, MicrosandboxResult, Operation};

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
            Ok(from_artifact(
                backend,
                create::create_snapshot(self, config).await?,
            ))
        })
    }

    fn create_archive<'a>(
        &'a self,
        config: SnapshotConfig,
        out: &'a Path,
        plain_tar: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotArchive>> {
        Box::pin(create::create_snapshot_archive(
            self, config, out, plain_tar,
        ))
    }

    fn open<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        reference: SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        Box::pin(async move {
            let selector = local_selector(self, reference).await?;
            Ok(from_artifact(
                backend,
                store::open_snapshot(self, &selector).await?,
            ))
        })
    }

    fn get<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        identifier: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotHandle>> {
        Box::pin(async move {
            Ok(from_handle(
                backend,
                store::get_handle(self, identifier).await?,
            ))
        })
    }

    fn list(
        &self,
        backend: Arc<dyn Backend>,
    ) -> BoxFuture<'_, MicrosandboxResult<Vec<SnapshotHandle>>> {
        Box::pin(async move {
            Ok(store::list_indexed(self)
                .await?
                .into_iter()
                .map(|handle| from_handle(backend.clone(), handle))
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
            let selector = local_selector(self, reference).await?;
            store::remove_snapshot(self, &selector, force).await
        })
    }

    fn prepare_restore<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        config: &'a mut SandboxConfig,
        reference: SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            // Only path-shaped inputs can denote an archive. IDs always resolve through
            // the index, never through a same-named file in the caller's directory.
            let may_be_archive = !matches!(reference, SnapshotReference::Id(_));
            let selector = local_selector(self, reference).await?;
            if may_be_archive && Path::new(&selector).is_file() {
                config.snapshot_archive_source = Some(PathBuf::from(selector));
            } else {
                let snapshot = from_artifact(backend, store::open_snapshot(self, &selector).await?);
                crate::sandbox::prepare_local_snapshot_restore(config, &snapshot)?;
            }
            // The create path also admits deferred references; successful preparation
            // consumes this one so restore builders do not validate/materialize twice.
            config.snapshot_reference = None;
            Ok(())
        })
    }

    fn path<'a>(&self, reference: &'a SnapshotReference) -> MicrosandboxResult<&'a Path> {
        match reference {
            SnapshotReference::Path(path) => Ok(Path::new(path)),
            _ => Err(MicrosandboxError::local_only(Operation::SnapshotOps)),
        }
    }

    fn verify<'a>(
        &'a self,
        snapshot: &'a Snapshot,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotVerifyReport>> {
        Box::pin(async move {
            let mut artifact = artifact::Snapshot::from_parts(
                snapshot.path()?.to_path_buf(),
                snapshot.digest().into(),
                snapshot.manifest().clone(),
                snapshot.labels().clone(),
            );
            artifact.previous_upper = snapshot.previous_upper.clone();
            verify::verify_snapshot(&artifact).await
        })
    }

    fn copy<'a>(
        &'a self,
        snapshot: &'a Snapshot,
        out: &'a Path,
        labels: BTreeMap<String, String>,
        record_integrity: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<Manifest>> {
        Box::pin(copy::copy_snapshot_archive(
            snapshot,
            out,
            labels,
            record_integrity,
        ))
    }

    fn list_dir(
        &self,
        backend: Arc<dyn Backend>,
        dir: PathBuf,
    ) -> BoxFuture<'_, MicrosandboxResult<Vec<Snapshot>>> {
        Box::pin(async move {
            Ok(store::list_dir(self, &dir)
                .await?
                .into_iter()
                .map(|snapshot| from_artifact(backend.clone(), snapshot))
                .collect())
        })
    }

    fn reindex(&self, dir: Option<PathBuf>) -> BoxFuture<'_, MicrosandboxResult<usize>> {
        Box::pin(async move {
            store::reindex_dir(self, &dir.unwrap_or_else(|| self.snapshots_dir())).await
        })
    }

    fn save<'a>(
        &'a self,
        reference: SnapshotReference,
        out: &'a Path,
        opts: SaveOpts,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            let selector = local_selector(self, reference).await?;
            archive::save_snapshot(self, &selector, out, opts).await
        })
    }

    fn load<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        path: &'a Path,
        dest: Option<&'a Path>,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotHandle>> {
        Box::pin(async move {
            Ok(from_handle(
                backend,
                archive::load_snapshot(self, path, dest).await?,
            ))
        })
    }

    fn load_many<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        paths: &'a [PathBuf],
        opts: LoadOpts,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<SnapshotHandle>>> {
        Box::pin(async move {
            Ok(archive::load_snapshots(self, paths, opts)
                .await?
                .into_iter()
                .map(|handle| from_handle(backend.clone(), handle))
                .collect())
        })
    }

    fn group_head<'a>(
        &'a self,
        selector: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<HeadUpdate>> {
        Box::pin(async move { group::select(&self.snapshots_dir(), selector).await })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn local_selector(
    local: &LocalBackend,
    reference: SnapshotReference,
) -> MicrosandboxResult<String> {
    match reference {
        SnapshotReference::Id(id) => store::lookup_by_digest(local, &id)
            .await?
            .map(|handle| handle.artifact_path.to_string_lossy().into_owned())
            .ok_or(MicrosandboxError::SnapshotNotFound(id)),
        SnapshotReference::Auto(value) => Ok(value),
        SnapshotReference::Path(value) => {
            // Do not turn missing input into the current directory; callers can use
            // an explicit "." when they intend to operate on that artifact.
            if value.is_empty() {
                return Err(MicrosandboxError::InvalidConfig(
                    "snapshot path or name must not be empty".into(),
                ));
            }
            let path = PathBuf::from(value);
            // Preserve an explicit relative path as a path, even if it is a bare name.
            Ok(if path.is_absolute() {
                path
            } else {
                std::env::current_dir()?.join(path)
            }
            .to_string_lossy()
            .into_owned())
        }
    }
}

fn from_artifact(backend: Arc<dyn Backend>, artifact: artifact::Snapshot) -> Snapshot {
    Snapshot {
        backend,
        reference: SnapshotReference::path(artifact.path.to_string_lossy()),
        reported_size_bytes: artifact.size_bytes(),
        digest: artifact.digest,
        manifest: artifact.manifest,
        labels: artifact.labels,
        head_update: artifact.head_update,
        previous_upper: artifact.previous_upper,
    }
}

fn from_handle(backend: Arc<dyn Backend>, handle: artifact::SnapshotHandle) -> SnapshotHandle {
    SnapshotHandle {
        backend,
        reference: SnapshotReference::path(handle.artifact_path.to_string_lossy()),
        local_path: Some(handle.artifact_path),
        snapshot_id: handle.snapshot_id,
        group: handle.group,
        head_update: handle.head_update,
        digest: handle.digest,
        name: handle.name,
        parent_digest: handle.parent_digest,
        scope: handle.scope,
        image_ref: handle.image_ref,
        state_kind: handle.state_kind,
        format: handle.format,
        fstype: handle.fstype,
        checkpoint_manifest_digest: handle.checkpoint_manifest_digest,
        size_bytes: handle.size_bytes,
        locality: handle.locality,
        availability: handle.availability,
        migration_state: handle.migration_state,
        migration_error_code: handle.migration_error_code,
        created_at: handle.created_at,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn typed_path_selector_rejects_empty_but_preserves_explicit_dot() {
        let local = crate::test_support::local_backend(Default::default());
        assert!(matches!(
            local_selector(&local, SnapshotReference::path("")).await,
            Err(MicrosandboxError::InvalidConfig(message))
                if message == "snapshot path or name must not be empty"
        ));
        assert_eq!(
            PathBuf::from(
                local_selector(&local, SnapshotReference::path("."))
                    .await
                    .unwrap()
            ),
            std::env::current_dir().unwrap().join(".")
        );
        assert!(local.db.get().is_none());
    }

    #[tokio::test]
    async fn empty_typed_path_is_rejected_before_open_remove_or_restore() {
        // A lazy backend keeps these admission checks independent of artifact and
        // database contents; none of the rejected operations may initialize storage.
        let local = Arc::new(crate::test_support::local_backend(Default::default()));
        let backend: Arc<dyn Backend> = local.clone();
        let mut config = SandboxConfig {
            snapshot_reference: Some(SnapshotReference::path("")),
            ..SandboxConfig::default()
        };
        let outcomes = [
            SnapshotBackend::open(local.as_ref(), backend.clone(), SnapshotReference::path(""))
                .await
                .map(|_| ()),
            SnapshotBackend::remove(
                local.as_ref(),
                backend.clone(),
                SnapshotReference::path(""),
                true,
            )
            .await,
            SnapshotBackend::prepare_restore(
                local.as_ref(),
                backend,
                &mut config,
                SnapshotReference::path(""),
            )
            .await,
        ];
        for outcome in outcomes {
            assert!(matches!(
                outcome,
                Err(MicrosandboxError::InvalidConfig(message))
                    if message == "snapshot path or name must not be empty"
            ));
        }
        assert_eq!(config.snapshot_reference, Some(SnapshotReference::path("")));
        assert!(config.snapshot_archive_source.is_none());
        assert!(config.snapshot_root_layer_sources.is_empty());
        assert!(local.db.get().is_none());
    }

    #[tokio::test]
    async fn resolved_builder_reference_is_consumed_once_and_preserves_layer_sources() {
        let temp = tempfile::tempdir().unwrap();
        let local = Arc::new(
            crate::test_support::local_backend_builder(temp.path().join("home"))
                .build()
                .await
                .unwrap(),
        );
        let backend: Arc<dyn Backend> = local.clone();
        let source = temp.path().join("artifact");
        std::fs::create_dir(&source).unwrap();
        let wire = microsandbox_types::snapshot::cloud_manifest::Manifest::from_bytes(
            br#"{"schema":1,"artifact":"snapshot","scope":"disk","created_at":"2026-05-01T12:00:00Z","parent":null,"image":{"ref":"docker.io/library/python:3.12","manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"source_sandbox":"source","state":{"kind":"file","format":"raw","fstype":"ext4","upper":{"file":"upper.ext4","size_bytes":512,"integrity":null}},"labels":{},"extensions":{},"requires":[]}"#
        ).unwrap();
        let manifest = microsandbox_types::snapshot::legacy::project_cloud_descriptor(
            &wire,
            &wire.digest().unwrap(),
        )
        .unwrap();
        std::fs::write(
            source.join(crate::snapshot::DESCRIPTOR_FILENAME),
            manifest.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        let upper = source.join("upper.ext4");
        std::fs::write(&upper, [42; 512]).unwrap();

        crate::with_backend(backend.clone(), async {
            for image_first in [true, false] {
                let builder = crate::Sandbox::builder("child");
                let builder = if image_first {
                    builder
                        .image("alpine:latest")
                        .snapshot_resolved("untrusted-hint", &upper)
                } else {
                    builder
                        .snapshot_resolved("untrusted-hint", &upper)
                        .image("alpine:latest")
                };
                let mut config = builder.build().await.unwrap();
                let reference = config
                    .snapshot_reference
                    .clone()
                    .expect("resolved helper must queue an artifact reference");
                SnapshotBackend::prepare_restore(
                    local.as_ref(),
                    backend.clone(),
                    &mut config,
                    reference,
                )
                .await
                .unwrap();
                assert!(config.snapshot_reference.is_none());
                assert_eq!(
                    config.manifest_digest.as_deref(),
                    Some(manifest.image.manifest_digest.as_str())
                );
                assert_eq!(config.snapshot_root_layer_sources.len(), 1);
                assert_eq!(config.snapshot_root_layer_sources[0].path, upper);
                assert_eq!(config.snapshot_root_virtual_size, Some(512));
            }
        })
        .await;
        assert!(matches!(
            local_selector(&local, SnapshotReference::id(source.to_string_lossy())).await,
            Err(MicrosandboxError::SnapshotNotFound(_))
        ));
    }
}
