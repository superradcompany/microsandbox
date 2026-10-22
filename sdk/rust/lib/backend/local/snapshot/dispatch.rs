//! Adapt the local artifact engine to backend-retaining public snapshot values.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::future::BoxFuture;
use microsandbox_image::snapshot::SnapshotRootDisk;

use super::{archive, artifact, copy, create, group, store, verify};
use crate::backend::{Backend, LocalBackend, SnapshotBackend};
use crate::sandbox::config::SnapshotRestoreMode;
use crate::sandbox::restore_resources::PreparedArchive;
use crate::sandbox::{RootfsSource, SandboxConfig};
use crate::snapshot::{
    Checkpoint as Snapshot, HeadUpdate, LoadOpts, Manifest, SaveOpts, SnapshotArchive,
    SnapshotConfig, SnapshotHandle, SnapshotReference, SnapshotVerifyReport,
};
use crate::{MicrosandboxError, MicrosandboxResult, Operation};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalBackend {
    /// Inspect a restore source; caller options remain separate from resolved settings.
    pub(crate) async fn prepare_local_restore(
        &self,
        backend: Arc<dyn Backend>,
        config: &mut SandboxConfig,
        mut reference: SnapshotReference,
    ) -> MicrosandboxResult<()> {
        if !config.local_restore_paths_resolved {
            super::super::host_paths::resolve_snapshot_reference(&mut reference)?;
            super::super::host_paths::resolve_host_paths(config)?;
        }
        // Existing bare archive names were promoted to absolute paths at admission.
        // Remaining bare names must not be shadowed by a file in a later cwd.
        let may_be_archive = match &reference {
            SnapshotReference::Path(_) => true,
            SnapshotReference::Auto(value) => store::looks_like_path(value),
            SnapshotReference::Id(_) => false,
        };
        let selector = local_selector(self, reference).await?;
        if may_be_archive && Path::new(&selector).is_file() {
            // The shared preparation path also serves retained checkpoint handles. A
            // selected installed member must never become an archive after replacement.
            if config.snapshot_expected_digest.is_some() {
                return Err(MicrosandboxError::SnapshotIntegrity(
                    "snapshot was replaced since this handle was opened".into(),
                ));
            }
            config.snapshot_archive_source = Some(PathBuf::from(selector));
        } else {
            let artifact = store::open_snapshot_leased(self, &selector).await?;
            if config
                .snapshot_expected_digest
                .as_ref()
                .is_some_and(|expected| expected != artifact.digest())
            {
                return Err(MicrosandboxError::SnapshotIntegrity(
                    "snapshot was replaced since this handle was opened".into(),
                ));
            }
            config.snapshot_lease = artifact.lease.clone();
            let snapshot = from_artifact(backend, artifact);
            crate::sandbox::prepare_local_snapshot_restore(config, &snapshot)?;
        }
        // The create path also admits deferred references; successful preparation
        // consumes this one so restore builders do not validate/materialize twice.
        config.snapshot_reference = None;
        self.prepare_archive_restore(config).await
    }

    /// Decode an archive once before resolving settings; retain its private files until creation.
    pub(crate) async fn prepare_archive_restore(
        &self,
        config: &mut SandboxConfig,
    ) -> MicrosandboxResult<()> {
        if self.reuse_prepared_archive(config)? {
            return Ok(());
        }
        let Some(archive) = config.snapshot_archive_source.clone() else {
            return Ok(());
        };

        tokio::fs::create_dir_all(self.sandboxes_dir()).await?;
        let stage = tempfile::Builder::new()
            .prefix(".archive-restore-")
            .tempdir_in(self.sandboxes_dir())?;
        let disk_only = config.snapshot_restore_mode == SnapshotRestoreMode::DiskOnly;
        // Archive decoding has a large async state machine. Keep it off the containing
        // create future so native SDK debug builds fit ordinary Tokio worker stacks.
        let materialized = Box::pin(crate::snapshot::materialize_archive_for_child(
            self,
            &archive,
            stage.path(),
            disk_only,
            config.snapshot_base.as_deref(),
            &config.restore_resources,
            config.restore_boot_overrides,
        ))
        .await?;
        let cache_operation =
            self.apply_materialized_archive(config, stage.path(), materialized)?;
        // Do not let a disk archive turn an explicit CoW restore into a fresh boot, and
        // reject it before replacement can remove the existing sandbox.
        if config.forked && config.checkpoint_restore.is_none() {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "copy-on-write memory requires a full snapshot restore".into(),
            ));
        }

        config.restore_resources.archive = Some(Arc::new(PreparedArchive {
            stage,
            mode: config.snapshot_restore_mode,
            source: archive,
            cache_operation,
        }));
        Ok(())
    }

    /// Reuse retained archive staging when it still matches this restore;
    /// otherwise discard every piece of the stale prepared state.
    fn reuse_prepared_archive(&self, config: &mut SandboxConfig) -> MicrosandboxResult<bool> {
        let Some(prepared) = &config.restore_resources.archive else {
            return Ok(false);
        };
        if prepared.mode == config.snapshot_restore_mode
            && config.snapshot_archive_source.as_ref() == Some(&prepared.source)
            && prepared.stage.path().parent() == Some(self.sandboxes_dir().as_path())
        {
            config.restore_boot_overrides.validate_scope(
                if config.restore_resources.geometry.is_some() {
                    crate::snapshot::SnapshotScope::Full
                } else {
                    crate::snapshot::SnapshotScope::Disk
                },
                config.snapshot_restore_mode,
            )?;
            return Ok(true);
        }

        config.clear_prepared_restore();
        Ok(false)
    }

    /// Apply the decoded manifest, checkpoint, and disk state to the config.
    /// Returns the cache leases the retained staging must keep alive.
    fn apply_materialized_archive(
        &self,
        config: &mut SandboxConfig,
        stage_path: &Path,
        materialized: super::archive::ArchiveChildMaterialization,
    ) -> MicrosandboxResult<microsandbox_image::GlobalCache> {
        config.spec.image = RootfsSource::oci(materialized.manifest.image.reference.clone());
        if config.spec.runtime.user.is_none() {
            config.spec.runtime.user = materialized.manifest.restore_defaults()?.user;
        }

        crate::sandbox::apply_snapshot_guest_clock(config, &materialized.manifest)?;
        crate::sandbox::require_recorded_mounts(config, &materialized.manifest)?;
        crate::sandbox::require_guest_mounts(config, materialized.required_bind_paths)?;
        config.snapshot_parent = Some(materialized.manifest.snapshot_id.to_string());
        crate::snapshot::apply_additional_disks(config, materialized.disk_mounts);
        config.manifest_digest = Some(materialized.manifest.image.manifest_digest.clone());
        crate::sandbox::apply_snapshot_root_layout(config, &materialized.manifest.root_disk)?;
        let cache_operation = materialized.cache_operation;
        if let Some(restore) = materialized.checkpoint_restore {
            let state = match &materialized.manifest.state {
                crate::snapshot::SnapshotState::Checkpoint(state) => state,
                crate::snapshot::SnapshotState::File(_) => {
                    return Err(crate::MicrosandboxError::SnapshotIntegrity(
                        "archive produced checkpoint construction state for file snapshot".into(),
                    ));
                }
            };
            let expected = microsandbox_image::checkpoint::ObjectId::new(&restore.checkpoint_root)
                .map_err(|error| crate::MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
            let closure = microsandbox_image::checkpoint::CheckpointClosure::open(
                &restore.closure,
                Some(&expected),
                self.config().fs_state_limit(),
            )
            .map_err(|error| crate::MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
            crate::sandbox::apply_checkpoint_restore_constraints(
                config,
                state,
                closure.checkpoint(),
            )?;

            config.checkpoint_restore = Some(restore);
            config.snapshot_upper_layers = materialized.upper_layers;
            config.suppress_launch_for_full_restore();
        } else if !materialized.upper_layers.is_empty() {
            config.snapshot_upper_layers = materialized.upper_layers;
        } else if matches!(
            materialized.manifest.state,
            crate::snapshot::SnapshotState::File(_)
        ) {
            config.snapshot_upper_source =
                Some(stage_path.join(match &materialized.manifest.root_disk {
                    SnapshotRootDisk::Managed => "upper.ext4",
                    SnapshotRootDisk::Flat => crate::sandbox::flat_rootfs::FLAT_ROOTFS_FILENAME,
                    SnapshotRootDisk::Tmpfs { .. } => {
                        unreachable!("file snapshots reject tmpfs roots")
                    }
                }));
        }
        Ok(cache_operation)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl SnapshotBackend for LocalBackend {
    fn inspect_group<'a>(
        &'a self,
        reference: &'a SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::snapshot::SnapshotGroupInfo>> {
        Box::pin(async move { group::inspect_history(self, self.path(reference)?).await })
    }

    fn remove_group<'a>(
        &'a self,
        reference: &'a SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::snapshot::SnapshotRemoveResult>> {
        Box::pin(async move { group::remove_history(self, self.path(reference)?).await })
    }

    fn remove_checkpoint<'a>(
        &'a self,
        checkpoint: &'a Snapshot,
        options: crate::snapshot::CheckpointRemoveOptions,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::snapshot::CheckpointRemoveResult>> {
        Box::pin(async move {
            let reference = checkpoint.reference();
            let selector = local_selector(self, reference).await?;
            store::remove_snapshot_report(self, &selector, options.force, Some(checkpoint.digest()))
                .await?
                .ok_or_else(|| MicrosandboxError::SnapshotNotFound(checkpoint.id().to_string()))
        })
    }

    fn change_head<'a>(
        &'a self,
        reference: &'a SnapshotReference,
        member: Option<&'a str>,
    ) -> BoxFuture<'a, MicrosandboxResult<HeadUpdate>> {
        Box::pin(async move { group::change_head(self.path(reference)?, member).await })
    }

    fn create_group<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        mut config: SnapshotConfig,
        source_id: crate::sandbox::SandboxId,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        Box::pin(async move {
            config.dest_dir = config.dest_dir.map(std::path::absolute).transpose()?;
            Ok(from_artifact(
                backend,
                create::create_group(self, config, source_id).await?,
            ))
        })
    }

    fn get_group<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::Snapshot>> {
        Box::pin(async move {
            group::validate_group_name(name)?;
            let directory = self.snapshots_dir().join(name);
            group::validate_directory(&directory).await?;
            Ok(crate::Snapshot {
                backend,
                name: name.into(),
                reference: SnapshotReference::Path(directory.to_string_lossy().into_owned()),
            })
        })
    }

    fn list_groups<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<crate::Snapshot>>> {
        Box::pin(async move {
            // The last group can disappear before catalog cleanup. Discover its journal
            // through stable parent pointers, rather than requiring a surviving member.
            for parent in super::deletion::recovery_parents(self)? {
                group::recover_histories(self, &parent).await?;
            }
            let mut groups = Vec::new();
            let mut entries = match tokio::fs::read_dir(self.snapshots_dir()).await {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(groups),
                Err(error) => return Err(error.into()),
            };
            while let Some(entry) = entries.next_entry().await? {
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if name.starts_with('.')
                    || !entry.file_type().await?.is_dir()
                    || !entry.path().join(group::GROUP_FILENAME).is_file()
                {
                    continue;
                }
                groups.push(self.get_group(backend.clone(), &name).await?);
            }
            groups.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(groups)
        })
    }

    fn read_head<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        reference: &'a SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<Option<Snapshot>>> {
        Box::pin(async move {
            let directory = self.path(reference)?;
            let Some(path) = group::inspect_directory(directory).await? else {
                return Ok(None);
            };
            // Resolve the head once; opening the exact ID must not silently follow a newer head.
            Ok(Some(from_artifact(
                backend,
                store::open_snapshot(self, &path.to_string_lossy()).await?,
            )))
        })
    }

    fn group_members<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        reference: &'a SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<SnapshotHandle>>> {
        Box::pin(async move {
            let directory = self.path(reference)?;
            group::inspect_directory(directory).await?;
            let mut paths = group::member_paths(directory).await?;
            paths.sort();
            let mut members = Vec::with_capacity(paths.len());
            for path in paths {
                members.push(from_handle(
                    backend.clone(),
                    store::get_handle(self, &path.to_string_lossy()).await?,
                ));
            }
            Ok(members)
        })
    }

    fn get_checkpoint<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        reference: &'a SnapshotReference,
        member: &'a str,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        Box::pin(async move {
            let path = group::selected_path(self.path(reference)?, member).await?;
            Ok(from_artifact(
                backend,
                store::open_snapshot(self, &path.to_string_lossy()).await?,
            ))
        })
    }

    fn checkpoint<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        mut config: SnapshotConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        Box::pin(async move {
            config.dest_dir = config.dest_dir.map(std::path::absolute).transpose()?;
            Ok(from_artifact(
                backend,
                create::create_checkpoint(self, config).await?,
            ))
        })
    }

    fn create<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        mut config: SnapshotConfig,
    ) -> BoxFuture<'a, MicrosandboxResult<Snapshot>> {
        Box::pin(async move {
            config.dest_dir = config.dest_dir.map(std::path::absolute).transpose()?;
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
        Box::pin(async move {
            let out = std::path::absolute(out)?;
            create::create_snapshot_archive(self, config, &out, plain_tar).await
        })
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
        Box::pin(async move { self.prepare_local_restore(backend, config, reference).await })
    }

    fn path<'a>(&self, reference: &'a SnapshotReference) -> MicrosandboxResult<&'a Path> {
        match reference {
            SnapshotReference::Path(path) => Ok(Path::new(path)),
            _ => Err(MicrosandboxError::local_only(Operation::SnapshotOps)),
        }
    }

    fn verify_group<'a>(
        &'a self,
        reference: &'a SnapshotReference,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::snapshot::SnapshotGroupVerifyReport>> {
        Box::pin(async move { verify::verify_group(self, self.path(reference)?).await })
    }

    fn verify<'a>(
        &'a self,
        snapshot: &'a Snapshot,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotVerifyReport>> {
        Box::pin(async move {
            let mut artifact =
                store::open_snapshot_leased(self, snapshot.path()?.to_string_lossy().as_ref())
                    .await?;
            if artifact.digest() != snapshot.digest() {
                return Err(MicrosandboxError::SnapshotIntegrity(
                    "snapshot was replaced since this handle was opened".into(),
                ));
            }
            // Keep the exact legacy flat-payload binding from the opened handle.
            artifact.previous_upper = snapshot.previous_upper.clone();
            verify::verify_snapshot(&artifact, self.config().fs_state_limit()).await
        })
    }

    fn copy<'a>(
        &'a self,
        snapshot: &'a Snapshot,
        out: &'a Path,
        labels: BTreeMap<String, String>,
        record_integrity: bool,
    ) -> BoxFuture<'a, MicrosandboxResult<Manifest>> {
        Box::pin(async move {
            let out = std::path::absolute(out)?;
            let artifact =
                store::open_snapshot_leased(self, snapshot.path()?.to_string_lossy().as_ref())
                    .await?;
            if artifact.digest() != snapshot.digest() {
                return Err(MicrosandboxError::SnapshotIntegrity(
                    "snapshot was replaced since this handle was opened".into(),
                ));
            }
            // The leased artifact stays alive through the copy's final awaited write.
            copy::copy_snapshot_archive(snapshot, &out, labels, record_integrity).await
        })
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
        mut opts: SaveOpts,
    ) -> BoxFuture<'a, MicrosandboxResult<()>> {
        Box::pin(async move {
            let out = std::path::absolute(out)?;
            opts.since = opts.since.map(anchor_archive_selector).transpose()?;
            let selector = local_selector(self, reference).await?;
            archive::save_snapshot(self, &selector, &out, opts).await
        })
    }

    fn load<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        path: &'a Path,
        dest: Option<&'a Path>,
    ) -> BoxFuture<'a, MicrosandboxResult<SnapshotHandle>> {
        Box::pin(async move {
            let path = std::path::absolute(path)?;
            let dest = dest.map(std::path::absolute).transpose()?;
            Ok(from_handle(
                backend,
                archive::load_snapshot(self, &path, dest.as_deref()).await?,
            ))
        })
    }

    fn load_group<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        name: &'a str,
        paths: &'a [PathBuf],
        mut opts: LoadOpts,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::SnapshotImportResult>> {
        Box::pin(async move {
            let paths = paths
                .iter()
                .map(std::path::absolute)
                .collect::<std::io::Result<Vec<_>>>()?;
            opts.dest = opts.dest.map(std::path::absolute).transpose()?;
            opts.base = opts.base.map(anchor_archive_selector).transpose()?;
            load_group_admitted(self, backend, name, &paths, opts).await
        })
    }

    fn load_many<'a>(
        &'a self,
        backend: Arc<dyn Backend>,
        paths: &'a [PathBuf],
        mut opts: LoadOpts,
    ) -> BoxFuture<'a, MicrosandboxResult<Vec<SnapshotHandle>>> {
        Box::pin(async move {
            let paths = paths
                .iter()
                .map(std::path::absolute)
                .collect::<std::io::Result<Vec<_>>>()?;
            opts.dest = opts.dest.map(std::path::absolute).transpose()?;
            opts.base = opts.base.map(anchor_archive_selector).transpose()?;
            load_many_admitted(self, backend, &paths, opts).await
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

/// Import a call-time-admitted request without interpreting its base selector again.
/// A bare group must stay a group even if a later working directory contains that filename.
pub(crate) async fn load_group_admitted(
    local: &LocalBackend,
    backend: Arc<dyn Backend>,
    name: &str,
    paths: &[PathBuf],
    mut opts: LoadOpts,
) -> MicrosandboxResult<crate::SnapshotImportResult> {
    group::validate_group_name(name)?;
    if opts.group.as_deref().is_some_and(|group| group != name) {
        return Err(MicrosandboxError::InvalidConfig(
            "import options cannot select a different destination group".into(),
        ));
    }
    opts.group = Some(name.into());
    let imported = archive::load_group(local, paths, opts).await?;
    Ok(crate::SnapshotImportResult {
        operation_id: imported.operation_id,
        snapshot: crate::Snapshot {
            backend: backend.clone(),
            name: name.into(),
            reference: SnapshotReference::path(imported.group_path.to_string_lossy()),
        },
        checkpoints: imported
            .members
            .into_iter()
            .map(|handle| from_handle(backend.clone(), handle))
            .collect(),
        added: imported.added,
        reused: imported.reused,
        head_update: imported.head_update,
        warnings: imported.warnings,
    })
}

pub(crate) async fn load_many_admitted(
    local: &LocalBackend,
    backend: Arc<dyn Backend>,
    paths: &[PathBuf],
    opts: LoadOpts,
) -> MicrosandboxResult<Vec<SnapshotHandle>> {
    Ok(archive::load_snapshots(local, paths, opts)
        .await?
        .into_iter()
        .map(|handle| from_handle(backend.clone(), handle))
        .collect())
}

async fn local_selector(
    local: &LocalBackend,
    reference: SnapshotReference,
) -> MicrosandboxResult<String> {
    match reference {
        SnapshotReference::Id(id) => store::lookup_by_digest(local, &id)
            .await?
            .map(|handle| handle.artifact_path.to_string_lossy().into_owned())
            .ok_or(MicrosandboxError::SnapshotNotFound(id)),
        SnapshotReference::Auto(value) => anchor_auto_selector(value),
        SnapshotReference::Path(value) => {
            // Do not turn missing input into the current directory; callers can use
            // an explicit "." when they intend to operate on that artifact.
            if value.is_empty() {
                return Err(MicrosandboxError::InvalidConfig(
                    "snapshot path or name must not be empty".into(),
                ));
            }
            // Preserve an explicit relative path as a path, even if it is a bare name.
            Ok(std::path::absolute(value)?.to_string_lossy().into_owned())
        }
    }
}

// Names and portable IDs belong to the snapshot store, whereas path-shaped selectors
// belong to the caller's current directory. Capture only the latter before awaiting I/O.
fn anchor_auto_selector(value: String) -> MicrosandboxResult<String> {
    if store::looks_like_path(&value) {
        Ok(std::path::absolute(value)?.to_string_lossy().into_owned())
    } else {
        Ok(value)
    }
}

/// Base selectors also accept bare archive filenames. Capture that interpretation once,
/// before deferred work can mistake a same-named file in another directory for the base.
pub(crate) fn anchor_archive_selector(value: String) -> MicrosandboxResult<String> {
    if store::looks_like_path(&value) || Path::new(&value).is_file() {
        Ok(std::path::absolute(value)?.to_string_lossy().into_owned())
    } else {
        Ok(value)
    }
}

pub(super) fn from_artifact(backend: Arc<dyn Backend>, artifact: artifact::Snapshot) -> Snapshot {
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

    #[test]
    fn archive_paths_stay_bound_during_async_io() {
        const CHILD: &str = "MSB_TEST_ARCHIVE_PATH_CWD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("backend::local::snapshot::dispatch::tests::archive_paths_stay_bound_during_async_io")
                .arg("--nocapture")
                .env(CHILD, "1")
                .output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("archive path lifetime checked")
            );
            return;
        }
        let original_cwd = std::env::current_dir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let first = root.path().canonicalize().unwrap().join("first");
        let second = root.path().canonicalize().unwrap().join("second");
        let source = first.join("saved");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir(&second).unwrap();
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
        std::fs::write(source.join("upper.ext4"), [42; 512]).unwrap();
        unsafe {
            std::env::set_var("MSB_CONFIG_PATH", root.path().join("missing-config.json"));
        }
        std::env::set_current_dir(&first).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap()
            .block_on(async {
                let local = Arc::new(
                    LocalBackend::builder()
                        .home(root.path().join("home"))
                        .build_lazy()
                        .unwrap(),
                );
                // Open the database before occupying the filesystem worker. Each operation
                // below is then paused at its first file access, after input admission.
                local.db().await.unwrap();
                let save = SnapshotBackend::save(
                    local.as_ref(),
                    SnapshotReference::Auto("./saved".into()),
                    Path::new("./saved.tar"),
                    SaveOpts {
                        plain_tar: true,
                        ..Default::default()
                    },
                );
                switch_cwd_at_first_io(&second, save).await.unwrap();
                assert!(first.join("saved.tar").is_file());
                assert!(!second.join("saved.tar").exists());
                std::env::set_current_dir(&first).unwrap();
                let load = SnapshotBackend::load(
                    local.as_ref(),
                    local.clone(),
                    Path::new("./saved.tar"),
                    Some(Path::new("./imported")),
                );
                let loaded = switch_cwd_at_first_io(&second, load).await.unwrap();
                assert!(loaded.path().unwrap().starts_with(first.join("imported")));
                assert!(!second.join("imported").exists());
            });
        std::env::set_current_dir(original_cwd).unwrap();
        println!("archive path lifetime checked");
    }

    async fn switch_cwd_at_first_io<F: std::future::Future>(cwd: &Path, operation: F) -> F::Output {
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let worker = tokio::task::spawn_blocking(move || {
            entered.send(()).unwrap();
            wait.recv().unwrap();
        });
        ready.await.unwrap();
        tokio::pin!(operation);
        // The runtime has exactly one blocking worker, currently held above, so the
        // first Tokio filesystem operation is guaranteed to yield before touching disk.
        assert!(futures::poll!(&mut operation).is_pending());
        std::env::set_current_dir(cwd).unwrap();
        release.send(()).unwrap();
        worker.await.unwrap();
        operation.await
    }

    #[test]
    fn auto_selectors_anchor_only_host_paths() {
        for selector in [
            "group",
            "group:member",
            "snap_00000000000000000000000000000001",
            "sha256:abc",
        ] {
            assert_eq!(anchor_auto_selector(selector.into()).unwrap(), selector);
        }
        for selector in ["./saved", "../saved", "artifacts/saved"] {
            assert_eq!(
                PathBuf::from(anchor_auto_selector(selector.into()).unwrap()),
                std::path::absolute(selector).unwrap()
            );
        }
    }

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
                let config = builder.build().await.unwrap();
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
