//! Disk-only and full snapshot creation with source lifecycle preservation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use chrono::Utc;
use microsandbox_image::checkpoint::{CheckpointClosure, ObjectId};
use microsandbox_image::snapshot::{
    CheckpointSnapshotState, DESCRIPTOR_FILENAME, DiskLayer, DiskLayerId, FileSnapshotState,
    ImageRef, LayerFileKind, LayerPayload, Manifest, SCHEMA, SnapshotCapture, SnapshotConsistency,
    SnapshotFormat, SnapshotId, SnapshotRootDisk, SnapshotScope, SnapshotState, layer_path,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::backend::LocalBackend;
use crate::db::entity::sandbox as sandbox_entity;
use crate::sandbox::{RootDisk, SandboxConfig, SandboxStatus};
use crate::{
    MicrosandboxError, MicrosandboxResult, Operation, PublishedSnapshotArtifact,
    SnapshotArtifactKind, SnapshotSourceRecoveryError, UnsupportedReason,
};

use super::store::index_upsert;
use super::{Snapshot, SnapshotArchive, SnapshotConfig};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(crate) const CHECKPOINT_DIRECTORY: &str = "checkpoint";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct CapturedFullSnapshot {
    checkpoint_path: PathBuf,
    checkpoint_root: ObjectId,
    manifest: Manifest,
    labels: BTreeMap<String, String>,
    source_recovery: Option<SnapshotSourceRecoveryError>,
}

/// A complete operation-owned artifact, not yet a durable group member.
#[derive(Debug)]
struct StagedSnapshot {
    snapshot: Snapshot,
    source_recovery: Option<SnapshotSourceRecoveryError>,
}

/// Non-identity publication options shared by the full-capture entry point.
#[derive(Clone, Copy)]
struct SnapshotDestination<'a> {
    name: &'a str,
    path: &'a Path,
    force: bool,
}

/// Descriptor metadata kept separate from physical disk-copy inputs.
struct FileSnapshotMetadata<'a> {
    image_reference: String,
    manifest_digest: String,
    source_sandbox: &'a str,
    root_disk: SnapshotRootDisk,
    user: Option<String>,
}

#[derive(Clone)]
struct SnapshotDiskSource {
    path: PathBuf,
    format: SnapshotFormat,
}

struct SnapshotDiskClosure {
    sources: Vec<SnapshotDiskSource>,
    virtual_size: u64,
    /// A live capture owns immutable runtime staging until artifact publication completes.
    capture_root: Option<PathBuf>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for SnapshotDiskClosure {
    fn drop(&mut self) {
        if let Some(path) = &self.capture_root
            && let Err(error) = std::fs::remove_dir_all(path)
        {
            tracing::warn!(%error, "failed to remove consumed disk-only capture staging");
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn create_snapshot(
    local: &LocalBackend,
    mut config: SnapshotConfig,
) -> MicrosandboxResult<Snapshot> {
    if config.force {
        return Err(MicrosandboxError::InvalidConfig(
            "grouped snapshots are immutable; choose another member name or remove the existing member explicitly".into(),
        ));
    }
    let generated_name = config.name.is_empty();
    if generated_name {
        config.name = format!("msb-{:08x}", rand::random::<u32>());
    }
    validate_snapshot_name(&config.name)?;
    let lineage = super::lineage::begin(local, &config.source_sandbox).await?;
    let root = config
        .dest_dir
        .take()
        .unwrap_or_else(|| local.snapshots_dir());
    let group_name = config
        .group
        .take()
        .unwrap_or_else(|| config.source_sandbox.clone());
    let group_dir = super::group::ensure(&root, Some(&group_name)).await?;
    let staging = tempfile::Builder::new()
        .prefix(".capture-")
        .tempdir_in(&group_dir)?;
    let name = config.name.clone();
    let source_sandbox = config.source_sandbox.clone();
    config.dest_dir = Some(staging.path().to_path_buf());
    let captured = capture_installed(local, config, lineage.sandbox_id()).await?;
    publish_snapshot_group(
        local,
        captured,
        staging,
        lineage,
        name,
        generated_name,
        &source_sandbox,
    )
    .await
}

/// Source failure is reported only after the outer group and ancestry commit. Staging never
/// becomes the artifact locator, and source recovery does not cause a second capture or thaw.
async fn publish_snapshot_group(
    local: &LocalBackend,
    captured: StagedSnapshot,
    staging: tempfile::TempDir,
    lineage: super::lineage::CaptureLineage,
    name: String,
    generated_name: bool,
    source_sandbox: &str,
) -> MicrosandboxResult<Snapshot> {
    let StagedSnapshot {
        snapshot: mut captured,
        source_recovery,
    } = captured;
    let group_dir = staging
        .path()
        .parent()
        .expect("group staging has a parent")
        .to_path_buf();
    let published = async {
    lineage.validate_source(local, source_sandbox).await?;
    // Ancestry belongs to the immutable descriptor, not to the group head or export base.
    captured.manifest.parent = lineage.parent.clone();
    captured.digest = captured
        .manifest
        .digest()
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let descriptor = captured
        .manifest
        .to_canonical_bytes()
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    write_descriptor(captured.path(), &descriptor).await?;
    // Publication owns its staging and ancestry sequencer. Dropping an SDK future must not
    // release the source lock while a blocking group commit is still running in the background.
    let captured = tokio::spawn(async move {
        let update = publish_with_name_retry(
            &group_dir,
            staging.path(),
            captured.id(),
            name,
            generated_name,
            || format!("msb-{:08x}", rand::random::<u32>()),
        ).await?;
        captured.path = group_dir.join(captured.id().as_str());
        lineage.commit(captured.id()).await?;
        tracing::info!(group = %update.group, head = %update.head, reason = ?update.reason, "snapshot group publication");
        captured.head_update = Some(update);
        Ok::<_, MicrosandboxError>(captured)
    }).await.map_err(|error| MicrosandboxError::Runtime(format!("snapshot publication task: {error}")))??;
    if let Err(error) = index_upsert(
        local,
        captured.path(),
        captured.digest(),
        captured.manifest(),
    )
    .await
    {
        tracing::warn!(%error, "snapshot index update failed after group publication");
    }
    Ok(captured)
    }.await;
    finish_capture(published, source_recovery, installed_artifact)
}

/// Retry generated local names against the same captured artifact; explicit names remain strict.
pub(super) async fn publish_with_name_retry(
    group_dir: &Path,
    staged: &Path,
    snapshot_id: &SnapshotId,
    mut name: String,
    generated_name: bool,
    mut next_name: impl FnMut() -> String,
) -> MicrosandboxResult<super::group::HeadUpdate> {
    loop {
        let aliases = BTreeMap::from([(snapshot_id.to_string(), name)]);
        match super::group::publish(group_dir, staged, &aliases, snapshot_id, false).await {
            Err(MicrosandboxError::SnapshotAlreadyExists(_)) if generated_name => {
                // Alias conflicts are preflight errors: no staged payload was moved and the
                // descriptor's identity/ancestry remain unchanged, so no recapture is needed.
                name = next_name();
            }
            result => return result,
        }
    }
}

/// Build a complete artifact in operation-owned staging; group publication happens afterward.
async fn capture_installed(
    local: &LocalBackend,
    config: SnapshotConfig,
    expected_source_id: i32,
) -> MicrosandboxResult<StagedSnapshot> {
    let total_started = Instant::now();
    let SnapshotConfig {
        name,
        group: _,
        dest_dir,
        source_sandbox,
        labels,
        force,
        record_integrity,
        full,
    } = config;

    // Validate the destination before anything else so name errors surface
    // ahead of sandbox lookups and no work happens for an invalid target.
    let dest_dir = resolve_destination(local, &name, dest_dir)?;
    if dest_dir.exists() && !force {
        return Err(MicrosandboxError::SnapshotAlreadyExists(
            dest_dir.display().to_string(),
        ));
    }

    let db = local.db().await?.read();

    // Look up the sandbox row + parse its persisted config.
    let model = microsandbox_db::catalog::sandbox_query(db)
        .await?
        .filter(sandbox_entity::Column::Name.eq(&source_sandbox))
        .one(db)
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(source_sandbox.clone()))?;

    if model.id != expected_source_id {
        return Err(MicrosandboxError::InvalidConfig(
            "source sandbox changed before snapshot capture".into(),
        ));
    }
    if full {
        return create_full_snapshot(
            local,
            SnapshotDestination {
                name: &name,
                path: &dest_dir,
                force,
            },
            &source_sandbox,
            labels,
            model,
        )
        .await;
    }

    if model.status == SandboxStatus::Draining {
        return Err(MicrosandboxError::SnapshotSandboxRunning(
            source_sandbox.clone(),
        ));
    }

    // Resident runtimes own the lifecycle lock and serialize the disk cut through control.
    // Stopped copies acquire it here; the SDK never reads a live writable head.
    let live = matches!(model.status, SandboxStatus::Running | SandboxStatus::Paused);
    let _lifecycle_guard = if live {
        None
    } else {
        Some(
            crate::runtime::acquire_sandbox_lifecycle_guard(
                &local.config().run_dir(),
                &source_sandbox,
                std::time::Duration::from_secs(5),
            )
            .await?,
        )
    };
    let current = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(&source_sandbox))
        .one(local.db().await?.read())
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(source_sandbox.clone()))?;
    if current.id != model.id
        || current.status == SandboxStatus::Draining
        || live
            != matches!(
                current.status,
                SandboxStatus::Running | SandboxStatus::Paused
            )
    {
        return Err(MicrosandboxError::SnapshotSandboxRunning(
            source_sandbox.clone(),
        ));
    }

    let sandbox_config: SandboxConfig = serde_json::from_str(&current.config)?;
    LocalBackend::validate_completed_restore(&sandbox_config)?;

    // Only OCI-rooted sandboxes can be snapshotted today; non-OCI
    // rootfs (passthrough, disk-image-rootfs) are out of scope.
    let manifest_digest_str = sandbox_config.manifest_digest.clone().ok_or_else(|| {
        MicrosandboxError::InvalidConfig(format!(
            "sandbox '{source_sandbox}' has no OCI image pinned; only OCI-rooted sandboxes can be snapshotted"
        ))
    })?;
    let image_reference = oci_reference_string(&sandbox_config)?;

    let root_disk = snapshot_root_disk(sandbox_config.spec.image.oci_root_disk(), &source_sandbox)?;
    if matches!(root_disk, SnapshotRootDisk::Tmpfs { .. }) {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "sandbox '{source_sandbox}' uses a tmpfs root disk, whose writable state exists only in a running full snapshot"
        )));
    }

    let sandbox_dir = local.sandboxes_dir().join(&source_sandbox);
    let disk = capture_disk_source(
        local,
        &sandbox_dir,
        &source_sandbox,
        current.id,
        current.status,
        &root_disk,
    )
    .await?;

    // Stage the artifact in a sibling directory, so a failed create never
    // leaves a partial artifact at the destination (which would poison
    // retries with SnapshotAlreadyExists) and a force overwrite only
    // removes the old artifact after the new one is complete.
    let parent_dir = dest_dir
        .parent()
        .ok_or_else(|| {
            MicrosandboxError::InvalidConfig(format!(
                "snapshot destination has no parent directory: {}",
                dest_dir.display()
            ))
        })?
        .to_path_buf();
    tokio::fs::create_dir_all(&parent_dir).await?;
    let staging_dir = parent_dir.join(format!(".{name}.{:016x}.staging", rand::random::<u64>()));
    tokio::fs::create_dir_all(&staging_dir).await?;

    let labels: BTreeMap<_, _> = labels.into_iter().collect();
    let artifact_started = Instant::now();
    let built = build_artifact(
        &staging_dir,
        &disk,
        &labels,
        record_integrity,
        FileSnapshotMetadata {
            image_reference,
            manifest_digest: manifest_digest_str,
            source_sandbox: &source_sandbox,
            root_disk,
            user: sandbox_config.spec.runtime.user.clone(),
        },
    )
    .await;
    let (digest, manifest) = match built {
        Ok(v) => v,
        Err(e) => {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(e);
        }
    };
    let artifact_build_us = artifact_started.elapsed().as_micros();

    let promote_started = Instant::now();
    promote_snapshot_directory(&staging_dir, &dest_dir, force).await?;
    let promote_us = promote_started.elapsed().as_micros();

    tracing::info!(
        target: "microsandbox_checkpoint_timing",
        operation = "snapshot_create_installed_disk",
        source_sandbox,
        total_us = total_started.elapsed().as_micros(),
        artifact_build_us,
        promote_us,
        "disk snapshot creation timing"
    );

    Ok(StagedSnapshot {
        snapshot: Snapshot::from_parts(dest_dir, digest, manifest, labels),
        source_recovery: None,
    })
}

/// Capture one running sandbox into an installed composite-checkpoint snapshot.
async fn create_full_snapshot(
    local: &LocalBackend,
    destination: SnapshotDestination<'_>,
    source_sandbox: &str,
    labels: Vec<(String, String)>,
    model: sandbox_entity::Model,
) -> MicrosandboxResult<StagedSnapshot> {
    let dest_dir = destination.path;
    let total_started = Instant::now();
    let parent_dir = dest_dir
        .parent()
        .ok_or_else(|| {
            MicrosandboxError::InvalidConfig(format!(
                "snapshot destination has no parent directory: {}",
                dest_dir.display()
            ))
        })?
        .to_path_buf();
    tokio::fs::create_dir_all(&parent_dir).await?;
    let capture_started = Instant::now();
    // The runtime owns capture and recovery even if this client disappears. Do not allocate an
    // artifact staging directory while waiting for it: there is nothing to stage until capture
    // succeeds. The guard also removes partial materialization on ordinary errors/cancellation.
    let captured = capture_full_snapshot(local, source_sandbox, labels, model).await?;
    let capture_us = capture_started.elapsed().as_micros();
    stage_full_snapshot(
        destination,
        source_sandbox,
        captured,
        parent_dir,
        total_started,
        capture_us,
    )
    .await
}

/// Materialize a validated capture without exposing its operation-owned path as publication.
async fn stage_full_snapshot(
    destination: SnapshotDestination<'_>,
    source_sandbox: &str,
    mut captured: CapturedFullSnapshot,
    parent_dir: PathBuf,
    total_started: Instant,
    capture_us: u128,
) -> MicrosandboxResult<StagedSnapshot> {
    let SnapshotDestination {
        name,
        path: dest_dir,
        force,
    } = destination;
    let source_recovery = captured.source_recovery.take();
    // Recovery belongs to the source, not to the immutable artifact. Carry it through staging
    // until the outer publisher owns the final group member and its ancestry cursor.
    let published = async {
        let staging = tempfile::Builder::new()
            .prefix(&format!(".{name}."))
            .suffix(".staging")
            .tempdir_in(&parent_dir)?;
        let staging_dir = staging.path().to_path_buf();
        let checkpoint_source = captured.checkpoint_path.clone();
        let checkpoint_destination = staging_dir.join(CHECKPOINT_DIRECTORY);
        let checkpoint_destination_for_copy = checkpoint_destination.clone();
        let materialize_started = Instant::now();
        let materialized = tokio::task::spawn_blocking(move || {
            materialize_checkpoint_closure(&checkpoint_source, &checkpoint_destination_for_copy)
        })
        .await
        .map_err(|error| MicrosandboxError::Custom(format!("checkpoint copy task: {error}")))?;
        if let Err(error) = materialized {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(error.into());
        }
        let materialize_us = materialize_started.elapsed().as_micros();
        let closure_verify_started = Instant::now();
        CheckpointClosure::open(&checkpoint_destination, Some(&captured.checkpoint_root))
            .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
        let closure_verify_us = closure_verify_started.elapsed().as_micros();
        let metadata_started = Instant::now();
        super::metadata::write(&staging_dir, &captured.labels).await?;
        let descriptor = captured
            .manifest
            .to_canonical_bytes()
            .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
        let digest = captured
            .manifest
            .digest()
            .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
        if let Err(error) = write_descriptor(&staging_dir, &descriptor).await {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(error);
        }
        let metadata_descriptor_us = metadata_started.elapsed().as_micros();

        let promote_started = Instant::now();
        promote_snapshot_directory(&staging_dir, dest_dir, force).await?;
        let promote_us = promote_started.elapsed().as_micros();
        tracing::info!(
            target: "microsandbox_checkpoint_timing",
            operation = "snapshot_create_installed_full",
            source_sandbox,
            total_us = total_started.elapsed().as_micros(),
            capture_us,
            materialize_us,
            closure_verify_us,
            metadata_descriptor_us,
            promote_us,
            "installed full snapshot creation timing"
        );
        Ok(Snapshot::from_parts(
            dest_dir.to_path_buf(),
            digest,
            captured.manifest,
            captured.labels,
        ))
    }
    .await;
    match published {
        Ok(snapshot) => Ok(StagedSnapshot {
            snapshot,
            source_recovery,
        }),
        Err(error) => Err(capture_publication_failure(error, source_recovery)),
    }
}

/// Capture a disk or full snapshot directly into an archive without creating
/// an installed artifact directory or index row.
pub(super) async fn create_snapshot_archive(
    local: &LocalBackend,
    config: SnapshotConfig,
    out: &Path,
    plain_tar: bool,
) -> MicrosandboxResult<SnapshotArchive> {
    let total_started = Instant::now();
    let SnapshotConfig {
        mut name,
        group,
        dest_dir,
        source_sandbox,
        labels,
        force,
        record_integrity,
        full,
    } = config;
    if dest_dir.is_some() || group.is_some() {
        return Err(MicrosandboxError::InvalidConfig(
            "direct archive capture does not install a group; omit group and dest_dir".into(),
        ));
    }
    if name.is_empty() {
        name = format!("msb-{:08x}", rand::random::<u32>());
    }
    validate_snapshot_name(&name)?;
    let lineage = super::lineage::begin(local, &source_sandbox).await?;
    let db = local.db().await?.read();
    let model = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(&source_sandbox))
        .one(db)
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(source_sandbox.clone()))?;
    if model.id != lineage.sandbox_id() {
        return Err(MicrosandboxError::InvalidConfig(
            "source sandbox changed before snapshot capture".into(),
        ));
    }
    if full {
        let capture_started = Instant::now();
        let mut captured = capture_full_snapshot(local, &source_sandbox, labels, model).await?;
        lineage
            .validate_source(local, &source_sandbox)
            .await
            .map_err(|error| capture_publication_failure(error, captured.source_recovery.take()))?;
        captured.manifest.parent = lineage.parent.clone();
        let capture_us = capture_started.elapsed().as_micros();
        return publish_full_archive(
            SnapshotDestination {
                name: &name,
                path: out,
                force,
            },
            &source_sandbox,
            captured,
            lineage,
            plain_tar,
            total_started,
            capture_us,
        )
        .await;
    }
    if model.status == SandboxStatus::Draining {
        return Err(MicrosandboxError::SnapshotSandboxRunning(source_sandbox));
    }
    let live = matches!(model.status, SandboxStatus::Running | SandboxStatus::Paused);
    let _lifecycle_guard = if live {
        None
    } else {
        Some(
            crate::runtime::acquire_sandbox_lifecycle_guard(
                &local.config().run_dir(),
                &source_sandbox,
                std::time::Duration::from_secs(5),
            )
            .await?,
        )
    };
    let current = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(&source_sandbox))
        .one(local.db().await?.read())
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(source_sandbox.clone()))?;
    if current.id != model.id
        || current.status == SandboxStatus::Draining
        || live
            != matches!(
                current.status,
                SandboxStatus::Running | SandboxStatus::Paused
            )
    {
        return Err(MicrosandboxError::SnapshotSandboxRunning(source_sandbox));
    }
    let sandbox_config: SandboxConfig = serde_json::from_str(&current.config)?;
    LocalBackend::validate_completed_restore(&sandbox_config)?;
    let manifest_digest = sandbox_config.manifest_digest.clone().ok_or_else(|| {
        MicrosandboxError::InvalidConfig(
            "only OCI-rooted sandboxes with a pinned image can be snapshotted".into(),
        )
    })?;
    let image_reference = oci_reference_string(&sandbox_config)?;
    let root_disk = snapshot_root_disk(sandbox_config.spec.image.oci_root_disk(), &source_sandbox)?;
    if matches!(root_disk, SnapshotRootDisk::Tmpfs { .. }) {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "sandbox '{source_sandbox}' uses a tmpfs root disk, whose writable state exists only in a running full snapshot"
        )));
    }
    let sandbox_dir = local.sandboxes_dir().join(&source_sandbox);
    let disk = capture_disk_source(
        local,
        &sandbox_dir,
        &source_sandbox,
        current.id,
        current.status,
        &root_disk,
    )
    .await?;
    lineage.validate_source(local, &source_sandbox).await?;
    let integrity_started = Instant::now();
    let integrities = vec![None; disk.sources.len()];
    let labels: BTreeMap<_, _> = labels.into_iter().collect();
    let mut manifest = new_file_manifest(
        &disk,
        integrities,
        image_reference,
        manifest_digest,
        &source_sandbox,
        root_disk,
    )?;
    manifest.parent = lineage.parent.clone();
    manifest.set_restore_defaults(microsandbox_image::snapshot::RestoreDefaults {
        user: sandbox_config.spec.runtime.user.clone(),
    })?;
    if record_integrity && let SnapshotState::File(file) = &mut manifest.state {
        for index in 0..file.layers.len() {
            let source = &disk.sources[index].path;
            let prefix = if index > 0 {
                let backing = layer_path(
                    &file.layers[index - 1].layer_id,
                    file.layers[index - 1].format,
                );
                microsandbox_image::checkpoint::relocated_qcow2_header(source, &backing)?
            } else {
                Vec::new()
            };
            file.layers[index].payload.integrity =
                Some(super::verify::compute_merkle_integrity_with_prefix(source, prefix).await?);
        }
    }
    let integrity_us = integrity_started.elapsed().as_micros();
    let digest = manifest
        .digest()
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let archive_started = Instant::now();
    let source_paths = disk
        .sources
        .iter()
        .map(|source| source.path.clone())
        .collect::<Vec<_>>();
    let owned_out = out.to_path_buf();
    let logical_bytes = disk.virtual_size;
    let (manifest, labels) = tokio::spawn(async move {
        // A stopped disk remains locked and a live immutable cut remains pinned until the
        // background writer finishes, even if the caller stops awaiting this operation.
        let _disk = disk;
        let _lifecycle_guard = _lifecycle_guard;
        super::archive::save_direct_file_snapshot(
            &manifest,
            &labels,
            &name,
            &source_paths,
            &owned_out,
            plain_tar,
            force,
        )
        .await?;
        lineage.commit(&manifest.snapshot_id).await?;
        Ok::<_, MicrosandboxError>((manifest, labels))
    })
    .await
    .map_err(|error| {
        MicrosandboxError::Runtime(format!("snapshot archive publication: {error}"))
    })??;
    let archive_us = archive_started.elapsed().as_micros();
    tracing::info!(
        target: "microsandbox_checkpoint_timing",
        operation = "snapshot_create_archive_disk",
        source_sandbox,
        plain_tar,
        record_integrity,
        logical_bytes,
        total_us = total_started.elapsed().as_micros(),
        integrity_us,
        archive_us,
        "direct disk snapshot archive timing"
    );
    Ok(SnapshotArchive::from_parts(
        out.to_path_buf(),
        digest,
        manifest,
        labels,
    ))
}

/// Publish the archive before surfacing source recovery failure, just like installed capture.
async fn publish_full_archive(
    destination: SnapshotDestination<'_>,
    source_sandbox: &str,
    mut captured: CapturedFullSnapshot,
    lineage: super::lineage::CaptureLineage,
    plain_tar: bool,
    total_started: Instant,
    capture_us: u128,
) -> MicrosandboxResult<SnapshotArchive> {
    let SnapshotDestination {
        name,
        path: out,
        force,
    } = destination;
    let source_recovery = captured.source_recovery.take();
    let published = async {
        let digest = captured
            .manifest
            .digest()
            .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
        let archive_started = Instant::now();
        let name = name.to_owned();
        let owned_out = out.to_path_buf();
        // Keep both the immutable input and source sequencer alive when the caller cancels its
        // wait. The archive writer and cursor publication still complete in their original order.
        let captured = tokio::spawn(async move {
            super::archive::save_direct_checkpoint_snapshot(
                &captured.manifest,
                &captured.labels,
                &name,
                &captured.checkpoint_path,
                &owned_out,
                plain_tar,
                force,
            )
            .await?;
            lineage.commit(&captured.manifest.snapshot_id).await?;
            Ok::<_, MicrosandboxError>(captured)
        })
        .await
        .map_err(|error| {
            MicrosandboxError::Runtime(format!("snapshot archive publication: {error}"))
        })??;
        let archive_us = archive_started.elapsed().as_micros();
        tracing::info!(
            target: "microsandbox_checkpoint_timing",
            operation = "snapshot_create_archive_full",
            source_sandbox, plain_tar, total_us = total_started.elapsed().as_micros(),
            capture_us, archive_us, "direct full snapshot archive timing"
        );
        Ok(SnapshotArchive::from_parts(
            out.to_path_buf(),
            digest,
            captured.manifest,
            captured.labels,
        ))
    }
    .await;
    finish_capture(published, source_recovery, |archive| {
        PublishedSnapshotArtifact {
            kind: SnapshotArtifactKind::Archive,
            path: archive.path().to_path_buf(),
            snapshot_id: archive.id().to_string(),
            digest: archive.descriptor_digest().to_string(),
        }
    })
}

/// Capture and validate runtime-owned checkpoint state without choosing its final representation.
///
/// Installed snapshots and direct archives share this boundary so both publish byte-for-byte the
/// same descriptor and checkpoint closure.
async fn capture_full_snapshot(
    local: &LocalBackend,
    source_sandbox: &str,
    labels: Vec<(String, String)>,
    model: sandbox_entity::Model,
) -> MicrosandboxResult<CapturedFullSnapshot> {
    if model.status != SandboxStatus::Running {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable("full snapshots require a running sandbox".into()),
        ));
    }
    let sandbox_config: SandboxConfig = serde_json::from_str(&model.config)?;
    LocalBackend::validate_completed_restore(&sandbox_config)?;
    let manifest_digest = sandbox_config.manifest_digest.clone().ok_or_else(|| {
        MicrosandboxError::InvalidConfig(format!(
            "sandbox '{source_sandbox}' has no OCI image pinned; full snapshots require an OCI root"
        ))
    })?;
    let image_reference = oci_reference_string(&sandbox_config)?;
    let root_disk = snapshot_root_disk(sandbox_config.spec.image.oci_root_disk(), source_sandbox)?;

    let checkpoint_id = format!("checkpoint_{:032x}", rand::random::<u128>());
    let outcome =
        crate::sandbox::control_checkpoint_create(local, source_sandbox, checkpoint_id.clone())
            .await?;
    let checkpoint = outcome.checkpoint;
    let validated = (|| {
        if checkpoint.checkpoint_id != checkpoint_id {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "runtime returned a checkpoint for another capture attempt".into(),
            ));
        }
        let checkpoint_root = ObjectId::new(&checkpoint.checkpoint_root)
            .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
        let closure = CheckpointClosure::open(&checkpoint.path, Some(&checkpoint_root))
            .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
        if closure.checkpoint().checkpoint_id != checkpoint_id {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "runtime checkpoint closure has another capture identity".into(),
            ));
        }

        let snapshot_id = SnapshotId::new(format!("snap_{:032x}", rand::random::<u128>()))
            .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
        // The database follows live resize targets; it cannot describe the original RAM map.
        // Use the runtime-owned geometry bound to this exact checkpoint instead.
        let geometry = closure.checkpoint().geometry;
        let requirements_summary = BTreeMap::from([
            (
                "architecture".into(),
                serde_json::Value::String(closure.checkpoint().architecture.clone()),
            ),
            (
                "device_count".into(),
                serde_json::Value::from(closure.checkpoint().devices.len() as u64),
            ),
            (
                "memory_bytes".into(),
                serde_json::Value::from(checkpoint.memory_logical_bytes),
            ),
            ("vcpus".into(), serde_json::Value::from(geometry.vcpus)),
            (
                "max_vcpus".into(),
                serde_json::Value::from(geometry.max_vcpus),
            ),
            (
                "memory_mib".into(),
                serde_json::Value::from(geometry.memory_mib),
            ),
            (
                "max_memory_mib".into(),
                serde_json::Value::from(geometry.max_memory_mib),
            ),
        ]);
        let mut manifest = Manifest {
            schema: SCHEMA.into(),
            snapshot_id,
            scope: SnapshotScope::Full,
            state: SnapshotState::Checkpoint(CheckpointSnapshotState {
                checkpoint_id: checkpoint_id.clone(),
                checkpoint_root: checkpoint.checkpoint_root.clone(),
                restore_intents: vec!["clone".into(), "resume".into()],
                requirements_summary,
            }),
            capture: SnapshotCapture {
                created_at: Utc::now().to_rfc3339(),
                source_lineage: Some(source_sandbox.into()),
                source_checkpoint: Some(checkpoint_id.clone()),
                consistency: SnapshotConsistency::ApplicationConsistent,
            },
            image: ImageRef {
                reference: image_reference,
                manifest_digest,
            },
            root_disk,
            parent: None,
            requires: Vec::new(),
            extensions: BTreeMap::new(),
        };
        manifest.set_restore_defaults(microsandbox_image::snapshot::RestoreDefaults {
            user: sandbox_config.spec.runtime.user.clone(),
        })?;
        manifest
            .validate()
            .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
        Ok(CapturedFullSnapshot {
            source_recovery: outcome.recovery_error.as_ref().map(|detail| {
                SnapshotSourceRecoveryError {
                    source_sandbox: source_sandbox.into(),
                    checkpoint_id,
                    checkpoint_root: checkpoint.checkpoint_root,
                    checkpoint_path: checkpoint.path.clone(),
                    artifact: None,
                    detail: detail.clone(),
                    publication_error: None,
                }
            }),
            checkpoint_path: checkpoint.path,
            checkpoint_root,
            manifest,
            labels: labels.into_iter().collect(),
        })
    })();
    validated.map_err(|error| capture_validation_failure(error, outcome.recovery_error.as_deref()))
}

/// Until validation succeeds, preserve the runtime diagnostic without claiming that its supplied
/// checkpoint locator is trustworthy or that the requested snapshot has been published.
fn capture_validation_failure(
    error: MicrosandboxError,
    recovery_error: Option<&str>,
) -> MicrosandboxError {
    match recovery_error {
        Some(detail) => MicrosandboxError::SnapshotIntegrity(format!(
            "{error}; source recovery also failed: {detail}"
        )),
        None => error,
    }
}

/// Only a successful publication may supply an artifact locator. Failure reporting never rolls
/// back the runtime checkpoint or a committed destination, and never attempts another source thaw.
fn finish_capture<T>(
    published: MicrosandboxResult<T>,
    source_recovery: Option<SnapshotSourceRecoveryError>,
    artifact: impl FnOnce(&T) -> PublishedSnapshotArtifact,
) -> MicrosandboxResult<T> {
    let Some(mut failure) = source_recovery else {
        return published;
    };
    match published {
        Ok(value) => failure.artifact = Some(artifact(&value)),
        Err(error) => failure.publication_error = Some(error.to_string()),
    }
    Err(MicrosandboxError::SnapshotSourceRecovery(Box::new(failure)))
}

fn installed_artifact(snapshot: &Snapshot) -> PublishedSnapshotArtifact {
    PublishedSnapshotArtifact {
        kind: SnapshotArtifactKind::Installed,
        path: snapshot.path().to_path_buf(),
        snapshot_id: snapshot.id().to_string(),
        digest: snapshot.digest().to_string(),
    }
}

fn capture_publication_failure(
    error: MicrosandboxError,
    source_recovery: Option<SnapshotSourceRecoveryError>,
) -> MicrosandboxError {
    match source_recovery {
        Some(mut failure) => {
            failure.publication_error = Some(error.to_string());
            MicrosandboxError::SnapshotSourceRecovery(Box::new(failure))
        }
        None => error,
    }
}

/// Build the artifact contents (upper copy, integrity, descriptor) into
/// `dir`. Pure staging: the caller promotes or discards the directory.
async fn build_artifact(
    dir: &std::path::Path,
    disk: &SnapshotDiskClosure,
    labels: &BTreeMap<String, String>,
    record_integrity: bool,
    metadata: FileSnapshotMetadata<'_>,
) -> MicrosandboxResult<(String, Manifest)> {
    let FileSnapshotMetadata {
        image_reference,
        manifest_digest: manifest_digest_str,
        source_sandbox,
        root_disk,
        user,
    } = metadata;
    let total_started = Instant::now();
    let snapshot_id = SnapshotId::new(format!("snap_{:032x}", rand::random::<u128>()))
        .map_err(|e| MicrosandboxError::SnapshotIntegrity(e.to_string()))?;
    let layers_dir = dir.join(microsandbox_image::snapshot::LAYERS_DIRECTORY);
    tokio::fs::create_dir_all(&layers_dir).await?;

    let copy_started = Instant::now();
    let mut captured: Vec<(DiskLayerId, SnapshotFormat, PathBuf)> =
        Vec::with_capacity(disk.sources.len());
    for source in &disk.sources {
        let layer_id = DiskLayerId::new(format!("layer_{:032x}", rand::random::<u128>()))
            .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
        let destination = dir.join(layer_path(&layer_id, source.format));
        let source_path = source.path.clone();
        let destination_for_copy = destination.clone();
        tokio::task::spawn_blocking(move || {
            microsandbox_utils::copy::fast_copy(&source_path, &destination_for_copy)
        })
        .await
        .map_err(|error| MicrosandboxError::Custom(format!("snapshot copy task: {error}")))??;
        if let Some((_, _, predecessor)) = captured.last() {
            microsandbox_image::checkpoint::relocate_qcow2_backing(&destination, predecessor)?;
        }
        captured.push((layer_id, source.format, destination));
    }
    let copy_us = copy_started.elapsed().as_micros();

    let payload_sync_started = Instant::now();
    for (_, _, destination) in &captured {
        let destination = destination.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(destination)?
                .sync_all()
        })
        .await
        .map_err(|error| MicrosandboxError::Custom(format!("snapshot fsync task: {error}")))??;
    }
    let payload_sync_us = payload_sync_started.elapsed().as_micros();

    let integrity_started = Instant::now();
    let mut integrities = Vec::with_capacity(captured.len());
    for (_, _, destination) in &captured {
        integrities.push(if record_integrity {
            Some(super::verify::compute_merkle_integrity(destination).await?)
        } else {
            None
        });
    }
    let integrity_us = integrity_started.elapsed().as_micros();

    // Labels are local presentation metadata. Persist them before the
    // descriptor is published so they never alter snapshot identity.
    let descriptor_started = Instant::now();
    super::metadata::write(dir, labels).await?;
    let mut manifest = new_file_manifest_with_id(
        snapshot_id,
        disk,
        captured
            .iter()
            .zip(integrities)
            .map(|((layer_id, format, _), integrity)| (layer_id.clone(), *format, integrity))
            .collect(),
        image_reference,
        manifest_digest_str,
        source_sandbox,
        root_disk,
    )?;
    manifest.set_restore_defaults(microsandbox_image::snapshot::RestoreDefaults { user })?;
    let canonical = manifest
        .to_canonical_bytes()
        .map_err(|e| MicrosandboxError::Custom(format!("manifest serialize: {e}")))?;
    let digest = manifest
        .digest()
        .map_err(|e| MicrosandboxError::Custom(format!("manifest digest: {e}")))?;

    // Atomic descriptor write: stage as `.tmp`, fsync, rename.
    let manifest_path = dir.join(DESCRIPTOR_FILENAME);
    let tmp_path = dir.join(format!("{DESCRIPTOR_FILENAME}.tmp"));
    tokio::fs::write(&tmp_path, &canonical).await?;
    let tmp_path_for_sync = tmp_path.clone();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&tmp_path_for_sync)?;
        f.sync_all()?;
        Ok(())
    })
    .await
    .map_err(|e| MicrosandboxError::Custom(format!("snapshot fsync task: {e}")))??;
    tokio::fs::rename(&tmp_path, &manifest_path).await?;
    let descriptor_us = descriptor_started.elapsed().as_micros();
    tracing::info!(
        target: "microsandbox_checkpoint_timing",
        operation = "snapshot_build_file_artifact",
        source_sandbox,
        record_integrity,
        logical_bytes = disk.virtual_size,
        layer_count = disk.sources.len(),
        total_us = total_started.elapsed().as_micros(),
        copy_us,
        payload_sync_us,
        integrity_us,
        descriptor_us,
        "disk snapshot artifact build timing"
    );

    Ok((digest, manifest))
}

fn new_file_manifest(
    disk: &SnapshotDiskClosure,
    integrities: Vec<Option<microsandbox_image::snapshot::UpperIntegrity>>,
    image_reference: String,
    manifest_digest: String,
    source_sandbox: &str,
    root_disk: SnapshotRootDisk,
) -> MicrosandboxResult<Manifest> {
    let snapshot_id = SnapshotId::new(format!("snap_{:032x}", rand::random::<u128>()))
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let layers = disk
        .sources
        .iter()
        .zip(integrities)
        .map(|(source, integrity)| {
            DiskLayerId::new(format!("layer_{:032x}", rand::random::<u128>()))
                .map(|layer_id| (layer_id, source.format, integrity))
                .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))
        })
        .collect::<MicrosandboxResult<Vec<_>>>()?;
    new_file_manifest_with_id(
        snapshot_id,
        disk,
        layers,
        image_reference,
        manifest_digest,
        source_sandbox,
        root_disk,
    )
}

fn new_file_manifest_with_id(
    snapshot_id: SnapshotId,
    disk: &SnapshotDiskClosure,
    layer_inputs: Vec<(
        DiskLayerId,
        SnapshotFormat,
        Option<microsandbox_image::snapshot::UpperIntegrity>,
    )>,
    image_reference: String,
    manifest_digest: String,
    source_sandbox: &str,
    root_disk: SnapshotRootDisk,
) -> MicrosandboxResult<Manifest> {
    if layer_inputs.is_empty() || layer_inputs.len() != disk.sources.len() {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "snapshot disk closure and integrity inputs differ".into(),
        ));
    }
    let head = layer_inputs
        .last()
        .expect("checked non-empty layer inputs")
        .0
        .clone();
    let disk_format = layer_inputs
        .last()
        .expect("checked non-empty layer inputs")
        .1;
    let capacities = microsandbox_image::checkpoint::layer_capacities(
        disk.sources
            .iter()
            .map(|source| microsandbox_image::checkpoint::CompactLayer {
                path: source.path.clone(),
                qcow2: source.format == SnapshotFormat::Qcow2,
            })
            .collect(),
    )?;
    let mut predecessor = None;
    let layers = layer_inputs
        .into_iter()
        .zip(capacities)
        .map(|((layer_id, format, integrity), virtual_size)| {
            let backing = predecessor.replace(layer_id.clone());
            DiskLayer {
                layer_id,
                format,
                virtual_size,
                backing,
                payload: LayerPayload {
                    file_kind: LayerFileKind::Regular,
                    integrity,
                },
            }
        })
        .collect();
    let manifest = Manifest {
        schema: SCHEMA.into(),
        snapshot_id,
        scope: SnapshotScope::Disk,
        state: SnapshotState::File(FileSnapshotState {
            disk_format,
            filesystem: "ext4".into(),
            virtual_size: disk.virtual_size,
            head,
            layers,
        }),
        capture: SnapshotCapture {
            created_at: Utc::now().to_rfc3339(),
            source_lineage: Some(source_sandbox.to_string()),
            source_checkpoint: None,
            consistency: SnapshotConsistency::CrashConsistent,
        },
        image: ImageRef {
            reference: image_reference,
            manifest_digest,
        },
        root_disk,
        parent: None,
        requires: Vec::new(),
        extensions: BTreeMap::new(),
    };
    manifest
        .validate()
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    Ok(manifest)
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Resolve the root layout carried by a snapshot while retaining the ownership boundary for
/// caller-provided disk images.
fn snapshot_root_disk(
    root_disk: Option<&RootDisk>,
    source_sandbox: &str,
) -> MicrosandboxResult<SnapshotRootDisk> {
    match root_disk {
        Some(RootDisk::Tmpfs { size_mib }) => Ok(SnapshotRootDisk::Tmpfs {
            size_mib: *size_mib,
        }),
        Some(RootDisk::DiskImage { .. }) => Err(MicrosandboxError::InvalidConfig(format!(
            "sandbox '{source_sandbox}' uses a user-owned disk-image root disk, which microsandbox does not snapshot"
        ))),
        Some(RootDisk::Flat { .. }) => Ok(SnapshotRootDisk::Flat),
        Some(RootDisk::Managed { .. }) | None => Ok(SnapshotRootDisk::Managed),
    }
}

/// Resident runtimes return a sealed closure while retaining their lifecycle lock.
/// Stopped callers own that lock themselves. Packaging never reads a live writable head.
async fn capture_disk_source(
    local: &LocalBackend,
    sandbox_dir: &Path,
    source: &str,
    source_id: i32,
    status: SandboxStatus,
    root_disk: &SnapshotRootDisk,
) -> MicrosandboxResult<SnapshotDiskClosure> {
    if !matches!(status, SandboxStatus::Running | SandboxStatus::Paused) {
        return snapshot_disk_closure(sandbox_dir, root_disk);
    }
    let id = format!("disk_{:032x}", rand::random::<u128>());
    let captured =
        crate::sandbox::control_disk_checkpoint_create(local, source, id.clone()).await?;
    let expected_path = sandbox_dir.join("runtime").join("checkpoints").join(&id);
    let expected_device = match root_disk {
        SnapshotRootDisk::Flat => "vda",
        SnapshotRootDisk::Managed => "vdb",
        SnapshotRootDisk::Tmpfs { .. } => {
            return Err(MicrosandboxError::InvalidConfig(
                "tmpfs requires a full snapshot".into(),
            ));
        }
    };
    if captured.checkpoint_id != id
        || captured.path != expected_path
        || captured.disk.device_id != expected_device
    {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "disk capture identity, path, or root device mismatch".into(),
        ));
    }
    captured
        .disk
        .validate()
        .map_err(|e| MicrosandboxError::SnapshotIntegrity(e.to_string()))?;
    let sources = captured
        .disk
        .layers
        .iter()
        .map(|layer| {
            let format = match layer.format.as_str() {
                "raw" => SnapshotFormat::Raw,
                "qcow2" => SnapshotFormat::Qcow2,
                other => {
                    return Err(MicrosandboxError::SnapshotIntegrity(format!(
                        "unsupported live disk format {other}"
                    )));
                }
            };
            Ok(SnapshotDiskSource {
                path: captured
                    .path
                    .join("layers")
                    .join(format!("{}.{}", layer.layer_id, layer.format)),
                format,
            })
        })
        .collect::<MicrosandboxResult<Vec<_>>>()?;
    let size = captured
        .disk
        .layers
        .last()
        .ok_or_else(|| MicrosandboxError::SnapshotIntegrity("empty disk capture".into()))?
        .virtual_size;
    let mut disk = validate_snapshot_disk_sources(sources, size)?;
    disk.capture_root = Some(expected_path);
    // A live runtime owns the lifecycle lock, not this SDK call. If the source was replaced
    // between lookup and capture, never publish its disk under the original image/config.
    let current = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(source))
        .one(local.db().await?.read())
        .await?;
    if !current.is_some_and(|model| model.id == source_id) {
        return Err(MicrosandboxError::Runtime(
            "snapshot source was replaced during disk capture; retry with the current sandbox"
                .into(),
        ));
    }
    Ok(disk)
}

fn snapshot_disk_closure(
    sandbox_dir: &Path,
    root_disk: &SnapshotRootDisk,
) -> MicrosandboxResult<SnapshotDiskClosure> {
    let expected_device = match root_disk {
        SnapshotRootDisk::Managed => "vdb",
        SnapshotRootDisk::Flat => "vda",
        SnapshotRootDisk::Tmpfs { .. } => {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "tmpfs root has no stopped disk closure".into(),
            ));
        }
    };
    if let Some(chain) = microsandbox_runtime::checkpoint::load_runtime_owned_root_chain(
        &sandbox_dir.join("runtime"),
    )
    .map_err(MicrosandboxError::Runtime)?
    {
        if chain.device_id != expected_device {
            return Err(MicrosandboxError::SnapshotIntegrity(format!(
                "root-disk journal names {} but the snapshot layout requires {expected_device}",
                chain.device_id
            )));
        }
        let sources = chain
            .layers
            .into_iter()
            .map(|layer| {
                let format = match layer.format.as_str() {
                    "raw" => SnapshotFormat::Raw,
                    "qcow2" => SnapshotFormat::Qcow2,
                    other => {
                        return Err(MicrosandboxError::SnapshotIntegrity(format!(
                            "root-disk journal uses unsupported format {other:?}"
                        )));
                    }
                };
                Ok(SnapshotDiskSource {
                    path: layer.path,
                    format,
                })
            })
            .collect::<MicrosandboxResult<Vec<_>>>()?;
        return validate_snapshot_disk_sources(sources, chain.virtual_size);
    }

    let path = sandbox_dir.join(match root_disk {
        SnapshotRootDisk::Managed => "upper.ext4",
        SnapshotRootDisk::Flat => crate::sandbox::flat_rootfs::FLAT_ROOTFS_FILENAME,
        SnapshotRootDisk::Tmpfs { .. } => unreachable!("rejected above"),
    });
    let virtual_size = std::fs::symlink_metadata(&path)
        .map_err(|error| {
            MicrosandboxError::SnapshotIntegrity(format!(
                "cannot read snapshot root disk {}: {error}",
                path.display()
            ))
        })?
        .len();
    validate_snapshot_disk_sources(
        vec![SnapshotDiskSource {
            path,
            format: SnapshotFormat::Raw,
        }],
        virtual_size,
    )
}

fn validate_snapshot_disk_sources(
    sources: Vec<SnapshotDiskSource>,
    virtual_size: u64,
) -> MicrosandboxResult<SnapshotDiskClosure> {
    if sources.is_empty() || virtual_size == 0 {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "snapshot root-disk closure is empty or has zero capacity".into(),
        ));
    }
    for source in &sources {
        let metadata = std::fs::symlink_metadata(&source.path).map_err(|error| {
            MicrosandboxError::SnapshotIntegrity(format!(
                "cannot read snapshot layer {}: {error}",
                source.path.display()
            ))
        })?;
        if !metadata.file_type().is_file() {
            return Err(MicrosandboxError::SnapshotIntegrity(format!(
                "snapshot layer is not a regular file: {}",
                source.path.display()
            )));
        }
    }
    Ok(SnapshotDiskClosure {
        sources,
        virtual_size,
        capture_root: None,
    })
}

fn oci_reference_string(config: &SandboxConfig) -> MicrosandboxResult<String> {
    use crate::sandbox::RootfsSource;
    match &config.spec.image {
        RootfsSource::Oci(oci) => Ok(oci.reference.clone()),
        _ => Err(MicrosandboxError::InvalidConfig(
            "snapshot requires an OCI-rooted sandbox".into(),
        )),
    }
}

fn resolve_destination(
    local: &LocalBackend,
    name: &str,
    dest_dir: Option<PathBuf>,
) -> MicrosandboxResult<PathBuf> {
    validate_snapshot_name(name)?;
    Ok(dest_dir.unwrap_or_else(|| local.snapshots_dir()).join(name))
}

fn validate_snapshot_name(name: &str) -> MicrosandboxResult<()> {
    if name.is_empty() {
        return Err(MicrosandboxError::InvalidConfig(
            "snapshot name must not be empty".into(),
        ));
    }
    if name.len() > 255 {
        return Err(MicrosandboxError::InvalidConfig(
            "snapshot name must not exceed 255 bytes".into(),
        ));
    }
    // Reject names the open/get/remove resolvers would misread: leading '.'
    // and '~' or a '/' read as paths, and ':' collides with digest prefixes
    // (sha256:...). Such a snapshot would be creatable but unaddressable.
    if name.contains('/')
        || name.contains('\\')
        || name.contains(':')
        || name.starts_with('.')
        || name.starts_with('~')
    {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "snapshot name must be a bare identifier, not a path: '{name}' (use dest_dir to choose a parent directory)"
        )));
    }
    Ok(())
}

/// Materialize only the members of a published checkpoint closure.
///
/// The immutable root is copied last, so an interrupted copy never looks like a published
/// checkpoint. Regular files are hard-linked when source and destination share a filesystem;
/// cross-filesystem copies retain sparse/reflink optimizations through `fast_copy`.
pub(crate) fn materialize_checkpoint_closure(
    source: &Path,
    destination: &Path,
) -> std::io::Result<()> {
    materialize_checkpoint_tree(source, destination, true)
}

/// Construction-only closure: retain independent links, but do not make disposable staging
/// durable. Persistent disk successors are published separately before guest activation.
pub(crate) fn stage_checkpoint_closure(source: &Path, destination: &Path) -> std::io::Result<()> {
    materialize_checkpoint_tree(source, destination, false)
}

fn materialize_checkpoint_tree(
    source: &Path,
    destination: &Path,
    durable: bool,
) -> std::io::Result<()> {
    let source_metadata = std::fs::symlink_metadata(source)?;
    if !source_metadata.file_type().is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "checkpoint source is not a directory",
        ));
    }
    std::fs::create_dir_all(destination)?;

    for member in ["objects", "layers"] {
        let source_member = source.join(member);
        match std::fs::symlink_metadata(&source_member) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                copy_checkpoint_directory(&source_member, &destination.join(member), durable)?;
            }
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("checkpoint member {member:?} is not a directory"),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    copy_checkpoint_file(
        &source.join("checkpoint.json"),
        &destination.join("checkpoint.json"),
    )?;
    if durable {
        sync_directory(destination)?;
    }
    Ok(())
}

fn copy_checkpoint_directory(
    source: &Path,
    destination: &Path,
    durable: bool,
) -> std::io::Result<()> {
    std::fs::create_dir(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = std::fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_dir() {
            copy_checkpoint_directory(&source_path, &destination_path, durable)?;
        } else if metadata.file_type().is_file() {
            copy_checkpoint_file(&source_path, &destination_path)?;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "checkpoint member is not a regular file or directory: {}",
                    source_path.display()
                ),
            ));
        }
    }
    if durable {
        sync_directory(destination)?;
    }
    Ok(())
}

pub(crate) fn copy_checkpoint_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(source)?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "checkpoint member is not a regular file: {}",
                source.display()
            ),
        ));
    }
    match std::fs::hard_link(source, destination) {
        Ok(()) => Ok(()),
        Err(_) => {
            microsandbox_utils::copy::fast_copy(source, destination)?;
            // FlushFileBuffers on Windows requires write access even though the bytes are now
            // immutable. Open read/write consistently on every platform for the same contract.
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(destination)?
                .sync_all()
        }
    }
}

async fn write_descriptor(directory: &Path, canonical: &[u8]) -> MicrosandboxResult<()> {
    let directory = directory.to_path_buf();
    let canonical = canonical.to_vec();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        use std::io::Write;

        let manifest_path = directory.join(DESCRIPTOR_FILENAME);
        let temporary = directory.join(format!(
            ".{DESCRIPTOR_FILENAME}.{:016x}.tmp",
            rand::random::<u64>()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&canonical)?;
        file.sync_all()?;
        drop(file);
        if let Err(error) = std::fs::rename(&temporary, &manifest_path) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        sync_directory(&directory)
    })
    .await
    .map_err(|error| MicrosandboxError::Custom(format!("snapshot descriptor task: {error}")))??;
    Ok(())
}

/// Atomically replace an installed snapshot while retaining the previous artifact until the new
/// staging directory is in place. If promotion fails, the previous destination is restored.
async fn promote_snapshot_directory(
    staging: &Path,
    destination: &Path,
    force: bool,
) -> MicrosandboxResult<()> {
    let parent = destination.parent().ok_or_else(|| {
        MicrosandboxError::InvalidConfig(format!(
            "snapshot destination has no parent directory: {}",
            destination.display()
        ))
    })?;
    if staging.parent() != Some(parent) {
        return Err(MicrosandboxError::InvalidConfig(
            "snapshot staging and destination must share a parent directory".into(),
        ));
    }

    if !destination.exists() {
        tokio::fs::rename(staging, destination).await?;
        sync_directory_async(parent).await?;
        return Ok(());
    }
    if !force {
        return Err(MicrosandboxError::SnapshotAlreadyExists(
            destination.display().to_string(),
        ));
    }

    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("snapshot");
    let backup = parent.join(format!(
        ".{file_name}.{:016x}.replaced",
        rand::random::<u64>()
    ));
    tokio::fs::rename(destination, &backup).await?;
    if let Err(promote_error) = tokio::fs::rename(staging, destination).await {
        match tokio::fs::rename(&backup, destination).await {
            Ok(()) => {
                let _ = sync_directory_async(parent).await;
                return Err(promote_error.into());
            }
            Err(rollback_error) => {
                return Err(MicrosandboxError::Custom(format!(
                    "failed to publish snapshot ({promote_error}) and failed to restore the previous artifact from {} ({rollback_error})",
                    backup.display()
                )));
            }
        }
    }
    sync_directory_async(parent).await?;
    remove_path(&backup).await?;
    sync_directory_async(parent).await?;
    Ok(())
}

async fn remove_path(path: &Path) -> std::io::Result<()> {
    let metadata = tokio::fs::symlink_metadata(path).await?;
    if metadata.file_type().is_dir() {
        tokio::fs::remove_dir_all(path).await
    } else {
        tokio::fs::remove_file(path).await
    }
}

async fn sync_directory_async(path: &Path) -> std::io::Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || sync_directory(&path))
        .await
        .map_err(std::io::Error::other)?
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    // Directory handles require platform-specific flags and directory renames already provide the
    // atomic visibility guarantee used here. File payloads and descriptors are still flushed.
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use microsandbox_types::DiskImageFormat;
    use sea_orm::{ActiveModelTrait, ActiveValue::Set};

    use super::*;

    async fn fixture_source(local: &LocalBackend) {
        let mut config = SandboxConfig::default();
        config.spec.name = "box".into();
        std::fs::create_dir_all(local.sandboxes_dir().join("box")).unwrap();
        sandbox_entity::ActiveModel {
            name: Set("box".into()),
            config: Set(serde_json::to_string(&config).unwrap()),
            status: Set(SandboxStatus::Crashed),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(local.db().await.unwrap().write())
        .await
        .unwrap();
    }

    fn file_metadata(root_disk: SnapshotRootDisk) -> FileSnapshotMetadata<'static> {
        FileSnapshotMetadata {
            image_reference: "docker.io/library/alpine:3.20".into(),
            manifest_digest: format!("sha256:{}", "a".repeat(64)),
            source_sandbox: "box",
            root_disk,
            user: None,
        }
    }

    #[test]
    fn invalid_capture_keeps_recovery_diagnostic_without_a_trusted_locator() {
        let error = capture_validation_failure(
            MicrosandboxError::SnapshotIntegrity("checkpoint digest mismatch".into()),
            Some("thaw timed out; re-pause failed"),
        );
        assert!(matches!(&error, MicrosandboxError::SnapshotIntegrity(_)));
        let message = error.to_string();
        assert!(message.contains("checkpoint digest mismatch"));
        assert!(message.contains("thaw timed out; re-pause failed"));
        assert!(!message.contains("saved at"));
    }

    /// A real, verifiable checkpoint closure without a VMM or guest process.
    fn captured_fixture(root: &Path, detail: Option<&str>) -> CapturedFullSnapshot {
        use microsandbox_image::checkpoint::{
            CaptureIntent, CheckpointManifest, ContentRef, LocalObjectStore, MemoryCaptureMode,
            MemoryExtent, MemoryExtentContent, MemoryManifest,
        };
        let store = LocalObjectStore::open(root).unwrap();
        let memory = MemoryManifest {
            schema: "microsandbox.memory/1".into(),
            architecture: std::env::consts::ARCH.into(),
            guest_page_size: 4096,
            topology_generation: 1,
            generation: 1,
            capture_mode: MemoryCaptureMode::Full,
            pause_generation: 7,
            extents: vec![MemoryExtent {
                start: 0,
                length: 6,
                content: MemoryExtentContent::Object(ContentRef {
                    object: store.put_bytes(b"memory").unwrap(),
                    object_offset: 0,
                }),
            }],
        };
        let checkpoint = CheckpointManifest {
            schema: "microsandbox.checkpoint/1".into(),
            checkpoint_id: "checkpoint_fixture".into(),
            capture_intent: CaptureIntent::FullSnapshot,
            geometry: microsandbox_image::checkpoint::CheckpointGeometry {
                vcpus: 1,
                max_vcpus: 1,
                memory_mib: 128,
                max_memory_mib: 128,
            },
            architecture: std::env::consts::ARCH.into(),
            pause_generation: 7,
            execution_state: store.put_bytes(b"execution").unwrap(),
            memory: store
                .put_bytes(&memory.to_canonical_bytes().unwrap())
                .unwrap(),
            disks: Vec::new(),
            devices: Vec::new(),
            resources: Vec::new(),
            requires: Vec::new(),
        };
        let bytes = checkpoint.to_canonical_bytes().unwrap();
        let checkpoint_root = ObjectId::from_bytes(&bytes).unwrap();
        std::fs::write(root.join("checkpoint.json"), bytes).unwrap();
        CheckpointClosure::open(root, Some(&checkpoint_root)).unwrap();
        let manifest = Manifest {
            schema: SCHEMA.into(),
            snapshot_id: SnapshotId::new("snap_00000000000000000000000000000001").unwrap(),
            scope: SnapshotScope::Full,
            state: SnapshotState::Checkpoint(CheckpointSnapshotState {
                checkpoint_id: checkpoint.checkpoint_id.clone(),
                checkpoint_root: checkpoint_root.to_string(),
                restore_intents: vec!["clone".into(), "resume".into()],
                requirements_summary: BTreeMap::new(),
            }),
            capture: SnapshotCapture {
                created_at: "2026-09-10T00:00:00Z".into(),
                source_lineage: Some("box".into()),
                source_checkpoint: Some(checkpoint.checkpoint_id.clone()),
                consistency: SnapshotConsistency::ApplicationConsistent,
            },
            image: ImageRef {
                reference: "docker.io/library/alpine:3.20".into(),
                manifest_digest: format!("sha256:{}", "a".repeat(64)),
            },
            root_disk: SnapshotRootDisk::Tmpfs { size_mib: Some(64) },
            parent: None,
            requires: Vec::new(),
            extensions: BTreeMap::new(),
        };
        manifest.validate().unwrap();
        CapturedFullSnapshot {
            checkpoint_path: root.to_path_buf(),
            source_recovery: detail.map(|detail| SnapshotSourceRecoveryError {
                source_sandbox: "box".into(),
                checkpoint_id: checkpoint.checkpoint_id,
                checkpoint_root: checkpoint_root.to_string(),
                checkpoint_path: root.to_path_buf(),
                artifact: None,
                detail: detail.into(),
                publication_error: None,
            }),
            checkpoint_root,
            manifest,
            labels: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn recovery_failure_preserves_published_installed_snapshot() {
        for detail in [
            "source resume failed",
            "workload thaw timed out; re-pause failed",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let local = LocalBackend::builder()
                .home(temp.path().join("home"))
                .build()
                .await
                .unwrap();
            let captured = captured_fixture(&temp.path().join("checkpoint"), Some(detail));
            let canonical = captured.manifest.to_canonical_bytes().unwrap();
            let root = captured.checkpoint_root.clone();
            let snapshot_id = captured.manifest.snapshot_id.clone();
            fixture_source(&local).await;
            let lineage = super::super::lineage::begin(&local, "box").await.unwrap();
            let group = super::super::group::ensure(&local.snapshots_dir(), Some("box"))
                .await
                .unwrap();
            let staging = tempfile::Builder::new()
                .prefix(".capture-")
                .tempdir_in(&group)
                .unwrap();
            let staged_path = staging.path().join("snapshot");
            let staged = stage_full_snapshot(
                SnapshotDestination {
                    name: "snapshot",
                    path: &staged_path,
                    force: false,
                },
                "box",
                captured,
                staging.path().to_path_buf(),
                Instant::now(),
                0,
            )
            .await
            .unwrap();
            assert!(staged.source_recovery.is_some());
            assert!(
                super::super::store::list_indexed(&local)
                    .await
                    .unwrap()
                    .is_empty()
            );
            let error = publish_snapshot_group(
                &local,
                staged,
                staging,
                lineage,
                "snapshot".into(),
                false,
                "box",
            )
            .await
            .unwrap_err();
            let destination = group.join(snapshot_id.as_str());
            let MicrosandboxError::SnapshotSourceRecovery(failure) = error else {
                panic!("expected partial failure")
            };
            assert_eq!(failure.detail, detail);
            assert!(failure.publication_error.is_none());
            let artifact = failure.artifact.unwrap();
            assert_eq!(artifact.kind, SnapshotArtifactKind::Installed);
            assert_eq!(artifact.path, destination);
            assert_ne!(artifact.path, staged_path);
            assert!(!staged_path.exists());
            let indexed = super::super::store::list_indexed(&local).await.unwrap();
            assert_eq!(indexed.len(), 1);
            assert_eq!(
                indexed[0].artifact_path,
                destination.canonicalize().unwrap()
            );
            assert_eq!(
                super::super::group::resolve(&local.snapshots_dir(), "box")
                    .await
                    .unwrap(),
                destination
            );
            assert_eq!(
                super::super::lineage::begin(&local, "box")
                    .await
                    .unwrap()
                    .parent,
                Some(snapshot_id)
            );
            assert_eq!(
                std::fs::read(destination.join(DESCRIPTOR_FILENAME)).unwrap(),
                canonical
            );
            CheckpointClosure::open(destination.join(CHECKPOINT_DIRECTORY), Some(&root)).unwrap();
            CheckpointClosure::open(&failure.checkpoint_path, Some(&root)).unwrap();
            let reopened =
                super::super::store::open_snapshot(&local, destination.to_str().unwrap())
                    .await
                    .unwrap();
            assert_eq!(artifact.snapshot_id, reopened.id().to_string());
            assert_eq!(artifact.digest, reopened.digest());
        }
    }

    #[tokio::test]
    async fn recovery_failure_preserves_published_archive() {
        let temp = tempfile::tempdir().unwrap();
        let local = LocalBackend::builder()
            .home(temp.path().join("home"))
            .build()
            .await
            .unwrap();
        let captured = captured_fixture(
            &temp.path().join("checkpoint"),
            Some("workload thaw failed"),
        );
        let expected = captured.manifest.to_canonical_bytes().unwrap();
        let out = temp.path().join("snapshot.tar");
        fixture_source(&local).await;
        let lineage = super::super::lineage::begin(&local, "box").await.unwrap();
        let error = publish_full_archive(
            SnapshotDestination {
                name: "snapshot",
                path: &out,
                force: false,
            },
            "box",
            captured,
            lineage,
            true,
            Instant::now(),
            0,
        )
        .await
        .unwrap_err();
        let MicrosandboxError::SnapshotSourceRecovery(failure) = error else {
            panic!("expected partial failure")
        };
        assert!(failure.publication_error.is_none());
        let artifact = failure.artifact.unwrap();
        assert_eq!(artifact.kind, SnapshotArtifactKind::Archive);
        assert_eq!(artifact.path, out);
        let restored = super::super::archive::materialize_archive_for_child(
            &local,
            &out,
            &temp.path().join("child"),
            false,
        )
        .await
        .unwrap();
        assert_eq!(restored.manifest.to_canonical_bytes().unwrap(), expected);
        assert_eq!(artifact.digest, restored.manifest.digest().unwrap());
        assert!(failure.checkpoint_path.join("checkpoint.json").exists());
    }

    #[tokio::test]
    async fn recovery_failure_keeps_original_artifact_and_both_diagnostics_on_publication_error() {
        let temp = tempfile::tempdir().unwrap();
        let local = LocalBackend::builder()
            .home(temp.path().join("home"))
            .build()
            .await
            .unwrap();
        fixture_source(&local).await;
        for archive in [false, true] {
            let captured = captured_fixture(
                &temp.path().join(if archive {
                    "archive-checkpoint"
                } else {
                    "installed-checkpoint"
                }),
                Some("source resume failed"),
            );
            let destination = temp
                .path()
                .join(if archive { "existing.tar" } else { "existing" });
            std::fs::write(&destination, b"previous artifact").unwrap();
            let target = SnapshotDestination {
                name: "snapshot",
                path: &destination,
                force: false,
            };
            let error = if archive {
                let lineage = super::super::lineage::begin(&local, "box").await.unwrap();
                publish_full_archive(target, "box", captured, lineage, true, Instant::now(), 0)
                    .await
                    .unwrap_err()
            } else {
                stage_full_snapshot(
                    target,
                    "box",
                    captured,
                    temp.path().to_path_buf(),
                    Instant::now(),
                    0,
                )
                .await
                .unwrap_err()
            };
            let MicrosandboxError::SnapshotSourceRecovery(failure) = error else {
                panic!("expected partial failure")
            };
            assert_eq!(failure.detail, "source resume failed");
            assert!(failure.artifact.is_none());
            assert!(
                failure
                    .publication_error
                    .as_ref()
                    .unwrap()
                    .contains("already exists")
            );
            assert_eq!(std::fs::read(destination).unwrap(), b"previous artifact");
            CheckpointClosure::open(&failure.checkpoint_path, None).unwrap();
        }
    }

    #[tokio::test]
    async fn successful_source_recovery_keeps_existing_success_result() {
        let temp = tempfile::tempdir().unwrap();
        let local = LocalBackend::builder()
            .home(temp.path().join("home"))
            .build()
            .await
            .unwrap();
        fixture_source(&local).await;
        let lineage = super::super::lineage::begin(&local, "box").await.unwrap();
        let captured = captured_fixture(&temp.path().join("checkpoint"), None);
        let out = temp.path().join("snapshot.tar");
        let archive = publish_full_archive(
            SnapshotDestination {
                name: "snapshot",
                path: &out,
                force: false,
            },
            "box",
            captured,
            lineage,
            true,
            Instant::now(),
            0,
        )
        .await
        .unwrap();
        assert_eq!(archive.path(), out);
    }

    #[test]
    fn snapshot_root_layout_preserves_owned_kinds() {
        assert_eq!(
            snapshot_root_disk(None, "sb").unwrap(),
            SnapshotRootDisk::Managed
        );
        assert_eq!(
            snapshot_root_disk(
                Some(&RootDisk::Managed {
                    size_mib: Some(4096)
                }),
                "sb"
            )
            .unwrap(),
            SnapshotRootDisk::Managed
        );
        assert_eq!(
            snapshot_root_disk(
                Some(&RootDisk::Flat {
                    size_mib: Some(8192),
                    fstype: None,
                    clone: microsandbox_types::FlatClone::Auto,
                }),
                "sb",
            )
            .unwrap(),
            SnapshotRootDisk::Flat
        );
        assert_eq!(
            snapshot_root_disk(
                Some(&RootDisk::Tmpfs {
                    size_mib: Some(256)
                }),
                "sb"
            )
            .unwrap(),
            SnapshotRootDisk::Tmpfs {
                size_mib: Some(256)
            }
        );
    }

    #[test]
    fn disk_image_root_disk_is_rejected_with_a_purposeful_error() {
        let err = snapshot_root_disk(
            Some(&RootDisk::DiskImage {
                path: PathBuf::from("./scratch.img"),
                format: DiskImageFormat::Raw,
                fstype: None,
            }),
            "sb",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("disk-image"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn artifact_integrity_is_recorded_only_when_requested() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.ext4");
        std::fs::write(&source, b"snapshot payload").unwrap();
        let disk = SnapshotDiskClosure {
            capture_root: None,
            sources: vec![SnapshotDiskSource {
                path: source,
                format: SnapshotFormat::Raw,
            }],
            virtual_size: b"snapshot payload".len() as u64,
        };

        let without_dir = temp.path().join("without");
        std::fs::create_dir(&without_dir).unwrap();
        let (_, without) = build_artifact(
            &without_dir,
            &disk,
            &BTreeMap::new(),
            false,
            file_metadata(SnapshotRootDisk::Managed),
        )
        .await
        .unwrap();
        assert_eq!(
            without.state.as_file().unwrap().layers[0].payload.integrity,
            None
        );

        let with_dir = temp.path().join("with");
        std::fs::create_dir(&with_dir).unwrap();
        let (_, with) = build_artifact(
            &with_dir,
            &disk,
            &BTreeMap::new(),
            true,
            file_metadata(SnapshotRootDisk::Managed),
        )
        .await
        .unwrap();
        assert!(matches!(
            &with.state.as_file().unwrap().layers[0].payload.integrity,
            Some(microsandbox_image::snapshot::UpperIntegrity::FileMerkleBlake3V1 { .. })
        ));
    }

    #[tokio::test]
    async fn artifact_preserves_an_ordered_raw_qcow_disk_closure() {
        let temp = tempfile::tempdir().unwrap();
        let raw = temp.path().join("root.raw");
        let qcow = temp.path().join("generation.qcow2");
        let raw_file = std::fs::File::create(&raw).unwrap();
        raw_file.set_len(4096).unwrap();
        microsandbox_image::checkpoint::create_qcow2_overlay(&qcow, 4096, &raw, "raw")
            .await
            .unwrap();
        let disk = SnapshotDiskClosure {
            capture_root: None,
            sources: vec![
                SnapshotDiskSource {
                    path: raw,
                    format: SnapshotFormat::Raw,
                },
                SnapshotDiskSource {
                    path: qcow,
                    format: SnapshotFormat::Qcow2,
                },
            ],
            virtual_size: 4096,
        };
        let artifact = temp.path().join("artifact");
        std::fs::create_dir(&artifact).unwrap();

        let (_, manifest) = build_artifact(
            &artifact,
            &disk,
            &BTreeMap::new(),
            true,
            file_metadata(SnapshotRootDisk::Flat),
        )
        .await
        .unwrap();

        let file = manifest.state.as_file().unwrap();
        assert_eq!(file.disk_format, SnapshotFormat::Qcow2);
        assert_eq!(file.layers.len(), 2);
        assert_eq!(file.layers[0].format, SnapshotFormat::Raw);
        assert_eq!(file.layers[1].format, SnapshotFormat::Qcow2);
        assert_eq!(
            file.layers[1].backing,
            Some(file.layers[0].layer_id.clone())
        );
        assert_eq!(file.head, file.layers[1].layer_id);
        let Some(microsandbox_image::snapshot::UpperIntegrity::FileMerkleBlake3V1 {
            logical_size,
            ..
        }) = &file.layers[1].payload.integrity
        else {
            panic!("qcow layer is missing BLAKE3 integrity");
        };
        assert_eq!(
            *logical_size,
            std::fs::metadata(&disk.sources[1].path).unwrap().len()
        );
        assert_ne!(*logical_size, file.virtual_size);
        let captured_qcow = artifact.join(file.layer_path(&file.layers[1]));
        let captured_backing = artifact.join(file.layer_path(&file.layers[0]));
        let prefix = microsandbox_image::checkpoint::relocated_qcow2_header(
            &disk.sources[1].path,
            &captured_backing,
        )
        .unwrap();
        assert_eq!(
            super::super::verify::compute_merkle_integrity_with_prefix(
                &disk.sources[1].path,
                prefix
            )
            .await
            .unwrap(),
            super::super::verify::compute_merkle_integrity(&captured_qcow)
                .await
                .unwrap(),
        );
    }

    #[test]
    fn checkpoint_materialization_copies_only_the_published_closure_shape() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        std::fs::create_dir_all(source.join("objects/sha256/aa")).unwrap();
        std::fs::create_dir_all(source.join("layers")).unwrap();
        std::fs::write(source.join("objects/sha256/aa/object"), b"memory").unwrap();
        std::fs::write(source.join("layers/layer.qcow2"), b"disk").unwrap();
        std::fs::write(source.join("checkpoint.json"), b"root").unwrap();
        std::fs::write(source.join("runtime-private.json"), b"ignored").unwrap();

        materialize_checkpoint_closure(&source, &destination).unwrap();

        assert_eq!(
            std::fs::read(destination.join("objects/sha256/aa/object")).unwrap(),
            b"memory"
        );
        assert_eq!(
            std::fs::read(destination.join("layers/layer.qcow2")).unwrap(),
            b"disk"
        );
        assert_eq!(
            std::fs::read(destination.join("checkpoint.json")).unwrap(),
            b"root"
        );
        assert!(!destination.join("runtime-private.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn checkpoint_materialization_rejects_symlink_members() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        std::fs::create_dir_all(source.join("objects")).unwrap();
        std::fs::write(source.join("outside"), b"outside").unwrap();
        symlink(source.join("outside"), source.join("objects/member")).unwrap();
        std::fs::write(source.join("checkpoint.json"), b"root").unwrap();

        let error = materialize_checkpoint_closure(&source, &destination).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn snapshot_promotion_replaces_only_after_staging_is_complete() {
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("snapshot");
        let staging = temp.path().join(".snapshot.staging");
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(destination.join("payload"), b"old").unwrap();
        std::fs::create_dir(&staging).unwrap();
        std::fs::write(staging.join("payload"), b"new").unwrap();

        promote_snapshot_directory(&staging, &destination, true)
            .await
            .unwrap();

        assert_eq!(std::fs::read(destination.join("payload")).unwrap(), b"new");
        assert!(!staging.exists());
        let hidden_entries = std::fs::read_dir(temp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".snapshot.")
            })
            .count();
        assert_eq!(hidden_entries, 0);
    }

    #[tokio::test]
    async fn snapshot_promotion_without_force_preserves_both_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("snapshot");
        let staging = temp.path().join(".snapshot.staging");
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(destination.join("payload"), b"old").unwrap();
        std::fs::create_dir(&staging).unwrap();
        std::fs::write(staging.join("payload"), b"new").unwrap();

        let error = promote_snapshot_directory(&staging, &destination, false)
            .await
            .unwrap_err();

        assert!(matches!(error, MicrosandboxError::SnapshotAlreadyExists(_)));
        assert_eq!(std::fs::read(destination.join("payload")).unwrap(), b"old");
        assert_eq!(std::fs::read(staging.join("payload")).unwrap(), b"new");
    }
}
