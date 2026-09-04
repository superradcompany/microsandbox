//! Snapshot creation from a stopped sandbox.

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
use crate::{MicrosandboxError, MicrosandboxResult, Operation, UnsupportedReason};

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
}

#[derive(Clone)]
struct SnapshotDiskSource {
    path: PathBuf,
    format: SnapshotFormat,
}

struct SnapshotDiskClosure {
    sources: Vec<SnapshotDiskSource>,
    virtual_size: u64,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn create_snapshot(
    local: &LocalBackend,
    config: SnapshotConfig,
) -> MicrosandboxResult<Snapshot> {
    let total_started = Instant::now();
    let SnapshotConfig {
        name,
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
    let model = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(&source_sandbox))
        .one(db)
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(source_sandbox.clone()))?;

    if full {
        return create_full_snapshot(
            local,
            &name,
            &dest_dir,
            &source_sandbox,
            labels,
            force,
            model,
        )
        .await;
    }

    if matches!(
        model.status,
        SandboxStatus::Running | SandboxStatus::Draining | SandboxStatus::Paused
    ) {
        return Err(MicrosandboxError::SnapshotSandboxRunning(
            source_sandbox.clone(),
        ));
    }

    // Reuse the runtime's existing lifecycle ownership lock so start,
    // replacement, and removal cannot race the upper copy.
    let _lifecycle_guard = crate::runtime::acquire_sandbox_lifecycle_guard(
        &local.config().run_dir(),
        &source_sandbox,
        std::time::Duration::from_secs(5),
    )
    .await?;
    let current = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(&source_sandbox))
        .one(local.db().await?.read())
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(source_sandbox.clone()))?;
    if current.id != model.id
        || matches!(
            current.status,
            SandboxStatus::Running | SandboxStatus::Draining | SandboxStatus::Paused
        )
    {
        return Err(MicrosandboxError::SnapshotSandboxRunning(
            source_sandbox.clone(),
        ));
    }

    let sandbox_config: SandboxConfig = serde_json::from_str(&current.config)?;

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
    let disk = snapshot_disk_closure(&sandbox_dir, &root_disk)?;

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
        image_reference,
        manifest_digest_str,
        &source_sandbox,
        record_integrity,
        root_disk,
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

    // Best-effort index upsert. Failures are logged, not propagated —
    // the artifact on disk is the source of truth.
    let index_started = Instant::now();
    if let Err(e) = index_upsert(local, &dest_dir, &digest, &manifest).await {
        tracing::warn!(error = %e, snapshot = %digest, "snapshot_index upsert failed");
    }
    let index_us = index_started.elapsed().as_micros();
    tracing::info!(
        target: "microsandbox_checkpoint_timing",
        operation = "snapshot_create_installed_stopped",
        source_sandbox,
        total_us = total_started.elapsed().as_micros(),
        artifact_build_us,
        promote_us,
        index_us,
        "stopped snapshot creation timing"
    );

    Ok(Snapshot::from_parts(dest_dir, digest, manifest, labels))
}

/// Capture one running sandbox into an installed composite-checkpoint snapshot.
async fn create_full_snapshot(
    local: &LocalBackend,
    name: &str,
    dest_dir: &Path,
    source_sandbox: &str,
    labels: Vec<(String, String)>,
    force: bool,
    model: sandbox_entity::Model,
) -> MicrosandboxResult<Snapshot> {
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
    let staging_dir = parent_dir.join(format!(".{name}.{:016x}.staging", rand::random::<u64>()));
    tokio::fs::create_dir_all(&staging_dir).await?;
    let capture_started = Instant::now();
    let captured = match capture_full_snapshot(source_sandbox, labels, model).await {
        Ok(captured) => captured,
        Err(error) => {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(error);
        }
    };
    let capture_us = capture_started.elapsed().as_micros();
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
    let index_started = Instant::now();
    if let Err(error) = index_upsert(local, dest_dir, &digest, &captured.manifest).await {
        tracing::warn!(error = %error, snapshot = %digest, "snapshot_index upsert failed");
    }
    let index_us = index_started.elapsed().as_micros();
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
        index_us,
        "installed full snapshot creation timing"
    );
    Ok(Snapshot::from_parts(
        dest_dir.to_path_buf(),
        digest,
        captured.manifest,
        captured.labels,
    ))
}

/// Capture directly from a stopped sandbox into an archive without creating
/// an installed artifact directory or index row.
pub(super) async fn create_snapshot_archive(
    local: &LocalBackend,
    config: SnapshotConfig,
    out: &Path,
    plain_tar: bool,
) -> MicrosandboxResult<SnapshotArchive> {
    let total_started = Instant::now();
    let SnapshotConfig {
        name,
        dest_dir,
        source_sandbox,
        labels,
        force,
        record_integrity,
        full,
    } = config;
    if dest_dir.is_some() {
        return Err(MicrosandboxError::InvalidConfig(
            "direct archive capture is mutually exclusive with dest_dir".into(),
        ));
    }
    validate_snapshot_name(&name)?;
    let db = local.db().await?.read();
    let model = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(&source_sandbox))
        .one(db)
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(source_sandbox.clone()))?;
    if full {
        let capture_started = Instant::now();
        let captured = capture_full_snapshot(&source_sandbox, labels, model).await?;
        let capture_us = capture_started.elapsed().as_micros();
        let digest = captured
            .manifest
            .digest()
            .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
        let archive_started = Instant::now();
        super::archive::save_direct_checkpoint_snapshot(
            &captured.manifest,
            &captured.labels,
            &name,
            &captured.checkpoint_path,
            out,
            plain_tar,
            force,
        )
        .await?;
        let archive_us = archive_started.elapsed().as_micros();
        tracing::info!(
            target: "microsandbox_checkpoint_timing",
            operation = "snapshot_create_archive_full",
            source_sandbox,
            plain_tar,
            total_us = total_started.elapsed().as_micros(),
            capture_us,
            archive_us,
            "direct full snapshot archive timing"
        );
        return Ok(SnapshotArchive::from_parts(
            out.to_path_buf(),
            digest,
            captured.manifest,
            captured.labels,
        ));
    }
    if matches!(
        model.status,
        SandboxStatus::Running | SandboxStatus::Draining | SandboxStatus::Paused
    ) {
        return Err(MicrosandboxError::SnapshotSandboxRunning(source_sandbox));
    }
    let _lifecycle_guard = crate::runtime::acquire_sandbox_lifecycle_guard(
        &local.config().run_dir(),
        &source_sandbox,
        std::time::Duration::from_secs(5),
    )
    .await?;
    let current = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(&source_sandbox))
        .one(local.db().await?.read())
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(source_sandbox.clone()))?;
    if current.id != model.id
        || matches!(
            current.status,
            SandboxStatus::Running | SandboxStatus::Draining | SandboxStatus::Paused
        )
    {
        return Err(MicrosandboxError::SnapshotSandboxRunning(source_sandbox));
    }
    let sandbox_config: SandboxConfig = serde_json::from_str(&current.config)?;
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
    let disk = snapshot_disk_closure(&sandbox_dir, &root_disk)?;
    let integrity_started = Instant::now();
    let integrities = if record_integrity {
        let mut values = Vec::with_capacity(disk.sources.len());
        for source in &disk.sources {
            values.push(Some(
                super::verify::compute_merkle_integrity(&source.path).await?,
            ));
        }
        values
    } else {
        vec![None; disk.sources.len()]
    };
    let integrity_us = integrity_started.elapsed().as_micros();
    let labels: BTreeMap<_, _> = labels.into_iter().collect();
    let manifest = new_file_manifest(
        &disk,
        integrities,
        image_reference,
        manifest_digest,
        &source_sandbox,
        root_disk,
    )?;
    let digest = manifest
        .digest()
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let archive_started = Instant::now();
    let source_paths = disk
        .sources
        .iter()
        .map(|source| source.path.clone())
        .collect::<Vec<_>>();
    super::archive::save_direct_file_snapshot(
        &manifest,
        &labels,
        &name,
        &source_paths,
        out,
        plain_tar,
        force,
    )
    .await?;
    let archive_us = archive_started.elapsed().as_micros();
    tracing::info!(
        target: "microsandbox_checkpoint_timing",
        operation = "snapshot_create_archive_stopped",
        source_sandbox,
        plain_tar,
        record_integrity,
        logical_bytes = disk.virtual_size,
        total_us = total_started.elapsed().as_micros(),
        integrity_us,
        archive_us,
        "direct stopped snapshot archive timing"
    );
    Ok(SnapshotArchive::from_parts(
        out.to_path_buf(),
        digest,
        manifest,
        labels,
    ))
}

/// Capture and validate runtime-owned checkpoint state without choosing its final representation.
///
/// Installed snapshots and direct archives share this boundary so both publish byte-for-byte the
/// same descriptor and checkpoint closure.
async fn capture_full_snapshot(
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
    let manifest_digest = sandbox_config.manifest_digest.clone().ok_or_else(|| {
        MicrosandboxError::InvalidConfig(format!(
            "sandbox '{source_sandbox}' has no OCI image pinned; full snapshots require an OCI root"
        ))
    })?;
    let image_reference = oci_reference_string(&sandbox_config)?;
    let root_disk = snapshot_root_disk(sandbox_config.spec.image.oci_root_disk(), source_sandbox)?;

    let checkpoint_id = format!("checkpoint_{:032x}", rand::random::<u128>());
    let checkpoint =
        crate::sandbox::control_checkpoint_create(source_sandbox, checkpoint_id.clone()).await?;
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
        (
            "vcpus".into(),
            serde_json::Value::from(sandbox_config.spec.resources.cpus),
        ),
        (
            "max_vcpus".into(),
            serde_json::Value::from(sandbox_config.spec.resources.max_cpus),
        ),
        (
            "memory_mib".into(),
            serde_json::Value::from(sandbox_config.spec.resources.memory_mib),
        ),
        (
            "max_memory_mib".into(),
            serde_json::Value::from(sandbox_config.spec.resources.max_memory_mib),
        ),
    ]);
    let manifest = Manifest {
        schema: SCHEMA.into(),
        snapshot_id,
        scope: SnapshotScope::Full,
        state: SnapshotState::Checkpoint(CheckpointSnapshotState {
            checkpoint_id: checkpoint_id.clone(),
            checkpoint_root: checkpoint.checkpoint_root,
            restore_intents: vec!["clone".into(), "resume".into()],
            requirements_summary,
        }),
        capture: SnapshotCapture {
            created_at: Utc::now().to_rfc3339(),
            source_lineage: Some(source_sandbox.into()),
            source_checkpoint: Some(checkpoint_id),
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
    manifest
        .validate()
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    Ok(CapturedFullSnapshot {
        checkpoint_path: checkpoint.path,
        checkpoint_root,
        manifest,
        labels: labels.into_iter().collect(),
    })
}

/// Build the artifact contents (upper copy, integrity, descriptor) into
/// `dir`. Pure staging: the caller promotes or discards the directory.
async fn build_artifact(
    dir: &std::path::Path,
    disk: &SnapshotDiskClosure,
    labels: &BTreeMap<String, String>,
    image_reference: String,
    manifest_digest_str: String,
    source_sandbox: &str,
    record_integrity: bool,
    root_disk: SnapshotRootDisk,
) -> MicrosandboxResult<(String, Manifest)> {
    let total_started = Instant::now();
    let snapshot_id = SnapshotId::new(format!("snap_{:032x}", rand::random::<u128>()))
        .map_err(|e| MicrosandboxError::SnapshotIntegrity(e.to_string()))?;
    let layers_dir = dir.join(microsandbox_image::snapshot::LAYERS_DIRECTORY);
    tokio::fs::create_dir_all(&layers_dir).await?;

    let copy_started = Instant::now();
    let mut captured = Vec::with_capacity(disk.sources.len());
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
    let manifest = new_file_manifest_with_id(
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
        "stopped snapshot artifact build timing"
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
    let mut predecessor = None;
    let layers = layer_inputs
        .into_iter()
        .map(|(layer_id, format, integrity)| {
            let backing = predecessor.replace(layer_id.clone());
            DiskLayer {
                layer_id,
                format,
                virtual_size: disk.virtual_size,
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
                copy_checkpoint_directory(&source_member, &destination.join(member))?;
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
    sync_directory(destination)
}

fn copy_checkpoint_directory(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::create_dir(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = std::fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_dir() {
            copy_checkpoint_directory(&source_path, &destination_path)?;
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
    sync_directory(destination)
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

    use super::*;

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
            "docker.io/library/alpine:3.20".into(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            "box",
            false,
            SnapshotRootDisk::Managed,
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
            "docker.io/library/alpine:3.20".into(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            "box",
            true,
            SnapshotRootDisk::Managed,
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
        std::fs::write(&qcow, b"compact qcow payload").unwrap();
        let disk = SnapshotDiskClosure {
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
            "docker.io/library/alpine:3.20".into(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            "box",
            true,
            SnapshotRootDisk::Flat,
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
        assert_eq!(*logical_size, b"compact qcow payload".len() as u64);
        assert_ne!(*logical_size, file.virtual_size);
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
