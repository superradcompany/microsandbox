//! Snapshot creation from a stopped sandbox.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::Utc;
use microsandbox_image::checkpoint::{CheckpointClosure, ObjectId};
use microsandbox_image::snapshot::{
    CheckpointSnapshotState, DESCRIPTOR_FILENAME, DiskLayer, DiskLayerId, FileSnapshotState,
    ImageRef, LayerFileKind, LayerPayload, Manifest, SCHEMA, SnapshotCapture, SnapshotConsistency,
    SnapshotFormat, SnapshotId, SnapshotScope, SnapshotState, layer_path,
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
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn create_snapshot(
    local: &LocalBackend,
    config: SnapshotConfig,
) -> MicrosandboxResult<Snapshot> {
    let SnapshotConfig {
        name,
        dest_dir,
        source_sandbox,
        labels,
        force,
        record_integrity,
        resumable,
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

    if resumable {
        return create_resumable_snapshot(
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

    ensure_snapshottable_root_disk(sandbox_config.spec.image.oci_root_disk(), &source_sandbox)?;

    // Resolve source upper.ext4 path from the canonical sandbox layout.
    let sandbox_dir = local.sandboxes_dir().join(&source_sandbox);
    let src_upper = sandbox_dir.join("upper.ext4");
    if !src_upper.exists() {
        return Err(MicrosandboxError::Custom(format!(
            "source sandbox '{source_sandbox}' has no upper.ext4 at {}",
            src_upper.display()
        )));
    }

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
    let built = build_artifact(
        &staging_dir,
        &src_upper,
        &labels,
        image_reference,
        manifest_digest_str,
        &source_sandbox,
        record_integrity,
    )
    .await;
    let (digest, manifest) = match built {
        Ok(v) => v,
        Err(e) => {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(e);
        }
    };

    promote_snapshot_directory(&staging_dir, &dest_dir, force).await?;

    // Best-effort index upsert. Failures are logged, not propagated —
    // the artifact on disk is the source of truth.
    if let Err(e) = index_upsert(local, &dest_dir, &digest, &manifest).await {
        tracing::warn!(error = %e, snapshot = %digest, "snapshot_index upsert failed");
    }

    Ok(Snapshot::from_parts(dest_dir, digest, manifest, labels))
}

/// Capture one running sandbox into an installed composite-checkpoint snapshot.
async fn create_resumable_snapshot(
    local: &LocalBackend,
    name: &str,
    dest_dir: &Path,
    source_sandbox: &str,
    labels: Vec<(String, String)>,
    force: bool,
    model: sandbox_entity::Model,
) -> MicrosandboxResult<Snapshot> {
    if model.status != SandboxStatus::Running {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable("resumable snapshots require a running sandbox".into()),
        ));
    }
    let sandbox_config: SandboxConfig = serde_json::from_str(&model.config)?;
    let manifest_digest = sandbox_config.manifest_digest.clone().ok_or_else(|| {
        MicrosandboxError::InvalidConfig(format!(
            "sandbox '{source_sandbox}' has no OCI image pinned; resumable snapshots currently require a managed OCI root"
        ))
    })?;
    let image_reference = oci_reference_string(&sandbox_config)?;
    ensure_snapshottable_root_disk(sandbox_config.spec.image.oci_root_disk(), source_sandbox)?;

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

    let checkpoint_id = format!("checkpoint_{:032x}", rand::random::<u128>());
    let checkpoint = match crate::sandbox::control_checkpoint_create(
        source_sandbox,
        checkpoint_id.clone(),
    )
    .await
    {
        Ok(checkpoint) => checkpoint,
        Err(error) => {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(error);
        }
    };
    if checkpoint.checkpoint_id != checkpoint_id {
        let _ = tokio::fs::remove_dir_all(&staging_dir).await;
        return Err(MicrosandboxError::SnapshotIntegrity(
            "runtime returned a checkpoint for another capture attempt".into(),
        ));
    }
    let checkpoint_root = ObjectId::new(&checkpoint.checkpoint_root)
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let closure = CheckpointClosure::open(&checkpoint.path, Some(&checkpoint_root))
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    if closure.checkpoint().checkpoint_id != checkpoint_id {
        let _ = tokio::fs::remove_dir_all(&staging_dir).await;
        return Err(MicrosandboxError::SnapshotIntegrity(
            "runtime checkpoint closure has another capture identity".into(),
        ));
    }

    let checkpoint_source = checkpoint.path.clone();
    let checkpoint_destination = staging_dir.join(CHECKPOINT_DIRECTORY);
    let checkpoint_destination_for_copy = checkpoint_destination.clone();
    let materialized = tokio::task::spawn_blocking(move || {
        materialize_checkpoint_closure(&checkpoint_source, &checkpoint_destination_for_copy)
    })
    .await
    .map_err(|error| MicrosandboxError::Custom(format!("checkpoint copy task: {error}")))?;
    if let Err(error) = materialized {
        let _ = tokio::fs::remove_dir_all(&staging_dir).await;
        return Err(error.into());
    }
    CheckpointClosure::open(&checkpoint_destination, Some(&checkpoint_root))
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;

    let snapshot_id = SnapshotId::new(format!("snap_{:032x}", rand::random::<u128>()))
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let labels: BTreeMap<_, _> = labels.into_iter().collect();
    super::metadata::write(&staging_dir, &labels).await?;
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
        scope: SnapshotScope::Resumable,
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
        parent: None,
        requires: Vec::new(),
        extensions: BTreeMap::new(),
    };
    manifest
        .validate()
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let descriptor = manifest
        .to_canonical_bytes()
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let digest = manifest
        .digest()
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    if let Err(error) = write_descriptor(&staging_dir, &descriptor).await {
        let _ = tokio::fs::remove_dir_all(&staging_dir).await;
        return Err(error);
    }

    promote_snapshot_directory(&staging_dir, dest_dir, force).await?;
    if let Err(error) = index_upsert(local, dest_dir, &digest, &manifest).await {
        tracing::warn!(error = %error, snapshot = %digest, "snapshot_index upsert failed");
    }
    Ok(Snapshot::from_parts(
        dest_dir.to_path_buf(),
        digest,
        manifest,
        labels,
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
    let SnapshotConfig {
        name,
        dest_dir,
        source_sandbox,
        labels,
        force,
        record_integrity,
        resumable,
    } = config;
    if dest_dir.is_some() {
        return Err(MicrosandboxError::InvalidConfig(
            "direct archive capture is mutually exclusive with dest_dir".into(),
        ));
    }
    validate_snapshot_name(&name)?;
    if resumable {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable(
                "resumable snapshots require VM pause/resume restore support".into(),
            ),
        ));
    }

    let db = local.db().await?.read();
    let model = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(&source_sandbox))
        .one(db)
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(source_sandbox.clone()))?;
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
    ensure_snapshottable_root_disk(sandbox_config.spec.image.oci_root_disk(), &source_sandbox)?;
    let source_layer = local
        .sandboxes_dir()
        .join(&source_sandbox)
        .join("upper.ext4");
    let metadata = tokio::fs::symlink_metadata(&source_layer).await?;
    if !metadata.file_type().is_file() {
        return Err(MicrosandboxError::SnapshotIntegrity(format!(
            "snapshot source is not a regular file: {}",
            source_layer.display()
        )));
    }
    let integrity = if record_integrity {
        Some(super::verify::compute_merkle_integrity(&source_layer).await?)
    } else {
        None
    };
    let labels: BTreeMap<_, _> = labels.into_iter().collect();
    let manifest = new_file_manifest(
        metadata.len(),
        integrity,
        image_reference,
        manifest_digest,
        &source_sandbox,
    )?;
    let digest = manifest
        .digest()
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    super::archive::save_direct_file_snapshot(
        &manifest,
        &labels,
        &name,
        &source_layer,
        out,
        plain_tar,
        force,
    )
    .await?;
    Ok(SnapshotArchive::from_parts(
        out.to_path_buf(),
        digest,
        manifest,
        labels,
    ))
}

/// Build the artifact contents (upper copy, integrity, descriptor) into
/// `dir`. Pure staging: the caller promotes or discards the directory.
async fn build_artifact(
    dir: &std::path::Path,
    src_upper: &std::path::Path,
    labels: &BTreeMap<String, String>,
    image_reference: String,
    manifest_digest_str: String,
    source_sandbox: &str,
    record_integrity: bool,
) -> MicrosandboxResult<(String, Manifest)> {
    // Copy the upper layer (sparse-aware, see microsandbox_utils::copy).
    let snapshot_id = SnapshotId::new(format!("snap_{:032x}", rand::random::<u128>()))
        .map_err(|e| MicrosandboxError::SnapshotIntegrity(e.to_string()))?;
    let layer_id = DiskLayerId::new(format!("layer_{:032x}", rand::random::<u128>()))
        .map_err(|e| MicrosandboxError::SnapshotIntegrity(e.to_string()))?;
    let relative_layer_path = layer_path(&layer_id, SnapshotFormat::Raw);
    let dst_upper = dir.join(&relative_layer_path);
    tokio::fs::create_dir_all(
        dst_upper
            .parent()
            .expect("canonical layer path always has a parent"),
    )
    .await?;
    let src_upper_clone = src_upper.to_path_buf();
    let dst_upper_clone = dst_upper.clone();
    let copied_len = tokio::task::spawn_blocking(move || {
        microsandbox_utils::copy::fast_copy(&src_upper_clone, &dst_upper_clone)
    })
    .await
    .map_err(|e| MicrosandboxError::Custom(format!("snapshot copy task: {e}")))??;

    let dst_upper_for_sync = dst_upper.clone();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&dst_upper_for_sync)?;
        f.sync_all()?;
        Ok(())
    })
    .await
    .map_err(|e| MicrosandboxError::Custom(format!("snapshot upper fsync task: {e}")))??;

    // Persistent payload integrity is deliberately opt-in: large allocated
    // uppers make any independent content pass observable. When requested,
    // the sparse-aware Merkle construction skips known all-hole subtrees.
    let integrity = if record_integrity {
        Some(super::verify::compute_merkle_integrity(&dst_upper).await?)
    } else {
        None
    };

    // Labels are local presentation metadata. Persist them before the
    // descriptor is published so they never alter snapshot identity.
    super::metadata::write(dir, labels).await?;
    let manifest = Manifest {
        schema: SCHEMA.into(),
        snapshot_id,
        scope: SnapshotScope::Disk,
        state: SnapshotState::File(FileSnapshotState {
            disk_format: SnapshotFormat::Raw,
            filesystem: "ext4".into(),
            virtual_size: copied_len,
            head: layer_id.clone(),
            layers: vec![DiskLayer {
                layer_id,
                format: SnapshotFormat::Raw,
                virtual_size: copied_len,
                backing: None,
                payload: LayerPayload {
                    file_kind: LayerFileKind::Regular,
                    integrity,
                },
            }],
        }),
        capture: SnapshotCapture {
            created_at: Utc::now().to_rfc3339(),
            source_lineage: Some(source_sandbox.to_string()),
            source_checkpoint: None,
            consistency: SnapshotConsistency::CrashConsistent,
        },
        image: ImageRef {
            reference: image_reference,
            manifest_digest: manifest_digest_str,
        },
        parent: None,
        requires: Vec::new(),
        extensions: BTreeMap::new(),
    };
    manifest.validate()?;
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

    Ok((digest, manifest))
}

fn new_file_manifest(
    size_bytes: u64,
    integrity: Option<microsandbox_image::snapshot::UpperIntegrity>,
    image_reference: String,
    manifest_digest: String,
    source_sandbox: &str,
) -> MicrosandboxResult<Manifest> {
    let snapshot_id = SnapshotId::new(format!("snap_{:032x}", rand::random::<u128>()))
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let layer_id = DiskLayerId::new(format!("layer_{:032x}", rand::random::<u128>()))
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let manifest = Manifest {
        schema: SCHEMA.into(),
        snapshot_id,
        scope: SnapshotScope::Disk,
        state: SnapshotState::File(FileSnapshotState {
            disk_format: SnapshotFormat::Raw,
            filesystem: "ext4".into(),
            virtual_size: size_bytes,
            head: layer_id.clone(),
            layers: vec![DiskLayer {
                layer_id,
                format: SnapshotFormat::Raw,
                virtual_size: size_bytes,
                backing: None,
                payload: LayerPayload {
                    file_kind: LayerFileKind::Regular,
                    integrity,
                },
            }],
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

/// Snapshots capture the managed upper. The other root-disk kinds have nothing msb-owned on the host to capture: a tmpfs upper lives in guest RAM (until resumable snapshots
/// capture memory), and a disk-image upper is a user-owned file msb never copies into artifacts it owns.
fn ensure_snapshottable_root_disk(
    root_disk: Option<&RootDisk>,
    source_sandbox: &str,
) -> MicrosandboxResult<()> {
    match root_disk {
        Some(RootDisk::Tmpfs { .. }) => Err(MicrosandboxError::InvalidConfig(format!(
            "sandbox '{source_sandbox}' uses a tmpfs root disk, which is ephemeral and cannot be snapshotted; use the managed kind"
        ))),
        Some(RootDisk::DiskImage { .. }) => Err(MicrosandboxError::InvalidConfig(format!(
            "sandbox '{source_sandbox}' uses a user-owned disk-image root disk, which microsandbox does not snapshot"
        ))),
        Some(RootDisk::Flat { .. }) => Err(MicrosandboxError::InvalidConfig(format!(
            "sandbox '{source_sandbox}' uses a flat root disk, which is not yet supported by snapshots"
        ))),
        Some(RootDisk::Managed { .. }) | None => Ok(()),
    }
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
    fn managed_or_default_root_disk_is_snapshottable() {
        assert!(ensure_snapshottable_root_disk(None, "sb").is_ok());
        assert!(
            ensure_snapshottable_root_disk(
                Some(&RootDisk::Managed {
                    size_mib: Some(4096)
                }),
                "sb"
            )
            .is_ok()
        );
    }

    #[test]
    fn tmpfs_root_disk_is_rejected_with_a_purposeful_error() {
        let err = ensure_snapshottable_root_disk(Some(&RootDisk::Tmpfs { size_mib: None }), "sb")
            .unwrap_err()
            .to_string();
        assert!(err.contains("tmpfs"), "unexpected error: {err}");
        assert!(err.contains("managed"), "unexpected error: {err}");
    }

    #[test]
    fn disk_image_root_disk_is_rejected_with_a_purposeful_error() {
        let err = ensure_snapshottable_root_disk(
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

    #[test]
    fn flat_root_disk_is_rejected_with_a_purposeful_error() {
        let err = ensure_snapshottable_root_disk(
            Some(&RootDisk::Flat {
                size_mib: Some(8192),
                fstype: None,
                clone: microsandbox_types::FlatClone::Auto,
            }),
            "sb",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("flat"), "unexpected error: {err}");
        assert!(err.contains("not yet supported"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn artifact_integrity_is_recorded_only_when_requested() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.ext4");
        std::fs::write(&source, b"snapshot payload").unwrap();

        let without_dir = temp.path().join("without");
        std::fs::create_dir(&without_dir).unwrap();
        let (_, without) = build_artifact(
            &without_dir,
            &source,
            &BTreeMap::new(),
            "docker.io/library/alpine:3.20".into(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            "box",
            false,
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
            &source,
            &BTreeMap::new(),
            "docker.io/library/alpine:3.20".into(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            "box",
            true,
        )
        .await
        .unwrap();
        assert!(matches!(
            &with.state.as_file().unwrap().layers[0].payload.integrity,
            Some(microsandbox_image::snapshot::UpperIntegrity::FileMerkleBlake3V1 { .. })
        ));
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
