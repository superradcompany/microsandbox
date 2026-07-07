//! Snapshot creation from a stopped sandbox.

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::Utc;
use microsandbox_image::snapshot::{
    DEFAULT_UPPER_FILE, DESCRIPTOR_FILENAME, ImageRef, Manifest, SCHEMA_VERSION,
    SNAPSHOT_ARTIFACT_KIND, SnapshotFormat, SnapshotScope, UpperLayer,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::backend::LocalBackend;
use crate::db::entity::sandbox as sandbox_entity;
use crate::sandbox::{RootDisk, SandboxConfig, SandboxStatus};
use crate::{MicrosandboxError, MicrosandboxResult};

use super::store::index_upsert;
use super::{Snapshot, SnapshotConfig};

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

    if resumable {
        return Err(MicrosandboxError::Unsupported {
            feature: "Resumable snapshots".into(),
            available_when: "after VM pause/resume and resumable restore support land".into(),
        });
    }

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

    if matches!(
        model.status,
        SandboxStatus::Running | SandboxStatus::Draining | SandboxStatus::Paused
    ) {
        return Err(MicrosandboxError::SnapshotSandboxRunning(
            source_sandbox.clone(),
        ));
    }

    let sandbox_config: SandboxConfig = serde_json::from_str(&model.config)?;

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
    let staging_dir = parent_dir.join(format!(".{name}.staging"));
    if staging_dir.exists() {
        tokio::fs::remove_dir_all(&staging_dir).await?;
    }
    tokio::fs::create_dir_all(&staging_dir).await?;

    let built = build_artifact(
        &staging_dir,
        &src_upper,
        record_integrity,
        labels,
        image_reference,
        manifest_digest_str,
        &source_sandbox,
    )
    .await;
    let (digest, manifest) = match built {
        Ok(v) => v,
        Err(e) => {
            let _ = tokio::fs::remove_dir_all(&staging_dir).await;
            return Err(e);
        }
    };

    // Promote the staged artifact into place.
    if dest_dir.exists() {
        tokio::fs::remove_dir_all(&dest_dir).await?;
    }
    if let Err(e) = tokio::fs::rename(&staging_dir, &dest_dir).await {
        let _ = tokio::fs::remove_dir_all(&staging_dir).await;
        return Err(e.into());
    }

    // Best-effort index upsert. Failures are logged, not propagated —
    // the artifact on disk is the source of truth.
    if let Err(e) = index_upsert(local, &dest_dir, &digest, &manifest).await {
        tracing::warn!(error = %e, snapshot = %digest, "snapshot_index upsert failed");
    }

    Ok(Snapshot::from_parts(dest_dir, digest, manifest))
}

/// Build the artifact contents (upper copy, integrity, descriptor) into
/// `dir`. Pure staging: the caller promotes or discards the directory.
async fn build_artifact(
    dir: &std::path::Path,
    src_upper: &std::path::Path,
    record_integrity: bool,
    labels: Vec<(String, String)>,
    image_reference: String,
    manifest_digest_str: String,
    source_sandbox: &str,
) -> MicrosandboxResult<(String, Manifest)> {
    // Copy the upper layer (sparse-aware, see microsandbox_utils::copy).
    let dst_upper = dir.join(DEFAULT_UPPER_FILE);
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

    let integrity = if record_integrity {
        Some(super::verify::compute_sparse_integrity(&dst_upper).await?)
    } else {
        None
    };

    // Build the manifest.
    let mut label_map: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in labels {
        label_map.insert(k, v);
    }

    let manifest = Manifest {
        schema: SCHEMA_VERSION,
        artifact: SNAPSHOT_ARTIFACT_KIND.into(),
        scope: SnapshotScope::Disk,
        format: SnapshotFormat::Raw,
        fstype: "ext4".into(),
        image: ImageRef {
            reference: image_reference,
            manifest_digest: manifest_digest_str,
        },
        parent: None,
        created_at: Utc::now().to_rfc3339(),
        labels: label_map,
        upper: UpperLayer {
            file: DEFAULT_UPPER_FILE.into(),
            size_bytes: copied_len,
            integrity,
        },
        source_sandbox: Some(source_sandbox.to_string()),
        extensions: BTreeMap::new(),
        requires: Vec::new(),
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
    if name.is_empty() {
        return Err(MicrosandboxError::InvalidConfig(
            "snapshot name must not be empty".into(),
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
    Ok(dest_dir.unwrap_or_else(|| local.snapshots_dir()).join(name))
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
}
