//! Snapshot creation from a stopped sandbox.

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::Utc;
use microsandbox_image::snapshot::{
    DEFAULT_UPPER_FILE, ImageRef, MANIFEST_FILENAME, Manifest, SCHEMA_VERSION, SnapshotFormat,
    UpperLayer,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::db::entity::sandbox as sandbox_entity;
use crate::sandbox::{SandboxConfig, SandboxStatus};
use crate::{MicrosandboxError, MicrosandboxResult};

use super::store::index_upsert;
use super::{Snapshot, SnapshotConfig, SnapshotDestination};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn create_snapshot(config: SnapshotConfig) -> MicrosandboxResult<Snapshot> {
    let SnapshotConfig {
        source_sandbox,
        destination,
        labels,
        force,
        record_integrity,
    } = config;

    let db = crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

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

    // v1 only supports OCI-rooted sandboxes. Non-OCI rootfs (passthrough,
    // disk-image-rootfs) are out of scope.
    let manifest_digest_str = sandbox_config.manifest_digest.clone().ok_or_else(|| {
        MicrosandboxError::InvalidConfig(format!(
            "sandbox '{source_sandbox}' has no OCI image pinned; only OCI-rooted sandboxes can be snapshotted"
        ))
    })?;
    let image_reference = oci_reference_string(&sandbox_config)?;

    // Resolve source upper.ext4 path from the canonical sandbox layout.
    let sandbox_dir = crate::config::config()
        .sandboxes_dir()
        .join(&source_sandbox);
    let src_upper = sandbox_dir.join("upper.ext4");
    if !src_upper.exists() {
        return Err(MicrosandboxError::Custom(format!(
            "source sandbox '{source_sandbox}' has no upper.ext4 at {}",
            src_upper.display()
        )));
    }

    // Resolve and prepare the destination directory.
    let dest_dir = resolve_destination(&destination)?;
    if dest_dir.exists() {
        if !force {
            return Err(MicrosandboxError::SnapshotAlreadyExists(
                dest_dir.display().to_string(),
            ));
        }
        tokio::fs::remove_dir_all(&dest_dir).await?;
    }
    tokio::fs::create_dir_all(&dest_dir).await?;

    // Copy the upper layer (sparse-aware, see microsandbox_utils::copy).
    let dst_upper = dest_dir.join(DEFAULT_UPPER_FILE);
    let src_upper_clone = src_upper.clone();
    let dst_upper_clone = dst_upper.clone();
    let copied_len = tokio::task::spawn_blocking(move || {
        microsandbox_utils::copy::fast_copy(&src_upper_clone, &dst_upper_clone)
    })
    .await
    .map_err(|e| MicrosandboxError::Custom(format!("snapshot copy task: {e}")))??;

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
        format: SnapshotFormat::Raw,
        fstype: "ext4".into(),
        image: ImageRef {
            reference: image_reference,
            manifest_digest: manifest_digest_str.clone(),
        },
        parent: None,
        created_at: Utc::now().to_rfc3339(),
        labels: label_map,
        upper: UpperLayer {
            file: DEFAULT_UPPER_FILE.into(),
            size_bytes: copied_len,
            integrity,
        },
        source_sandbox: Some(source_sandbox.clone()),
    };
    manifest.validate()?;
    let canonical = manifest
        .to_canonical_bytes()
        .map_err(|e| MicrosandboxError::Custom(format!("manifest serialize: {e}")))?;
    let digest = manifest
        .digest()
        .map_err(|e| MicrosandboxError::Custom(format!("manifest digest: {e}")))?;

    // Atomic manifest write: stage as `.tmp`, fsync, rename.
    let manifest_path = dest_dir.join(MANIFEST_FILENAME);
    let tmp_path = dest_dir.join(format!("{MANIFEST_FILENAME}.tmp"));
    tokio::fs::write(&tmp_path, &canonical).await?;
    let tmp_path_for_sync = tmp_path.clone();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let f = std::fs::File::open(&tmp_path_for_sync)?;
        f.sync_all()?;
        Ok(())
    })
    .await
    .map_err(|e| MicrosandboxError::Custom(format!("snapshot fsync task: {e}")))??;
    tokio::fs::rename(&tmp_path, &manifest_path).await?;

    // Best-effort index upsert. Failures are logged, not propagated —
    // the artifact on disk is the source of truth.
    if let Err(e) = index_upsert(&dest_dir, &digest, &manifest).await {
        tracing::warn!(error = %e, snapshot = %digest, "snapshot_index upsert failed");
    }

    Ok(Snapshot::from_parts(dest_dir, digest, manifest))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn oci_reference_string(config: &SandboxConfig) -> MicrosandboxResult<String> {
    use crate::sandbox::RootfsSource;
    match &config.image {
        RootfsSource::Oci(reference) => Ok(reference.clone()),
        _ => Err(MicrosandboxError::InvalidConfig(
            "snapshot requires an OCI-rooted sandbox".into(),
        )),
    }
}

fn resolve_destination(dest: &SnapshotDestination) -> MicrosandboxResult<PathBuf> {
    match dest {
        SnapshotDestination::Path(p) => Ok(p.clone()),
        SnapshotDestination::Name(name) => {
            if name.is_empty() {
                return Err(MicrosandboxError::InvalidConfig(
                    "snapshot name must not be empty".into(),
                ));
            }
            if name.contains('/') || name.starts_with('.') {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "snapshot name must be a bare identifier, not a path: '{name}'"
                )));
            }
            Ok(crate::config::config().snapshots_dir().join(name))
        }
    }
}
