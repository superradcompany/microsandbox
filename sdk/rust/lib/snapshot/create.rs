//! Snapshot creation from a stopped sandbox.

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::Utc;
use microsandbox_image::snapshot::{
    DEFAULT_UPPER_FILE, DESCRIPTOR_FILENAME, ImageRef, Manifest, ROOTFS_LAYOUT_EXTENSION,
    SCHEMA_VERSION, SNAPSHOT_ARTIFACT_KIND, SnapshotFormat, SnapshotScope, UpperLayer,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::backend::LocalBackend;
use crate::db::entity::sandbox as sandbox_entity;
use crate::sandbox::{RootDisk, SandboxConfig, SandboxStatus};
use crate::{MicrosandboxError, MicrosandboxResult};

use super::store::index_upsert;
use super::{Snapshot, SnapshotConfig};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const FLAT_ROOTFS_SNAPSHOT_FILE: &str = "rootfs.raw";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotPayload {
    LayeredUpper,
    FlatRootfs,
}

struct SnapshotArtifactMetadata {
    labels: Vec<(String, String)>,
    image_reference: String,
    manifest_digest: String,
    source_sandbox: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SnapshotPayload {
    fn filename(self) -> &'static str {
        match self {
            Self::LayeredUpper => DEFAULT_UPPER_FILE,
            Self::FlatRootfs => FLAT_ROOTFS_SNAPSHOT_FILE,
        }
    }
}

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

    let payload =
        ensure_snapshottable_root_disk(sandbox_config.spec.image.oci_root_disk(), &source_sandbox)?;

    // Resolve the payload path from the canonical sandbox layout. Layered OCI captures only its writable upper; flat OCI captures the complete private root disk.
    let sandbox_dir = local.sandboxes_dir().join(&source_sandbox);
    let source = sandbox_dir.join(payload.filename());
    if !source.exists() {
        return Err(MicrosandboxError::Custom(format!(
            "source sandbox '{source_sandbox}' has no snapshot payload at {}",
            source.display()
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
        &source,
        payload,
        record_integrity,
        SnapshotArtifactMetadata {
            labels,
            image_reference,
            manifest_digest: manifest_digest_str,
            source_sandbox: source_sandbox.clone(),
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
    source: &std::path::Path,
    payload: SnapshotPayload,
    record_integrity: bool,
    metadata: SnapshotArtifactMetadata,
) -> MicrosandboxResult<(String, Manifest)> {
    // Snapshot into a private staged file so artifact preparation cannot mutate the stopped sandbox disk or an immutable cached base, even when the copy uses shared COW extents.
    let destination = dir.join(payload.filename());
    let source_clone = source.to_path_buf();
    let destination_clone = destination.clone();
    let copied_len = tokio::task::spawn_blocking(move || {
        microsandbox_utils::copy::fast_copy(&source_clone, &destination_clone)
    })
    .await
    .map_err(|e| MicrosandboxError::Custom(format!("snapshot copy task: {e}")))??;

    if payload == SnapshotPayload::FlatRootfs {
        let trim_path = destination.clone();
        let trim = tokio::task::spawn_blocking(move || {
            microsandbox_image::ext4::trim_snapshot_image(&trim_path)
        })
        .await
        .map_err(|error| MicrosandboxError::Custom(format!("snapshot trim task: {error}")))?
        .map_err(|error| MicrosandboxError::Custom(format!("snapshot trim failed: {error}")))?;
        tracing::info!(
            journal_replayed = trim.journal_replayed,
            free_bytes = trim.free_bytes,
            deallocated_bytes = trim.deallocated_bytes,
            ranges = trim.ranges,
            trim_supported = trim.trim_supported,
            "prepared flat rootfs snapshot payload"
        );
    }

    let destination_for_sync = destination.clone();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&destination_for_sync)?;
        f.sync_all()?;
        Ok(())
    })
    .await
    .map_err(|e| MicrosandboxError::Custom(format!("snapshot upper fsync task: {e}")))??;

    let integrity = if record_integrity {
        Some(super::verify::compute_sparse_integrity(&destination).await?)
    } else {
        None
    };

    // Build the manifest.
    let mut label_map: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in metadata.labels {
        label_map.insert(k, v);
    }

    let mut extensions = BTreeMap::new();
    let mut requires = Vec::new();
    if payload == SnapshotPayload::FlatRootfs {
        extensions.insert(
            ROOTFS_LAYOUT_EXTENSION.into(),
            serde_json::Value::String("flat".into()),
        );
        requires.push(ROOTFS_LAYOUT_EXTENSION.into());
    }

    let manifest = Manifest {
        schema: SCHEMA_VERSION,
        artifact: SNAPSHOT_ARTIFACT_KIND.into(),
        scope: SnapshotScope::Disk,
        format: SnapshotFormat::Raw,
        fstype: "ext4".into(),
        image: ImageRef {
            reference: metadata.image_reference,
            manifest_digest: metadata.manifest_digest,
        },
        parent: None,
        created_at: Utc::now().to_rfc3339(),
        labels: label_map,
        upper: UpperLayer {
            file: payload.filename().into(),
            size_bytes: copied_len,
            integrity,
        },
        source_sandbox: Some(metadata.source_sandbox),
        extensions,
        requires,
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

/// Snapshots capture the complete microsandbox-owned writable state: the managed upper for a layered root or the private complete filesystem for a flat root. A tmpfs upper lives
/// in guest RAM (until resumable snapshots capture memory), while a disk-image upper is a user-owned file microsandbox never copies into artifacts it owns.
fn ensure_snapshottable_root_disk(
    root_disk: Option<&RootDisk>,
    source_sandbox: &str,
) -> MicrosandboxResult<SnapshotPayload> {
    match root_disk {
        Some(RootDisk::Tmpfs { .. }) => Err(MicrosandboxError::InvalidConfig(format!(
            "sandbox '{source_sandbox}' uses a tmpfs root disk, which is ephemeral and cannot be snapshotted; use the managed kind"
        ))),
        Some(RootDisk::DiskImage { .. }) => Err(MicrosandboxError::InvalidConfig(format!(
            "sandbox '{source_sandbox}' uses a user-owned disk-image root disk, which microsandbox does not snapshot"
        ))),
        Some(RootDisk::Flat { .. }) => Ok(SnapshotPayload::FlatRootfs),
        Some(RootDisk::Managed { .. }) | None => Ok(SnapshotPayload::LayeredUpper),
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
    use std::io::Read;
    use std::path::PathBuf;

    use microsandbox_image::ext4::{Ext4RootfsOptions, materialize_ext4_rootfs};
    use microsandbox_image::snapshot::SnapshotRootfsLayout;
    use microsandbox_image::tree::FileTree;
    use microsandbox_types::{DiskImageFormat, FlatClone};
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn managed_or_default_root_disk_is_snapshottable() {
        assert_eq!(
            ensure_snapshottable_root_disk(None, "sb").unwrap(),
            SnapshotPayload::LayeredUpper
        );
        assert_eq!(
            ensure_snapshottable_root_disk(
                Some(&RootDisk::Managed {
                    size_mib: Some(4096)
                }),
                "sb"
            )
            .unwrap(),
            SnapshotPayload::LayeredUpper
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
    fn flat_root_disk_captures_the_complete_private_rootfs() {
        assert_eq!(
            ensure_snapshottable_root_disk(
                Some(&RootDisk::Flat {
                    size_mib: Some(8192),
                    fstype: None,
                    clone: FlatClone::Auto,
                }),
                "sb",
            )
            .unwrap(),
            SnapshotPayload::FlatRootfs
        );
    }

    #[tokio::test]
    async fn flat_artifact_is_self_describing_and_never_mutates_the_source() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.raw");
        materialize_ext4_rootfs(&source, FileTree::new(), &Ext4RootfsOptions::default()).unwrap();
        let source_digest = file_digest(&source);
        let staging = dir.path().join("staging");
        std::fs::create_dir(&staging).unwrap();

        let (_, manifest) =
            build_artifact(
                &staging,
                &source,
                SnapshotPayload::FlatRootfs,
                false,
                SnapshotArtifactMetadata {
                    labels: Vec::new(),
                    image_reference: "docker.io/library/alpine:3.20".into(),
                    manifest_digest:
                        "sha256:0000000000000000000000000000000000000000000000000000000000000001"
                            .into(),
                    source_sandbox: "flat-source".into(),
                },
            )
            .await
            .unwrap();

        assert_eq!(
            manifest.rootfs_layout().unwrap(),
            SnapshotRootfsLayout::Flat
        );
        assert_eq!(manifest.upper.file, FLAT_ROOTFS_SNAPSHOT_FILE);
        assert!(manifest.requires.contains(&ROOTFS_LAYOUT_EXTENSION.into()));
        assert!(staging.join(FLAT_ROOTFS_SNAPSHOT_FILE).is_file());
        assert!(!staging.join(DEFAULT_UPPER_FILE).exists());
        assert_eq!(file_digest(&source), source_digest);
    }

    fn file_digest(path: &std::path::Path) -> [u8; 32] {
        let mut file = std::fs::File::open(path).unwrap();
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let read = file.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        hasher.finalize().into()
    }
}
