//! Bridge filesystem publication and catalog ownership with existing snapshot-index roots.

use std::path::{Path, PathBuf};

use microsandbox_db::DbWriteConnection;
use microsandbox_image::snapshot::Manifest;
use microsandbox_image::storage_lease::StorageLease;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::backend::LocalBackend;
use crate::db::entity::snapshot;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// The publisher holds the destination namespace lease before this call and through
/// `complete`. Existing image GC already treats every snapshot row as a durable root.
pub(super) async fn prepare(
    db: &DbWriteConnection,
    path: &Path,
    digest: &str,
    manifest: &Manifest,
) -> MicrosandboxResult<()> {
    let key = super::store::canonical_path(path).display().to_string();
    if let Some(existing) = snapshot::Entity::find_by_id(key).one(db).await? {
        if existing.digest != digest {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "publication conflicts with an indexed snapshot generation".into(),
            ));
        }
        return Ok(());
    }
    // Reserve only the immutable ID, never a user alias whose collision is still to be
    // checked by group publication. A failed batch cannot supersede an existing alias.
    super::store::index_write(
        db,
        path,
        digest,
        manifest,
        "publishing",
        Some(manifest.snapshot_id.to_string()),
    )
    .await
}

pub(super) async fn complete(
    db: &DbWriteConnection,
    path: &Path,
    digest: &str,
    manifest: &Manifest,
) -> MicrosandboxResult<()> {
    super::store::index_write(db, path, digest, manifest, "ready", None).await
}

/// Find intents through the catalog, including external destinations. A live publisher
/// prevents exclusive admission. A dead publisher left either a complete member or no member.
pub(crate) async fn recover(local: &LocalBackend) -> MicrosandboxResult<()> {
    let db = local.db().await?;
    let pending = snapshot::Entity::find()
        .filter(snapshot::Column::Availability.eq("publishing"))
        .all(db.read())
        .await?;
    for row in pending {
        let path = PathBuf::from(&row.artifact_path);
        let Some(_namespace) = StorageLease::try_exclusive(&path)? else {
            continue;
        };
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.file_type().is_dir() => {
                // On Windows the reader uses this same out-of-directory lock. The
                // exclusive recovery lease already pins the entry, and reacquiring
                // it shared here would deadlock this process.
                #[cfg(unix)]
                let _reader = super::lease::reader_async(path.clone()).await?;
                let bytes =
                    tokio::fs::read(path.join(microsandbox_image::snapshot::DESCRIPTOR_FILENAME))
                        .await?;
                let manifest = Manifest::from_bytes(&bytes)
                    .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
                if manifest
                    .digest()
                    .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?
                    != row.digest
                {
                    return Err(MicrosandboxError::SnapshotIntegrity(format!(
                        "pending publication changed at {}",
                        path.display()
                    )));
                }
                complete(db.write(), &path, &row.digest, &manifest).await?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                snapshot::Entity::delete_by_id(row.artifact_path)
                    .exec(db.write())
                    .await?;
                super::store::recompute_children(db.write()).await?;
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(MicrosandboxError::SnapshotIntegrity(
                    "pending snapshot path is not a directory".into(),
                ));
            }
        }
    }
    Ok(())
}
