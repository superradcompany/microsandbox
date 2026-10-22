//! Bridge filesystem publication and catalog ownership with existing snapshot-index roots.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use microsandbox_db::DbWriteConnection;
use microsandbox_image::snapshot::Manifest;
use microsandbox_image::storage_lease::StorageLease;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter};

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
    let retained = db
        .transaction(|txn| {
            let key = key.clone();
            let digest = digest.to_owned();
            let path = path.to_path_buf();

            async move {
                let Some(existing) = snapshot::Entity::find_by_id(key).one(&txn).await? else {
                    return Ok((txn, false));
                };
                if existing.digest != digest {
                    return Err(MicrosandboxError::SnapshotIntegrity(
                        "publication conflicts with an indexed snapshot generation".into(),
                    ));
                }

                // A live namespace lease already protects installed files. Keep their
                // availability if later publication fails, even while readers prevent recovery.
                match tokio::fs::symlink_metadata(&path).await {
                    Ok(_) => return Ok((txn, true)),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }

                // Absent files need a reservation against stale-row cleanup after a parent
                // is recreated. Preserve aliases and ancestry while restoring that copy.
                let mut existing: snapshot::ActiveModel = existing.into();
                existing.availability = Set("publishing".into());
                existing.update(&txn).await?;
                Ok((txn, true))
            }
        })
        .await?;

    if retained {
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

/// Complete the whole durable batch while retaining group ownership. Readers can help a
/// live publisher or recover a dead one without waiting for its shared namespace pins.
pub(super) async fn complete_batch(
    db: &DbWriteConnection,
    directory: &Path,
) -> MicrosandboxResult<bool> {
    Ok(complete_batch_report(db, directory).await?.is_some())
}

/// Return cleanup warnings to the initiating operation while retaining the existing
/// recovery helper's boolean contract for readers and maintenance callers.
pub(super) async fn complete_batch_report(
    db: &DbWriteConnection,
    directory: &Path,
) -> MicrosandboxResult<Option<Vec<String>>> {
    let Some(pending) = super::group::pending_index(directory).await? else {
        return Ok(None);
    };
    super::store::index_write_batch(db, &pending.snapshots).await?;
    Ok(Some(pending.finish().await?))
}

/// Recover whole groups, including external destinations. Namespace pins distinguish dead
/// publishers from live ones; one busy member defers its entire group rather than exposing
/// whichever prefix happened to be unpinned first.
pub(crate) async fn recover(local: &LocalBackend) -> MicrosandboxResult<()> {
    let db = local.db().await?;
    let pending = pending_groups(local).await?;
    for scope in pending.keys() {
        if scope.0 {
            complete_batch(db.write(), &scope.1).await?;
        }
    }
    // Finishing a journal may leave historical noncanonical reservations of the same
    // entries. Refresh before ordinary recovery so those aliases are retired in this pass.
    let pending = pending_groups(local).await?;
    let mut admitted = Vec::new();
    for (scope, rows) in pending {
        // Filesystem rollback acquires its own deletion pins. Recover before retaining our
        // exclusive namespace pins, otherwise recovery would contend with itself.
        if scope.0 {
            super::group::recover_publication(&scope.1).await?;
        }
        let mut leases = Vec::new();
        let mut keys = BTreeSet::new();
        for row in &rows {
            let path = Path::new(&row.artifact_path);
            // Historical path aliases can reserve the same member twice. Pin the entry once
            // while retaining both row addresses for replacement in the index transaction.
            if !keys.insert(StorageLease::key(path)?) {
                continue;
            }
            let Some(lease) = StorageLease::try_exclusive(path)? else {
                leases.clear();
                break;
            };
            leases.push(lease);
        }
        if !leases.is_empty() {
            admitted.push((scope, rows, leases));
        }
    }
    if admitted.is_empty() {
        return Ok(());
    }

    // The first query can race a publisher preparing its reservations. It retains all its
    // namespace pins through completion, so after admission a second query either sees the
    // same complete set or defers it. Never recover a stale prefix of a newer batch. Refresh
    // once for all admitted groups rather than repeatedly scanning the index per group.
    let mut current = pending_groups(local).await?;
    for (scope, rows, _leases) in admitted {
        if current.remove(&scope).as_ref() != Some(&rows) {
            continue;
        }
        let mut published = Vec::new();
        let mut absent = Vec::new();
        #[cfg(unix)]
        let mut readers = Vec::new();
        for row in rows {
            let path = PathBuf::from(&row.artifact_path);
            match tokio::fs::symlink_metadata(&path).await {
                Ok(metadata) if metadata.file_type().is_dir() => {
                    // On Windows the exclusive namespace pin already protects this entry;
                    // reacquiring it shared through the reader helper would deadlock.
                    #[cfg(unix)]
                    readers.push(super::lease::reader_async(path.clone()).await?);
                    let bytes = tokio::fs::read(
                        path.join(microsandbox_image::snapshot::DESCRIPTOR_FILENAME),
                    )
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
                    published.push((path, row.digest, manifest));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    absent.push(row.artifact_path);
                }
                Err(error) => return Err(error.into()),
                Ok(_) => {
                    return Err(MicrosandboxError::SnapshotIntegrity(
                        "pending snapshot path is not a directory".into(),
                    ));
                }
            }
        }
        super::store::index_recover_batch(db.write(), &published, absent).await?;
    }
    Ok(())
}

/// Group metadata supplies the coordination scope; standalone historical artifacts retain
/// their individual recovery scope. Canonicalize coordination keys, never persisted inputs.
async fn pending_groups(
    local: &LocalBackend,
) -> MicrosandboxResult<BTreeMap<(bool, PathBuf), Vec<snapshot::Model>>> {
    let pending = snapshot::Entity::find()
        .filter(snapshot::Column::Availability.eq("publishing"))
        .all(local.db().await?.read())
        .await?;
    let mut groups: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for row in pending {
        let path = Path::new(&row.artifact_path);
        let scope = match super::group::group_path(path) {
            Some(group) => (true, std::fs::canonicalize(group)?),
            None => (false, super::store::canonical_path(path)),
        };
        groups.entry(scope).or_default().push(row);
    }
    for rows in groups.values_mut() {
        rows.sort_by(|left, right| left.artifact_path.cmp(&right.artifact_path));
    }
    Ok(groups)
}
