//! Snapshot artifact storage operations: open, list, index upsert.

use std::path::{Path, PathBuf};

use chrono::Utc;
use microsandbox_image::snapshot::{DESCRIPTOR_FILENAME, Manifest};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    QueryOrder,
};

use crate::backend::LocalBackend;
use crate::db::entity::snapshot as snapshot_entity;
use crate::{MicrosandboxError, MicrosandboxResult};

use super::{Snapshot, SnapshotFormat, SnapshotHandle, SnapshotScope};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open and validate snapshot artifact metadata.
///
/// `path_or_name` is treated as a path if it contains `/` or starts
/// with `.` or `~`; otherwise as a bare name resolved under the
/// passed-in `local` backend's snapshots directory.
pub(super) async fn open_snapshot(
    local: &LocalBackend,
    path_or_name: &str,
) -> MicrosandboxResult<Snapshot> {
    if path_or_name.is_empty() {
        return Err(MicrosandboxError::InvalidConfig(
            "snapshot path or name must not be empty".into(),
        ));
    }

    let dir = if looks_like_path(path_or_name) {
        PathBuf::from(path_or_name)
    } else {
        local.snapshots_dir().join(path_or_name)
    };

    if !dir.exists() {
        return Err(MicrosandboxError::SnapshotNotFound(
            dir.display().to_string(),
        ));
    }

    let manifest_path = dir.join(DESCRIPTOR_FILENAME);
    let bytes = tokio::fs::read(&manifest_path).await.map_err(|e| {
        MicrosandboxError::SnapshotNotFound(format!("{}: {e}", manifest_path.display()))
    })?;
    let manifest = Manifest::from_bytes(&bytes)
        .map_err(|e| MicrosandboxError::SnapshotIntegrity(format!("{e}")))?;
    let digest = manifest
        .digest()
        .map_err(|e| MicrosandboxError::SnapshotIntegrity(format!("{e}")))?;

    // Verify the upper file is present and matches the recorded size.
    // Content verification is an explicit operation because raw upper
    // files may be multi-GiB, dense files.
    let upper_path = dir.join(&manifest.upper.file);
    let upper_meta = tokio::fs::symlink_metadata(&upper_path)
        .await
        .map_err(|e| {
            MicrosandboxError::SnapshotIntegrity(format!(
                "missing upper file: {}: {e}",
                upper_path.display()
            ))
        })?;
    if !upper_meta.file_type().is_file() {
        return Err(MicrosandboxError::SnapshotIntegrity(format!(
            "upper is not a regular file: {}",
            upper_path.display()
        )));
    }
    let actual_size = upper_meta.len();
    if actual_size != manifest.upper.size_bytes {
        return Err(MicrosandboxError::SnapshotIntegrity(format!(
            "upper size mismatch: manifest says {}, file is {}",
            manifest.upper.size_bytes, actual_size
        )));
    }

    let snap = Snapshot::from_parts(dir.clone(), digest.clone(), manifest);

    // Opportunistic auto-reindex: if the artifact lives under the
    // configured snapshots dir but its digest isn't in the local
    // index, insert it. Keeps the cache aligned with reality without
    // forcing the user to think about it. Best-effort — errors are
    // logged, not propagated.
    let snapshots_dir = local.snapshots_dir();
    if dir.parent() == Some(snapshots_dir.as_path())
        && let Ok(None) = lookup_by_digest(local, &digest).await
        && let Err(e) = index_upsert(local, snap.path(), snap.digest(), snap.manifest()).await
    {
        tracing::debug!(error = %e, snapshot = %digest, "auto-reindex skipped");
    }

    Ok(snap)
}

/// Insert or update an index row for the given artifact.
pub(super) async fn index_upsert(
    local: &LocalBackend,
    artifact_path: &Path,
    digest: &str,
    manifest: &Manifest,
) -> MicrosandboxResult<()> {
    let db = local.db().await?.write();

    let created_at = chrono::DateTime::parse_from_rfc3339(&manifest.created_at)
        .map(|d| d.naive_utc())
        .unwrap_or_else(|_| Utc::now().naive_utc());
    let indexed_at = Utc::now().naive_utc();

    let artifact_path_str = artifact_path.display().to_string();
    let artifact_name = artifact_path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string());

    // Delete any prior row for this digest, name, or path, then insert.
    // This keeps the rebuildable index aligned when an artifact is
    // replaced in-place or when a manifest rewrite changes its digest.
    // The superseded rows' parent edges disappear with them, so their
    // parents' child_count must come down first; the fresh insert re-adds
    // its own edge below.
    let mut supersede = sea_orm::Condition::any()
        .add(snapshot_entity::Column::Digest.eq(digest.to_string()))
        .add(snapshot_entity::Column::ArtifactPath.eq(artifact_path_str.clone()));
    if let Some(name) = artifact_name.as_ref() {
        supersede = supersede.add(snapshot_entity::Column::Name.eq(name.clone()));
    }
    let superseded = snapshot_entity::Entity::find()
        .filter(supersede.clone())
        .all(db)
        .await?;
    for row in &superseded {
        if let Some(parent) = row.parent_digest.as_ref() {
            db.execute_unprepared(&format!(
                "UPDATE snapshot_index SET child_count = MAX(0, child_count - 1) WHERE digest = '{}'",
                parent.replace('\'', "''")
            ))
            .await?;
        }
    }
    snapshot_entity::Entity::delete_many()
        .filter(supersede)
        .exec(db)
        .await?;

    let format_str = match manifest.format {
        microsandbox_image::snapshot::SnapshotFormat::Raw => "raw",
        microsandbox_image::snapshot::SnapshotFormat::Qcow2 => "qcow2",
    };
    let scope_str = match manifest.scope {
        SnapshotScope::Disk => "disk",
        SnapshotScope::Resumable => "resumable",
    };

    let row = snapshot_entity::ActiveModel {
        digest: Set(digest.to_string()),
        name: Set(artifact_name),
        parent_digest: Set(manifest.parent.clone()),
        scope: Set(scope_str.into()),
        image_ref: Set(manifest.image.reference.clone()),
        image_manifest_digest: Set(manifest.image.manifest_digest.clone()),
        format: Set(format_str.into()),
        fstype: Set(manifest.fstype.clone()),
        artifact_path: Set(artifact_path_str),
        size_bytes: Set(Some(manifest.upper.size_bytes as i64)),
        created_at: Set(created_at),
        indexed_at: Set(indexed_at),
        child_count: Set(0),
    };
    row.insert(db).await?;

    // If this snapshot has a parent, bump the parent's child_count.
    if let Some(parent) = manifest.parent.as_ref() {
        use sea_orm::ConnectionTrait;
        db.execute_unprepared(&format!(
            "UPDATE snapshot_index SET child_count = child_count + 1 WHERE digest = '{}'",
            parent.replace('\'', "''")
        ))
        .await?;
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Heuristic split between a bare snapshot name and a filesystem path.
pub(super) fn looks_like_path(s: &str) -> bool {
    if s.contains('/') || s.starts_with('.') || s.starts_with('~') {
        return true;
    }
    // On Windows hosts, native separators and drive/UNC prefixes (`C:\snaps\foo`, `C:foo`, `\\server\share`) mark a path even when no forward slash appears.
    #[cfg(windows)]
    {
        use typed_path::{Utf8WindowsComponent, Utf8WindowsPath};
        s.contains('\\')
            || matches!(
                Utf8WindowsPath::new(s).components().next(),
                Some(Utf8WindowsComponent::Prefix(_))
            )
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub(super) async fn list_indexed(local: &LocalBackend) -> MicrosandboxResult<Vec<SnapshotHandle>> {
    let db = local.db().await?.read();
    let rows = snapshot_entity::Entity::find()
        .order_by_desc(snapshot_entity::Column::CreatedAt)
        .all(db)
        .await?;
    Ok(rows.into_iter().map(handle_from_model).collect())
}

pub(super) async fn list_dir(
    local: &LocalBackend,
    dir: &Path,
) -> MicrosandboxResult<Vec<Snapshot>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        // Dot-prefixed directories are never artifacts; create() stages
        // in-progress snapshots as `.<name>.staging` siblings, and a crashed
        // staging dir must not be listed or indexed as a snapshot.
        if path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with('.'))
        {
            continue;
        }
        if !path.join(DESCRIPTOR_FILENAME).exists() {
            continue;
        }
        match open_snapshot(local, path.to_string_lossy().as_ref()).await {
            Ok(s) => out.push(s),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping malformed snapshot artifact")
            }
        }
    }
    Ok(out)
}

pub(super) async fn remove_snapshot(
    local: &LocalBackend,
    path_or_name: &str,
    force: bool,
) -> MicrosandboxResult<()> {
    let pools = local.db().await?;
    let read_db = pools.read();
    let write_db = pools.write();

    // Resolve the target row. Accept digest, name, or path.
    let (digest, artifact_path) =
        if path_or_name.starts_with("sha256:") || path_or_name.starts_with("sha512:") {
            let row = snapshot_entity::Entity::find_by_id(path_or_name.to_string())
                .one(read_db)
                .await?
                .ok_or_else(|| MicrosandboxError::SnapshotNotFound(path_or_name.into()))?;
            (row.digest.clone(), PathBuf::from(row.artifact_path))
        } else if looks_like_path(path_or_name) {
            // Path: open to read the digest, then drop both row and dir.
            let snap = open_snapshot(local, path_or_name).await?;
            (snap.digest.clone(), snap.path.clone())
        } else {
            // Bare name: prefer the index lookup; fall back to default-dir resolution.
            let row = snapshot_entity::Entity::find()
                .filter(snapshot_entity::Column::Name.eq(path_or_name.to_string()))
                .one(read_db)
                .await?;
            if let Some(row) = row {
                (row.digest.clone(), PathBuf::from(row.artifact_path))
            } else {
                let dir = local.snapshots_dir().join(path_or_name);
                let snap = open_snapshot(local, dir.to_string_lossy().as_ref()).await?;
                (snap.digest.clone(), snap.path.clone())
            }
        };

    // Check children unless --force.
    let row = snapshot_entity::Entity::find_by_id(digest.clone())
        .one(read_db)
        .await?;
    if let Some(ref row) = row
        && row.child_count > 0
        && !force
    {
        return Err(MicrosandboxError::Custom(format!(
            "snapshot {} has {} indexed child snapshot(s); pass --force to remove anyway",
            digest, row.child_count
        )));
    }

    // Drop the index row and decrement parent's child_count if any.
    let parent = row.as_ref().and_then(|r| r.parent_digest.clone());
    snapshot_entity::Entity::delete_by_id(digest.clone())
        .exec(write_db)
        .await?;
    if let Some(p) = parent {
        write_db
            .execute_unprepared(&format!(
                "UPDATE snapshot_index SET child_count = MAX(0, child_count - 1) WHERE digest = '{}'",
                p.replace('\'', "''")
            ))
            .await?;
    }

    // Delete the artifact directory.
    if artifact_path.exists() {
        tokio::fs::remove_dir_all(&artifact_path).await?;
    }
    Ok(())
}

pub(super) async fn reindex_dir(local: &LocalBackend, dir: &Path) -> MicrosandboxResult<usize> {
    let snapshots = list_dir(local, dir).await?;
    let mut indexed = 0usize;
    for snap in &snapshots {
        if let Err(e) = index_upsert(local, &snap.path, &snap.digest, &snap.manifest).await {
            tracing::warn!(path = %snap.path.display(), error = %e, "reindex: upsert failed");
            continue;
        }
        indexed += 1;
    }
    // After upserts, recompute child_count from parent edges in one pass
    // to keep the cache honest about the current set of artifacts.
    let db = local.db().await?.write();
    db.execute_unprepared(
        "UPDATE snapshot_index SET child_count = (\
            SELECT COUNT(*) FROM snapshot_index AS c \
            WHERE c.parent_digest = snapshot_index.digest)",
    )
    .await?;
    Ok(indexed)
}

/// Look up a snapshot by digest, name, or path in the local index.
pub(super) async fn get_handle(
    local: &LocalBackend,
    needle: &str,
) -> MicrosandboxResult<SnapshotHandle> {
    let db = local.db().await?.read();

    let row = if needle.starts_with("sha256:") || needle.starts_with("sha512:") {
        snapshot_entity::Entity::find_by_id(needle.to_string())
            .one(db)
            .await?
    } else if looks_like_path(needle) {
        // Path lookup: match by artifact_path.
        let canon = std::fs::canonicalize(needle)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| needle.to_string());
        snapshot_entity::Entity::find()
            .filter(snapshot_entity::Column::ArtifactPath.eq(canon))
            .one(db)
            .await?
    } else {
        snapshot_entity::Entity::find()
            .filter(snapshot_entity::Column::Name.eq(needle.to_string()))
            .one(db)
            .await?
    };

    row.map(handle_from_model)
        .ok_or_else(|| MicrosandboxError::SnapshotNotFound(needle.into()))
}

/// Look up a snapshot by digest in the local index.
pub(super) async fn lookup_by_digest(
    local: &LocalBackend,
    digest: &str,
) -> MicrosandboxResult<Option<SnapshotHandle>> {
    let db = local.db().await?.read();
    let row = snapshot_entity::Entity::find_by_id(digest.to_string())
        .one(db)
        .await?;
    Ok(row.map(handle_from_model))
}

fn handle_from_model(m: snapshot_entity::Model) -> SnapshotHandle {
    let format = match m.format.as_str() {
        "qcow2" => SnapshotFormat::Qcow2,
        _ => SnapshotFormat::Raw,
    };
    let scope = match m.scope.as_str() {
        "disk" => SnapshotScope::Disk,
        "resumable" => SnapshotScope::Resumable,
        other => {
            tracing::warn!(digest = %m.digest, scope = other, "unknown snapshot scope in index; treating as disk");
            SnapshotScope::Disk
        }
    };
    SnapshotHandle {
        digest: m.digest,
        name: m.name,
        parent_digest: m.parent_digest,
        scope,
        image_ref: m.image_ref,
        format,
        size_bytes: m.size_bytes.map(|n| n as u64),
        created_at: m.created_at,
        artifact_path: PathBuf::from(m.artifact_path),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::looks_like_path;

    #[test]
    fn bare_names_are_not_paths() {
        assert!(!looks_like_path("nightly"));
        assert!(!looks_like_path("my-snapshot_2"));
    }

    #[test]
    fn posix_anchors_and_separators_are_paths() {
        assert!(looks_like_path("/srv/snaps/foo"));
        assert!(looks_like_path("snaps/foo"));
        assert!(looks_like_path("./foo"));
        assert!(looks_like_path("~/snaps"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_forms_are_paths() {
        assert!(looks_like_path(r"C:\snaps\foo"));
        assert!(looks_like_path(r"C:foo"));
        assert!(looks_like_path(r"\\server\share\foo"));
        assert!(looks_like_path(r"snaps\foo"));
    }
}
