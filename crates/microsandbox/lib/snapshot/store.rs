//! Snapshot artifact storage operations: open, list, index upsert.

use std::path::{Path, PathBuf};

use chrono::Utc;
use microsandbox_image::snapshot::{MANIFEST_FILENAME, Manifest};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    QueryOrder,
};

use crate::db::entity::snapshot as snapshot_entity;
use crate::{MicrosandboxError, MicrosandboxResult};

use super::{Snapshot, SnapshotFormat, SnapshotHandle};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open and validate snapshot artifact metadata.
///
/// `path_or_name` is treated as a path if it contains `/` or starts
/// with `.` or `~`; otherwise as a bare name resolved under the
/// default snapshots directory.
pub(super) async fn open_snapshot(path_or_name: &str) -> MicrosandboxResult<Snapshot> {
    if path_or_name.is_empty() {
        return Err(MicrosandboxError::InvalidConfig(
            "snapshot path or name must not be empty".into(),
        ));
    }

    let dir = if looks_like_path(path_or_name) {
        PathBuf::from(path_or_name)
    } else {
        crate::config::config().snapshots_dir().join(path_or_name)
    };

    if !dir.exists() {
        return Err(MicrosandboxError::SnapshotNotFound(
            dir.display().to_string(),
        ));
    }

    let manifest_path = dir.join(MANIFEST_FILENAME);
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
    if dir.starts_with(crate::config::config().snapshots_dir())
        && let Ok(None) = lookup_by_digest(&digest).await
        && let Err(e) = index_upsert(snap.path(), snap.digest(), snap.manifest()).await
    {
        tracing::debug!(error = %e, snapshot = %digest, "auto-reindex skipped");
    }

    Ok(snap)
}

/// Insert or update an index row for the given artifact.
pub(super) async fn index_upsert(
    artifact_path: &Path,
    digest: &str,
    manifest: &Manifest,
) -> MicrosandboxResult<()> {
    let db = crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

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
    snapshot_entity::Entity::delete_by_id(digest.to_string())
        .exec(db)
        .await?;
    if let Some(name) = artifact_name.as_ref() {
        snapshot_entity::Entity::delete_many()
            .filter(snapshot_entity::Column::Name.eq(name.clone()))
            .exec(db)
            .await?;
    }
    snapshot_entity::Entity::delete_many()
        .filter(snapshot_entity::Column::ArtifactPath.eq(artifact_path_str.clone()))
        .exec(db)
        .await?;

    let format_str = match manifest.format {
        microsandbox_image::snapshot::SnapshotFormat::Raw => "raw",
        microsandbox_image::snapshot::SnapshotFormat::Qcow2 => "qcow2",
    };

    let row = snapshot_entity::ActiveModel {
        digest: Set(digest.to_string()),
        name: Set(artifact_name),
        parent_digest: Set(manifest.parent.clone()),
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

fn looks_like_path(s: &str) -> bool {
    s.contains('/') || s.starts_with('.') || s.starts_with('~')
}

pub(super) async fn list_indexed() -> MicrosandboxResult<Vec<SnapshotHandle>> {
    let db = crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;
    let rows = snapshot_entity::Entity::find()
        .order_by_desc(snapshot_entity::Column::CreatedAt)
        .all(db)
        .await?;
    Ok(rows.into_iter().map(handle_from_model).collect())
}

pub(super) async fn list_dir(dir: &Path) -> MicrosandboxResult<Vec<Snapshot>> {
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
        if !path.join(MANIFEST_FILENAME).exists() {
            continue;
        }
        match open_snapshot(path.to_string_lossy().as_ref()).await {
            Ok(s) => out.push(s),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping malformed snapshot artifact")
            }
        }
    }
    Ok(out)
}

pub(super) async fn remove_snapshot(path_or_name: &str, force: bool) -> MicrosandboxResult<()> {
    let db = crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

    // Resolve the target row. Accept digest, name, or path.
    let (digest, artifact_path) =
        if path_or_name.starts_with("sha256:") || path_or_name.starts_with("sha512:") {
            let row = snapshot_entity::Entity::find_by_id(path_or_name.to_string())
                .one(db)
                .await?
                .ok_or_else(|| MicrosandboxError::SnapshotNotFound(path_or_name.into()))?;
            (row.digest.clone(), PathBuf::from(row.artifact_path))
        } else if looks_like_path(path_or_name) {
            // Path: open to read the digest, then drop both row and dir.
            let snap = open_snapshot(path_or_name).await?;
            (snap.digest.clone(), snap.path.clone())
        } else {
            // Bare name: prefer the index lookup; fall back to default-dir resolution.
            let row = snapshot_entity::Entity::find()
                .filter(snapshot_entity::Column::Name.eq(path_or_name.to_string()))
                .one(db)
                .await?;
            if let Some(row) = row {
                (row.digest.clone(), PathBuf::from(row.artifact_path))
            } else {
                let dir = crate::config::config().snapshots_dir().join(path_or_name);
                let snap = open_snapshot(dir.to_string_lossy().as_ref()).await?;
                (snap.digest.clone(), snap.path.clone())
            }
        };

    // Check children unless --force.
    let row = snapshot_entity::Entity::find_by_id(digest.clone())
        .one(db)
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
        .exec(db)
        .await?;
    if let Some(p) = parent {
        db.execute_unprepared(&format!(
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

pub(super) async fn reindex_dir(dir: &Path) -> MicrosandboxResult<usize> {
    let snapshots = list_dir(dir).await?;
    let mut indexed = 0usize;
    for snap in &snapshots {
        if let Err(e) = index_upsert(&snap.path, &snap.digest, &snap.manifest).await {
            tracing::warn!(path = %snap.path.display(), error = %e, "reindex: upsert failed");
            continue;
        }
        indexed += 1;
    }
    // After upserts, recompute child_count from parent edges in one pass
    // to keep the cache honest about the current set of artifacts.
    let db = crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;
    db.execute_unprepared(
        "UPDATE snapshot_index SET child_count = (\
            SELECT COUNT(*) FROM snapshot_index AS c \
            WHERE c.parent_digest = snapshot_index.digest)",
    )
    .await?;
    Ok(indexed)
}

/// Look up a snapshot by digest, name, or path in the local index.
pub(super) async fn get_handle(needle: &str) -> MicrosandboxResult<SnapshotHandle> {
    let db = crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

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
pub(super) async fn lookup_by_digest(digest: &str) -> MicrosandboxResult<Option<SnapshotHandle>> {
    let db = crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;
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
    SnapshotHandle {
        digest: m.digest,
        name: m.name,
        parent_digest: m.parent_digest,
        image_ref: m.image_ref,
        format,
        size_bytes: m.size_bytes.map(|n| n as u64),
        created_at: m.created_at,
        artifact_path: PathBuf::from(m.artifact_path),
    }
}
