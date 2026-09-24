//! Local backend: Snapshot artifact storage operations: open, list, index upsert.

use std::path::{Path, PathBuf};

use chrono::Utc;
use microsandbox_image::snapshot::migration::V066_DESCRIPTOR_FILENAME;
use microsandbox_image::snapshot::{
    DEFAULT_UPPER_FILE, DESCRIPTOR_FILENAME, Manifest, SnapshotState,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    QueryOrder,
};

use crate::backend::LocalBackend;
use crate::db::entity::snapshot as snapshot_entity;
use crate::{MicrosandboxError, MicrosandboxResult};

use super::{Snapshot, SnapshotFormat, SnapshotHandle, SnapshotScope, UpperIntegrity};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open and validate snapshot artifact metadata.
///
/// Explicit paths remain valid. Bare selectors resolve a group's head; qualified selectors
/// resolve a group member. Global portable identities must identify exactly one local copy.
pub(super) async fn open_snapshot(
    local: &LocalBackend,
    path_or_name: &str,
) -> MicrosandboxResult<Snapshot> {
    if path_or_name.is_empty() {
        return Err(MicrosandboxError::InvalidConfig(
            "snapshot path or name must not be empty".into(),
        ));
    }

    let dir = resolve_path(local, path_or_name).await?;

    if !dir.exists() {
        return Err(MicrosandboxError::SnapshotNotFound(
            dir.display().to_string(),
        ));
    }

    let manifest_path = dir.join(DESCRIPTOR_FILENAME);
    if !manifest_path.exists() && dir.join(V066_DESCRIPTOR_FILENAME).exists() {
        super::migration::reconcile_explicit(local.db().await?, &dir).await?;
    }
    let bytes = tokio::fs::read(&manifest_path).await.map_err(|e| {
        MicrosandboxError::SnapshotNotFound(format!("{}: {e}", manifest_path.display()))
    })?;
    let (manifest, translated_labels, previous_upper) = match Manifest::from_bytes(&bytes) {
        Ok(manifest) => (manifest, None, None),
        Err(final_error) => {
            microsandbox_image::snapshot::migration::translate_released_flat_forward(&bytes)
                .map(|translation| {
                    let upper = dir.join(&translation.upper_file);
                    (translation.target, Some(translation.labels), Some(upper))
                })
                .map_err(|legacy_error| {
                    MicrosandboxError::SnapshotIntegrity(format!(
                        "descriptor is neither final nor a supported released flat snapshot: {final_error}; {legacy_error}"
                    ))
                })?
        }
    };
    let digest = manifest
        .digest()
        .map_err(|e| MicrosandboxError::SnapshotIntegrity(format!("{e}")))?;

    if let SnapshotState::File(file_state) = &manifest.state {
        // Metadata open proves every member of the physical closure exists. Raw images expose
        // their guest capacity as file length; qcow2 files are compact containers, so their
        // payload length is validated independently from guest-visible virtual size.
        for layer in &file_state.layers {
            let canonical_path = dir.join(file_state.layer_path(layer));
            let upper_path = if canonical_path.exists() {
                canonical_path
            } else if let Some(path) = &previous_upper {
                path.clone()
            } else if file_state.layers.len() == 1 && dir.join(DEFAULT_UPPER_FILE).exists() {
                dir.join(DEFAULT_UPPER_FILE)
            } else {
                canonical_path
            };
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
            match layer.format {
                SnapshotFormat::Raw if actual_size != layer.virtual_size => {
                    return Err(MicrosandboxError::SnapshotIntegrity(format!(
                        "raw layer size mismatch: descriptor says {}, file is {}",
                        layer.virtual_size, actual_size
                    )));
                }
                SnapshotFormat::Qcow2 if actual_size == 0 => {
                    return Err(MicrosandboxError::SnapshotIntegrity(format!(
                        "qcow2 layer is empty: {}",
                        upper_path.display()
                    )));
                }
                SnapshotFormat::Raw | SnapshotFormat::Qcow2 => {}
            }
            if let Some(UpperIntegrity::FileMerkleBlake3V1 { logical_size, .. }) =
                &layer.payload.integrity
                && *logical_size != actual_size
            {
                return Err(MicrosandboxError::SnapshotIntegrity(format!(
                    "layer payload size mismatch: integrity says {logical_size}, file is {actual_size}"
                )));
            }
        }
    }

    let labels = super::metadata::read(&dir, &manifest, translated_labels).await?;
    let mut snap = Snapshot::from_parts(dir.clone(), digest.clone(), manifest, labels);
    snap.previous_upper = previous_upper;

    // Published managed members and explicitly opened flat artifacts remain discoverable for
    // parent traversal. Archive/capture staging must never replace durable index entries.
    let snapshots_dir = local.snapshots_dir();
    let managed = dir
        .strip_prefix(&snapshots_dir)
        .ok()
        .is_some_and(|relative| {
            relative
                .components()
                .all(|part| !part.as_os_str().to_string_lossy().starts_with('.'))
        });
    if managed
        && (super::group::group_path(&dir).is_some()
            || dir.parent() == Some(snapshots_dir.as_path()))
        && let Ok(existing) = indexed_path(local, &dir).await
        && existing.as_ref().is_none_or(|row| row.digest != digest)
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

    let created_at = chrono::DateTime::parse_from_rfc3339(&manifest.capture.created_at)
        .map(|d| d.naive_utc())
        .unwrap_or_else(|_| Utc::now().naive_utc());
    let indexed_at = Utc::now().naive_utc();

    let artifact_path = canonical_path(artifact_path);
    let artifact_path_str = artifact_path.display().to_string();
    let group_path = super::group::group_path(&artifact_path);
    let group_name = group_path
        .as_ref()
        .and_then(|path| path.file_name())
        .map(|name| name.to_string_lossy().into_owned());
    let artifact_name = super::group::member_name(&artifact_path)?.or_else(|| {
        artifact_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
    });
    let group_path = group_path.map(|path| path.display().to_string());

    // Portable identities may occur in multiple groups. Replace only this local address,
    // never another copy that happens to share descriptor bytes, identity, or member name.
    let mut supersede = sea_orm::Condition::any()
        .add(snapshot_entity::Column::ArtifactPath.eq(artifact_path_str.clone()));
    if let (Some(group), Some(name)) = (&group_path, &artifact_name) {
        supersede = supersede.add(
            sea_orm::Condition::all()
                .add(snapshot_entity::Column::GroupPath.eq(group.clone()))
                .add(snapshot_entity::Column::Name.eq(name.clone())),
        );
    }

    let (state_kind, format, fstype, checkpoint_manifest_digest, size_bytes) = match &manifest.state
    {
        SnapshotState::File(state) => {
            let format = match state.disk_format {
                microsandbox_image::snapshot::SnapshotFormat::Raw => "raw",
                microsandbox_image::snapshot::SnapshotFormat::Qcow2 => "qcow2",
            };
            (
                "file",
                Some(format.to_string()),
                Some(state.filesystem.clone()),
                None,
                Some(i64::try_from(state.virtual_size).map_err(|_| {
                    MicrosandboxError::SnapshotIntegrity(
                        "snapshot size does not fit the local index".into(),
                    )
                })?),
            )
        }
        SnapshotState::Checkpoint(state) => (
            "checkpoint",
            None,
            None,
            Some(state.checkpoint_root.clone()),
            None,
        ),
    };
    let scope_str = match manifest.scope {
        SnapshotScope::Disk => "disk",
        SnapshotScope::Full => "full",
    };

    let row = snapshot_entity::ActiveModel {
        digest: Set(digest.to_string()),
        snapshot_id: Set(Some(manifest.snapshot_id.to_string())),
        descriptor_digest: Set(Some(digest.to_string())),
        name: Set(artifact_name),
        group_name: Set(group_name),
        group_path: Set(group_path),
        parent_digest: Set(manifest.parent.as_ref().map(ToString::to_string)),
        scope: Set(scope_str.into()),
        state_kind: Set(state_kind.into()),
        image_ref: Set(manifest.image.reference.clone()),
        image_manifest_digest: Set(manifest.image.manifest_digest.clone()),
        format: Set(format),
        fstype: Set(fstype),
        checkpoint_manifest_digest: Set(checkpoint_manifest_digest),
        artifact_path: Set(artifact_path_str),
        size_bytes: Set(size_bytes),
        locality: Set("embedded".into()),
        storage_binding_id: Set(None),
        availability: Set("ready".into()),
        migration_state: Set("canonical".into()),
        migration_error_code: Set(None),
        created_at: Set(created_at),
        indexed_at: Set(indexed_at),
        child_count: Set(0),
    };
    db.transaction::<_, _, _, sea_orm::DbErr>(|transaction| {
        let row = row.clone();
        let supersede = supersede.clone();
        async move {
            snapshot_entity::Entity::delete_many()
                .filter(supersede)
                .exec(&transaction)
                .await?;
            row.insert(&transaction).await?;
            recompute_children(&transaction).await?;
            Ok((transaction, ()))
        }
    })
    .await?;

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
    let mut candidates = Vec::new();
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if !entry.file_type().await?.is_dir() {
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
        if path.join(super::group::GROUP_FILENAME).is_file() {
            // Groups are exactly one level deep. Do not recursively walk arbitrary folders,
            // symlink trees, checkpoint stores, or failed staging directories.
            let mut members = tokio::fs::read_dir(&path).await?;
            while let Some(member) = members.next_entry().await? {
                if member.file_type().await?.is_dir()
                    && !member.file_name().to_string_lossy().starts_with('.')
                {
                    candidates.push(member.path());
                }
            }
        } else {
            candidates.push(path);
        }
    }
    let mut out = Vec::new();
    for path in candidates {
        if !path.join(DESCRIPTOR_FILENAME).exists() && !path.join(V066_DESCRIPTOR_FILENAME).exists()
        {
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

    // A retained handle identifies one exact installed copy, even after its directory
    // disappears. Clean only that ungrouped stale row; grouped artifacts still require
    // the group lock/head checks below, so a broken head is never silently forgotten.
    if looks_like_path(path_or_name)
        && matches!(tokio::fs::symlink_metadata(path_or_name).await, Err(ref error) if error.kind() == std::io::ErrorKind::NotFound)
        && let Some(row) = indexed_path(local, Path::new(path_or_name)).await?
        && row.group_path.is_none()
        && super::group::group_path(Path::new(path_or_name)).is_none()
    {
        if row.child_count > 0 && !force {
            return Err(MicrosandboxError::Custom(format!(
                "snapshot {} has {} indexed child snapshot(s); pass --force to remove anyway",
                row.digest, row.child_count
            )));
        }
        snapshot_entity::Entity::delete_by_id(row.artifact_path)
            .exec(write_db)
            .await?;
        recompute_children(write_db).await?;
        return Ok(());
    }

    let snapshot = open_snapshot(local, path_or_name).await?;
    let artifact_path = canonical_path(snapshot.path());
    let artifact_key = artifact_path.display().to_string();

    // Check children unless --force.
    let row = snapshot_entity::Entity::find_by_id(artifact_key.clone())
        .one(read_db)
        .await?;
    if let Some(ref row) = row
        && row.child_count > 0
        && !force
    {
        return Err(MicrosandboxError::Custom(format!(
            "snapshot {} has {} indexed child snapshot(s); pass --force to remove anyway",
            snapshot.id(),
            row.child_count
        )));
    }

    // The group helper validates head removal and removes the member under its publication
    // lock. Even --force must not leave a group's head dangling while other members remain.
    if !super::group::remove_member(&artifact_path).await? && artifact_path.exists() {
        tokio::fs::remove_dir_all(&artifact_path).await?;
    }
    snapshot_entity::Entity::delete_by_id(artifact_key)
        .exec(write_db)
        .await?;
    recompute_children(write_db).await?;
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
    recompute_children(db).await?;
    Ok(indexed)
}

/// Resolve a local address and refresh its rebuildable index row before returning a handle.
pub(super) async fn get_handle(
    local: &LocalBackend,
    needle: &str,
) -> MicrosandboxResult<SnapshotHandle> {
    let snapshot = open_snapshot(local, needle).await?;
    let artifact_path = canonical_path(snapshot.path());
    let alias = super::group::member_name(&artifact_path)?.or_else(|| {
        artifact_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
    });
    if let Some(row) = indexed_path(local, &artifact_path).await?
        && row.digest == snapshot.digest()
        && row.name == alias
        && row.group_path
            == super::group::group_path(&artifact_path).map(|path| path.display().to_string())
    {
        return Ok(handle_from_model(row));
    }
    index_upsert(
        local,
        snapshot.path(),
        snapshot.digest(),
        snapshot.manifest(),
    )
    .await?;
    let row =
        snapshot_entity::Entity::find_by_id(canonical_path(snapshot.path()).display().to_string())
            .one(local.db().await?.read())
            .await?;
    row.map(handle_from_model)
        .ok_or_else(|| MicrosandboxError::SnapshotNotFound(needle.into()))
}

/// Look up a snapshot by digest in the local index.
pub(super) async fn lookup_by_digest(
    local: &LocalBackend,
    digest: &str,
) -> MicrosandboxResult<Option<SnapshotHandle>> {
    let db = local.db().await?.read();
    let rows = snapshot_entity::Entity::find()
        .filter(
            sea_orm::Condition::any()
                .add(snapshot_entity::Column::Digest.eq(digest.to_string()))
                .add(snapshot_entity::Column::SnapshotId.eq(digest.to_string())),
        )
        .all(db)
        .await?;
    unique_identity_match(rows, digest).map(|row| row.map(handle_from_model))
}

async fn resolve_path(local: &LocalBackend, selector: &str) -> MicrosandboxResult<PathBuf> {
    if looks_like_path(selector) {
        return Ok(PathBuf::from(selector));
    }
    if microsandbox_image::snapshot::SnapshotId::new(selector).is_ok()
        || selector.starts_with("sha256:")
        || selector.starts_with("sha512:")
    {
        return lookup_by_digest(local, selector)
            .await?
            .map(|handle| handle.artifact_path)
            .ok_or_else(|| MicrosandboxError::SnapshotNotFound(selector.into()));
    }
    if !selector.contains(':') {
        let flat = local.snapshots_dir().join(selector);
        if flat.join(DESCRIPTOR_FILENAME).is_file() || flat.join(V066_DESCRIPTOR_FILENAME).is_file()
        {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "'{selector}' is an ungrouped snapshot; bare names now select group heads, so open this artifact by its explicit path: {}",
                flat.display()
            )));
        }
    }
    super::group::resolve(&local.snapshots_dir(), selector).await
}

fn canonical_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

async fn indexed_path(
    local: &LocalBackend,
    path: &Path,
) -> MicrosandboxResult<Option<snapshot_entity::Model>> {
    Ok(
        snapshot_entity::Entity::find_by_id(canonical_path(path).display().to_string())
            .one(local.db().await?.read())
            .await?,
    )
}

fn unique_identity_match(
    mut rows: Vec<snapshot_entity::Model>,
    identity: &str,
) -> MicrosandboxResult<Option<snapshot_entity::Model>> {
    if rows.len() > 1 {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "snapshot identity {identity} has {} local copies; use group:member or an explicit artifact path",
            rows.len()
        )));
    }
    Ok(rows.pop())
}

async fn recompute_children<C: ConnectionTrait>(db: &C) -> Result<(), sea_orm::DbErr> {
    // Repeated imports are instances, not additional lineage edges. Apply the same number of
    // distinct child identities to every local copy of a parent.
    db.execute_unprepared(
        "UPDATE snapshot_index SET child_count = (SELECT COUNT(DISTINCT COALESCE(c.snapshot_id, c.digest)) FROM snapshot_index c WHERE c.parent_digest = snapshot_index.snapshot_id)",
    ).await?;
    Ok(())
}

fn handle_from_model(m: snapshot_entity::Model) -> SnapshotHandle {
    let format = m.format.as_deref().map(|format| match format {
        "qcow2" => SnapshotFormat::Qcow2,
        _ => SnapshotFormat::Raw,
    });
    let scope = match m.scope.as_str() {
        "disk" => SnapshotScope::Disk,
        // `resumable` was the released index projection. The artifact is authoritative and the
        // index is rebuildable, but accepting the old cache value keeps upgrades non-disruptive.
        "full" | "resumable" => SnapshotScope::Full,
        other => {
            tracing::warn!(digest = %m.digest, scope = other, "unknown snapshot scope in index; treating as disk");
            SnapshotScope::Disk
        }
    };
    SnapshotHandle {
        snapshot_id: m.snapshot_id.unwrap_or_else(|| m.digest.clone()),
        digest: m.digest,
        name: m.name,
        group: m.group_name,
        head_update: None,
        parent_digest: m.parent_digest,
        scope,
        image_ref: m.image_ref,
        state_kind: m.state_kind,
        format,
        fstype: m.fstype,
        checkpoint_manifest_digest: m.checkpoint_manifest_digest,
        size_bytes: m.size_bytes.map(|n| n as u64),
        locality: m.locality,
        availability: m.availability,
        migration_state: m.migration_state,
        migration_error_code: m.migration_error_code,
        created_at: m.created_at,
        artifact_path: PathBuf::from(m.artifact_path),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use microsandbox_image::snapshot::{
        CheckpointSnapshotState, ImageRef, SCHEMA, SnapshotCapture, SnapshotConsistency,
        SnapshotId, SnapshotRootDisk,
    };

    use super::*;

    fn manifest(id: u128, parent: Option<&Manifest>) -> Manifest {
        Manifest {
            schema: SCHEMA.into(),
            snapshot_id: SnapshotId::new(format!("snap_{id:032x}")).unwrap(),
            scope: SnapshotScope::Full,
            // These tests exercise addressing and indexing, not checkpoint restoration.
            state: SnapshotState::Checkpoint(CheckpointSnapshotState {
                checkpoint_id: "checkpoint_test".into(),
                checkpoint_root: format!("sha256:{}", "a".repeat(64)),
                restore_intents: vec!["resume".into()],
                requirements_summary: BTreeMap::new(),
            }),
            capture: SnapshotCapture {
                created_at: "2026-09-10T00:00:00Z".into(),
                source_lineage: None,
                source_checkpoint: None,
                consistency: SnapshotConsistency::CrashConsistent,
            },
            image: ImageRef {
                reference: "docker.io/library/alpine:3.20".into(),
                manifest_digest: format!("sha256:{}", "b".repeat(64)),
            },
            root_disk: SnapshotRootDisk::Managed,
            parent: parent.map(|parent| parent.snapshot_id.clone()),
            extensions: BTreeMap::new(),
            requires: Vec::new(),
        }
    }

    async fn install(
        local: &LocalBackend,
        group: &str,
        name: &str,
        manifest: &Manifest,
    ) -> PathBuf {
        let directory = super::super::group::ensure(&local.snapshots_dir(), Some(group))
            .await
            .unwrap();
        let stage = tempfile::tempdir().unwrap();
        let artifact = stage.path().join("member");
        std::fs::create_dir(&artifact).unwrap();
        std::fs::write(
            artifact.join(DESCRIPTOR_FILENAME),
            manifest.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        super::super::group::publish(
            &directory,
            stage.path(),
            &BTreeMap::from([(manifest.snapshot_id.to_string(), name.into())]),
            &manifest.snapshot_id,
            false,
        )
        .await
        .unwrap();
        directory.join(manifest.snapshot_id.as_str())
    }

    #[tokio::test]
    async fn duplicate_identities_keep_group_addresses_and_remove_only_selected_copy() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let snapshot = manifest(1, None);
        let first = install(&local, "first", "baseline", &snapshot).await;
        let second = install(&local, "second", "baseline", &snapshot).await;
        assert_eq!(
            reindex_dir(&local, &local.snapshots_dir()).await.unwrap(),
            2
        );
        let first_handle = get_handle(&local, "first:baseline").await.unwrap();
        let second_handle = get_handle(&local, "second").await.unwrap();
        assert_eq!(first_handle.digest(), second_handle.digest());
        assert_eq!(first_handle.group(), Some("first"));
        assert_eq!(second_handle.group(), Some("second"));
        assert!(
            get_handle(&local, snapshot.snapshot_id.as_str())
                .await
                .unwrap_err()
                .to_string()
                .contains("local copies")
        );
        assert!(
            get_handle(&local, first_handle.digest())
                .await
                .unwrap_err()
                .to_string()
                .contains("local copies")
        );
        remove_snapshot(&local, "first:baseline", false)
            .await
            .unwrap();
        assert!(!first.exists());
        assert!(second.exists());
        assert_eq!(list_indexed(&local).await.unwrap().len(), 1);
        assert_eq!(
            get_handle(&local, "second").await.unwrap().digest(),
            snapshot.digest().unwrap()
        );
    }

    #[tokio::test]
    async fn distinct_child_counts_and_head_guard_survive_reindex() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let parent = manifest(1, None);
        let child = manifest(2, Some(&parent));
        for group in ["first", "second"] {
            install(&local, group, "base", &parent).await;
            install(&local, group, "child", &child).await;
        }
        reindex_dir(&local, &local.snapshots_dir()).await.unwrap();
        reindex_dir(&local, &local.snapshots_dir()).await.unwrap();
        let rows = snapshot_entity::Entity::find()
            .filter(snapshot_entity::Column::SnapshotId.eq(parent.snapshot_id.as_str()))
            .all(local.db().await.unwrap().read())
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.child_count == 1));
        assert!(
            remove_snapshot(&local, "first:child", true)
                .await
                .unwrap_err()
                .to_string()
                .contains("current head")
        );
        assert_eq!(
            get_handle(&local, "first").await.unwrap().id(),
            child.snapshot_id.as_str()
        );
    }

    #[tokio::test]
    async fn flat_artifact_requires_explicit_path() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let artifact = local.snapshots_dir().join("flat");
        std::fs::create_dir_all(&artifact).unwrap();
        let snapshot = manifest(1, None);
        std::fs::write(
            artifact.join(DESCRIPTOR_FILENAME),
            snapshot.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        assert!(open_snapshot(&local, "flat").await.is_err());
        assert_eq!(
            open_snapshot(&local, artifact.to_str().unwrap())
                .await
                .unwrap()
                .id(),
            &snapshot.snapshot_id
        );
    }

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
