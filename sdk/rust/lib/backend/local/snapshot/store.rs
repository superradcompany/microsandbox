//! Local backend: Snapshot artifact storage operations: open, list, index upsert.

use std::path::{Path, PathBuf};

use chrono::Utc;
use microsandbox_image::snapshot::migration::V066_DESCRIPTOR_FILENAME;
use microsandbox_image::snapshot::{
    DEFAULT_UPPER_FILE, DESCRIPTOR_FILENAME, Manifest, SnapshotState,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait,
    QueryFilter, QueryOrder, Statement,
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
    let mut snapshot = open_snapshot_leased(local, path_or_name).await?;
    // Metadata handles do not represent active reads. Operation entry points explicitly
    // retain the lease while using payload paths; listing/inspection releases it here.
    snapshot.lease = None;
    Ok(snapshot)
}

pub(super) async fn open_snapshot_leased(
    local: &LocalBackend,
    path_or_name: &str,
) -> MicrosandboxResult<Snapshot> {
    open_snapshot_impl(local, path_or_name, true, true).await
}

/// Verification retains payload leases but must not repair the discovery index as a side effect.
pub(super) async fn open_for_verification(
    local: &LocalBackend,
    path: &Path,
) -> MicrosandboxResult<Snapshot> {
    open_snapshot_impl(local, &path.to_string_lossy(), true, false).await
}

async fn open_snapshot_impl(
    local: &LocalBackend,
    path_or_name: &str,
    reader: bool,
    index: bool,
) -> MicrosandboxResult<Snapshot> {
    if path_or_name.is_empty() {
        return Err(MicrosandboxError::InvalidConfig(
            "snapshot path or name must not be empty".into(),
        ));
    }

    let dir = resolve_path(local, path_or_name).await?;
    super::group::recover_member(&dir).await?;
    let mut lease = if reader {
        Some(
            super::lease::reader_async(canonical_path(&dir))
                .await
                .map_err(|error| {
                    if error.kind() == std::io::ErrorKind::NotFound {
                        MicrosandboxError::SnapshotNotFound(format!("{}: {error}", dir.display()))
                    } else {
                        error.into()
                    }
                })?,
        )
    } else {
        None
    };

    if !dir.exists() {
        return Err(MicrosandboxError::SnapshotNotFound(
            dir.display().to_string(),
        ));
    }

    let manifest_path = dir.join(DESCRIPTOR_FILENAME);
    if !manifest_path.exists() && dir.join(V066_DESCRIPTOR_FILENAME).exists() {
        if !index {
            // Verification owns stable writer admission while selecting readers. It must not
            // start a catalog/descriptor migration inside that read operation.
            return Err(MicrosandboxError::Unsupported {
                op: crate::Operation::SnapshotOps,
                reason: crate::error::UnsupportedReason::NotAvailable(
                    "legacy manifest.json requires explicit migration before group verification"
                        .into(),
                ),
            });
        }
        // Migration changes the descriptor inode. Keep the namespace admitted until
        // the reader has transferred protection to the newly published descriptor.
        let _namespace = microsandbox_image::storage_lease::StorageLease::shared(&dir)?;
        super::migration::reconcile_explicit(local.db().await?, &dir).await?;
        if reader {
            lease = Some(super::lease::reader_async(canonical_path(&dir)).await?);
        }
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
    snap.lease = lease;
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
    if reader
        && index
        && managed
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
    // Lock and reread first. Metadata captured by list/reindex may describe an artifact
    // removed or replaced while waiting for image admission.
    let _artifact_lease = super::lease::reader_async(canonical_path(artifact_path)).await?;
    let bytes = tokio::fs::read(artifact_path.join(DESCRIPTOR_FILENAME)).await?;
    let current = Manifest::from_bytes(&bytes)
        .or_else(|_| {
            microsandbox_image::snapshot::migration::translate_released_flat_forward(&bytes)
                .map(|translation| translation.target)
        })
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    if current
        .digest()
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?
        != digest
    {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "snapshot changed before indexing".into(),
        ));
    }
    let cache = microsandbox_image::GlobalCache::new(&local.cache_dir())?;
    let digest_id: microsandbox_image::Digest = manifest.image.manifest_digest.parse()?;
    let _image_lease = cache
        .lease_paths_async(vec![cache.fsmeta_erofs_path(&digest_id)])
        .await?;
    index_write(
        local.db().await?.write(),
        artifact_path,
        digest,
        manifest,
        "ready",
        None,
    )
    .await
}

/// Existing snapshot rows are also durable image roots. Pending publication uses the same
/// ownership relation as ready snapshots; no new schema or archive field is required.
pub(super) async fn index_write(
    db: &microsandbox_db::DbWriteConnection,
    artifact_path: &Path,
    digest: &str,
    manifest: &Manifest,
    availability: &str,
    name: Option<String>,
) -> MicrosandboxResult<()> {
    write_index_rows(
        db,
        vec![index_row(
            artifact_path,
            digest,
            manifest,
            availability,
            name,
        )?],
        Vec::new(),
    )
    .await
}

/// Publish ready index rows in one SQLite transaction; a batch must never appear a row at a time.
pub(super) async fn index_write_batch(
    db: &microsandbox_db::DbWriteConnection,
    snapshots: &[(PathBuf, String, Manifest)],
) -> MicrosandboxResult<()> {
    let rows = snapshots
        .iter()
        .map(|(path, digest, manifest)| index_row(path, digest, manifest, "ready", None))
        .collect::<MicrosandboxResult<Vec<_>>>()?;
    write_index_rows(db, rows, Vec::new()).await
}

/// Resolve all reservations from one recovered batch in the same index commit. Absent
/// payloads are rolled-back reservations, not members to expose and remove in a second pass.
pub(super) async fn index_recover_batch(
    db: &microsandbox_db::DbWriteConnection,
    snapshots: &[(PathBuf, String, Manifest)],
    absent: Vec<String>,
) -> MicrosandboxResult<()> {
    let rows = snapshots
        .iter()
        .map(|(path, digest, manifest)| index_row(path, digest, manifest, "ready", None))
        .collect::<MicrosandboxResult<Vec<_>>>()?;
    write_index_rows(db, rows, absent).await
}

async fn write_index_rows(
    db: &microsandbox_db::DbWriteConnection,
    rows: Vec<(snapshot_entity::ActiveModel, sea_orm::Condition)>,
    absent: Vec<String>,
) -> MicrosandboxResult<()> {
    db.transaction::<_, _, _, sea_orm::DbErr>(|transaction| {
        let rows = rows.clone();
        let absent = absent.clone();
        async move {
            if !absent.is_empty() {
                snapshot_entity::Entity::delete_many()
                    .filter(snapshot_entity::Column::ArtifactPath.is_in(absent))
                    .filter(snapshot_entity::Column::Availability.eq("publishing"))
                    .exec(&transaction)
                    .await?;
            }
            for (row, supersede) in rows {
                snapshot_entity::Entity::delete_many()
                    .filter(supersede)
                    .exec(&transaction)
                    .await?;
                row.insert(&transaction).await?;
            }
            recompute_children(&transaction).await?;
            Ok((transaction, ()))
        }
    })
    .await?;
    Ok(())
}

fn index_row(
    artifact_path: &Path,
    digest: &str,
    manifest: &Manifest,
    availability: &str,
    name: Option<String>,
) -> MicrosandboxResult<(snapshot_entity::ActiveModel, sea_orm::Condition)> {
    let created_at = chrono::DateTime::parse_from_rfc3339(&manifest.capture.created_at)
        .map(|d| d.naive_utc())
        .unwrap_or_else(|_| Utc::now().naive_utc());
    let indexed_at = Utc::now().naive_utc();

    let requested_path = artifact_path.display().to_string();
    let artifact_path = canonical_path(artifact_path);
    let artifact_path_str = artifact_path.display().to_string();
    let group_path = super::group::group_path(&artifact_path);
    let group_name = group_path
        .as_ref()
        .and_then(|path| path.file_name())
        .map(|name| name.to_string_lossy().into_owned());
    let artifact_name = name
        .or(super::group::member_name(&artifact_path)?)
        .or_else(|| {
            artifact_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        });
    let group_path = group_path.map(|path| path.display().to_string());

    // Portable identities may occur in multiple groups. Replace only this local address,
    // never another copy that happens to share descriptor bytes, identity, or member name.
    let mut supersede = sea_orm::Condition::any()
        .add(snapshot_entity::Column::ArtifactPath.eq(artifact_path_str.clone()))
        // Recovery can arrive through an older noncanonical reservation. Replace that
        // exact address in the same transaction as its canonical row, never by digest.
        .add(snapshot_entity::Column::ArtifactPath.eq(requested_path));
    if let (Some(group), Some(name)) = (&group_path, &artifact_name)
        && availability == "ready"
    {
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
        availability: Set(availability.into()),
        migration_state: Set("canonical".into()),
        migration_error_code: Set(None),
        created_at: Set(created_at),
        indexed_at: Set(indexed_at),
        child_count: Set(0),
    };
    Ok((row, supersede))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Heuristic split between a bare snapshot name and a filesystem path.
pub(crate) fn looks_like_path(s: &str) -> bool {
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
    super::publication::recover(local).await?;
    let mut parents = snapshot_entity::Entity::find()
        .all(local.db().await?.read())
        .await?
        .into_iter()
        .filter_map(|row| {
            PathBuf::from(row.artifact_path)
                .parent()
                .map(Path::to_path_buf)
        })
        .collect::<std::collections::BTreeSet<_>>();
    parents.extend(super::deletion::recovery_parents(local)?);
    for parent in parents {
        super::deletion::recover_parent(local, &parent).await?;
    }

    let db = local.db().await?.read();
    let rows = snapshot_entity::Entity::find()
        .filter(snapshot_entity::Column::Availability.ne("publishing"))
        .order_by_desc(snapshot_entity::Column::CreatedAt)
        .all(db)
        .await?;
    Ok(rows.into_iter().map(handle_from_model).collect())
}

pub(super) async fn list_dir(
    local: &LocalBackend,
    dir: &Path,
) -> MicrosandboxResult<Vec<Snapshot>> {
    // Directory entries and retained snapshots must keep the same host base across awaits.
    let dir = std::path::absolute(dir)?;
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut candidates = Vec::new();
    let mut entries = tokio::fs::read_dir(&dir).await?;
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
            candidates.extend(super::group::member_paths(&path).await?);
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
    remove_snapshot_expected(local, path_or_name, force, None).await
}

pub(crate) async fn remove_snapshot_expected(
    local: &LocalBackend,
    path_or_name: &str,
    force: bool,
    expected: Option<&str>,
) -> MicrosandboxResult<()> {
    remove_snapshot_report(local, path_or_name, force, expected)
        .await
        .map(|_| ())
}

pub(super) async fn remove_snapshot_report(
    local: &LocalBackend,
    path_or_name: &str,
    force: bool,
    expected: Option<&str>,
) -> MicrosandboxResult<Option<crate::snapshot::CheckpointRemoveResult>> {
    let path = canonical_path(&resolve_path(local, path_or_name).await?);
    super::group::recover_member(&path).await?;
    // Initialize/reconcile before taking the deletion lock: migration itself pins the
    // namespace, so starting it while holding that namespace exclusively would deadlock.
    let pools = local.db().await?;
    if let Some(group) = super::group::group_path(&path) {
        super::publication::complete_batch(pools.write(), &group).await?;
    }
    if !path.join(DESCRIPTOR_FILENAME).exists() && path.join(V066_DESCRIPTOR_FILENAME).exists() {
        super::migration::reconcile_explicit(pools, &path).await?;
    }
    // A vanished external parent cannot host an entry lease. Serialize stale-row removal
    // with catalog publication instead; no live artifact is deleted on this path.
    if looks_like_path(path_or_name)
        && let Some(parent) = path.parent()
        && matches!(tokio::fs::symlink_metadata(parent).await, Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        if remove_missing_snapshot(local, &path, force, expected).await? {
            return Ok(None);
        }

        return Err(MicrosandboxError::SnapshotNotFound(
            path.display().to_string(),
        ));
    }

    if let Some(parent) = path.parent() {
        super::deletion::register_parent(local, parent)?;
        super::deletion::recover_parent(local, parent).await?;
    }
    let _deletion = super::lease::deletion(&path)?.ok_or_else(|| {
        MicrosandboxError::Custom(format!(
            "snapshot is in use by an active operation: {}",
            path.display()
        ))
    })?;
    let read_db = pools.read();
    let write_db = pools.write();

    // A retained handle identifies one exact installed copy, even after its directory
    // disappears. A surviving group still requires its lock/head checks below, so a
    // broken head is never silently forgotten.
    if looks_like_path(path_or_name)
        && remove_missing_snapshot(local, &path, force, expected).await?
    {
        return Ok(None);
    }

    let snapshot = open_snapshot_impl(local, path.to_string_lossy().as_ref(), false, true).await?;
    if expected.is_some_and(|expected| expected != snapshot.digest()) {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "snapshot handle refers to a replaced artifact".into(),
        ));
    }
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

    // Group publication pairs member retirement with its recorded-parent head fallback.
    // The result is captured under ownership; never reread a head another writer can change.
    let removal = super::group::remove_member_leased(&artifact_path, _deletion.clone()).await?;
    if let Some(removal) = &removal {
        tracing::debug!(head_update = ?removal.head_update, "checkpoint removed");
        for warning in &removal.warnings {
            tracing::warn!(%warning);
        }
    }
    if removal.is_none() && artifact_path.exists() {
        let path = artifact_path.clone();
        let lease = _deletion.clone();
        tokio::task::spawn_blocking(move || {
            let _lease = lease;
            super::deletion::quarantine(&path)
        })
        .await
        .map_err(|error| MicrosandboxError::Custom(format!("snapshot removal task: {error}")))??;
    }
    let report = crate::snapshot::CheckpointRemoveResult {
        id: snapshot.id().clone(),
        head_update: removal.as_ref().map(|removal| removal.head_update.clone()),
        warnings: removal.map(|removal| removal.warnings).unwrap_or_default(),
    };
    // Publication already committed. A later database/cleanup failure must retain
    // the removal's identity and head outcome rather than imply nothing happened.
    let cleanup: MicrosandboxResult<()> = async {
        snapshot_entity::Entity::delete_by_id(artifact_key)
            .exec(write_db)
            .await?;
        recompute_children(write_db).await?;
        drop(_deletion);
        if let Some(parent) = artifact_path.parent() {
            super::deletion::recover_parent(local, parent).await?;
        }
        Ok(())
    }
    .await;
    if let Err(source) = cleanup {
        return Err(MicrosandboxError::SnapshotRemovalRecovery {
            result: Box::new(report),
            source: Box::new(source),
        });
    }
    Ok(Some(report))
}

/// Forget an absent artifact only if no surviving group needs its head/membership checks.
async fn remove_missing_snapshot(
    local: &LocalBackend,
    path: &Path,
    force: bool,
    expected: Option<&str>,
) -> MicrosandboxResult<bool> {
    let path = path.to_path_buf();
    let expected = expected.map(str::to_owned);

    local.db().await?.write().transaction(|txn| {
        let path = path.clone();
        let expected = expected.clone();

        async move {
            let row = snapshot_entity::Entity::find_by_id(path.display().to_string())
                .one(&txn)
                .await?;
            let Some(row) = row else {
                return Ok((txn, false));
            };
            // Publishers record ownership before installing files. An absent source is
            // not stale while that handoff is pending, including a recreated parent.
            if row.availability == "publishing" {
                return Ok((txn, false));
            }
            if let Some(group) = &row.group_path {
                match tokio::fs::symlink_metadata(group).await {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                    Ok(_) => return Ok((txn, false)),
                }
            }
            if let Some(parent) = path.parent() {
                match tokio::fs::symlink_metadata(parent.join(super::group::GROUP_FILENAME)).await {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                    Ok(_) => return Ok((txn, false)),
                }
            }
            match tokio::fs::symlink_metadata(&path).await {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Ok((txn, false)),
            }
            if expected.as_ref().is_some_and(|expected| expected != &row.digest) {
                return Err(MicrosandboxError::SnapshotIntegrity(
                    "snapshot handle refers to a replaced artifact".into(),
                ));
            }
            if row.child_count > 0 && !force {
                return Err(MicrosandboxError::Custom(format!(
                    "snapshot {} has {} indexed child snapshot(s); pass --force to remove anyway",
                    row.digest, row.child_count
                )));
            }

            snapshot_entity::Entity::delete_by_id(row.artifact_path).exec(&txn).await?;
            if let Some(parent) = row.parent_digest {
                // Only this parent edge changed; preserve distinct-child counting across
                // all its local copies without rewriting unrelated catalog rows.
                txn.execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "UPDATE snapshot_index SET child_count = \
                    (SELECT COUNT(DISTINCT COALESCE(c.snapshot_id, c.digest)) \
                    FROM snapshot_index c WHERE c.parent_digest = snapshot_index.snapshot_id) \
                    WHERE snapshot_id = ?",
                    [parent.into()],
                )).await?;
            }
            Ok((txn, true))
        }
    }).await
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
        return Ok(std::path::absolute(selector)?);
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

pub(super) fn canonical_path(path: &Path) -> PathBuf {
    // Retirement removes the entry before catalog cleanup. Preserve its address by
    // resolving the surviving parent, even when a caller reached it through a symlink
    // (including macOS /var -> /private/var). Otherwise recovery misses the original row.
    std::fs::canonicalize(path)
        .or_else(|_| microsandbox_image::storage_lease::StorageLease::key(path))
        .unwrap_or_else(|_| path.to_path_buf())
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

pub(super) async fn recompute_children<C: ConnectionTrait>(db: &C) -> Result<(), sea_orm::DbErr> {
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

    use microsandbox_image::{
        snapshot::{
            CheckpointSnapshotState, ImageRef, SCHEMA, SnapshotCapture, SnapshotConsistency,
            SnapshotId, SnapshotRootDisk,
        },
        storage_lease::StorageLease,
    };

    use super::*;

    /// Parallel subprocess tests can inherit a lookup descriptor until exec. Busy is
    /// a valid pre-publication result then; never retry a committed or unrelated error.
    async fn after_reader_release<T, F, Fut>(mut operation: F) -> MicrosandboxResult<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = MicrosandboxResult<T>>,
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match operation().await {
                Err(MicrosandboxError::Custom(message))
                    if message.contains("snapshot is in use by an active operation") =>
                {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "reader protection never released: {message}"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                result => return result,
            }
        }
    }

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

    #[test]
    fn snapshot_paths_stay_bound_after_open_and_list() {
        const CHILD: &str = "MSB_TEST_SNAPSHOT_PATH_CWD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("backend::local::snapshot::store::tests::snapshot_paths_stay_bound_after_open_and_list")
                .arg("--nocapture")
                .env(CHILD, "1")
                .output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("snapshot path lifetime checked")
            );
            return;
        }
        let original_cwd = std::env::current_dir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let first = root.path().canonicalize().unwrap().join("first");
        let second = root.path().canonicalize().unwrap().join("second");
        for (base, id) in [(&first, 901), (&second, 902)] {
            let directory = base.join("artifacts/saved");
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(
                directory.join(DESCRIPTOR_FILENAME),
                manifest(id, None).to_canonical_bytes().unwrap(),
            )
            .unwrap();
        }
        unsafe {
            std::env::set_var("MSB_CONFIG_PATH", root.path().join("missing-config.json"));
        }
        std::env::set_current_dir(&first).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                use crate::backend::SnapshotBackend;
                use crate::snapshot::SnapshotReference;
                let local = std::sync::Arc::new(
                    LocalBackend::builder()
                        .home(root.path().join("home"))
                        .build_lazy()
                        .unwrap(),
                );
                let snapshot = SnapshotBackend::open(
                    local.as_ref(),
                    local.clone(),
                    SnapshotReference::Auto("./artifacts/saved".into()),
                )
                .await
                .unwrap();
                let listed = SnapshotBackend::list_dir(
                    local.as_ref(),
                    local.clone(),
                    PathBuf::from("./artifacts"),
                )
                .await
                .unwrap();
                assert_eq!(listed.len(), 1);
                std::env::set_current_dir(&second).unwrap();
                for retained in [&snapshot, &listed[0]] {
                    assert_eq!(retained.path().unwrap(), first.join("artifacts/saved"));
                    let reopened = SnapshotBackend::open(
                        local.as_ref(),
                        local.clone(),
                        retained.reference.clone(),
                    )
                    .await
                    .unwrap();
                    assert_eq!(reopened.id(), &manifest(901, None).snapshot_id);
                }
                SnapshotBackend::remove(
                    local.as_ref(),
                    local.clone(),
                    snapshot.reference.clone(),
                    false,
                )
                .await
                .unwrap();
                assert!(!first.join("artifacts/saved").exists());
                assert!(second.join("artifacts/saved").exists());
            });
        std::env::set_current_dir(original_cwd).unwrap();
        println!("snapshot path lifetime checked");
    }

    #[tokio::test]
    async fn whole_group_removal_refuses_external_dependents_and_readers() {
        let home = tempfile::tempdir().unwrap();
        let local = std::sync::Arc::new(
            crate::test_support::local_backend_builder(home.path())
                .build()
                .await
                .unwrap(),
        );
        let parent = manifest(940, None);
        let child = manifest(941, Some(&parent));
        let dependent = manifest(942, Some(&parent));
        install(&local, "history", "parent", &parent).await;
        let child_path = install(&local, "history", "child", &child).await;
        install(&local, "external", "dependent", &dependent).await;
        // Explicitly index fixtures as real capture/import does before returning.
        reindex_dir(&local, &local.snapshots_dir()).await.unwrap();
        let backend: std::sync::Arc<dyn crate::backend::Backend> = local.clone();
        crate::with_backend(backend, async {
            let group = crate::Snapshot::get("history").await.unwrap();
            assert!(
                group
                    .remove()
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("surviving checkpoint")
            );
            let other = crate::Snapshot::get("external").await.unwrap();
            other.head().await.unwrap().unwrap().remove().await.unwrap();
            let reader = super::super::lease::reader(&child_path).unwrap();
            assert!(
                group
                    .remove()
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("active reader")
            );
            drop(reader);
            let gate = StorageLease::shared(&local.snapshots_dir().join("history")).unwrap();
            assert!(
                group
                    .remove()
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("verification")
            );
            drop(gate);
            let report = group.remove().await.unwrap();
            assert_eq!(
                report.removed,
                vec![parent.snapshot_id.clone(), child.snapshot_id.clone()]
            );
            assert_eq!(
                report.head_update.previous.as_deref(),
                Some(child.snapshot_id.as_str())
            );
            assert!(report.head_update.head.is_none());
            assert!(!local.snapshots_dir().join("history").exists());
            assert!(list_indexed(&local).await.unwrap().is_empty());
            assert!(other.remove().await.unwrap().removed.is_empty());
        })
        .await;
    }

    #[test]
    fn whole_group_recovery_preserves_a_recreated_group() {
        // Recovery must reach the injected SQL failure immediately. Unrelated parallel
        // fork/exec tests can temporarily inherit setup's reader leases and correctly
        // cause pre-publication refusal instead. Create the fixture after exec in an
        // isolated process; do not retry removal or weaken its committed-result checks.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend::local::snapshot::store::tests::whole_group_recovery_worker",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }

    #[tokio::test]
    #[ignore = "subprocess helper for the committed group-recovery contract"]
    async fn whole_group_recovery_worker() {
        let home = tempfile::tempdir().unwrap();
        let local = std::sync::Arc::new(
            crate::test_support::local_backend_builder(home.path())
                .build()
                .await
                .unwrap(),
        );
        let original = manifest(943, None);
        install(&local, "history", "original", &original).await;
        reindex_dir(&local, &local.snapshots_dir()).await.unwrap();
        let backend: std::sync::Arc<dyn crate::backend::Backend> = local.clone();
        crate::with_backend(backend, async {
            let group = crate::Snapshot::get("history").await.unwrap();
            let db = local.db().await.unwrap();
            db.write().execute_raw(sea_orm::Statement::from_string(sea_orm::DatabaseBackend::Sqlite,
                "CREATE TRIGGER reject_group_cleanup BEFORE DELETE ON snapshot_index BEGIN SELECT RAISE(FAIL, 'injected group cleanup failure'); END".to_string())).await.unwrap();
            let error = group.remove().await.unwrap_err();
            let MicrosandboxError::SnapshotGroupRemovalRecovery { result, .. } = error else { panic!("lost committed group result: {error}"); };
            assert_eq!(result.removed, vec![original.snapshot_id]);
            assert!(!local.snapshots_dir().join("history").exists());
            db.write().execute_raw(sea_orm::Statement::from_string(sea_orm::DatabaseBackend::Sqlite, "DROP TRIGGER reject_group_cleanup".to_string())).await.unwrap();
            let replacement = manifest(944, None);
            let replacement_path = install(&local, "history", "replacement", &replacement).await;
            open_snapshot(&local, replacement_path.to_str().unwrap()).await.unwrap();
            let groups = crate::Snapshot::list().await.unwrap();
            assert_eq!(groups.len(), 1);
            assert_eq!(groups[0].name(), "history");
            let rows = list_indexed(&local).await.unwrap();
            assert_eq!(rows.len(), 1);
            assert!(replacement_path.join(DESCRIPTOR_FILENAME).exists());
            assert_eq!(crate::Snapshot::get("history").await.unwrap().head().await.unwrap().unwrap().id(), &replacement.snapshot_id);
        }).await;
    }

    #[tokio::test]
    async fn checkpoint_removal_returns_its_own_head_outcome() {
        let home = tempfile::tempdir().unwrap();
        let local = std::sync::Arc::new(
            crate::test_support::local_backend_builder(home.path())
                .build()
                .await
                .unwrap(),
        );
        let parent = manifest(930, None);
        let child = manifest(931, Some(&parent));
        let sibling = manifest(932, Some(&parent));
        install(&local, "history", "base", &parent).await;
        install(&local, "history", "child", &child).await;
        install(&local, "history", "sibling", &sibling).await;
        let backend: std::sync::Arc<dyn crate::backend::Backend> = local.clone();
        crate::with_backend(backend, async {
            let group = crate::Snapshot::get("history").await.unwrap();
            let base = group.get_checkpoint("base").await.unwrap();
            let child_value = group.get_checkpoint("child").await.unwrap();
            let sibling_value = group.get_checkpoint("sibling").await.unwrap();
            assert!(base.remove().await.is_err()); // Indexed dependents still protect the base.
            let report = after_reader_release(|| sibling_value.remove())
                .await
                .unwrap();
            assert_eq!(report.id, sibling.snapshot_id);
            let change = report.head_update.unwrap();
            assert!(!change.changed);
            assert_eq!(change.head.as_deref(), Some(child.snapshot_id.as_str()));
            assert!(sibling_value.remove().await.is_err()); // No fabricated repeated removal.
            let report = after_reader_release(|| child_value.remove()).await.unwrap();
            let change = report.head_update.as_ref().unwrap();
            assert_eq!(change.previous.as_deref(), Some(child.snapshot_id.as_str()));
            assert_eq!(change.head.as_deref(), Some(parent.snapshot_id.as_str()));
            assert!(change.changed);
            group.clear_head().await.unwrap();
            // A later head mutation cannot change the earlier operation's report.
            assert_eq!(
                report.head_update.unwrap().head.as_deref(),
                Some(parent.snapshot_id.as_str())
            );
            let report = after_reader_release(|| base.remove()).await.unwrap();
            assert_eq!(report.id, parent.snapshot_id);
            assert!(!report.head_update.unwrap().changed);
        })
        .await;
    }

    #[tokio::test]
    async fn committed_checkpoint_removal_keeps_report_when_catalog_cleanup_fails() {
        let home = tempfile::tempdir().unwrap();
        let local = std::sync::Arc::new(
            crate::test_support::local_backend_builder(home.path())
                .build()
                .await
                .unwrap(),
        );
        let checkpoint = manifest(933, None);
        let path = install(&local, "cleanup", "only", &checkpoint).await;
        let backend: std::sync::Arc<dyn crate::backend::Backend> = local.clone();
        crate::with_backend(backend, async {
            let value = crate::Snapshot::get("cleanup").await.unwrap().get_checkpoint("only").await.unwrap();
            let pools = local.db().await.unwrap();
            pools.write().execute_raw(Statement::from_string(DatabaseBackend::Sqlite,
                "CREATE TRIGGER reject_removal_cleanup BEFORE DELETE ON snapshot_index BEGIN SELECT RAISE(FAIL, 'injected catalog cleanup failure'); END".to_owned())).await.unwrap();
            let error = after_reader_release(|| value.remove()).await.unwrap_err();
            let MicrosandboxError::SnapshotRemovalRecovery { result, source } = error else { panic!("unexpected error: {error}") };
            assert!(!path.exists());
            assert_eq!(result.id, checkpoint.snapshot_id);
            let change = result.head_update.unwrap();
            assert_eq!(change.previous.as_deref(), Some(checkpoint.snapshot_id.as_str()));
            assert_eq!(change.head, None);
            assert!(source.to_string().contains("injected catalog cleanup failure"));
            pools.write().execute_raw(Statement::from_string(DatabaseBackend::Sqlite,
                "DROP TRIGGER reject_removal_cleanup".to_owned())).await.unwrap();
            super::super::deletion::recover_parent(&local, path.parent().unwrap()).await.unwrap();
            assert!(snapshot_entity::Entity::find_by_id(path.display().to_string()).one(pools.read()).await.unwrap().is_none());
        }).await;
    }

    #[tokio::test]
    async fn retained_sdk_handles_reject_replacement_before_export_or_removal() {
        let home = tempfile::tempdir().unwrap();
        let local = std::sync::Arc::new(
            crate::test_support::local_backend_builder(home.path())
                .build()
                .await
                .unwrap(),
        );
        let artifact = local.snapshots_dir().join("flat");
        std::fs::create_dir_all(&artifact).unwrap();
        let original = manifest(920, None);
        std::fs::write(
            artifact.join(DESCRIPTOR_FILENAME),
            original.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        let backend: std::sync::Arc<dyn crate::backend::Backend> = local.clone();
        crate::with_backend(backend, async {
            let opened = crate::Checkpoint::open(artifact.to_str().unwrap())
                .await
                .unwrap();
            let handle = crate::Checkpoint::list().await.unwrap().pop().unwrap();
            remove_snapshot(&local, artifact.to_str().unwrap(), false)
                .await
                .unwrap();
            let replacement = manifest(921, None);
            std::fs::create_dir(&artifact).unwrap();
            std::fs::write(
                artifact.join(DESCRIPTOR_FILENAME),
                replacement.to_canonical_bytes().unwrap(),
            )
            .unwrap();
            // Retained values must not resolve a reused path into a different generation.
            let out = home.path().join("unexpected.tar.zst");
            for result in [
                opened
                    .save_to(&out, crate::snapshot::SaveOpts::default())
                    .await,
                handle
                    .save_to(&out, crate::snapshot::SaveOpts::default())
                    .await,
                handle.remove(false).await,
                handle.remove(true).await,
            ] {
                assert!(matches!(
                    result,
                    Err(MicrosandboxError::SnapshotIntegrity(_))
                ));
            }
            assert!(matches!(
                opened.remove().await,
                Err(MicrosandboxError::SnapshotIntegrity(_))
            ));
            assert!(matches!(
                opened.remove_with(|options| options.force()).await,
                Err(MicrosandboxError::SnapshotIntegrity(_))
            ));
            assert!(!out.exists());
            assert_eq!(
                open_snapshot(&local, artifact.to_str().unwrap())
                    .await
                    .unwrap()
                    .digest(),
                replacement.digest().unwrap(),
            );
        })
        .await;
    }

    #[tokio::test]
    async fn pending_publication_recovers_both_sides_of_the_rename() {
        #[cfg(unix)]
        if std::env::var_os("MSB_TEST_PENDING_PUBLICATION_RECOVERY").is_none() {
            // Dropping the lease simulates publisher exit. A sibling test's fork
            // could retain that descriptor until exec, so isolate this fixture
            // rather than weakening its immediate recovery assertions.
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "backend::local::snapshot::store::tests::pending_publication_recovers_both_sides_of_the_rename",
                    "--nocapture",
                ])
                .env("MSB_TEST_PENDING_PUBLICATION_RECOVERY", "1")
                .status()
                .unwrap();
            assert!(
                status.success(),
                "isolated publication recovery failed: {status}"
            );
            return;
        }
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let group = super::super::group::ensure(&local.snapshots_dir(), Some("pending"))
            .await
            .unwrap()
            .canonicalize()
            .unwrap();
        for existing in [false, true] {
            for published in [false, true] {
                let data = manifest(910 + u128::from(published) + 2 * u128::from(existing), None);
                let path = group.join(data.snapshot_id.as_str());
                if existing {
                    std::fs::create_dir(&path).unwrap();
                    std::fs::write(
                        path.join(DESCRIPTOR_FILENAME),
                        data.to_canonical_bytes().unwrap(),
                    )
                    .unwrap();
                    super::super::publication::complete(
                        local.db().await.unwrap().write(),
                        &path,
                        &data.digest().unwrap(),
                        &data,
                    )
                    .await
                    .unwrap();

                    std::fs::remove_dir_all(&path).unwrap();
                    assert_eq!(
                        indexed_path(&local, &path)
                            .await
                            .unwrap()
                            .unwrap()
                            .availability,
                        "ready"
                    );
                }

                let lease = StorageLease::shared(&path).unwrap();
                super::super::publication::prepare(
                    local.db().await.unwrap().write(),
                    &path,
                    &data.digest().unwrap(),
                    &data,
                )
                .await
                .unwrap();
                super::super::publication::recover(&local).await.unwrap();
                assert_eq!(
                    indexed_path(&local, &path)
                        .await
                        .unwrap()
                        .unwrap()
                        .availability,
                    "publishing"
                );
                if published {
                    std::fs::create_dir(&path).unwrap();
                    std::fs::write(
                        path.join(DESCRIPTOR_FILENAME),
                        data.to_canonical_bytes().unwrap(),
                    )
                    .unwrap();
                }
                drop(lease); // Simulate process exit on either side of filesystem publication.
                super::super::publication::recover(&local).await.unwrap();
                let row = indexed_path(&local, &path).await.unwrap();
                if published {
                    assert_eq!(row.unwrap().availability, "ready");
                } else {
                    assert!(row.is_none());
                }
            }
        }
    }

    #[tokio::test]
    async fn committed_batch_recovery_finishes_index_with_live_publisher_pins() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let group = super::super::group::ensure(&local.snapshots_dir(), Some("committed"))
            .await
            .unwrap()
            .canonicalize()
            .unwrap();
        let staged = tempfile::tempdir_in(&group).unwrap();
        let base = manifest(970, None);
        let child = manifest(971, Some(&base));
        let db = local.db().await.unwrap();
        let mut publishers = Vec::new();
        for data in [&base, &child] {
            let path = group.join(data.snapshot_id.as_str());
            publishers.push(StorageLease::shared(&path).unwrap());
            super::super::publication::prepare(db.write(), &path, &data.digest().unwrap(), data)
                .await
                .unwrap();
            let incoming = staged.path().join(data.snapshot_id.as_str());
            std::fs::create_dir(&incoming).unwrap();
            std::fs::write(
                incoming.join(DESCRIPTOR_FILENAME),
                data.to_canonical_bytes().unwrap(),
            )
            .unwrap();
        }
        super::super::group::publish_batch_indexed(
            &group,
            staged.path(),
            &BTreeMap::new(),
            std::slice::from_ref(&child.snapshot_id),
            false,
            super::super::group::IndexedPublication {
                operation: "00000000000000000000000000000001".into(),
                outcome: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
            },
        )
        .await
        .unwrap();
        assert!(group.join(".group-transaction").exists());

        // A post-filesystem failure retains a committed journal and the complete reservation
        // set. Reading must report failure rather than silently return an older index view.
        db.write()
            .execute_unprepared(
                "CREATE TRIGGER fail_batch_index BEFORE INSERT ON snapshot_index \
             WHEN NEW.availability = 'ready' AND EXISTS \
             (SELECT 1 FROM snapshot_index WHERE availability = 'ready') \
             BEGIN SELECT RAISE(FAIL, 'injected batch-index failure'); END",
            )
            .await
            .unwrap();
        assert!(
            list_indexed(&local)
                .await
                .unwrap_err()
                .to_string()
                .contains("injected batch-index failure")
        );
        for data in [&base, &child] {
            assert_eq!(
                indexed_path(&local, &group.join(data.snapshot_id.as_str()))
                    .await
                    .unwrap()
                    .unwrap()
                    .availability,
                "publishing"
            );
        }
        assert!(group.join(".group-transaction").exists());
        db.write()
            .execute_unprepared("DROP TRIGGER fail_batch_index")
            .await
            .unwrap();
        let listed = tokio::time::timeout(std::time::Duration::from_secs(5), list_indexed(&local))
            .await
            .expect("committed recovery waited on the original publisher's pins")
            .unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().all(|member| member.availability == "ready"));
        assert!(!group.join(".group-transaction").exists());
        assert!(
            !super::super::publication::complete_batch(db.write(), &group)
                .await
                .unwrap()
        );
        drop(publishers);
    }

    #[tokio::test]
    async fn pending_batch_recovery_defers_live_publishers_and_commits_all_rows_together() {
        const CHILD: &str = "MSB_TEST_BATCH_RECOVERY_CHILD";
        if std::env::var_os(CHILD).is_none() {
            // Parallel fork-based tests can inherit the publisher's flock until exec.
            // A busy namespace correctly defers recovery, so isolate the injected SQL
            // failure test instead of weakening production admission or retrying errors.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("backend::local::snapshot::store::tests::pending_batch_recovery_defers_live_publishers_and_commits_all_rows_together")
                .arg("--nocapture")
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let group = super::super::group::ensure(&local.snapshots_dir(), Some("batch"))
            .await
            .unwrap()
            .canonicalize()
            .unwrap();
        let db = local.db().await.unwrap();
        let mut paths = Vec::new();
        for number in 0..3 {
            let data = manifest(950 + number, None);
            let path = group.join(data.snapshot_id.as_str());
            super::super::publication::prepare(db.write(), &path, &data.digest().unwrap(), &data)
                .await
                .unwrap();
            if number < 2 {
                std::fs::create_dir(&path).unwrap();
                std::fs::write(
                    path.join(DESCRIPTOR_FILENAME),
                    data.to_canonical_bytes().unwrap(),
                )
                .unwrap();
            }
            paths.push(path);
        }

        // One still-live publisher must defer its whole group, including earlier entries
        // that a per-row recovery loop would otherwise expose prematurely.
        let publisher = StorageLease::shared(&paths[1]).unwrap();
        super::super::publication::recover(&local).await.unwrap();
        for path in &paths {
            assert_eq!(
                indexed_path(&local, path)
                    .await
                    .unwrap()
                    .unwrap()
                    .availability,
                "publishing"
            );
        }
        drop(publisher);

        // Fail after the first ready insertion inside the transaction. Both that insertion
        // and deletion of the absent reservation must roll back, preserving all three roots.
        db.write()
            .execute_unprepared(
                "CREATE TRIGGER fail_second_ready BEFORE INSERT ON snapshot_index \
             WHEN NEW.availability = 'ready' AND EXISTS \
             (SELECT 1 FROM snapshot_index WHERE availability = 'ready') \
             BEGIN SELECT RAISE(FAIL, 'injected second-row failure'); END",
            )
            .await
            .unwrap();
        let error = super::super::publication::recover(&local)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("injected second-row failure"));
        for path in &paths {
            assert_eq!(
                indexed_path(&local, path)
                    .await
                    .unwrap()
                    .unwrap()
                    .availability,
                "publishing"
            );
        }
        db.write()
            .execute_unprepared("DROP TRIGGER fail_second_ready")
            .await
            .unwrap();
        super::super::publication::recover(&local).await.unwrap();
        for path in &paths[..2] {
            assert_eq!(
                indexed_path(&local, path)
                    .await
                    .unwrap()
                    .unwrap()
                    .availability,
                "ready"
            );
        }
        assert!(indexed_path(&local, &paths[2]).await.unwrap().is_none());
        super::super::publication::recover(&local).await.unwrap();
        assert_eq!(list_indexed(&local).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn recovery_finds_quarantine_after_last_index_row_is_gone() {
        let home = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        for parent in [local.snapshots_dir(), external.path().to_path_buf()] {
            std::fs::create_dir_all(&parent).unwrap();
            super::super::deletion::register_parent(&local, &parent).unwrap();
            let journal = parent.join(".snapshot-deletions/delete-interrupted");
            std::fs::create_dir_all(journal.join("payload")).unwrap();
            std::fs::write(journal.join("payload/bytes"), b"retained").unwrap();
            std::fs::write(journal.join("source.json"), br#""missing-snapshot""#).unwrap();
            microsandbox_utils::process_lock::open_lock_file(&journal.join("active.lock")).unwrap();
            assert!(list_indexed(&local).await.unwrap().is_empty());
            assert!(!journal.exists());
        }
    }

    #[tokio::test]
    async fn incomplete_deletion_records_preserve_live_snapshots_and_quarantined_payloads() {
        for (record_name, record) in [
            ("source.json", b"".as_slice()),
            ("source.json", br#""unfinished"#),
            ("source.json.part", br#""unfinished"#),
        ] {
            for quarantined in [false, true] {
                if quarantined && record_name == "source.json.part" {
                    continue; // The complete record is published before moving a payload.
                }

                let home = tempfile::tempdir().unwrap();
                let local = crate::test_support::local_backend_builder(home.path())
                    .build()
                    .await
                    .unwrap();
                let data = manifest(903, None);
                let live = install(&local, "live", "baseline", &data).await;
                assert_eq!(
                    reindex_dir(&local, &local.snapshots_dir()).await.unwrap(),
                    1
                );
                let journal = local
                    .snapshots_dir()
                    .join(".snapshot-deletions")
                    .join("delete-interrupted");
                std::fs::create_dir_all(&journal).unwrap();
                std::fs::write(journal.join(record_name), record).unwrap();
                if quarantined {
                    std::fs::create_dir(journal.join("payload")).unwrap();
                    std::fs::write(journal.join("payload/bytes"), b"retained").unwrap();
                }

                let result = list_indexed(&local).await;

                assert!(live.join(DESCRIPTOR_FILENAME).exists());
                if quarantined {
                    let error = result.unwrap_err();
                    assert!(matches!(error, MicrosandboxError::SnapshotIntegrity(_)));
                    let message = error.to_string();
                    assert!(message.contains(journal.to_str().unwrap()));
                    assert!(message.contains("payload"));
                    assert_eq!(
                        std::fs::read(journal.join("payload/bytes")).unwrap(),
                        b"retained"
                    );
                } else {
                    assert_eq!(result.unwrap().len(), 1);
                    assert!(!journal.exists());
                }
            }
        }
    }

    #[tokio::test]
    async fn stale_metadata_cannot_resurrect_a_removed_snapshot() {
        #[cfg(unix)]
        if std::env::var_os("MSB_TEST_STALE_SNAPSHOT_REMOVAL").is_none() {
            // Metadata opening briefly holds a reader lease. Other test threads
            // may fork while it is held and retain it until exec, so construct
            // this immediate-removal fixture only after entering its own process.
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "backend::local::snapshot::store::tests::stale_metadata_cannot_resurrect_a_removed_snapshot",
                    "--nocapture",
                ])
                .env("MSB_TEST_STALE_SNAPSHOT_REMOVAL", "1")
                .status()
                .unwrap();
            assert!(
                status.success(),
                "isolated stale-metadata fixture failed: {status}"
            );
            return;
        }
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let data = manifest(900, None);
        let path = install(&local, "stale", "baseline", &data).await;
        let opened = open_snapshot(&local, path.to_str().unwrap()).await.unwrap();
        remove_snapshot(&local, path.to_str().unwrap(), true)
            .await
            .unwrap();
        assert!(
            index_upsert(&local, &path, opened.digest(), opened.manifest())
                .await
                .is_err()
        );
        assert!(indexed_path(&local, &path).await.unwrap().is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn migrated_reader_pins_the_published_descriptor() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        local.db().await.unwrap();
        let path = home.path().join("external-legacy");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("upper.ext4"), b"hello").unwrap();
        std::fs::write(path.join(V066_DESCRIPTOR_FILENAME), br#"{"schema":1,"format":"raw","fstype":"ext4","image":{"ref":"docker.io/library/alpine:3.20","manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"parent":null,"created_at":"2026-07-01T10:00:00Z","labels":{},"upper":{"file":"upper.ext4","size_bytes":5,"integrity":null},"source_sandbox":"box"}"#).unwrap();
        let reader = open_snapshot_leased(&local, path.to_str().unwrap())
            .await
            .unwrap();
        assert!(path.join(DESCRIPTOR_FILENAME).exists());
        // The legacy inode has been retired. Protection must follow snapshot.json.
        assert!(super::super::lease::deletion(&path).unwrap().is_none());
        drop(reader);
        remove_snapshot(&local, path.to_str().unwrap(), true)
            .await
            .unwrap();
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn read_only_grouped_snapshot_preserves_explicit_path_reads() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let group = super::super::group::ensure(external.path(), Some("readonly"))
            .await
            .unwrap();
        let data = manifest(902, None);
        let path = group.join(data.snapshot_id.as_str());
        std::fs::create_dir(&path).unwrap();
        std::fs::write(
            path.join(DESCRIPTOR_FILENAME),
            data.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        let lock = group.join(".group.lock");
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o444)).unwrap();
        std::fs::set_permissions(&group, std::fs::Permissions::from_mode(0o555)).unwrap();
        let result = open_snapshot_leased(&local, path.to_str().unwrap()).await;
        std::fs::set_permissions(&group, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
        let reader = result.unwrap();
        assert_eq!(reader.id(), &data.snapshot_id);
        assert!(!group.join(".msb-leases").exists());
    }

    #[tokio::test]
    async fn group_listing_retains_valid_artifacts_beside_malformed_metadata() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let data = manifest(904, None);
        let path = install(&local, "history", "baseline", &data).await;
        let group = path.parent().unwrap();
        let corrupt = group.join("snap_00000000000000000000000000000389");
        std::fs::create_dir(&corrupt).unwrap();
        std::fs::write(corrupt.join(DESCRIPTOR_FILENAME), b"malformed descriptor").unwrap();
        // Explicit-path discovery has always been useful for recovering otherwise healthy
        // artifacts when local selection metadata is damaged. Preserve that behavior.
        std::fs::write(
            group.join(super::super::group::GROUP_FILENAME),
            b"malformed group",
        )
        .unwrap();
        let found = list_dir(&local, &local.snapshots_dir()).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id(), &data.snapshot_id);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn read_only_external_snapshot_needs_no_sidecar_directory() {
        const CHILD: &str = "MSB_TEST_READONLY_SNAPSHOT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            // The final assertion requires all reader descriptors to be closed.
            // Parallel subprocess tests may inherit the flock until their exec,
            // so run this ownership check without unrelated fork producers.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("backend::local::snapshot::store::tests::read_only_external_snapshot_needs_no_sidecar_directory")
                .arg("--nocapture")
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let path = external.path().join("readonly");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(
            path.join(DESCRIPTOR_FILENAME),
            manifest(901, None).to_canonical_bytes().unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(external.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let result = open_snapshot_leased(&local, path.to_str().unwrap()).await;
        std::fs::set_permissions(external.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let reader = result.unwrap();
        assert!(!external.path().join(".msb-leases").exists());
        assert!(super::super::lease::deletion(&path).unwrap().is_none());
        drop(reader);
        assert!(super::super::lease::deletion(&path).unwrap().is_some());
    }

    #[tokio::test]
    async fn active_snapshot_reader_protects_only_its_installed_copy_even_from_force() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let snapshot = manifest(77, None);
        let first = install(&local, "first", "baseline", &snapshot).await;
        let second = install(&local, "second", "baseline", &snapshot).await;
        let reader = open_snapshot_leased(&local, first.to_str().unwrap())
            .await
            .unwrap();
        let error = remove_snapshot(&local, first.to_str().unwrap(), true)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("active operation"), "{error}");
        remove_snapshot(&local, second.to_str().unwrap(), false)
            .await
            .unwrap();
        assert!(!second.exists());
        assert!(first.join(DESCRIPTOR_FILENAME).exists());
        drop(reader);
        // The live-reader refusal above stays strict; after release allow only the
        // transient inheritance interval exercised by the parallel crash tests.
        after_reader_release(|| remove_snapshot(&local, first.to_str().unwrap(), false))
            .await
            .unwrap();
        assert!(!first.exists());
    }

    #[tokio::test]
    async fn retired_snapshot_recovers_stale_index_without_deleting_new_publication() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let parent = local.snapshots_dir();
        let artifact = parent.join("flat");
        let snapshot = manifest(78, None);
        std::fs::create_dir_all(&artifact).unwrap();
        std::fs::write(
            artifact.join(DESCRIPTOR_FILENAME),
            snapshot.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        let opened = open_snapshot(&local, artifact.to_str().unwrap())
            .await
            .unwrap();
        index_upsert(&local, &artifact, opened.digest(), opened.manifest())
            .await
            .unwrap();
        let lease = StorageLease::try_exclusive(&artifact).unwrap().unwrap();
        super::super::deletion::quarantine(&artifact).unwrap();
        drop(lease);
        // Simulate a crash before removing the index row.
        super::super::deletion::recover_parent(&local, &parent)
            .await
            .unwrap();
        assert!(indexed_path(&local, &artifact).await.unwrap().is_none());

        std::fs::create_dir(&artifact).unwrap();
        std::fs::write(
            artifact.join(DESCRIPTOR_FILENAME),
            snapshot.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        index_upsert(&local, &artifact, opened.digest(), opened.manifest())
            .await
            .unwrap();
        super::super::deletion::quarantine(&artifact).unwrap();
        // A complete new generation at the same address must survive recovery.
        std::fs::create_dir(&artifact).unwrap();
        std::fs::write(
            artifact.join(DESCRIPTOR_FILENAME),
            snapshot.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        super::super::deletion::recover_parent(&local, &parent)
            .await
            .unwrap();
        assert!(indexed_path(&local, &artifact).await.unwrap().is_some());
        assert!(artifact.join(DESCRIPTOR_FILENAME).exists());
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
    async fn distinct_child_counts_and_parent_fallback_survive_reindex() {
        // This checks indexed ancestry, not transient descriptor inheritance from sibling
        // fork tests. The shared helper retries only an uncommitted busy-reader refusal.
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
            after_reader_release(|| remove_snapshot(&local, "first:base", false))
                .await
                .unwrap_err()
                .to_string()
                .contains("indexed child")
        );
        after_reader_release(|| remove_snapshot(&local, "first:child", false))
            .await
            .unwrap();
        assert_eq!(
            get_handle(&local, "first").await.unwrap().id(),
            parent.snapshot_id.as_str()
        );
        assert_eq!(
            get_handle(&local, "second").await.unwrap().id(),
            child.snapshot_id.as_str()
        );
        // A second installed copy of the same child still protects the parent;
        // removing one copy must not reset the distinct-child count to zero.
        assert!(
            after_reader_release(|| remove_snapshot(&local, "first:base", false))
                .await
                .unwrap_err()
                .to_string()
                .contains("indexed child")
        );
        after_reader_release(|| remove_snapshot(&local, "second:child", false))
            .await
            .unwrap();
        let rows = snapshot_entity::Entity::find()
            .filter(snapshot_entity::Column::SnapshotId.eq(parent.snapshot_id.as_str()))
            .all(local.db().await.unwrap().read())
            .await
            .unwrap();
        assert!(rows.iter().all(|row| row.child_count == 0));
        after_reader_release(|| remove_snapshot(&local, "first:base", false))
            .await
            .unwrap();
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
