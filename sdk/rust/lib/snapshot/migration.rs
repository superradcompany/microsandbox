//! Automatic adjacent-release snapshot artifact migration.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::File;
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use chrono::Utc;
use microsandbox_db::pool::DbPools;
use microsandbox_image::snapshot::migration::{
    V066_BACKUP_FILENAME, V066_DESCRIPTOR_FILENAME, V066PayloadIdentity, V066SourceInfo,
    inspect_v066_source, translate_v066_forward,
};
use microsandbox_image::snapshot::{
    DESCRIPTOR_FILENAME, Manifest, SPARSE_SHA256_V1, SnapshotState, UpperIntegrity,
};
use microsandbox_utils::extent::ExtentMap;
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement, TransactionTrait};
use sha2::{Digest as _, Sha256};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MIGRATION_KIND: &str = "v0.6.6-manifest-to-snapshot-v1";
const MIGRATION_LOCK_FILENAME: &str = ".snapshot-migration.lock";
const MAX_LEGACY_DESCRIPTOR_BYTES: u64 = 1024 * 1024;
const MAX_PARENT_DEPTH: usize = 128;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Summary of one automatic reconciliation pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MigrationReport {
    pub migrated: usize,
    pub canonical: usize,
    pub blocked: usize,
}

struct PinnedCandidate {
    path: PathBuf,
    source_bytes: Vec<u8>,
    source: V066SourceInfo,
    payload: File,
    payload_before: FileIdentity,
    #[cfg(unix)]
    directory: File,
    #[cfg(unix)]
    _lock: File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    len: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanos: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanos: i64,
}

struct HashedCandidate {
    pinned: PinnedCandidate,
    payload: V066PayloadIdentity,
}

struct PlannedCandidate {
    hashed: HashedCandidate,
    target: Manifest,
    target_bytes: Vec<u8>,
    target_digest: String,
    target_parent_digest: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Discover and synchronously reconcile managed legacy artifacts.
pub(crate) async fn reconcile_managed(
    pools: &DbPools,
    snapshots_dir: &Path,
) -> MicrosandboxResult<MigrationReport> {
    let mut paths = indexed_artifact_paths(pools.write().inner()).await?;
    if snapshots_dir.exists() {
        let mut entries = tokio::fs::read_dir(snapshots_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let name_is_visible = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| !name.starts_with('.'));
            if name_is_visible && entry.file_type().await?.is_dir() {
                paths.insert(path);
            }
        }
    }
    reconcile_paths(pools, paths).await
}

/// Reconcile an explicitly opened or newly staged artifact through the same
/// migration gateway used by startup.
pub(crate) async fn reconcile_explicit(
    pools: &DbPools,
    artifact_path: &Path,
) -> MicrosandboxResult<MigrationReport> {
    let mut paths = indexed_artifact_paths(pools.write().inner()).await?;
    paths.insert(artifact_path.to_path_buf());
    let report = reconcile_paths(pools, paths).await?;
    if artifact_path.join(V066_DESCRIPTOR_FILENAME).exists() {
        return Err(load_blocked_error(pools.write().inner(), artifact_path).await?);
    }
    Ok(report)
}

/// Normalize a complete legacy component inside private import staging.
/// Staged paths are intentionally not journaled or indexed because failure
/// discards the stage and promotion chooses the final installation paths.
pub(crate) async fn normalize_staged(
    pools: &DbPools,
    artifact_paths: &[PathBuf],
) -> MicrosandboxResult<()> {
    let mut pinned = Vec::new();
    for path in artifact_paths {
        if path.join(V066_DESCRIPTOR_FILENAME).exists() {
            let path = path.clone();
            pinned.push(
                tokio::task::spawn_blocking(move || pin_candidate(path))
                    .await
                    .map_err(|error| {
                        MicrosandboxError::Custom(format!(
                            "staged snapshot migration task: {error}"
                        ))
                    })??,
            );
        }
    }
    if pinned.is_empty() {
        return Ok(());
    }
    let mut hashed = Vec::with_capacity(pinned.len());
    for candidate in pinned {
        hashed.push(
            tokio::task::spawn_blocking(move || hash_candidate(candidate))
                .await
                .map_err(|error| {
                    MicrosandboxError::Custom(format!("staged snapshot hash task: {error}"))
                })??,
        );
    }
    let canonical = indexed_canonical_digests(pools.write().inner()).await?;
    let (planned, failures) = plan_graph(hashed, &canonical);
    if let Some((_, error)) = failures.into_iter().next() {
        return Err(error);
    }
    for candidate in &planned {
        publish_descriptor(candidate)?;
    }
    for candidate in &planned {
        retire_legacy_descriptor(candidate)?;
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Planning and Publication
//--------------------------------------------------------------------------------------------------

async fn reconcile_paths(
    pools: &DbPools,
    paths: BTreeSet<PathBuf>,
) -> MicrosandboxResult<MigrationReport> {
    let db = pools.write().inner();
    let mut report = MigrationReport::default();
    let mut pinned = Vec::new();

    for path in paths {
        let legacy = path.join(V066_DESCRIPTOR_FILENAME);
        let canonical = path.join(DESCRIPTOR_FILENAME);
        let backup = path.join(V066_BACKUP_FILENAME);
        if !legacy.exists() {
            if canonical.exists() {
                report.canonical += 1;
                if backup.exists() {
                    mark_completed_if_journaled(db, &path).await?;
                }
            }
            continue;
        }

        match tokio::task::spawn_blocking({
            let path = path.clone();
            move || pin_candidate(path)
        })
        .await
        .map_err(|error| MicrosandboxError::Custom(format!("snapshot migration task: {error}")))?
        {
            Ok(candidate) => {
                journal_discovered(db, &candidate).await?;
                pinned.push(candidate);
            }
            Err(error) => {
                report.blocked += 1;
                record_blocked_path(db, &path, &error).await?;
            }
        }
    }

    let mut hashed = Vec::new();
    for candidate in pinned {
        let path = candidate.path.clone();
        match tokio::task::spawn_blocking(move || hash_candidate(candidate))
            .await
            .map_err(|error| {
                MicrosandboxError::Custom(format!("snapshot migration hash task: {error}"))
            })? {
            Ok(candidate) => hashed.push(candidate),
            Err(error) => {
                report.blocked += 1;
                record_blocked_path(db, &path, &error).await?;
            }
        }
    }

    let canonical_digests = indexed_canonical_digests(db).await?;
    let (planned, graph_failures) = plan_graph(hashed, &canonical_digests);
    for (path, error) in graph_failures {
        report.blocked += 1;
        record_blocked_path(db, &path, &error).await?;
    }
    if planned.is_empty() {
        return Ok(report);
    }

    preflight_target_collisions(db, &planned).await?;
    for candidate in &planned {
        journal_planned(db, candidate).await?;
    }

    for candidate in &planned {
        if let Err(error) = publish_descriptor(candidate) {
            for blocked in &planned {
                record_blocked_path(db, &blocked.hashed.pinned.path, &error).await?;
            }
            report.blocked += planned.len();
            return Ok(report);
        }
        journal_phase(db, &candidate.hashed.pinned.path, "descriptor_published").await?;
    }

    publish_index_component(db, &planned).await?;
    for candidate in &planned {
        retire_legacy_descriptor(candidate)?;
        journal_complete(db, &candidate.hashed.pinned.path).await?;
        report.migrated += 1;
    }

    Ok(report)
}

fn pin_candidate(path: PathBuf) -> MicrosandboxResult<PinnedCandidate> {
    #[cfg(unix)]
    {
        let directory = open_directory_nofollow(&path)?;
        let lock = openat_file(
            &directory,
            MIGRATION_LOCK_FILENAME,
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW,
            0o600,
        )?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return migration_error(
                "legacy_migration_io",
                "discovered",
                &path,
                format!("lock artifact: {}", std::io::Error::last_os_error()),
            );
        }
        let mut descriptor = openat_file(
            &directory,
            V066_DESCRIPTOR_FILENAME,
            libc::O_RDONLY | libc::O_NOFOLLOW,
            0,
        )?;
        require_regular_bounded(
            &descriptor,
            MAX_LEGACY_DESCRIPTOR_BYTES,
            "legacy descriptor",
            &path,
        )?;
        let mut source_bytes = Vec::new();
        descriptor.read_to_end(&mut source_bytes)?;
        let source = inspect_v066_source(&source_bytes).map_err(|error| {
            MicrosandboxError::SnapshotMigration {
                code: classify_legacy_error(&error.to_string()).into(),
                phase: "discovered".into(),
                artifact: path.display().to_string(),
                detail: bounded_detail(error.to_string()),
            }
        })?;
        let payload = openat_file(
            &directory,
            &source.upper_file,
            libc::O_RDONLY | libc::O_NOFOLLOW,
            0,
        )
        .map_err(|error| MicrosandboxError::SnapshotMigration {
            code: "legacy_payload_missing".into(),
            phase: "discovered".into(),
            artifact: path.display().to_string(),
            detail: bounded_detail(error.to_string()),
        })?;
        let payload_before = file_identity(&payload)?;
        if payload_before.len != source.size_bytes {
            return migration_error(
                "legacy_payload_size_mismatch",
                "discovered",
                &path,
                format!(
                    "descriptor={}, file={}",
                    source.size_bytes, payload_before.len
                ),
            );
        }
        Ok(PinnedCandidate {
            path,
            source_bytes,
            source,
            payload,
            payload_before,
            directory,
            _lock: lock,
        })
    }

    #[cfg(not(unix))]
    {
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return migration_error(
                "legacy_migration_io",
                "discovered",
                &path,
                "artifact path is not a non-link directory",
            );
        }
        let source_bytes = std::fs::read(path.join(V066_DESCRIPTOR_FILENAME))?;
        if source_bytes.len() as u64 > MAX_LEGACY_DESCRIPTOR_BYTES {
            return migration_error(
                "legacy_descriptor_malformed",
                "discovered",
                &path,
                "legacy descriptor exceeds the size limit",
            );
        }
        let source = inspect_v066_source(&source_bytes).map_err(|error| {
            MicrosandboxError::SnapshotMigration {
                code: classify_legacy_error(&error.to_string()).into(),
                phase: "discovered".into(),
                artifact: path.display().to_string(),
                detail: bounded_detail(error.to_string()),
            }
        })?;
        let payload_path = path.join(&source.upper_file);
        let payload_meta = std::fs::symlink_metadata(&payload_path)?;
        if !payload_meta.is_file() || payload_meta.file_type().is_symlink() {
            return migration_error(
                "legacy_payload_not_regular",
                "discovered",
                &path,
                "payload is not a confined regular file",
            );
        }
        let payload = OpenOptions::new().read(true).open(payload_path)?;
        let payload_before = file_identity(&payload)?;
        Ok(PinnedCandidate {
            path,
            source_bytes,
            source,
            payload,
            payload_before,
        })
    }
}

fn hash_candidate(mut candidate: PinnedCandidate) -> MicrosandboxResult<HashedCandidate> {
    let payload = hash_payload(&mut candidate.payload)?;
    let after = file_identity(&candidate.payload)?;
    if after != candidate.payload_before {
        return migration_error(
            "legacy_descriptor_changed_during_migration",
            "discovered",
            &candidate.path,
            "payload identity or change metadata changed while hashing",
        );
    }
    Ok(HashedCandidate {
        pinned: candidate,
        payload,
    })
}

fn plan_graph(
    candidates: Vec<HashedCandidate>,
    canonical_digests: &HashSet<String>,
) -> (Vec<PlannedCandidate>, Vec<(PathBuf, MicrosandboxError)>) {
    let mut by_source = HashMap::new();
    let mut failures = Vec::new();
    let mut conflicted = HashSet::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if let Some(previous) =
            by_source.insert(candidate.pinned.source.source_digest.clone(), index)
        {
            conflicted.insert(previous);
            conflicted.insert(index);
            let error = MicrosandboxError::SnapshotMigration {
                code: "legacy_index_conflict".into(),
                phase: "planned".into(),
                artifact: candidate.pinned.path.display().to_string(),
                detail: format!(
                    "legacy digest is present at both {} and {}",
                    candidates[previous].pinned.path.display(),
                    candidate.pinned.path.display()
                ),
            };
            failures.push((candidate.pinned.path.clone(), error));
        }
    }
    by_source.retain(|_, index| !conflicted.contains(index));

    let mut visiting = HashSet::new();
    let mut translated: HashMap<usize, PlannedCandidate> = HashMap::new();
    let mut order = Vec::new();
    for index in 0..candidates.len() {
        if conflicted.contains(&index) {
            continue;
        }
        if let Err(error) = visit_candidate(
            index,
            &candidates,
            &by_source,
            canonical_digests,
            &mut visiting,
            &mut translated,
            &mut order,
            0,
        ) {
            failures.push((candidates[index].pinned.path.clone(), error));
        }
    }

    let planned = order
        .into_iter()
        .filter_map(|index| translated.remove(&index))
        .collect();
    (planned, failures)
}

#[allow(clippy::too_many_arguments)]
fn visit_candidate(
    index: usize,
    candidates: &[HashedCandidate],
    by_source: &HashMap<String, usize>,
    canonical_digests: &HashSet<String>,
    visiting: &mut HashSet<usize>,
    translated: &mut HashMap<usize, PlannedCandidate>,
    order: &mut Vec<usize>,
    depth: usize,
) -> MicrosandboxResult<String> {
    if let Some(candidate) = translated.get(&index) {
        return Ok(candidate.target_digest.clone());
    }
    if depth > MAX_PARENT_DEPTH {
        return migration_error(
            "legacy_graph_too_deep",
            "planned",
            &candidates[index].pinned.path,
            "legacy parent graph exceeds the traversal limit",
        );
    }
    if !visiting.insert(index) {
        return migration_error(
            "legacy_parent_cycle",
            "planned",
            &candidates[index].pinned.path,
            "legacy parent graph contains a cycle",
        );
    }

    let target_parent_digest = match candidates[index].pinned.source.parent_digest.as_ref() {
        None => None,
        Some(parent) => {
            if let Some(parent_index) = by_source.get(parent) {
                let translated_parent = visit_candidate(
                    *parent_index,
                    candidates,
                    by_source,
                    canonical_digests,
                    visiting,
                    translated,
                    order,
                    depth + 1,
                );
                match translated_parent {
                    Ok(parent) => Some(parent),
                    Err(error) => {
                        visiting.remove(&index);
                        return Err(error);
                    }
                }
            } else if canonical_digests.contains(parent) {
                Some(parent.clone())
            } else {
                visiting.remove(&index);
                return migration_error(
                    "legacy_parent_missing",
                    "planned",
                    &candidates[index].pinned.path,
                    format!("parent {parent} is not available"),
                );
            }
        }
    };

    let translation = translate_v066_forward(
        &candidates[index].pinned.source_bytes,
        &candidates[index].payload,
        target_parent_digest.clone(),
    )
    .map_err(|error| MicrosandboxError::SnapshotMigration {
        code: classify_legacy_error(&error.to_string()).into(),
        phase: "planned".into(),
        artifact: candidates[index].pinned.path.display().to_string(),
        detail: bounded_detail(error.to_string()),
    });
    let translation = match translation {
        Ok(translation) => translation,
        Err(error) => {
            visiting.remove(&index);
            return Err(error);
        }
    };
    let target_bytes = translation.target.to_canonical_bytes().map_err(|error| {
        MicrosandboxError::SnapshotMigration {
            code: "legacy_descriptor_malformed".into(),
            phase: "planned".into(),
            artifact: candidates[index].pinned.path.display().to_string(),
            detail: bounded_detail(error.to_string()),
        }
    });
    let target_bytes = match target_bytes {
        Ok(bytes) => bytes,
        Err(error) => {
            visiting.remove(&index);
            return Err(error);
        }
    };
    let target_digest = translation.target_digest.clone();
    translated.insert(
        index,
        PlannedCandidate {
            hashed: HashedCandidate {
                pinned: clone_pinned_for_plan(&candidates[index])?,
                payload: candidates[index].payload.clone(),
            },
            target: translation.target,
            target_bytes,
            target_digest: target_digest.clone(),
            target_parent_digest,
        },
    );
    visiting.remove(&index);
    order.push(index);
    Ok(target_digest)
}

fn clone_pinned_for_plan(candidate: &HashedCandidate) -> MicrosandboxResult<PinnedCandidate> {
    Ok(PinnedCandidate {
        path: candidate.pinned.path.clone(),
        source_bytes: candidate.pinned.source_bytes.clone(),
        source: candidate.pinned.source.clone(),
        payload: candidate.pinned.payload.try_clone()?,
        payload_before: candidate.pinned.payload_before.clone(),
        #[cfg(unix)]
        directory: candidate.pinned.directory.try_clone()?,
        #[cfg(unix)]
        _lock: candidate.pinned._lock.try_clone()?,
    })
}

fn publish_descriptor(candidate: &PlannedCandidate) -> MicrosandboxResult<()> {
    #[cfg(unix)]
    {
        if let Ok(mut existing) = openat_file(
            &candidate.hashed.pinned.directory,
            DESCRIPTOR_FILENAME,
            libc::O_RDONLY | libc::O_NOFOLLOW,
            0,
        ) {
            let mut bytes = Vec::new();
            existing.read_to_end(&mut bytes)?;
            if bytes == candidate.target_bytes {
                return Ok(());
            }
            return migration_error(
                "legacy_target_collision",
                "planned",
                &candidate.hashed.pinned.path,
                "an unexpected snapshot.json already exists",
            );
        }
        let temp_name = format!(".snapshot.json.migrate.{}", std::process::id());
        let mut temp = openat_file(
            &candidate.hashed.pinned.directory,
            &temp_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600,
        )?;
        temp.write_all(&candidate.target_bytes)?;
        temp.sync_all()?;
        drop(temp);
        renameat(
            &candidate.hashed.pinned.directory,
            &temp_name,
            DESCRIPTOR_FILENAME,
        )?;
        candidate.hashed.pinned.directory.sync_all()?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let target = candidate.hashed.pinned.path.join(DESCRIPTOR_FILENAME);
        if target.exists() {
            if std::fs::read(&target)? == candidate.target_bytes {
                return Ok(());
            }
            return migration_error(
                "legacy_target_collision",
                "planned",
                &candidate.hashed.pinned.path,
                "an unexpected snapshot.json already exists",
            );
        }
        let temp = candidate
            .hashed
            .pinned
            .path
            .join(format!(".snapshot.json.migrate.{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(&candidate.target_bytes)?;
        file.sync_all()?;
        std::fs::rename(temp, target)?;
        Ok(())
    }
}

fn retire_legacy_descriptor(candidate: &PlannedCandidate) -> MicrosandboxResult<()> {
    #[cfg(unix)]
    {
        if openat_file(
            &candidate.hashed.pinned.directory,
            V066_BACKUP_FILENAME,
            libc::O_RDONLY | libc::O_NOFOLLOW,
            0,
        )
        .is_ok()
        {
            return migration_error(
                "legacy_migration_recovery_required",
                "index_published",
                &candidate.hashed.pinned.path,
                "legacy backup already exists while manifest.json is still active",
            );
        }
        renameat(
            &candidate.hashed.pinned.directory,
            V066_DESCRIPTOR_FILENAME,
            V066_BACKUP_FILENAME,
        )?;
        candidate.hashed.pinned.directory.sync_all()?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let source = candidate.hashed.pinned.path.join(V066_DESCRIPTOR_FILENAME);
        let backup = candidate.hashed.pinned.path.join(V066_BACKUP_FILENAME);
        if backup.exists() {
            return migration_error(
                "legacy_migration_recovery_required",
                "index_published",
                &candidate.hashed.pinned.path,
                "legacy backup already exists while manifest.json is still active",
            );
        }
        std::fs::rename(source, backup)?;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Database
//--------------------------------------------------------------------------------------------------

async fn indexed_artifact_paths(db: &DatabaseConnection) -> MicrosandboxResult<BTreeSet<PathBuf>> {
    let rows = db
        .query_all(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT artifact_path FROM snapshot_index",
        ))
        .await?;
    let mut paths = BTreeSet::new();
    for row in rows {
        paths.insert(PathBuf::from(row.try_get_by_index::<String>(0)?));
    }
    Ok(paths)
}

async fn indexed_canonical_digests(db: &DatabaseConnection) -> MicrosandboxResult<HashSet<String>> {
    let rows = db
        .query_all(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT digest, artifact_path FROM snapshot_index",
        ))
        .await?;
    let mut digests = HashSet::new();
    for row in rows {
        let digest = row.try_get_by_index::<String>(0)?;
        let path = PathBuf::from(row.try_get_by_index::<String>(1)?);
        if path.join(DESCRIPTOR_FILENAME).exists() {
            digests.insert(digest);
        }
    }
    Ok(digests)
}

async fn preflight_target_collisions(
    db: &DatabaseConnection,
    planned: &[PlannedCandidate],
) -> MicrosandboxResult<()> {
    let rows = db
        .query_all(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT digest, artifact_path FROM snapshot_index",
        ))
        .await?;
    let existing: HashMap<String, String> = rows
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get_by_index::<String>(0)?,
                row.try_get_by_index::<String>(1)?,
            ))
        })
        .collect::<Result<_, sea_orm::DbErr>>()?;
    let mut targets = HashMap::new();
    for candidate in planned {
        let path = candidate.hashed.pinned.path.display().to_string();
        if let Some(other) = existing.get(&candidate.target_digest)
            && other != &path
        {
            return migration_error(
                "legacy_target_collision",
                "planned",
                &candidate.hashed.pinned.path,
                format!("target identity already belongs to {other}"),
            );
        }
        if let Some(other) = targets.insert(candidate.target_digest.clone(), path.clone())
            && other != path
        {
            return migration_error(
                "legacy_target_collision",
                "planned",
                &candidate.hashed.pinned.path,
                format!("target identity is planned at both {other} and {path}"),
            );
        }
    }
    Ok(())
}

async fn publish_index_component(
    db: &DatabaseConnection,
    planned: &[PlannedCandidate],
) -> MicrosandboxResult<()> {
    let transaction = db.begin().await?;
    for candidate in planned {
        revalidate_planned_candidate(candidate)?;
        let path = candidate.hashed.pinned.path.display().to_string();
        transaction
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "DELETE FROM snapshot_index WHERE digest = ? OR artifact_path = ?",
                [
                    candidate.hashed.pinned.source.source_digest.clone().into(),
                    path.clone().into(),
                ],
            ))
            .await?;
        insert_canonical_index_row(&transaction, candidate).await?;
        transaction
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE snapshot_artifact_migration SET phase = 'index_published', updated_at = ? WHERE kind = ? AND artifact_path = ?",
                [
                    Utc::now().naive_utc().into(),
                    MIGRATION_KIND.into(),
                    path.into(),
                ],
            ))
            .await?;
    }
    transaction
        .execute_unprepared(
            "UPDATE snapshot_index SET child_count = (SELECT COUNT(*) FROM snapshot_index child WHERE child.parent_digest = snapshot_index.digest)",
        )
        .await?;
    transaction.commit().await?;
    Ok(())
}

fn revalidate_planned_candidate(candidate: &PlannedCandidate) -> MicrosandboxResult<()> {
    if file_identity(&candidate.hashed.pinned.payload)? != candidate.hashed.pinned.payload_before {
        return migration_error(
            "legacy_descriptor_changed_during_migration",
            "descriptor_published",
            &candidate.hashed.pinned.path,
            "payload identity changed before index publication",
        );
    }
    #[cfg(unix)]
    let (source, target) = {
        let mut source = openat_file(
            &candidate.hashed.pinned.directory,
            V066_DESCRIPTOR_FILENAME,
            libc::O_RDONLY | libc::O_NOFOLLOW,
            0,
        )?;
        let mut target = openat_file(
            &candidate.hashed.pinned.directory,
            DESCRIPTOR_FILENAME,
            libc::O_RDONLY | libc::O_NOFOLLOW,
            0,
        )?;
        let mut source_bytes = Vec::new();
        let mut target_bytes = Vec::new();
        source.read_to_end(&mut source_bytes)?;
        target.read_to_end(&mut target_bytes)?;
        (source_bytes, target_bytes)
    };
    #[cfg(not(unix))]
    let (source, target) = (
        std::fs::read(candidate.hashed.pinned.path.join(V066_DESCRIPTOR_FILENAME))?,
        std::fs::read(candidate.hashed.pinned.path.join(DESCRIPTOR_FILENAME))?,
    );
    if source != candidate.hashed.pinned.source_bytes || target != candidate.target_bytes {
        return migration_error(
            "legacy_descriptor_changed_during_migration",
            "descriptor_published",
            &candidate.hashed.pinned.path,
            "source or target descriptor changed before index publication",
        );
    }
    Ok(())
}

async fn insert_canonical_index_row<C>(
    db: &C,
    candidate: &PlannedCandidate,
) -> MicrosandboxResult<()>
where
    C: ConnectionTrait,
{
    let created_at = chrono::DateTime::parse_from_rfc3339(&candidate.target.created_at)
        .map_err(|error| MicrosandboxError::SnapshotMigration {
            code: "legacy_descriptor_malformed".into(),
            phase: "index_published".into(),
            artifact: candidate.hashed.pinned.path.display().to_string(),
            detail: bounded_detail(error.to_string()),
        })?
        .naive_utc();
    let SnapshotState::File(file) = &candidate.target.state else {
        unreachable!("v0.6.6 translation always produces file state")
    };
    let format = match file.format {
        microsandbox_image::snapshot::SnapshotFormat::Raw => "raw",
        microsandbox_image::snapshot::SnapshotFormat::Qcow2 => "qcow2",
    };
    let name = candidate
        .hashed
        .pinned
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string);
    db.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT INTO snapshot_index (digest, name, parent_digest, scope, state_kind, image_ref, image_manifest_digest, format, fstype, checkpoint_manifest_digest, artifact_path, size_bytes, locality, storage_binding_id, availability, migration_state, migration_error_code, created_at, indexed_at, child_count) VALUES (?, ?, ?, 'disk', 'file', ?, ?, ?, ?, NULL, ?, ?, 'embedded', NULL, 'ready', 'complete', NULL, ?, ?, 0)",
        [
            candidate.target_digest.clone().into(),
            name.into(),
            candidate.target_parent_digest.clone().into(),
            candidate.target.image.reference.clone().into(),
            candidate.target.image.manifest_digest.clone().into(),
            format.into(),
            file.fstype.clone().into(),
            candidate.hashed.pinned.path.display().to_string().into(),
            i64::try_from(file.upper.size_bytes)
                .map_err(|_| MicrosandboxError::SnapshotIntegrity("snapshot size does not fit SQLite".into()))?
                .into(),
            created_at.into(),
            Utc::now().naive_utc().into(),
        ],
    ))
    .await?;
    Ok(())
}

async fn journal_discovered(
    db: &DatabaseConnection,
    candidate: &PinnedCandidate,
) -> MicrosandboxResult<()> {
    let now = Utc::now().naive_utc();
    let path = candidate.path.display().to_string();
    db.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT INTO snapshot_artifact_migration (kind, artifact_path, source_digest, source_parent_digest, phase, attempts, discovered_at, updated_at) VALUES (?, ?, ?, ?, 'discovered', 1, ?, ?) ON CONFLICT(kind, artifact_path) DO UPDATE SET attempts = attempts + 1, updated_at = excluded.updated_at, error_code = NULL, error_detail = NULL",
        [
            MIGRATION_KIND.into(),
            path.into(),
            candidate.source.source_digest.clone().into(),
            candidate.source.parent_digest.clone().into(),
            now.into(),
            now.into(),
        ],
    ))
    .await?;
    Ok(())
}

async fn journal_planned(
    db: &DatabaseConnection,
    candidate: &PlannedCandidate,
) -> MicrosandboxResult<()> {
    let file_identity = format_file_identity(&candidate.hashed.pinned.payload_before);
    db.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "UPDATE snapshot_artifact_migration SET target_digest = ?, target_parent_digest = ?, payload_integrity = ?, payload_size = ?, payload_file_identity = ?, phase = 'planned', updated_at = ?, error_code = NULL, error_detail = NULL WHERE kind = ? AND artifact_path = ?",
        [
            candidate.target_digest.clone().into(),
            candidate.target_parent_digest.clone().into(),
            candidate.hashed.payload.sparse_integrity.digest.clone().into(),
            i64::try_from(candidate.hashed.payload.size_bytes)
                .map_err(|_| MicrosandboxError::SnapshotIntegrity("snapshot size does not fit SQLite".into()))?
                .into(),
            file_identity.into(),
            Utc::now().naive_utc().into(),
            MIGRATION_KIND.into(),
            candidate.hashed.pinned.path.display().to_string().into(),
        ],
    ))
    .await?;
    Ok(())
}

async fn journal_phase(
    db: &DatabaseConnection,
    path: &Path,
    phase: &str,
) -> MicrosandboxResult<()> {
    db.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "UPDATE snapshot_artifact_migration SET phase = ?, updated_at = ? WHERE kind = ? AND artifact_path = ?",
        [
            phase.into(),
            Utc::now().naive_utc().into(),
            MIGRATION_KIND.into(),
            path.display().to_string().into(),
        ],
    ))
    .await?;
    Ok(())
}

async fn journal_complete(db: &DatabaseConnection, path: &Path) -> MicrosandboxResult<()> {
    let now = Utc::now().naive_utc();
    db.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "UPDATE snapshot_artifact_migration SET phase = 'complete', updated_at = ?, completed_at = ?, error_code = NULL, error_detail = NULL WHERE kind = ? AND artifact_path = ?",
        [
            now.into(),
            now.into(),
            MIGRATION_KIND.into(),
            path.display().to_string().into(),
        ],
    ))
    .await?;
    Ok(())
}

async fn mark_completed_if_journaled(
    db: &DatabaseConnection,
    path: &Path,
) -> MicrosandboxResult<()> {
    journal_complete(db, path).await
}

async fn record_blocked_path(
    db: &DatabaseConnection,
    path: &Path,
    error: &MicrosandboxError,
) -> MicrosandboxResult<()> {
    let (code, phase, detail) = match error {
        MicrosandboxError::SnapshotMigration {
            code,
            phase,
            detail,
            ..
        } => (code.clone(), phase.clone(), detail.clone()),
        _ => (
            "legacy_migration_io".into(),
            "discovered".into(),
            bounded_detail(error.to_string()),
        ),
    };
    let now = Utc::now().naive_utc();
    db.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT INTO snapshot_artifact_migration (kind, artifact_path, phase, attempts, error_code, error_detail, discovered_at, updated_at) VALUES (?, ?, ?, 1, ?, ?, ?, ?) ON CONFLICT(kind, artifact_path) DO UPDATE SET attempts = attempts + 1, phase = excluded.phase, error_code = excluded.error_code, error_detail = excluded.error_detail, updated_at = excluded.updated_at",
        [
            MIGRATION_KIND.into(),
            path.display().to_string().into(),
            phase.into(),
            code.clone().into(),
            bounded_detail(detail).into(),
            now.into(),
            now.into(),
        ],
    ))
    .await?;
    db.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "UPDATE snapshot_index SET migration_state = 'blocked', migration_error_code = ? WHERE artifact_path = ?",
        [code.into(), path.display().to_string().into()],
    ))
    .await?;
    Ok(())
}

async fn load_blocked_error(
    db: &DatabaseConnection,
    path: &Path,
) -> MicrosandboxResult<MicrosandboxError> {
    let row = db
        .query_one(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT phase, error_code, error_detail FROM snapshot_artifact_migration WHERE kind = ? AND artifact_path = ?",
            [
                MIGRATION_KIND.into(),
                path.display().to_string().into(),
            ],
        ))
        .await?;
    let Some(row) = row else {
        return Ok(MicrosandboxError::SnapshotMigration {
            code: "legacy_migration_recovery_required".into(),
            phase: "discovered".into(),
            artifact: path.display().to_string(),
            detail: "legacy artifact did not reach canonical publication".into(),
        });
    };
    Ok(MicrosandboxError::SnapshotMigration {
        phase: row.try_get_by_index::<String>(0)?,
        code: row
            .try_get_by_index::<Option<String>>(1)?
            .unwrap_or_else(|| "legacy_migration_recovery_required".into()),
        detail: row
            .try_get_by_index::<Option<String>>(2)?
            .unwrap_or_else(|| "legacy artifact migration is blocked".into()),
        artifact: path.display().to_string(),
    })
}

//--------------------------------------------------------------------------------------------------
// Functions: File Integrity and Confinement
//--------------------------------------------------------------------------------------------------

fn hash_payload(file: &mut File) -> MicrosandboxResult<V066PayloadIdentity> {
    let len = file.metadata()?.len();
    let mut sparse = Sha256::new();
    sparse.update(b"msb-sparse-sha256-v1\0");
    sparse.update(len.to_le_bytes());
    let mut ordinary = Sha256::new();

    match ExtentMap::scan_file(file)? {
        Some(map) => {
            let mut offset = 0;
            for (start, extent_len) in map.extents {
                if start > offset {
                    hash_zeroes(start - offset, &mut sparse, &mut ordinary);
                }
                hash_extent(file, start, extent_len, &mut sparse, &mut ordinary)?;
                offset = start + extent_len;
            }
            if offset < len {
                hash_zeroes(len - offset, &mut sparse, &mut ordinary);
            }
        }
        None => {
            file.seek(SeekFrom::Start(0))?;
            let mut buffer = vec![0; 1024 * 1024];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                sparse.update(&buffer[..read]);
                ordinary.update(&buffer[..read]);
            }
        }
    }

    Ok(V066PayloadIdentity {
        size_bytes: len,
        sparse_integrity: UpperIntegrity {
            algorithm: SPARSE_SHA256_V1.into(),
            digest: format!("sha256:{}", hex::encode(sparse.finalize())),
        },
        sha256: format!("sha256:{}", hex::encode(ordinary.finalize())),
    })
}

fn hash_extent(
    file: &mut File,
    offset: u64,
    len: u64,
    sparse: &mut Sha256,
    ordinary: &mut Sha256,
) -> std::io::Result<()> {
    let mut buffer = vec![0; 1024 * 1024];
    let mut consumed = 0;
    file.seek(SeekFrom::Start(offset))?;
    while consumed < len {
        let wanted = (len - consumed).min(buffer.len() as u64) as usize;
        let read = file.read(&mut buffer[..wanted])?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "payload truncated while hashing",
            ));
        }
        sparse.update(&buffer[..read]);
        ordinary.update(&buffer[..read]);
        consumed += read as u64;
    }
    Ok(())
}

fn hash_zeroes(mut len: u64, sparse: &mut Sha256, ordinary: &mut Sha256) {
    static ZEROES: [u8; 1024 * 1024] = [0; 1024 * 1024];
    while len > 0 {
        let chunk = len.min(ZEROES.len() as u64) as usize;
        sparse.update(&ZEROES[..chunk]);
        ordinary.update(&ZEROES[..chunk]);
        len -= chunk as u64;
    }
}

fn file_identity(file: &File) -> MicrosandboxResult<FileIdentity> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(MicrosandboxError::SnapshotMigration {
            code: "legacy_payload_not_regular".into(),
            phase: "discovered".into(),
            artifact: "legacy payload".into(),
            detail: "payload handle is not a regular file".into(),
        });
    }
    Ok(FileIdentity {
        len: metadata.len(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        modified_seconds: metadata.mtime(),
        #[cfg(unix)]
        modified_nanos: metadata.mtime_nsec(),
        #[cfg(unix)]
        changed_seconds: metadata.ctime(),
        #[cfg(unix)]
        changed_nanos: metadata.ctime_nsec(),
    })
}

#[cfg(unix)]
fn open_directory_nofollow(path: &Path) -> MicrosandboxResult<File> {
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        MicrosandboxError::InvalidConfig("snapshot path contains a NUL byte".into())
    })?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn openat_file(directory: &File, name: &str, flags: i32, mode: u32) -> MicrosandboxResult<File> {
    let name = std::ffi::CString::new(name)
        .map_err(|_| MicrosandboxError::InvalidConfig("snapshot filename contains NUL".into()))?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn renameat(directory: &File, source: &str, target: &str) -> MicrosandboxResult<()> {
    let source = std::ffi::CString::new(source)
        .map_err(|_| MicrosandboxError::InvalidConfig("snapshot filename contains NUL".into()))?;
    let target = std::ffi::CString::new(target)
        .map_err(|_| MicrosandboxError::InvalidConfig("snapshot filename contains NUL".into()))?;
    let result = unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            target.as_ptr(),
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(unix)]
fn require_regular_bounded(
    file: &File,
    max_size: u64,
    kind: &str,
    artifact: &Path,
) -> MicrosandboxResult<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return migration_error(
            "legacy_descriptor_malformed",
            "discovered",
            artifact,
            format!("{kind} is not a regular file"),
        );
    }
    if metadata.len() > max_size {
        return migration_error(
            "legacy_descriptor_malformed",
            "discovered",
            artifact,
            format!("{kind} exceeds {max_size} bytes"),
        );
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Error Helpers
//--------------------------------------------------------------------------------------------------

fn migration_error<T>(
    code: &str,
    phase: &str,
    artifact: &Path,
    detail: impl Into<String>,
) -> MicrosandboxResult<T> {
    Err(MicrosandboxError::SnapshotMigration {
        code: code.into(),
        phase: phase.into(),
        artifact: artifact.display().to_string(),
        detail: bounded_detail(detail.into()),
    })
}

fn classify_legacy_error(message: &str) -> &'static str {
    [
        "unsupported_legacy_schema",
        "unsupported_legacy_layout",
        "legacy_descriptor_malformed",
        "legacy_integrity_unsupported",
        "legacy_payload_size_mismatch",
    ]
    .into_iter()
    .find(|code| message.contains(code))
    .unwrap_or("legacy_descriptor_malformed")
}

fn bounded_detail(mut detail: String) -> String {
    const LIMIT: usize = 1024;
    if detail.len() > LIMIT {
        detail.truncate(LIMIT);
    }
    detail
}

fn format_file_identity(identity: &FileIdentity) -> String {
    #[cfg(unix)]
    {
        format!(
            "dev={};ino={};len={};mtime={}.{};ctime={}.{}",
            identity.device,
            identity.inode,
            identity.len,
            identity.modified_seconds,
            identity.modified_nanos,
            identity.changed_seconds,
            identity.changed_nanos
        )
    }
    #[cfg(not(unix))]
    {
        format!("len={}", identity.len)
    }
}
