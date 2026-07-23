//! Internal adjacent-release snapshot downgrade coordination.
//!
//! This module is public only so the workspace CLI can coordinate snapshot
//! artifacts with its database and binary rollback. It is not a general
//! snapshot conversion API.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use chrono::Utc;
use microsandbox_image::snapshot::migration::{
    V066_BACKUP_FILENAME, V066_DESCRIPTOR_FILENAME, inspect_v066_source, translate_v066_reverse,
};
use microsandbox_image::snapshot::{DESCRIPTOR_FILENAME, Manifest, SnapshotState};
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement, TransactionTrait};
use serde::Serialize;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const FORWARD_KIND: &str = "v0.6.6-manifest-to-snapshot-v1";
const REVERSE_KIND: &str = "v0.6.7-snapshot-to-v0.6.6-manifest";
const MIGRATION_LOCK_FILENAME: &str = ".snapshot-migration.lock";
const MAX_DESCRIPTOR_BYTES: u64 = 1024 * 1024;
const MAX_PARENT_DEPTH: usize = 128;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Summary returned to the workspace CLI after reverse publication.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DowngradeReport {
    /// Number of retained artifacts represented in v0.6.6 form.
    pub artifacts: usize,
}

/// In-memory result of a complete retained-graph downgrade preflight.
///
/// The private fields keep descriptor translation internal while allowing the
/// CLI to place its durable operation boundary between planning and mutation.
pub struct DowngradePlan {
    candidates: Vec<Candidate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TranslationSource {
    ExactBackup,
    Native,
    AlreadyLegacy,
}

impl TranslationSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::ExactBackup => "exact_backup",
            Self::Native => "native_final",
            Self::AlreadyLegacy => "already_legacy",
        }
    }
}

struct Candidate {
    path: PathBuf,
    indexed_digest: Option<String>,
    source_digest: String,
    source_parent_digest: Option<String>,
    source_bytes: Option<Vec<u8>>,
    source: Option<Manifest>,
    target_bytes: Option<Vec<u8>>,
    target_digest: Option<String>,
    target_parent_digest: Option<String>,
    translation_source: TranslationSource,
    recovery_member: Option<String>,
    _lock: ArtifactLock,
}

struct ArtifactLock {
    #[cfg(unix)]
    file: File,
}

#[derive(Debug)]
struct ForwardJournal {
    source_digest: String,
    target_digest: String,
    source_parent_digest: Option<String>,
    target_parent_digest: Option<String>,
    phase: String,
}

#[derive(Debug)]
struct ReverseJournal {
    source_digest: Option<String>,
    target_digest: Option<String>,
    target_parent_digest: Option<String>,
    phase: String,
    translation_source: Option<String>,
}

#[derive(Serialize)]
struct RecoveryIndexEntry<'a> {
    artifact_path: String,
    indexed_digest: &'a Option<String>,
    source_digest: &'a str,
    source_parent_digest: &'a Option<String>,
    target_digest: &'a Option<String>,
    target_parent_digest: &'a Option<String>,
    translation_source: &'static str,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ArtifactLock {
    fn acquire(path: &Path) -> MicrosandboxResult<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return downgrade_error(
                path,
                "discovered",
                "artifact path is not a non-link directory",
            );
        }

        #[cfg(unix)]
        {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path.join(MIGRATION_LOCK_FILENAME))?;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return downgrade_error(
                    path,
                    "discovered",
                    format!("lock artifact: {}", std::io::Error::last_os_error()),
                );
            }
            Ok(Self { file })
        }

        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }
}

#[cfg(unix)]
impl Drop for ArtifactLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Reverse every retained managed artifact into the v0.6.6 descriptor and
/// index shape before the CLI rolls the database schema back.
///
/// The operation is resumable through `snapshot_artifact_migration`. Canonical
/// descriptors are copied into `recovery_dir` before legacy publication, so a
/// failed binary downgrade never relies on files inside the artifact directory
/// that the v0.6.6 exporter does not understand.
pub async fn reverse_managed_v066(
    db: &DatabaseConnection,
    snapshots_dir: &Path,
    recovery_dir: &Path,
) -> MicrosandboxResult<DowngradeReport> {
    let plan = preflight_managed_v066(db, snapshots_dir).await?;
    execute_managed_v066(db, recovery_dir, plan).await
}

/// Preflight the complete retained graph and durably record every planned
/// per-artifact identity without publishing any legacy descriptor or index.
pub async fn preflight_managed_v066(
    db: &DatabaseConnection,
    snapshots_dir: &Path,
) -> MicrosandboxResult<DowngradePlan> {
    let paths = discover_paths(db, snapshots_dir).await?;
    let mut candidates = Vec::with_capacity(paths.len());
    for path in paths {
        candidates.push(load_candidate(db, path).await?);
    }

    plan_graph(&mut candidates)?;
    preflight_index(db, &candidates).await?;
    journal_plans(db, &candidates).await?;

    Ok(DowngradePlan { candidates })
}

/// Execute a previously completed preflight through canonical backup, legacy
/// descriptor publication, one index-graph commit, and canonical retirement.
pub async fn execute_managed_v066(
    db: &DatabaseConnection,
    recovery_dir: &Path,
    plan: DowngradePlan,
) -> MicrosandboxResult<DowngradeReport> {
    let candidates = plan.candidates;
    backup_canonical_descriptors(db, recovery_dir, &candidates).await?;
    publish_legacy_descriptors(db, &candidates).await?;
    publish_legacy_index(db, &candidates).await?;
    retire_canonical_descriptors(db, &candidates).await?;

    Ok(DowngradeReport {
        artifacts: candidates.len(),
    })
}

async fn discover_paths(
    db: &DatabaseConnection,
    snapshots_dir: &Path,
) -> MicrosandboxResult<BTreeSet<PathBuf>> {
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

    if snapshots_dir.exists() {
        let mut entries = tokio::fs::read_dir(snapshots_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let visible = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| !name.starts_with('.'));
            if visible && entry.file_type().await?.is_dir() {
                paths.insert(path);
            }
        }
    }
    Ok(paths)
}

async fn load_candidate(db: &DatabaseConnection, path: PathBuf) -> MicrosandboxResult<Candidate> {
    let lock = ArtifactLock::acquire(&path)?;
    let indexed_digest = indexed_digest(db, &path).await?;
    let reverse = reverse_journal(db, &path).await?;
    let canonical_path = path.join(DESCRIPTOR_FILENAME);
    let legacy_path = path.join(V066_DESCRIPTOR_FILENAME);
    let backup_path = path.join(V066_BACKUP_FILENAME);

    if canonical_path.exists() {
        let source_bytes = read_regular_bounded(&canonical_path, "canonical descriptor")?;
        let source = Manifest::from_bytes(&source_bytes).map_err(|error| {
            MicrosandboxError::SnapshotMigration {
                code: "snapshot_downgrade_unrepresentable".into(),
                phase: "preflight".into(),
                artifact: path.display().to_string(),
                detail: error.to_string(),
            }
        })?;
        validate_payload(&path, &source)?;
        let source_digest = source.digest()?;
        if let Some(indexed) = indexed_digest.as_deref()
            && indexed != source_digest
            && reverse
                .as_ref()
                .and_then(|row| row.target_digest.as_deref())
                != Some(indexed)
        {
            return downgrade_error(
                &path,
                "preflight",
                format!(
                    "index digest {indexed} does not match canonical descriptor {source_digest}"
                ),
            );
        }

        let forward = forward_journal(db, &path).await?;
        let (translation_source, target_bytes, target_digest, target_parent_digest) =
            if backup_path.exists() {
                let backup = read_regular_bounded(&backup_path, "legacy backup")?;
                let info = inspect_v066_source(&backup).map_err(|error| {
                    MicrosandboxError::SnapshotMigration {
                        code: "snapshot_downgrade_recovery_required".into(),
                        phase: "preflight".into(),
                        artifact: path.display().to_string(),
                        detail: error.to_string(),
                    }
                })?;
                let Some(forward) = forward else {
                    return downgrade_error(
                        &path,
                        "preflight",
                        "legacy backup is not covered by a completed forward journal",
                    );
                };
                if forward.phase != "complete"
                    || forward.source_digest != info.source_digest
                    || forward.target_digest != source_digest
                    || forward.source_parent_digest != info.parent_digest
                    || forward.target_parent_digest != source.parent
                {
                    return downgrade_error(
                        &path,
                        "preflight",
                        "legacy backup does not match the completed forward journal",
                    );
                }
                (
                    TranslationSource::ExactBackup,
                    Some(backup),
                    Some(info.source_digest),
                    info.parent_digest,
                )
            } else if legacy_path.exists() {
                let Some(reverse) = reverse.as_ref() else {
                    return downgrade_error(
                        &path,
                        "preflight",
                        "manifest.json is visible beside snapshot.json without a reverse journal",
                    );
                };
                let legacy = read_regular_bounded(&legacy_path, "legacy descriptor")?;
                let info = inspect_v066_source(&legacy).map_err(|error| {
                    MicrosandboxError::SnapshotMigration {
                        code: "snapshot_downgrade_recovery_required".into(),
                        phase: "preflight".into(),
                        artifact: path.display().to_string(),
                        detail: error.to_string(),
                    }
                })?;
                if reverse.source_digest.as_deref() != Some(source_digest.as_str())
                    || reverse.target_digest.as_deref() != Some(info.source_digest.as_str())
                    || reverse.target_parent_digest != info.parent_digest
                {
                    return downgrade_error(
                        &path,
                        "preflight",
                        "published legacy descriptor does not match its reverse journal",
                    );
                }
                let source = match reverse.translation_source.as_deref() {
                    Some("exact_backup") => TranslationSource::ExactBackup,
                    Some("native_final") => TranslationSource::Native,
                    _ => {
                        return downgrade_error(
                            &path,
                            "preflight",
                            "reverse journal has an unknown translation source",
                        );
                    }
                };
                (
                    source,
                    Some(legacy),
                    Some(info.source_digest),
                    info.parent_digest,
                )
            } else {
                (TranslationSource::Native, None, None, None)
            };

        let recovery_member = Some(format!(
            "{}.snapshot.json",
            source_digest
                .strip_prefix("sha256:")
                .unwrap_or(&source_digest)
        ));
        return Ok(Candidate {
            path,
            indexed_digest,
            source_digest,
            source_parent_digest: source.parent.clone(),
            source_bytes: Some(source_bytes),
            source: Some(source),
            target_bytes,
            target_digest,
            target_parent_digest,
            translation_source,
            recovery_member,
            _lock: lock,
        });
    }

    if legacy_path.exists() {
        let target_bytes = read_regular_bounded(&legacy_path, "legacy descriptor")?;
        let info = inspect_v066_source(&target_bytes).map_err(|error| {
            MicrosandboxError::SnapshotMigration {
                code: "snapshot_downgrade_recovery_required".into(),
                phase: "preflight".into(),
                artifact: path.display().to_string(),
                detail: error.to_string(),
            }
        })?;
        if let Some(reverse) = reverse.as_ref()
            && let Some(target) = reverse.target_digest.as_deref()
            && target != info.source_digest
        {
            return downgrade_error(
                &path,
                "preflight",
                "published legacy descriptor does not match its reverse journal",
            );
        }
        if let Some(reverse) = reverse.as_ref()
            && reverse.target_parent_digest != info.parent_digest
        {
            return downgrade_error(
                &path,
                "preflight",
                "published legacy parent does not match its reverse journal",
            );
        }
        let source_digest = reverse
            .as_ref()
            .and_then(|row| row.source_digest.clone())
            .unwrap_or_else(|| info.source_digest.clone());
        let source_parent_digest = None;
        let translation_source = match reverse
            .as_ref()
            .and_then(|row| row.translation_source.as_deref())
        {
            Some("exact_backup") => TranslationSource::ExactBackup,
            Some("native_final") => TranslationSource::Native,
            _ => TranslationSource::AlreadyLegacy,
        };
        return Ok(Candidate {
            path,
            indexed_digest,
            source_digest,
            source_parent_digest,
            source_bytes: None,
            source: None,
            target_bytes: Some(target_bytes),
            target_digest: Some(info.source_digest),
            target_parent_digest: info.parent_digest,
            translation_source,
            recovery_member: None,
            _lock: lock,
        });
    }

    Err(MicrosandboxError::SnapshotMigration {
        code: "snapshot_downgrade_recovery_required".into(),
        phase: reverse
            .as_ref()
            .map(|row| row.phase.clone())
            .unwrap_or_else(|| "preflight".into()),
        artifact: path.display().to_string(),
        detail: "indexed or managed artifact has neither snapshot.json nor manifest.json".into(),
    })
}

fn plan_graph(candidates: &mut [Candidate]) -> MicrosandboxResult<()> {
    let mut by_source = HashMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if by_source
            .insert(candidate.source_digest.clone(), index)
            .is_some()
        {
            return downgrade_error(
                &candidate.path,
                "preflight",
                "multiple retained artifacts have the same canonical identity",
            );
        }
    }

    let mut visiting = HashSet::new();
    let mut complete = HashSet::new();
    for index in 0..candidates.len() {
        visit_candidate(
            index,
            candidates,
            &by_source,
            &mut visiting,
            &mut complete,
            0,
        )?;
    }

    let mut targets = HashMap::new();
    for candidate in candidates {
        let target = candidate
            .target_digest
            .as_ref()
            .expect("graph planning assigns every target digest");
        if let Some(other) = targets.insert(target.clone(), candidate.path.clone())
            && other != candidate.path
        {
            return downgrade_error(
                &candidate.path,
                "preflight",
                format!("legacy identity collides with {}", other.display()),
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn visit_candidate(
    index: usize,
    candidates: &mut [Candidate],
    by_source: &HashMap<String, usize>,
    visiting: &mut HashSet<usize>,
    complete: &mut HashSet<usize>,
    depth: usize,
) -> MicrosandboxResult<String> {
    if complete.contains(&index) {
        return Ok(candidates[index]
            .target_digest
            .clone()
            .expect("completed candidate has a target digest"));
    }
    if depth > MAX_PARENT_DEPTH {
        return downgrade_error(
            &candidates[index].path,
            "preflight",
            "snapshot parent graph exceeds the traversal limit",
        );
    }
    if !visiting.insert(index) {
        return downgrade_error(
            &candidates[index].path,
            "preflight",
            "snapshot parent graph contains a cycle",
        );
    }

    let mapped_parent = match candidates[index].source_parent_digest.clone() {
        None => None,
        Some(parent) => {
            let Some(parent_index) = by_source.get(&parent).copied() else {
                return downgrade_error(
                    &candidates[index].path,
                    "preflight",
                    format!("retained parent {parent} is missing from the managed graph"),
                );
            };
            Some(visit_candidate(
                parent_index,
                candidates,
                by_source,
                visiting,
                complete,
                depth + 1,
            )?)
        }
    };

    match candidates[index].translation_source {
        TranslationSource::Native => {
            if let Some(source) = candidates[index].source.as_ref() {
                let translated =
                    translate_v066_reverse(source, mapped_parent.clone()).map_err(|error| {
                        MicrosandboxError::SnapshotMigration {
                            code: "snapshot_downgrade_unrepresentable".into(),
                            phase: "preflight".into(),
                            artifact: candidates[index].path.display().to_string(),
                            detail: error.to_string(),
                        }
                    })?;
                candidates[index].target_bytes = Some(translated.target_bytes);
                candidates[index].target_digest = Some(translated.target_digest);
                candidates[index].target_parent_digest = mapped_parent;
            }
        }
        TranslationSource::ExactBackup => {
            if candidates[index].target_parent_digest != mapped_parent {
                return downgrade_error(
                    &candidates[index].path,
                    "preflight",
                    "exact legacy backup parent does not match the reverse graph mapping",
                );
            }
        }
        TranslationSource::AlreadyLegacy => {
            // Already-legacy nodes identify their graph in the target digest
            // namespace, so no canonical parent rewrite is needed.
        }
    }

    if candidates[index].target_digest.is_none() || candidates[index].target_bytes.is_none() {
        return downgrade_error(
            &candidates[index].path,
            "preflight",
            "reverse journal is incomplete and the canonical descriptor is unavailable",
        );
    }
    visiting.remove(&index);
    complete.insert(index);
    Ok(candidates[index].target_digest.clone().unwrap())
}

async fn preflight_index(
    db: &DatabaseConnection,
    candidates: &[Candidate],
) -> MicrosandboxResult<()> {
    let known_paths: HashSet<String> = candidates
        .iter()
        .map(|candidate| candidate.path.display().to_string())
        .collect();
    let rows = db
        .query_all(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT digest, artifact_path, state_kind, scope, format, fstype FROM snapshot_index",
        ))
        .await?;
    for row in rows {
        let path = row.try_get_by_index::<String>(1)?;
        if !known_paths.contains(&path) {
            return downgrade_error(
                Path::new(&path),
                "preflight",
                "indexed artifact was omitted from the complete managed graph",
            );
        }
        let state_kind = row.try_get_by_index::<String>(2)?;
        let scope = row.try_get_by_index::<String>(3)?;
        let format = row.try_get_by_index::<Option<String>>(4)?;
        let fstype = row.try_get_by_index::<Option<String>>(5)?;
        if state_kind != "file"
            || scope != "disk"
            || format.as_deref() != Some("raw")
            || fstype.as_deref() != Some("ext4")
        {
            return downgrade_error(
                Path::new(&path),
                "preflight",
                "snapshot index row is not representable by v0.6.6",
            );
        }
    }
    Ok(())
}

async fn journal_plans(
    db: &DatabaseConnection,
    candidates: &[Candidate],
) -> MicrosandboxResult<()> {
    let now = Utc::now().naive_utc();
    for candidate in candidates {
        db.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO snapshot_artifact_migration (kind, artifact_path, indexed_digest, source_digest, target_digest, source_parent_digest, target_parent_digest, phase, attempts, discovered_at, updated_at, recovery_member, translation_source) VALUES (?, ?, ?, ?, ?, ?, ?, 'reverse_planned', 1, ?, ?, ?, ?) ON CONFLICT(kind, artifact_path) DO UPDATE SET indexed_digest = excluded.indexed_digest, source_digest = COALESCE(snapshot_artifact_migration.source_digest, excluded.source_digest), target_digest = excluded.target_digest, source_parent_digest = COALESCE(snapshot_artifact_migration.source_parent_digest, excluded.source_parent_digest), target_parent_digest = excluded.target_parent_digest, attempts = snapshot_artifact_migration.attempts + 1, updated_at = excluded.updated_at, recovery_member = COALESCE(snapshot_artifact_migration.recovery_member, excluded.recovery_member), translation_source = COALESCE(snapshot_artifact_migration.translation_source, excluded.translation_source), error_code = NULL, error_detail = NULL",
            [
                REVERSE_KIND.into(),
                candidate.path.display().to_string().into(),
                candidate.indexed_digest.clone().into(),
                candidate.source_digest.clone().into(),
                candidate.target_digest.clone().into(),
                candidate.source_parent_digest.clone().into(),
                candidate.target_parent_digest.clone().into(),
                now.into(),
                now.into(),
                candidate.recovery_member.clone().into(),
                candidate.translation_source.as_str().into(),
            ],
        ))
        .await?;
    }
    Ok(())
}

async fn backup_canonical_descriptors(
    db: &DatabaseConnection,
    recovery_dir: &Path,
    candidates: &[Candidate],
) -> MicrosandboxResult<()> {
    std::fs::create_dir_all(recovery_dir)?;
    #[cfg(unix)]
    std::fs::set_permissions(
        recovery_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;

    let index_entries: Vec<_> = candidates
        .iter()
        .map(|candidate| RecoveryIndexEntry {
            artifact_path: candidate.path.display().to_string(),
            indexed_digest: &candidate.indexed_digest,
            source_digest: &candidate.source_digest,
            source_parent_digest: &candidate.source_parent_digest,
            target_digest: &candidate.target_digest,
            target_parent_digest: &candidate.target_parent_digest,
            translation_source: candidate.translation_source.as_str(),
        })
        .collect();
    let index_bytes = serde_json::to_vec_pretty(&index_entries).map_err(|error| {
        MicrosandboxError::Custom(format!("serialize snapshot recovery index: {error}"))
    })?;
    write_create_new_or_validate(&recovery_dir.join("snapshot-index.json"), &index_bytes)?;

    for candidate in candidates {
        let (Some(member), Some(bytes)) = (
            candidate.recovery_member.as_deref(),
            candidate.source_bytes.as_deref(),
        ) else {
            continue;
        };
        let path = recovery_dir.join(member);
        write_create_new_or_validate(&path, bytes)?;
        journal_phase(db, &candidate.path, "canonical_backed_up").await?;
    }
    sync_directory(recovery_dir)?;
    Ok(())
}

async fn publish_legacy_descriptors(
    db: &DatabaseConnection,
    candidates: &[Candidate],
) -> MicrosandboxResult<()> {
    for candidate in candidates {
        let target = candidate
            .target_bytes
            .as_deref()
            .expect("preflight assigns target bytes");
        let legacy = candidate.path.join(V066_DESCRIPTOR_FILENAME);
        if legacy.exists() {
            if read_regular_bounded(&legacy, "legacy descriptor")? != target {
                return downgrade_error(
                    &candidate.path,
                    "legacy_descriptor_published",
                    "an unexpected manifest.json blocks reverse publication",
                );
            }
        } else if candidate.translation_source == TranslationSource::ExactBackup {
            let backup = candidate.path.join(V066_BACKUP_FILENAME);
            if !backup.exists() || read_regular_bounded(&backup, "legacy backup")? != target {
                return downgrade_error(
                    &candidate.path,
                    "legacy_descriptor_published",
                    "the exact legacy backup is unavailable or changed",
                );
            }
            std::fs::rename(backup, &legacy)?;
        } else {
            let temp = candidate
                .path
                .join(format!(".manifest.json.downgrade.{}", std::process::id()));
            write_create_new_or_validate(&temp, target)?;
            std::fs::rename(temp, &legacy)?;
        }
        sync_directory(&candidate.path)?;
        journal_phase(db, &candidate.path, "legacy_descriptor_published").await?;
    }
    Ok(())
}

async fn publish_legacy_index(
    db: &DatabaseConnection,
    candidates: &[Candidate],
) -> MicrosandboxResult<()> {
    let transaction = db.begin().await?;
    for candidate in candidates {
        if candidate.indexed_digest.is_none() {
            continue;
        }
        let temporary = format!(
            "reverse:{}",
            candidate
                .source_digest
                .strip_prefix("sha256:")
                .unwrap_or(&candidate.source_digest)
        );
        transaction
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE snapshot_index SET digest = ? WHERE artifact_path = ?",
                [
                    temporary.into(),
                    candidate.path.display().to_string().into(),
                ],
            ))
            .await?;
    }
    for candidate in candidates {
        if candidate.indexed_digest.is_none() {
            continue;
        }
        transaction
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE snapshot_index SET digest = ?, parent_digest = ?, migration_state = 'reverse_complete', migration_error_code = NULL WHERE artifact_path = ?",
                [
                    candidate.target_digest.clone().into(),
                    candidate.target_parent_digest.clone().into(),
                    candidate.path.display().to_string().into(),
                ],
            ))
            .await?;
        transaction
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE snapshot_artifact_migration SET phase = 'legacy_index_published', updated_at = ? WHERE kind = ? AND artifact_path = ?",
                [
                    Utc::now().naive_utc().into(),
                    REVERSE_KIND.into(),
                    candidate.path.display().to_string().into(),
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

async fn retire_canonical_descriptors(
    db: &DatabaseConnection,
    candidates: &[Candidate],
) -> MicrosandboxResult<()> {
    for candidate in candidates {
        let canonical = candidate.path.join(DESCRIPTOR_FILENAME);
        match std::fs::remove_file(&canonical) {
            Ok(()) => sync_directory(&candidate.path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        journal_phase(db, &candidate.path, "reverse_complete").await?;
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

async fn indexed_digest(
    db: &DatabaseConnection,
    path: &Path,
) -> MicrosandboxResult<Option<String>> {
    let row = db
        .query_one(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT digest FROM snapshot_index WHERE artifact_path = ?",
            [path.display().to_string().into()],
        ))
        .await?;
    row.map(|row| row.try_get_by_index::<String>(0).map_err(Into::into))
        .transpose()
}

async fn forward_journal(
    db: &DatabaseConnection,
    path: &Path,
) -> MicrosandboxResult<Option<ForwardJournal>> {
    let row = db
        .query_one(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT source_digest, target_digest, source_parent_digest, target_parent_digest, phase FROM snapshot_artifact_migration WHERE kind = ? AND artifact_path = ?",
            [FORWARD_KIND.into(), path.display().to_string().into()],
        ))
        .await?;
    row.map(|row| {
        Ok(ForwardJournal {
            source_digest: row.try_get_by_index::<String>(0)?,
            target_digest: row.try_get_by_index::<String>(1)?,
            source_parent_digest: row.try_get_by_index::<Option<String>>(2)?,
            target_parent_digest: row.try_get_by_index::<Option<String>>(3)?,
            phase: row.try_get_by_index::<String>(4)?,
        })
    })
    .transpose()
}

async fn reverse_journal(
    db: &DatabaseConnection,
    path: &Path,
) -> MicrosandboxResult<Option<ReverseJournal>> {
    let row = db
        .query_one(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT source_digest, target_digest, target_parent_digest, phase, translation_source FROM snapshot_artifact_migration WHERE kind = ? AND artifact_path = ?",
            [REVERSE_KIND.into(), path.display().to_string().into()],
        ))
        .await?;
    row.map(|row| {
        Ok(ReverseJournal {
            source_digest: row.try_get_by_index::<Option<String>>(0)?,
            target_digest: row.try_get_by_index::<Option<String>>(1)?,
            target_parent_digest: row.try_get_by_index::<Option<String>>(2)?,
            phase: row.try_get_by_index::<String>(3)?,
            translation_source: row.try_get_by_index::<Option<String>>(4)?,
        })
    })
    .transpose()
}

async fn journal_phase(
    db: &DatabaseConnection,
    path: &Path,
    phase: &str,
) -> MicrosandboxResult<()> {
    db.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "UPDATE snapshot_artifact_migration SET phase = ?, updated_at = ?, completed_at = CASE WHEN ? = 'reverse_complete' THEN ? ELSE completed_at END WHERE kind = ? AND artifact_path = ?",
        [
            phase.into(),
            Utc::now().naive_utc().into(),
            phase.into(),
            Utc::now().naive_utc().into(),
            REVERSE_KIND.into(),
            path.display().to_string().into(),
        ],
    ))
    .await?;
    Ok(())
}

fn validate_payload(path: &Path, manifest: &Manifest) -> MicrosandboxResult<()> {
    let SnapshotState::File(file) = &manifest.state else {
        return downgrade_error(
            path,
            "preflight",
            "checkpoint state is not representable by v0.6.6",
        );
    };
    let payload_path = path.join(&file.upper.file);
    let metadata = std::fs::symlink_metadata(&payload_path).map_err(|error| {
        MicrosandboxError::SnapshotMigration {
            code: "snapshot_downgrade_unrepresentable".into(),
            phase: "preflight".into(),
            artifact: path.display().to_string(),
            detail: format!("payload {}: {error}", payload_path.display()),
        }
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return downgrade_error(path, "preflight", "payload is not a confined regular file");
    }
    if metadata.len() != file.upper.size_bytes {
        return downgrade_error(
            path,
            "preflight",
            format!(
                "payload size changed: descriptor={}, file={}",
                file.upper.size_bytes,
                metadata.len()
            ),
        );
    }
    let before_modified = metadata.modified().ok();
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let mut payload = options.open(&payload_path)?;
    let identity = super::migration::hash_payload(&mut payload)?;
    let after = payload.metadata()?;
    if after.len() != metadata.len() || after.modified().ok() != before_modified {
        return downgrade_error(
            path,
            "preflight",
            "payload changed while verifying integrity",
        );
    }
    if identity.sparse_integrity != file.upper.integrity {
        return downgrade_error(
            path,
            "preflight",
            "payload does not match its mandatory sparse integrity",
        );
    }
    Ok(())
}

fn read_regular_bounded(path: &Path, label: &str) -> MicrosandboxResult<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(MicrosandboxError::Custom(format!(
            "{label} is not a regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > MAX_DESCRIPTOR_BYTES {
        return Err(MicrosandboxError::Custom(format!(
            "{label} exceeds the size limit: {}",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn write_create_new_or_validate(path: &Path, bytes: &[u8]) -> MicrosandboxResult<()> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if std::fs::read(path)? == bytes {
                Ok(())
            } else {
                Err(MicrosandboxError::Custom(format!(
                    "recovery member collision: {}",
                    path.display()
                )))
            }
        }
        Err(error) => Err(error.into()),
    }
}

fn sync_directory(path: &Path) -> MicrosandboxResult<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    let _ = path;
    Ok(())
}

fn downgrade_error<T>(
    path: &Path,
    phase: &str,
    detail: impl Into<String>,
) -> MicrosandboxResult<T> {
    Err(MicrosandboxError::SnapshotMigration {
        code: "snapshot_downgrade_recovery_required".into(),
        phase: phase.into(),
        artifact: path.display().to_string(),
        detail: detail.into(),
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use microsandbox_db::pool::DbPools;
    use microsandbox_migration::{Migrator, MigratorTrait};
    use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

    use super::*;

    const LEGACY: &[u8] = br#"{"schema":1,"format":"raw","fstype":"ext4","image":{"ref":"docker.io/library/alpine:3.20","manifest_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"parent":null,"created_at":"2026-07-01T10:00:00Z","labels":{},"upper":{"file":"upper.ext4","size_bytes":5,"integrity":null},"source_sandbox":"box"}"#;

    #[tokio::test]
    async fn completed_forward_artifact_restores_exact_v066_bytes_and_index() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("msb.db");
        let snapshots = temp.path().join("snapshots");
        let artifact = snapshots.join("legacy");
        let recovery = temp.path().join("recovery");
        std::fs::create_dir_all(&artifact).unwrap();
        std::fs::write(artifact.join("upper.ext4"), b"hello").unwrap();
        std::fs::write(artifact.join(V066_DESCRIPTOR_FILENAME), LEGACY).unwrap();

        let pools = DbPools::open(&db_path, 2, Duration::from_secs(5), Duration::from_secs(5))
            .await
            .unwrap();
        Migrator::up(pools.write().inner(), None).await.unwrap();
        crate::snapshot::migration::reconcile_managed(&pools, &snapshots)
            .await
            .unwrap();

        let canonical = std::fs::read(artifact.join(DESCRIPTOR_FILENAME)).unwrap();
        let canonical_manifest = Manifest::from_bytes(&canonical).unwrap();
        let canonical_digest = canonical_manifest.digest().unwrap();
        assert_eq!(
            std::fs::read(artifact.join(V066_BACKUP_FILENAME)).unwrap(),
            LEGACY
        );

        let plan = preflight_managed_v066(pools.write().inner(), &snapshots)
            .await
            .unwrap();
        drop(plan);
        std::fs::rename(
            artifact.join(V066_BACKUP_FILENAME),
            artifact.join(V066_DESCRIPTOR_FILENAME),
        )
        .unwrap();
        journal_phase(
            pools.write().inner(),
            &artifact,
            "legacy_descriptor_published",
        )
        .await
        .unwrap();

        // Reconstruct the plan after a crash between exact descriptor
        // publication and the index-graph commit.
        let plan = preflight_managed_v066(pools.write().inner(), &snapshots)
            .await
            .unwrap();
        let report = execute_managed_v066(pools.write().inner(), &recovery, plan)
            .await
            .unwrap();
        assert_eq!(report.artifacts, 1);
        assert_eq!(
            std::fs::read(artifact.join(V066_DESCRIPTOR_FILENAME)).unwrap(),
            LEGACY
        );
        assert!(!artifact.join(DESCRIPTOR_FILENAME).exists());
        assert!(!artifact.join(V066_BACKUP_FILENAME).exists());
        assert_eq!(
            std::fs::read(recovery.join(format!(
                "{}.snapshot.json",
                canonical_digest.strip_prefix("sha256:").unwrap()
            )))
            .unwrap(),
            canonical
        );

        let row = pools
            .write()
            .inner()
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT digest, migration_state FROM snapshot_index",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.try_get_by_index::<String>(0).unwrap(),
            inspect_v066_source(LEGACY).unwrap().source_digest
        );
        assert_eq!(
            row.try_get_by_index::<String>(1).unwrap(),
            "reverse_complete"
        );

        Migrator::down(pools.write().inner(), Some(1))
            .await
            .unwrap();
        let count = pools
            .write()
            .inner()
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) FROM snapshot_index",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index::<i64>(0)
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn unrepresentable_native_descriptor_fails_before_publication() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("msb.db");
        let snapshots = temp.path().join("snapshots");
        let artifact = snapshots.join("native");
        std::fs::create_dir_all(&artifact).unwrap();
        std::fs::write(artifact.join("upper.ext4"), b"hello").unwrap();
        std::fs::write(artifact.join(V066_DESCRIPTOR_FILENAME), LEGACY).unwrap();

        let pools = DbPools::open(&db_path, 2, Duration::from_secs(5), Duration::from_secs(5))
            .await
            .unwrap();
        Migrator::up(pools.write().inner(), None).await.unwrap();
        crate::snapshot::migration::reconcile_managed(&pools, &snapshots)
            .await
            .unwrap();

        // Turn the migrated fixture into a native final artifact carrying a
        // final-only extension. With the exact backup and forward journal gone,
        // downgrade must assess the canonical descriptor itself and refuse the
        // complete graph before publishing manifest.json.
        std::fs::remove_file(artifact.join(V066_BACKUP_FILENAME)).unwrap();
        pools
            .write()
            .inner()
            .execute(Statement::from_string(
                DatabaseBackend::Sqlite,
                "DELETE FROM snapshot_artifact_migration",
            ))
            .await
            .unwrap();
        let mut manifest =
            Manifest::from_bytes(&std::fs::read(artifact.join(DESCRIPTOR_FILENAME)).unwrap())
                .unwrap();
        manifest.extensions.insert(
            "example.final-only".into(),
            serde_json::json!({"enabled": true}),
        );
        let canonical = manifest.to_canonical_bytes().unwrap();
        let digest = manifest.digest().unwrap();
        std::fs::write(artifact.join(DESCRIPTOR_FILENAME), canonical).unwrap();
        pools
            .write()
            .inner()
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::Sqlite,
                "UPDATE snapshot_index SET digest = ?, migration_state = 'canonical' WHERE artifact_path = ?",
                [digest.into(), artifact.display().to_string().into()],
            ))
            .await
            .unwrap();

        let error = preflight_managed_v066(pools.write().inner(), &snapshots)
            .await
            .err()
            .unwrap();

        assert!(
            error
                .to_string()
                .contains("snapshot_downgrade_unrepresentable")
        );
        assert!(artifact.join(DESCRIPTOR_FILENAME).exists());
        assert!(!artifact.join(V066_DESCRIPTOR_FILENAME).exists());
        let state = pools
            .write()
            .inner()
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT migration_state FROM snapshot_index",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index::<String>(0)
            .unwrap();
        assert_eq!(state, "canonical");
    }
}
