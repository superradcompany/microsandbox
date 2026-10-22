//! Local backend: Durable local snapshot namespaces and their explicitly selected heads.
//!
//! Group membership is represented by installed artifact directories. Only the head and each
//! member's optional local alias need metadata; immutable descriptors remain authoritative for
//! ancestry. All group operations share one process-held lock, acquired off the async executor.

mod capture;
mod inspection;
mod removal;
mod remove_history;
mod retirement;
mod transaction;

#[cfg(windows)]
mod txf;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod generation;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use microsandbox_image::snapshot::{
    DESCRIPTOR_FILENAME, MAX_DESCRIPTOR_BYTES, Manifest, SnapshotId,
};
use microsandbox_utils::process_lock;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};

use super::writer::WriterLease;
use crate::db::entity::sandbox;
use crate::{MicrosandboxError, MicrosandboxResult, SnapshotImportOutcome};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(crate) const GROUP_FILENAME: &str = "group.json";
const GROUP_SCHEMA: &str = "microsandbox.snapshot-group/1";
const CREATING_FILENAME: &str = ".group-creating";
const CREATING_SCHEMA: &str = "microsandbox.group-creation/1";
const MEMBER_FILENAME: &str = "group-member.json";
const MEMBER_SCHEMA: &str = "microsandbox.snapshot-group-member/1";
const MAX_METADATA_BYTES: usize = 4096;
const MAX_NAME_BYTES: usize = 128;
const MAX_ANCESTRY_DEPTH: usize = 65536;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub use crate::snapshot::{HeadUpdate, HeadUpdateReason};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupState {
    schema: String,
    head: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberMetadata {
    schema: String,
    name: String,
}

#[derive(Debug)]
struct Member {
    path: PathBuf,
    digest: String,
    parent: Option<String>,
    name: Option<String>,
}

/// A reserved destination whose first group metadata is published with its first batch.
/// Holding the existing root creation lock prevents another creator from claiming its name.
pub(super) struct ImportDestination {
    pub(super) directory: PathBuf,
    _creation_lock: Option<File>,
}

/// The caller can still report publication certainty if the blocking publisher fails.
/// Only the transaction writer advances this state, after all validation has passed.
pub(super) struct IndexedPublication {
    pub(super) operation: String,
    pub(super) outcome: Arc<AtomicU8>,
}

/// Facts recorded under publication ownership, before another writer can change the group.
pub(super) struct BatchPublication {
    pub(super) head_update: Option<HeadUpdate>,
    pub(super) added: Vec<SnapshotId>,
    pub(super) reused: Vec<SnapshotId>,
    pub(super) warnings: Vec<String>,
}

/// One member removal's immutable facts, captured before releasing publication ownership.
#[derive(Debug)]
pub(super) struct MemberRemoval {
    pub(super) head_update: HeadUpdate,
    pub(super) warnings: Vec<String>,
}

/// A committed filesystem view retained until all corresponding index rows commit.
pub(super) struct PendingIndex {
    _lock: File,
    directory: PathBuf,
    pub(super) snapshots: Vec<(PathBuf, String, Manifest)>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PendingIndex {
    pub(super) async fn finish(self) -> MicrosandboxResult<Vec<String>> {
        blocking(move || {
            let result = transaction::finish_index(&self.directory);
            drop(self); // Keep ownership through the durable acknowledgement and cleanup.
            result
        })
        .await
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn check_atomic_import(root: &Path) -> MicrosandboxResult<()> {
    #[cfg(windows)]
    {
        txf::check(root)
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        generation::check(root)
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    {
        Err(MicrosandboxError::InvalidConfig(format!(
            "atomic snapshot import is unavailable at {}: this platform has no qualified atomic publisher",
            root.display()
        )))
    }
}

/// Resolve a group head or a qualified group member; explicit paths belong to the caller.
pub(super) async fn resolve(root: &Path, selector: &str) -> MicrosandboxResult<PathBuf> {
    let root = root.to_path_buf();
    let selector = selector.to_owned();
    blocking(move || {
        let (name, member) = parse_selector(&selector)?;
        let directory = root.join(name);
        let _lock = lock_group(&directory).map_err(|error| match error {
            // A selector lookup has the same not-found contract as an explicit snapshot path.
            MicrosandboxError::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound => {
                MicrosandboxError::SnapshotNotFound(selector.clone())
            }
            other => other,
        })?;
        let state = read_group(&directory)?;
        let (id, _) = resolve_selected(&directory, &state, member)?;
        Ok(directory.join(id))
    })
    .await
}

/// Admit an explicit member path through its group's recovery barrier before pinning payloads.
pub(super) async fn recover_member(path: &Path) -> MicrosandboxResult<()> {
    if let Some(directory) = group_path(path) {
        blocking(move || {
            // Explicit artifact paths may reach an existing group through a symlink. Resolve
            // only the coordination directory so aliases share its lock; retain the caller's
            // artifact path and the stricter validation for named group selectors.
            let directory = fs::canonicalize(directory)?;
            let _lock = lock_recovery(&directory)?;
            if is_creating(&directory)? && !path_exists(&directory.join(GROUP_FILENAME))? {
                return Err(MicrosandboxError::SnapshotNotFound(format!(
                    "unpublished snapshot group {}",
                    directory.display()
                )));
            }
            Ok(())
        })
        .await?;
    }
    Ok(())
}

/// Capture the membership view under group ownership so a directory walk cannot expose a
/// publication prefix. Payload opening remains separately protected by reader leases.
pub(super) async fn member_paths(directory: &Path) -> MicrosandboxResult<Vec<PathBuf>> {
    let directory = directory.to_path_buf();
    blocking(move || {
        let _lock = lock_recovery(&directory)?;
        if is_creating(&directory)? && !path_exists(&directory.join(GROUP_FILENAME))? {
            return Ok(Vec::new());
        }
        // Listing has historically skipped malformed members individually. The recovery
        // barrier must not turn one corrupt sibling or a missing head into a failed listing.
        let mut paths = Vec::new();
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() && !entry.file_name().to_string_lossy().starts_with('.')
            {
                paths.push(entry.path());
            }
        }
        Ok(paths)
    })
    .await
}

/// Open or create an explicitly named group, or create a fresh generated local group.
#[cfg(test)]
pub(super) async fn ensure(root: &Path, name: Option<&str>) -> MicrosandboxResult<PathBuf> {
    Ok(prepare_destination(root, name, false, None, false)
        .await?
        .directory)
}

/// A new capture group binds once, before publication. Existing unbound groups remain
/// unbound: supplying a source must never turn an import into another sandbox's history.
pub(super) async fn ensure_capture(
    root: &Path,
    name: &str,
    source: super::source::Source,
) -> MicrosandboxResult<PathBuf> {
    source.validate()?;
    Ok(
        prepare_destination(root, Some(name), false, Some(source), false)
            .await?
            .directory,
    )
}

/// Claim a new capture history under the root creation lock, rejecting all collisions.
pub(super) async fn ensure_new_capture(
    root: &Path,
    name: &str,
    source: super::source::Source,
) -> MicrosandboxResult<CaptureReservation> {
    source.validate()?;
    let root = root.to_path_buf();
    let name = name.to_owned();
    // The result itself owns rollback. If the awaiting future is cancelled, the
    // blocking worker's unobserved return value still retires its reservation.
    blocking(move || capture::claim(&root, &name, source)).await
}

/// Validate a group independently of whether it currently selects a head.
pub(super) async fn inspect_directory(directory: &Path) -> MicrosandboxResult<Option<PathBuf>> {
    let directory = directory.to_path_buf();
    blocking(move || {
        let _lock = lock_group(&directory)?;
        let state = read_group(&directory)?;
        if state.head.is_none() {
            return Ok(None);
        }
        let (id, _) = resolve_selected(&directory, &state, None)?;
        Ok(Some(directory.join(id)))
    })
    .await
}

/// Validate group metadata without requiring its selected head to be readable.
pub(super) async fn validate_directory(directory: &Path) -> MicrosandboxResult<()> {
    let directory = directory.to_path_buf();
    blocking(move || {
        let _lock = lock_group(&directory)?;
        read_group(&directory)?;
        Ok(())
    })
    .await
}

/// Verification must report malformed member entries instead of silently skipping them.
pub(super) async fn verification_paths(directory: &Path) -> MicrosandboxResult<Vec<PathBuf>> {
    let directory = directory.to_path_buf();
    blocking(move || {
        let _lock = lock_group(&directory)?;
        let state = read_group(&directory)?;
        let mut paths = Vec::new();
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with('.')
                && (entry.file_type()?.is_dir() || SnapshotId::new(name.as_ref()).is_ok())
            {
                paths.push(entry.path());
            }
        }
        // A dangling selected head is a missing member, not an empty verified group.
        if let Some(head) = state.head {
            paths.push(directory.join(head));
        }
        paths.sort();
        paths.dedup();
        Ok(paths)
    })
    .await
}

/// Group-local member lookup never interprets a member name as a host path.
pub(super) async fn selected_path(directory: &Path, member: &str) -> MicrosandboxResult<PathBuf> {
    validate_name(member, "checkpoint selector")?;
    let directory = directory.to_path_buf();
    let member = member.to_owned();
    blocking(move || {
        let _lock = lock_group(&directory)?;
        let state = read_group(&directory)?;
        let (id, _) = resolve_selected(&directory, &state, Some(&member))?;
        Ok(directory.join(id))
    })
    .await
}

pub(super) async fn ensure_checkpoint(
    root: &Path,
    name: &str,
    source: super::source::Source,
) -> MicrosandboxResult<PathBuf> {
    source.validate()?;
    Ok(
        prepare_destination(root, Some(name), false, Some(source), true)
            .await?
            .directory,
    )
}

/// Resolve selectors before capture. A source-only selector never creates or chooses a
/// default group; the complete association set must contain exactly one match.
pub(super) async fn capture_source(
    local: &crate::backend::LocalBackend,
    root: &Path,
    group: Option<&str>,
    sandbox_name: Option<&str>,
) -> MicrosandboxResult<(String, String)> {
    if group.is_none() && sandbox_name.is_none() {
        return Err(MicrosandboxError::InvalidConfig(
            "checkpoint requires a group or sandbox selector".into(),
        ));
    }
    if let Some(group) = group {
        validate_group_name(group)?;
    }
    let requested = if let Some(name) = sandbox_name {
        let db = local.db().await?;
        let model = sandbox::Entity::find()
            .filter(sandbox::Column::Name.eq(name))
            .one(db.read())
            .await?
            .ok_or_else(|| MicrosandboxError::SandboxNotFound(name.into()))?;
        Some(super::source::Source::capture(db.write(), model.id, name).await?)
    } else {
        None
    };
    let root = root.to_path_buf();
    let group = group.map(str::to_owned);
    let (group, source) = blocking(move || {
        if let Some(group) = group {
            let directory = root.join(&group);
            let _lock = lock_group(&directory)?;
            let source = read_source(&directory)?.ok_or_else(|| unbound(&directory))?;
            if let Some(requested) = &requested { source.require_same(requested)?; }
            return Ok((group, source));
        }
        let requested = requested.expect("one selector was required");
        // Group creation uses the same root lock. Without it, directory iteration could
        // miss a concurrently added second association and choose an arbitrary default.
        let _creation = if path_exists(&root)? {
            require_directory(&root)?;
            let lock = process_lock::open_lock_file(&root.join(".groups.lock"))?;
            process_lock::lock_exclusive(&lock)?;
            Some(lock)
        } else { None };
        let entries = match fs::read_dir(&root) {
            Ok(entries) => Some(entries),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let mut matches = Vec::new();
        for entry in entries.into_iter().flatten() {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
            if name.starts_with('.') || !entry.file_type()?.is_dir() || !entry.path().join(GROUP_FILENAME).is_file() { continue; }
            validate_group_name(&name)?;
            let _lock = lock_group(&entry.path())?;
            if let Some(source) = read_source(&entry.path())? {
                source.validate()?;
                if source.require_same(&requested).is_ok() { matches.push((name, source)); }
            }
        }
        if matches.len() != 1 {
            matches.sort_by(|left, right| left.0.cmp(&right.0));
            let names = matches.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>().join(", ");
            return Err(MicrosandboxError::InvalidConfig(if matches.is_empty() {
                "sandbox has no associated snapshot group; create a group first".into()
            } else {
                format!("sandbox has multiple associated snapshot groups ({names}); select one explicitly")
            }));
        }
        Ok(matches.pop().expect("exactly one match"))
    }).await?;
    let name = source.resolve(local).await?;
    Ok((group, name))
}

/// Reserve a new import namespace without exposing an empty group. The creation marker is
/// local coordination metadata, never a portable snapshot extension or a group membership.
pub(super) async fn ensure_import(
    root: &Path,
    name: Option<&str>,
) -> MicrosandboxResult<ImportDestination> {
    prepare_destination(root, name, true, None, false).await
}

async fn prepare_destination(
    root: &Path,
    name: Option<&str>,
    importing: bool,
    source: Option<super::source::Source>,
    require_existing: bool,
) -> MicrosandboxResult<ImportDestination> {
    let root = root.to_path_buf();
    let name = name.map(str::to_owned);
    blocking(move || {
        if let Some(name) = &name { validate_group_name(name)?; }
        fs::create_dir_all(&root)?;
        require_directory(&root)?;
        let creation_lock = process_lock::open_lock_file(&root.join(".groups.lock"))?;
        process_lock::lock_exclusive(&creation_lock)?;
        let name = match name {
            Some(name) => name,
            None => loop {
                let candidate = format!("msb-{:08x}", rand::random::<u32>());
                if !path_exists(&root.join(&candidate))? { break candidate; }
            },
        };
        let directory = root.join(&name);
        if path_exists(&directory)? {
            require_directory(&directory)?;
            if let Some(source) = &source {
                let _lock = lock_group(&directory)?;
                require_source(&directory, source)?;
            }
            if is_creating(&directory)? {
                let _lock = lock_recovery(&directory)?;
                if !path_exists(&directory.join(GROUP_FILENAME))? {
                    if !read_members(&directory, true)?.is_empty() {
                        return Err(integrity("unpublished group contains members without a recoverable batch".into()));
                    }
                    if !importing {
                        write_group(&directory, None)?;
                        finish_creation(&directory)?;
                    }
                    return Ok(ImportDestination { directory, _creation_lock: importing.then_some(creation_lock) });
                }
            }
            if !path_exists(&directory.join(GROUP_FILENAME))? {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "'{name}' already names a snapshot directory, not a snapshot group; choose another group name or open the existing snapshot by its explicit path"
                )));
            }
            read_group(&directory)?;
            return Ok(ImportDestination { directory, _creation_lock: None });
        }
        if require_existing {
            return Err(MicrosandboxError::SnapshotNotFound(name));
        }
        let staging = tempfile::Builder::new().prefix(".group-new-").tempdir_in(&root)?;
        if let Some(source) = &source {
            write_json(staging.path(), super::source::SOURCE_FILENAME, source)?;
        }
        if importing {
            write_json(staging.path(), CREATING_FILENAME, &CREATING_SCHEMA)?;
        } else {
            write_group(staging.path(), None)?;
        }
        process_lock::create_new_lock_file(&staging.path().join(".group.lock"))?.sync_all()?;
        sync_directory(staging.path())?;
        fs::rename(staging.path(), &directory)?;
        sync_directory(&root)?;
        Ok(ImportDestination { directory, _creation_lock: importing.then_some(creation_lock) })
    }).await
}

fn require_source(directory: &Path, expected: &super::source::Source) -> MicrosandboxResult<()> {
    read_source(directory)?
        .ok_or_else(|| unbound(directory))?
        .require_same(expected)
}

fn unbound(directory: &Path) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!(
        "snapshot group '{}' is unbound and cannot capture checkpoints; create a new group for this sandbox",
        directory.display(),
    ))
}

fn read_source(directory: &Path) -> MicrosandboxResult<Option<super::source::Source>> {
    let path = directory.join(super::source::SOURCE_FILENAME);
    if !path_exists(&path)? {
        return Ok(None);
    }
    let source: super::source::Source =
        serde_json::from_slice(&read_regular(&path, MAX_METADATA_BYTES)?)?;
    source.validate()?;
    Ok(Some(source))
}

/// Publish complete staged artifacts and atomically decide the group's next head.
///
/// `staged` contains immediate child artifact directories. The caller prepares, validates, and
/// flushes their payloads before calling this function. All descriptor and alias conflicts are
/// checked before publication; existing identical artifacts are never overwritten.
#[cfg(test)]
pub(super) async fn publish(
    group_dir: &Path,
    staged: &Path,
    aliases: &BTreeMap<String, String>,
    candidate: &SnapshotId,
    set_head: bool,
) -> MicrosandboxResult<HeadUpdate> {
    publish_batch(
        group_dir,
        staged,
        aliases,
        std::slice::from_ref(candidate),
        set_head,
    )
    .await?
    .ok_or_else(|| integrity("single snapshot publication did not choose a head".into()))
}

/// Publish a validated batch under one lock, selecting a head only when supplied candidates
/// have one tip that is a known descendant of every other candidate.
#[cfg(test)]
pub(super) async fn publish_batch(
    group_dir: &Path,
    staged: &Path,
    aliases: &BTreeMap<String, String>,
    candidates: &[SnapshotId],
    set_head: bool,
) -> MicrosandboxResult<Option<HeadUpdate>> {
    publish_batch_inner(group_dir, staged, aliases, candidates, set_head, None, None)
        .await
        .map(|publication| publication.head_update)
}

/// Retain the committed journal until publication::complete_batch has indexed every member.
#[cfg(test)]
pub(super) async fn publish_batch_indexed(
    group_dir: &Path,
    staged: &Path,
    aliases: &BTreeMap<String, String>,
    candidates: &[SnapshotId],
    set_head: bool,
    operation: IndexedPublication,
) -> MicrosandboxResult<Option<HeadUpdate>> {
    publish_batch_inner(
        group_dir,
        staged,
        aliases,
        candidates,
        set_head,
        Some(operation),
        None,
    )
    .await
    .map(|publication| publication.head_update)
}

pub(super) async fn publish_admitted(
    group_dir: &Path,
    staged: &Path,
    aliases: &BTreeMap<String, String>,
    candidate: &SnapshotId,
    writer: WriterLease,
) -> MicrosandboxResult<HeadUpdate> {
    publish_batch_inner(
        group_dir,
        staged,
        aliases,
        std::slice::from_ref(candidate),
        false,
        None,
        Some(writer),
    )
    .await?
    .head_update
    .ok_or_else(|| integrity("single snapshot publication did not choose a head".into()))
}

pub(super) async fn publish_batch_indexed_admitted(
    group_dir: &Path,
    staged: &Path,
    aliases: &BTreeMap<String, String>,
    candidates: &[SnapshotId],
    set_head: bool,
    operation: IndexedPublication,
    writer: WriterLease,
) -> MicrosandboxResult<BatchPublication> {
    publish_batch_inner(
        group_dir,
        staged,
        aliases,
        candidates,
        set_head,
        Some(operation),
        Some(writer),
    )
    .await
}

async fn publish_batch_inner(
    group_dir: &Path,
    staged: &Path,
    aliases: &BTreeMap<String, String>,
    candidates: &[SnapshotId],
    set_head: bool,
    index_operation: Option<IndexedPublication>,
    writer: Option<WriterLease>,
) -> MicrosandboxResult<BatchPublication> {
    if candidates.is_empty() {
        return Err(MicrosandboxError::InvalidConfig(
            "snapshot batch must contain at least one candidate head".into(),
        ));
    }
    let writer = match writer {
        Some(writer) => {
            writer.validate(group_dir)?;
            writer
        }
        None => WriterLease::acquire(group_dir).await?,
    };
    let group_dir = group_dir.to_path_buf();
    let staged = staged.to_path_buf();
    let aliases = aliases.clone();
    let candidates: BTreeSet<String> = candidates.iter().map(ToString::to_string).collect();
    blocking(move || {
        let _writer = writer;
        require_directory(&staged)?;
        if fs::canonicalize(&group_dir)?.starts_with(fs::canonicalize(&staged)?) {
            return Err(MicrosandboxError::InvalidConfig(
                "snapshot staging must not contain the destination group".into(),
            ));
        }
        // Recover before acquiring incoming namespace pins: a retry may contain the same
        // IDs that an interrupted transaction must retire.
        drop(lock_publication(&group_dir)?);
        let incoming = read_members(&staged, false)?;
        // Acquire member protection before the group publication lock: removers take the
        // same order, and a reader must never wait on deletion while holding the group lock.
        let _leases = incoming
            .keys()
            .map(|id| microsandbox_image::storage_lease::StorageLease::shared(&group_dir.join(id)))
            .collect::<std::io::Result<Vec<_>>>()?;
        let _lock = lock_publication(&group_dir)?;
        let state = publication_state(&group_dir)?;
        let mut members = read_members(&group_dir, true)?;
        validate_head(&state, &members)?;

        let mut added = Vec::new();
        let mut reused = Vec::new();
        for (id, member) in &incoming {
            if let Some(existing) = members.get(id) {
                if existing.digest != member.digest {
                    return Err(integrity(format!(
                        "snapshot ID {id} already exists in this group with a different descriptor"
                    )));
                }
                reused.push(
                    SnapshotId::new(id.clone()).map_err(|error| integrity(error.to_string()))?,
                );
            } else {
                added.push(
                    SnapshotId::new(id.clone()).map_err(|error| integrity(error.to_string()))?,
                );
                // Even an unrecognized file at the destination must not be overwritten.
                if path_exists(&group_dir.join(id))? {
                    return Err(integrity(format!(
                        "snapshot destination already exists: {}",
                        group_dir.join(id).display()
                    )));
                }
                members.insert(
                    id.clone(),
                    Member {
                        path: member.path.clone(),
                        digest: member.digest.clone(),
                        parent: member.parent.clone(),
                        name: None,
                    },
                );
            }
        }
        for candidate in &candidates {
            if !members.contains_key(candidate) {
                return Err(MicrosandboxError::SnapshotNotFound(candidate.clone()));
            }
        }
        apply_aliases(&mut members, &aliases)?;
        validate_ancestry(&members)?;
        let update = batch_head_update(
            &group_dir,
            state.head.as_deref(),
            &candidates,
            &members,
            set_head,
        )?;

        let next_head = update
            .as_ref()
            .and_then(|update| update.head.clone())
            .or_else(|| state.head.clone());
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if let Some(operation) = index_operation.as_ref() {
            let warnings = generation::publish(
                &group_dir, &staged, &incoming, &aliases, next_head, operation,
            )?;
            return Ok(BatchPublication {
                head_update: update,
                added,
                reused,
                warnings,
            });
        }
        transaction::publish(
            &group_dir,
            &incoming,
            &members,
            &aliases,
            state.head,
            next_head,
            index_operation.as_ref(),
        )?;
        Ok(BatchPublication {
            head_update: update,
            added,
            reused,
            warnings: Vec::new(),
        })
    })
    .await
}

/// Admit the committed batch under group ownership before changing any ready index rows.
pub(super) async fn pending_index(directory: &Path) -> MicrosandboxResult<Option<PendingIndex>> {
    let directory = directory.to_path_buf();
    blocking(move || {
        let lock = lock_recovery(&directory)?;
        Ok(
            transaction::pending_index(&directory)?.map(|snapshots| PendingIndex {
                _lock: lock,
                directory,
                snapshots,
            }),
        )
    })
    .await
}

/// Reservation recovery also applies to a new destination which is not yet a visible group.
pub(super) async fn recover_publication(directory: &Path) -> MicrosandboxResult<()> {
    let directory = directory.to_path_buf();
    blocking(move || {
        drop(lock_recovery(&directory)?);
        Ok(())
    })
    .await
}

/// List installed members available as dependency sources without creating a destination group.
/// Callers must still validate the physical payloads they borrow from these artifact paths.
pub(super) async fn dependency_members(
    root: &Path,
    name: &str,
) -> MicrosandboxResult<Vec<PathBuf>> {
    let root = root.to_path_buf();
    let name = name.to_owned();
    blocking(move || {
        validate_group_name(&name)?;
        if !path_exists(&root)? {
            return Ok(Vec::new());
        }
        require_directory(&root)?;
        let directory = root.join(name);
        if !path_exists(&directory)? {
            return Ok(Vec::new());
        }
        require_directory(&directory)?;
        publication_state(&directory)?;
        // Preflight must not create even a lock file in an existing malformed namespace.
        let lock = process_lock::open_existing_lock_file(&directory.join(".group.lock"))?;
        process_lock::lock_exclusive(&lock)?;
        transaction::recover(&directory)?;
        if is_creating(&directory)? && !path_exists(&directory.join(GROUP_FILENAME))? {
            return Ok(Vec::new());
        }
        let state = read_group(&directory)?;
        let members = read_members(&directory, true)?;
        validate_head(&state, &members)?;
        validate_ancestry(&members)?;
        Ok(members.into_values().map(|member| member.path).collect())
    })
    .await
}

/// Read a bare group's head, or explicitly select a qualified member as its head.
pub(super) async fn select(root: &Path, selector: &str) -> MicrosandboxResult<HeadUpdate> {
    let root = root.to_path_buf();
    let selector = selector.to_owned();
    let (name, selected) = parse_selector(&selector)?;
    let writer = if selected.is_some() {
        Some(WriterLease::acquire(&root.join(name)).await?)
    } else {
        None
    };
    blocking(move || {
        let _writer = writer;
        let (name, selected) = parse_selector(&selector)?;
        let directory = root.join(name);
        let _lock = lock_group(&directory)?;
        let state = read_group(&directory)?;
        let (candidate, member) = resolve_selected(&directory, &state, selected)?;
        let members = BTreeMap::from([(candidate.clone(), member)]);
        let update = head_update(
            &directory,
            state.head.as_deref(),
            &candidate,
            &members,
            selected.is_some(),
        )?;
        if update.changed {
            write_group(&directory, update.head.clone())?;
        }
        Ok(update)
    })
    .await
}

/// Set or clear the head without rewriting any immutable checkpoint descriptor.
pub(super) async fn change_head(
    directory: &Path,
    member: Option<&str>,
) -> MicrosandboxResult<HeadUpdate> {
    if let Some(member) = member {
        validate_name(member, "checkpoint selector")?;
    }
    let writer = WriterLease::acquire(directory).await?;
    let directory = directory.to_path_buf();
    let member = member.map(str::to_owned);
    blocking(move || {
        let _writer = writer;
        let _lock = lock_group(&directory)?;
        if transaction::pending_index(&directory)?.is_some() {
            return Err(integrity("snapshot batch index completion is pending; recover the import before changing its head".into()));
        }
        let state = read_group(&directory)?;
        let update = if let Some(member) = member {
            // Explicit selection can repair a dangling old head, but the new member
            // must exist and carry valid identity before the head is changed.
            let (candidate, value) = resolve_selected(&directory, &state, Some(&member))?;
            head_update(&directory, state.head.as_deref(), &candidate, &BTreeMap::from([(candidate.clone(), value)]), true)?
        } else {
            HeadUpdate {
                group: directory.file_name().and_then(|name| name.to_str()).ok_or_else(|| integrity("group directory has no valid name".into()))?.into(),
                previous: state.head.clone(),
                head: None,
                reason: if state.head.is_some() { HeadUpdateReason::Cleared } else { HeadUpdateReason::Unchanged },
                changed: state.head.is_some(),
            }
        };
        if update.changed { write_group(&directory, update.head.clone())?; }
        Ok(update)
    }).await
}

/// Read a member's optional local friendly name without altering its immutable descriptor.
pub(super) fn member_name(path: &Path) -> MicrosandboxResult<Option<String>> {
    let metadata_path = path.join(MEMBER_FILENAME);
    if !path_exists(&metadata_path)? {
        return Ok(None);
    }
    let metadata: MemberMetadata =
        serde_json::from_slice(&read_regular(&metadata_path, MAX_METADATA_BYTES)?)?;
    if metadata.schema != MEMBER_SCHEMA {
        return Err(integrity(format!(
            "unsupported snapshot member metadata schema: {}",
            metadata.schema
        )));
    }
    validate_alias(&metadata.name)?;
    Ok(Some(metadata.name))
}

/// Return the containing group when a member's parent has regular group metadata.
pub(super) fn group_path(path: &Path) -> Option<PathBuf> {
    let parent = path.parent()?;
    is_group(parent).then(|| parent.to_path_buf())
}

/// Includes reserved, not-yet-published groups so their writers share admission.
pub(super) fn is_group(directory: &Path) -> bool {
    [GROUP_FILENAME, CREATING_FILENAME]
        .into_iter()
        .any(|filename| {
            fs::symlink_metadata(directory.join(filename))
                .is_ok_and(|metadata| metadata.file_type().is_file())
        })
}

/// Remove a grouped member under its publication lock, returning false for ungrouped paths.
#[cfg(test)]
pub(super) async fn remove_member(path: &Path) -> MicrosandboxResult<bool> {
    let lease = super::lease::deletion(path)?.ok_or_else(|| {
        MicrosandboxError::Custom("snapshot is in use by an active operation".into())
    })?;
    Ok(remove_member_leased(path, lease).await?.is_some())
}

pub(super) async fn remove_member_leased(
    path: &Path,
    lease: super::lease::DeletionLease,
) -> MicrosandboxResult<Option<MemberRemoval>> {
    let path = path.to_path_buf();
    blocking(move || {
        let _lease = lease;
        let Some(directory) = group_path(&path) else {
            return Ok(None);
        };
        let _lock = lock_group(&directory)?;
        if transaction::pending_index(&directory)?.is_some() {
            return Err(integrity(
                "snapshot batch index completion is pending; retry removal after recovery".into(),
            ));
        }
        let state = read_group(&directory)?;
        let members = read_members(&directory, true)?;
        validate_head(&state, &members)?;
        let id = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                MicrosandboxError::InvalidConfig("snapshot member path has no stable ID".into())
            })?;
        let member = members
            .get(id)
            .ok_or_else(|| MicrosandboxError::SnapshotNotFound(id.into()))?;
        let head = if state.head.as_deref() == Some(id) {
            // Ancestry is immutable evidence; only a surviving parent in THIS group is
            // eligible. Never infer a replacement from timestamps, aliases or other groups.
            member
                .parent
                .as_ref()
                .filter(|parent| parent.as_str() != id && members.contains_key(*parent))
                .cloned()
        } else {
            state.head.clone()
        };
        let changed = head != state.head;
        let update = HeadUpdate {
            group: directory
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| integrity("group directory has no valid name".into()))?
                .into(),
            previous: state.head,
            reason: if !changed {
                HeadUpdateReason::Unchanged
            } else if head.is_some() {
                HeadUpdateReason::ParentSelected
            } else {
                HeadUpdateReason::Cleared
            },
            head,
            changed,
        };
        let warnings = removal::publish(&directory, id, update.head.clone())?;
        Ok(Some(MemberRemoval {
            head_update: update,
            warnings,
        }))
    })
    .await
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> MicrosandboxResult<T> + Send + 'static,
) -> MicrosandboxResult<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| MicrosandboxError::Custom(format!("snapshot group operation: {error}")))?
}

fn parse_selector(selector: &str) -> MicrosandboxResult<(&str, Option<&str>)> {
    let (group, member) = match selector.split_once(':') {
        Some((group, member)) => (group, Some(member)),
        None => (selector, None),
    };
    validate_group_name(group)?;
    if let Some(member) = member {
        validate_name(member, "snapshot selector")?;
    }
    Ok((group, member))
}

fn validate_name(name: &str, kind: &str) -> MicrosandboxResult<()> {
    let first = name.as_bytes().first().copied();
    if name.len() > MAX_NAME_BYTES
        || !first.is_some_and(|byte| byte.is_ascii_alphanumeric())
        || name.ends_with('.')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "invalid {kind} '{name}': use 1–{MAX_NAME_BYTES} ASCII letters, digits, '-', '_' or '.', start with a letter or digit, and do not end with '.'"
        )));
    }
    // Reject device names even on Unix so local selectors remain portable to Windows.
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
    {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "invalid {kind} '{name}': reserved device name"
        )));
    }
    Ok(())
}

pub(super) fn validate_alias(name: &str) -> MicrosandboxResult<()> {
    validate_name(name, "snapshot name")?;
    if SnapshotId::new(name).is_ok() {
        return Err(MicrosandboxError::InvalidConfig(
            "a snapshot's friendly name must not be a stable snapshot ID".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_group_name(name: &str) -> MicrosandboxResult<()> {
    validate_name(name, "group")?;
    if matches!(name, "sha256" | "sha512") || SnapshotId::new(name).is_ok() {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "invalid group name '{name}': reserved snapshot identifier namespace"
        )));
    }
    Ok(())
}

fn is_creating(directory: &Path) -> MicrosandboxResult<bool> {
    let path = directory.join(CREATING_FILENAME);
    if !path_exists(&path)? {
        return Ok(false);
    }
    let schema: String = serde_json::from_slice(&read_regular(&path, MAX_METADATA_BYTES)?)?;
    if schema != CREATING_SCHEMA {
        return Err(integrity(
            "unsupported snapshot group creation record".into(),
        ));
    }
    Ok(true)
}

fn finish_creation(directory: &Path) -> MicrosandboxResult<()> {
    if is_creating(directory)? {
        fs::remove_file(directory.join(CREATING_FILENAME))?;
        sync_directory(directory)?;
    }
    Ok(())
}

fn publication_state(directory: &Path) -> MicrosandboxResult<GroupState> {
    if !path_exists(&directory.join(GROUP_FILENAME))? && is_creating(directory)? {
        return Ok(GroupState {
            schema: GROUP_SCHEMA.into(),
            head: None,
        });
    }
    read_group(directory)
}

fn lock_publication(directory: &Path) -> MicrosandboxResult<File> {
    require_directory(directory)?;
    publication_state(directory)?;
    lock_recovery(directory)
}

fn lock_group(directory: &Path) -> MicrosandboxResult<File> {
    require_directory(directory)?;
    read_group(directory)?;
    lock_recovery(directory)
}

/// Explicit artifact reads do not depend on valid group selection metadata. They still
/// coordinate with publication, and only a pending journal requires interpreting group state.
fn lock_recovery(directory: &Path) -> MicrosandboxResult<File> {
    require_directory(directory)?;
    let path = directory.join(".group.lock");
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    // A lock requires no writes to its contents. Read-only external groups with an existing
    // lock remain readable; create a coordination file only when it is genuinely absent.
    let lock = match options.open(&path) {
        Ok(file) if file.metadata()?.is_file() => file,
        Ok(_) => {
            return Err(integrity(
                "snapshot group lock is not a regular file".into(),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            process_lock::open_lock_file(&path)?
        }
        Err(error) => return Err(error.into()),
    };
    process_lock::lock_exclusive(&lock)?;
    transaction::recover(directory)?;
    Ok(lock)
}

/// Reclaim interrupted Unix generation retirements under existing writer admission.
pub(super) fn recover_retired(directory: &Path) -> MicrosandboxResult<()> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    generation::recover_retired(directory)?;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = directory;
    Ok(())
}

fn read_group(directory: &Path) -> MicrosandboxResult<GroupState> {
    let path = directory.join(GROUP_FILENAME);
    if !path_exists(&path)? {
        return Err(MicrosandboxError::SnapshotNotFound(format!(
            "snapshot group {}",
            directory.display()
        )));
    }
    let state: GroupState = serde_json::from_slice(&read_regular(&path, MAX_METADATA_BYTES)?)?;
    if state.schema != GROUP_SCHEMA {
        return Err(integrity(format!(
            "unsupported snapshot group schema: {}",
            state.schema
        )));
    }
    if let Some(head) = &state.head {
        SnapshotId::new(head).map_err(|error| integrity(error.to_string()))?;
    }
    Ok(state)
}

fn write_group(directory: &Path, head: Option<String>) -> MicrosandboxResult<()> {
    write_json(
        directory,
        GROUP_FILENAME,
        &GroupState {
            schema: GROUP_SCHEMA.into(),
            head,
        },
    )
}

fn read_members(directory: &Path, installed: bool) -> MicrosandboxResult<BTreeMap<String, Member>> {
    let mut members = BTreeMap::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let filename = entry.file_name();
        let name = filename
            .to_str()
            .ok_or_else(|| integrity("snapshot member directory name is not valid UTF-8".into()))?;
        if name == ".msb-leases" {
            continue;
        }
        if installed && !name.starts_with("snap_") {
            continue;
        }
        if !entry.file_type()?.is_dir() {
            if installed {
                return Err(integrity(format!(
                    "snapshot member is not a regular directory: {}",
                    entry.path().display()
                )));
            }
            return Err(integrity(format!(
                "snapshot staging contains a non-directory member: {}",
                entry.path().display()
            )));
        }
        let (id, member) = read_member(&entry.path(), installed)?;
        if installed && id != name {
            return Err(integrity(format!(
                "snapshot member directory {name} does not match descriptor ID {id}"
            )));
        }
        if members.insert(id.clone(), member).is_some() {
            return Err(integrity(format!(
                "snapshot staging contains duplicate stable ID {id}"
            )));
        }
    }
    Ok(members)
}

fn apply_aliases(
    members: &mut BTreeMap<String, Member>,
    aliases: &BTreeMap<String, String>,
) -> MicrosandboxResult<()> {
    for (id, name) in aliases {
        validate_alias(name)?;
        let member = members
            .get_mut(id)
            .ok_or_else(|| MicrosandboxError::SnapshotNotFound(id.clone()))?;
        if let Some(existing) = &member.name
            && existing != name
        {
            return Err(MicrosandboxError::SnapshotAlreadyExists(format!(
                "snapshot {id} already has local name '{existing}', not '{name}'"
            )));
        }
        member.name = Some(name.clone());
    }
    let mut names = BTreeMap::new();
    for (id, member) in members {
        if let Some(name) = &member.name
            && let Some(previous) = names.insert(name.clone(), id.clone())
        {
            return Err(MicrosandboxError::SnapshotAlreadyExists(format!(
                "snapshot name '{name}' conflicts between {previous} and {id} in this group"
            )));
        }
    }
    Ok(())
}

fn read_member(path: &Path, installed: bool) -> MicrosandboxResult<(String, Member)> {
    require_directory(path)?;
    let manifest = Manifest::from_bytes(&read_regular(
        &path.join(DESCRIPTOR_FILENAME),
        MAX_DESCRIPTOR_BYTES,
    )?)
    .map_err(|error| integrity(error.to_string()))?;
    let id = manifest.snapshot_id.to_string();
    let member = Member {
        digest: manifest
            .digest()
            .map_err(|error| integrity(error.to_string()))?,
        parent: manifest.parent.map(|parent| parent.to_string()),
        name: if installed { member_name(path)? } else { None },
        path: path.to_path_buf(),
    };
    Ok((id, member))
}

fn resolve_selected(
    directory: &Path,
    state: &GroupState,
    selected: Option<&str>,
) -> MicrosandboxResult<(String, Member)> {
    // ID and head lookup touch only the selected descriptor. Large histories do not make the
    // normal open path progressively slower, and unrelated artifacts need not be reopened.
    let selected_id = match selected {
        None => Some(state.head.clone().ok_or_else(|| {
            MicrosandboxError::SnapshotNotFound(format!(
                "snapshot group {} has no head selected; choose an installed member with 'msb snapshot modify {} --set-head <member>'",
                directory.display(),
                directory.file_name().unwrap_or_default().to_string_lossy()
            ))
        })?),
        Some(selected) if SnapshotId::new(selected).is_ok() => Some(selected.to_owned()),
        Some(_) => None,
    };
    let expected = match selected_id {
        Some(id) => id,
        None => {
            let selected = selected.unwrap();
            let mut matched = None;
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                let name = entry.file_name();
                let Some(name) = name.to_str().filter(|name| name.starts_with("snap_")) else {
                    continue;
                };
                require_directory(&entry.path())?;
                if member_name(&entry.path())?.as_deref() == Some(selected) {
                    if matched.is_some() {
                        return Err(integrity(format!(
                            "snapshot name '{selected}' is ambiguous in this group"
                        )));
                    }
                    matched = Some(name.to_owned());
                }
            }
            matched.ok_or_else(|| {
                MicrosandboxError::SnapshotNotFound(format!(
                    "{}:{selected}",
                    directory.file_name().unwrap_or_default().to_string_lossy()
                ))
            })?
        }
    };
    let path = directory.join(&expected);
    if !path_exists(&path)? {
        return Err(MicrosandboxError::SnapshotNotFound(format!(
            "snapshot group member {} is missing",
            path.display()
        )));
    }
    let (id, member) = read_member(&path, true)?;
    if id != expected {
        return Err(integrity(format!(
            "snapshot member directory {expected} does not match descriptor ID {id}"
        )));
    }
    Ok((id, member))
}

fn validate_head(state: &GroupState, members: &BTreeMap<String, Member>) -> MicrosandboxResult<()> {
    if let Some(head) = &state.head
        && !members.contains_key(head)
    {
        return Err(integrity(format!(
            "snapshot group head {head} is missing; explicitly select an installed member to repair the head"
        )));
    }
    Ok(())
}

fn head_update(
    directory: &Path,
    previous: Option<&str>,
    candidate: &str,
    members: &BTreeMap<String, Member>,
    explicit: bool,
) -> MicrosandboxResult<HeadUpdate> {
    let reason = match previous {
        Some(head) if head == candidate => HeadUpdateReason::Unchanged,
        _ if explicit => HeadUpdateReason::Selected,
        None => HeadUpdateReason::Initialized,
        Some(head) => ancestry_reason(candidate, head, members)?,
    };
    let changed = matches!(
        reason,
        HeadUpdateReason::Initialized
            | HeadUpdateReason::FastForwarded
            | HeadUpdateReason::Selected
    );
    Ok(HeadUpdate {
        group: directory
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| integrity("snapshot group directory has no valid name".into()))?
            .into(),
        previous: previous.map(str::to_owned),
        head: Some(if changed {
            candidate.into()
        } else {
            previous.unwrap_or(candidate).into()
        }),
        reason,
        changed,
    })
}

fn batch_head_update(
    directory: &Path,
    previous: Option<&str>,
    candidates: &BTreeSet<String>,
    members: &BTreeMap<String, Member>,
    explicit: bool,
) -> MicrosandboxResult<Option<HeadUpdate>> {
    // Remove supplied heads that are proven ancestors of another supplied head. Shared paths
    // need be traversed only once: their candidate ancestors were already marked on first visit.
    let mut ancestors = HashSet::new();
    let mut visited = HashSet::new();
    for candidate in candidates {
        let mut current = members[candidate].parent.as_deref();
        while let Some(parent) = current {
            if !visited.insert(parent) {
                break;
            }
            if candidates.contains(parent) {
                ancestors.insert(parent);
            }
            current = members
                .get(parent)
                .and_then(|member| member.parent.as_deref());
        }
    }
    let mut tips = candidates
        .iter()
        .filter(|candidate| !ancestors.contains(candidate.as_str()));
    let candidate = tips
        .next()
        .ok_or_else(|| integrity("snapshot batch has no candidate tip".into()))?;
    if tips.next().is_none() {
        return head_update(directory, previous, candidate, members, explicit).map(Some);
    }
    if explicit {
        return Err(MicrosandboxError::InvalidConfig(
            "--set-head cannot choose between multiple snapshot archive heads with incomparable or unknown ancestry; load without --set-head, then use 'msb snapshot modify <group> --set-head <member>'".into(),
        ));
    }
    // A fresh group may contain several branches without claiming that one is current.
    previous
        .map(|head| {
            let mut update = head_update(directory, Some(head), head, members, false)?;
            update.reason = HeadUpdateReason::AmbiguousCandidates;
            Ok(update)
        })
        .transpose()
}

fn ancestry_reason(
    candidate: &str,
    head: &str,
    members: &BTreeMap<String, Member>,
) -> MicrosandboxResult<HeadUpdateReason> {
    let mut current = candidate;
    let mut visited = HashSet::new();
    while visited.len() < MAX_ANCESTRY_DEPTH {
        if !visited.insert(current) {
            return Err(integrity("snapshot ancestry contains a cycle".into()));
        }
        let Some(member) = members.get(current) else {
            return Ok(HeadUpdateReason::UnknownAncestry);
        };
        let Some(parent) = member.parent.as_deref() else {
            return Ok(HeadUpdateReason::Diverged);
        };
        if parent == head {
            return Ok(HeadUpdateReason::FastForwarded);
        }
        current = parent;
    }
    Err(integrity(format!(
        "snapshot ancestry exceeds the {MAX_ANCESTRY_DEPTH}-member traversal limit"
    )))
}

fn validate_ancestry(members: &BTreeMap<String, Member>) -> MicrosandboxResult<()> {
    let mut complete = HashSet::new();
    for id in members.keys() {
        let mut current = id.as_str();
        let mut visiting = HashSet::new();
        while !complete.contains(current) {
            if !visiting.insert(current) {
                return Err(integrity("snapshot ancestry contains a cycle".into()));
            }
            if visiting.len() > MAX_ANCESTRY_DEPTH {
                return Err(integrity(format!(
                    "snapshot ancestry exceeds the {MAX_ANCESTRY_DEPTH}-member traversal limit"
                )));
            }
            let Some(parent) = members
                .get(current)
                .and_then(|member| member.parent.as_deref())
            else {
                break;
            };
            current = parent;
        }
        complete.extend(visiting);
    }
    Ok(())
}

fn write_member_name(directory: &Path, name: Option<&str>) -> MicrosandboxResult<()> {
    let path = directory.join(MEMBER_FILENAME);
    match name {
        Some(name) => write_json(
            directory,
            MEMBER_FILENAME,
            &MemberMetadata {
                schema: MEMBER_SCHEMA.into(),
                name: name.into(),
            },
        ),
        None => {
            // Imported local metadata does not choose names in the receiving namespace.
            if path_exists(&path)? {
                if !fs::symlink_metadata(&path)?.file_type().is_file() {
                    return Err(integrity(format!(
                        "snapshot member metadata is not a regular file: {}",
                        path.display()
                    )));
                }
                fs::remove_file(path)?;
                sync_directory(directory)?;
            }
            Ok(())
        }
    }
}

fn write_json(directory: &Path, filename: &str, value: &impl Serialize) -> MicrosandboxResult<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(integrity(
            "snapshot group metadata exceeds its size limit".into(),
        ));
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".group-write-")
        .tempfile_in(directory)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(directory.join(filename))
        .map_err(|error| MicrosandboxError::from(error.error))?;
    sync_directory(directory)?;
    Ok(())
}

fn read_regular(path: &Path, maximum: usize) -> MicrosandboxResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > maximum as u64 {
        return Err(integrity(format!(
            "snapshot metadata is not a bounded regular file: {}",
            path.display()
        )));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(integrity(format!(
            "snapshot metadata is not a regular file: {}",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(integrity(format!(
            "snapshot metadata exceeds its size limit: {}",
            path.display()
        )));
    }
    Ok(bytes)
}

fn require_directory(path: &Path) -> MicrosandboxResult<()> {
    if !fs::symlink_metadata(path)?.file_type().is_dir() {
        return Err(integrity(format!(
            "snapshot group path is not a regular directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn path_exists(path: &Path) -> MicrosandboxResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn integrity(message: String) -> MicrosandboxError {
    MicrosandboxError::SnapshotIntegrity(message)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    // Match artifact publication: payloads and metadata are flushed, directory rename is atomic.
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
#[path = "group_tests.rs"]
mod tests;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub(super) use capture::{CaptureReservation, CaptureTarget};
pub(super) use inspection::inspect as inspect_history;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub(super) use remove_history::{recover as recover_histories, remove as remove_history};
