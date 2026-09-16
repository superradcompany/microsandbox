//! Local backend: Durable local snapshot namespaces and their explicitly selected heads.
//!
//! Group membership is represented by installed artifact directories. Only the head and each
//! member's optional local alias need metadata; immutable descriptors remain authoritative for
//! ancestry. All group operations share one process-held lock, acquired off the async executor.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use microsandbox_image::snapshot::{
    DESCRIPTOR_FILENAME, MAX_DESCRIPTOR_BYTES, Manifest, SnapshotId,
};
use microsandbox_utils::process_lock;
use serde::{Deserialize, Serialize};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(crate) const GROUP_FILENAME: &str = "group.json";
const GROUP_SCHEMA: &str = "microsandbox.snapshot-group/1";
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

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

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

/// Open or create an explicitly named group, or create a fresh generated local group.
pub(super) async fn ensure(root: &Path, name: Option<&str>) -> MicrosandboxResult<PathBuf> {
    let root = root.to_path_buf();
    let name = name.map(str::to_owned);
    blocking(move || {
        if let Some(name) = &name {
            validate_group_name(name)?;
        }
        fs::create_dir_all(&root)?;
        require_directory(&root)?;
        // Serialize creation separately: the group lock does not exist until publication.
        let creation_lock = process_lock::open_lock_file(&root.join(".groups.lock"))?;
        process_lock::lock_exclusive(&creation_lock)?;
        let name = match name {
            Some(name) => name,
            None => loop {
                let candidate = format!("msb-{:08x}", rand::random::<u32>());
                if !path_exists(&root.join(&candidate))? {
                    break candidate;
                }
            },
        };
        let directory = root.join(&name);
        if path_exists(&directory)? {
            require_directory(&directory)?;
            if !path_exists(&directory.join(GROUP_FILENAME))? {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "'{name}' already names a snapshot directory, not a snapshot group; choose another group name or open the existing snapshot by its explicit path"
                )));
            }
            read_group(&directory)?;
            return Ok(directory);
        }

        // The initial head and lock become visible together with the new group directory.
        let staging = tempfile::Builder::new()
            .prefix(".group-new-")
            .tempdir_in(&root)?;
        write_group(staging.path(), None)?;
        process_lock::create_new_lock_file(&staging.path().join(".group.lock"))?.sync_all()?;
        sync_directory(staging.path())?;
        fs::rename(staging.path(), &directory)?;
        sync_directory(&root)?;
        Ok(directory)
    })
    .await
}

/// Publish complete staged artifacts and atomically decide the group's next head.
///
/// `staged` contains immediate child artifact directories. The caller prepares, validates, and
/// flushes their payloads before calling this function. All descriptor and alias conflicts are
/// checked before publication; existing identical artifacts are never overwritten.
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
pub(super) async fn publish_batch(
    group_dir: &Path,
    staged: &Path,
    aliases: &BTreeMap<String, String>,
    candidates: &[SnapshotId],
    set_head: bool,
) -> MicrosandboxResult<Option<HeadUpdate>> {
    if candidates.is_empty() {
        return Err(MicrosandboxError::InvalidConfig(
            "snapshot batch must contain at least one candidate head".into(),
        ));
    }
    let group_dir = group_dir.to_path_buf();
    let staged = staged.to_path_buf();
    let aliases = aliases.clone();
    let candidates: BTreeSet<String> = candidates.iter().map(ToString::to_string).collect();
    blocking(move || {
        require_directory(&staged)?;
        if fs::canonicalize(&group_dir)?.starts_with(fs::canonicalize(&staged)?) {
            return Err(MicrosandboxError::InvalidConfig(
                "snapshot staging must not contain the destination group".into(),
            ));
        }
        let incoming = read_members(&staged, false)?;
        let _lock = lock_group(&group_dir)?;
        let state = read_group(&group_dir)?;
        let mut members = read_members(&group_dir, true)?;
        validate_head(&state, &members)?;

        for (id, member) in &incoming {
            if let Some(existing) = members.get(id) {
                if existing.digest != member.digest {
                    return Err(integrity(format!(
                        "snapshot ID {id} already exists in this group with a different descriptor"
                    )));
                }
            } else {
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

        // Complete members are durable before publishing the head. A crash or I/O error can
        // leave additional complete members, but never a head pointing at a half-written one.
        for (id, member) in &incoming {
            let destination = group_dir.join(id);
            if !path_exists(&destination)? {
                write_member_name(&member.path, members[id].name.as_deref())?;
                sync_directory(&member.path)?;
                fs::rename(&member.path, destination)?;
            }
        }
        for id in aliases.keys() {
            write_member_name(&group_dir.join(id), members[id].name.as_deref())?;
        }
        sync_directory(&group_dir)?;
        if let Some(update) = &update
            && update.changed
        {
            write_group(&group_dir, Some(update.head.clone()))?;
        }
        Ok(update)
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
        read_group(&directory)?;
        // Preflight must not create even a lock file in an existing malformed namespace.
        let lock = process_lock::open_existing_lock_file(&directory.join(".group.lock"))?;
        process_lock::lock_exclusive(&lock)?;
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
    blocking(move || {
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
            write_group(&directory, Some(update.head.clone()))?;
        }
        Ok(update)
    })
    .await
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
    let metadata = fs::symlink_metadata(parent.join(GROUP_FILENAME)).ok()?;
    metadata.file_type().is_file().then(|| parent.to_path_buf())
}

/// Remove a grouped member under its publication lock, returning false for ungrouped paths.
pub(super) async fn remove_member(path: &Path) -> MicrosandboxResult<bool> {
    let path = path.to_path_buf();
    blocking(move || {
        let Some(directory) = group_path(&path) else {
            return Ok(false);
        };
        let _lock = lock_group(&directory)?;
        let state = read_group(&directory)?;
        let members = read_members(&directory, true)?;
        validate_head(&state, &members)?;
        let id = path.file_name().and_then(|name| name.to_str()).ok_or_else(|| {
            MicrosandboxError::InvalidConfig("snapshot member path has no stable ID".into())
        })?;
        if !members.contains_key(id) {
            return Err(MicrosandboxError::SnapshotNotFound(id.into()));
        }
        if state.head.as_deref() == Some(id) {
            if members.len() > 1 {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "cannot remove current head {id}; first select another snapshot with 'msb snapshot head {}:<snapshot>'",
                    directory.file_name().unwrap_or_default().to_string_lossy()
                )));
            }
            // Clear first so an interrupted recursive removal cannot strand a dangling head.
            // A failed removal is recoverable by explicitly selecting the surviving member.
            write_group(&directory, None)?;
        }
        fs::remove_dir_all(&path).map_err(|error| {
            MicrosandboxError::Custom(format!(
                "could not fully remove snapshot {}: {error}; inspect the group before retrying",
                path.display()
            ))
        })?;
        sync_directory(&directory)?;
        Ok(true)
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

fn validate_group_name(name: &str) -> MicrosandboxResult<()> {
    validate_name(name, "group")?;
    if matches!(name, "sha256" | "sha512") || SnapshotId::new(name).is_ok() {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "invalid group name '{name}': reserved snapshot identifier namespace"
        )));
    }
    Ok(())
}

fn lock_group(directory: &Path) -> MicrosandboxResult<File> {
    require_directory(directory)?;
    read_group(directory)?;
    let lock = process_lock::open_lock_file(&directory.join(".group.lock"))?;
    process_lock::lock_exclusive(&lock)?;
    Ok(lock)
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
                "snapshot group {} has no head selected; choose an installed member with 'msb snapshot head {}:<snapshot>'",
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
        head: if changed {
            candidate.into()
        } else {
            previous.unwrap_or(candidate).into()
        },
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
            "--set-head cannot choose between multiple snapshot archive heads with incomparable or unknown ancestry; load without --set-head, then use 'msb snapshot head <group>:<snapshot>'".into(),
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
