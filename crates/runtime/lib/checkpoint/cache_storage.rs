//! Observed memory-cache usage and cooperative reclamation of published RAM files.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, SystemTime};

use cap_primitives::fs as cap_fs;
use microsandbox_utils::process_lock::try_lock_exclusive;
use serde::Serialize;

#[cfg(test)]
use super::memory_cache::open_readonly;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

// Retain the directory cursor between bounded calls so a pinned prefix cannot starve later
// abandoned files. No inode/handoff locks are held between calls; explicit scans are independent.
static SWEEP_CURSORS: LazyLock<Mutex<HashMap<(PathBuf, bool), SweepCursor>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Selection policy shared by explicit pruning and bounded lifecycle sweeps.
#[derive(Clone, Debug, Default)]
pub struct MemoryPruneOptions {
    /// Observe eligibility without unlinking files or creating lock files.
    pub dry_run: bool,
    /// Minimum age of the backing's modification time, independent of ownership checks.
    pub older_than: Duration,
    /// Bound directory entries examined by an opportunistic sweep; explicit prune uses `None`.
    pub max_entries: Option<usize>,
    /// Automatic reclamation targets branch RAM; retain reusable snapshot realizations until explicit prune.
    pub branches_only: bool,
}

/// Namespace of a complete, immutable RAM realization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryCacheKind {
    /// Transient local branch backing.
    BranchMemory,
    /// Rebuildable RAM realized from a durable snapshot's objects.
    SnapshotMemory,
}

/// Eligibility observed while holding the same locks used for actual reclamation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryCacheState {
    /// No owner prevents removal at the instant of inspection.
    Reclaimable,
    /// A mapping, SDK handle, or retained baseline still owns the inode.
    InUse,
    /// A branch request is still transferring ownership to its children.
    PendingHandoff,
    /// The age filter excludes this file.
    TooYoung,
    /// No stable handoff lock exists, so branch ownership cannot be established safely.
    MissingHandoffLock,
    /// The observed file disappeared or was replaced; a subsequent scan can retry it.
    Changed,
    /// This operation successfully unlinked the observed inode.
    Removed,
    /// An I/O or validation failure prevented a safe decision.
    Error,
}

/// Per-file observations; allocated bytes are not exclusive physical ownership on CoW filesystems.
#[derive(Clone, Debug, Serialize)]
pub struct MemoryCacheEntry {
    /// Published backing pathname.
    pub path: PathBuf,
    /// Branch or durable-snapshot realization.
    pub kind: MemoryCacheKind,
    /// Observed logical file length, or unknown when metadata could not be read.
    pub logical_bytes: Option<u64>,
    /// Observed allocated blocks, when supported, without deduplicating shared extents.
    pub allocated_bytes: Option<u64>,
    /// Reason the entry can or cannot be reclaimed.
    pub state: MemoryCacheState,
    /// I/O diagnostic when eligibility could not be established.
    pub error: Option<String>,
}

/// Machine-readable result shared by CLI and SDK reporting.
#[derive(Clone, Debug, Default, Serialize)]
pub struct MemoryCacheReport {
    /// Whether this operation only inspected candidates.
    pub dry_run: bool,
    /// Files observed during this scan.
    pub entries: Vec<MemoryCacheEntry>,
    /// Number of files successfully unlinked.
    pub files_removed: u64,
    /// Sum of logical lengths of files successfully unlinked, not physical bytes freed.
    pub logical_bytes_removed: u64,
    /// Physical reclamation is not measurable from per-file metadata on shared storage.
    pub physical_bytes_reclaimed: Option<u64>,
    /// Whether the scan reached its entry bound before examining both namespaces completely.
    pub truncated: bool,
}

pub(super) struct MemoryFileObservation {
    pub metadata: Option<fs::Metadata>,
    pub state: MemoryCacheState,
}

#[derive(Default)]
struct SweepCursor {
    namespace: usize,
    directory: Option<NamespaceCursor>,
}

struct NamespaceCursor {
    handle: Arc<fs::File>,
    entries: cap_fs::ReadDir,
}

struct MemoryCandidate {
    directory: Arc<fs::File>,
    name: PathBuf,
    display_path: PathBuf,
    kind: MemoryCacheKind,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Inspect published RAM without altering cache contents, permissions, or stable lock files.
pub fn inspect_memory_cache(root: &Path) -> io::Result<MemoryCacheReport> {
    prune_memory_cache(
        root,
        &MemoryPruneOptions {
            dry_run: true,
            ..Default::default()
        },
    )
}

/// Revalidate every candidate under the ownership locks before unlinking it.
///
/// Only recognized, published `.ram` files are eligible. Stable locks, staging directories,
/// anonymous Linux RAM leases, sandbox disks, and durable snapshot objects are never removed.
pub fn prune_memory_cache(
    root: &Path,
    options: &MemoryPruneOptions,
) -> io::Result<MemoryCacheReport> {
    let mut report = MemoryCacheReport {
        dry_run: options.dry_run,
        ..Default::default()
    };
    let root_handle = match open_directory(root) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(report),
        Err(error) => return Err(error),
    };
    let now = SystemTime::now();
    let (candidates, truncated) = candidates(
        root,
        &root_handle,
        options.max_entries,
        options.branches_only,
    )?;
    report.truncated = truncated;
    for candidate in candidates {
        let observation = match candidate.kind {
            MemoryCacheKind::BranchMemory => reclaim_branch_in(
                &candidate.directory,
                &candidate.name,
                !options.dry_run,
                options.older_than,
                now,
            ),
            MemoryCacheKind::SnapshotMemory => reclaim_memory_in(
                &candidate.directory,
                &candidate.name,
                !options.dry_run,
                options.older_than,
                now,
            ),
        };
        let path = candidate.display_path;
        let kind = candidate.kind;
        let entry = match observation {
            Ok(observation) => MemoryCacheEntry {
                path,
                kind,
                logical_bytes: observation.metadata.as_ref().map(fs::Metadata::len),
                allocated_bytes: observation.metadata.as_ref().and_then(allocated_bytes),
                state: observation.state,
                error: None,
            },
            Err(error) => MemoryCacheEntry {
                path,
                kind,
                logical_bytes: None,
                allocated_bytes: None,
                state: MemoryCacheState::Error,
                error: Some(error.to_string()),
            },
        };
        if entry.state == MemoryCacheState::Removed {
            report.files_removed += 1;
            report.logical_bytes_removed = report
                .logical_bytes_removed
                .saturating_add(entry.logical_bytes.unwrap_or(0));
        }
        report.entries.push(entry);
    }
    report.entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(report)
}

fn candidates(
    root: &Path,
    root_handle: &fs::File,
    limit: Option<usize>,
    branches_only: bool,
) -> io::Result<(Vec<MemoryCandidate>, bool)> {
    let mut cursor = if limit.is_some() {
        SWEEP_CURSORS
            .lock()
            .map_err(|_| io::Error::other("memory sweep cursor lock poisoned"))?
            .remove(&(root.to_path_buf(), branches_only))
            .unwrap_or_default()
    } else {
        SweepCursor::default()
    };
    let mut paths = Vec::new();
    let namespaces = [
        ("branches", MemoryCacheKind::BranchMemory),
        ("snapshots", MemoryCacheKind::SnapshotMemory),
    ];
    let mut examined = 0;
    while cursor.namespace < if branches_only { 1 } else { namespaces.len() } {
        let (namespace, kind) = namespaces[cursor.namespace];
        // Re-admit the namespace even when resuming a saved iterator. A removed or replaced
        // directory must not leave that iterator's old names associated with a new pathname.
        let handle = match open_namespace(root_handle, Path::new(namespace)) {
            Ok(handle) => handle,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                cursor.directory = None;
                cursor.namespace += 1;
                continue;
            }
            Err(error) => return Err(error),
        };
        if cursor
            .directory
            .as_ref()
            .is_some_and(|directory| !same_file(&directory.handle, &handle).unwrap_or(false))
        {
            cursor.directory = None;
        }
        if cursor.directory.is_none() {
            let entries = cap_fs::read_base_dir(&handle)?;
            cursor.directory = Some(NamespaceCursor {
                handle: Arc::new(handle),
                entries,
            });
        }
        loop {
            if limit.is_some_and(|limit| examined >= limit) {
                let mut cursors = SWEEP_CURSORS
                    .lock()
                    .map_err(|_| io::Error::other("memory sweep cursor lock poisoned"))?;
                // Keep descriptors bounded even when embedding clients use many backend roots.
                if cursors.len() >= 64 {
                    cursors.clear();
                }
                cursors.insert((root.to_path_buf(), branches_only), cursor);
                return Ok((paths, true));
            }
            let directory = cursor.directory.as_mut().expect("opened namespace");
            match directory.entries.next() {
                Some(item) => {
                    examined += 1;
                    let name = PathBuf::from(item?.file_name());
                    if recognized_name(&name.to_string_lossy(), kind) {
                        paths.push(MemoryCandidate {
                            directory: Arc::clone(&directory.handle),
                            display_path: root.join(namespace).join(&name),
                            name,
                            kind,
                        });
                    }
                }
                None => {
                    cursor.directory = None;
                    cursor.namespace += 1;
                    break;
                }
            }
        }
    }
    Ok((paths, false))
}

pub(super) fn reclaim_branch_file(
    path: &Path,
    remove: bool,
    older_than: Duration,
    now: SystemTime,
) -> io::Result<MemoryFileObservation> {
    let (directory, name) = match file_scope(path) {
        Ok(scope) => scope,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(changed()),
        Err(error) => return Err(error),
    };
    reclaim_branch_in(&directory, &name, remove, older_than, now)
}

fn reclaim_branch_in(
    directory: &fs::File,
    name: &Path,
    remove: bool,
    older_than: Duration,
    now: SystemTime,
) -> io::Result<MemoryFileObservation> {
    // Locks and RAM are resolved relative to the same retained directory. Inspection never
    // creates missing locks, and stable lock names are never unlinked or replaced here.
    let handoff = match open_relative(directory, &name.with_extension("handoff-lock"), true) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return observe_protected(directory, name, MemoryCacheState::MissingHandoffLock);
        }
        Err(error) => return Err(error),
    };
    let metadata = handoff.metadata()?;
    if !metadata.is_file() || is_link(&metadata) {
        return Err(io::Error::other("handoff lock is not a regular file"));
    }
    if !try_lock_exclusive(&handoff)? {
        return observe_protected(directory, name, MemoryCacheState::PendingHandoff);
    }
    reclaim_memory_in(directory, name, remove, older_than, now)
}

/// The inode lock spans identity validation and directory-relative unlink.
pub(super) fn reclaim_memory_file(
    path: &Path,
    remove: bool,
    older_than: Duration,
    now: SystemTime,
) -> io::Result<MemoryFileObservation> {
    let (directory, name) = match file_scope(path) {
        Ok(scope) => scope,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(changed()),
        Err(error) => return Err(error),
    };
    reclaim_memory_in(&directory, &name, remove, older_than, now)
}

fn reclaim_memory_in(
    directory: &fs::File,
    name: &Path,
    remove: bool,
    older_than: Duration,
    now: SystemTime,
) -> io::Result<MemoryFileObservation> {
    let file = match open_relative(directory, name, false) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(changed()),
        Err(error) => return Err(error),
    };
    reclaim_open_file(directory, name, file, remove, older_than, now)
}

fn reclaim_open_file(
    directory: &fs::File,
    name: &Path,
    file: fs::File,
    remove: bool,
    older_than: Duration,
    now: SystemTime,
) -> io::Result<MemoryFileObservation> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || is_link(&metadata) {
        return Err(io::Error::other(
            "memory backing is not a regular non-symlink file",
        ));
    }
    if !try_lock_exclusive(&file)? {
        return Ok(MemoryFileObservation {
            metadata: Some(metadata),
            state: MemoryCacheState::InUse,
        });
    }
    let current = match open_relative(directory, name, false) {
        Ok(current) => current,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(MemoryFileObservation {
                metadata: Some(metadata),
                state: MemoryCacheState::Changed,
            });
        }
        Err(error) => return Err(error),
    };
    if !same_file(&file, &current)? {
        return Ok(MemoryFileObservation {
            metadata: Some(metadata),
            state: MemoryCacheState::Changed,
        });
    }
    // mtime is an age policy only. Pins and handoffs close publication-to-pin intervals.
    let state = if older_than != Duration::ZERO
        && now.duration_since(metadata.modified()?).unwrap_or_default() < older_than
    {
        MemoryCacheState::TooYoung
    } else if remove {
        match cap_fs::remove_file(directory, name) {
            Ok(()) => MemoryCacheState::Removed,
            Err(error) if error.kind() == io::ErrorKind::NotFound => MemoryCacheState::Changed,
            Err(error) => return Err(error),
        }
    } else {
        MemoryCacheState::Reclaimable
    };
    Ok(MemoryFileObservation {
        metadata: Some(metadata),
        state,
    })
}

fn observe_protected(
    directory: &fs::File,
    name: &Path,
    state: MemoryCacheState,
) -> io::Result<MemoryFileObservation> {
    let file = match open_relative(directory, name, false) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(changed()),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || is_link(&metadata) {
        return Err(io::Error::other(
            "memory backing is not a regular non-symlink file",
        ));
    }
    Ok(MemoryFileObservation {
        metadata: Some(metadata),
        state,
    })
}

fn changed() -> MemoryFileObservation {
    MemoryFileObservation {
        metadata: None,
        state: MemoryCacheState::Changed,
    }
}

fn file_scope(path: &Path) -> io::Result<(fs::File, PathBuf)> {
    let absolute = std::path::absolute(path)?;
    let parent = absolute
        .parent()
        .ok_or_else(|| io::Error::other("memory backing has no parent"))?;
    let name = absolute
        .file_name()
        .ok_or_else(|| io::Error::other("memory backing has no filename"))?;
    Ok((open_directory(parent)?, PathBuf::from(name)))
}

fn open_directory(path: &Path) -> io::Result<fs::File> {
    let absolute = std::path::absolute(path)?;
    let parent = absolute
        .parent()
        .ok_or_else(|| io::Error::other("memory cache directory has no parent"))?;
    let name = absolute
        .file_name()
        .ok_or_else(|| io::Error::other("memory cache directory has no name"))?;
    let parent = cap_fs::open_ambient_dir(parent, cap_primitives::ambient_authority())?;
    open_namespace(&parent, Path::new(name))
}

fn open_namespace(parent: &fs::File, name: &Path) -> io::Result<fs::File> {
    let directory = cap_fs::open_dir_nofollow(parent, name)?;
    // Windows junctions and other reparse points are excluded along with symlinks.
    if is_link(&directory.metadata()?) {
        return Err(io::Error::other(
            "memory cache namespace is not a non-symlink directory",
        ));
    }
    Ok(directory)
}

fn open_relative(directory: &fs::File, name: &Path, writable: bool) -> io::Result<fs::File> {
    let mut options = cap_fs::OpenOptions::new();
    options.read(true).write(writable);
    options._cap_fs_ext_follow(cap_fs::FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use cap_fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        options.share_mode(if writable {
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        } else {
            FILE_SHARE_READ | FILE_SHARE_DELETE
        });
    }
    cap_fs::open(directory, name, &options)
}

fn same_file(first: &fs::File, second: &fs::File) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let first = first.metadata()?;
        let second = second.metadata()?;
        Ok((first.dev(), first.ino()) == (second.dev(), second.ino()))
    }
    #[cfg(windows)]
    {
        Ok(super::memory_cache::windows_file_identity(first)?
            == super::memory_cache::windows_file_identity(second)?)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (first, second);
        Ok(false)
    }
}

fn recognized_name(name: &str, kind: MemoryCacheKind) -> bool {
    let Some((identity, page_size)) = name
        .strip_suffix(".ram")
        .and_then(|name| name.rsplit_once('-'))
    else {
        return false;
    };
    if !page_size
        .parse::<u64>()
        .is_ok_and(|size| size.is_power_of_two())
    {
        return false;
    }
    match kind {
        MemoryCacheKind::BranchMemory => {
            !identity.is_empty()
                && identity.len() <= 128
                && identity
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        }
        MemoryCacheKind::SnapshotMemory => identity.strip_prefix("sha256-").is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())
        }),
    }
}

fn is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Junctions and other reparse points must be excluded along with symbolic links.
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn allocated_bytes(metadata: &fs::Metadata) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(metadata.blocks().saturating_mul(512))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_utils::process_lock::{lock_exclusive, lock_shared, open_lock_file};

    fn branch(root: &Path, name: &str) -> PathBuf {
        fs::create_dir_all(root.join("branches")).unwrap();
        let path = root.join("branches").join(format!("{name}-4096.ram"));
        fs::write(&path, vec![7u8; 4096]).unwrap();
        drop(open_lock_file(&path.with_extension("handoff-lock")).unwrap());
        path
    }

    #[test]
    fn dry_run_revalidates_new_pins_and_preserves_stable_locks() {
        let root = tempfile::tempdir().unwrap();
        let path = branch(root.path(), "child");
        let lock = path.with_extension("handoff-lock");
        let before = fs::read_dir(root.path().join("branches")).unwrap().count();
        let report = inspect_memory_cache(root.path()).unwrap();
        assert_eq!(report.entries[0].state, MemoryCacheState::Reclaimable);
        assert_eq!(report.files_removed, 0);
        assert!(path.exists());
        assert_eq!(
            fs::read_dir(root.path().join("branches")).unwrap().count(),
            before
        );

        let pin = open_readonly(&path).unwrap();
        lock_shared(&pin).unwrap();
        let report = prune_memory_cache(root.path(), &MemoryPruneOptions::default()).unwrap();
        assert_eq!(report.entries[0].state, MemoryCacheState::InUse);
        assert_eq!(report.files_removed, 0);
        drop(pin);
        let report = prune_memory_cache(root.path(), &MemoryPruneOptions::default()).unwrap();
        assert_eq!(report.files_removed, 1);
        assert_eq!(report.logical_bytes_removed, 4096);
        assert_eq!(report.physical_bytes_reclaimed, None);
        assert!(lock.exists());
        assert!(!path.exists());
    }

    #[test]
    fn pending_handoffs_and_uncoordinated_files_are_protected() {
        let root = tempfile::tempdir().unwrap();
        let path = branch(root.path(), "pending");
        let handoff = open_lock_file(&path.with_extension("handoff-lock")).unwrap();
        lock_exclusive(&handoff).unwrap();
        let unknown = root.path().join("branches/unreserved-4096.ram");
        fs::write(&unknown, b"retain").unwrap();
        let report = prune_memory_cache(root.path(), &MemoryPruneOptions::default()).unwrap();
        assert_eq!(report.entries[0].state, MemoryCacheState::PendingHandoff);
        assert_eq!(
            report.entries[1].state,
            MemoryCacheState::MissingHandoffLock
        );
        assert_eq!(report.files_removed, 0);
        assert!(!unknown.with_extension("handoff-lock").exists());
    }

    #[test]
    fn age_boundary_is_inclusive_and_future_mtime_stays_protected() {
        let root = tempfile::tempdir().unwrap();
        let path = branch(root.path(), "age");
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000);
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(time))
            .unwrap();
        for (now, state) in [
            (time - Duration::from_secs(1), MemoryCacheState::TooYoung),
            (time + Duration::from_secs(59), MemoryCacheState::TooYoung),
            (
                time + Duration::from_secs(60),
                MemoryCacheState::Reclaimable,
            ),
        ] {
            assert_eq!(
                reclaim_branch_file(&path, false, Duration::from_secs(60), now)
                    .unwrap()
                    .state,
                state
            );
        }
        assert!(path.exists());
    }

    #[test]
    fn concurrent_sweepers_only_count_each_removed_file_once() {
        let root = tempfile::tempdir().unwrap();
        for id in 0..20 {
            branch(root.path(), &format!("child{id}"));
        }
        let removed = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        prune_memory_cache(root.path(), &MemoryPruneOptions::default()).unwrap()
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| {
                    let report = worker.join().unwrap();
                    assert!(
                        !report
                            .entries
                            .iter()
                            .any(|entry| entry.state == MemoryCacheState::Error),
                        "{report:?}"
                    );
                    report.files_removed
                })
                .sum::<u64>()
        });
        assert_eq!(removed, 20);
        assert!(
            inspect_memory_cache(root.path())
                .unwrap()
                .entries
                .is_empty()
        );
    }

    #[test]
    fn bounded_scans_advance_past_a_pinned_prefix_and_keep_snapshot_cache() {
        let root = tempfile::tempdir().unwrap();
        let mut pins = Vec::new();
        for id in 0..12 {
            let path = branch(root.path(), &format!("pinned{id}"));
            let pin = open_readonly(&path).unwrap();
            lock_shared(&pin).unwrap();
            pins.push(pin);
        }
        let stale = branch(root.path(), "stale");
        fs::create_dir_all(root.path().join("snapshots")).unwrap();
        let snapshot = root
            .path()
            .join(format!("snapshots/sha256-{}-4096.ram", "a".repeat(64)));
        fs::write(&snapshot, b"warm snapshot realization").unwrap();
        let options = MemoryPruneOptions {
            max_entries: Some(2),
            branches_only: true,
            ..Default::default()
        };
        for _ in 0..40 {
            prune_memory_cache(root.path(), &options).unwrap();
        }
        assert!(!stale.exists());
        assert!(snapshot.exists());
        assert_eq!(pins.len(), 12);
        let explicit = prune_memory_cache(root.path(), &MemoryPruneOptions::default()).unwrap();
        assert_eq!(explicit.files_removed, 1);
        assert!(!snapshot.exists());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_cursor_rejects_a_namespace_replaced_by_a_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        for name in ["first", "second", "third"] {
            branch(root.path(), name);
            branch(outside.path(), name);
        }
        let preview = MemoryPruneOptions {
            dry_run: true,
            max_entries: Some(1),
            branches_only: true,
            ..Default::default()
        };
        assert!(prune_memory_cache(root.path(), &preview).unwrap().truncated);

        fs::rename(root.path().join("branches"), root.path().join("original")).unwrap();
        symlink(
            outside.path().join("branches"),
            root.path().join("branches"),
        )
        .unwrap();
        let apply = MemoryPruneOptions {
            dry_run: false,
            ..preview
        };
        assert!(prune_memory_cache(root.path(), &apply).is_err());
        for name in ["first", "second", "third"] {
            assert_eq!(
                fs::read(outside.path().join(format!("branches/{name}-4096.ram"))).unwrap(),
                vec![7; 4096]
            );
            assert!(
                root.path()
                    .join(format!("original/{name}-4096.ram"))
                    .exists()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn admitted_candidates_keep_their_directory_across_namespace_replacement() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        branch(root.path(), "selected");
        let foreign = branch(outside.path(), "selected");
        let root_handle = open_directory(root.path()).unwrap();
        let (selected, truncated) = candidates(root.path(), &root_handle, None, true).unwrap();
        assert!(!truncated);
        assert_eq!(selected.len(), 1);

        // Replace the namespace after discovery, before opening either the handoff or RAM.
        // Every subsequent operation must stay relative to the admitted directory handle.
        fs::rename(root.path().join("branches"), root.path().join("original")).unwrap();
        symlink(
            outside.path().join("branches"),
            root.path().join("branches"),
        )
        .unwrap();
        let candidate = &selected[0];
        let removed = reclaim_branch_in(
            &candidate.directory,
            &candidate.name,
            true,
            Duration::ZERO,
            SystemTime::now(),
        )
        .unwrap();
        assert_eq!(removed.state, MemoryCacheState::Removed);
        assert_eq!(fs::read(&foreign).unwrap(), vec![7; 4096]);
        assert!(foreign.with_extension("handoff-lock").exists());
        assert!(
            root.path()
                .join("original/selected-4096.handoff-lock")
                .exists()
        );
        assert!(!root.path().join("original/selected-4096.ram").exists());
    }

    #[cfg(unix)]
    #[test]
    fn initial_namespace_symlinks_are_rejected_without_touching_their_targets() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let foreign = branch(outside.path(), "outside");
        symlink(
            outside.path().join("branches"),
            root.path().join("branches"),
        )
        .unwrap();
        assert!(inspect_memory_cache(root.path()).is_err());
        assert!(prune_memory_cache(root.path(), &MemoryPruneOptions::default()).is_err());
        assert_eq!(fs::read(&foreign).unwrap(), vec![7; 4096]);
    }

    #[test]
    fn absent_cache_inspection_has_no_filesystem_side_effects() {
        let root = tempfile::tempdir().unwrap();
        let absent = root.path().join("absent");
        assert!(inspect_memory_cache(&absent).unwrap().entries.is_empty());
        assert!(!absent.exists());
    }

    #[test]
    fn replacement_after_open_is_never_unlinked() {
        let root = tempfile::tempdir().unwrap();
        let path = branch(root.path(), "replacement");
        let opened = open_readonly(&path).unwrap();
        fs::rename(&path, root.path().join("old-inode")).unwrap();
        fs::write(&path, b"new backing").unwrap();
        let (directory, name) = file_scope(&path).unwrap();
        let observation = reclaim_open_file(
            &directory,
            &name,
            opened,
            true,
            Duration::ZERO,
            SystemTime::now(),
        )
        .unwrap();
        assert_eq!(observation.state, MemoryCacheState::Changed);
        assert_eq!(fs::read(&path).unwrap(), b"new backing");
    }

    #[test]
    fn abrupt_owner_exit_releases_pins_for_a_later_sweep() {
        struct ChildOwner(std::process::Child);
        impl Drop for ChildOwner {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let root = tempfile::tempdir().unwrap();
        let path = branch(root.path(), "process-owner");
        let ready = path.with_extension("ready");
        let mut owner = ChildOwner(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "checkpoint::cache_storage::tests::child_process_pin",
                    "--ignored",
                ])
                .env("MSB_STORAGE_TEST_PIN", &path)
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(
                owner.0.try_wait().unwrap().is_none(),
                "pin helper exited early"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "pin helper did not start"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            prune_memory_cache(root.path(), &MemoryPruneOptions::default())
                .unwrap()
                .entries[0]
                .state,
            MemoryCacheState::InUse
        );
        // SIGKILL/TerminateProcess bypasses all Rust destructors, just like a crashed runtime.
        owner.0.kill().unwrap();
        owner.0.wait().unwrap();
        assert_eq!(
            prune_memory_cache(root.path(), &MemoryPruneOptions::default())
                .unwrap()
                .files_removed,
            1
        );
    }

    #[test]
    #[ignore = "subprocess helper launched with an isolated backing path by abrupt_owner_exit"]
    fn child_process_pin() {
        let Some(path) = std::env::var_os("MSB_STORAGE_TEST_PIN") else {
            return;
        };
        let path = PathBuf::from(path);
        let pin = open_readonly(&path).unwrap();
        lock_shared(&pin).unwrap();
        fs::write(path.with_extension("ready"), b"ready").unwrap();
        loop {
            std::thread::park();
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_unknown_artifacts_and_staging_are_never_deleted() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("keep");
        fs::write(&target, b"private").unwrap();
        fs::create_dir_all(root.path().join("branches/.capture-private")).unwrap();
        fs::write(
            root.path().join("branches/.capture-private/memory"),
            b"partial",
        )
        .unwrap();
        fs::write(root.path().join("branches/unknown.txt"), b"keep").unwrap();
        let linked = root.path().join("branches/linked-4096.ram");
        symlink(&target, &linked).unwrap();
        drop(open_lock_file(&linked.with_extension("handoff-lock")).unwrap());
        let report = prune_memory_cache(root.path(), &MemoryPruneOptions::default()).unwrap();
        assert_eq!(report.files_removed, 0);
        assert_eq!(report.entries[0].state, MemoryCacheState::Error);
        assert_eq!(fs::read(&target).unwrap(), b"private");
        assert!(
            root.path()
                .join("branches/.capture-private/memory")
                .exists()
        );
        assert!(root.path().join("branches/unknown.txt").exists());
        let alias = outside.path().join("alias");
        symlink(root.path(), &alias).unwrap();
        assert!(inspect_memory_cache(&alias).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn errors_preserve_successful_removal_counts_and_outcomes() {
        let root = tempfile::tempdir().unwrap();
        let removable = branch(root.path(), "removable");
        let outside = root.path().join("unmanaged");
        fs::write(&outside, b"preserve").unwrap();
        let invalid = root.path().join("branches/invalid-4096.ram");
        std::os::unix::fs::symlink(&outside, &invalid).unwrap();

        let report = prune_memory_cache(root.path(), &MemoryPruneOptions::default()).unwrap();
        assert_eq!(report.files_removed, 1);
        assert_eq!(report.logical_bytes_removed, 4096);
        assert_eq!(report.physical_bytes_reclaimed, None);
        assert_eq!(report.entries.len(), 2);
        let error = report
            .entries
            .iter()
            .find(|entry| entry.path == invalid)
            .unwrap();
        assert_eq!(error.state, MemoryCacheState::Error);
        assert!(error.error.is_some());
        assert_eq!(error.logical_bytes, None);
        assert_eq!(
            report
                .entries
                .iter()
                .find(|entry| entry.path == removable)
                .unwrap()
                .state,
            MemoryCacheState::Removed
        );
        assert!(!removable.exists());
        assert!(removable.with_extension("handoff-lock").exists());
        assert!(invalid.is_symlink());
        assert_eq!(fs::read(outside).unwrap(), b"preserve");
    }
}
