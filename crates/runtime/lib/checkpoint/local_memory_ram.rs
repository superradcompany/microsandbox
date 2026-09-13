//! Bounded Linux tmpfs storage for ephemeral local branch generations.
//!
//! This is not a portable snapshot store. A RAM-side handoff lock complements the ordinary
//! backend reservation; tmpfs files use the same immutable inode pins as disk-backed RAM.

use std::fs::File;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
#[cfg(any(feature = "runner", test))]
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
};

#[cfg(any(feature = "runner", test))]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(any(feature = "runner", test))]
use super::memory_cache::evict_unpinned;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(any(feature = "runner", test))]
const LEASE_SCHEMA: &str = "microsandbox.local-memory-ram/1";
#[cfg(any(feature = "runner", test))]
const LEASE_NAME: &str = "reservation.json";
#[cfg(any(feature = "runner", test))]
const HOST_HEADROOM: u64 = 256 * 1024 * 1024;
#[cfg(any(feature = "runner", test))]
const MAX_LEASE_BYTES: u64 = 16 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(any(feature = "runner", test))]
struct Lease {
    schema: String,
    capacity: u64,
    handoff_lock: PathBuf,
    filename: String,
}

#[cfg(any(feature = "runner", test))]
pub(super) struct RamAllocation {
    pub(super) staging: tempfile::TempDir,
    pub(super) path: PathBuf,
    pub(super) publication: RamPublication,
}

#[cfg(any(feature = "runner", test))]
pub(super) struct RamPublication {
    root: PathBuf,
    lease: Lease,
    // This lock exists before the destination memory inode does. In particular it protects
    // baseline copying, whose copy/reflink helper may create or replace that inode.
    _staging_pin: File,
}

#[derive(Default)]
#[cfg(any(feature = "runner", test))]
struct Usage {
    charged: u64,
    pending: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[cfg(any(feature = "runner", test))]
impl RamPublication {
    /// Move accounting from the pending reservation to the immutable file under the same
    /// allocation lock. The caller already holds a shared pin on the staging inode.
    pub(super) fn publish(&self, staging: &Path, destination: &Path) -> io::Result<()> {
        let _allocation = allocation_lock(&self.root)?;
        let metadata = destination.with_extension("ram-lease");
        write_lease(&metadata, &self.lease)?;
        if let Err(error) = std::fs::hard_link(staging.join("memory"), destination) {
            let _ = std::fs::remove_file(&metadata);
            return Err(error);
        }
        std::fs::remove_file(staging.join(LEASE_NAME))?;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Reserve worst-case written bytes before source quiescence. Absence, pressure or an unusable
/// optional facility returns None; actual baseline copying remains the caller's fallible work.
#[cfg(any(feature = "runner", test))]
pub(super) fn prepare(
    backend_root: &Path,
    disk_root: &Path,
    id: &str,
    page_size: u64,
    capacity: u64,
) -> Option<RamAllocation> {
    // Unit tests exercise both choices through the injected probe below; ordinary capture
    // tests consistently exercise RAM admission regardless of the test host's filesystem.
    #[cfg(test)]
    let probe = || {
        let _ = disk_root;
        Ok(false)
    };
    #[cfg(not(test))]
    let probe = || probe_reflink(disk_root);
    optional_storage(
        "preparation",
        prepare_with_probe(backend_root, id, page_size, capacity, probe),
    )
}

#[cfg(any(feature = "runner", test))]
fn prepare_with_probe(
    backend_root: &Path,
    id: &str,
    page_size: u64,
    capacity: u64,
    probe_reflink: impl FnOnce() -> io::Result<bool>,
) -> io::Result<Option<RamAllocation>> {
    let Some((root, namespace)) = storage_namespace(backend_root)? else {
        return Ok(None);
    };
    let filename = format!("{id}-{page_size}.ram");
    let handoff_lock = namespace.join(&filename).with_extension("handoff-lock");
    let reservation = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&handoff_lock)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    // The initiating SDK must already own this stable RAM-side handoff lock. Otherwise the
    // existing backend reservation remains authoritative and capture uses the disk path.
    if microsandbox_utils::process_lock::try_lock_exclusive(&reservation)? {
        return Ok(None);
    }
    // On a reflink-capable backend, retaining disk-backed generations preserves their cheap
    // extent sharing. Moving them to tmpfs would turn subsequent clones into full RAM copies.
    if probe_reflink()? {
        return Ok(None);
    }
    let _allocation = allocation_lock(&root)?;
    reclaim(&root)?;
    let usage = usage(&root)?;
    let (total, available) = memory_capacity()?;
    let shared = File::open(&root)?;
    let mut filesystem: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(shared.as_raw_fd(), &mut filesystem) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let free = (filesystem.f_bavail as u64).saturating_mul(filesystem.f_frsize as u64);
    if !admits(capacity, total, available, free, &usage) {
        tracing::debug!(target: "microsandbox_checkpoint_timing", operation = "local_memory_ram_admission", capacity, available, free, charged = usage.charged, pending = usage.pending, "retain disk-backed local memory under RAM pressure");
        return Ok(None);
    }
    let staging = tempfile::Builder::new()
        .prefix(".capture-")
        .tempdir_in(&namespace)?;
    let lease = Lease {
        schema: LEASE_SCHEMA.into(),
        capacity,
        handoff_lock,
        filename,
    };
    let staging_pin = write_lease(&staging.path().join(LEASE_NAME), &lease)?;
    microsandbox_utils::process_lock::lock_shared(&staging_pin)?;
    Ok(Some(RamAllocation {
        path: namespace.join(&lease.filename),
        staging,
        publication: RamPublication {
            root,
            lease,
            _staging_pin: staging_pin,
        },
    }))
}

#[cfg(any(feature = "runner", test))]
fn probe_reflink(disk_root: &Path) -> io::Result<bool> {
    let probe = tempfile::Builder::new()
        .prefix(".reflink-probe-")
        .tempdir_in(disk_root)?;
    let source = probe.path().join("source");
    std::fs::write(&source, [1; 8192])?;
    let (_, strategy) =
        microsandbox_utils::copy::fast_copy_without_sync(&source, &probe.path().join("clone"))?;
    Ok(strategy == microsandbox_utils::copy::FastCopyStrategy::Reflink)
}

/// Retain this alongside the ordinary backend reservation. It is deliberately independent
/// of MSB_HOME so pending publication survives source exit and backend-directory removal.
pub(super) fn reserve(backend_root: &Path, id: &str, page_size: u64) -> Option<File> {
    optional_storage(
        "reservation",
        (|| {
            let Some((_, namespace)) = storage_namespace(backend_root)? else {
                return Ok(None);
            };
            let path = namespace.join(format!("{id}-{page_size}.handoff-lock"));
            let file = microsandbox_utils::process_lock::open_lock_file(&path)?;
            microsandbox_utils::process_lock::lock_exclusive(&file)?;
            Ok(Some(file))
        })(),
    )
}

fn optional_storage<T>(stage: &'static str, result: io::Result<Option<T>>) -> Option<T> {
    match result {
        Ok(value) => value,
        Err(error) => {
            // The mandatory backend reservation/disk strategy remains available. Do not try
            // to repair insecure paths or change permissions to enable an optional RAM cache.
            tracing::debug!(target: "microsandbox_checkpoint_timing", operation = "local_memory_ram_unavailable", stage, %error, "retain disk-backed local memory");
            None
        }
    }
}

fn storage_namespace(backend_root: &Path) -> io::Result<Option<(PathBuf, PathBuf)>> {
    // Unit tests keep every artifact in their own temporary backend; release live tests
    // exercise the real tmpfs mount. This never redirects another user's global test state.
    #[cfg(test)]
    let root = backend_root.join(".test-ram-cache");
    #[cfg(not(test))]
    let root = {
        let shared = match File::open("/dev/shm") {
            Ok(shared) => shared,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(shared.as_raw_fd(), &mut filesystem) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if filesystem.f_type != libc::TMPFS_MAGIC {
            return Ok(None);
        }
        let uid = unsafe { libc::geteuid() };
        PathBuf::from(format!("/dev/shm/microsandbox-memory-{uid}"))
    };
    protected_directory(&root)?;
    let canonical = std::fs::canonicalize(backend_root)?;
    use std::os::unix::ffi::OsStrExt;
    let namespace = root.join(hex::encode(Sha256::digest(
        canonical.as_os_str().as_bytes(),
    )));
    protected_directory(&namespace)?;
    Ok(Some((root, namespace)))
}

#[cfg(any(feature = "runner", test))]
fn admits(request: u64, total: u64, available: u64, free: u64, usage: &Usage) -> bool {
    let Some(required) = request.checked_add(usage.pending) else {
        return false;
    };
    request != 0
        && usage
            .charged
            .checked_add(request)
            .is_some_and(|charged| charged <= total / 2)
        && required <= free
        && required
            .checked_add(HOST_HEADROOM.max(request / 4))
            .is_some_and(|needed| needed <= available)
}

fn protected_directory(path: &Path) -> io::Result<()> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "RAM cache directory is not owned by this user",
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "RAM cache directory permits access by other users",
        ));
    }
    Ok(())
}

#[cfg(any(feature = "runner", test))]
fn allocation_lock(root: &Path) -> io::Result<File> {
    let file = microsandbox_utils::process_lock::open_lock_file(&root.join("allocation.lock"))?;
    microsandbox_utils::process_lock::lock_exclusive(&file)?;
    Ok(file)
}

#[cfg(any(feature = "runner", test))]
fn write_lease(path: &Path, lease: &Lease) -> io::Result<File> {
    let bytes = serde_json::to_vec(lease).map_err(io::Error::other)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&bytes)?;
    Ok(file)
}

#[cfg(any(feature = "runner", test))]
fn read_lease(path: &Path) -> io::Result<Option<Lease>> {
    let mut bytes = Vec::new();
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Ok(None);
    }
    file.take(MAX_LEASE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LEASE_BYTES {
        return Ok(None);
    }
    let Ok(lease) = serde_json::from_slice::<Lease>(&bytes) else {
        return Ok(None);
    };
    if lease.schema != LEASE_SCHEMA
        || lease.capacity == 0
        || lease.filename.strip_suffix(".ram").is_none_or(|stem| {
            stem.is_empty()
                || stem
                    .bytes()
                    .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')))
        })
        || !lease.handoff_lock.is_absolute()
    {
        return Ok(None);
    }
    Ok(Some(lease))
}

#[cfg(any(feature = "runner", test))]
fn usage(root: &Path) -> io::Result<Usage> {
    let mut usage = Usage::default();
    for namespace in std::fs::read_dir(root)? {
        let namespace = namespace?;
        if !namespace.file_type()?.is_dir()
            || namespace
                .file_name()
                .to_str()
                .is_none_or(|name| name.len() != 64 || !name.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            continue;
        }
        for entry in std::fs::read_dir(namespace.path())? {
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(".capture-"))
            {
                if let Some(lease) = read_lease(&entry.path().join(LEASE_NAME))? {
                    let allocated = std::fs::metadata(entry.path().join("memory"))
                        .map(|m| m.blocks().saturating_mul(512))
                        .unwrap_or(0);
                    usage.charged = usage.charged.saturating_add(lease.capacity);
                    usage.pending = usage
                        .pending
                        .saturating_add(lease.capacity.saturating_sub(allocated));
                }
            } else if entry.file_type()?.is_file()
                && entry.path().extension().is_some_and(|ext| ext == "ram")
            {
                let metadata = match entry.metadata() {
                    Ok(metadata) => metadata,
                    // A consumer can release and explicitly evict its backing between this
                    // directory entry and stat. It no longer contributes resident cache bytes.
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error),
                };
                usage.charged = usage
                    .charged
                    .saturating_add(metadata.blocks().saturating_mul(512));
            }
        }
    }
    Ok(usage)
}

#[cfg(any(feature = "runner", test))]
fn reclaim(root: &Path) -> io::Result<()> {
    for namespace in std::fs::read_dir(root)? {
        let namespace = namespace?;
        if namespace.file_type()?.is_dir()
            && namespace
                .file_name()
                .to_str()
                .is_some_and(|name| name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            protected_directory(&namespace.path())?;
            reclaim_namespace(&namespace.path())?;
        }
    }
    Ok(())
}

#[cfg(any(feature = "runner", test))]
fn reclaim_namespace(namespace: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(namespace)? {
        let entry = entry?;
        let staging = entry.file_type()?.is_dir()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".capture-"));
        let lease_path = if staging {
            entry.path().join(LEASE_NAME)
        } else if entry.file_type()?.is_file()
            && entry
                .path()
                .extension()
                .is_some_and(|ext| ext == "ram-lease")
        {
            entry.path()
        } else {
            continue;
        };
        let Some(lease) = read_lease(&lease_path)? else {
            continue;
        };
        // Preparation owns the reservation inode before opening/copying any RAM file. A
        // cancelled SDK handoff alone therefore cannot make a half-copied baseline eligible
        // for removal. Hold this lock through cleanup to exclude any still-running producer.
        let _staging_pin = if staging {
            let pin = match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&lease_path)
            {
                Ok(pin) => pin,
                // Successful completion/cancellation can drop the producer's TempDir after
                // we read its lease. A vanished staging entry needs no further reclamation.
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if !microsandbox_utils::process_lock::try_lock_exclusive(&pin)? {
                continue;
            }
            Some(pin)
        } else {
            None
        };
        if !staging && lease_path.file_stem() != Path::new(&lease.filename).file_stem() {
            continue;
        }
        if lease.handoff_lock.parent() != Some(namespace)
            || lease.handoff_lock.file_stem() != Path::new(&lease.filename).file_stem()
            || lease
                .handoff_lock
                .extension()
                .is_none_or(|extension| extension != "handoff-lock")
        {
            continue;
        }
        let handoff = match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&lease.handoff_lock)
        {
            Ok(file) => file,
            // A manually removed RAM-side guard is not proof of no pending handoff. Never
            // create a replacement inode that could bypass a still-open original lock.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !microsandbox_utils::process_lock::try_lock_exclusive(&handoff)? {
            continue;
        }
        let memory = if staging {
            entry.path().join("memory")
        } else {
            namespace.join(&lease.filename)
        };
        if !evict_unpinned(&memory)? && memory.exists() {
            continue;
        }
        std::fs::remove_file(&lease_path)?;
        if staging {
            // Only remove the now-empty owned staging directory, never recursively delete an
            // unrecognized payload that happens to share this namespace.
            match std::fs::remove_dir(entry.path()) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

#[cfg(any(feature = "runner", test))]
fn memory_capacity() -> io::Result<(u64, u64)> {
    let contents = std::fs::read_to_string("/proc/meminfo")?;
    let read = |name| {
        contents.lines().find_map(|line| {
            let mut words = line.split_whitespace();
            (words.next()? == name)
                .then(|| words.next()?.parse::<u64>().ok()?.checked_mul(1024))
                .flatten()
        })
    };
    let total = read("MemTotal:").ok_or_else(|| io::Error::other("MemTotal is unavailable"))?;
    let available =
        read("MemAvailable:").ok_or_else(|| io::Error::other("MemAvailable is unavailable"))?;
    Ok(limit_cgroup_capacity(
        (total, available),
        std::fs::read_to_string("/proc/self/cgroup"),
        |path| std::fs::read_to_string(path),
    ))
}

#[cfg(any(feature = "runner", test))]
fn limit_cgroup_capacity(
    (mut total, mut available): (u64, u64),
    groups: io::Result<String>,
    mut read: impl FnMut(&Path) -> io::Result<String>,
) -> (u64, u64) {
    // RAM is optional. Unknown restrictions must select disk backing, not size an allocation
    // using machine-wide memory or turn a missing optional facility into a branch failure.
    let Ok(groups) = groups else {
        return (0, 0);
    };
    let mut unified = None;
    for line in groups.lines() {
        let mut fields = line.splitn(3, ':');
        let (Some(hierarchy), Some(controllers), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return (0, 0);
        };
        if controllers
            .split(',')
            .any(|controller| controller == "memory")
        {
            // Resolving v1's independent mount/controller hierarchy is not implemented. Even
            // a hybrid host's v2 hierarchy cannot describe a separately mounted v1 limit.
            return (0, 0);
        }
        if hierarchy == "0" && controllers.is_empty() {
            if unified.replace(path).is_some() {
                return (0, 0);
            }
        }
    }
    // A runtime inside a cgroup must not admit against the machine-wide number alone. Check
    // each visible v2 ancestor, because a leaf can be unlimited beneath a constrained parent.
    if let Some(relative) = unified {
        let root = Path::new("/sys/fs/cgroup");
        if !relative.starts_with('/') || read(&root.join("cgroup.controllers")).is_err() {
            return (0, 0);
        }
        let relative = Path::new(relative.trim_start_matches('/'));
        if !relative
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
        {
            return (0, 0);
        }
        let mut scope = root.join(relative);
        // A nonstandard mount/cgroup namespace may not expose the proc path beneath this
        // mount. Do not mistake that unresolved path for a disabled memory controller.
        if scope != root && read(&scope.join("cgroup.events")).is_err() {
            return (0, 0);
        }
        loop {
            match read(&scope.join("memory.max")) {
                Ok(limit) if limit.trim() == "max" => {}
                Ok(limit) => {
                    let Ok(limit) = limit.trim().parse::<u64>() else {
                        return (0, 0);
                    };
                    let Ok(current) = read(&scope.join("memory.current")) else {
                        return (0, 0);
                    };
                    let Ok(current) = current.trim().parse::<u64>() else {
                        return (0, 0);
                    };
                    total = total.min(limit);
                    available = available.min(limit.saturating_sub(current));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return (0, 0),
            }
            if scope == root || !scope.pop() {
                break;
            }
        }
    }
    (total, available)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unusable_optional_storage_selects_disk_without_repair() {
        for error in [libc::EACCES, libc::EROFS, libc::ENOSPC, libc::ENOENT] {
            assert!(
                optional_storage::<File>("test", Err(io::Error::from_raw_os_error(error)),)
                    .is_none()
            );
        }
        assert_eq!(optional_storage("test", Ok(Some(7))), Some(7));
        assert_eq!(optional_storage::<u64>("test", Ok(None)), None);

        let temp = tempfile::tempdir().unwrap();
        let cache = temp.path().join(".test-ram-cache");
        std::fs::create_dir(&cache).unwrap();
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(reserve(temp.path(), "unusable", 4096).is_none());
        assert!(prepare(temp.path(), temp.path(), "unusable", 4096, 4096).is_none());
        assert_eq!(
            std::fs::metadata(cache).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn unknown_or_v1_memory_limits_decline_optional_ram() {
        let host = (8192, 6144);
        for groups in [
            Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            Ok("2:cpu,memory:/limited".into()),
            Ok("2:memory:/limited\n0::/unified".into()),
            Ok("0::/../../outside".into()),
            Ok("malformed".into()),
        ] {
            let capacity = limit_cgroup_capacity(host, groups, |_| {
                Err(io::Error::from(io::ErrorKind::NotFound))
            });
            assert_eq!(capacity, (0, 0));
        }
        assert_eq!(
            limit_cgroup_capacity(host, Ok("0::/".into()), |_| {
                Err(io::Error::from(io::ErrorKind::NotFound))
            }),
            (0, 0)
        );
    }

    #[test]
    fn v2_admission_honors_ancestors_and_disabled_controllers() {
        let host = (8192, 6144);
        let groups = Ok("0::/parent/child".into());
        let capacity = limit_cgroup_capacity(host, groups, |path| match path.to_str().unwrap() {
            "/sys/fs/cgroup/cgroup.controllers" => Ok("memory cpu".into()),
            "/sys/fs/cgroup/parent/child/cgroup.events" => Ok("populated 1".into()),
            "/sys/fs/cgroup/parent/child/memory.max" => Ok("max".into()),
            "/sys/fs/cgroup/parent/memory.max" => Ok("4096".into()),
            "/sys/fs/cgroup/parent/memory.current" => Ok("1024".into()),
            _ => Err(io::Error::from(io::ErrorKind::NotFound)),
        });
        assert_eq!(capacity, (4096, 3072));
        let disabled = limit_cgroup_capacity(host, Ok("0::/".into()), |path| {
            if path.ends_with("cgroup.controllers") {
                Ok("cpu".into())
            } else {
                Err(io::Error::from(io::ErrorKind::NotFound))
            }
        });
        assert_eq!(disabled, host);
    }

    #[test]
    fn unreadable_or_malformed_v2_limits_decline_optional_ram() {
        for (limit, current) in [
            (Err(io::ErrorKind::PermissionDenied), Ok("0")),
            (Ok("invalid"), Ok("0")),
            (Ok("4096"), Err(io::ErrorKind::NotFound)),
            (Ok("4096"), Ok("invalid")),
        ] {
            let capacity = limit_cgroup_capacity((8192, 6144), Ok("0::/".into()), |path| {
                if path.ends_with("cgroup.controllers") {
                    Ok("memory".into())
                } else if path.ends_with("memory.max") {
                    limit.map(String::from).map_err(io::Error::from)
                } else {
                    current.map(String::from).map_err(io::Error::from)
                }
            });
            assert_eq!(capacity, (0, 0));
        }
    }

    #[test]
    fn admission_bounds_live_bytes_pending_bytes_and_host_headroom() {
        let gib = 1024 * 1024 * 1024;
        assert!(admits(gib, 8 * gib, 4 * gib, 4 * gib, &Usage::default()));
        assert!(!admits(gib, 8 * gib, gib, 4 * gib, &Usage::default()));
        assert!(!admits(gib, 8 * gib, 4 * gib, gib / 2, &Usage::default()));
        assert!(!admits(
            gib,
            8 * gib,
            4 * gib,
            4 * gib,
            &Usage {
                charged: 4 * gib,
                pending: 0
            }
        ));
        assert!(!admits(
            gib,
            8 * gib,
            2 * gib,
            4 * gib,
            &Usage {
                charged: gib,
                pending: gib
            }
        ));
        assert!(!admits(
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            &Usage {
                charged: 0,
                pending: 1
            }
        ));
    }

    #[test]
    fn protected_namespace_refuses_symlinks_and_broad_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("private");
        protected_directory(&target).unwrap();
        std::os::unix::fs::symlink(&target, temp.path().join("alias")).unwrap();
        assert!(protected_directory(&temp.path().join("alias")).is_err());
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(protected_directory(&target).is_err());
    }

    #[test]
    fn reflink_capable_backend_keeps_disk_generations() {
        let temp = tempfile::tempdir().unwrap();
        let _handoff = reserve(temp.path(), "choice", 4096).unwrap();
        let disk = prepare_with_probe(temp.path(), "choice", 4096, 8192, || Ok(true)).unwrap();
        assert!(disk.is_none());
        let ram = prepare_with_probe(temp.path(), "choice", 4096, 8192, || Ok(false)).unwrap();
        assert!(ram.is_some());
        drop(ram);

        // The real bounded probe leaves no files behind on either filesystem strategy.
        let probe_root = temp.path().join("probe");
        std::fs::create_dir(&probe_root).unwrap();
        let _supported = probe_reflink(&probe_root).unwrap();
        assert_eq!(std::fs::read_dir(&probe_root).unwrap().count(), 0);
    }

    #[test]
    fn reclamation_respects_handoff_and_live_inode_pins() {
        let temp = tempfile::tempdir().unwrap();
        let namespace = temp.path().join("a".repeat(64));
        protected_directory(&namespace).unwrap();
        let handoff_path = namespace.join("branch_1-4096.handoff-lock");
        let handoff = microsandbox_utils::process_lock::open_lock_file(&handoff_path).unwrap();
        microsandbox_utils::process_lock::lock_exclusive(&handoff).unwrap();
        let file = namespace.join("branch_1-4096.ram");
        std::fs::write(&file, b"guest ram").unwrap();
        let lease = Lease {
            schema: LEASE_SCHEMA.into(),
            capacity: 4096,
            handoff_lock: handoff_path,
            filename: "branch_1-4096.ram".into(),
        };
        let metadata = file.with_extension("ram-lease");
        write_lease(&metadata, &lease).unwrap();
        reclaim_namespace(&namespace).unwrap();
        assert!(file.exists());
        let pin = super::super::memory_cache::open_pinned(&file, 9)
            .unwrap()
            .unwrap();
        drop(handoff);
        reclaim_namespace(&namespace).unwrap();
        assert!(file.exists());
        drop(pin);
        reclaim_namespace(&namespace).unwrap();
        assert!(!file.exists());
        assert!(!metadata.exists());
    }

    #[test]
    fn accounting_charges_pending_capacity_then_only_published_pages() {
        let temp = tempfile::tempdir().unwrap();
        let namespace = temp.path().join("b".repeat(64));
        protected_directory(&namespace).unwrap();
        let staging = tempfile::Builder::new()
            .prefix(".capture-")
            .tempdir_in(&namespace)
            .unwrap();
        let lease = Lease {
            schema: LEASE_SCHEMA.into(),
            capacity: 1024 * 1024,
            handoff_lock: temp.path().join("handoff"),
            filename: "branch_2-4096.ram".into(),
        };
        let staging_pin = write_lease(&staging.path().join(LEASE_NAME), &lease).unwrap();
        microsandbox_utils::process_lock::lock_shared(&staging_pin).unwrap();
        let before = usage(temp.path()).unwrap();
        assert_eq!(before.charged, 1024 * 1024);
        assert_eq!(before.pending, 1024 * 1024);
        let file = staging.path().join("memory");
        std::fs::write(&file, vec![7; 8192]).unwrap();
        let allocated = std::fs::metadata(&file).unwrap().blocks() * 512;
        let writing = usage(temp.path()).unwrap();
        assert_eq!(writing.charged, 1024 * 1024);
        assert_eq!(writing.pending, (1024u64 * 1024).saturating_sub(allocated));
        let published = namespace.join(&lease.filename);
        let publication = RamPublication {
            root: temp.path().into(),
            lease,
            _staging_pin: staging_pin,
        };
        publication.publish(staging.path(), &published).unwrap();
        let after = usage(temp.path()).unwrap();
        assert_eq!(after.pending, 0);
        assert_eq!(after.charged, allocated);
    }

    #[test]
    fn cancelled_handoff_cannot_reclaim_a_baseline_copy_in_progress() {
        let temp = tempfile::tempdir().unwrap();
        let handoff = reserve(temp.path(), "copy", 4096).unwrap();
        let allocation = prepare(temp.path(), temp.path(), "copy", 4096, 8192)
            .expect("tiny RAM reservation fits");
        let namespace = allocation.path.parent().unwrap();
        let memory = allocation.staging.path().join("memory");
        let lease = allocation.staging.path().join(LEASE_NAME);
        drop(handoff);

        // Reproduce both vulnerable points deterministically: no destination inode yet, and
        // an unlocked destination halfway through baseline copy. The metadata pin must cover
        // both, independently of the writer pin only acquired after prepare has completed.
        reclaim_namespace(namespace).unwrap();
        assert!(lease.exists());
        let mut copy = File::create(&memory).unwrap();
        copy.write_all(&[7; 4096]).unwrap();
        reclaim_namespace(namespace).unwrap();
        assert!(memory.exists());
        copy.write_all(&[9; 4096]).unwrap();
        drop(copy);
        assert_eq!(
            std::fs::read(&memory).unwrap(),
            [vec![7; 4096], vec![9; 4096]].concat()
        );

        // Producer loss releases the extra pin. With neither a pending SDK handoff nor a
        // memory pin remaining, the same incomplete staging generation can be reclaimed.
        drop(allocation.publication);
        reclaim_namespace(namespace).unwrap();
        assert!(!lease.exists());
        assert!(!memory.exists());
    }

    #[test]
    fn malformed_or_mismatched_lease_never_removes_another_file() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("branch_1-4096.ram");
        std::fs::write(&file, b"keep").unwrap();
        let lease = Lease {
            schema: LEASE_SCHEMA.into(),
            capacity: 4096,
            handoff_lock: temp.path().join("handoff"),
            filename: "branch_1-4096.ram".into(),
        };
        write_lease(&temp.path().join("different.ram-lease"), &lease).unwrap();
        std::fs::write(temp.path().join("broken.ram-lease"), b"not JSON").unwrap();
        reclaim_namespace(temp.path()).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"keep");
    }
}
