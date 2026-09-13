//! Cross-process accounting for ephemeral memfds. Only tiny lease records live on disk.

// Client-only builds need handoff/pin helpers, but do not allocate generations themselves.
#![cfg_attr(not(feature = "runner"), allow(dead_code))]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use microsandbox_utils::process_lock::{
    lock_exclusive, lock_shared, open_lock_file, try_lock_exclusive,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Lease {
    schema: String,
    capacity: u64,
    allocated: Option<u64>,
}

pub(super) struct Reservation {
    pub(super) path: PathBuf,
    pin: File,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Reservation {
    pub(super) fn publish(mut self, allocated: u64) -> io::Result<(PathBuf, File)> {
        let _lock = allocation_lock(self.path.parent().unwrap())?;
        let mut lease = read_lease(&self.pin)?;
        lease.allocated = Some(allocated);
        self.pin.seek(SeekFrom::Start(0))?;
        let bytes = serde_json::to_vec(&lease)?;
        self.pin.write_all(&bytes)?;
        self.pin.set_len(bytes.len() as u64)?;
        Ok((self.path, self.pin))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn protected_directory(path: &Path) -> io::Result<()> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unprotected memory accounting directory",
        ));
    }
    Ok(())
}

fn root(_backend: &Path) -> io::Result<PathBuf> {
    #[cfg(test)]
    let path = _backend.join(".test-memfd-budget");
    #[cfg(not(test))]
    let path = PathBuf::from(format!("/tmp/microsandbox-memory-{}", unsafe {
        libc::geteuid()
    }));
    protected_directory(&path)?;
    Ok(path)
}

fn stem(backend: &Path, id: &str, page: u64) -> io::Result<String> {
    use std::os::unix::ffi::OsStrExt;
    let canonical = std::fs::canonicalize(backend)?;
    Ok(format!(
        "{}-{id}-{page}",
        hex::encode(Sha256::digest(canonical.as_os_str().as_bytes()))
    ))
}

/// Bridge capture-to-child accounting even if the source exits before the child acquires its pin.
pub(super) fn handoff(backend: &Path, id: &str, page: u64) -> io::Result<File> {
    let path = root(backend)?.join(format!("{}.handoff", stem(backend, id, page)?));
    let file = open_lock_file(&path)?;
    lock_exclusive(&file)?;
    Ok(file)
}

fn allocation_lock(root: &Path) -> io::Result<File> {
    let file = open_lock_file(&root.join("allocation.lock"))?;
    lock_exclusive(&file)?;
    Ok(file)
}

fn read_lease(file: &File) -> io::Result<Lease> {
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    reader.take(1025).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 {
        return Err(io::Error::other("oversized memory lease"));
    }
    let lease: Lease = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if lease.schema != "msb-memfd-budget-1" {
        return Err(io::Error::other("unrecognized memory lease"));
    }
    Ok(lease)
}

/// Each runtime retains a separate shared lease lock for as long as it owns the backing.
pub(super) fn pin(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::other("invalid memory lease"));
    }
    lock_shared(&file)?;
    Ok(file)
}

pub(super) fn reserve(
    backend: &Path,
    disk: &Path,
    id: &str,
    page: u64,
    capacity: u64,
) -> io::Result<Option<Reservation>> {
    // Preserve extent sharing on reflink filesystems instead of replacing a cheap clone with
    // a full populated-RAM copy. Probe results are not a promise about the later copy itself.
    let probe = tempfile::Builder::new()
        .prefix(".reflink-probe-")
        .tempdir_in(disk)?;
    let source = probe.path().join("source");
    std::fs::write(&source, [1; 8192])?;
    let reflink = microsandbox_utils::copy::reflink(&source, &probe.path().join("clone")).is_ok();
    if reflink && !cfg!(test) {
        return Ok(None);
    }
    let root = root(backend)?;
    let name = stem(backend, id, page)?;
    let handoff = open_lock_file(&root.join(format!("{name}.handoff")))?;
    if try_lock_exclusive(&handoff)? {
        return Ok(None);
    }
    let _lock = allocation_lock(&root)?;
    let (charged, pending) = usage_and_reclaim(&root)?;
    let (total, available) = memory_capacity()?;
    if !admits(capacity, total, available, charged, pending) {
        tracing::debug!(target: "microsandbox_checkpoint_timing", operation = "local_memory_ram_admission", capacity, total, available, charged, pending, "retain disk backing under memory pressure");
        return Ok(None);
    }
    let path = root.join(format!("{name}.lease"));
    let mut pin = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    lock_shared(&pin)?;
    pin.write_all(&serde_json::to_vec(&Lease {
        schema: "msb-memfd-budget-1".into(),
        capacity,
        allocated: None,
    })?)?;
    Ok(Some(Reservation { path, pin }))
}

fn usage_and_reclaim(root: &Path) -> io::Result<(u64, u64)> {
    let (mut charged, mut pending) = (0u64, 0u64);
    for entry in std::fs::read_dir(root)? {
        let path = entry?.path();
        if path.extension().is_none_or(|ext| ext != "lease") {
            continue;
        }
        let file = pin(&path)?;
        let lease = read_lease(&file)?;
        // A new open description tests other owners without releasing their shared locks.
        let exclusive = try_lock_exclusive(&file)?;
        let handoff = open_lock_file(&path.with_extension("handoff"))?;
        if exclusive && try_lock_exclusive(&handoff)? {
            std::fs::remove_file(&path)?;
            continue;
        }
        charged = charged.saturating_add(lease.allocated.unwrap_or(lease.capacity));
        if lease.allocated.is_none() {
            pending = pending.saturating_add(lease.capacity);
        }
    }
    Ok((charged, pending))
}

fn admits(request: u64, total: u64, available: u64, charged: u64, pending: u64) -> bool {
    request != 0
        && charged.checked_add(request).is_some_and(|n| n <= total / 2)
        && pending
            .checked_add(request)
            .and_then(|n| n.checked_add((256 * 1024 * 1024).max(request / 4)))
            .is_some_and(|n| n <= available)
}

fn memory_capacity() -> io::Result<(u64, u64)> {
    let contents = std::fs::read_to_string("/proc/meminfo")?;
    let read = |key| {
        contents.lines().find_map(|line| {
            let mut words = line.split_whitespace();
            (words.next()? == key)
                .then(|| words.next()?.parse::<u64>().ok()?.checked_mul(1024))
                .flatten()
        })
    };
    let total = read("MemTotal:").ok_or_else(|| io::Error::other("missing MemTotal"))?;
    let available =
        read("MemAvailable:").ok_or_else(|| io::Error::other("missing MemAvailable"))?;
    Ok(limit_cgroups(
        (total, available),
        std::fs::read_to_string("/proc/self/cgroup"),
        |p| std::fs::read_to_string(p),
    ))
}

fn limit_cgroups(
    (mut total, mut available): (u64, u64),
    groups: io::Result<String>,
    mut read: impl FnMut(&Path) -> io::Result<String>,
) -> (u64, u64) {
    let Ok(groups) = groups else {
        return (0, 0);
    };
    let mut unified = None;
    for line in groups.lines() {
        let parts = line.splitn(3, ':').collect::<Vec<_>>();
        if parts.len() != 3 || parts[1].split(',').any(|c| c == "memory") {
            return (0, 0);
        }
        if parts[0] == "0" && parts[1].is_empty() && unified.replace(parts[2]).is_some() {
            return (0, 0);
        }
    }
    if let Some(relative) = unified {
        let root = Path::new("/sys/fs/cgroup");
        if !relative.starts_with('/') || read(&root.join("cgroup.controllers")).is_err() {
            return (0, 0);
        }
        let relative = Path::new(relative.trim_start_matches('/'));
        if relative
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return (0, 0);
        }
        let mut scope = root.join(relative);
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
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
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
    fn simultaneous_reservations_keep_private_write_headroom() {
        let gib = 1 << 30;
        assert!(admits(gib, 8 * gib, 4 * gib, gib, gib));
        assert!(!admits(gib, 8 * gib, 2 * gib, gib, gib));
        assert!(!admits(gib, 8 * gib, 7 * gib, 4 * gib, 0));
        assert!(!admits(u64::MAX, u64::MAX, u64::MAX, 0, 1));
    }

    #[test]
    fn accounting_survives_source_and_launcher_release_until_child_drops() {
        let dir = tempfile::tempdir().unwrap();
        let root = root(dir.path()).unwrap();
        let path = root.join("test.lease");
        let handoff = open_lock_file(&path.with_extension("handoff")).unwrap();
        lock_exclusive(&handoff).unwrap();
        let mut source = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        lock_shared(&source).unwrap();
        source
            .write_all(
                &serde_json::to_vec(&Lease {
                    schema: "msb-memfd-budget-1".into(),
                    capacity: 8192,
                    allocated: Some(4096),
                })
                .unwrap(),
            )
            .unwrap();
        drop(source);
        assert_eq!(usage_and_reclaim(&root).unwrap(), (4096, 0));
        let child = pin(&path).unwrap();
        drop(handoff);
        assert_eq!(usage_and_reclaim(&root).unwrap(), (4096, 0));
        drop(child);
        assert_eq!(usage_and_reclaim(&root).unwrap(), (0, 0));
        assert!(!path.exists());
    }

    #[test]
    fn cgroup_ancestors_and_unknown_limits_bound_admission() {
        let limited = limit_cgroups((8192, 6144), Ok("0::/parent/child".into()), |p| {
            match p.to_str().unwrap() {
                "/sys/fs/cgroup/cgroup.controllers" => Ok("memory cpu".into()),
                "/sys/fs/cgroup/parent/child/cgroup.events" => Ok("populated 1".into()),
                "/sys/fs/cgroup/parent/child/memory.max" => Ok("max".into()),
                "/sys/fs/cgroup/parent/memory.max" => Ok("4096".into()),
                "/sys/fs/cgroup/parent/memory.current" => Ok("1024".into()),
                _ => Err(io::ErrorKind::NotFound.into()),
            }
        });
        assert_eq!(limited, (4096, 3072));
        for groups in ["2:memory:/limited", "0::/../../outside", "bad"] {
            assert_eq!(
                limit_cgroups((8192, 6144), Ok(groups.into()), |_| Err(
                    io::ErrorKind::NotFound.into()
                )),
                (0, 0)
            );
        }
    }

    #[test]
    fn metadata_paths_refuse_symlinks_and_broad_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private");
        protected_directory(&path).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(protected_directory(&alias).is_err());
        std::fs::set_permissions(path.clone(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(protected_directory(&path).is_err());
    }
}
