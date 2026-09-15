//! Backing allocation and admission for sandbox-owned, unnamed volumes.

use std::collections::HashSet;
use std::fs::File;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use microsandbox_image::ext4::{Ext4FormatOptions, format_ext4};
use microsandbox_types::{OwnedVolumeStorage, VolumeMount};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve a canonical mount identity without accepting a serialized host path.
pub(crate) fn backing_path(
    sandbox_dir: &Path,
    guest: &str,
    storage: &OwnedVolumeStorage,
) -> PathBuf {
    sandbox_dir
        .join("owned-volumes")
        .join(microsandbox_types::owned_volume_mount_id(guest))
        .join(match storage {
            OwnedVolumeStorage::Directory { .. } => "data",
            OwnedVolumeStorage::Disk { .. } => "disk.raw",
        })
}

/// Allocate only on initial creation. Restarts and restores must find their existing backing.
pub(crate) async fn prepare(
    sandbox_dir: &Path,
    mounts: &[VolumeMount],
    restored: bool,
) -> MicrosandboxResult<()> {
    let owned: Vec<_> = mounts
        .iter()
        .filter(|mount| matches!(mount, VolumeMount::Owned { .. }))
        .cloned()
        .collect();
    if owned.is_empty() {
        return Ok(());
    }
    validate_tags(mounts)?;
    if restored {
        return validate(sandbox_dir, mounts);
    }
    let destination = sandbox_dir.join("owned-volumes");
    if destination.try_exists()? {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "owned volume backing already exists: {}",
            destination.display()
        )));
    }
    tokio::fs::create_dir_all(sandbox_dir).await?;
    let parent = sandbox_dir
        .parent()
        .ok_or_else(|| MicrosandboxError::InvalidConfig("sandbox directory has no parent".into()))?
        .to_path_buf();
    // The blocking worker owns its operation-unique directory. Cancellation cannot
    // leave a late formatter writing into a replacement sandbox's name.
    let stage = tokio::task::spawn_blocking(move || -> MicrosandboxResult<tempfile::TempDir> {
        let stage = tempfile::Builder::new()
            .prefix(".owned-volume-create-")
            .tempdir_in(parent)?;
        for mount in owned {
            let VolumeMount::Owned { guest, storage, .. } = mount else {
                unreachable!()
            };
            let directory = stage
                .path()
                .join(microsandbox_types::owned_volume_mount_id(&guest));
            std::fs::create_dir(&directory)?;
            match storage {
                OwnedVolumeStorage::Directory { .. } => {
                    std::fs::create_dir(directory.join("data"))?
                }
                OwnedVolumeStorage::Disk { capacity_mib } => {
                    if capacity_mib == 0 {
                        return Err(MicrosandboxError::InvalidConfig(
                            "owned disk size must be positive".into(),
                        ));
                    }
                    format_ext4(
                        &directory.join("disk.raw"),
                        &Ext4FormatOptions {
                            size_bytes: u64::from(capacity_mib) * 1024 * 1024,
                            ..Default::default()
                        },
                    )
                    .map_err(|error| {
                        MicrosandboxError::Custom(format!("format owned disk {guest}: {error}"))
                    })?;
                }
            }
        }
        Ok(stage)
    })
    .await
    .map_err(|error| MicrosandboxError::Custom(format!("owned volume preparation: {error}")))??;
    // No await between publication and returning to the retained creation cleanup.
    std::fs::rename(stage.path(), &destination)?;
    validate(sandbox_dir, mounts)
}

/// Admit existing backing without recreating missing state or following planted symlinks.
pub(crate) fn validate(sandbox_dir: &Path, mounts: &[VolumeMount]) -> MicrosandboxResult<()> {
    if !mounts
        .iter()
        .any(|mount| matches!(mount, VolumeMount::Owned { .. }))
    {
        return Ok(());
    }
    validate_tags(mounts)?;
    for mount in mounts {
        let VolumeMount::Owned { guest, storage, .. } = mount else {
            continue;
        };
        let path = backing_path(sandbox_dir, guest, storage);
        for component in [path.parent().and_then(Path::parent), path.parent()]
            .into_iter()
            .flatten()
        {
            let metadata = std::fs::symlink_metadata(component).map_err(|error| {
                MicrosandboxError::InvalidConfig(format!(
                    "owned volume {guest} backing unavailable at {}: {error}",
                    component.display()
                ))
            })?;
            if metadata.file_type().is_symlink() {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "owned volume {guest} backing must not be a symlink"
                )));
            }
        }
        if let OwnedVolumeStorage::Disk { capacity_mib } = storage {
            let mount_id = microsandbox_types::owned_volume_mount_id(guest);
            if let Some(chain) = microsandbox_runtime::checkpoint::load_runtime_owned_disk_chain(
                &sandbox_dir.join("runtime"),
                &mount_id,
            )
            .map_err(MicrosandboxError::InvalidConfig)?
            {
                if chain.device_id != mount_id
                    || chain.virtual_size != u64::from(*capacity_mib) * 1024 * 1024
                {
                    return Err(MicrosandboxError::InvalidConfig(format!(
                        "owned volume {guest} chain identity or capacity differs from its configuration"
                    )));
                }
                // A restored or compacted chain need not retain its original disk.raw.
                // Loading the journal validates its complete, confined physical closure.
                continue;
            }
        }
        if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "owned volume {guest} backing must not be a symlink"
            )));
        }
        let metadata = std::fs::metadata(&path)?;
        let correct = match storage {
            OwnedVolumeStorage::Directory { .. } => metadata.is_dir(),
            OwnedVolumeStorage::Disk { capacity_mib } => {
                metadata.is_file() && metadata.len() == u64::from(*capacity_mib) * 1024 * 1024
            }
        };
        if !correct {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "owned volume {guest} backing kind or capacity does not match its configuration"
            )));
        }
    }
    Ok(())
}

/// Lock the owned device's lifetime, not a data inode that checkpointing can replace.
pub(crate) fn disk_lock_path(sandbox_dir: &Path, guest: &str) -> MicrosandboxResult<PathBuf> {
    let path = owned_disk_lock_path(sandbox_dir, guest);
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    if !std::fs::symlink_metadata(&path)?.file_type().is_file() {
        return Err(MicrosandboxError::InvalidConfig(
            "owned disk lock must be a regular file".into(),
        ));
    }
    Ok(path)
}

/// Fence owned-disk teardown after acquiring the sandbox's transition and lifecycle guards.
///
/// Linux may release the inherited lifecycle lock before deferred KVM/file teardown releases the
/// disk locks, even with an already-zombie process leader. Inspect the resources themselves rather
/// than a recycled PID. Only owned disks belong to this fence: named/external disks can legitimately
/// have another owner after this runtime exits. Missing markers are not created by observation.
/// Windows probes the exclusive sidecar rather than the actual disk image.
pub(crate) fn try_acquire_disk_guards(
    sandbox_dir: &Path,
    mounts: &[VolumeMount],
) -> MicrosandboxResult<Option<Vec<File>>> {
    let mut guards = Vec::new();
    for mount in mounts {
        let VolumeMount::Owned {
            guest,
            storage: OwnedVolumeStorage::Disk { .. },
            ..
        } = mount
        else {
            continue;
        };
        let path = owned_disk_lock_path(sandbox_dir, guest);
        #[cfg(windows)]
        let path = super::spawn::windows_disk_lock_path(&path)?;
        // Match owned backing admission: a missing directory is fine for observation, but a
        // redirected (including dangling) parent must not turn a different inode into the fence.
        for parent in [path.parent().and_then(Path::parent), path.parent()]
            .into_iter()
            .flatten()
        {
            match std::fs::symlink_metadata(parent) {
                Ok(metadata) if !metadata.file_type().is_dir() => {
                    return Err(MicrosandboxError::InvalidConfig(format!(
                        "owned disk lock parent must be a real directory: {}",
                        parent.display()
                    )));
                }
                Ok(metadata) => {
                    #[cfg(windows)]
                    if metadata.file_attributes()
                        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                        != 0
                    {
                        return Err(MicrosandboxError::InvalidConfig(
                            "owned disk lock parent must not be a reparse point".into(),
                        ));
                    }
                    #[cfg(unix)]
                    let _ = metadata;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options
            // A planted FIFO must not block this synchronous probe before fstat can reject it.
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        #[cfg(windows)]
        options
            .share_mode(0)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
        let file = match options.open(&path) {
            Ok(file) => file,
            // Never-started or already-removed sandboxes need no disk ownership release.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            #[cfg(windows)]
            Err(error) if matches!(error.raw_os_error(), Some(32 | 33)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !file.metadata()?.is_file() {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "owned disk lock is not a regular file: {}",
                path.display()
            )));
        }
        #[cfg(windows)]
        if file.metadata()?.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(MicrosandboxError::InvalidConfig(
                "owned disk lock must not be a reparse point".into(),
            ));
        }
        #[cfg(unix)]
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                // Dropping partial acquisitions is important: a cancelled waiter must not
                // retain one disk while another disk's owner is still completing shutdown.
                return Ok(None);
            }
            return Err(error.into());
        }
        guards.push(file);
    }
    Ok(Some(guards))
}

/// Wait within the existing restart budget without weakening disk attachment admission.
/// Caller retains transition and lifecycle ownership until the new process is launched.
pub(crate) async fn wait_for_disk_release(
    sandbox_dir: &Path,
    mounts: &[VolumeMount],
    timeout: std::time::Duration,
) -> MicrosandboxResult<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if try_acquire_disk_guards(sandbox_dir, mounts)?.is_some() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(MicrosandboxError::SandboxStillRunning(format!(
                "owned disks for {} are still held after waiting for runtime teardown",
                sandbox_dir.display()
            )));
        }
        // This is an ownership observation, not an unconditional grace period. The usual
        // released case returns above immediately; cancellation drops no persistent state.
        tokio::time::sleep_until(
            deadline.min(tokio::time::Instant::now() + std::time::Duration::from_millis(1)),
        )
        .await;
    }
}

fn owned_disk_lock_path(sandbox_dir: &Path, guest: &str) -> PathBuf {
    sandbox_dir
        .join("owned-volumes")
        .join(microsandbox_types::owned_volume_mount_id(guest))
        .join(".disk-owner")
}

fn validate_tags(mounts: &[VolumeMount]) -> MicrosandboxResult<()> {
    let mut tags = HashSet::new();
    for mount in mounts {
        let tag = if matches!(mount, VolumeMount::Owned { .. }) {
            microsandbox_types::owned_volume_mount_id(mount.guest())
        } else {
            super::spawn::guest_mount_tag(mount.guest())
        };
        if !tags.insert(tag) {
            return Err(MicrosandboxError::InvalidConfig(
                "volume mount identities collide".into(),
            ));
        }
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::MountBuilder;

    fn disk_marker_fixture() -> (tempfile::TempDir, Vec<VolumeMount>) {
        let directory = tempfile::tempdir().unwrap();
        let mounts: Vec<_> = ["/data", "/logs"]
            .into_iter()
            .map(|guest| {
                MountBuilder::new(guest)
                    .owned_with(|owned| owned.disk().size(1_u32))
                    .build()
                    .unwrap()
            })
            .collect();
        for mount in &mounts {
            let path = owned_disk_lock_path(directory.path(), mount.guest());
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            disk_lock_path(directory.path(), mount.guest()).unwrap();
            #[cfg(windows)]
            drop(
                File::create(super::super::spawn::windows_disk_lock_path(&path).unwrap()).unwrap(),
            );
        }
        (directory, mounts)
    }

    #[test]
    fn disk_teardown_probe_releases_partial_guards_and_never_creates_markers() {
        let (directory, mounts) = disk_marker_fixture();
        let last_owner = try_acquire_disk_guards(directory.path(), &mounts[1..])
            .unwrap()
            .unwrap();
        assert!(
            try_acquire_disk_guards(directory.path(), &mounts)
                .unwrap()
                .is_none()
        );
        // A failed multi-disk probe must not leave its first disk pinned.
        assert!(
            try_acquire_disk_guards(directory.path(), &mounts[..1])
                .unwrap()
                .is_some()
        );
        drop(last_owner);
        let guards = try_acquire_disk_guards(directory.path(), &mounts)
            .unwrap()
            .unwrap();
        assert_eq!(guards.len(), 2);
        #[cfg(unix)]
        for guard in &guards {
            assert_ne!(
                unsafe { libc::fcntl(guard.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
        drop(guards);
        let absent = directory.path().join("never-created");
        assert!(
            try_acquire_disk_guards(&absent, &mounts)
                .unwrap()
                .unwrap()
                .is_empty()
        );
        assert!(!absent.exists());
    }

    #[cfg(unix)]
    #[test]
    fn disk_teardown_probe_refuses_symlink_and_non_file_markers() {
        use std::os::unix::ffi::OsStrExt;
        let (directory, mounts) = disk_marker_fixture();
        let marker = owned_disk_lock_path(directory.path(), mounts[0].guest());
        std::fs::remove_file(&marker).unwrap();
        std::os::unix::fs::symlink(
            owned_disk_lock_path(directory.path(), mounts[1].guest()),
            &marker,
        )
        .unwrap();
        assert!(try_acquire_disk_guards(directory.path(), &mounts).is_err());
        std::fs::remove_file(&marker).unwrap();
        std::fs::create_dir(&marker).unwrap();
        assert!(try_acquire_disk_guards(directory.path(), &mounts).is_err());
        std::fs::remove_dir(&marker).unwrap();
        let fifo = std::ffi::CString::new(marker.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(try_acquire_disk_guards(directory.path(), &mounts).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn disk_teardown_probe_refuses_redirected_or_dangling_parents() {
        let (directory, mounts) = disk_marker_fixture();
        let marker = owned_disk_lock_path(directory.path(), mounts[0].guest());
        let parent = marker.parent().unwrap();
        let moved = directory.path().join("relocated");
        std::fs::rename(parent, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, parent).unwrap();
        assert!(try_acquire_disk_guards(directory.path(), &mounts).is_err());
        std::fs::remove_file(parent).unwrap();
        std::os::unix::fs::symlink(directory.path().join("absent"), parent).unwrap();
        assert!(try_acquire_disk_guards(directory.path(), &mounts).is_err());
    }

    #[tokio::test]
    async fn restart_disk_fence_is_bounded_cancel_safe_and_release_driven() {
        use std::time::Duration;
        let (directory, mounts) = disk_marker_fixture();
        let owner = try_acquire_disk_guards(directory.path(), &mounts)
            .unwrap()
            .unwrap();
        assert!(matches!(
            wait_for_disk_release(directory.path(), &mounts, Duration::from_millis(10)).await,
            Err(MicrosandboxError::SandboxStillRunning(_))
        ));
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                wait_for_disk_release(directory.path(), &mounts, Duration::from_secs(5))
            )
            .await
            .is_err()
        );
        assert!(
            try_acquire_disk_guards(directory.path(), &mounts)
                .unwrap()
                .is_none()
        );
        drop(owner);
        // Parallel Unix tests may temporarily inherit the owner's CLOEXEC descriptors
        // between fork and exec. Dropping our copy alone does not fence those children.
        wait_for_disk_release(directory.path(), &mounts, Duration::from_secs(5))
            .await
            .unwrap();
        // Test zero-budget admission on markers that have never been locked: even a
        // successful probe of the first fixture could itself be inherited by a fork.
        let (unowned_directory, unowned_mounts) = disk_marker_fixture();
        wait_for_disk_release(unowned_directory.path(), &unowned_mounts, Duration::ZERO)
            .await
            .unwrap();
    }

    #[test]
    fn no_owned_mounts_leave_legacy_admission_unchanged() {
        // Repeated guest tags are deliberately left to existing mount validation when
        // this feature is absent; owned admission must not inspect paths or allocate tags.
        let mount = MountBuilder::new("/legacy").tmpfs().build().unwrap();
        validate(
            Path::new("nonexistent-owned-admission-root"),
            &[mount.clone(), mount],
        )
        .unwrap();
    }

    #[tokio::test]
    async fn directory_is_empty_private_and_never_recreated_on_restart() {
        let home = tempfile::tempdir().unwrap();
        let sandbox = home.path().join("source");
        let mount = MountBuilder::new("/data").owned().build().unwrap();
        prepare(&sandbox, std::slice::from_ref(&mount), false)
            .await
            .unwrap();
        let path = backing_path(
            &sandbox,
            "/data",
            &OwnedVolumeStorage::Directory { quota_mib: None },
        );
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
        std::fs::write(path.join("kept"), b"persisted").unwrap();
        validate(&sandbox, std::slice::from_ref(&mount)).unwrap();
        assert_eq!(std::fs::read(path.join("kept")).unwrap(), b"persisted");
        assert!(
            prepare(&sandbox, std::slice::from_ref(&mount), false)
                .await
                .is_err()
        );
        std::fs::remove_dir_all(&path).unwrap();
        assert!(prepare(&sandbox, &[mount], true).await.is_err());
        assert!(
            !path.exists(),
            "missing data must not silently become an empty volume"
        );
    }

    #[test]
    fn owned_ids_are_portable_and_unaffected_by_argument_order() {
        for guest in ["/data", "/var/lib/docker", "/résultats/文件", "/work files"] {
            let id = microsandbox_types::owned_volume_mount_id(guest);
            assert!(id.len() <= 20);
            assert!(
                id.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
            );
            assert_eq!(id, microsandbox_types::owned_volume_mount_id(guest));
        }
        assert_ne!(
            microsandbox_types::owned_volume_mount_id("/var/log"),
            microsandbox_types::owned_volume_mount_id("/var_log")
        );
    }

    #[tokio::test]
    async fn owned_disk_is_sized_ext4_and_detects_truncation() {
        let home = tempfile::tempdir().unwrap();
        let sandbox = home.path().join("source");
        let mount = MountBuilder::new("/data")
            .owned_with(|v| v.disk().size(256_u32))
            .build()
            .unwrap();
        prepare(&sandbox, std::slice::from_ref(&mount), false)
            .await
            .unwrap();
        let path = backing_path(
            &sandbox,
            "/data",
            &OwnedVolumeStorage::Disk { capacity_mib: 256 },
        );
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 256 * 1024 * 1024);
        file.set_len(1024).unwrap();
        assert!(validate(&sandbox, &[mount]).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn owned_backing_rejects_symlink_escape() {
        let home = tempfile::tempdir().unwrap();
        let sandbox = home.path().join("source");
        let mount = MountBuilder::new("/data").owned().build().unwrap();
        prepare(&sandbox, std::slice::from_ref(&mount), false)
            .await
            .unwrap();
        let path = backing_path(
            &sandbox,
            "/data",
            &OwnedVolumeStorage::Directory { quota_mib: None },
        );
        std::fs::remove_dir(&path).unwrap();
        std::os::unix::fs::symlink(home.path(), &path).unwrap();
        assert!(validate(&sandbox, &[mount]).is_err());
    }
}
