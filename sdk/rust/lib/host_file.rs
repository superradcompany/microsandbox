//! Bounded host file admission. Validate the opened inode, never stat then reopen.

#[cfg(target_os = "linux")]
use std::ffi::OsStr;
#[cfg(unix)]
use std::ffi::{CStr, CString};
use std::fs::{File, FileType, OpenOptions};
use std::io;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Kind of host inode a caller accepts once it is open.
#[derive(Debug, Clone, Copy)]
pub(crate) enum HostFileKind {
    /// A regular file, such as a sandbox log.
    Regular,

    /// A disk image file or a host block device.
    #[cfg(unix)]
    Disk,
}

/// Access mode requested when opening a host file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostFileAccess {
    /// Open read-only.
    ReadOnly,

    /// Open read-write.
    #[cfg(unix)]
    ReadWrite,
}

/// Symlink and path-traversal policy applied when opening a host file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostFilePolicy {
    /// Follow symlinks normally while still validating the opened inode type.
    Standard,

    /// Reject symlinks and parent (`..`) components throughout the path.
    #[cfg_attr(not(test), allow(dead_code))]
    Strict,

    /// Anchor at a trusted host root directory and reject symlinks and parent (`..`)
    /// components strictly beneath it (falling back to full-path strict checks if
    /// the target lies outside the root).
    StrictBeneath(PathBuf),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HostFileKind {
    fn admits(self, file_type: FileType) -> bool {
        match self {
            Self::Regular => file_type.is_file(),
            #[cfg(unix)]
            Self::Disk => file_type.is_file() || file_type.is_block_device(),
        }
    }

    fn rejection(self) -> &'static str {
        match self {
            Self::Regular => "host source is not a regular file",
            #[cfg(unix)]
            Self::Disk => "host source is not a regular file or block device",
        }
    }
}

impl HostFileAccess {
    fn is_writable(self) -> bool {
        match self {
            Self::ReadOnly => false,
            #[cfg(unix)]
            Self::ReadWrite => true,
        }
    }
}

impl HostFilePolicy {
    #[cfg(test)]
    pub(crate) fn from_strict(strict: bool) -> Self {
        if strict { Self::Strict } else { Self::Standard }
    }

    pub(crate) fn strict_beneath(root: PathBuf) -> Self {
        Self::StrictBeneath(root)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open a host file and keep it only if the opened inode is of the expected kind.
///
/// On Unix, opens never wait for a FIFO peer. [`HostFilePolicy::Strict`] rejects
/// symlinks in every path component, while [`HostFilePolicy::StrictBeneath`] opens
/// the trusted root once and enforces symlink-free traversal beneath it.
pub(crate) fn open(
    path: &Path,
    kind: HostFileKind,
    access: HostFileAccess,
    policy: &HostFilePolicy,
) -> io::Result<File> {
    let file = match policy {
        HostFilePolicy::Strict => open_without_symlinks(path, kind, access)?,
        HostFilePolicy::StrictBeneath(root) => {
            open_beneath_without_symlinks(root, path, kind, access)?
        }
        HostFilePolicy::Standard => {
            let mut options = OpenOptions::new();
            options.read(true).write(access.is_writable());

            #[cfg(unix)]
            options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);

            options.open(path)?
        }
    };

    if !kind.admits(file.metadata()?.file_type()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            kind.rejection(),
        ));
    }

    Ok(file)
}

#[cfg(unix)]
fn open_without_symlinks(
    path: &Path,
    kind: HostFileKind,
    access: HostFileAccess,
) -> io::Result<File> {
    let anchor = if path.is_absolute() { "/" } else { "." };
    let directory = open_search_directory(Path::new(anchor))?;
    open_components_without_symlinks(directory, path, kind, access)
}

#[cfg(unix)]
fn open_beneath_without_symlinks(
    root: &Path,
    path: &Path,
    kind: HostFileKind,
    access: HostFileAccess,
) -> io::Result<File> {
    let Ok(relative) = path.strip_prefix(root) else {
        return open_without_symlinks(path, kind, access);
    };

    let directory = open_search_directory(root)?;
    open_components_without_symlinks(directory, relative, kind, access)
}

#[cfg(unix)]
fn open_components_without_symlinks(
    mut directory: File,
    path: &Path,
    kind: HostFileKind,
    access: HostFileAccess,
) -> io::Result<File> {
    // Retain each directory while opening the next. A concurrent rename cannot
    // redirect later components to a symlink or a different ancestor.
    let mut components = path
        .components()
        .filter(|part| !matches!(part, Component::RootDir | Component::CurDir))
        .peekable();

    while let Some(component) = components.next() {
        let Component::Normal(part) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "strict host paths cannot contain parent components",
            ));
        };

        let name = CString::new(part.as_bytes())?;
        let final_component = components.peek().is_none();

        #[cfg(target_os = "linux")]
        let component_flags = if final_component {
            libc::O_PATH
        } else {
            search_directory_flags()
        };

        #[cfg(not(target_os = "linux"))]
        let component_flags = if final_component {
            if access.is_writable() {
                libc::O_RDWR
            } else {
                libc::O_RDONLY
            }
        } else {
            search_directory_flags()
        };

        let flags = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | component_flags;

        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            let error = io::Error::last_os_error();

            // A refused symlink is ELOOP, or ENOTDIR when a directory is expected.
            // The open already refused it; this lookup only names the setting responsible.
            if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR))
                && is_symlink_at(&directory, &name)
            {
                return Err(io::Error::new(
                    error.kind(),
                    format!("runtime.strict_host_files rejects symlink {part:?} in host path"),
                ));
            }

            return Err(error);
        }

        let file = unsafe { File::from_raw_fd(fd) };
        if final_component {
            #[cfg(target_os = "linux")]
            return reopen_pinned(&file, part, kind, access);

            #[cfg(not(target_os = "linux"))]
            {
                let _ = kind;
                return Ok(file);
            }
        }

        directory = file;
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "host source has no filename",
    ))
}

/// Reopen an `O_PATH`-pinned inode through procfs after validating its file type.
///
/// Checking the pinned inode first ensures special files such as FIFOs or devices
/// are never opened before being rejected, and catches final symlinks which Linux
/// `openat(O_PATH | O_NOFOLLOW)` returns as an `O_PATH` descriptor instead of `ELOOP`.
#[cfg(target_os = "linux")]
fn reopen_pinned(
    pinned: &File,
    part: &OsStr,
    kind: HostFileKind,
    access: HostFileAccess,
) -> io::Result<File> {
    let file_type = pinned.metadata()?.file_type();
    if file_type.is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("runtime.strict_host_files rejects symlink {part:?} in host path"),
        ));
    }

    if !kind.admits(file_type) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            kind.rejection(),
        ));
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(access.is_writable())
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    options.open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
}

#[cfg(unix)]
fn search_directory_flags() -> libc::c_int {
    #[cfg(target_os = "linux")]
    {
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC
    }
    #[cfg(target_os = "macos")]
    {
        libc::O_SEARCH | libc::O_DIRECTORY | libc::O_CLOEXEC
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC
    }
}

#[cfg(unix)]
fn open_search_directory(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(search_directory_flags());
    options.open(path)
}

#[cfg(unix)]
fn is_symlink_at(directory: &File, name: &CStr) -> bool {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    result == 0 && unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFLNK
}

#[cfg(not(unix))]
fn open_without_symlinks(
    _path: &Path,
    _kind: HostFileKind,
    _access: HostFileAccess,
) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "strict host file opens require Unix",
    ))
}

#[cfg(not(unix))]
fn open_beneath_without_symlinks(
    _root: &Path,
    _path: &Path,
    _kind: HostFileKind,
    _access: HostFileAccess,
) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "strict host file opens require Unix",
    ))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests {
    use std::fs::{self, Permissions};
    use std::io::Read;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::process::Command;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn fifo_opens_fail_without_waiting_for_a_peer() {
        const PROBE: &str = "MSB_HOST_FILE_FIFO_PROBE";

        if let Some(path) = std::env::var_os(PROBE) {
            for kind in [HostFileKind::Regular, HostFileKind::Disk] {
                for policy in [HostFilePolicy::Standard, HostFilePolicy::Strict] {
                    for access in [HostFileAccess::ReadOnly, HostFileAccess::ReadWrite] {
                        let error = open(Path::new(&path), kind, access, &policy).unwrap_err();
                        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                    }
                }
            }
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap().join("pipe");
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);

        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "host_file::tests::fifo_opens_fail_without_waiting_for_a_peer",
                "--nocapture",
            ])
            .env(PROBE, &path)
            .spawn()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "FIFO child failed: {status}");
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("FIFO opens must not wait for a peer");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn disk_kind_admits_block_devices_but_no_other_special_files() {
        let temp = tempfile::tempdir().unwrap();
        let regular = temp.path().join("disk.raw");
        fs::write(&regular, b"disk").unwrap();

        for kind in [HostFileKind::Regular, HostFileKind::Disk] {
            assert!(
                open(
                    &regular,
                    kind,
                    HostFileAccess::ReadOnly,
                    &HostFilePolicy::Standard
                )
                .is_ok()
            );

            for special in [temp.path(), Path::new("/dev/null")] {
                let error = open(
                    special,
                    kind,
                    HostFileAccess::ReadOnly,
                    &HostFilePolicy::Standard,
                )
                .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                assert_eq!(error.to_string(), kind.rejection());
            }
        }

        // Unprivileged tests cannot create or usually open a block device, so check
        // admission against a real one's type. Some containers expose none.
        let Some(device) = fs::read_dir("/dev")
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| entry.file_type().is_ok_and(|kind| kind.is_block_device()))
        else {
            return;
        };

        let file_type = device.file_type().unwrap();
        assert!(HostFileKind::Disk.admits(file_type));
        assert!(!HostFileKind::Regular.admits(file_type));
    }

    #[test]
    fn strict_opens_reject_symlinks_and_parent_components() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let real = root.join("real");
        fs::create_dir(&real).unwrap();

        let path = real.join("file");
        fs::write(&path, b"contents").unwrap();
        symlink(&real, root.join("linked-dir")).unwrap();
        symlink(&path, root.join("linked-file")).unwrap();

        let dotted = real.join("..").join("real").join("file");
        assert!(
            open(
                &dotted,
                HostFileKind::Regular,
                HostFileAccess::ReadOnly,
                &HostFilePolicy::Standard
            )
            .is_ok()
        );

        let error = open(
            &dotted,
            HostFileKind::Regular,
            HostFileAccess::ReadOnly,
            &HostFilePolicy::Strict,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("parent components"), "{error}");

        for (link, name) in [
            (root.join("linked-dir").join("file"), "\"linked-dir\""),
            (root.join("linked-file"), "\"linked-file\""),
        ] {
            assert!(
                open(
                    &link,
                    HostFileKind::Regular,
                    HostFileAccess::ReadOnly,
                    &HostFilePolicy::Standard
                )
                .is_ok()
            );

            let error = open(
                &link,
                HostFileKind::Regular,
                HostFileAccess::ReadOnly,
                &HostFilePolicy::Strict,
            )
            .unwrap_err();
            let message = error.to_string();
            assert!(message.contains("runtime.strict_host_files"), "{message}");
            assert!(message.contains(name), "{message}");
        }

        for (access, mode) in [
            (HostFileAccess::ReadOnly, libc::O_RDONLY),
            (HostFileAccess::ReadWrite, libc::O_RDWR),
        ] {
            let file = open(
                &path,
                HostFileKind::Regular,
                access,
                &HostFilePolicy::Strict,
            )
            .unwrap();
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            assert_eq!(flags & libc::O_ACCMODE, mode);
        }
    }

    #[test]
    fn strict_relative_paths_resolve_from_the_current_directory() {
        const PROBE: &str = "MSB_HOST_FILE_RELATIVE_PROBE";

        if std::env::var_os(PROBE).is_some() {
            let mut contents = String::new();
            open(
                Path::new("real/file"),
                HostFileKind::Regular,
                HostFileAccess::ReadOnly,
                &HostFilePolicy::Strict,
            )
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
            assert_eq!(contents, "relative");

            assert!(
                open(
                    Path::new("linked/file"),
                    HostFileKind::Regular,
                    HostFileAccess::ReadOnly,
                    &HostFilePolicy::Strict,
                )
                .is_err()
            );
            return;
        }

        // Only an isolated child may run with a different working directory.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::create_dir(root.join("real")).unwrap();
        fs::write(root.join("real/file"), b"relative").unwrap();
        symlink(root.join("real"), root.join("linked")).unwrap();

        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "host_file::tests::strict_relative_paths_resolve_from_the_current_directory",
                "--nocapture",
            ])
            .current_dir(&root)
            .env(PROBE, "1")
            .status()
            .unwrap();
        assert!(status.success(), "relative probe failed: {status}");
    }

    #[test]
    fn strict_opens_only_need_search_permission_on_parent_directories() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().canonicalize().unwrap().join("search-only");
        fs::create_dir(&parent).unwrap();

        let path = parent.join("image.raw");
        fs::write(&path, b"disk").unwrap();
        fs::set_permissions(&parent, Permissions::from_mode(0o111)).unwrap();

        let ordinary = open(
            &path,
            HostFileKind::Disk,
            HostFileAccess::ReadOnly,
            &HostFilePolicy::Standard,
        );
        let strict = open(
            &path,
            HostFileKind::Disk,
            HostFileAccess::ReadOnly,
            &HostFilePolicy::Strict,
        );

        // Restore permissions before any assertion so the fixture can always be removed.
        fs::set_permissions(&parent, Permissions::from_mode(0o700)).unwrap();

        assert!(ordinary.is_ok(), "ordinary open failed: {ordinary:?}");
        let mut file = strict.unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "disk");
    }

    #[test]
    fn strict_beneath_allows_symlinked_root_while_rejecting_child_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let real_home = base.join("real-home");
        let logs = real_home.join("sandboxes/sbx/logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(logs.join("exec.log"), b"ok").unwrap();

        // Simulate a symlinked MSB_HOME (or macOS /var -> /private/var above home).
        let symlinked_home = base.join("home-link");
        symlink(&real_home, &symlinked_home).unwrap();
        symlink(logs.join("exec.log"), logs.join("alias.log")).unwrap();

        let policy = HostFilePolicy::strict_beneath(symlinked_home.clone());

        let mut contents = String::new();
        open(
            &symlinked_home.join("sandboxes/sbx/logs/exec.log"),
            HostFileKind::Regular,
            HostFileAccess::ReadOnly,
            &policy,
        )
        .unwrap()
        .read_to_string(&mut contents)
        .unwrap();
        assert_eq!(contents, "ok");

        let error = open(
            &symlinked_home.join("sandboxes/sbx/logs/alias.log"),
            HostFileKind::Regular,
            HostFileAccess::ReadOnly,
            &policy,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("runtime.strict_host_files"), "{message}");
        assert!(message.contains("\"alias.log\""), "{message}");
    }
}
