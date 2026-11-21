//! Bounded host file admission. Validate the opened inode, never stat then reopen.

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
use std::path::Path;

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

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open a host file and keep it only if the opened inode is of the expected kind.
///
/// On Unix, opens never wait for a FIFO peer. `strict` also rejects symlinks in every
/// path component, including parent directories, and is unsupported elsewhere.
pub(crate) fn open(
    path: &Path,
    kind: HostFileKind,
    writable: bool,
    strict: bool,
) -> io::Result<File> {
    let file = if strict {
        open_without_symlinks(path, writable)?
    } else {
        let mut options = OpenOptions::new();
        options.read(true).write(writable);
        #[cfg(unix)]
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
        options.open(path)?
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
fn open_without_symlinks(path: &Path, writable: bool) -> io::Result<File> {
    // Retain each directory while opening the next. A concurrent rename cannot
    // redirect later components to a symlink or a different ancestor.
    let mut directory =
        open_search_directory(Path::new(if path.is_absolute() { "/" } else { "." }))?;
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
        let flags = libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_CLOEXEC
            | if final_component {
                if writable {
                    libc::O_RDWR
                } else {
                    libc::O_RDONLY
                }
            } else {
                search_directory_flags()
            };

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
            return Ok(file);
        }
        directory = file;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "host source has no filename",
    ))
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
fn open_without_symlinks(_path: &Path, _writable: bool) -> io::Result<File> {
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
    use std::io::Read;
    use std::os::unix::fs::symlink;
    use std::process::Command;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn fifo_opens_fail_without_waiting_for_a_peer() {
        const PROBE: &str = "MSB_HOST_FILE_FIFO_PROBE";
        if let Some(path) = std::env::var_os(PROBE) {
            for kind in [HostFileKind::Regular, HostFileKind::Disk] {
                for strict in [false, true] {
                    for writable in [false, true] {
                        let error = open(Path::new(&path), kind, writable, strict).unwrap_err();
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
        std::fs::write(&regular, b"disk").unwrap();

        for kind in [HostFileKind::Regular, HostFileKind::Disk] {
            assert!(open(&regular, kind, false, false).is_ok());
            for special in [temp.path(), Path::new("/dev/null")] {
                let error = open(special, kind, false, false).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                assert_eq!(error.to_string(), kind.rejection());
            }
        }

        // Unprivileged tests cannot create or usually open a block device, so check
        // admission against a real one's type. Some containers expose none.
        let Some(device) = std::fs::read_dir("/dev")
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
        std::fs::create_dir(&real).unwrap();
        let path = real.join("file");
        std::fs::write(&path, b"contents").unwrap();
        symlink(&real, root.join("linked-dir")).unwrap();
        symlink(&path, root.join("linked-file")).unwrap();

        let dotted = real.join("..").join("real").join("file");
        assert!(open(&dotted, HostFileKind::Regular, false, false).is_ok());
        let error = open(&dotted, HostFileKind::Regular, false, true).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("parent components"), "{error}");

        for (link, name) in [
            (root.join("linked-dir").join("file"), "\"linked-dir\""),
            (root.join("linked-file"), "\"linked-file\""),
        ] {
            assert!(open(&link, HostFileKind::Regular, false, false).is_ok());
            let error = open(&link, HostFileKind::Regular, false, true).unwrap_err();
            let message = error.to_string();
            assert!(message.contains("runtime.strict_host_files"), "{message}");
            assert!(message.contains(name), "{message}");
        }

        for (writable, mode) in [(false, libc::O_RDONLY), (true, libc::O_RDWR)] {
            let file = open(&path, HostFileKind::Regular, writable, true).unwrap();
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            assert_eq!(flags & libc::O_ACCMODE, mode);
        }
    }

    #[test]
    fn strict_relative_paths_resolve_from_the_current_directory() {
        const PROBE: &str = "MSB_HOST_FILE_RELATIVE_PROBE";
        if std::env::var_os(PROBE).is_some() {
            let mut contents = String::new();
            open(Path::new("real/file"), HostFileKind::Regular, false, true)
                .unwrap()
                .read_to_string(&mut contents)
                .unwrap();
            assert_eq!(contents, "relative");
            assert!(open(Path::new("linked/file"), HostFileKind::Regular, false, true).is_err());
            return;
        }

        // Only an isolated child may run with a different working directory.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("real")).unwrap();
        std::fs::write(root.join("real/file"), b"relative").unwrap();
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
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().canonicalize().unwrap().join("search-only");
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join("image.raw");
        std::fs::write(&path, b"disk").unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o111)).unwrap();

        let ordinary = open(&path, HostFileKind::Disk, false, false);
        let strict = open(&path, HostFileKind::Disk, false, true);
        // Restore permissions before any assertion so the fixture can always be removed.
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(ordinary.is_ok(), "ordinary open failed: {ordinary:?}");
        let mut file = strict.unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "disk");
    }
}
