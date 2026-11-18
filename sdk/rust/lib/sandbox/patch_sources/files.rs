//! Pin regular files and directories without following links or opening special files.
use std::fs::File;
use std::io;
use std::path::Path;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn open_regular(path: &Path, writable: bool) -> io::Result<File> {
    let file = open_path(path, writable, false)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host source is not a regular file",
        ));
    }
    Ok(file)
}

pub(crate) fn open_directory(path: &Path) -> io::Result<File> {
    let file = open_path(path, false, true)?;
    if !file.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host source is not a directory",
        ));
    }
    Ok(file)
}

/// Pin one directory child without crossing a mount, including same-device binds.
///
/// `directory` is the type the parent listed. A child swapped for any other
/// type after the listing is refused without being opened.
#[cfg(target_os = "linux")]
pub(crate) fn open_child(root: &File, name: &Path, directory: bool) -> io::Result<File> {
    let pinned = open_beneath(root, name, libc::O_PATH, true)?;
    reopen(&pinned, false, directory)
}

/// Open a host source after checking its type, so a device or FIFO is never opened.
fn open_path(path: &Path, writable: bool, directory: bool) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    let file = {
        let root = File::open(if path.is_absolute() { "/" } else { "." })?;
        let relative = path.strip_prefix("/").unwrap_or(path);
        let pinned = open_beneath(&root, relative, libc::O_PATH, false)?;
        reopen(&pinned, writable, directory)?
    };
    #[cfg(all(unix, not(target_os = "linux")))]
    let file = open_without_links(path, writable, directory)?;
    #[cfg(unix)]
    {
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, writable, directory);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "bounded patch source staging requires Unix",
        ))
    }
}

/// Refuse a source whose `st_mode` is not the expected regular file or directory.
#[cfg(unix)]
fn check_type(mode: libc::mode_t, directory: bool) -> io::Result<()> {
    let expected = if directory {
        libc::S_IFDIR
    } else {
        libc::S_IFREG
    };
    if mode & libc::S_IFMT == expected {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        if directory {
            "host source is not a directory"
        } else {
            "host source is not a regular file"
        },
    ))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn open_without_links(path: &Path, writable: bool, directory: bool) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    use std::ffi::OsStr;
    use std::os::unix::fs::OpenOptionsExt;

    #[cfg(target_vendor = "apple")]
    let search_flags = libc::O_SEARCH;
    #[cfg(not(target_vendor = "apple"))]
    let search_flags = libc::O_RDONLY | libc::O_DIRECTORY;
    let mut parent = File::options()
        .read(true)
        .custom_flags(search_flags | libc::O_CLOEXEC)
        .open(if path.is_absolute() { "/" } else { "." })?;
    let mut components = path
        .components()
        .filter(|component| !matches!(component, Component::RootDir | Component::CurDir))
        .peekable();
    while let Some(component) = components.next() {
        let name = match component {
            Component::Normal(name) => name,
            Component::ParentDir => OsStr::new(".."),
            _ => unreachable!("root and current directory components are filtered"),
        };
        let name = CString::new(name.as_bytes())?;
        let final_component = components.peek().is_none();
        if final_component {
            // No O_PATH here: a swap after this check can still reach the
            // open, but the check after opening still refuses it.
            let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
            let result = unsafe {
                libc::fstatat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    &mut status,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            check_type(status.st_mode, directory)?;
        }
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
                search_flags
            }
            | if final_component && directory {
                libc::O_DIRECTORY
            } else {
                0
            };
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        if final_component {
            return Ok(file);
        }
        parent = file;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "patch source path is empty",
    ))
}

/// Open an `O_PATH` pin once its type is checked.
///
/// Reopening through procfs reaches the pinned inode, never a swapped entry.
#[cfg(target_os = "linux")]
fn reopen(pinned: &File, writable: bool, directory: bool) -> io::Result<File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    check_type(pinned.metadata()?.mode(), directory)?;
    File::options()
        .read(true)
        .write(writable)
        .custom_flags(
            libc::O_NONBLOCK | libc::O_CLOEXEC | if directory { libc::O_DIRECTORY } else { 0 },
        )
        .open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
}

#[cfg(target_os = "linux")]
fn open_beneath(root: &File, name: &Path, flags: libc::c_int, no_mounts: bool) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let name = CString::new(name.as_os_str().as_bytes())?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        // BENEATH, NO_SYMLINKS, NO_MAGICLINKS, and optionally NO_XDEV.
        resolve: 0x08 | 0x04 | 0x02 | u64::from(no_mounts),
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}
