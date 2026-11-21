//! Pin regular files and directories without following links or opening special files.

#[cfg(unix)]
use std::ffi::CString;
#[cfg(all(unix, not(target_os = "linux")))]
use std::ffi::OsStr;
use std::fs::File;
use std::io;
#[cfg(all(unix, not(target_os = "linux")))]
use std::mem;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(all(unix, not(target_os = "linux")))]
use std::path::Component;
use std::path::Path;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Expected filesystem entry type when pinning a patch source.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SourceKind {
    Regular,
    Directory,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum MountBoundary {
    AllowCrossMount,
    SameMount,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SourceKind {
    #[cfg(unix)]
    fn expected_mode(self) -> libc::mode_t {
        match self {
            Self::Regular => libc::S_IFREG,
            Self::Directory => libc::S_IFDIR,
        }
    }

    fn rejection(self) -> &'static str {
        match self {
            Self::Regular => "host source is not a regular file",
            Self::Directory => "host source is not a directory",
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open a regular patch source file without following symlinks or opening special files.
pub(crate) fn open_regular(path: &Path) -> io::Result<File> {
    let file = open_path(path, SourceKind::Regular)?;

    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            SourceKind::Regular.rejection(),
        ));
    }

    Ok(file)
}

/// Open a patch source directory without following symlinks or opening special files.
pub(crate) fn open_directory(path: &Path) -> io::Result<File> {
    let file = open_path(path, SourceKind::Directory)?;

    if !file.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            SourceKind::Directory.rejection(),
        ));
    }

    Ok(file)
}

/// Pin one directory child without crossing a mount, including same-device binds.
///
/// `kind` is the type the parent listed. A child swapped for any other
/// type after the listing is refused without being opened.
#[cfg(target_os = "linux")]
pub(super) fn open_child(root: &File, name: &Path, kind: SourceKind) -> io::Result<File> {
    let pinned = open_beneath(root, name, libc::O_PATH, MountBoundary::SameMount)?;
    reopen(&pinned, kind)
}

/// Open a host source after checking its type, so a device or FIFO is never opened.
fn open_path(path: &Path, kind: SourceKind) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    let file = {
        let anchor = if path.is_absolute() { "/" } else { "." };
        let root = File::open(anchor)?;
        let relative = path.strip_prefix("/").unwrap_or(path);
        let pinned = open_beneath(
            &root,
            relative,
            libc::O_PATH,
            MountBoundary::AllowCrossMount,
        )?;
        reopen(&pinned, kind)?
    };

    #[cfg(all(unix, not(target_os = "linux")))]
    let file = open_without_links(path, kind)?;

    #[cfg(unix)]
    {
        Ok(file)
    }

    #[cfg(not(unix))]
    {
        let _ = (path, kind);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "bounded patch source staging requires Unix",
        ))
    }
}

/// Refuse a source whose `st_mode` is not the expected regular file or directory.
#[cfg(unix)]
fn check_type(mode: libc::mode_t, kind: SourceKind) -> io::Result<()> {
    if mode & libc::S_IFMT == kind.expected_mode() {
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        kind.rejection(),
    ))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn open_without_links(path: &Path, kind: SourceKind) -> io::Result<File> {
    #[cfg(target_vendor = "apple")]
    let search_flags = libc::O_SEARCH;
    #[cfg(not(target_vendor = "apple"))]
    let search_flags = libc::O_RDONLY | libc::O_DIRECTORY;

    let anchor = if path.is_absolute() { "/" } else { "." };
    let mut parent = File::options()
        .read(true)
        .custom_flags(search_flags | libc::O_CLOEXEC)
        .open(anchor)?;

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
            let mut status = unsafe { mem::zeroed::<libc::stat>() };
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

            check_type(status.st_mode, kind)?;
        }

        let component_flags = if final_component {
            match kind {
                SourceKind::Regular => libc::O_RDONLY,
                SourceKind::Directory => libc::O_RDONLY | libc::O_DIRECTORY,
            }
        } else {
            search_flags
        };
        let flags = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | component_flags;

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
fn reopen(pinned: &File, kind: SourceKind) -> io::Result<File> {
    check_type(pinned.metadata()?.mode(), kind)?;

    let dir_flag = match kind {
        SourceKind::Directory => libc::O_DIRECTORY,
        SourceKind::Regular => 0,
    };

    File::options()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | dir_flag)
        .open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
}

#[cfg(target_os = "linux")]
fn open_beneath(
    root: &File,
    name: &Path,
    flags: libc::c_int,
    boundary: MountBoundary,
) -> io::Result<File> {
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    let name = CString::new(name.as_os_str().as_bytes())?;
    let no_xdev = u64::from(boundary == MountBoundary::SameMount);
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        // BENEATH, NO_SYMLINKS, NO_MAGICLINKS, and optionally NO_XDEV.
        resolve: 0x08 | 0x04 | 0x02 | no_xdev,
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
