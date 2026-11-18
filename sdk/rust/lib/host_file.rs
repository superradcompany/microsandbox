//! Bounded host file admission. Validate the opened inode, never stat then reopen.

use std::fs::{File, OpenOptions};
use std::io;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn open_regular(path: &Path, writable: bool, strict: bool) -> io::Result<File> {
    let file = if strict {
        open_without_symlinks(path, writable)?
    } else {
        let mut options = OpenOptions::new();
        options.read(true).write(writable);
        #[cfg(unix)]
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
        options.open(path)?
    };
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host source is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn open_without_symlinks(path: &Path, writable: bool) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    // Retain each directory while opening the next. A concurrent rename cannot
    // redirect later components to a symlink or a different ancestor.
    let mut directory = File::open(if path.is_absolute() { "/" } else { "." })?;
    let mut components = path
        .components()
        .filter(|part| !matches!(part, Component::RootDir | Component::CurDir))
        .peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "strict host paths cannot contain parent components",
            ));
        };
        let name = CString::new(name.as_bytes())?;
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
                libc::O_RDONLY | libc::O_DIRECTORY
            };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
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

#[cfg(not(unix))]
fn open_without_symlinks(_path: &Path, _writable: bool) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "strict host file opens require Unix",
    ))
}
