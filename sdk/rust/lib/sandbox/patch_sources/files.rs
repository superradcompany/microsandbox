//! Pin regular files and directories without following links or waiting on FIFOs.
use std::fs::File;
use std::io;
use std::path::Path;

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

fn open_path(path: &Path, writable: bool, directory: bool) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    let file = {
        let root = File::open(if path.is_absolute() { "/" } else { "." })?;
        open_beneath(
            &root,
            path.strip_prefix("/").unwrap_or(path),
            writable,
            directory,
            false,
        )?
    };
    #[cfg(all(unix, not(target_os = "linux")))]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        File::options()
            .read(true)
            .write(writable)
            .custom_flags(
                libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC
                    | if directory { libc::O_DIRECTORY } else { 0 },
            )
            .open(path)?
    };
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

/// Pin one directory child without crossing a mount, including same-device binds.
#[cfg(target_os = "linux")]
pub(crate) fn open_child(root: &File, name: &Path) -> io::Result<File> {
    open_beneath(root, name, false, false, true)
}

#[cfg(target_os = "linux")]
fn open_beneath(
    root: &File,
    name: &Path,
    writable: bool,
    directory: bool,
    no_mounts: bool,
) -> io::Result<File> {
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
        flags: (if writable {
            libc::O_RDWR
        } else {
            libc::O_RDONLY
        } | libc::O_NONBLOCK
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if directory { libc::O_DIRECTORY } else { 0 }) as u64,
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
