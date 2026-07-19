//! Process-held cross-platform file locks.

use std::fs::{File, OpenOptions};
use std::io;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::Path;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, ERROR_LOCK_VIOLATION, HANDLE};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, UnlockFileEx,
};
#[cfg(windows)]
use windows_sys::Win32::System::IO::OVERLAPPED;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Opens or creates an owner-only lock file without truncating it.
pub fn open_lock_file(path: &Path) -> io::Result<File> {
    open_lock_file_with(path, true, false)
}

/// Opens an existing lock file without creating a missing path.
pub fn open_existing_lock_file(path: &Path) -> io::Result<File> {
    open_lock_file_with(path, false, false)
}

/// Creates a new lock file and fails if the path already exists.
pub fn create_new_lock_file(path: &Path) -> io::Result<File> {
    open_lock_file_with(path, false, true)
}

/// Acquires an exclusive process-held lock, blocking until it becomes available.
pub fn lock_exclusive(file: &File) -> io::Result<()> {
    lock_exclusive_inner(file, false).map(|_| ())
}

/// Attempts to acquire an exclusive process-held lock without blocking.
///
/// Returns `Ok(false)` only when another process currently owns the lock.
pub fn try_lock_exclusive(file: &File) -> io::Result<bool> {
    lock_exclusive_inner(file, true)
}

/// Releases an exclusive process-held lock.
pub fn unlock(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    #[cfg(windows)]
    {
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        let result = unsafe {
            UnlockFileEx(
                file.as_raw_handle() as HANDLE,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

#[cfg(unix)]
fn lock_exclusive_inner(file: &File, nonblocking: bool) -> io::Result<bool> {
    let operation = if nonblocking {
        libc::LOCK_EX | libc::LOCK_NB
    } else {
        libc::LOCK_EX
    };
    let result = unsafe { libc::flock(file.as_raw_fd(), operation) };
    if result == 0 {
        return Ok(true);
    }

    let error = io::Error::last_os_error();
    if nonblocking
        && matches!(
            error.raw_os_error(),
            Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN
        )
    {
        return Ok(false);
    }
    Err(error)
}

fn open_lock_file_with(path: &Path, create: bool, create_new: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options
        .create(create)
        .create_new(create_new)
        .truncate(false)
        .read(true)
        .write(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    options.open(path)
}

#[cfg(windows)]
fn lock_exclusive_inner(file: &File, nonblocking: bool) -> io::Result<bool> {
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let flags = LOCKFILE_EXCLUSIVE_LOCK
        | if nonblocking {
            LOCKFILE_FAIL_IMMEDIATELY
        } else {
            0
        };
    let result = unsafe {
        LockFileEx(
            file.as_raw_handle() as HANDLE,
            flags,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if result != 0 {
        return Ok(true);
    }

    let error = io::Error::last_os_error();
    if nonblocking
        && matches!(
            error.raw_os_error(),
            Some(code) if code as u32 == ERROR_LOCK_VIOLATION || code as u32 == ERROR_IO_PENDING
        )
    {
        return Ok(false);
    }
    Err(error)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_lock_is_exclusive_and_reusable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lease.lock");
        let first = open_lock_file(&path).unwrap();
        let second = open_lock_file(&path).unwrap();

        assert!(try_lock_exclusive(&first).unwrap());
        assert!(!try_lock_exclusive(&second).unwrap());
        unlock(&first).unwrap();
        assert!(try_lock_exclusive(&second).unwrap());
    }
}
