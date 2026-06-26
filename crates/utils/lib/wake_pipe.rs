//! Cross-platform wake notification.
//!
//! Works on both Linux and macOS (unlike `eventfd` which is Linux-only).
//! The write end signals, the read end is pollable via `epoll`/`kqueue`/`poll`.

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::RawHandle;
use std::time::Duration;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CreateEventW, ResetEvent, SetEvent, WaitForSingleObject,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Cross-platform wake notification.
///
/// On Unix, the write end signals and the read end is pollable via
/// `epoll`/`kqueue`/`poll`. On Windows, wakeups are coalesced behind a
/// manual-reset event for code that needs a blocking wait.
#[cfg(unix)]
pub struct WakePipe {
    read_fd: OwnedFd,
    write_fd: OwnedFd,
}

/// Cross-platform wake notification.
///
/// Windows wakeups are coalesced behind a manual-reset event. Multiple
/// [`wake`](Self::wake) calls before [`drain`](Self::drain) still represent one
/// readable/ready state, matching the Unix pipe behavior needed by queue
/// wakeups.
#[cfg(windows)]
pub struct WakePipe {
    handle: HANDLE,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WakePipe {
    /// Create a new wake pipe.
    ///
    /// Both ends are set to non-blocking and close-on-exec.
    #[cfg(unix)]
    pub fn new() -> Self {
        let mut fds = [0i32; 2];

        // SAFETY: pipe() is a standard POSIX call. We check the return value
        // and immediately wrap the raw fds in OwnedFd for RAII cleanup.
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert!(
            ret == 0,
            "pipe() failed: {}",
            std::io::Error::last_os_error()
        );

        // Set non-blocking and close-on-exec on both ends.
        // SAFETY: fds are valid open file descriptors from the pipe() call above.
        unsafe {
            set_nonblock_cloexec(fds[0]);
            set_nonblock_cloexec(fds[1]);
        }

        Self {
            // SAFETY: fds are valid and not owned by anything else yet.
            read_fd: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            write_fd: unsafe { OwnedFd::from_raw_fd(fds[1]) },
        }
    }

    /// Create a new wake primitive.
    #[cfg(windows)]
    pub fn new() -> Self {
        let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if handle.is_null() {
            panic!("CreateEventW failed: {}", std::io::Error::last_os_error());
        }
        Self { handle }
    }

    /// Signal the reader. Safe to call from any thread, multiple times.
    ///
    /// Writes a single byte. If the pipe buffer is full the write is silently
    /// dropped — the reader will still wake because there are unread bytes.
    #[cfg(unix)]
    pub fn wake(&self) {
        // SAFETY: write_fd is a valid, non-blocking file descriptor.
        // Writing 1 byte to a pipe is atomic on all POSIX systems.
        unsafe {
            libc::write(self.write_fd.as_raw_fd(), [1u8].as_ptr().cast(), 1);
        }
    }

    /// Signal the reader. Safe to call from any thread, multiple times.
    #[cfg(windows)]
    pub fn wake(&self) {
        unsafe {
            SetEvent(self.handle);
        }
    }

    /// Drain all pending wake signals. Call after processing to reset the
    /// pipe for the next edge-triggered notification.
    #[cfg(unix)]
    pub fn drain(&self) {
        let mut buf = [0u8; 512];
        loop {
            // SAFETY: read_fd is a valid, non-blocking file descriptor.
            let n =
                unsafe { libc::read(self.read_fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
        }
    }

    /// Drain all pending wake signals.
    #[cfg(windows)]
    pub fn drain(&self) {
        unsafe {
            ResetEvent(self.handle);
        }
    }

    /// Block until the wake primitive is signaled or the timeout expires.
    ///
    /// Returns `true` if the primitive was signaled and `false` on timeout.
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        wait_timeout(self, timeout)
    }

    /// File descriptor for `epoll`/`kqueue`/`poll(2)` registration.
    ///
    /// Becomes readable when [`wake()`](Self::wake) has been called.
    #[cfg(unix)]
    pub fn as_raw_fd(&self) -> RawFd {
        self.read_fd.as_raw_fd()
    }

    /// Waitable handle for Windows wait APIs.
    #[cfg(windows)]
    pub fn as_raw_handle(&self) -> RawHandle {
        self.handle as RawHandle
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for WakePipe {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
unsafe impl Send for WakePipe {}

#[cfg(windows)]
unsafe impl Sync for WakePipe {}

#[cfg(windows)]
impl Drop for WakePipe {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Set `O_NONBLOCK` and `FD_CLOEXEC` on a file descriptor.
///
/// # Safety
///
/// `fd` must be a valid, open file descriptor.
#[cfg(unix)]
unsafe fn set_nonblock_cloexec(fd: RawFd) {
    unsafe {
        // Set non-blocking.
        let flags = libc::fcntl(fd, libc::F_GETFL);
        assert!(
            flags >= 0,
            "fcntl(F_GETFL) failed: {}",
            std::io::Error::last_os_error()
        );
        let ret = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        assert!(
            ret >= 0,
            "fcntl(F_SETFL) failed: {}",
            std::io::Error::last_os_error()
        );

        // Set close-on-exec.
        let flags = libc::fcntl(fd, libc::F_GETFD);
        assert!(
            flags >= 0,
            "fcntl(F_GETFD) failed: {}",
            std::io::Error::last_os_error()
        );
        let ret = libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        assert!(
            ret >= 0,
            "fcntl(F_SETFD) failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(unix)]
fn wait_timeout(pipe: &WakePipe, timeout: Duration) -> bool {
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    poll_fd_readable_timeout(pipe.as_raw_fd(), timeout_ms)
}

#[cfg(unix)]
fn poll_fd_readable_timeout(fd: RawFd, timeout_ms: i32) -> bool {
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a valid stack-allocated pollfd.
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ret > 0 {
            return true;
        }
        if ret == 0 {
            return false;
        }

        let errno = std::io::Error::last_os_error();
        if errno.raw_os_error() != Some(libc::EINTR) {
            return false;
        }
    }
}

#[cfg(windows)]
fn wait_timeout(pipe: &WakePipe, timeout: Duration) -> bool {
    let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
    let result = unsafe { WaitForSingleObject(pipe.handle, timeout_ms) };
    match result {
        WAIT_OBJECT_0 => true,
        WAIT_TIMEOUT | WAIT_FAILED => false,
        _ => false,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wake_and_drain() {
        let pipe = WakePipe::new();
        // Initially no data — drain is a no-op.
        pipe.drain();

        // Wake then drain.
        pipe.wake();
        pipe.wake();
        pipe.drain();

        // After drain, another wake should work.
        pipe.wake();
        pipe.drain();
    }

    #[cfg(unix)]
    #[test]
    fn fd_is_valid() {
        let pipe = WakePipe::new();
        let fd = pipe.as_raw_fd();
        assert!(fd >= 0);
    }

    #[test]
    fn nonblocking_read() {
        let pipe = WakePipe::new();
        // Reading from an empty non-blocking pipe should not block.
        pipe.drain();
    }

    #[test]
    fn wait_timeout_observes_wake() {
        let pipe = WakePipe::new();

        assert!(!pipe.wait_timeout(Duration::from_millis(1)));
        pipe.wake();
        assert!(pipe.wait_timeout(Duration::from_secs(1)));
        pipe.drain();
        assert!(!pipe.wait_timeout(Duration::from_millis(1)));
    }
}
