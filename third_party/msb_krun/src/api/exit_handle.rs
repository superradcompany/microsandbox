//! Handle for triggering VM exit from any thread.

use std::{io, result};

use utils::eventfd::EventFd;

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A thread-safe, cloneable handle that triggers VM exit when fired.
///
/// Obtained via [`Vm::exit_handle()`](super::vm::Vm::exit_handle) before
/// calling [`Vm::enter()`](super::vm::Vm::enter). Background tasks (idle
/// timeout, max-duration timer, relay drain) use this to shut down the VMM
/// cleanly — the exit event fd fires, exit observers run, and the process
/// terminates.
///
/// Multiple triggers are idempotent: the VMM reads the event once and calls
/// `_exit()`.
pub struct ExitHandle {
    #[cfg(unix)]
    write_fd: OwnedFd,
    #[cfg(target_os = "windows")]
    event: EventFd,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExitHandle {
    /// Create an `ExitHandle` from an [`EventFd`].
    ///
    /// Dups the write end so the handle is independent of the original fd
    /// lifetime.
    #[cfg(unix)]
    pub(crate) fn from_event_fd(evt: &EventFd) -> result::Result<Self, io::Error> {
        // On Linux, EventFd is a single fd (read/write on the same fd).
        // On macOS, EventFd is a pipe pair — we need the write end.
        #[cfg(target_os = "linux")]
        let raw_fd = evt.as_raw_fd();
        #[cfg(target_os = "macos")]
        let raw_fd = evt.get_write_fd();

        let fd = unsafe { libc::dup(raw_fd) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let write_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self { write_fd })
    }

    /// Create an `ExitHandle` from an [`EventFd`].
    #[cfg(target_os = "windows")]
    pub(crate) fn from_event_fd(evt: &EventFd) -> result::Result<Self, io::Error> {
        Ok(Self {
            event: evt.try_clone()?,
        })
    }

    /// Trigger VM exit.
    ///
    /// Writes to the exit event fd, causing the VMM event loop to invoke
    /// exit observers and call `_exit()`. Safe to call from any thread.
    /// Async-signal-safe.
    #[cfg(unix)]
    pub fn trigger(&self) {
        let val: u64 = 1;
        // SAFETY: write_fd is a valid, owned file descriptor. Writing 8 bytes
        // (a u64) matches the EventFd/pipe protocol used by the VMM.
        let _ = unsafe {
            libc::write(
                self.write_fd.as_raw_fd(),
                &val as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            )
        };
    }

    /// Trigger VM exit.
    #[cfg(target_os = "windows")]
    pub fn trigger(&self) {
        let _ = self.event.write(1);
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Clone for ExitHandle {
    #[cfg(unix)]
    fn clone(&self) -> Self {
        let fd = unsafe { libc::dup(self.write_fd.as_raw_fd()) };
        assert!(fd >= 0, "Failed to dup ExitHandle fd");
        let write_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Self { write_fd }
    }

    #[cfg(target_os = "windows")]
    fn clone(&self) -> Self {
        Self {
            event: self
                .event
                .try_clone()
                .expect("Failed to clone ExitHandle event"),
        }
    }
}

// SAFETY: OwnedFd is Send. The write operation is atomic for 8-byte writes
// on both eventfd (Linux) and pipes (macOS, when ≤ PIPE_BUF).
unsafe impl Send for ExitHandle {}
unsafe impl Sync for ExitHandle {}
