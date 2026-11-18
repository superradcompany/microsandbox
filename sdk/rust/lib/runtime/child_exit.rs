//! Linux exit notification for an owned, unreaped child, independent of SIGCHLD.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::time::Duration;

use tokio::io::unix::AsyncFd;
use tokio::process::Child;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) struct ChildExit(Option<AsyncFd<OwnedFd>>);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ChildExit {
    /// Holding the child across registration prevents reuse of its PID before reaping.
    pub(super) fn observe(child: &Child) -> Option<Self> {
        let pid = child.id()?;
        let descriptor = (|| -> io::Result<_> {
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: pidfd_open returned a fresh descriptor. The OwnedFd moves into
            // AsyncFd and keeps the same descriptor open until deregistration.
            unsafe { AsyncFd::register(OwnedFd::from_raw_fd(fd as i32)) }.map_err(io::Error::from)
        })();
        match descriptor {
            Ok(fd) => Some(Self(Some(fd))),
            Err(error) => {
                tracing::debug!(pid, %error, "falling back to periodic child exit checks");
                Some(Self(None))
            }
        }
    }

    /// After a wakeup, the owner calls try_wait on the original child. On
    /// kernels without pidfds, only released children incur periodic checks.
    pub(super) async fn wait(&mut self) {
        if let Some(fd) = &self.0 {
            if let Ok(mut ready) = fd.readable().await {
                ready.clear_ready();
                return;
            }
            self.0 = None;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
