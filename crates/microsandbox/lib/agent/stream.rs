//! Async reader/writer over a raw file descriptor.
//!
//! Wraps a Unix file descriptor in `tokio::io::unix::AsyncFd` to provide
//! non-blocking async I/O. Used by [`AgentBridge`](super::AgentBridge) for
//! communication with agentd over the virtio-console FD pair.

use std::io;
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Async reader wrapping a file descriptor.
pub struct FdReader {
    inner: AsyncFd<OwnedFd>,
}

/// Async writer wrapping a file descriptor.
pub struct FdWriter {
    inner: AsyncFd<OwnedFd>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create an async reader/writer pair from a raw file descriptor.
///
/// The FD is duplicated so the reader and writer operate independently.
/// Both copies are set to non-blocking mode.
///
/// # Safety
///
/// The caller must ensure `raw_fd` is a valid, open file descriptor.
/// Ownership of `raw_fd` is transferred to the returned `FdReader`.
pub fn from_raw_fd(raw_fd: RawFd) -> io::Result<(FdReader, FdWriter)> {
    // Dup the FD so reader and writer are independent.
    // Safety: raw_fd is valid per precondition.
    let read_owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let write_owned = nix::unistd::dup(&read_owned).map_err(io_from_nix)?;

    // Set both non-blocking.
    set_nonblocking(&read_owned)?;
    set_nonblocking(&write_owned)?;

    let reader = FdReader {
        inner: AsyncFd::new(read_owned)?,
    };
    let writer = FdWriter {
        inner: AsyncFd::new(write_owned)?,
    };

    Ok((reader, writer))
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl AsyncRead for FdReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = match self.inner.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };

            let fd = self.inner.get_ref();
            let unfilled = buf.initialize_unfilled();

            match nix::unistd::read(fd, unfilled) {
                Ok(0) => return Poll::Ready(Ok(())),
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(nix::errno::Errno::EAGAIN) => {
                    guard.clear_ready();
                    continue;
                }
                Err(e) => return Poll::Ready(Err(io_from_nix(e))),
            }
        }
    }
}

impl AsyncWrite for FdWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = match self.inner.poll_write_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };

            let fd = self.inner.get_ref();

            match nix::unistd::write(fd, buf) {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(nix::errno::Errno::EAGAIN) => {
                    guard.clear_ready();
                    continue;
                }
                Err(e) => return Poll::Ready(Err(io_from_nix(e))),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Set a file descriptor to non-blocking mode.
fn set_nonblocking(fd: &OwnedFd) -> io::Result<()> {
    use nix::fcntl::{FcntlArg, OFlag, fcntl};

    let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(io_from_nix)?;
    let flags = OFlag::from_bits_truncate(flags);
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).map_err(io_from_nix)?;
    Ok(())
}

/// Convert a nix::errno::Errno to std::io::Error.
fn io_from_nix(e: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}
