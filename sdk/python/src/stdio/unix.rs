//! Poll pipes/terminals without parking a runtime worker in a blocking read.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::Lease;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct Stdio {
    inner: Inner,
    // Release the lease only after closing/deregistering the duplicated fd.
    _lease: Lease,
}

enum Inner {
    Pollable(AsyncFd<NonblockingFile>),
    File(tokio::fs::File),
    Null(File),
}

struct NonblockingFile {
    file: File,
    restore_blocking: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Stdio {
    pub(super) fn new(input: bool, lease: Lease) -> io::Result<Self> {
        let fd = if input {
            libc::STDIN_FILENO
        } else {
            libc::STDOUT_FILENO
        };
        // SAFETY: fcntl duplicates the borrowed process fd; ownership of the
        // new close-on-exec descriptor transfers to File only on success.
        let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicated < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(duplicated) };
        let metadata = file.metadata()?;
        let inner = if metadata.is_file() {
            // epoll does not accept regular files. Their finite disk I/O can
            // use Tokio's file adapter; open-ended pipe reads must not.
            Inner::File(tokio::fs::File::from_std(file))
        } else if metadata.file_type().is_char_device()
            && fs::metadata("/dev/null").is_ok_and(|null| null.rdev() == metadata.rdev())
        {
            // /dev/null always completes immediately but Linux epoll rejects
            // it. Preserve redirected EOF/output without spawning a worker.
            Inner::Null(file)
        } else {
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            let restore_blocking = flags & libc::O_NONBLOCK == 0;
            if restore_blocking
                && unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                    < 0
            {
                return Err(io::Error::last_os_error());
            }
            let file = NonblockingFile {
                file,
                restore_blocking,
            };
            // SAFETY: File owns this fixed, open fd for the entire registration.
            // O_NONBLOCK is retained until deregistration and the lease prevents
            // another SDK operation from changing its status flags.
            Inner::Pollable(unsafe { AsyncFd::register(file) }?)
        };
        Ok(Self {
            inner,
            _lease: lease,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl AsRawFd for NonblockingFile {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl Drop for NonblockingFile {
    fn drop(&mut self) {
        // dup shares status flags with the caller's descriptor. The operation
        // owns stdio exclusively, and must restore blocking mode on cancellation
        // as well as success without replacing unrelated flags.
        if self.restore_blocking {
            let flags = unsafe { libc::fcntl(self.as_raw_fd(), libc::F_GETFL) };
            if flags >= 0 {
                unsafe { libc::fcntl(self.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) };
            }
        }
    }
}

impl AsyncRead for Stdio {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            Inner::File(file) => Pin::new(file).poll_read(cx, buf),
            Inner::Null(file) => {
                let count = file.read(buf.initialize_unfilled())?;
                buf.advance(count);
                Poll::Ready(Ok(()))
            }
            Inner::Pollable(fd) => {
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                loop {
                    let mut guard = ready!(fd.poll_read_ready(cx))?;
                    match guard.try_io(|fd| (&fd.get_ref().file).read(buf.initialize_unfilled())) {
                        Ok(Ok(count)) => {
                            buf.advance(count);
                            return Poll::Ready(Ok(()));
                        }
                        Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Ok(Err(error)) => return Poll::Ready(Err(error)),
                        Err(_) => continue,
                    }
                }
            }
        }
    }
}

impl AsyncWrite for Stdio {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            Inner::File(file) => Pin::new(file).poll_write(cx, buf),
            Inner::Null(file) => Poll::Ready(file.write(buf)),
            Inner::Pollable(fd) => loop {
                let mut guard = ready!(fd.poll_write_ready(cx))?;
                match guard.try_io(|fd| (&fd.get_ref().file).write(buf)) {
                    Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(result) => return Poll::Ready(result),
                    Err(_) => continue,
                }
            },
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            Inner::File(file) => Pin::new(file).poll_flush(cx),
            Inner::Pollable(_) | Inner::Null(_) => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}
