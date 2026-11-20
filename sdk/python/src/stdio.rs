//! Cancellable binary stdio for Python operations that can outlive asyncio waits.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(unix)]
#[path = "stdio/unix.rs"]
mod unix;
#[cfg(windows)]
#[path = "stdio/windows.rs"]
mod windows;

#[cfg(unix)]
use unix::Stdio;
#[cfg(windows)]
use windows::Stdio;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

static INPUT_OWNED: AtomicBool = AtomicBool::new(false);
static OUTPUT_OWNED: AtomicBool = AtomicBool::new(false);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct StdioStream {
    input: Stdio,
    output: Stdio,
}

struct Lease(&'static AtomicBool);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl StdioStream {
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            input: stdin()?,
            output: Stdio::new(false, Lease::acquire(&OUTPUT_OWNED)?)?,
        })
    }
}

impl Lease {
    fn acquire(owned: &'static AtomicBool) -> io::Result<Self> {
        owned
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::other("stdio is already in use by another SDK operation"))?;
        Ok(Self(owned))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for Lease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl AsyncRead for StdioStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().input).poll_read(cx, buf)
    }
}

impl AsyncWrite for StdioStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().output).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().output).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().output).poll_shutdown(cx)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn stdin() -> io::Result<Stdio> {
    Stdio::new(true, Lease::acquire(&INPUT_OWNED)?)
}
