//! Cancellable binary stdio for Python operations that can outlive asyncio waits.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use futures::task::AtomicWaker;
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
    cancellation: Arc<Cancellation>,
}

struct Lease(&'static AtomicBool);

#[derive(Default)]
struct Cancellation {
    cancelled: AtomicBool,
    reader: AtomicWaker,
    writer: AtomicWaker,
}

pub(crate) struct CancelOnDrop(Arc<Cancellation>);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl StdioStream {
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            input: stdin()?,
            output: Stdio::new(false, Lease::acquire(&OUTPUT_OWNED)?)?,
            cancellation: Arc::new(Cancellation::default()),
        })
    }

    pub(crate) fn cancel_on_drop(&self) -> CancelOnDrop {
        CancelOnDrop(self.cancellation.clone())
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

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        // russh retains a background session after the initial peer banner.
        // Cancelling the caller must wake that session, even though it still
        // owns the stream and therefore has not dropped its I/O adapters yet.
        self.0.cancelled.store(true, Ordering::Release);
        self.0.reader.wake();
        self.0.writer.wake();
    }
}

impl AsyncRead for StdioStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.cancellation.reader.register(cx.waker());
        if this.cancellation.cancelled.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        Pin::new(&mut this.input).poll_read(cx, buf)
    }
}

impl AsyncWrite for StdioStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.cancellation.writer.register(cx.waker());
        if this.cancellation.cancelled.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        Pin::new(&mut this.output).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.cancellation.writer.register(cx.waker());
        if this.cancellation.cancelled.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        Pin::new(&mut this.output).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn stdin() -> io::Result<Stdio> {
    Stdio::new(true, Lease::acquire(&INPUT_OWNED)?)
}
