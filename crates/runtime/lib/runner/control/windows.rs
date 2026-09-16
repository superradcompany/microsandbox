//! Drain named-pipe replies before disconnecting legacy readers.

use std::io;
use std::os::windows::io::{AsRawHandle, BorrowedHandle};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::sync::OwnedSemaphorePermit;
use windows_sys::Win32::Storage::FileSystem::FlushFileBuffers;

use super::dispatch::Dispatcher;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct ConnectedPipe(NamedPipeServer);

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for ConnectedPipe {
    fn drop(&mut self) {
        // Also unblock an outstanding native drain if the async task is cancelled.
        let _ = self.0.disconnect();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn serve_named_pipe(
    server: NamedPipeServer,
    dispatcher: Arc<Dispatcher>,
    permit: OwnedSemaphorePermit,
    flush_timeout: Duration,
) -> io::Result<()> {
    let mut server = ConnectedPipe(server);
    let served = super::server::serve(&mut server.0, dispatcher).await;
    let flushed = drain(&server.0, permit, flush_timeout).await;
    // Disconnect releases an unread native flush after its deadline, and gives
    // legacy read-to-EOF clients EOF only after a successful drain.
    drop(server);
    served.and(flushed)
}

async fn drain(
    server: &NamedPipeServer,
    permit: OwnedSemaphorePermit,
    flush_timeout: Duration,
) -> io::Result<()> {
    // SAFETY: the borrow cannot outlive server. The blocking worker owns its
    // duplicate, so cancellation cannot leave it using a closed/reused handle.
    let handle =
        unsafe { BorrowedHandle::borrow_raw(server.as_raw_handle()) }.try_clone_to_owned()?;
    let flushed = tokio::task::spawn_blocking(move || {
        // Keep admission until the native call exits, even if its await times
        // out. Unresponsive clients cannot create unbounded blocking workers.
        let _permit = permit;
        // SAFETY: handle is a live owned pipe handle throughout the call.
        if unsafe { FlushFileBuffers(handle.as_raw_handle()) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    });
    tokio::time::timeout(flush_timeout, flushed)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "control pipe reply drain timed out",
            )
        })?
        .map_err(io::Error::other)?
}
