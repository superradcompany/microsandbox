//! Reference VFS RPC server loop — the Rust counterpart to Go `vfs.Serve`.
//!
//! Run this on the parent end of an inherited socketpair while the runtime
//! serves the guest via [`unix_socket_backend`](super::mount::unix_socket_backend).

use std::io::{self, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::super::PathFs;
use super::dispatch::{DispatchState, dispatch_with_state};
use super::protocol::{
    MAX_FRAME_LEN, VfsResponse, decode_error_errno, decode_request, read_frame, read_hello,
    to_cbor, write_frame, write_hello,
};
use crate::backends::shared::platform;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum provider calls that may run at once per mount.
///
/// Invariant: must stay in sync with `MaxConcurrentOps` in `sdk/go/vfs/server.go`
/// and `MAX_PENDING_CALLS` in the transport module — the three
/// bound the same in-flight window from opposite ends of the socket.
pub const MAX_CONCURRENT_OPS: usize = 16;

/// Maximum time to wait for in-flight serve workers during shutdown before
/// aborting the connection (mirrors `virtualMountServeShutdownWait` in Go).
pub const SERVE_SHUTDOWN_JOIN_TIMEOUT: Duration = Duration::from_secs(30);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct ServeJob {
    id: u64,
    req_bytes: Vec<u8>,
    release: SyncSender<()>,
}

/// Shared shutdown hook: poisons the writer and optionally tears down the reader
/// (Unix `shutdown`) so `read_jobs` does not keep blocking after a write failure.
struct ServeAbort {
    aborted: AtomicBool,
    hook: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl ServeAbort {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            aborted: AtomicBool::new(false),
            hook: Mutex::new(None),
        })
    }

    fn set_hook(self: &Arc<Self>, hook: Box<dyn Fn() + Send + Sync>) {
        *self.hook.lock().unwrap() = Some(hook);
    }

    fn abort(self: &Arc<Self>) {
        if self.aborted.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(hook) = self.hook.lock().unwrap().take() {
            hook();
        }
    }

    fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::SeqCst)
    }
}

struct SharedWriter<W: Write + Send + 'static> {
    inner: Mutex<Option<W>>,
}

impl<W: Write + Send + 'static> SharedWriter<W> {
    fn write_frame(&self, id: u64, payload: &[u8]) -> io::Result<()> {
        let mut guard = self.inner.lock().unwrap();
        let w = guard
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "vfs: writer closed"))?;
        write_frame(w, id, payload)
    }

    fn poison(&self) {
        *self.inner.lock().unwrap() = None;
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run the request/response loop for one virtual mount over a connected
/// `UnixStream`.
///
/// Performs the responder half of the hello handshake, then reads framed CBOR
/// requests from `stream`, dispatches each to `provider`, and writes replies.
/// Returns `Ok(())` on a clean EOF (the runtime closed the channel).
pub fn serve_unix(
    stream: std::os::unix::net::UnixStream,
    provider: Arc<dyn PathFs>,
) -> io::Result<()> {
    use std::net::Shutdown;

    let reader = stream.try_clone()?;
    let reader_abort = reader.try_clone()?;
    let writer_abort = stream.try_clone()?;
    let abort = ServeAbort::new();
    abort.set_hook(Box::new(move || {
        let _ = reader_abort.shutdown(Shutdown::Both);
        let _ = writer_abort.shutdown(Shutdown::Both);
    }));
    serve_loop(reader, stream, provider, abort)
}

/// Like [`serve_unix`] with separate read and write halves of one connection.
pub fn serve<R, W>(reader: R, writer: W, provider: Arc<dyn PathFs>) -> io::Result<()>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    serve_loop(reader, writer, provider, ServeAbort::new())
}

fn serve_loop<R, W>(
    mut reader: R,
    mut writer: W,
    provider: Arc<dyn PathFs>,
    abort: Arc<ServeAbort>,
) -> io::Result<()>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    read_hello(&mut reader)?;
    write_hello(&mut writer)?;

    let writer = Arc::new(SharedWriter {
        inner: Mutex::new(Some(writer)),
    });
    let state = Arc::new(DispatchState::default());
    let (job_tx, job_rx) = mpsc::sync_channel::<ServeJob>(MAX_CONCURRENT_OPS);
    let job_rx = Arc::new(Mutex::new(job_rx));

    // In-flight token pool: acquire before reading each frame so a fast guest
    // cannot queue more than MAX_CONCURRENT_OPS decoded requests (matches Go
    // `sem <- struct{}{}` before `readFrame`).
    let (in_flight_tx, in_flight_rx) = mpsc::sync_channel(MAX_CONCURRENT_OPS);
    for _ in 0..MAX_CONCURRENT_OPS {
        in_flight_tx.send(()).expect("seed in-flight tokens");
    }

    let mut workers: Vec<JoinHandle<()>> = Vec::with_capacity(MAX_CONCURRENT_OPS);
    for _ in 0..MAX_CONCURRENT_OPS {
        let job_rx = Arc::clone(&job_rx);
        let writer = Arc::clone(&writer);
        let state = Arc::clone(&state);
        let provider = Arc::clone(&provider);
        let abort = Arc::clone(&abort);
        workers.push(thread::spawn(move || {
            serve_worker(job_rx, writer, state, provider, abort);
        }));
    }

    let result = read_jobs(&mut reader, &job_tx, in_flight_rx, in_flight_tx, &abort);

    drop(job_tx);
    join_workers_bounded(workers, abort);
    result
}

fn join_workers_bounded(workers: Vec<JoinHandle<()>>, abort: Arc<ServeAbort>) {
    let deadline = Instant::now() + SERVE_SHUTDOWN_JOIN_TIMEOUT;
    let mut timed_out = false;
    let mut background_joins: Vec<JoinHandle<()>> = Vec::new();
    for h in workers {
        if timed_out {
            background_joins.push(thread::spawn(move || {
                let _ = h.join();
            }));
            continue;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let (tx, rx) = mpsc::sync_channel(0);
        let helper = thread::spawn(move || {
            let _ = h.join();
            let _ = tx.send(());
        });
        match rx.recv_timeout(remaining) {
            Ok(()) => {}
            Err(_) => {
                tracing::warn!(
                    ?SERVE_SHUTDOWN_JOIN_TIMEOUT,
                    "vfs: timed out waiting for in-flight provider calls during shutdown"
                );
                abort.abort();
                timed_out = true;
                background_joins.push(helper);
            }
        }
    }
    // Drop without joining: detached worker threads finish shutdown in the
    // background instead of blocking the serve loop past SERVE_SHUTDOWN_JOIN_TIMEOUT.
    drop(background_joins);
}

/// Returns an in-flight read token when dropped (including on panic).
struct InFlightGuard(Option<SyncSender<()>>);

impl InFlightGuard {
    fn new(release: SyncSender<()>) -> Self {
        Self(Some(release))
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            let _ = release.send(());
        }
    }
}

fn serve_worker<W: Write + Send + 'static>(
    job_rx: Arc<Mutex<mpsc::Receiver<ServeJob>>>,
    writer: Arc<SharedWriter<W>>,
    state: Arc<DispatchState>,
    provider: Arc<dyn PathFs>,
    abort: Arc<ServeAbort>,
) {
    loop {
        let job = {
            let rx = job_rx.lock().unwrap();
            rx.recv()
        };
        let Ok(ServeJob {
            id,
            req_bytes,
            release,
        }) = job
        else {
            break;
        };
        let _in_flight = InFlightGuard::new(release);
        let panic_result = catch_unwind(AssertUnwindSafe(|| {
            let resp = match decode_request(&req_bytes) {
                Ok(req) => match catch_unwind(AssertUnwindSafe(|| {
                    dispatch_with_state(provider.as_ref(), req, &state)
                })) {
                    Ok(resp) => resp,
                    Err(payload) => {
                        tracing::error!(?payload, "vfs: provider panicked while handling request");
                        VfsResponse::Err(libc::EIO)
                    }
                },
                Err(err) => VfsResponse::Err(decode_error_errno(&err)),
            };
            let mut payload = to_cbor(&resp);
            if payload.len() > MAX_FRAME_LEN as usize {
                tracing::error!(
                    request_id = id,
                    encoded_len = payload.len(),
                    max = MAX_FRAME_LEN,
                    "vfs: encoded response exceeds frame limit"
                );
                payload = to_cbor(&VfsResponse::Err(
                    platform::eio().raw_os_error().unwrap_or(libc::EIO),
                ));
            }
            if let Err(err) = writer.write_frame(id, &payload) {
                tracing::error!(request_id = id, error = %err, "vfs: response write failed");
                writer.poison();
                abort.abort();
            }
        }));
        if panic_result.is_err() {
            tracing::error!("vfs: serve worker panicked while handling request");
            abort.abort();
        }
    }
}

fn read_jobs<R: Read>(
    reader: &mut R,
    job_tx: &SyncSender<ServeJob>,
    in_flight_rx: mpsc::Receiver<()>,
    in_flight_tx: SyncSender<()>,
    abort: &ServeAbort,
) -> io::Result<()> {
    loop {
        if abort.is_aborted() {
            return Ok(());
        }
        if in_flight_rx.recv().is_err() {
            return Ok(());
        }
        let (id, req_bytes) = match read_frame(reader) {
            Ok(frame) => frame,
            Err(e) if abort.is_aborted() || e.kind() == io::ErrorKind::UnexpectedEof => {
                let _ = in_flight_tx.send(());
                return Ok(());
            }
            Err(e) => {
                let _ = in_flight_tx.send(());
                return Err(e);
            }
        };
        if job_tx
            .send(ServeJob {
                id,
                req_bytes,
                release: in_flight_tx.clone(),
            })
            .is_err()
        {
            let _ = in_flight_tx.send(());
            return Ok(());
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::super::super::test_backend::InMemoryFs;
    use super::super::protocol::{VfsRequest, decode_request, validate_request_limits};
    use super::super::transport::MAX_PENDING_CALLS;
    use super::{MAX_CONCURRENT_OPS, SERVE_SHUTDOWN_JOIN_TIMEOUT, ServeAbort};
    use crate::PathFs;
    use serde_bytes::ByteBuf;

    #[test]
    fn serve_abort_invokes_hook_once() {
        let called = Arc::new(AtomicBool::new(false));
        let called_hook = Arc::clone(&called);
        let abort = ServeAbort::new();
        abort.set_hook(Box::new(move || {
            called_hook.store(true, Ordering::SeqCst);
        }));
        abort.abort();
        abort.abort();
        assert!(called.load(Ordering::SeqCst));
    }

    #[cfg(unix)]
    #[test]
    fn serve_unix_exits_after_response_write_failure() {
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        use super::super::protocol::{read_hello, write_frame, write_hello};

        let (mut client, server) = UnixStream::pair().unwrap();
        let provider: Arc<dyn PathFs> = Arc::new(InMemoryFs::new());
        let serve_handle =
            std::thread::spawn(move || super::serve_unix(server, provider).expect("serve_unix"));

        write_hello(&mut client).unwrap();
        read_hello(&mut client).unwrap();
        let req = super::super::protocol::to_cbor(&VfsRequest::StatFs);
        write_frame(&mut client, 1, &req).unwrap();
        // Drop the client without reading the reply so the server's next write fails
        // with EPIPE and the abort hook tears down the connection (matches Go `abort()`).
        drop(client);

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if serve_handle.is_finished() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                panic!("serve_unix did not exit after response write failure");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        serve_handle.join().expect("serve_unix thread panicked");
    }

    #[test]
    fn max_concurrent_ops_matches_go_and_requester() {
        assert_eq!(MAX_CONCURRENT_OPS, 16);
        assert_eq!(MAX_CONCURRENT_OPS, MAX_PENDING_CALLS);
    }

    #[test]
    fn serve_shutdown_join_timeout_matches_go() {
        assert_eq!(SERVE_SHUTDOWN_JOIN_TIMEOUT.as_secs(), 30);
    }

    #[test]
    fn decode_request_rejects_oversized_getattr_many_batch() {
        let paths: Vec<ByteBuf> = (0..=super::super::protocol::MAX_BATCH_PATHS)
            .map(|i| ByteBuf::from(format!("/p{i}").into_bytes()))
            .collect();
        let bytes = super::super::protocol::to_cbor(&VfsRequest::GetAttrMany { paths });
        assert!(decode_request(&bytes).is_err());
        assert!(
            validate_request_limits(&VfsRequest::GetAttrMany {
                paths: vec![ByteBuf::from(b"/ok".to_vec())],
            })
            .is_ok()
        );
    }
}
