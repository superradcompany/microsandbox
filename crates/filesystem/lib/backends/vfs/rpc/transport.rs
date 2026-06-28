//! Multiplexed socket transport for RPC calls from the runtime to the provider.

use std::{
    collections::HashMap,
    io::{self, Read, Write},
    marker::PhantomData,
    net::Shutdown,
    os::unix::net::UnixStream,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use super::client::VfsTransport;
use super::protocol::{self, PROTOCOL_VERSION, VfsRequest, VfsResponse};
use crate::backends::shared::platform;

/// Maximum queued outbound calls before `call` blocks.
///
/// Invariant: must stay in sync with `MaxConcurrentOps` in
/// `sdk/go/vfs/server.go` and [`MAX_CONCURRENT_OPS`](super::serve::MAX_CONCURRENT_OPS)
/// — the three bound the same in-flight window from opposite ends of the socket.
pub(crate) const MAX_PENDING_CALLS: usize = 16;

/// Default time to wait for a single RPC response when a mount does not set its
/// own `call_timeout_secs`. Matches [`HELLO_TIMEOUT`] — long enough for a normal
/// provider, short enough that a wedged one frees the FUSE worker (the op then
/// surfaces to the guest as `EIO`) rather than pinning it for minutes.
pub(crate) const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum time to wait for the peer's half of the hello handshake. Bounds VM
/// boot so a peer that never serves (wrong fd inherited, parent crashed after
/// spawn) fails fast instead of blocking `build_vm` forever.
pub(crate) const HELLO_TIMEOUT: Duration = Duration::from_secs(30);

enum IoCommand {
    Call { id: u64, payload: Vec<u8> },
}

/// Sender/receiver pair a worker thread reuses to await one RPC reply.
type RespChannel = (
    mpsc::Sender<io::Result<VfsResponse>>,
    mpsc::Receiver<io::Result<VfsResponse>>,
);

thread_local! {
    /// Per-thread response rendezvous, reused across calls instead of allocating
    /// a fresh channel per op. A FUSE worker thread blocks in `call_payload`
    /// until its one reply arrives, so it never has two calls outstanding — the
    /// single channel is always drained between uses (and replaced on the error
    /// path, where a late reply could otherwise be left queued).
    static RESP_CHANNEL: std::cell::RefCell<RespChannel> =
        std::cell::RefCell::new(mpsc::channel());
}

/// A duplex byte stream the [`SocketTransport`] can split into independent read
/// and write halves — one per I/O thread.
///
/// Both halves must reference the same underlying connection so that
/// [`shutdown`](Self::shutdown) on the write half unblocks a reader parked in
/// `read` on the read half (this is how the transport tears its threads down on
/// drop). A `SOCK_STREAM` [`UnixStream`] satisfies this via `try_clone` + socket
/// `shutdown`.
pub trait IoStream: Send + 'static {
    /// The read half handed to the reader thread.
    type Read: Read + Send + 'static;
    /// The write half handed to the writer thread.
    type Write: Write + Send + 'static;

    /// Produce two independent handles to the same underlying stream.
    fn try_split(self) -> io::Result<(Self::Read, Self::Write)>;

    /// Shut down both directions of the underlying connection, waking a reader
    /// blocked in `read` so it observes EOF and exits.
    fn shutdown(write_half: &Self::Write) -> io::Result<()>;
}

impl IoStream for UnixStream {
    type Read = UnixStream;
    type Write = UnixStream;

    fn try_split(self) -> io::Result<(UnixStream, UnixStream)> {
        let read_half = self.try_clone()?;
        Ok((read_half, self))
    }

    fn shutdown(write_half: &UnixStream) -> io::Result<()> {
        write_half.shutdown(Shutdown::Both)
    }
}

/// Map from `request_id` to the worker waiting on that reply, shared between the
/// reader and writer threads.
type Inflight = Arc<Mutex<HashMap<u64, mpsc::Sender<io::Result<VfsResponse>>>>>;

/// A multiplexed [`VfsTransport`] over any duplex byte stream (e.g. an inherited
/// `SOCK_STREAM` socketpair).
///
/// A dedicated writer thread drains queued calls onto the stream and a dedicated
/// reader thread demuxes responses by `request_id`, so concurrent FUSE workers
/// can have requests in flight at once. Splitting read from write means a write
/// that blocks on a full socket buffer never stalls response draining (no
/// deadlock under load) and a reply wakes the parked reader immediately (no
/// fixed poll latency).
pub struct SocketTransport<S> {
    next_id: AtomicU64,
    cmd_tx: mpsc::SyncSender<IoCommand>,
    /// Shared `request_id → waiting worker` map. Held here too (not only in the
    /// I/O threads) so a caller can drop its own entry when it gives up on a
    /// reply, instead of leaving it to leak until the reply arrives or the
    /// connection dies.
    inflight: Inflight,
    call_timeout: Duration,
    peer_version: u32,
    _reader: JoinHandle<()>,
    _writer: JoinHandle<()>,
    // `fn() -> S` so the marker never makes the transport's `Send`/`Sync` depend
    // on `S` — the stream itself is owned by the I/O threads, not this struct.
    _stream: PhantomData<fn() -> S>,
}

/// Enqueue one outbound RPC, waiting until `deadline` when the bounded queue is full.
fn send_cmd_with_deadline(
    tx: &SyncSender<IoCommand>,
    cmd: IoCommand,
    deadline: Instant,
) -> io::Result<()> {
    let mut cmd = cmd;
    loop {
        match tx.try_send(cmd) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(pending)) => {
                if Instant::now() >= deadline {
                    return Err(platform::eio());
                }
                cmd = pending;
                thread::sleep(Duration::from_millis(1));
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "vfs: transport thread exited",
                ));
            }
        }
    }
}

impl<S> SocketTransport<S> {
    /// Wrap a stream *without* performing the hello handshake, using the
    /// 30-second default call timeout. For peers that handshake out of band (e.g.
    /// tests). Most callers want [`connect`].
    ///
    /// [`connect`]: SocketTransport::connect
    pub fn new(stream: S) -> io::Result<Self>
    where
        S: IoStream,
    {
        Self::with_call_timeout(stream, DEFAULT_CALL_TIMEOUT)
    }

    /// Wrap a stream *without* performing the hello handshake, using an explicit
    /// per-op call timeout and the peer's negotiated protocol version.
    pub fn with_call_timeout(stream: S, call_timeout: Duration) -> io::Result<Self>
    where
        S: IoStream,
    {
        Self::with_call_timeout_and_peer_version(stream, call_timeout, PROTOCOL_VERSION)
    }

    pub(crate) fn with_call_timeout_and_peer_version(
        stream: S,
        call_timeout: Duration,
        peer_version: u32,
    ) -> io::Result<Self>
    where
        S: IoStream,
    {
        let (read_half, write_half) = stream.try_split()?;
        let (cmd_tx, cmd_rx) = mpsc::sync_channel(MAX_PENDING_CALLS);
        let inflight: Inflight = Arc::new(Mutex::new(HashMap::new()));
        let reader = thread::spawn({
            let inflight = Arc::clone(&inflight);
            move || reader_loop(read_half, inflight)
        });
        let writer = thread::spawn({
            let inflight = Arc::clone(&inflight);
            move || writer_loop::<S>(write_half, cmd_rx, inflight)
        });
        Ok(Self {
            next_id: AtomicU64::new(1),
            cmd_tx,
            inflight,
            call_timeout,
            peer_version,
            _reader: reader,
            _writer: writer,
            _stream: PhantomData,
        })
    }
}

impl<S: IoStream> SocketTransport<S> {
    /// Wrap a stream and perform the requester half of the hello handshake:
    /// write our hello, then read and validate the peer's. Fails if the peer
    /// speaks an incompatible [`PROTOCOL_VERSION`](protocol::PROTOCOL_VERSION).
    pub fn connect(mut stream: S) -> io::Result<Self>
    where
        S: Read + Write,
    {
        protocol::write_hello(&mut stream)?;
        let peer_version = protocol::read_hello(&mut stream)?;
        Self::with_call_timeout_and_peer_version(stream, DEFAULT_CALL_TIMEOUT, peer_version)
    }
}

impl<S> SocketTransport<S> {
    /// Peer protocol version from the hello handshake.
    pub fn peer_protocol_version(&self) -> u32 {
        self.peer_version
    }
}

impl<S> SocketTransport<S> {
    /// Stamp a request id, hand the pre-encoded payload to the I/O thread, and
    /// block for the demuxed reply. Shared by [`call`](VfsTransport::call) and
    /// [`call_write`](VfsTransport::call_write).
    fn call_payload(&self, payload: Vec<u8>) -> io::Result<VfsResponse> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let deadline = Instant::now() + self.call_timeout;
        RESP_CHANNEL.with(|cell| {
            let resp_tx = cell.borrow().0.clone();
            self.inflight.lock().unwrap().insert(id, resp_tx);
            match send_cmd_with_deadline(&self.cmd_tx, IoCommand::Call { id, payload }, deadline) {
                Ok(()) => {}
                Err(e) => {
                    self.inflight.lock().unwrap().remove(&id);
                    return Err(if e.kind() == io::ErrorKind::BrokenPipe {
                        e
                    } else {
                        platform::eio()
                    });
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let received = cell.borrow().1.recv_timeout(remaining);
            match received {
                Ok(resp) => resp,
                Err(e) => {
                    // Drop our in-flight entry so a never-answered call can't leak
                    // it for the connection's lifetime (the reader only reclaims
                    // entries whose replies actually arrive).
                    self.inflight.lock().unwrap().remove(&id);
                    // On timeout/disconnect a late reply may still be delivered
                    // to the cloned sender; swap in a fresh channel so the next
                    // call on this thread can't pick up that stale response.
                    *cell.borrow_mut() = mpsc::channel();
                    Err(match e {
                        // Guest-facing contract: a wedged provider frees the FUSE
                        // worker as EIO, not ETIMEDOUT.
                        RecvTimeoutError::Timeout => platform::eio(),
                        RecvTimeoutError::Disconnected => io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "vfs: response channel closed",
                        ),
                    })
                }
            }
        })
    }
}

fn fail_inflight(
    inflight: &mut HashMap<u64, mpsc::Sender<io::Result<VfsResponse>>>,
    err: io::Error,
) {
    for (_, tx) in inflight.drain() {
        let _ = tx.send(Err(io::Error::new(err.kind(), format!("vfs: {err}"))));
    }
}

/// Writer thread: drain queued calls onto the stream. Each call's `inflight`
/// entry is registered by `call_payload` before the command is queued, so a fast
/// reply can never arrive before the reader can match it. Exits when the command
/// channel disconnects (transport dropped) or a write fails, then shuts the
/// connection down to wake the reader.
fn writer_loop<S: IoStream>(
    mut write_half: S::Write,
    cmd_rx: mpsc::Receiver<IoCommand>,
    inflight: Inflight,
) {
    while let Ok(IoCommand::Call { id, payload }) = cmd_rx.recv() {
        if let Err(e) = protocol::write_frame(&mut write_half, id, &payload) {
            // The frame never made it; fail just this call and stop — the
            // connection is broken, so the reader will fail the rest on EOF.
            if let Some(tx) = inflight.lock().unwrap().remove(&id) {
                let _ = tx.send(Err(e));
            }
            break;
        }
    }
    // Closing both directions unblocks the reader (parked in `read`) so it can
    // fail any still-in-flight calls and exit, dropping the last stream handle.
    let _ = S::shutdown(&write_half);
}

/// Reader thread: demux responses by `request_id` and hand each to the worker
/// waiting on it. A read error or EOF fails every in-flight call and ends the
/// thread.
fn reader_loop<R: Read>(mut read_half: R, inflight: Inflight) {
    loop {
        match protocol::read_frame(&mut read_half) {
            Ok((id, resp_bytes)) => {
                let resp = protocol::from_cbor(&resp_bytes);
                let waiter = inflight.lock().unwrap().remove(&id);
                match waiter {
                    Some(tx) => {
                        let _ = tx.send(resp);
                    }
                    None => {
                        // A response for an unknown id (duplicate/late reply, or
                        // one whose in-flight entry was already dropped) is a
                        // single stray frame — drop it and keep serving the
                        // other mounts/workers rather than tearing down the
                        // whole transport.
                        tracing::warn!(request_id = id, "vfs: dropping orphan response");
                    }
                }
            }
            Err(e) => {
                let err = if e.kind() == io::ErrorKind::UnexpectedEof {
                    io::Error::new(io::ErrorKind::BrokenPipe, "vfs: transport closed")
                } else {
                    e
                };
                fail_inflight(&mut inflight.lock().unwrap(), err);
                return;
            }
        }
    }
}

impl<S: IoStream> VfsTransport for SocketTransport<S> {
    fn peer_protocol_version(&self) -> u32 {
        self.peer_version
    }

    fn call(&self, req: VfsRequest) -> io::Result<VfsResponse> {
        self.call_payload(protocol::to_cbor(&req))
    }

    fn call_write(&self, path: &[u8], offset: u64, data: &[u8]) -> io::Result<VfsResponse> {
        self.call_payload(protocol::encode_write(path, offset, data))
    }

    fn call_getattr(&self, path: &[u8]) -> io::Result<VfsResponse> {
        self.call_payload(protocol::encode_getattr(path))
    }

    fn call_read(&self, path: &[u8], offset: u64, size: u32) -> io::Result<VfsResponse> {
        self.call_payload(protocol::encode_read(path, offset, size))
    }

    fn call_getattr_many(&self, paths: &[&[u8]]) -> io::Result<VfsResponse> {
        self.call_payload(protocol::encode_getattr_many(paths))
    }
}

#[cfg(test)]
mod max_pending_calls_tests {
    use super::MAX_PENDING_CALLS;

    #[test]
    fn max_pending_calls_matches_go() {
        // Keep in sync with MaxConcurrentOps in sdk/go/vfs/server.go.
        assert_eq!(MAX_PENDING_CALLS, 16);
    }

    #[test]
    fn max_readdir_cache_paths_matches_go() {
        // Keep in sync with maxReaddirCachePaths in sdk/go/vfs/protocol.go.
        assert_eq!(super::protocol::MAX_READDIR_CACHE_PATHS, 64);
    }
}
