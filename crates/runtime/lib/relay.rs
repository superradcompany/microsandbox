//! Agent relay for the sandbox process.
//!
//! The [`AgentRelay`] reads from the console backend's ring buffers (data
//! written by agentd in the guest via virtio-console), listens on a Unix
//! domain socket (`agent.sock`) for SDK client connections, and transparently
//! relays protocol frames between clients and the guest agent.
//!
//! Each client is assigned a non-overlapping correlation ID range during
//! handshake so that the relay can route agent responses back to the correct
//! client without rewriting frame headers.

use std::collections::{HashMap, HashSet};
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::{Bytes, BytesMut};
use microsandbox_protocol::codec::{self, MAX_FRAME_SIZE};
use microsandbox_protocol::exec::{ExecRequest, ExecSignal, ExecStderr, ExecStdout};
use microsandbox_protocol::message::{
    FLAG_SESSION_START, FLAG_SHUTDOWN, FLAG_TERMINAL, FRAME_HEADER_SIZE, Message, MessageType,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, unix::AsyncFd};
use tokio::net::UnixListener;
use tokio::net::unix::OwnedReadHalf;
use tokio::sync::{Mutex, mpsc, watch};

use crate::console::ConsoleSharedState;
use crate::exec_log::{LogSource, LogWriter};
use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Types: capture
//--------------------------------------------------------------------------------------------------

/// Metadata recorded for each observed exec session. Populated by
/// `client_reader_task` when an `ExecRequest` arrives, consumed by
/// the ring reader's tap, and removed on `ExecExited`.
#[derive(Debug, Clone, Copy)]
struct SessionInfo {
    /// Monotonic per-relay session id. Distinct from the protocol
    /// correlation id, which can be reused across slot recycling
    /// (each `msb exec` is a separate client; slot 0 is freed and
    /// reassigned, so the same correlation id can appear twice
    /// within a sandbox lifetime). The monotonic counter gives every
    /// session a unique id within the relay's lifetime, which is
    /// what users see in `exec.log` entries.
    session_id: u64,

    /// Whether the session was opened in pty mode (drives
    /// `LogSource::Output` vs `Stdout` tagging).
    is_pty: bool,
}

/// Per-session bookkeeping for the log tap. Keyed by protocol
/// correlation id (which is what subsequent `Exec*` frames carry).
type SessionRegistry = std::sync::Mutex<HashMap<u32, SessionInfo>>;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum number of simultaneous clients.
const MAX_CLIENTS: u32 = 16;

/// Size of the correlation ID range allocated to each client.
const ID_RANGE_STEP: u32 = u32::MAX / MAX_CLIENTS;

/// Size of the length prefix in the wire format.
const LEN_PREFIX_SIZE: usize = 4;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// State for a connected client.
struct ClientState {
    /// Active session IDs owned by this client (tracked for disconnect cleanup).
    active_sessions: HashSet<u32>,
    /// Channel for sending frames to this client's writer task.
    /// Using a channel avoids holding the client mutex across async writes.
    /// Uses `Bytes` for zero-copy frame forwarding from the ring buffer.
    write_tx: mpsc::Sender<Bytes>,
}

/// Capacity of the per-client write channel.
const CLIENT_WRITE_CHANNEL_CAPACITY: usize = 64;

/// The agent relay running in the sandbox process.
///
/// Reads agent frames from the console backend's ring buffers and listens
/// for client connections on a Unix domain socket. Frames are routed between
/// clients and the guest agent without decoding.
pub struct AgentRelay {
    /// Shared ring buffers + wake pipes for console backend communication.
    shared: Arc<ConsoleSharedState>,
    /// Unix domain socket listener for client connections.
    listener: UnixListener,
    /// Path to the Unix domain socket.
    sock_path: PathBuf,
    /// Cached `core.ready` frame bytes (length-prefixed wire format).
    ready_frame: Option<Vec<u8>>,
    /// Optional `exec.log` writer. When set, the ring reader task
    /// captures the primary session's stdout/stderr to JSON Lines.
    log_writer: Option<Arc<LogWriter>>,
}

/// A frame extracted from the byte stream, kept as raw bytes for transparent
/// forwarding.
struct RawFrame {
    /// The complete frame bytes including the 4-byte length prefix.
    /// Uses `Bytes` for zero-copy extraction from the ring buffer.
    data: Bytes,
    /// The correlation ID extracted from the frame header.
    id: u32,
    /// The flags byte extracted from the frame header.
    flags: u8,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AgentRelay {
    /// Create a new agent relay.
    ///
    /// Takes the shared console state (ring buffers) and a path where the
    /// Unix domain socket will be bound for client connections.
    pub async fn new(
        agent_sock_path: &Path,
        shared: Arc<ConsoleSharedState>,
    ) -> RuntimeResult<Self> {
        // Remove stale socket file if it exists.
        if agent_sock_path.exists() {
            let _ = std::fs::remove_file(agent_sock_path);
        }

        // Ensure the parent directory exists.
        if let Some(parent) = agent_sock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(agent_sock_path)?;
        tracing::info!("agent relay listening on {}", agent_sock_path.display());

        Ok(Self {
            shared,
            listener,
            sock_path: agent_sock_path.to_path_buf(),
            ready_frame: None,
            log_writer: None,
        })
    }

    /// Attach a log writer for `exec.log` capture.
    ///
    /// Must be called before [`run()`](Self::run). When attached, the
    /// ring reader captures the primary session's stdout/stderr into
    /// the writer's JSON Lines file (see
    /// `design/runtime/sandbox-logs.md` D3 / D3a). The
    /// `--- sandbox started ---` marker is **not** written here — it
    /// is written from [`wait_ready`](Self::wait_ready) once agentd
    /// signals `core.ready`, so the marker only appears when the
    /// guest has actually finished booting.
    pub fn with_log_writer(mut self, writer: Arc<LogWriter>) -> Self {
        self.log_writer = Some(writer);
        self
    }

    /// Read frames from the console ring buffer until `core.ready` is
    /// received.
    ///
    /// This is a **blocking** call (uses `libc::poll` on the wake pipe).
    /// Must be called before [`run()`](Self::run). The ready frame is cached
    /// so it can be sent to clients during handshake.
    pub fn wait_ready(&mut self) -> RuntimeResult<()> {
        const READY_TIMEOUT_SECS: i32 = 60;

        let mut buf = BytesMut::new();
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(READY_TIMEOUT_SECS as u64);

        loop {
            // Drain the wake pipe and pop all available chunks.
            self.shared.tx_wake.drain();
            while let Some(chunk) = self.shared.tx_ring.pop() {
                buf.extend_from_slice(&chunk);
            }

            // Try to extract complete frames.
            while let Some(frame) = try_extract_frame(&mut buf) {
                let raw_data = frame.data.to_vec();
                let msg = decode_frame(raw_data.clone())?;

                if msg.t == MessageType::Ready {
                    tracing::info!("agent relay: received core.ready from agentd");
                    self.ready_frame = Some(raw_data);
                    // Now that agentd has signalled readiness, mark the
                    // exec.log lifecycle. Doing this here (rather than
                    // in `with_log_writer`) means the marker only shows
                    // up when the guest actually came up — pre-relay
                    // failures (mount errors, etc.) leave exec.log empty
                    // and let `boot-error.json` carry the story alone.
                    if let Some(ref writer) = self.log_writer {
                        writer.write_system("--- sandbox started ---");
                    }
                    return Ok(());
                }

                tracing::debug!(
                    "agent relay: discarding pre-ready frame type={:?} id={}",
                    msg.t,
                    msg.id
                );
            }

            // Check timeout.
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(RuntimeError::Custom(
                    "agent relay: timed out waiting for core.ready from agentd".into(),
                ));
            }

            // Block until the wake pipe is readable or timeout expires.
            let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
            poll_fd_readable_timeout(self.shared.tx_wake.as_raw_fd(), timeout_ms);
        }
    }

    /// Run the main relay loop.
    ///
    /// Accepts client connections, relays frames between clients and the
    /// console ring buffers, and handles client disconnects with session
    /// cleanup.
    ///
    /// If a client sends a `core.shutdown` message (identified by
    /// `FLAG_SHUTDOWN` in the frame header), the relay notifies the caller
    /// via `drain_tx`.
    pub async fn run(
        self,
        mut shutdown: watch::Receiver<bool>,
        drain_tx: mpsc::Sender<()>,
    ) -> RuntimeResult<()> {
        let ready_frame = self.ready_frame.ok_or_else(|| {
            RuntimeError::Custom("agent relay: run() called before wait_ready()".into())
        })?;

        // Shared state: map from client slot index to client state.
        let clients: Arc<Mutex<HashMap<u32, ClientState>>> = Arc::new(Mutex::new(HashMap::new()));

        // Bounded channel for client reader tasks to send frames to the ring writer.
        // Backpressure prevents unbounded memory growth from client floods.
        let (agent_tx, agent_rx) = mpsc::channel::<Vec<u8>>(256);

        // Track which client slots are in use.
        let used_slots: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));

        // Spawn the ring writer task (client frames → rx_ring → guest).
        let shared_for_writer = Arc::clone(&self.shared);
        let ring_writer_handle = tokio::spawn(ring_writer_task(shared_for_writer, agent_rx));

        // Spawn the ring reader task (tx_ring → guest frames → clients).
        // When a log writer is attached, the reader also captures
        // every exec session's stdout/stderr into `exec.log` (tagged
        // with a relay-monotonic session id so readers can group or
        // filter by session — the protocol correlation id can be
        // reused across slot recycling, so we mint our own).
        //
        // `session_registry` is shared between the per-client reader
        // (records pty flag and assigns the monotonic id from
        // `next_session_id` on observed ExecRequest payloads) and
        // the ring reader's tap (looks up the session info for each
        // Exec* frame).
        let session_registry: Arc<SessionRegistry> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));
        // Counter starts at 1 so 0 is unambiguously "not a session"
        // for any out-of-band tooling that might compare against it.
        let next_session_id: Arc<AtomicU64> = Arc::new(AtomicU64::new(1));
        let clients_for_reader = Arc::clone(&clients);
        let shared_for_reader = Arc::clone(&self.shared);
        let log_writer_for_reader = self.log_writer.clone();
        let registry_for_reader = Arc::clone(&session_registry);
        let ring_reader_handle = tokio::spawn(ring_reader_task(
            shared_for_reader,
            clients_for_reader,
            log_writer_for_reader,
            registry_for_reader,
        ));

        // Accept loop.
        loop {
            tokio::select! {
                accept_result = self.listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            // Allocate a client slot.
                            let slot = {
                                let mut slots = used_slots.lock().await;
                                let mut found = None;
                                for i in 0..MAX_CLIENTS {
                                    if !slots.contains(&i) {
                                        slots.insert(i);
                                        found = Some(i);
                                        break;
                                    }
                                }
                                found
                            };

                            let slot = match slot {
                                Some(s) => s,
                                None => {
                                    tracing::error!("agent relay: max clients reached, rejecting connection");
                                    drop(stream);
                                    continue;
                                }
                            };

                            let id_offset = slot * ID_RANGE_STEP;
                            tracing::info!(
                                "agent relay: client connected slot={slot} id_offset={id_offset}"
                            );

                            // Perform handshake: send [id_offset: u32 BE][ready_frame_bytes...].
                            let (reader_half, mut writer_half) = stream.into_split();

                            let mut handshake = Vec::with_capacity(4 + ready_frame.len());
                            handshake.extend_from_slice(&id_offset.to_be_bytes());
                            handshake.extend_from_slice(&ready_frame);

                            if let Err(e) = writer_half.write_all(&handshake).await {
                                tracing::error!(
                                    "agent relay: handshake write failed slot={slot}: {e}"
                                );
                                used_slots.lock().await.remove(&slot);
                                continue;
                            }

                            // Spawn a per-client writer task so the ring reader
                            // never holds the mutex across async writes.
                            let (write_tx, mut write_rx) =
                                mpsc::channel::<Bytes>(CLIENT_WRITE_CHANNEL_CAPACITY);
                            tokio::spawn(async move {
                                while let Some(data) = write_rx.recv().await {
                                    if let Err(e) = writer_half.write_all(&data).await {
                                        tracing::error!(
                                            "agent relay: client writer slot={slot} failed: {e}"
                                        );
                                        break;
                                    }
                                }
                            });

                            // Register the client.
                            {
                                let mut map = clients.lock().await;
                                map.insert(slot, ClientState {
                                    active_sessions: HashSet::new(),
                                    write_tx,
                                });
                            }

                            // Spawn a reader task for this client.
                            let agent_tx_clone = agent_tx.clone();
                            let clients_clone = Arc::clone(&clients);
                            let used_slots_clone = Arc::clone(&used_slots);
                            let drain_tx_clone = drain_tx.clone();
                            let registry_clone = Arc::clone(&session_registry);
                            let next_id_clone = Arc::clone(&next_session_id);

                            tokio::spawn(client_reader_task(
                                slot,
                                reader_half,
                                agent_tx_clone,
                                clients_clone,
                                used_slots_clone,
                                drain_tx_clone,
                                registry_clone,
                                next_id_clone,
                            ));
                        }
                        Err(e) => {
                            tracing::error!("agent relay: accept error: {e}");
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("agent relay: shutdown signal received");
                        break;
                    }
                }
            }
        }

        // The "--- sandbox stopped ---" marker is written by the VMM's
        // `on_exit` observer (runs before `_exit()`), so we don't
        // double-write it here.

        // Clean up the socket file.
        let _ = std::fs::remove_file(&self.sock_path);

        // Abort background tasks.
        ring_writer_handle.abort();
        ring_reader_handle.abort();

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Block until a file descriptor becomes readable or timeout expires.
///
/// `timeout_ms` is in milliseconds. Use `-1` for infinite.
fn poll_fd_readable_timeout(fd: RawFd, timeout_ms: i32) {
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a valid stack-allocated pollfd.
        let ret = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ret >= 0 {
            return; // Success — fd is readable, or timeout expired (ret == 0).
        }
        // ret == -1: error. Retry on EINTR, give up on other errors.
        let errno = std::io::Error::last_os_error();
        if errno.raw_os_error() != Some(libc::EINTR) {
            tracing::error!("agent relay: poll() failed: {errno}");
            return;
        }
        // EINTR — retry.
    }
}

/// Try to extract a complete frame from a byte buffer.
///
/// Returns `None` if the buffer doesn't contain a full frame yet. On
/// success, the consumed bytes are removed from `buf`.
fn try_extract_frame(buf: &mut BytesMut) -> Option<RawFrame> {
    if buf.len() < LEN_PREFIX_SIZE {
        return None;
    }

    let frame_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

    // Sanity checks.
    if frame_len > MAX_FRAME_SIZE as usize {
        // Corrupt data — clear the entire buffer. Nibbling just 4 bytes would
        // re-interpret frame body bytes as a new length, cascading failures.
        tracing::error!(
            "agent relay: frame too large ({frame_len} bytes), clearing {} bytes of buffer",
            buf.len()
        );
        buf.clear();
        return None;
    }

    if buf.len() < LEN_PREFIX_SIZE + frame_len {
        return None; // Need more data.
    }

    if frame_len < FRAME_HEADER_SIZE {
        // Corrupt frame — discard.
        tracing::error!("agent relay: frame too short ({frame_len} bytes), discarding");
        let _ = buf.split_to(LEN_PREFIX_SIZE + frame_len);
        return None;
    }

    // Split off the complete frame — zero-copy via freeze().
    let data = buf.split_to(LEN_PREFIX_SIZE + frame_len).freeze();

    let id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let flags = data[8];

    Some(RawFrame { data, id, flags })
}

/// Decode raw frame bytes into a protocol `Message`.
fn decode_frame(mut buf: Vec<u8>) -> RuntimeResult<Message> {
    codec::try_decode_from_buf(&mut buf)
        .map_err(|e| RuntimeError::Custom(format!("decode frame: {e}")))?
        .ok_or_else(|| RuntimeError::Custom("decode frame: incomplete frame".into()))
}

/// Tap a guest-originated frame into `exec.log` if it belongs to the
/// primary session. Best-effort: any decode error is logged and
/// dropped — capture failures must never disrupt the routing path.
fn tap_frame_into_log(frame: &RawFrame, writer: &LogWriter, session_registry: &SessionRegistry) {
    // Decode the message envelope to learn the type. The full CBOR
    // decode is small (the envelope is a 3-field map; the heavy
    // payload is left as opaque bytes in `Message::p`).
    let msg = match decode_frame(frame.data.to_vec()) {
        Ok(m) => m,
        Err(err) => {
            tracing::debug!(error = %err, "exec_log: skipping frame with decode error");
            return;
        }
    };

    // Look up the session info recorded by `client_reader_task` when
    // the ExecRequest arrived. Returns `None` for frames whose
    // session predates the relay's lifetime or whose ExecRequest
    // we missed (defensive — shouldn't happen in normal operation).
    let session_info = session_registry
        .lock()
        .ok()
        .and_then(|m| m.get(&msg.id).copied());

    match msg.t {
        // ExecRequest flows host→guest, observed in `client_reader_task`.
        MessageType::ExecStdout => {
            let Some(info) = session_info else { return };
            // pty mode merges stdout+stderr into a single stream
            // shipped over ExecStdout frames; tag as `Output`
            // accordingly.
            let tag = if info.is_pty {
                LogSource::Output
            } else {
                LogSource::Stdout
            };
            match msg.payload::<ExecStdout>() {
                Ok(p) => writer.write_chunk(tag, info.session_id, &p.data),
                Err(err) => tracing::debug!(error = %err, "exec_log: stdout payload decode failed"),
            }
        }
        MessageType::ExecStderr => {
            // ExecStderr frames are pipe-mode-only by construction.
            let Some(info) = session_info else { return };
            match msg.payload::<ExecStderr>() {
                Ok(p) => writer.write_chunk(LogSource::Stderr, info.session_id, &p.data),
                Err(err) => tracing::debug!(error = %err, "exec_log: stderr payload decode failed"),
            }
        }
        _ => {}
    }

    // Drop the registry entry on any terminal frame (ExecExited,
    // ExecFailed) so we don't leak `SessionInfo` for the lifetime of
    // the relay. The flag is set on both — checking it here covers
    // every terminal exec frame uniformly.
    if (frame.flags & FLAG_TERMINAL) != 0
        && let Ok(mut registry) = session_registry.lock()
    {
        registry.remove(&msg.id);
    }
}

/// Background task that pushes client frames into the rx_ring for the guest.
/// Retries on full ring with backoff to avoid dropping frames.
async fn ring_writer_task(shared: Arc<ConsoleSharedState>, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(frame_bytes) = rx.recv().await {
        let mut data = frame_bytes;
        for attempt in 0..50 {
            match shared.rx_ring.push(data) {
                Ok(()) => {
                    shared.rx_wake.wake();
                    break;
                }
                Err(returned) => {
                    if attempt == 49 {
                        tracing::error!("agent relay: rx_ring full after retries, dropping frame");
                        break;
                    }
                    data = returned;
                    // Brief yield to let the guest drain the ring.
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }
        }
    }
    tracing::debug!("agent relay: ring writer task exiting");
}

/// Background task that reads frames from the tx_ring (written by the guest
/// agent) and routes them to the correct client based on correlation ID range.
///
/// When `log_writer` is `Some`, the task also taps the primary session's
/// `ExecStdout` / `ExecStderr` payloads into `exec.log`. The "primary"
/// session is the first one whose `ExecRequest` arrives after the relay
/// starts, recorded via CAS into `primary_session_id`. See
/// `design/runtime/sandbox-logs.md` D3a.
async fn ring_reader_task(
    shared: Arc<ConsoleSharedState>,
    clients: Arc<Mutex<HashMap<u32, ClientState>>>,
    log_writer: Option<Arc<LogWriter>>,
    session_registry: Arc<SessionRegistry>,
) {
    // Wrap the tx_wake read fd in AsyncFd for tokio-driven notification.
    let wake_fd = shared.tx_wake.as_raw_fd();
    let async_fd = match AsyncFd::new(wake_fd) {
        Ok(fd) => fd,
        Err(e) => {
            tracing::error!("agent relay: failed to create AsyncFd for tx_wake: {e}");
            return;
        }
    };

    let mut buf = BytesMut::new();
    let mut frames = Vec::new();

    loop {
        // Wait for the wake pipe to become readable.
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(e) => {
                tracing::error!("agent relay: AsyncFd readable error: {e}");
                break;
            }
        };
        guard.clear_ready();

        // Drain the wake pipe and pop all available chunks.
        shared.tx_wake.drain();
        while let Some(chunk) = shared.tx_ring.pop() {
            buf.extend_from_slice(&chunk);
        }

        // Extract all complete frames first, then route them.
        // This avoids holding the client mutex across async writes.
        while let Some(frame) = try_extract_frame(&mut buf) {
            frames.push(frame);
        }

        for frame in frames.drain(..) {
            let client_slot = frame.id / ID_RANGE_STEP;
            let client_slot = client_slot.min(MAX_CLIENTS - 1);

            let is_terminal = (frame.flags & FLAG_TERMINAL) != 0;

            // Tap every exec session's stdout/stderr into `exec.log`
            // when a log writer is attached. The CBOR decode is only
            // done when there is a writer, so the no-capture path is
            // unchanged.
            if let Some(writer) = log_writer.as_ref() {
                tap_frame_into_log(&frame, writer, &session_registry);
            }

            // Acquire lock briefly to get session bookkeeping + clone writer.
            // Then release before the async write to avoid blocking other clients.
            let writer_result = {
                let mut map = clients.lock().await;
                if let Some(client) = map.get_mut(&client_slot) {
                    if is_terminal {
                        client.active_sessions.remove(&frame.id);
                    }
                    Ok(client.write_tx.clone())
                } else {
                    Err(frame.id)
                }
            };

            match writer_result {
                Ok(write_tx) => {
                    if write_tx.send(frame.data).await.is_err() {
                        tracing::error!("agent relay: write channel closed for slot={client_slot}");
                    }
                }
                Err(id) => {
                    tracing::debug!(
                        "agent relay: no client for slot={client_slot} id={id} (frame dropped)"
                    );
                }
            }
        }
    }
    tracing::debug!("agent relay: ring reader task exiting");
}

/// Read a single raw frame from an async reader (used for client connections).
async fn read_raw_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> RuntimeResult<RawFrame> {
    // Read the 4-byte length prefix.
    let mut len_buf = [0u8; LEN_PREFIX_SIZE];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(RuntimeError::Custom("agent relay: unexpected EOF".into()));
        }
        Err(e) => return Err(RuntimeError::Io(e)),
    }

    let frame_len = u32::from_be_bytes(len_buf);

    if frame_len > MAX_FRAME_SIZE {
        return Err(RuntimeError::Custom(format!(
            "agent relay: frame too large: {frame_len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }

    let frame_len = frame_len as usize;

    if frame_len < FRAME_HEADER_SIZE {
        return Err(RuntimeError::Custom(format!(
            "agent relay: frame too short: {frame_len} bytes"
        )));
    }

    // Single allocation: length prefix + payload in one Vec.
    let mut data = Vec::with_capacity(LEN_PREFIX_SIZE + frame_len);
    data.extend_from_slice(&len_buf);
    data.resize(LEN_PREFIX_SIZE + frame_len, 0);
    reader.read_exact(&mut data[LEN_PREFIX_SIZE..]).await?;

    let id = u32::from_be_bytes([
        data[LEN_PREFIX_SIZE],
        data[LEN_PREFIX_SIZE + 1],
        data[LEN_PREFIX_SIZE + 2],
        data[LEN_PREFIX_SIZE + 3],
    ]);
    let flags = data[LEN_PREFIX_SIZE + 4];

    Ok(RawFrame {
        data: Bytes::from(data),
        id,
        flags,
    })
}

/// Background task that reads frames from a client and forwards them to the
/// ring writer channel. Handles client disconnect with session cleanup.
///
/// The argument count is over the clippy default (7) because the task
/// shares per-relay state across both tasks: client routing
/// (`agent_tx`, `clients`, `used_slots`, `drain_tx`) plus the
/// session registry / monotonic id atomic for the log capture path.
/// Bundling them into a struct would be more boilerplate than the
/// lint guards against — there's a single call site.
#[allow(clippy::too_many_arguments)]
async fn client_reader_task(
    slot: u32,
    mut reader: OwnedReadHalf,
    agent_tx: mpsc::Sender<Vec<u8>>,
    clients: Arc<Mutex<HashMap<u32, ClientState>>>,
    used_slots: Arc<Mutex<HashSet<u32>>>,
    drain_tx: mpsc::Sender<()>,
    session_registry: Arc<SessionRegistry>,
    next_session_id: Arc<AtomicU64>,
) {
    loop {
        let frame = match read_raw_frame(&mut reader).await {
            Ok(f) => f,
            Err(_) => {
                tracing::info!("agent relay: client disconnected slot={slot}");
                break;
            }
        };

        // Track session starts for disconnect cleanup.
        let is_session_start = (frame.flags & FLAG_SESSION_START) != 0;
        let is_terminal = (frame.flags & FLAG_TERMINAL) != 0;
        let is_shutdown = (frame.flags & FLAG_SHUTDOWN) != 0;

        // Notify the caller to start drain escalation.
        if is_shutdown {
            tracing::info!("agent relay: client slot={slot} sent core.shutdown, notifying drain");
            let _ = drain_tx.try_send(());
        }

        // Register each ExecRequest in the session registry: assign a
        // relay-monotonic session id and record the pty flag. The
        // monotonic id is what users see in `exec.log` entries — it's
        // unique per session within the relay's lifetime, unlike the
        // protocol correlation id which can be reused after slot
        // recycling.
        //
        // FLAG_SESSION_START is set on both ExecRequest and FsRequest,
        // so we decode the type to disambiguate.
        if is_session_start
            && let Ok(msg) = decode_frame(frame.data.to_vec())
            && msg.t == MessageType::ExecRequest
        {
            let pty = msg.payload::<ExecRequest>().map(|r| r.tty).unwrap_or(false);
            let session_id = next_session_id.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut registry) = session_registry.lock() {
                registry.insert(
                    frame.id,
                    SessionInfo {
                        session_id,
                        is_pty: pty,
                    },
                );
            }
        }

        // Only acquire the lock when session bookkeeping is needed.
        // Data frames (the vast majority) skip the lock entirely.
        if is_session_start || is_terminal {
            let mut map = clients.lock().await;
            if let Some(client) = map.get_mut(&slot) {
                if is_session_start {
                    client.active_sessions.insert(frame.id);
                }
                if is_terminal {
                    client.active_sessions.remove(&frame.id);
                }
            }
        }

        // Forward frame to ring writer (bounded — applies backpressure).
        if agent_tx.send(frame.data.to_vec()).await.is_err() {
            tracing::error!("agent relay: ring writer channel closed");
            break;
        }
    }

    // Client disconnected — send SIGKILL for each active session.
    let active_sessions = {
        let mut map = clients.lock().await;
        if let Some(client) = map.remove(&slot) {
            client.active_sessions
        } else {
            HashSet::new()
        }
    };

    if !active_sessions.is_empty() {
        tracing::info!(
            "agent relay: cleaning up {} active sessions for slot={slot}",
            active_sessions.len()
        );

        for session_id in active_sessions {
            let kill_msg = match Message::with_payload(
                MessageType::ExecSignal,
                session_id,
                &ExecSignal { signal: 9 }, // SIGKILL
            ) {
                Ok(msg) => msg,
                Err(e) => {
                    tracing::error!(
                        "agent relay: failed to encode SIGKILL for session {session_id}: {e}"
                    );
                    continue;
                }
            };

            let mut buf = Vec::new();
            if let Err(e) = codec::encode_to_buf(&kill_msg, &mut buf) {
                tracing::error!(
                    "agent relay: failed to encode SIGKILL frame for session {session_id}: {e}"
                );
                continue;
            }

            if agent_tx.send(buf).await.is_err() {
                tracing::error!("agent relay: ring writer channel closed during cleanup");
                break;
            }
        }
    }

    // Release the client slot.
    used_slots.lock().await.remove(&slot);
    tracing::debug!("agent relay: slot={slot} released");
}
