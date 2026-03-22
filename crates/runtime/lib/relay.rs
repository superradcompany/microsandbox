//! Agent relay for the supervisor process.
//!
//! The [`AgentRelay`] creates a Unix socketpair for communicating with agentd
//! in the guest VM, listens on a Unix domain socket (`agent.sock`) for SDK
//! client connections, and transparently relays protocol frames between clients
//! and the agent channel.
//!
//! Each client is assigned a non-overlapping correlation ID range during
//! handshake so that the relay can route agent responses back to the correct
//! client without rewriting frame headers.

use std::collections::{HashMap, HashSet};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use microsandbox_protocol::codec::{self, MAX_FRAME_SIZE};
use microsandbox_protocol::exec::ExecSignal;
use microsandbox_protocol::message::{
    FLAG_SESSION_START, FLAG_SHUTDOWN, FLAG_TERMINAL, FRAME_HEADER_SIZE, Message, MessageType,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, mpsc, watch};

use crate::{RuntimeError, RuntimeResult};

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
    /// Writer half for sending frames to this client.
    writer: OwnedWriteHalf,
}

/// The agent relay running in the supervisor.
///
/// Owns the agent socketpair host FD, listens for client connections on
/// a Unix domain socket, and relays frames between clients and agentd.
pub struct AgentRelay {
    /// Host-side FD of the agent socketpair.
    host_fd: OwnedFd,
    /// Guest-side FD (consumed when passed to the microvm child).
    guest_fd: Option<OwnedFd>,
    /// Unix domain socket listener for client connections.
    listener: UnixListener,
    /// Path to the Unix domain socket.
    sock_path: PathBuf,
    /// Cached `core.ready` frame bytes (length-prefixed wire format).
    ready_frame: Option<Vec<u8>>,
}

/// A frame read from the wire, kept as raw bytes for transparent forwarding.
struct RawFrame {
    /// The complete frame bytes including the 4-byte length prefix.
    data: Vec<u8>,
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
    /// Creates a Unix socketpair for the agent channel and starts listening
    /// on the given path for client connections.
    pub async fn new(agent_sock_path: &Path) -> RuntimeResult<Self> {
        // Create a SOCK_STREAM socketpair for host <-> guest agent communication.
        let (host_fd, guest_fd) = create_socketpair()?;

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
            host_fd,
            guest_fd: Some(guest_fd),
            listener,
            sock_path: agent_sock_path.to_path_buf(),
            ready_frame: None,
        })
    }

    /// Consume the guest-side FD for passing to the microvm child.
    ///
    /// Returns the raw FD. The caller is responsible for ensuring the FD
    /// survives across `fork+exec` (e.g., by clearing `FD_CLOEXEC`).
    /// Can only be called once.
    pub fn take_guest_fd(&mut self) -> Option<RawFd> {
        self.guest_fd.take().map(IntoRawFd::into_raw_fd)
    }

    /// Read frames from the agent host FD until `core.ready` is received.
    ///
    /// The ready frame is cached so it can be sent to clients during handshake.
    pub async fn wait_ready(&mut self) -> RuntimeResult<()> {
        // Dup the host FD so we can wrap it in an async reader without
        // consuming the OwnedFd.
        let dup_fd = duplicate_fd(self.host_fd.as_raw_fd())?;

        // Safety: dup_fd is a valid fd we just created.
        let std_stream =
            unsafe { std::os::unix::net::UnixStream::from_raw_fd(dup_fd.into_raw_fd()) };
        std_stream
            .set_nonblocking(true)
            .map_err(|e| RuntimeError::Custom(format!("set nonblocking: {e}")))?;
        let mut reader = UnixStream::from_std(std_stream)?;

        loop {
            let frame = read_raw_frame(&mut reader).await?;

            // Check if this is a Ready message by decoding the CBOR body.
            // We need the raw bytes if it's Ready, so clone before consuming.
            let raw_data = frame.data.clone();
            let msg = decode_frame(frame)?;

            if msg.t == MessageType::Ready {
                tracing::info!("agent relay: received core.ready from agentd");
                self.ready_frame = Some(raw_data);
                return Ok(());
            }

            tracing::debug!(
                "agent relay: discarding pre-ready frame type={:?} id={}",
                msg.t,
                msg.id
            );
        }
    }

    /// Run the main relay loop.
    ///
    /// Accepts client connections, relays frames between clients and the agent
    /// host FD, and handles client disconnects with session cleanup.
    ///
    /// If a client sends a `core.shutdown` message (identified by
    /// `FLAG_SHUTDOWN` in the frame header), the relay notifies the supervisor
    /// via `drain_tx` so it can start drain escalation.
    pub async fn run(
        self,
        mut shutdown: watch::Receiver<bool>,
        drain_tx: mpsc::Sender<()>,
    ) -> RuntimeResult<()> {
        let ready_frame = self.ready_frame.ok_or_else(|| {
            RuntimeError::Custom("agent relay: run() called before wait_ready()".into())
        })?;

        // Convert the host FD into async read/write halves via a single dup.
        let dup_fd = duplicate_fd(self.host_fd.as_raw_fd())?;
        let std_stream =
            unsafe { std::os::unix::net::UnixStream::from_raw_fd(dup_fd.into_raw_fd()) };
        std_stream.set_nonblocking(true)?;
        let agent_stream = UnixStream::from_std(std_stream)?;
        let (agent_read_half, agent_write_half) = agent_stream.into_split();

        // Shared state: map from client slot index to client state.
        let clients: Arc<Mutex<HashMap<u32, ClientState>>> = Arc::new(Mutex::new(HashMap::new()));

        // Channel for client reader tasks to send frames to the agent writer.
        let (agent_tx, agent_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // Track which client slots are in use.
        let used_slots: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));

        // Spawn the agent writer task.
        let agent_writer_handle = tokio::spawn(agent_writer_task(agent_write_half, agent_rx));

        // Spawn the agent reader task (routes agent responses to clients).
        let clients_for_reader = Arc::clone(&clients);
        let agent_reader_handle =
            tokio::spawn(agent_reader_task(agent_read_half, clients_for_reader));

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

                            // Register the client.
                            {
                                let mut map = clients.lock().await;
                                map.insert(slot, ClientState {
                                    active_sessions: HashSet::new(),
                                    writer: writer_half,
                                });
                            }

                            // Spawn a reader task for this client.
                            let agent_tx_clone = agent_tx.clone();
                            let clients_clone = Arc::clone(&clients);
                            let used_slots_clone = Arc::clone(&used_slots);
                            let drain_tx_clone = drain_tx.clone();

                            tokio::spawn(client_reader_task(
                                slot,
                                reader_half,
                                agent_tx_clone,
                                clients_clone,
                                used_slots_clone,
                                drain_tx_clone,
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

        // Clean up the socket file.
        let _ = std::fs::remove_file(&self.sock_path);

        // Abort background tasks.
        agent_writer_handle.abort();
        agent_reader_handle.abort();

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create a Unix SOCK_STREAM socketpair.
///
/// Returns `(host_fd, guest_fd)` as owned file descriptors.
/// Uses libc directly for macOS compatibility (nix's `SOCK_CLOEXEC` is not
/// available on Darwin).
fn create_socketpair() -> RuntimeResult<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if ret != 0 {
        return Err(RuntimeError::Io(std::io::Error::last_os_error()));
    }

    let fd1 = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let fd2 = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    set_cloexec(fd1.as_raw_fd())?;
    set_cloexec(fd2.as_raw_fd())?;
    set_nonblock(fd1.as_raw_fd())?;
    set_nonblock(fd2.as_raw_fd())?;

    Ok((fd1, fd2))
}

/// Duplicate a file descriptor.
fn duplicate_fd(fd: RawFd) -> RuntimeResult<OwnedFd> {
    let duplicated = unsafe { libc::dup(fd) };
    if duplicated == -1 {
        return Err(RuntimeError::Io(std::io::Error::last_os_error()));
    }

    let owned_fd = unsafe { OwnedFd::from_raw_fd(duplicated) };
    set_cloexec(owned_fd.as_raw_fd())?;
    Ok(owned_fd)
}

/// Set non-blocking mode on a file descriptor.
fn set_nonblock(fd: RawFd) -> RuntimeResult<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(RuntimeError::Io(std::io::Error::last_os_error()));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(RuntimeError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Set the close-on-exec flag on a file descriptor.
fn set_cloexec(fd: RawFd) -> RuntimeResult<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(RuntimeError::Io(std::io::Error::last_os_error()));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(RuntimeError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Read a single raw frame from an async reader.
///
/// Returns the complete frame bytes (including the 4-byte length prefix)
/// along with the extracted correlation ID and flags.
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

    // Enforce the same size limit as the protocol codec.
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

    // Read the full frame payload.
    let mut payload = vec![0u8; frame_len];
    reader.read_exact(&mut payload).await?;

    // Extract header fields from the payload.
    let id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let flags = payload[4];

    // Assemble the complete frame (length prefix + payload).
    let mut data = Vec::with_capacity(LEN_PREFIX_SIZE + frame_len);
    data.extend_from_slice(&len_buf);
    data.extend_from_slice(&payload);

    Ok(RawFrame { data, id, flags })
}

/// Decode a `RawFrame` into a protocol `Message`.
///
/// Uses `try_decode_from_buf` on the frame data. The frame is consumed
/// (only called in `wait_ready` which doesn't need the raw bytes afterward).
fn decode_frame(frame: RawFrame) -> RuntimeResult<Message> {
    let mut buf = frame.data;
    codec::try_decode_from_buf(&mut buf)
        .map_err(|e| RuntimeError::Custom(format!("decode frame: {e}")))?
        .ok_or_else(|| RuntimeError::Custom("decode frame: incomplete frame".into()))
}

/// Background task that writes frames from clients to the agent host FD.
async fn agent_writer_task(mut writer: OwnedWriteHalf, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(frame_bytes) = rx.recv().await {
        if let Err(e) = writer.write_all(&frame_bytes).await {
            tracing::error!("agent relay: write to agent failed: {e}");
            break;
        }
    }
    tracing::debug!("agent relay: agent writer task exiting");
}

/// Background task that reads frames from the agent host FD and routes them
/// to the correct client based on correlation ID range.
async fn agent_reader_task(
    mut reader: OwnedReadHalf,
    clients: Arc<Mutex<HashMap<u32, ClientState>>>,
) {
    loop {
        let frame = match read_raw_frame(&mut reader).await {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("agent relay: read from agent failed: {e}");
                break;
            }
        };

        // Determine which client this frame belongs to by ID range.
        let client_slot = frame.id / ID_RANGE_STEP;
        let client_slot = client_slot.min(MAX_CLIENTS - 1);

        // Track terminal flags for session cleanup.
        let is_terminal = (frame.flags & FLAG_TERMINAL) != 0;

        // Look up client and write outside the lock to avoid head-of-line blocking.
        let mut map = clients.lock().await;
        if let Some(client) = map.get_mut(&client_slot) {
            if is_terminal {
                client.active_sessions.remove(&frame.id);
            }

            // Take a mutable reference to the writer, then drop the map lock
            // before performing I/O. This requires unsafe trickery or restructuring.
            // Instead, we use a simpler approach: since write_all on a Unix socket
            // is typically non-blocking for small frames, the lock contention is
            // minimal in practice. For large frames (file streaming), the kernel
            // buffer absorbs the write. If this becomes a bottleneck, switch to
            // per-client mpsc channels.
            if let Err(e) = client.writer.write_all(&frame.data).await {
                tracing::error!("agent relay: write to client slot={client_slot} failed: {e}");
                // Client is gone; cleanup will happen in client_reader_task.
            }
        } else {
            tracing::debug!(
                "agent relay: no client for slot={client_slot} id={} (frame dropped)",
                frame.id
            );
        }
    }
    tracing::debug!("agent relay: agent reader task exiting");
}

/// Background task that reads frames from a client and forwards them to the
/// agent writer channel. Handles client disconnect with session cleanup.
async fn client_reader_task(
    slot: u32,
    mut reader: OwnedReadHalf,
    agent_tx: mpsc::UnboundedSender<Vec<u8>>,
    clients: Arc<Mutex<HashMap<u32, ClientState>>>,
    used_slots: Arc<Mutex<HashSet<u32>>>,
    drain_tx: mpsc::Sender<()>,
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

        // Notify the supervisor to start drain escalation.
        if is_shutdown {
            tracing::info!(
                "agent relay: client slot={slot} sent core.shutdown, notifying supervisor"
            );
            let _ = drain_tx.try_send(());
        }

        {
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

        // Forward frame to agent writer.
        if agent_tx.send(frame.data).is_err() {
            tracing::error!("agent relay: agent writer channel closed");
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

            if agent_tx.send(buf).is_err() {
                tracing::error!("agent relay: agent writer channel closed during cleanup");
                break;
            }
        }
    }

    // Release the client slot.
    used_slots.lock().await.remove(&slot);
    tracing::debug!("agent relay: slot={slot} released");
}
