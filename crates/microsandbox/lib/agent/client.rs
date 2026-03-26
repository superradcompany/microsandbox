//! SDK-side client for connecting to the sandbox agent relay.
//!
//! [`AgentClient`] communicates over a Unix domain socket to the sandbox's
//! relay. During connection, the relay assigns a non-overlapping correlation ID
//! range and sends the cached `core.ready` payload so the client can begin
//! issuing commands immediately.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};

use microsandbox_protocol::{
    codec,
    core::Ready,
    message::{FLAG_TERMINAL, Message},
};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Client for communicating with agentd through the agent relay.
///
/// Connects over a Unix domain socket to the supervisor's agent relay.
/// Correlation IDs are allocated from the range assigned during the relay
/// handshake.
pub struct AgentClient {
    /// Writer half of the Unix socket connection.
    writer: Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    /// Next correlation ID to allocate (starts at `id_offset + 1`).
    next_id: AtomicU32,
    /// Upper bound (exclusive) of the assigned ID range.
    id_max: u32,
    /// Pending response channels keyed by correlation ID.
    pending: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Message>>>>,
    /// Background reader task handle.
    reader_handle: JoinHandle<()>,
    /// Cached `core.ready` payload from the relay handshake.
    ready: Ready,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AgentClient {
    /// Connect to the sandbox's agent relay socket.
    ///
    /// Performs the relay handshake to receive the assigned ID offset and
    /// the cached `core.ready` payload, then spawns a background reader task.
    pub async fn connect(sock_path: &Path) -> MicrosandboxResult<Self> {
        let stream = UnixStream::connect(sock_path).await.map_err(|e| {
            crate::MicrosandboxError::Runtime(format!(
                "failed to connect to agent relay at {}: {e}",
                sock_path.display()
            ))
        })?;

        let (mut reader, writer) = stream.into_split();

        // Read the handshake: [id_offset: u32 BE][ready_frame_bytes...]
        let mut offset_buf = [0u8; 4];
        reader.read_exact(&mut offset_buf).await.map_err(|e| {
            crate::MicrosandboxError::Runtime(format!("handshake read id_offset: {e}"))
        })?;
        let id_offset = u32::from_be_bytes(offset_buf);

        // Read the ready frame using the protocol codec directly.
        let ready_msg = codec::read_message(&mut reader).await.map_err(|e| {
            crate::MicrosandboxError::Runtime(format!("handshake read ready frame: {e}"))
        })?;

        let ready: Ready = ready_msg
            .payload()
            .map_err(|e| crate::MicrosandboxError::Runtime(format!("decode ready payload: {e}")))?;

        tracing::info!(
            "agent client: connected to relay, id_offset={id_offset}, boot_time={}ns",
            ready.boot_time_ns
        );

        let pending: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Message>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let reader_handle = tokio::spawn(reader_loop(reader, Arc::clone(&pending)));

        let writer = Arc::new(Mutex::new(writer));

        // Compute the upper bound of the assigned ID range.
        // ID_RANGE_STEP = u32::MAX / 16 ≈ 268M IDs per client.
        let id_range_step: u32 = u32::MAX / 16;
        let id_max = id_offset.saturating_add(id_range_step);

        Ok(Self {
            writer,
            next_id: AtomicU32::new(id_offset + 1),
            id_max,
            pending,
            reader_handle,
            ready,
        })
    }

    /// Allocate a new unique correlation ID from the assigned range.
    ///
    /// Wraps around within the assigned range if the counter overflows.
    pub fn next_id(&self) -> u32 {
        loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 && id < self.id_max {
                return id;
            }
            // Wrapped past the range or hit 0 (reserved) — reset to range start.
            let start = self.id_max.saturating_sub(u32::MAX / 16) + 1;
            self.next_id.store(start, Ordering::Relaxed);
        }
    }

    /// Send a message to agentd through the relay without waiting for a response.
    pub async fn send(&self, msg: &Message) -> MicrosandboxResult<()> {
        let mut buf = Vec::new();
        codec::encode_to_buf(msg, &mut buf)
            .map_err(|e| crate::MicrosandboxError::Runtime(format!("encode message: {e}")))?;

        let mut writer = self.writer.lock().await;
        tokio::io::AsyncWriteExt::write_all(&mut *writer, &buf)
            .await
            .map_err(|e| crate::MicrosandboxError::Runtime(format!("write to relay: {e}")))?;

        Ok(())
    }

    /// Send a request and wait for the correlated response.
    ///
    /// Assigns a unique correlation ID to the message before sending.
    pub async fn request(&self, mut msg: Message) -> MicrosandboxResult<Message> {
        let id = self.next_id();
        msg.id = id;

        let (tx, mut rx) = mpsc::unbounded_channel();
        self.pending.lock().await.insert(id, tx);

        if let Err(e) = self.send(&msg).await {
            self.pending.lock().await.remove(&id);
            return Err(e);
        }

        rx.recv().await.ok_or_else(|| {
            crate::MicrosandboxError::Runtime("agent client reader closed before response".into())
        })
    }

    /// Register a channel for the given correlation ID.
    ///
    /// Returns a receiver that will receive all messages dispatched to this ID.
    /// The subscription is automatically removed when a terminal message is
    /// received or when the receiver is dropped.
    ///
    /// Call this **before** sending the request to ensure no messages are lost.
    pub async fn subscribe(&self, id: u32) -> mpsc::UnboundedReceiver<Message> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.pending.lock().await.insert(id, tx);
        rx
    }

    /// Return the cached `core.ready` payload from the relay handshake.
    pub fn ready(&self) -> &Ready {
        &self.ready
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Background task that reads messages from the relay and dispatches them
/// to pending channels by correlation ID.
async fn reader_loop(
    mut reader: tokio::net::unix::OwnedReadHalf,
    pending: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Message>>>>,
) {
    loop {
        let msg = match codec::read_message(&mut reader).await {
            Ok(msg) => msg,
            Err(e) => {
                tracing::debug!("agent client: reader EOF or error: {e}");
                break;
            }
        };

        let dispatch_id = msg.id;
        let is_terminal = (msg.flags & FLAG_TERMINAL) != 0;

        let mut map = pending.lock().await;
        if let Some(tx) = map.get(&dispatch_id) {
            if tx.send(msg).is_err() {
                // Receiver dropped — clean up.
                map.remove(&dispatch_id);
            } else if is_terminal {
                // Terminal message sent successfully — remove subscription.
                map.remove(&dispatch_id);
            }
        } else {
            tracing::trace!("agent client: no pending handler for id={dispatch_id}");
        }
    }

    // When the reader exits, drop all senders so receivers get None.
    let mut map = pending.lock().await;
    map.clear();
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for AgentClient {
    fn drop(&mut self) {
        self.reader_handle.abort();
    }
}
