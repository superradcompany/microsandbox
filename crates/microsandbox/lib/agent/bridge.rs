//! Bridge for host↔agentd communication over virtio-console.
//!
//! [`AgentBridge`] manages a background reader task that dispatches incoming
//! messages to pending channels by correlation ID. The `core.ready` message
//! from agentd is dispatched to correlation ID 0.
//!
//! All handlers use `mpsc::UnboundedSender<Message>`. Single-response callers
//! (`request()`, `wait_ready()`) simply read one message and drop the receiver.
//! Multi-message callers (`subscribe()`) keep reading until the session ends.

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use microsandbox_protocol::codec;
use microsandbox_protocol::message::{Message, MessageType};
use tokio::io::AsyncRead;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::MicrosandboxResult;

use super::stream;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Bridge for communicating with agentd in the guest VM.
///
/// Provides request/response and streaming messaging over the agent FD pair.
/// A background task reads incoming messages and dispatches them to pending
/// channels by correlation ID.
pub struct AgentBridge {
    writer: Arc<Mutex<stream::FdWriter>>,
    next_id: AtomicU32,
    pending: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Message>>>>,
    reader_handle: JoinHandle<()>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AgentBridge {
    /// Create a new agent bridge from the host-side agent file descriptor.
    ///
    /// Spawns a background reader task that dispatches incoming messages.
    pub fn new(agent_host_fd: RawFd) -> MicrosandboxResult<Self> {
        // Safety: agent_host_fd is a valid fd from spawn_supervisor.
        let (reader, writer) = unsafe { stream::from_raw_fd(agent_host_fd) }?;
        let pending: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Message>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let reader_handle = tokio::spawn(reader_loop(reader, Arc::clone(&pending)));

        Ok(Self {
            writer: Arc::new(Mutex::new(writer)),
            next_id: AtomicU32::new(1),
            pending,
            reader_handle,
        })
    }

    /// Allocate a new unique correlation ID.
    ///
    /// ID 0 is reserved for `core.ready`; it is skipped on wraparound.
    pub fn next_id(&self) -> u32 {
        let mut id = self.next_id.fetch_add(1, Ordering::Relaxed);
        if id == 0 {
            id = self.next_id.fetch_add(1, Ordering::Relaxed);
        }
        id
    }

    /// Send a message to agentd without waiting for a response.
    pub async fn send(&self, msg: &Message) -> MicrosandboxResult<()> {
        let mut writer = self.writer.lock().await;
        codec::write_message(&mut *writer, msg).await?;
        Ok(())
    }

    /// Send a request to agentd and wait for the correlated response.
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
            crate::MicrosandboxError::Runtime("agent bridge reader closed before response".into())
        })
    }

    /// Register a channel for the given correlation ID.
    ///
    /// Returns a receiver that will receive all messages dispatched to this ID.
    /// The subscription is automatically removed when a terminal message
    /// (`ExecExited`) is received or when the receiver is dropped.
    ///
    /// Call this **before** sending the request to ensure no messages are lost.
    pub async fn subscribe(&self, id: u32) -> mpsc::UnboundedReceiver<Message> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.pending.lock().await.insert(id, tx);
        rx
    }

    /// Wait for agentd to report readiness (`core.ready` message).
    ///
    /// The ready message is dispatched to correlation ID 0 by convention.
    pub async fn wait_ready(&self) -> MicrosandboxResult<()> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        self.pending.lock().await.insert(0, tx);

        rx.recv().await.ok_or_else(|| {
            crate::MicrosandboxError::Runtime("agent bridge closed before ready signal".into())
        })?;

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Background task that reads messages from agentd and dispatches them.
async fn reader_loop<R: AsyncRead + Unpin>(
    mut reader: R,
    pending: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Message>>>>,
) {
    loop {
        let msg = match codec::read_message(&mut reader).await {
            Ok(msg) => msg,
            Err(microsandbox_protocol::ProtocolError::UnexpectedEof) => {
                tracing::debug!("agent bridge: reader EOF");
                break;
            }
            Err(e) => {
                tracing::error!("agent bridge: read error: {e}");
                break;
            }
        };

        // Route `core.ready` to correlation ID 0.
        let dispatch_id = if msg.t == MessageType::Ready {
            0
        } else {
            msg.id
        };

        let is_terminal = msg.t == MessageType::ExecExited;

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
            tracing::trace!("agent bridge: no pending handler for id={dispatch_id}");
        }
    }

    // When the reader exits, drop all senders so receivers get None.
    let mut map = pending.lock().await;
    map.clear();
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for AgentBridge {
    fn drop(&mut self) {
        self.reader_handle.abort();
    }
}
