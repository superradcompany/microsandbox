//! Bridge for host↔agentd communication over virtio-console.
//!
//! [`AgentBridge`] manages a background reader task that dispatches incoming
//! messages to pending request channels by correlation ID. The `core.ready`
//! message from agentd is dispatched to correlation ID 0.

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use microsandbox_protocol::codec;
use microsandbox_protocol::message::{Message, MessageType};
use tokio::io::AsyncRead;
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;

use crate::MicrosandboxResult;

use super::stream;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Bridge for communicating with agentd in the guest VM.
///
/// Provides request/response messaging over the agent FD pair.
/// A background task reads incoming messages and dispatches them
/// to pending `oneshot` channels by correlation ID.
pub struct AgentBridge {
    writer: Arc<Mutex<stream::FdWriter>>,
    next_id: AtomicU32,
    pending: Arc<Mutex<HashMap<u32, oneshot::Sender<Message>>>>,
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
        let (reader, writer) = stream::from_raw_fd(agent_host_fd)?;
        let pending: Arc<Mutex<HashMap<u32, oneshot::Sender<Message>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let reader_handle = tokio::spawn(reader_loop(reader, Arc::clone(&pending)));

        Ok(Self {
            writer: Arc::new(Mutex::new(writer)),
            next_id: AtomicU32::new(1),
            pending,
            reader_handle,
        })
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
        let mut id = self.next_id.fetch_add(1, Ordering::Relaxed);
        // ID 0 is reserved for core.ready; skip it on wraparound.
        if id == 0 {
            id = self.next_id.fetch_add(1, Ordering::Relaxed);
        }
        msg.id = id;

        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);

        self.send(&msg).await?;

        rx.await.map_err(|_| {
            crate::MicrosandboxError::Runtime("agent bridge reader closed before response".into())
        })
    }

    /// Wait for agentd to report readiness (`core.ready` message).
    ///
    /// The ready message is dispatched to correlation ID 0 by convention.
    pub async fn wait_ready(&self) -> MicrosandboxResult<()> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(0, tx);

        rx.await.map_err(|_| {
            crate::MicrosandboxError::Runtime("agent bridge closed before ready signal".into())
        })?;

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Background task that reads messages from agentd and dispatches them.
async fn reader_loop<R: AsyncRead + Unpin>(
    mut reader: R,
    pending: Arc<Mutex<HashMap<u32, oneshot::Sender<Message>>>>,
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

        if let Some(tx) = pending.lock().await.remove(&dispatch_id) {
            let _ = tx.send(msg);
        } else {
            tracing::trace!("agent bridge: no pending request for id={dispatch_id}");
        }
    }

    // When the reader exits, wake all pending requests so they fail gracefully.
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
