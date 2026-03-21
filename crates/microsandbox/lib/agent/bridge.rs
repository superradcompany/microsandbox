//! Bridge for host↔agentd communication over virtio-console.
//!
//! [`AgentBridge`] manages a background reader task that dispatches incoming
//! messages to pending channels by correlation ID. The `core.ready` message
//! from agentd is dispatched to correlation ID 0.
//!
//! All handlers use `mpsc::UnboundedSender<Message>`. Single-response callers
//! (`request()`, `wait_ready()`) simply read one message and drop the receiver.
//! Multi-message callers (`subscribe()`) keep reading until the session ends.

use std::{
    collections::HashMap,
    os::unix::io::RawFd,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use microsandbox_protocol::{
    codec,
    core::Ready,
    message::{Message, MessageType},
};
use tokio::{
    io::AsyncRead,
    sync::{Mutex, mpsc},
    task::JoinHandle,
};

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
    ready: Arc<Mutex<Option<Message>>>,
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
        let ready = Arc::new(Mutex::new(None));

        let reader_handle = tokio::spawn(reader_loop(
            reader,
            Arc::clone(&pending),
            Arc::clone(&ready),
        ));

        Ok(Self {
            writer: Arc::new(Mutex::new(writer)),
            next_id: AtomicU32::new(1),
            pending,
            ready,
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
    /// Returns the [`Ready`] payload containing boot timing data.
    pub async fn wait_ready(&self) -> MicrosandboxResult<Ready> {
        if let Some(msg) = self.ready.lock().await.take() {
            return decode_ready(msg);
        }

        let (tx, mut rx) = mpsc::unbounded_channel();
        self.pending.lock().await.insert(0, tx);

        if let Some(msg) = self.ready.lock().await.take() {
            self.pending.lock().await.remove(&0);
            return decode_ready(msg);
        }

        let msg = rx.recv().await.ok_or_else(|| {
            crate::MicrosandboxError::Runtime("agent bridge closed before ready signal".into())
        })?;

        decode_ready(msg)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Background task that reads messages from agentd and dispatches them.
async fn reader_loop<R: AsyncRead + Unpin>(
    mut reader: R,
    pending: Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Message>>>>,
    ready: Arc<Mutex<Option<Message>>>,
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

        let is_terminal = matches!(msg.t, MessageType::ExecExited | MessageType::FsResponse);

        let mut map = pending.lock().await;
        if let Some(tx) = map.get(&dispatch_id) {
            if tx.send(msg).is_err() {
                // Receiver dropped — clean up.
                map.remove(&dispatch_id);
            } else if is_terminal {
                // Terminal message sent successfully — remove subscription.
                map.remove(&dispatch_id);
            }
        } else if dispatch_id == 0 {
            drop(map);
            let mut ready_slot = ready.lock().await;
            if ready_slot.is_none() {
                *ready_slot = Some(msg);
            } else {
                tracing::trace!("agent bridge: duplicate ready message buffered");
            }
        } else {
            tracing::trace!("agent bridge: no pending handler for id={dispatch_id}");
        }
    }

    // When the reader exits, drop all senders so receivers get None.
    let mut map = pending.lock().await;
    map.clear();
}

fn decode_ready(msg: Message) -> MicrosandboxResult<Ready> {
    let ready: Ready = msg.payload().map_err(|e| {
        crate::MicrosandboxError::Runtime(format!("failed to decode ready payload: {e}"))
    })?;

    Ok(ready)
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for AgentBridge {
    fn drop(&mut self) {
        self.reader_handle.abort();
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::os::fd::IntoRawFd;

    use tokio::net::UnixStream;

    use super::*;

    #[tokio::test]
    async fn test_wait_ready_accepts_early_ready_message() {
        let (bridge_side, writer_side) = std::os::unix::net::UnixStream::pair().unwrap();
        bridge_side.set_nonblocking(true).unwrap();
        writer_side.set_nonblocking(true).unwrap();

        let bridge = AgentBridge::new(bridge_side.into_raw_fd()).unwrap();
        let mut writer = UnixStream::from_std(writer_side).unwrap();

        let ready_msg = Message::with_payload(
            MessageType::Ready,
            0,
            &Ready {
                boot_time_ns: 1,
                init_time_ns: 2,
                ready_time_ns: 3,
            },
        )
        .unwrap();

        codec::write_message(&mut writer, &ready_msg).await.unwrap();
        drop(writer);
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let ready = bridge.wait_ready().await.unwrap();
        assert_eq!(ready.boot_time_ns, 1);
        assert_eq!(ready.init_time_ns, 2);
        assert_eq!(ready.ready_time_ns, 3);
    }
}
