//! Generic stream handle scaffold.
//!
//! The active high-level client API currently returns `mpsc` receivers from
//! [`AgentClient::stream`](crate::AgentClient::stream) and
//! [`AgentClient::stream_raw`](crate::AgentClient::stream_raw). This type is
//! reserved for a future object-oriented stream API over custom transports.

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::error::{AgentClientError, AgentClientResult};
use crate::message::IntoOutboundMessage;
use crate::transport::AgentTransport;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A protocol stream opened with a session-start message.
///
/// The stream owns a correlation ID and a shared transport handle. It is not
/// used by the current [`AgentClient`](crate::AgentClient) routing path.
pub struct AgentStream<T>
where
    T: AgentTransport,
{
    id: u32,
    transport: Arc<Mutex<T>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<T> AgentStream<T>
where
    T: AgentTransport,
{
    /// Create a stream from an assigned correlation ID and shared transport.
    #[allow(dead_code)]
    pub(crate) fn new(id: u32, transport: Arc<Mutex<T>>) -> Self {
        Self { id, transport }
    }

    /// The correlation ID assigned to this stream.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Send a follow-up message on the stream.
    ///
    /// This scaffold is intentionally not wired to a routing implementation yet.
    /// Use [`AgentClient::send`](crate::AgentClient::send) for active streams
    /// opened with [`AgentClient::stream`](crate::AgentClient::stream).
    pub async fn send<M>(&self, message: M) -> AgentClientResult<()>
    where
        M: IntoOutboundMessage,
    {
        let _ = message;
        let _transport = self.transport.lock().await;
        Err(AgentClientError::NotImplemented("stream send"))
    }
}
