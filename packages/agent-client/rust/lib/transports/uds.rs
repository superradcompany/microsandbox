//! Unix domain socket transport adapter.
//!
//! Enable the `uds` crate feature to use this module. It is intended for local
//! microsandbox relay sockets on platforms that support Tokio Unix streams.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;

use tokio::net::UnixStream;

use crate::AgentClientResult;
use crate::transport::{AgentTransport, TransportPacket, read_packet_from_io, write_packet_to_io};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Agent transport backed by a Unix domain socket.
///
/// This adapter implements the generic [`AgentTransport`] trait. Most SDK code
/// should use [`AgentClient::connect`](crate::AgentClient::connect), which
/// performs the relay handshake and starts request routing.
pub struct UdsTransport {
    stream: UnixStream,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl UdsTransport {
    /// Connect to a Unix domain socket path.
    ///
    /// The returned transport is connected but not handshaken. Pass it to a
    /// client constructor that accepts custom transports when such a constructor
    /// is available, or use [`AgentClient::connect`](crate::AgentClient::connect)
    /// for the built-in path.
    pub async fn connect(path: impl AsRef<Path>) -> AgentClientResult<Self> {
        let stream = UnixStream::connect(path).await?;
        Ok(Self { stream })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl AgentTransport for UdsTransport {
    fn read_packet(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = AgentClientResult<Option<TransportPacket>>> + Send + '_>> {
        Box::pin(read_packet_from_io(&mut self.stream))
    }

    fn write_packet(
        &mut self,
        packet: TransportPacket,
    ) -> Pin<Box<dyn Future<Output = AgentClientResult<()>> + Send + '_>> {
        Box::pin(write_packet_to_io(&mut self.stream, packet))
    }
}
