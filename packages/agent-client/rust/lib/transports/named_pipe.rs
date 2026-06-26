//! Windows named-pipe transport adapter.
//!
//! Enable the `named-pipe` crate feature to use this module. It is intended for
//! local microsandbox relay pipes on Windows hosts.

use std::ffi::OsStr;
use std::future::Future;
use std::pin::Pin;

use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

use crate::AgentClientResult;
use crate::transport::{AgentTransport, TransportPacket, read_packet_from_io, write_packet_to_io};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Agent transport backed by a Windows named pipe.
///
/// This adapter implements the generic [`AgentTransport`] trait. Most SDK code
/// should use [`AgentClient::connect`](crate::AgentClient::connect), which
/// performs the relay handshake and starts request routing.
pub struct NamedPipeTransport {
    stream: NamedPipeClient,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl NamedPipeTransport {
    /// Connect to a Windows named-pipe path.
    ///
    /// The returned transport is connected but not handshaken. Pass it to a
    /// client constructor that accepts custom transports when such a constructor
    /// is available, or use [`AgentClient::connect`](crate::AgentClient::connect)
    /// for the built-in path.
    pub async fn connect(path: impl AsRef<OsStr>) -> AgentClientResult<Self> {
        let stream = ClientOptions::new().open(path)?;
        Ok(Self { stream })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl AgentTransport for NamedPipeTransport {
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
