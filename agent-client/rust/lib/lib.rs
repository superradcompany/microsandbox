//! Transport-agnostic client for the microsandbox agent protocol.
//!
//! This crate owns the low-level client layer: handshakes, correlation IDs,
//! request/stream routing, message encoding, and transport adapters. High-level
//! SDK crates remain responsible for sandbox lifecycle and name resolution.
//!
//! No transport is enabled by default. Enable `uds` for local microsandbox relay
//! sockets or `websocket` for relay endpoints exposed over WebSocket.

#![warn(missing_docs)]

pub mod client;
pub mod error;
pub mod message;
pub mod stream;
pub mod transport;

/// Transport adapters that can be enabled with crate features.
pub mod transports {
    /// Unix domain socket transport support.
    #[cfg(feature = "uds")]
    pub mod uds;
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use client::{AgentClient, AgentProtocol};
pub use error::{AgentClientError, AgentClientResult};
pub use message::{EncodedMessage, IntoOutboundMessage, OutboundMessage, TypedMessage};
pub use stream::AgentStream;
pub use transport::{AgentTransport, TransportPacket};
