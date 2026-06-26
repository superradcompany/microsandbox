//! Transport-agnostic client for the microsandbox agent protocol.
//!
//! This crate owns the low-level client layer: handshakes, correlation IDs,
//! request/stream routing, message encoding, and transport adapters. High-level
//! SDK crates remain responsible for sandbox lifecycle and name resolution.
//!
//! No transport is enabled by default. Enable `uds` for local microsandbox relay
//! sockets on Unix, `named-pipe` for local relay pipes on Windows, or `stream`
//! to drive the client over any `AsyncRead + AsyncWrite` byte stream (e.g. a
//! caller-owned, pre-authenticated transport adapted to bytes).

#![warn(missing_docs)]

pub mod client;
pub mod error;
pub mod message;
pub mod stream;
pub mod transport;

/// Transport adapters that can be enabled with crate features.
pub mod transports {
    /// Windows named-pipe transport support.
    #[cfg(all(feature = "named-pipe", windows))]
    pub mod named_pipe;

    /// Unix domain socket transport support.
    #[cfg(all(feature = "uds", unix))]
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
