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
#![doc = include_str!("../README.md")]

pub mod client;
pub mod error;
/// Internal Unix-local shared-memory transport used by the UDS adapter and runtime relay.
///
/// The SDK connects through [`OptimizedAgentClient`] for automatic arena negotiation.
#[cfg(all(feature = "uds", unix))]
#[doc(hidden)]
pub mod local_shm;
pub mod message;
#[doc(hidden)]
pub mod optimized;
pub mod protocol;
pub mod stream;
pub mod transport;

/// Transport adapters that can be enabled with crate features.
pub mod transports;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use client::AgentClient;
pub use error::{AgentClientError, AgentClientResult};
pub use message::{EncodedMessage, IntoOutboundMessage, OutboundMessage, TypedMessage};
pub use microsandbox_protocol_client::{
    Client, ClientError, ClientResult, ConnectOptions, Connector, Delivery, ErrorKind, Request,
    RequestOptions,
};
#[doc(hidden)]
pub use optimized::{AgentClient as OptimizedAgentClient, AgentFrame};
pub use protocol::{AgentProtocol, AgentReady, AgentWireFormat};
pub use stream::{AgentStream, RawAgentStream};
pub use transport::{AgentTransport, TransportPacket};
