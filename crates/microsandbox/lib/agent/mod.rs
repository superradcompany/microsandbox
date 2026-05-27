//! Agent communication with the guest VM.
//!
//! [`AgentClient`] is the Rust-ergonomic transport over the sandbox process's
//! agent relay socket. [`AgentBridge`] is a thinner, FFI-shaped façade around
//! it for use by Node/Python/Go bindings.

mod bridge;
mod client;
mod error;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use bridge::{AgentBridge, BridgeFrame, StreamHandle};
pub use client::{AgentClient, AgentProtocol};
pub use error::{AgentClientError, AgentClientResult};
pub use microsandbox_protocol::codec::RawFrame;
