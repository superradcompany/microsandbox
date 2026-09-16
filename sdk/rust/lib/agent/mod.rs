//! Agent communication with the guest VM.
//!
//! [`AgentClient`] is the Rust-ergonomic transport over the sandbox process's
//! agent relay socket. [`AgentBridge`] is a thinner, FFI-shaped façade around
//! it for use by Node/Python/Go bindings.

mod bridge;
mod client;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use bridge::{AgentBridge, BridgeFrame, StreamHandle};
pub use client::AgentClient;
#[cfg(feature = "local")]
pub use client::{connect_sandbox, connect_sandbox_with_timeout};
pub use microsandbox_agent_client::optimized::AgentProtocol;
pub use microsandbox_agent_client::{AgentClientError, AgentClientResult};
pub use microsandbox_protocol::codec::RawFrame;
