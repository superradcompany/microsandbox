//! Agent communication with the guest VM.
//!
//! The [`AgentBridge`] provides request/response messaging with agentd
//! over a virtio-console FD pair using the CBOR-based agent protocol.

mod bridge;
mod stream;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use bridge::AgentBridge;
