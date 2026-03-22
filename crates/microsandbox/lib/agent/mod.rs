//! Agent communication with the guest VM.
//!
//! The [`AgentClient`] provides request/response messaging with agentd
//! through the supervisor's agent relay socket.

mod client;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use client::AgentClient;
