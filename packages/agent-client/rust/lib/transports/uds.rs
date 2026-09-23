//! Unix streams are accepted directly by the active framed client.

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

/// Connected Unix byte transport for `AgentClient::connect_stream`.
pub use tokio::net::UnixStream as UdsTransport;
