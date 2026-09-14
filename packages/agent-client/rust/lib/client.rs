//! Agent specialization of the shared framed client.

use crate::AgentProtocol;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Low-level agent connection with native, encoded, raw, stream, and packet APIs.
pub type AgentClient = microsandbox_protocol_client::Client<AgentProtocol>;
