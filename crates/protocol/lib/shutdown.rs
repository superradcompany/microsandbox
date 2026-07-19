//! Host-requested shutdown and guest durability acknowledgement payloads.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options attached to a host shutdown request.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShutdownRequest {
    /// Ask a PID-1 agent to acknowledge after filesystem teardown has reached a durable state.
    #[serde(default)]
    pub ready_ack: bool,
}

/// Guest acknowledgement that the host may safely terminate the VM process.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShutdownReady {}
