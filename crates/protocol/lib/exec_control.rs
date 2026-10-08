//! Optional host-only execution control, independent of the agent input byte stream.
//!
//! The relay adds this capability to its client-facing Ready payload only. It is never sent to
//! agentd, persisted in snapshots, or part of the guest message inventory.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::core::Ready;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// First host-only execution control contract.
pub const EXEC_CONTROL_VERSION: u8 = 1;
/// Framed host-control operation; requires the advertised capability and generation two.
pub const EXEC_CONTROL_REQUEST: &str = "control.exec.signal";
/// Physical-delivery result, distinct from an execution's terminal result.
pub const EXEC_CONTROL_RESPONSE: &str = "control.exec.signal.result";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Ephemeral authority for the exact agent connection that received this advertisement.
#[derive(Clone, Serialize, Deserialize)]
pub struct ExecControlReady {
    /// Supported host-only contract.
    pub version: u8,
    /// Existing local host-control endpoint, resolved by the runtime.
    pub endpoint: String,
    /// Random connection capability; invalidated on disconnect and never persisted.
    pub connection: [u8; 16],
}

/// Client-facing Ready extension. Keeping this separate preserves existing Ready struct literals.
#[derive(Serialize)]
pub struct ExecControlAdvertisement<'a> {
    /// Original guest capability payload, unchanged.
    #[serde(flatten)]
    pub ready: &'a Ready,
    /// Host-owned route advertised to this one agent connection.
    pub exec_control: &'a ExecControlReady,
}

/// Partial Ready reader that ignores unrelated guest capabilities.
#[derive(Default, Deserialize)]
pub struct ExecControlDiscovery {
    /// Absence means that the existing agent path remains authoritative.
    #[serde(default)]
    pub exec_control: Option<ExecControlReady>,
}

/// One signal bound to a still-active agent connection and execution correlation.
#[derive(Serialize, Deserialize)]
pub struct ExecControlRequest {
    /// Contract selected from the advertised capability.
    pub version: u8,
    /// Connection authority copied from the original Ready extension.
    pub connection: [u8; 16],
    /// Correlation allocated on that connection; never a raw guest PID.
    pub id: u32,
    /// Unix signal number.
    pub signal: i32,
}

/// Acknowledges physical guest transport admission, not process exit or signal handling.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecControlResponse {
    /// The complete signal frame reached the guest console transport.
    pub delivered: bool,
    /// Stable failure code, including uncertainty after admission.
    pub error_code: Option<String>,
    /// Non-sensitive delivery diagnostic.
    pub error: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExecControlResponse {
    /// A complete physical write was observed.
    pub fn delivered() -> Self {
        Self {
            delivered: true,
            error_code: None,
            error: None,
        }
    }

    /// Reject or report delivery uncertainty without inventing an execution result.
    pub fn error(code: &str, message: impl Into<String>) -> Self {
        Self {
            delivered: false,
            error_code: Some(code.into()),
            error: Some(message.into()),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for ExecControlReady {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ready metadata is commonly logged. Never expose the connection authority there.
        formatter
            .debug_struct("ExecControlReady")
            .field("version", &self.version)
            .field("endpoint", &self.endpoint)
            .field("connection", &"[redacted]")
            .finish()
    }
}
