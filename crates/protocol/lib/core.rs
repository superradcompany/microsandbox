//! Core protocol message payloads.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Payload for `core.ready` messages.
///
/// Sent by the guest agent to signal that it has finished initialization
/// and is ready to receive commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ready {}

