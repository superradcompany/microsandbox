//! Global execution-output buffering configuration.

use microsandbox_protocol::exec::MIN_EXEC_OUTPUT_WINDOW;
use microsandbox_types::ConfigPatch;
use serde::{Deserialize, Serialize};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Host-side defaults for command output, shared by the CLI and SDKs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ConfigPatch)]
#[serde(default)]
#[config_patch(serde)]
pub struct ExecConfig {
    /// Maximum unread event bytes per command, including queue overhead.
    ///
    /// Defaults to `None` (unlimited). A limit must be at least 64 KiB. Stdout and
    /// stderr share it; output retained by callers and transport buffers is excluded.
    pub buffer_bytes: Option<u32>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExecConfig {
    pub(crate) fn validate(&self) -> MicrosandboxResult<()> {
        if self
            .buffer_bytes
            .is_some_and(|bytes| bytes < MIN_EXEC_OUTPUT_WINDOW)
        {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "exec.buffer_bytes must be at least {MIN_EXEC_OUTPUT_WINDOW} bytes"
            )));
        }
        Ok(())
    }
}
