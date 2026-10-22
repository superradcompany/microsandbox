//! Sandbox-owned execution admission and I/O policy.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Memory-accounting charge in addition to each output payload.
pub const EXEC_OUTPUT_EVENT_OVERHEAD: u32 = 256;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Effective policy shared by every execution in one sandbox.
///
/// The values are fixed defaults chosen by the runtime; a resumed memory snapshot keeps its
/// captured policy. Connected clients discover the effective policy in Ready; execution
/// requests cannot change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct ExecLimits {
    /// Maximum admitted executions, including exited streams with unread output.
    pub max_executions: u32,
    /// Maximum stdin bytes not yet delivered into the command's pipe.
    pub input_limit: u32,
    /// Maximum unconsumed stdout/stderr allowance, including per-message overhead.
    pub output_limit: u32,
    /// Maximum payload of one stdin message.
    pub stdin_chunk_size: u32,
    /// Maximum payload of one stdout or stderr message.
    pub output_chunk_size: u32,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExecLimits {
    /// Reject policies whose chunks cannot make progress within their allowances.
    pub fn validate(&self) -> Result<(), &'static str> {
        // The protocol frame ceiling is 4 MiB; leave space for its envelope.
        const MAX_CHUNK_SIZE: u32 = 4 * 1024 * 1024 - 1024;
        if self.stdin_chunk_size > MAX_CHUNK_SIZE || self.output_chunk_size > MAX_CHUNK_SIZE {
            return Err("execution chunk sizes must fit within the protocol frame ceiling");
        }
        if self.max_executions == 0 {
            return Err("exec.max_executions must be positive");
        }
        if self.stdin_chunk_size == 0 || self.stdin_chunk_size > self.input_limit {
            return Err("exec.stdin_chunk_size must be positive and fit within exec.input_limit");
        }
        let output_charge = self
            .output_chunk_size
            .checked_add(EXEC_OUTPUT_EVENT_OVERHEAD);
        if self.output_chunk_size == 0 || output_charge.is_none_or(|n| n > self.output_limit) {
            return Err(
                "exec.output_chunk_size plus message overhead must fit within exec.output_limit",
            );
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for ExecLimits {
    fn default() -> Self {
        Self {
            max_executions: 128,
            input_limit: 64 * 1024,
            output_limit: 1024 * 1024,
            stdin_chunk_size: 16 * 1024,
            output_chunk_size: 16 * 1024,
        }
    }
}
