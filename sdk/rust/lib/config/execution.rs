//! Global execution defaults resolved into sandbox-owned limits at creation.

use microsandbox_types::{ConfigPatch, ExecLimits, ExecLimitsPatch};
use serde::{Deserialize, Serialize};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Execution admission and I/O defaults, shared by the CLI and SDKs.
#[derive(Debug, Clone, Serialize, Deserialize, ConfigPatch)]
#[serde(default)]
#[config_patch(serde)]
pub struct ExecConfig {
    /// Maximum executions, including exited streams with retained output. Defaults to 128.
    pub max_executions: u32,
    /// Maximum outstanding stdin payload per execution. Defaults to 64 KiB.
    pub input_limit: u32,
    /// Combined unread stdout/stderr allowance including metadata. Defaults to 1 MiB.
    pub output_limit: u32,
    /// Maximum stdin payload per message. Defaults to 16 KiB.
    pub stdin_chunk_size: u32,
    /// Maximum stdout/stderr payload per message. Defaults to 16 KiB.
    pub output_chunk_size: u32,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExecConfig {
    pub(crate) fn validate(&self) -> MicrosandboxResult<()> {
        self.limits()
            .validate()
            .map_err(|error| MicrosandboxError::InvalidConfig(error.into()))
    }

    /// Resolve the concrete values advertised to every client of the sandbox.
    pub fn limits(&self) -> ExecLimits {
        ExecLimits {
            max_executions: self.max_executions,
            input_limit: self.input_limit,
            output_limit: self.output_limit,
            stdin_chunk_size: self.stdin_chunk_size,
            output_chunk_size: self.output_chunk_size,
        }
    }
}

impl ExecConfigPatch {
    /// Reject explicit settings the captured guest cannot honor.
    pub(crate) fn validate_captured(&self, captured: Option<ExecLimits>) -> MicrosandboxResult<()> {
        if self.is_satisfied_by(captured) {
            return Ok(());
        }
        Err(MicrosandboxError::InvalidConfig(if captured.is_none() {
            "this memory snapshot has no execution limits and cannot enforce explicit execution settings; remove the settings or use a disk-only restore"
        } else {
            "explicit execution settings conflict with the memory snapshot's captured execution limits; remove the conflicting settings or use a disk-only restore"
        }.into()))
    }

    /// Whether a captured policy can honor every explicitly supplied field.
    pub(crate) fn is_satisfied_by(&self, captured: Option<ExecLimits>) -> bool {
        self.is_empty()
            || captured.is_some_and(|limits| ExecLimitsPatch::from(self).resolve(limits) == limits)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for ExecConfig {
    fn default() -> Self {
        ExecLimits::default().into()
    }
}

impl From<ExecLimits> for ExecConfig {
    fn from(limits: ExecLimits) -> Self {
        Self {
            max_executions: limits.max_executions,
            input_limit: limits.input_limit,
            output_limit: limits.output_limit,
            stdin_chunk_size: limits.stdin_chunk_size,
            output_chunk_size: limits.output_chunk_size,
        }
    }
}

impl From<&ExecConfigPatch> for ExecLimitsPatch {
    fn from(patch: &ExecConfigPatch) -> Self {
        Self {
            max_executions: patch.max_executions,
            input_limit: patch.input_limit,
            output_limit: patch.output_limit,
            stdin_chunk_size: patch.stdin_chunk_size,
            output_chunk_size: patch.output_chunk_size,
        }
    }
}
