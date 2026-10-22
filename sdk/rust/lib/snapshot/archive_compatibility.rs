//! Explicit archive recipient compatibility; this never rewrites checkpoint identity.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::MicrosandboxError;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Archive metadata dialect and required-capability target for a fresh export.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchiveCompatibility {
    /// Canonical extension names understood by the current reader.
    #[default]
    #[serde(rename = "current")]
    Current,
    /// Historical archive extension names, with refusal of unsupported required behavior.
    /// This does not convert CPU/device state or promise cross-architecture resume.
    #[serde(rename = "0.7.8")]
    V0_7_8,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl FromStr for ArchiveCompatibility {
    type Err = MicrosandboxError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "current" => Ok(Self::Current),
            "0.7.8" => Ok(Self::V0_7_8),
            _ => Err(MicrosandboxError::InvalidConfig(format!(
                "unsupported archive compatibility target '{value}'; use current or 0.7.8"
            ))),
        }
    }
}
