//! Stub types for sandbox configuration.
//!
//! These types are referenced by [`SandboxConfig`](super::SandboxConfig) but
//! will be fully implemented in later phases. They carry enough structure
//! for Phase 4 to compile and for configs to round-trip through serde.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Root filesystem source for a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RootfsSource {
    /// Use a host directory directly as the root filesystem.
    Bind(PathBuf),

    /// Use an OCI image reference (e.g. `python:3.12`).
    Oci(String),
}

/// A volume mount mapping a host source to a guest path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMount {
    /// Source identifier (host path or named volume).
    pub source: String,

    /// Mount target path inside the guest.
    pub target: String,

    /// Whether the mount is read-only.
    #[serde(default)]
    pub read_only: bool,
}

/// A rootfs patch applied as an overlay layer before VM start.
///
/// Fully implemented in Phase 8 (Image Management).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Patch {}

/// Network configuration for a sandbox.
///
/// Fully implemented in Phase 6 (Networking).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkConfig {}

/// Secrets configuration for a sandbox.
///
/// Fully implemented in Phase 7 (Secrets Management).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretsConfig {}

/// SSH configuration for a sandbox.
///
/// Fully implemented in Phase 9 (SSH).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshConfig {}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for RootfsSource {
    fn default() -> Self {
        Self::Oci(String::new())
    }
}

impl From<&str> for RootfsSource {
    fn from(s: &str) -> Self {
        Self::Oci(s.to_string())
    }
}

impl From<String> for RootfsSource {
    fn from(s: String) -> Self {
        Self::Oci(s)
    }
}

impl From<PathBuf> for RootfsSource {
    fn from(p: PathBuf) -> Self {
        Self::Bind(p)
    }
}
