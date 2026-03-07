//! Types for sandbox configuration.
//!
//! These types are referenced by [`SandboxConfig`](super::SandboxConfig).

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

/// A volume mount specification for a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum VolumeMount {
    /// Bind mount a host directory into the guest.
    Bind {
        /// Host path to bind mount.
        host: PathBuf,
        /// Guest mount path.
        guest: String,
        /// Whether the mount is read-only.
        #[serde(default)]
        readonly: bool,
    },

    /// Mount a named volume into the guest.
    Named {
        /// Volume name.
        name: String,
        /// Guest mount path.
        guest: String,
        /// Whether the mount is read-only.
        #[serde(default)]
        readonly: bool,
    },

    /// Temporary filesystem (memory-backed).
    Tmpfs {
        /// Guest mount path.
        guest: String,
        /// Size limit in MiB.
        #[serde(default)]
        size_mib: Option<u32>,
    },
}

/// Builder for constructing a [`VolumeMount`].
pub struct MountBuilder {
    guest: String,
    mount: MountKind,
    readonly: bool,
    size_mib: Option<u32>,
}

/// Internal kind for the mount builder.
enum MountKind {
    Bind(PathBuf),
    Named(String),
    Tmpfs,
    Unset,
}

/// A rootfs patch applied as an overlay layer before VM start.
///
/// Fully implemented in Phase 13 (Patches).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Patch {}

/// Network configuration for a sandbox.
///
/// Fully implemented in Phase 9 (Network).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkConfig {}

/// Secrets configuration for a sandbox.
///
/// Fully implemented in Phase 11 (Secrets).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretsConfig {}

/// SSH configuration for a sandbox.
///
/// Fully implemented in Phase 14 (Polish).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshConfig {}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MountBuilder {
    /// Create a new mount builder for the given guest path.
    pub fn new(guest: impl Into<String>) -> Self {
        Self {
            guest: guest.into(),
            mount: MountKind::Unset,
            readonly: false,
            size_mib: None,
        }
    }

    /// Bind mount from a host path.
    pub fn bind(mut self, host: impl Into<PathBuf>) -> Self {
        self.mount = MountKind::Bind(host.into());
        self
    }

    /// Use a named volume.
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.mount = MountKind::Named(name.into());
        self
    }

    /// Use tmpfs (memory-backed).
    pub fn tmpfs(mut self) -> Self {
        self.mount = MountKind::Tmpfs;
        self
    }

    /// Make the mount read-only.
    pub fn readonly(mut self) -> Self {
        self.readonly = true;
        self
    }

    /// Set size limit in MiB (for tmpfs).
    pub fn size_mib(mut self, size: u32) -> Self {
        self.size_mib = Some(size);
        self
    }

    /// Build the volume mount.
    ///
    /// Panics if no mount type was set (bind, named, or tmpfs).
    pub fn build(self) -> VolumeMount {
        match self.mount {
            MountKind::Bind(host) => VolumeMount::Bind {
                host,
                guest: self.guest,
                readonly: self.readonly,
            },
            MountKind::Named(name) => VolumeMount::Named {
                name,
                guest: self.guest,
                readonly: self.readonly,
            },
            MountKind::Tmpfs => VolumeMount::Tmpfs {
                guest: self.guest,
                size_mib: self.size_mib,
            },
            MountKind::Unset => panic!("MountBuilder: no mount type set (call .bind(), .named(), or .tmpfs())"),
        }
    }
}

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
