//! Types for sandbox configuration.
//!
//! These types are referenced by [`SandboxConfig`](super::SandboxConfig).

use std::io;
use std::path::PathBuf;

use microsandbox_filesystem::{AccessMode, DynFileSystem, PassthroughConfig, PassthroughFs, ProxyFs};
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
pub enum VolumeMount {
    /// Bind mount a host directory into the guest.
    Bind {
        /// Host path to bind mount.
        host: PathBuf,
        /// Guest mount path.
        guest: String,
        /// Whether the mount is read-only.
        readonly: bool,
    },

    /// Mount a named volume into the guest.
    Named {
        /// Volume name.
        name: String,
        /// Guest mount path.
        guest: String,
        /// Whether the mount is read-only.
        readonly: bool,
    },

    /// Temporary filesystem (memory-backed).
    Tmpfs {
        /// Guest mount path.
        guest: String,
        /// Size limit in MiB.
        size_mib: Option<u32>,
    },

    /// Custom filesystem backend (e.g. a [`ProxyFs`]-wrapped backend with hooks).
    ///
    /// Created when a [`MountBuilder`] has hooks set (`.on_read()`, `.on_write()`,
    /// `.on_access()`), or when using `.backend()` directly.
    ///
    /// Backend mounts cannot be serialized or passed through process boundaries.
    /// They require in-process VM creation to function.
    Backend {
        /// Guest mount path.
        guest: String,
        /// Pre-built filesystem backend.
        backend: Box<dyn DynFileSystem + Send + Sync>,
        /// Whether the mount is read-only.
        readonly: bool,
    },
}

/// Builder for constructing a [`VolumeMount`].
///
/// When hooks are set via `.on_read()`, `.on_write()`, or `.on_access()`,
/// the builder produces a [`VolumeMount::Backend`] with a [`ProxyFs`]-wrapped
/// backend. Otherwise it produces a [`VolumeMount::Bind`], [`VolumeMount::Named`],
/// or [`VolumeMount::Tmpfs`].
pub struct MountBuilder {
    guest: String,
    mount: MountKind,
    readonly: bool,
    size_mib: Option<u32>,
    on_access: Option<Box<dyn Fn(&str, AccessMode) -> Result<(), io::Error> + Send + Sync>>,
    on_read: Option<Box<dyn Fn(&str, &[u8]) -> Vec<u8> + Send + Sync>>,
    on_write: Option<Box<dyn Fn(&str, &[u8]) -> Vec<u8> + Send + Sync>>,
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
            on_access: None,
            on_read: None,
            on_write: None,
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

    /// Set an access control hook.
    ///
    /// Called before `open`, `create`, and `opendir`. Receives the file path
    /// (relative to mount root) and the [`AccessMode`]. Return `Ok(())` to
    /// allow the operation, or `Err(e)` to deny it.
    ///
    /// When any hook is set, the mount produces a [`VolumeMount::Backend`]
    /// with a [`ProxyFs`]-wrapped backend.
    pub fn on_access(
        mut self,
        hook: impl Fn(&str, AccessMode) -> Result<(), io::Error> + Send + Sync + 'static,
    ) -> Self {
        self.on_access = Some(Box::new(hook));
        self
    }

    /// Set a read interception hook.
    ///
    /// Called after data is read from the underlying backend, before returning
    /// to the guest. Receives the file path and raw data, returns (possibly
    /// transformed) data.
    ///
    /// When set, the zero-copy read path is broken — data flows through memory.
    pub fn on_read(
        mut self,
        hook: impl Fn(&str, &[u8]) -> Vec<u8> + Send + Sync + 'static,
    ) -> Self {
        self.on_read = Some(Box::new(hook));
        self
    }

    /// Set a write interception hook.
    ///
    /// Called after receiving data from the guest, before passing to the
    /// underlying backend. Receives the file path and raw data, returns
    /// (possibly transformed) data.
    ///
    /// When set, the zero-copy write path is broken — data flows through memory.
    pub fn on_write(
        mut self,
        hook: impl Fn(&str, &[u8]) -> Vec<u8> + Send + Sync + 'static,
    ) -> Self {
        self.on_write = Some(Box::new(hook));
        self
    }

    /// Build the volume mount.
    pub(crate) fn build(self) -> crate::MicrosandboxResult<VolumeMount> {
        let has_hooks =
            self.on_access.is_some() || self.on_read.is_some() || self.on_write.is_some();

        if has_hooks {
            self.build_backend()
        } else {
            self.build_plain()
        }
    }
}

impl MountBuilder {
    /// Build a plain mount (no hooks).
    fn build_plain(self) -> crate::MicrosandboxResult<VolumeMount> {
        match self.mount {
            MountKind::Bind(host) => Ok(VolumeMount::Bind {
                host,
                guest: self.guest,
                readonly: self.readonly,
            }),
            MountKind::Named(name) => Ok(VolumeMount::Named {
                name,
                guest: self.guest,
                readonly: self.readonly,
            }),
            MountKind::Tmpfs => Ok(VolumeMount::Tmpfs {
                guest: self.guest,
                size_mib: self.size_mib,
            }),
            MountKind::Unset => Err(crate::MicrosandboxError::InvalidConfig(
                "MountBuilder: no mount type set (call .bind(), .named(), or .tmpfs())".into(),
            )),
        }
    }

    /// Build a [`VolumeMount::Backend`] with a [`ProxyFs`]-wrapped backend.
    fn build_backend(self) -> crate::MicrosandboxResult<VolumeMount> {
        let root_dir = match self.mount {
            MountKind::Bind(ref host) => host.clone(),
            MountKind::Named(ref name) => crate::config::config().volumes_dir().join(name),
            MountKind::Tmpfs => {
                return Err(crate::MicrosandboxError::InvalidConfig(
                    "hooks are not supported on tmpfs mounts (tmpfs is handled by the guest kernel)"
                        .into(),
                ));
            }
            MountKind::Unset => {
                return Err(crate::MicrosandboxError::InvalidConfig(
                    "MountBuilder: no mount type set (call .bind() or .named())".into(),
                ));
            }
        };

        // Create the inner PassthroughFs backend.
        let cfg = PassthroughConfig {
            root_dir,
            ..Default::default()
        };
        let inner = PassthroughFs::new(cfg).map_err(|e| {
            crate::MicrosandboxError::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("failed to create passthrough backend: {e}"),
            ))
        })?;

        // Wrap in ProxyFs with hooks.
        let mut proxy_builder = ProxyFs::builder(Box::new(inner));
        if let Some(hook) = self.on_access {
            proxy_builder = proxy_builder.on_access(hook);
        }
        if let Some(hook) = self.on_read {
            proxy_builder = proxy_builder.on_read(hook);
        }
        if let Some(hook) = self.on_write {
            proxy_builder = proxy_builder.on_write(hook);
        }
        let proxy = proxy_builder.build().map_err(crate::MicrosandboxError::Io)?;

        Ok(VolumeMount::Backend {
            guest: self.guest,
            backend: Box::new(proxy),
            readonly: self.readonly,
        })
    }
}

impl VolumeMount {
    /// Get the guest mount path.
    pub fn guest(&self) -> &str {
        match self {
            Self::Bind { guest, .. }
            | Self::Named { guest, .. }
            | Self::Tmpfs { guest, .. }
            | Self::Backend { guest, .. } => guest,
        }
    }

    /// Returns `true` if this is a [`VolumeMount::Backend`] variant.
    pub fn is_backend(&self) -> bool {
        matches!(self, Self::Backend { .. })
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

/// Custom serialization — only serializable variants are written.
/// [`VolumeMount::Backend`] cannot be serialized and will return an error.
impl Serialize for VolumeMount {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        match self {
            Self::Bind {
                host,
                guest,
                readonly,
            } => {
                let mut map = serializer.serialize_map(Some(4))?;
                map.serialize_entry("type", "Bind")?;
                map.serialize_entry("host", host)?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("readonly", readonly)?;
                map.end()
            }
            Self::Named {
                name,
                guest,
                readonly,
            } => {
                let mut map = serializer.serialize_map(Some(4))?;
                map.serialize_entry("type", "Named")?;
                map.serialize_entry("name", name)?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("readonly", readonly)?;
                map.end()
            }
            Self::Tmpfs { guest, size_mib } => {
                let mut map = serializer.serialize_map(Some(3))?;
                map.serialize_entry("type", "Tmpfs")?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("size_mib", size_mib)?;
                map.end()
            }
            Self::Backend { .. } => Err(serde::ser::Error::custom(
                "VolumeMount::Backend cannot be serialized",
            )),
        }
    }
}

/// Custom deserialization — only Bind, Named, Tmpfs are expected.
impl<'de> Deserialize<'de> for VolumeMount {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Helper for tagged deserialization.
        #[derive(Deserialize)]
        #[serde(tag = "type")]
        enum VolumeMountHelper {
            Bind {
                host: PathBuf,
                guest: String,
                #[serde(default)]
                readonly: bool,
            },
            Named {
                name: String,
                guest: String,
                #[serde(default)]
                readonly: bool,
            },
            Tmpfs {
                guest: String,
                #[serde(default)]
                size_mib: Option<u32>,
            },
        }

        let helper = VolumeMountHelper::deserialize(deserializer)?;
        Ok(match helper {
            VolumeMountHelper::Bind {
                host,
                guest,
                readonly,
            } => Self::Bind {
                host,
                guest,
                readonly,
            },
            VolumeMountHelper::Named {
                name,
                guest,
                readonly,
            } => Self::Named {
                name,
                guest,
                readonly,
            },
            VolumeMountHelper::Tmpfs { guest, size_mib } => Self::Tmpfs { guest, size_mib },
        })
    }
}

impl std::fmt::Debug for VolumeMount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind {
                host,
                guest,
                readonly,
            } => f
                .debug_struct("Bind")
                .field("host", host)
                .field("guest", guest)
                .field("readonly", readonly)
                .finish(),
            Self::Named {
                name,
                guest,
                readonly,
            } => f
                .debug_struct("Named")
                .field("name", name)
                .field("guest", guest)
                .field("readonly", readonly)
                .finish(),
            Self::Tmpfs { guest, size_mib } => f
                .debug_struct("Tmpfs")
                .field("guest", guest)
                .field("size_mib", size_mib)
                .finish(),
            Self::Backend {
                guest, readonly, ..
            } => f
                .debug_struct("Backend")
                .field("guest", guest)
                .field("readonly", readonly)
                .field("backend", &"<dyn DynFileSystem>")
                .finish(),
        }
    }
}
