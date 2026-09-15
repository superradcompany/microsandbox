//! Builder API for constructing a PassthroughFs instance.
//!
//! ```ignore
//! use microsandbox_filesystem::{HostPermissions, PassthroughFs, StatVirtualization};
//!
//! PassthroughFs::builder()
//!     .root_dir("./rootfs")
//!     .stat_virtualization(StatVirtualization::Strict)
//!     .host_permissions(HostPermissions::Private)
//!     .build()?
//! ```

use std::{io, path::PathBuf, time::Duration};

use super::{
    BindIdentityMapHandle, CachePolicy, HostPermissions, PassthroughConfig, PassthroughFs,
    StatVirtualization,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for constructing a [`PassthroughFs`] instance.
pub struct PassthroughFsBuilder {
    root_dir: Option<PathBuf>,
    no_symlink_root: bool,
    stat_virtualization: StatVirtualization,
    host_permissions: HostPermissions,
    readonly: bool,
    entry_timeout: Duration,
    attr_timeout: Duration,
    cache_policy: CachePolicy,
    writeback: bool,
    inject_init: bool,
    bind_identity_map: Option<BindIdentityMapHandle>,
    quota_bytes: Option<u64>,
    deny: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFsBuilder {
    /// Create a new builder with default settings.
    pub(crate) fn new() -> Self {
        Self {
            root_dir: None,
            no_symlink_root: false,
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
            readonly: false,
            entry_timeout: Duration::from_secs(5),
            attr_timeout: Duration::from_secs(5),
            cache_policy: CachePolicy::Auto,
            writeback: false,
            inject_init: true,
            bind_identity_map: None,
            quota_bytes: None,
            deny: Vec::new(),
        }
    }

    /// Set the host directory to expose.
    pub fn root_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.root_dir = Some(path.into());
        self
    }

    /// Resolve `root_dir` trusting no component of the path.
    ///
    /// When enabled, `root_dir` is resolved from the real filesystem root
    /// following no symlink in any component and refusing `..`, so neither a
    /// planted symlink nor an injected `..` can move the mount off its intended
    /// target. The caller must pass an absolute, already-canonicalized path.
    pub fn no_symlink_root(mut self, enabled: bool) -> Self {
        self.no_symlink_root = enabled;
        self
    }

    /// Set the stat virtualization policy. Default: [`StatVirtualization::Strict`].
    pub fn stat_virtualization(mut self, policy: StatVirtualization) -> Self {
        self.stat_virtualization = policy;
        self
    }

    /// Set the host permission propagation policy. Default: [`HostPermissions::Private`].
    pub fn host_permissions(mut self, policy: HostPermissions) -> Self {
        self.host_permissions = policy;
        self
    }

    /// Set whether mutating guest operations should be rejected.
    pub fn readonly(mut self, readonly: bool) -> Self {
        self.readonly = readonly;
        self
    }

    /// Set the optional bind identity map handle.
    pub fn bind_identity_map(mut self, handle: BindIdentityMapHandle) -> Self {
        self.bind_identity_map = Some(handle);
        self
    }

    /// Set the FUSE entry cache timeout.
    pub fn entry_timeout(mut self, timeout: Duration) -> Self {
        self.entry_timeout = timeout;
        self
    }

    /// Set the FUSE attribute cache timeout.
    pub fn attr_timeout(mut self, timeout: Duration) -> Self {
        self.attr_timeout = timeout;
        self
    }

    /// Set the cache policy.
    pub fn cache_policy(mut self, policy: CachePolicy) -> Self {
        self.cache_policy = policy;
        self
    }

    /// Enable or disable writeback caching.
    pub fn writeback(mut self, enabled: bool) -> Self {
        self.writeback = enabled;
        self
    }

    /// Enable or disable exposing the synthetic init binary at mount root.
    pub fn inject_init(mut self, enabled: bool) -> Self {
        self.inject_init = enabled;
        self
    }

    /// Set an optional guest-write byte budget for this mount's subtree.
    pub fn quota_bytes(mut self, bytes: Option<u64>) -> Self {
        self.quota_bytes = bytes;
        self
    }

    /// Deny-list of gitignore-style patterns to hide from the guest.
    pub fn deny(mut self, patterns: impl IntoIterator<Item = String>) -> Self {
        self.deny.extend(patterns);
        self
    }

    /// Build the PassthroughFs instance.
    pub fn build(self) -> io::Result<PassthroughFs> {
        let root_dir = self
            .root_dir
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "root_dir not set"))?;
        if self.bind_identity_map.is_some()
            && matches!(self.stat_virtualization, StatVirtualization::Off)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bind identity maps require stat virtualization",
            ));
        }

        let cfg = PassthroughConfig {
            root_dir,
            no_symlink_root: self.no_symlink_root,
            stat_virtualization: self.stat_virtualization,
            host_permissions: self.host_permissions,
            readonly: self.readonly,
            entry_timeout: self.entry_timeout,
            attr_timeout: self.attr_timeout,
            cache_policy: self.cache_policy,
            writeback: self.writeback,
            inject_init: self.inject_init,
            bind_identity_map: self.bind_identity_map,
            quota_bytes: self.quota_bytes,
            quota_root: None,
            deny: self.deny,
        };

        PassthroughFs::new(cfg)
    }
}
