//! Builder for constructing a `DualFs` backend.

use std::sync::Arc;

use super::{
    hooks::DualDispatchHook,
    policies::ReadBackendBWriteBackendA,
    policy::DualDispatchPolicy,
    types::{CachePolicy, DualFsConfig, DualState},
};
use microsandbox_utils::size::Bytes;

use crate::{DynFileSystem, backends::shared::init_binary};

use std::{io, time::Duration};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for [`DualFs`](super::DualFs).
pub struct DualFsBuilder {
    backend_a: Option<Box<dyn DynFileSystem>>,
    backend_b: Option<Box<dyn DynFileSystem>>,
    policy: Option<Arc<dyn DualDispatchPolicy>>,
    hooks: Vec<Arc<dyn DualDispatchHook>>,
    entry_timeout: Duration,
    attr_timeout: Duration,
    cache_policy: CachePolicy,
    writeback: bool,
    copy_chunk_size: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DualFsBuilder {
    /// Create a new builder with default settings.
    pub(crate) fn new() -> Self {
        let defaults = DualFsConfig::default();
        DualFsBuilder {
            backend_a: None,
            backend_b: None,
            policy: None,
            hooks: Vec::new(),
            entry_timeout: defaults.entry_timeout,
            attr_timeout: defaults.attr_timeout,
            cache_policy: defaults.cache_policy,
            writeback: defaults.writeback,
            copy_chunk_size: defaults.copy_chunk_size,
        }
    }

    /// Set the backend_a backend.
    pub fn backend_a(mut self, fs: impl DynFileSystem + 'static) -> Self {
        self.backend_a = Some(Box::new(fs));
        self
    }

    /// Set the backend_b backend.
    pub fn backend_b(mut self, fs: impl DynFileSystem + 'static) -> Self {
        self.backend_b = Some(Box::new(fs));
        self
    }

    /// Set the dispatch policy.
    pub fn policy(mut self, policy: impl DualDispatchPolicy + 'static) -> Self {
        self.policy = Some(Arc::new(policy));
        self
    }

    /// Add a lifecycle hook.
    pub fn hook(mut self, hook: Arc<dyn DualDispatchHook>) -> Self {
        self.hooks.push(hook);
        self
    }

    /// Set the FUSE entry cache timeout.
    pub fn entry_timeout(mut self, d: Duration) -> Self {
        self.entry_timeout = d;
        self
    }

    /// Set the FUSE attribute cache timeout.
    pub fn attr_timeout(mut self, d: Duration) -> Self {
        self.attr_timeout = d;
        self
    }

    /// Set the cache policy.
    pub fn cache_policy(mut self, p: CachePolicy) -> Self {
        self.cache_policy = p;
        self
    }

    /// Enable writeback caching.
    pub fn writeback(mut self, v: bool) -> Self {
        self.writeback = v;
        self
    }

    /// Set the materialization chunk size.
    ///
    /// Accepts bare `u64` (interpreted as bytes) or a [`SizeExt`](microsandbox_utils::size::SizeExt) helper:
    ///
    /// ```ignore
    /// .copy_chunk_size(1.mib())   // 1 MiB chunks
    /// .copy_chunk_size(4096)      // 4096-byte chunks
    /// ```
    pub fn copy_chunk_size(mut self, size: impl Into<Bytes>) -> Self {
        self.copy_chunk_size = size.into().as_u64() as usize;
        self
    }

    /// Build the `DualFs` backend.
    pub fn build(self) -> io::Result<super::DualFs> {
        let backend_a = self
            .backend_a
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "backend_a is required"))?;
        let backend_b = self
            .backend_b
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "backend_b is required"))?;

        let policy: Arc<dyn DualDispatchPolicy> = self
            .policy
            .unwrap_or_else(|| Arc::new(ReadBackendBWriteBackendA));

        let init_file = init_binary::create_init_file()?;

        Ok(super::DualFs {
            backend_a,
            backend_b,
            policy,
            hooks: self.hooks,
            state: DualState::new(),
            init_file,
            cfg: DualFsConfig {
                entry_timeout: self.entry_timeout,
                attr_timeout: self.attr_timeout,
                cache_policy: self.cache_policy,
                writeback: self.writeback,
                copy_chunk_size: self.copy_chunk_size,
            },
        })
    }
}
