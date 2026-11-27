//! Receiver-shared preparation state, separate from stable resource identity.

use std::sync::{
    Arc, RwLock, Weak,
    atomic::{AtomicBool, Ordering},
};

use tokio::sync::Mutex;

#[cfg(feature = "cloud")]
use super::agent_pool::AgentPool;
use super::{Sandbox, SandboxConfig, SandboxIdentity};
use crate::context::SandboxInner;
use crate::{Context, MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Clones of one resource coordinate preparation and retain the run they start.
/// Independent lookups create independent bindings and never inherit ownership.
#[derive(Default)]
pub(super) struct SandboxBinding {
    pub(super) preparation: Mutex<()>,
    current: RwLock<Option<Arc<RuntimeSession>>>,
}

/// An idle helper retains its destination and identity, never the shutdown owner.
#[derive(Clone)]
pub(super) struct WeakSandbox {
    backend: Arc<dyn Context>,
    binding: Weak<SandboxBinding>,
    identity: SandboxIdentity,
    name: String,
    ephemeral: bool,
}

/// One immutable connection/generation and its construction-time runtime settings.
/// Active operations retain this object rather than following a receiver's next run.
pub(crate) struct RuntimeSession {
    pub(crate) inner: SandboxInner,
    pub(crate) config: SandboxConfig,
    /// Whether this cloud session was built from an observed `Running` state and
    /// has not been invalidated by a lifecycle change or stale-connection signal.
    #[cfg(feature = "cloud")]
    cloud_confirmed_running: AtomicBool,
    /// Idle cloud agent WebSockets for this run; cleared when the run is invalidated or dropped.
    #[cfg(feature = "cloud")]
    pub(super) agents: Arc<AgentPool>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeSession {
    pub(crate) fn new(inner: SandboxInner, config: SandboxConfig) -> Self {
        Self {
            inner,
            config,
            #[cfg(feature = "cloud")]
            cloud_confirmed_running: AtomicBool::new(false),
            #[cfg(feature = "cloud")]
            agents: Arc::new(AgentPool::new()),
        }
    }

    #[cfg(feature = "cloud")]
    pub(crate) fn cloud(
        inner: SandboxInner,
        config: SandboxConfig,
        confirmed_running: bool,
    ) -> Self {
        Self {
            inner,
            config,
            cloud_confirmed_running: AtomicBool::new(confirmed_running),
            agents: Arc::new(AgentPool::new()),
        }
    }

    pub(crate) fn shell(&self) -> String {
        self.config
            .spec
            .runtime
            .shell
            .as_deref()
            .unwrap_or("/bin/sh")
            .to_string()
    }

    pub(crate) fn default_command(
        &self,
    ) -> MicrosandboxResult<microsandbox_types::ResolvedCommand> {
        microsandbox_types::resolve_default_command(
            self.config.spec.runtime.entrypoint.as_deref(),
            self.config.spec.runtime.cmd.as_deref(),
            None,
        )
        .map_err(Into::into)
    }

    #[cfg(feature = "cloud")]
    pub(crate) fn is_cloud_confirmed_running(&self) -> bool {
        matches!(self.inner, SandboxInner::Cloud(_))
            && self.cloud_confirmed_running.load(Ordering::Acquire)
    }

    #[cfg(feature = "cloud")]
    pub(crate) fn invalidate_cloud_running(&self) {
        self.cloud_confirmed_running.store(false, Ordering::Release);
        self.agents.evict();
    }
}

impl SandboxBinding {
    pub(super) fn new(session: Option<Arc<RuntimeSession>>) -> Self {
        Self {
            preparation: Mutex::new(()),
            current: RwLock::new(session),
        }
    }

    pub(super) fn current(&self) -> Option<Arc<RuntimeSession>> {
        self.current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    #[cfg(feature = "cloud")]
    pub(super) fn confirmed_cloud_session(&self) -> Option<Arc<RuntimeSession>> {
        let session = self.current()?;
        session.is_cloud_confirmed_running().then_some(session)
    }

    #[cfg(feature = "cloud")]
    pub(super) fn invalidate_cloud_running(&self) {
        if let Some(session) = self.current() {
            session.invalidate_cloud_running();
        }
    }

    pub(super) fn publish(&self, session: Arc<RuntimeSession>) {
        // No await separates successful startup from receiver ownership. If a
        // preparation future is dropped earlier, its unpublished owner drops too.
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = Some(session);
    }
}

impl WeakSandbox {
    pub(super) fn new(sandbox: &Sandbox) -> Self {
        Self {
            backend: sandbox.backend.clone(),
            binding: Arc::downgrade(&sandbox.binding),
            identity: sandbox.identity.clone(),
            name: sandbox.name.clone(),
            ephemeral: sandbox.ephemeral,
        }
    }

    pub(super) fn upgrade(&self) -> MicrosandboxResult<Sandbox> {
        // Weak::upgrade is the admission point: a helper cannot resurrect a
        // binding whose final owner has already begun cleanup.
        let binding = self.binding.upgrade().ok_or_else(|| MicrosandboxError::Custom(
            format!("sandbox receiver '{}' has been released; acquire a new Sandbox to begin another operation", self.name),
        ))?;
        Ok(Sandbox {
            backend: self.backend.clone(),
            binding,
            identity: self.identity.clone(),
            name: self.name.clone(),
            ephemeral: self.ephemeral,
        })
    }
}
