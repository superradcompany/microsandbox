//! Receiver-shared preparation state, separate from stable resource identity.

use std::sync::{Arc, RwLock, Weak};

use tokio::sync::Mutex;

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
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

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
