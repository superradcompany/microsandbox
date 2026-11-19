//! Construction of cloud-backed sandbox handles.

use std::sync::Arc;

use super::{Sandbox, SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Build an outer `Sandbox` from a [`CloudCreateSandboxResponse`](crate::context::CloudCreateSandboxResponse)
    /// HTTP response plus the originating [`SandboxConfig`].
    pub(crate) fn from_cloud(
        backend: Arc<dyn crate::context::Context>,
        cloud: crate::context::CloudCreateSandboxResponse,
        config: SandboxConfig,
    ) -> Self {
        let state = crate::context::SandboxRemoteState {
            id: cloud.id,
            org_id: cloud.org_id,
            created_at: cloud.created_at,
        };
        Self::from_cloud_state(backend, state, cloud.name, config)
    }

    /// Build an outer `Sandbox` from cloud state already captured by a
    /// [`SandboxRecord`](super::SandboxRecord). Cloud agent operations establish their own
    /// authenticated WebSocket lazily, so reconnecting does not need to hold
    /// an eager agent client.
    pub(crate) fn from_cloud_state(
        backend: Arc<dyn crate::context::Context>,
        state: crate::context::SandboxRemoteState,
        name: String,
        config: SandboxConfig,
    ) -> Self {
        let backend = backend
            .with_agent_identity(&name, &state.id)
            .unwrap_or(backend);
        let identity = crate::context::sandbox::SandboxIdentity::Cloud(state.id.clone());
        let session = super::state::RuntimeSession {
            inner: crate::context::SandboxInner::Cloud(Arc::new(state)),
            config: config.clone(),
        };
        Self {
            backend,
            identity,
            name,
            ephemeral: config.spec.lifecycle.ephemeral,
            binding: Arc::new(super::state::SandboxBinding::new(Some(Arc::new(session)))),
        }
    }
}
