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
        let confirmed_running = cloud.status == microsandbox_types::CloudSandboxStatus::Running;
        let state = crate::context::SandboxRemoteState {
            id: cloud.id,
            org_id: cloud.org_id,
            created_at: cloud.created_at,
        };
        Self::from_cloud_state_with_readiness(backend, state, cloud.name, config, confirmed_running)
    }

    /// Build an outer `Sandbox` from cloud state already captured by a
    /// [`SandboxRecord`](super::SandboxRecord). Cloud agent operations establish their own
    /// authenticated WebSocket lazily, so reconnecting does not need to hold
    /// an eager agent client.
    #[cfg(test)]
    pub(crate) fn from_cloud_state(
        backend: Arc<dyn crate::context::Context>,
        state: crate::context::SandboxRemoteState,
        name: String,
        config: SandboxConfig,
    ) -> Self {
        Self::from_cloud_state_with_readiness(backend, state, name, config, true)
    }

    /// Build an outer `Sandbox` from cloud state with an explicit running confirmation flag.
    pub(crate) fn from_cloud_state_with_readiness(
        backend: Arc<dyn crate::context::Context>,
        state: crate::context::SandboxRemoteState,
        name: String,
        config: SandboxConfig,
        confirmed_running: bool,
    ) -> Self {
        let backend = backend
            .with_agent_identity(&name, &state.id)
            .unwrap_or(backend);
        let identity = crate::context::sandbox::SandboxIdentity::Cloud(state.id.clone());
        let session = super::state::RuntimeSession::cloud(
            crate::context::SandboxInner::Cloud(Arc::new(state)),
            config.clone(),
            confirmed_running,
        );
        Self {
            backend,
            identity,
            name,
            ephemeral: config.spec.lifecycle.ephemeral,
            binding: Arc::new(super::state::SandboxBinding::new(Some(Arc::new(session)))),
        }
    }
}
