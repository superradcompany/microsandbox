//! Construction of cloud-backed sandbox handles.

use std::sync::Arc;

use super::{Sandbox, SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Build an outer `Sandbox` from a [`CloudCreateSandboxResponse`](crate::backend::CloudCreateSandboxResponse)
    /// HTTP response plus the originating [`SandboxConfig`].
    pub(crate) fn from_cloud(
        backend: Arc<dyn crate::backend::Backend>,
        cloud: crate::backend::CloudCreateSandboxResponse,
        config: SandboxConfig,
    ) -> Self {
        let state = crate::backend::SandboxCloudState {
            id: cloud.id,
            org_id: cloud.org_id,
            created_at: cloud.created_at,
        };
        Self::from_cloud_state(backend, state, cloud.name, config)
    }

    /// Build an outer `Sandbox` from cloud state already captured by a
    /// [`SandboxHandle`](super::SandboxHandle). Cloud agent operations establish their own
    /// authenticated WebSocket lazily, so reconnecting does not need to hold
    /// an eager agent client.
    pub(crate) fn from_cloud_state(
        backend: Arc<dyn crate::backend::Backend>,
        state: crate::backend::SandboxCloudState,
        name: String,
        config: SandboxConfig,
    ) -> Self {
        let backend = backend
            .with_agent_identity(&name, &state.id)
            .unwrap_or(backend);
        Self {
            backend,
            inner: Arc::new(crate::backend::SandboxInner::Cloud(state)),
            name,
            config,
        }
    }
}
