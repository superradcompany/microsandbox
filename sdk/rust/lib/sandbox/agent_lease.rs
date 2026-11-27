//! Single seam for opening a guest agent connection on a prepared sandbox.
//!
//! Local runs reuse their shared client; cloud runs check out from the run's connection pool and
//! recover once if a cached running session is rejected with `409 sandbox_not_running`.

use std::sync::Arc;

use super::{Sandbox, state::RuntimeSession};
#[cfg(feature = "cloud")]
use crate::agent::AGENT_CONNECT_TIMEOUT;
use crate::{
    MicrosandboxResult,
    agent::AgentConnection,
    context::{Context, SandboxInner},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An agent connection bound to the runtime session that owns it.
pub(super) struct AgentLease {
    pub(super) session: Arc<RuntimeSession>,
    pub(super) connection: AgentConnection,
}

/// Outcome of preparing a sandbox for an agent operation.
pub(super) enum PreparedAgent {
    /// Backend supports direct agent communication (local or cloud).
    Direct(AgentLease),
    /// Backend delegates through `SandboxOps` without a direct agent connection.
    Fallback(Arc<RuntimeSession>),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeSession {
    pub(super) async fn open_agent(
        &self,
        backend: &dyn Context,
        name: &str,
    ) -> MicrosandboxResult<Option<AgentConnection>> {
        match &self.inner {
            #[cfg(feature = "local")]
            SandboxInner::Local(local) => Ok(Some(AgentConnection::shared(local.client.clone()))),
            #[cfg(feature = "cloud")]
            SandboxInner::Cloud(_) if backend.as_cloud().is_some() => self
                .agents
                .checkout(|| backend.dial_agent(name, AGENT_CONNECT_TIMEOUT))
                .await
                .map(Some),
            _ => {
                let _ = (backend, name);
                Ok(None)
            }
        }
    }
}

impl Sandbox {
    /// Prepare this sandbox and open an agent connection when supported by the backend.
    pub(super) async fn open_agent(&self) -> MicrosandboxResult<PreparedAgent> {
        let prepared = self.prepare_runtime_tracked().await?;
        match prepared
            .session
            .open_agent(self.backend.as_ref(), &self.name)
            .await
        {
            Ok(Some(connection)) => Ok(PreparedAgent::Direct(AgentLease {
                session: prepared.session,
                connection,
            })),
            Ok(None) => Ok(PreparedAgent::Fallback(prepared.session)),
            #[cfg(feature = "cloud")]
            Err(error) if prepared.cached && error.is_sandbox_not_running() => {
                let fresh = self.recover_cloud_runtime(&prepared.session).await?;
                match fresh.open_agent(self.backend.as_ref(), &self.name).await? {
                    Some(connection) => Ok(PreparedAgent::Direct(AgentLease {
                        session: fresh,
                        connection,
                    })),
                    None => Ok(PreparedAgent::Fallback(fresh)),
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Open an agent connection on an already-prepared runtime without re-preparing.
    pub(super) async fn open_prepared_agent(&self) -> MicrosandboxResult<PreparedAgent> {
        let session = self.prepared_runtime()?;
        match session
            .open_agent(self.backend.as_ref(), &self.name)
            .await?
        {
            Some(connection) => Ok(PreparedAgent::Direct(AgentLease {
                session,
                connection,
            })),
            None => Ok(PreparedAgent::Fallback(session)),
        }
    }
}
