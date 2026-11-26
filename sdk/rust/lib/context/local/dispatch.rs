//! Dispatch from a retained local context.

use super::*;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Context for LocalContext {
    fn clone_shared(&self) -> Arc<dyn Context> {
        Arc::new(self.clone())
    }

    fn kind(&self) -> ContextKind {
        ContextKind::Local
    }

    fn info(&self) -> crate::MicrosandboxResult<ContextInfo> {
        Ok(ContextInfo {
            kind: ContextKind::Local,
            api_url: None,
            source: self.inner.selection_source,
            profile: self.inner.profile.clone(),
        })
    }

    fn sandbox_ops(&self) -> &dyn SandboxOps {
        self
    }

    fn volume_ops(&self) -> &dyn VolumeOps {
        self
    }

    fn service_ops(&self) -> &dyn crate::context::ServiceOps {
        self
    }

    fn snapshot_ops(&self) -> &dyn SnapshotOps {
        self
    }

    fn as_local(&self) -> Option<&LocalContext> {
        Some(self)
    }

    fn dial_agent<'a>(
        &'a self,
        name: &'a str,
        timeout: std::time::Duration,
    ) -> futures::future::BoxFuture<'a, MicrosandboxResult<crate::agent::AgentClient>> {
        Box::pin(async move {
            let in_band = self.config().in_band_agent_transport();
            let mut last_error = None;

            for sock_path in self.agent_socket_paths(name) {
                if !agent_endpoint_may_exist(&sock_path) {
                    continue;
                }

                let attempt = if in_band {
                    let deadline = tokio::time::Instant::now() + timeout;
                    crate::agent::AgentClient::connect_in_band_with_deadline(&sock_path, deadline)
                        .await
                } else {
                    crate::agent::AgentClient::connect_with_timeout(&sock_path, timeout).await
                };

                match attempt {
                    Ok(client) => return Ok(client),
                    Err(error) => last_error = Some(error),
                }
            }

            match last_error {
                Some(error) => Err(error.into()),
                None => Err(MicrosandboxError::SandboxNotRunning(format!(
                    "{name:?} has no agent endpoint (is it running?)"
                ))),
            }
        })
    }
}
