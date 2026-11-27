//! Identity-bound agent connections for cloud sandbox objects.

use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use microsandbox_types::CloudErrorBody;
use tokio_tungstenite::{
    connect_async_tls_with_config,
    tungstenite::{
        Error as WsError,
        client::IntoClientRequest,
        http::{
            HeaderValue as WsHeaderValue,
            header::{AUTHORIZATION as WS_AUTHORIZATION, USER_AGENT as WS_USER_AGENT},
        },
    },
};

use super::{RemoteContext, cloud_agent_tls_connector, default_user_agent, http::cloud_http_error};
use crate::context::{Context, ContextInfo, ContextKind, SandboxOps, ServiceOps, VolumeOps};
use crate::{MicrosandboxError, MicrosandboxResult, timing};

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Context for RemoteContext {
    fn clone_shared(&self) -> Arc<dyn Context> {
        Arc::new(self.clone())
    }

    fn kind(&self) -> ContextKind {
        ContextKind::Remote
    }

    fn info(&self) -> MicrosandboxResult<ContextInfo> {
        Ok(ContextInfo {
            kind: ContextKind::Remote,
            api_url: Some(self.inner.url.clone()),
            source: self.inner.selection_source,
            profile: self.inner.profile.clone(),
        })
    }

    fn as_cloud(&self) -> Option<&RemoteContext> {
        Some(self)
    }

    fn sandbox_ops(&self) -> &dyn SandboxOps {
        self
    }

    fn volume_ops(&self) -> &dyn VolumeOps {
        self
    }

    fn snapshot_ops(&self) -> &dyn crate::context::SnapshotOps {
        self
    }

    fn service_ops(&self) -> &dyn ServiceOps {
        self
    }

    fn with_agent_identity(&self, name: &str, id: &str) -> Option<Arc<dyn Context>> {
        let mut bound = self.clone();
        bound.agent_identity = Some((name.to_owned(), id.to_owned()));
        Some(Arc::new(bound))
    }

    /// Open an agent connection over `GET /v1/sandboxes/:id/agent`.
    fn dial_agent<'a>(
        &'a self,
        name: &'a str,
        timeout: Duration,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::agent::AgentClient>> {
        Box::pin(async move {
            // Treat the caller's timeout as one budget for lookup, WebSocket upgrade, and
            // agent handshake so a stalled peer never hangs exec, fs, or attach calls.
            let mut timing = timing::ConnectionTiming::new(name);
            let result = tokio::time::timeout(timeout, async {
                timing.stage("identity");
                let lookup_started = std::time::Instant::now();
                let id = match &self.agent_identity {
                    Some((bound_name, id)) if bound_name == name => id.clone(),
                    _ => self.get_sandbox(name).await?.id,
                };
                tracing::trace!(
                    target: timing::TARGET,
                    sandbox_id = %id,
                    elapsed_seconds = lookup_started.elapsed().as_secs_f64(),
                    "cloud agent identity resolved"
                );
                timing.identity(&id);
                let url = self.agent_ws_url(&id)?;
                let mut request = url
                    .into_client_request()
                    .map_err(|e| MicrosandboxError::Runtime(format!("cloud agent request: {e}")))?;
                let bearer = format!("Bearer {}", self.inner.api_key);
                let mut auth_value = WsHeaderValue::from_str(&bearer).map_err(|e| {
                    MicrosandboxError::InvalidConfig(format!("invalid API key header value: {e}"))
                })?;
                auth_value.set_sensitive(true);
                request.headers_mut().insert(WS_AUTHORIZATION, auth_value);
                request.headers_mut().insert(
                    WS_USER_AGENT,
                    WsHeaderValue::from_str(&default_user_agent()).map_err(|e| {
                        MicrosandboxError::InvalidConfig(format!("invalid user-agent value: {e}"))
                    })?,
                );

                timing.stage("websocket");
                let websocket_started = std::time::Instant::now();
                let connector = cloud_agent_tls_connector()?;
                let (socket, _) =
                    connect_async_tls_with_config(request, None, false, Some(connector))
                        .await
                        .map_err(|e| {
                            tracing::trace!(
                                target: timing::TARGET,
                                sandbox_id = %id,
                                elapsed_seconds = websocket_started.elapsed().as_secs_f64(),
                                success = false,
                                "cloud agent websocket finished"
                            );
                            cloud_agent_ws_error(&id, e)
                        })?;

                tracing::trace!(
                    target: timing::TARGET,
                    sandbox_id = %id,
                    elapsed_seconds = websocket_started.elapsed().as_secs_f64(),
                    success = true,
                    "cloud agent websocket finished"
                );
                timing.stage("handshake");
                let handshake_started = std::time::Instant::now();
                let client = crate::agent::AgentClient::connect_stream_with_timeout(
                    super::ws_io::WsByteStream::new(socket),
                    timeout,
                )
                .await;
                tracing::trace!(
                    target: timing::TARGET,
                    sandbox_id = %id,
                    elapsed_seconds = handshake_started.elapsed().as_secs_f64(),
                    success = client.is_ok(),
                    "cloud agent handshake finished"
                );
                client.map_err(Into::into)
            })
            .await;
            match result {
                Ok(result) => {
                    timing.finish(if result.is_ok() { "success" } else { "error" });
                    result
                }
                Err(_) => {
                    timing.finish("timeout");
                    Err(MicrosandboxError::Runtime(format!(
                        "timed out connecting to cloud sandbox agent {name:?} after {timeout:?} (stage: {})",
                        timing.current_stage()
                    )))
                }
            }
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Preserve structured control-plane HTTP rejections (such as `409 sandbox_not_running` and
/// `404 sandbox_not_found`) returned during WebSocket upgrade.
fn cloud_agent_ws_error(sandbox_id: &str, error: WsError) -> MicrosandboxError {
    match error {
        WsError::Http(response) => {
            let status = response.status().as_u16();
            let body_text = response
                .body()
                .as_deref()
                .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                .unwrap_or_default();
            let typed: Option<CloudErrorBody> = serde_json::from_str(&body_text).ok();
            let op = format!("GET /v1/sandboxes/{sandbox_id}/agent");
            cloud_http_error(status, typed.as_ref(), &body_text, &op)
        }
        other => MicrosandboxError::Runtime(format!("cloud agent websocket: {other}")),
    }
}
