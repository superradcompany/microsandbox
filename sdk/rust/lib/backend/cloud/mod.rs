//! Cloud backend implementation — talks to an msb-cloud control plane over HTTP.
//!
//! Holds the (url, api_key) tuple and a `reqwest::Client`. Lifecycle ops are
//! plain HTTP; logs stream over SSE; exec, attach, and guest-fs ride the agent
//! WebSocket route through the shared agent client (see the `DialAgent` impl).
//!
//! Construction is URL + API key first; `from_env` and `from_profile` are sugar.
//! Auth is API-key-only — the same `msb_live_*` / `msb_test_*` tokens msb-cloud
//! issues today. No OAuth or session credentials are honored here.

mod http;
pub(in crate::backend) mod sandbox;
mod volume;
mod ws_io;

use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{
        client::IntoClientRequest,
        http::{
            HeaderValue as WsHeaderValue,
            header::{AUTHORIZATION as WS_AUTHORIZATION, USER_AGENT as WS_USER_AGENT},
        },
    },
};

use self::http::urlencoding;
use super::{Backend, BackendKind, SandboxBackend, VolumeBackend};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default User-Agent header value.
fn default_user_agent() -> String {
    format!("microsandbox-sdk/{}", env!("CARGO_PKG_VERSION"))
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Cloud-runtime backend: talks to an msb-cloud control plane over HTTP.
///
/// Holds the deployment URL and API key. The `(url, api_key)` pair determines
/// which org's view the backend sees: msb-cloud derives the org from the API
/// key, so there is no per-call org argument.
///
/// Constructors:
/// - [`CloudBackend::new`] — primary; explicit URL + key. Works for hosted SaaS,
///   self-hosted, and on-prem deployments identically.
/// - [`CloudBackend::from_env`] — reads `MSB_API_URL` + `MSB_API_KEY`.
/// - [`CloudBackend::from_profile`] — reads a named profile from the SDK config.
/// - [`CloudBackend::builder`] — tuned construction (custom client, timeout,
///   user agent).
pub struct CloudBackend {
    url: String,
    api_key: String,
    http: reqwest::Client,
}

/// Fluent builder for `CloudBackend`. Use for tuned construction.
///
/// ```ignore
/// let cloud = CloudBackend::builder()
///     .url("https://msb.example.com")
///     .api_key(key)
///     .request_timeout(Duration::from_secs(60))
///     .build()?;
/// ```
pub struct CloudBackendBuilder {
    url: Option<String>,
    api_key: Option<String>,
    request_timeout: Duration,
    user_agent: Option<String>,
    custom_client: Option<reqwest::Client>,
}

//--------------------------------------------------------------------------------------------------
// Methods: CloudBackend
//--------------------------------------------------------------------------------------------------

impl CloudBackend {
    /// Construct a `CloudBackend` with an explicit URL and API key.
    ///
    /// Primary constructor. Works identically for hosted msb-cloud, self-hosted
    /// deployments, and on-prem installs — no constructor implies a specific
    /// deployment shape.
    pub fn new(url: impl Into<String>, api_key: impl Into<String>) -> MicrosandboxResult<Self> {
        Self::builder().url(url).api_key(api_key).build()
    }

    /// Construct from `MSB_API_URL` + `MSB_API_KEY` env vars.
    ///
    /// Returns `InvalidConfig` if either is missing or empty.
    pub fn from_env() -> MicrosandboxResult<Self> {
        let url = std::env::var("MSB_API_URL").map_err(|_| {
            MicrosandboxError::InvalidConfig(
                "MSB_API_URL not set — required for cloud backend".into(),
            )
        })?;
        let api_key = std::env::var("MSB_API_KEY").map_err(|_| {
            MicrosandboxError::InvalidConfig(
                "MSB_API_KEY not set — required for cloud backend".into(),
            )
        })?;
        Self::new(url.trim(), api_key.trim())
    }

    /// Construct from a named SDK profile in `~/.microsandbox/config.json`.
    ///
    /// Profiles are local SDK sugar over the primary `(url, api_key)` constructor;
    /// msb-cloud does not receive or interpret profile names.
    pub fn from_profile(name: &str) -> MicrosandboxResult<Self> {
        super::profile::cloud_backend_from_profile(name)
    }

    /// Start building a `CloudBackend` with custom options. Call `.build()` when done.
    pub fn builder() -> CloudBackendBuilder {
        CloudBackendBuilder::default()
    }

    /// Configured msb-cloud endpoint URL (no trailing slash).
    pub fn url(&self) -> &str {
        &self.url
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Agent relay
//--------------------------------------------------------------------------------------------------

impl CloudBackend {
    /// WebSocket URL of the sandbox's agent route, derived from the backend's
    /// HTTP endpoint (`http` → `ws`, `https` → `wss`).
    fn agent_ws_url(&self, sandbox_id: &str) -> MicrosandboxResult<String> {
        let ws_base = if let Some(rest) = self.url.strip_prefix("http://") {
            format!("ws://{rest}")
        } else if let Some(rest) = self.url.strip_prefix("https://") {
            format!("wss://{rest}")
        } else {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "cloud backend URL must start with http:// or https://: {}",
                self.url
            )));
        };

        let id = urlencoding(sandbox_id);
        Ok(format!("{ws_base}/v1/sandboxes/{id}/agent"))
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: CloudBackendBuilder
//--------------------------------------------------------------------------------------------------

impl CloudBackendBuilder {
    /// Set the msb-cloud endpoint URL.
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Set the API key (`msb_live_...` / `msb_test_...`).
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Set the per-request timeout for outbound HTTP calls.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Override the default `User-Agent` header value.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Provide a fully custom `reqwest::Client`. When set, `request_timeout`
    /// and `user_agent` builder options are ignored — the supplied client owns
    /// its own configuration.
    pub fn client(mut self, client: reqwest::Client) -> Self {
        self.custom_client = Some(client);
        self
    }

    /// Build the `CloudBackend`. Errors when URL or API key are missing, or
    /// when the underlying HTTP client fails to construct.
    pub fn build(self) -> MicrosandboxResult<CloudBackend> {
        let url = self.url.ok_or_else(|| {
            MicrosandboxError::InvalidConfig("CloudBackend requires a URL (call .url(...))".into())
        })?;
        let url = url.trim();
        if url.is_empty() {
            return Err(MicrosandboxError::InvalidConfig(
                "CloudBackend URL must not be empty".into(),
            ));
        }
        let api_key = self.api_key.ok_or_else(|| {
            MicrosandboxError::InvalidConfig(
                "CloudBackend requires an API key (call .api_key(...))".into(),
            )
        })?;
        let api_key = api_key.trim();
        if api_key.is_empty() {
            return Err(MicrosandboxError::InvalidConfig(
                "CloudBackend API key must not be empty".into(),
            ));
        }
        // Normalise trailing slash so per-route construction can append cleanly.
        let url = url.trim_end_matches('/').to_string();
        let api_key = api_key.to_string();

        let http = if let Some(client) = self.custom_client {
            client
        } else {
            let mut headers = HeaderMap::new();
            let bearer = format!("Bearer {api_key}");
            let mut auth_value = HeaderValue::from_str(&bearer).map_err(|e| {
                MicrosandboxError::InvalidConfig(format!("invalid API key header value: {e}"))
            })?;
            auth_value.set_sensitive(true);
            headers.insert(AUTHORIZATION, auth_value);
            let ua = self.user_agent.unwrap_or_else(default_user_agent);
            headers.insert(
                USER_AGENT,
                HeaderValue::from_str(&ua).map_err(|e| {
                    MicrosandboxError::InvalidConfig(format!("invalid user-agent value: {e}"))
                })?,
            );

            reqwest::Client::builder()
                .timeout(self.request_timeout)
                .default_headers(headers)
                .build()
                .map_err(|e| {
                    MicrosandboxError::InvalidConfig(format!("failed to build HTTP client: {e}"))
                })?
        };

        Ok(CloudBackend { url, api_key, http })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Backend for CloudBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Cloud
    }

    fn sandboxes(&self) -> &dyn SandboxBackend {
        self
    }

    fn volumes(&self) -> &dyn VolumeBackend {
        self
    }

    /// Open an agent connection over `GET /v1/sandboxes/:id/agent`.
    ///
    /// The route upgrades to a WebSocket that pipes bytes to and from the
    /// sandbox's agent, so the standard agent client runs over it unchanged.
    fn dial_agent<'a>(
        &'a self,
        name: &'a str,
        timeout: std::time::Duration,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::agent::AgentClient>> {
        Box::pin(async move {
            let sandbox = self.get_sandbox(name).await?;
            let url = self.agent_ws_url(&sandbox.id)?;
            let mut request = url
                .into_client_request()
                .map_err(|e| MicrosandboxError::Runtime(format!("cloud agent request: {e}")))?;
            let bearer = format!("Bearer {}", self.api_key);
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

            let (socket, _) = connect_async(request)
                .await
                .map_err(|e| MicrosandboxError::Runtime(format!("cloud agent websocket: {e}")))?;

            crate::agent::AgentClient::connect_stream_with_timeout(
                self::ws_io::WsByteStream::new(socket),
                timeout,
            )
            .await
            .map_err(Into::into)
        })
    }
}

impl Default for CloudBackendBuilder {
    fn default() -> Self {
        Self {
            url: None,
            api_key: None,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            user_agent: None,
            custom_client: None,
        }
    }
}

impl From<CloudBackend> for Arc<dyn Backend> {
    fn from(backend: CloudBackend) -> Self {
        Arc::new(backend)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_succeeds_with_url_and_key() {
        let b = CloudBackend::new("https://msb.example.com", "msb_test_abc").unwrap();
        assert_eq!(b.kind(), BackendKind::Cloud);
        assert_eq!(b.url(), "https://msb.example.com");
    }

    #[test]
    fn new_strips_trailing_slash() {
        let b = CloudBackend::new("https://msb.example.com/", "msb_test_abc").unwrap();
        assert_eq!(b.url(), "https://msb.example.com");
    }

    #[test]
    fn builder_rejects_missing_url() {
        assert!(CloudBackendBuilder::default().api_key("k").build().is_err());
    }

    #[test]
    fn builder_rejects_missing_key() {
        assert!(
            CloudBackendBuilder::default()
                .url("https://x")
                .build()
                .is_err()
        );
    }

    #[test]
    fn builder_rejects_empty_url() {
        assert!(CloudBackend::new("", "k").is_err());
    }

    #[test]
    fn builder_rejects_whitespace_url() {
        assert!(CloudBackend::new("   ", "k").is_err());
    }

    #[test]
    fn builder_rejects_empty_key() {
        assert!(CloudBackend::new("https://x", "").is_err());
    }

    #[test]
    fn builder_rejects_whitespace_key() {
        assert!(CloudBackend::new("https://x", "   ").is_err());
    }

    #[test]
    fn from_env_errors_when_url_missing() {
        // Note: this test can race with parallel tests setting env vars. Just
        // verify the function returns an error when MSB_API_URL is clearly absent;
        // we don't try to scrub env state.
        unsafe { std::env::remove_var("MSB_API_URL") };
        assert!(CloudBackend::from_env().is_err());
    }

    #[test]
    fn agent_ws_url_maps_http_schemes() {
        let plain = CloudBackend::new("http://127.0.0.1:8080", "msb_test_abc").unwrap();
        assert_eq!(
            plain.agent_ws_url("sandbox id").unwrap(),
            "ws://127.0.0.1:8080/v1/sandboxes/sandbox%20id/agent"
        );

        let tls = CloudBackend::new("https://cloud.example.com", "msb_test_abc").unwrap();
        assert_eq!(
            tls.agent_ws_url("abc").unwrap(),
            "wss://cloud.example.com/v1/sandboxes/abc/agent"
        );
    }

    #[test]
    fn agent_ws_url_rejects_non_http_url() {
        let backend = CloudBackend::new("file:///tmp/api", "msb_test_abc").unwrap();
        let err = backend.agent_ws_url("abc").unwrap_err();

        assert!(matches!(err, MicrosandboxError::InvalidConfig(_)));
    }
}
