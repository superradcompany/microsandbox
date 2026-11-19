//! Cloud backend implementation — talks to the cloud API over HTTP.
//!
//! Holds the (url, api_key) tuple and a `reqwest::Client`. Lifecycle ops are
//! plain HTTP; logs stream over SSE; exec, attach, and guest-fs ride the agent
//! WebSocket route through the shared agent client (see the `DialAgent` impl).
//!
//! Construction requires an API key. Hosted-cloud callers use the default
//! endpoint; `with_url`, environment configuration, and profiles can override it
//! for development, self-hosted, and on-prem deployments.
//! Auth is API-key-only, using `msb_live_*` / `msb_test_*` tokens.
//! No OAuth or session credentials are honored here.

mod agent;
mod constructors;
mod http;
mod modify;
#[cfg(test)]
mod named_volume_tests;
pub(in crate::context) mod sandbox;
mod service;
mod sharing;
mod snapshot;
#[cfg(test)]
mod stop_tests;
#[cfg(test)]
mod stream_tests;
mod volume;
mod ws_io;

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use reqwest::header::HeaderValue;
use rustls_platform_verifier::BuilderVerifierExt;
use tokio_tungstenite::Connector;

use self::http::urlencoding;
use super::{Context, ContextSelectionSource};
use crate::config::layers::BackendConfig;
use crate::{ComputeType, MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Hosted microsandbox API endpoint used when no cloud URL is configured.
pub const DEFAULT_CLOUD_API_URL: &str = "https://api.microsandbox.dev";

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Cached TLS configuration for cloud agent WebSockets.
///
/// Building this explicitly avoids Rustls's process-global crypto-provider
/// selection, which is ambiguous when an embedding application enables both
/// Ring and AWS-LC through different dependencies.
static CLOUD_AGENT_TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

/// Default User-Agent header value.
fn default_user_agent() -> String {
    format!("microsandbox-sdk/{}", env!("CARGO_PKG_VERSION"))
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Cloud-runtime backend: talks to the cloud API over HTTP.
///
/// Holds the deployment URL, API key, and captured user and managed settings.
/// The `(url, api_key)` pair determines
/// which org's view the backend sees: the cloud API derives the org from the API
/// key, so there is no per-call org argument.
///
/// Constructors:
/// - [`RemoteContext::new`] — explicit API key with the configured API URL.
/// - [`RemoteContext::with_url`] — explicit URL + key for any compatible provider.
/// - [`RemoteContext::from_env`] — reads `MSB_API_KEY`; `MSB_API_URL` is optional.
/// - [`RemoteContext::from_profile`] — reads a named profile from the SDK config.
/// - [`RemoteContext::builder`] — tuned construction (custom client, timeout,
///   user agent).
#[derive(Clone)]
pub struct RemoteContext {
    inner: Arc<RemoteContextInner>,
    // A resource-bound view must keep the original ID when a name is reused.
    agent_identity: Option<(String, String)>,
}

#[derive(Clone)]
struct RemoteContextInner {
    url: String,
    api_key: String,
    http: reqwest::Client,
    service_http: reqwest::Client,
    authorization: HeaderValue,
    user_agent_header: Option<HeaderValue>,
    request_timeout: Duration,
    user_agent: Option<String>,
    compute_type: Option<ComputeType>,
    custom_client: Option<reqwest::Client>,
    config: Arc<BackendConfig>,
    selection_source: ContextSelectionSource,
    profile: Option<String>,
}

/// Fluent builder for `RemoteContext`. Use for tuned construction.
///
/// ```ignore
/// let cloud = RemoteContext::builder()
///     .api_key(key)
///     .request_timeout(Duration::from_secs(60))
///     .build()?;
/// ```
pub struct RemoteContextBuilder {
    url: Option<String>,
    api_key: Option<String>,
    request_timeout: Duration,
    user_agent: Option<String>,
    compute_type: Option<ComputeType>,
    custom_client: Option<reqwest::Client>,
    shared_client: Option<reqwest::Client>,
    config: Option<Arc<BackendConfig>>,
}

//--------------------------------------------------------------------------------------------------
// Methods: RemoteContext
//--------------------------------------------------------------------------------------------------

impl RemoteContext {
    /// Construct from `MSB_API_KEY` and an optional `MSB_API_URL` override.
    ///
    /// Returns `InvalidConfig` if `MSB_API_KEY` is missing or empty. A missing
    /// or empty `MSB_API_URL` uses [`DEFAULT_CLOUD_API_URL`].
    pub fn from_env() -> MicrosandboxResult<Self> {
        Ok(RemoteContextBuilder::from_env()?
            .build()?
            .with_selection_metadata(ContextSelectionSource::MsbApiKey, None))
    }

    /// Construct from a named SDK profile in `~/.microsandbox/config.json`.
    ///
    /// Profiles are local SDK sugar over the primary `(url, api_key)` constructor;
    /// the cloud API does not receive or interpret profile names.
    pub fn from_profile(name: &str) -> MicrosandboxResult<Self> {
        super::profile::cloud_backend_from_profile(name)
    }

    /// Start building a `RemoteContext` with custom options. Call `.build()` when done.
    pub fn builder() -> RemoteContextBuilder {
        RemoteContextBuilder::default()
    }

    /// Configured cloud API endpoint URL (no trailing slash).
    pub fn url(&self) -> &str {
        &self.inner.url
    }

    /// Settings captured when this backend was constructed.
    pub(crate) fn config_sources(&self) -> &BackendConfig {
        &self.inner.config
    }

    /// Record the selection source and optional profile name for diagnostics.
    pub(crate) fn with_selection_metadata(
        mut self,
        selection_source: ContextSelectionSource,
        profile_name: Option<String>,
    ) -> Self {
        Arc::make_mut(&mut self.inner).selection_source = selection_source;
        Arc::make_mut(&mut self.inner).profile = profile_name;
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Build the isolated Rustls connector used by cloud agent WebSockets.
fn cloud_agent_tls_connector() -> MicrosandboxResult<Connector> {
    let config = if let Some(config) = CLOUD_AGENT_TLS_CONFIG.get() {
        Arc::clone(config)
    } else {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| {
                MicrosandboxError::Runtime(format!(
                    "cloud agent TLS protocol configuration: {error}"
                ))
            })?
            .with_platform_verifier()
            .map_err(|error| {
                MicrosandboxError::Runtime(format!(
                    "cloud agent TLS verifier configuration: {error}"
                ))
            })?
            .with_no_client_auth();
        let config = Arc::new(config);

        // A concurrent first connection may win initialization. Reuse its
        // equivalent immutable config instead of changing global TLS state.
        Arc::clone(CLOUD_AGENT_TLS_CONFIG.get_or_init(|| config))
    };

    Ok(Connector::Rustls(config))
}

//--------------------------------------------------------------------------------------------------
// Methods: Agent relay
//--------------------------------------------------------------------------------------------------

impl RemoteContext {
    /// WebSocket URL of the sandbox's agent route, derived from the backend's
    /// HTTP endpoint (`http` → `ws`, `https` → `wss`).
    fn agent_ws_url(&self, sandbox_id: &str) -> MicrosandboxResult<String> {
        let ws_base = if let Some(rest) = self.inner.url.strip_prefix("http://") {
            format!("ws://{rest}")
        } else if let Some(rest) = self.inner.url.strip_prefix("https://") {
            format!("wss://{rest}")
        } else {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "cloud backend URL must start with http:// or https://: {}",
                self.inner.url
            )));
        };

        let id = urlencoding(sandbox_id);
        Ok(format!("{ws_base}/v1/sandboxes/{id}/agent"))
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: RemoteContextBuilder
//--------------------------------------------------------------------------------------------------

impl RemoteContextBuilder {
    /// Read cloud connection settings without loading device configuration twice.
    pub(crate) fn from_env() -> MicrosandboxResult<Self> {
        let api_key = std::env::var("MSB_API_KEY").map_err(|_| {
            MicrosandboxError::InvalidConfig(
                "MSB_API_KEY not set — required for cloud backend".into(),
            )
        })?;

        Ok(Self::default()
            .api_key(api_key)
            .url(Self::environment_url()))
    }

    fn environment_url() -> String {
        std::env::var("MSB_API_URL")
            .ok()
            .filter(|url| !url.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_CLOUD_API_URL.to_owned())
    }

    /// Reuse sources already read by backend selection, or explicit sources in tests.
    pub(crate) fn config_sources(mut self, config: BackendConfig) -> Self {
        self.config = Some(Arc::new(config));
        self
    }

    /// Set the cloud API endpoint URL.
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Set the API key (`msb_live_...` / `msb_test_...`).
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Select the machine type for new sandboxes. Omission uses the server default.
    pub fn compute_type(mut self, compute_type: ComputeType) -> Self {
        self.compute_type = Some(compute_type);
        self
    }

    /// Set the per-request timeout for outbound HTTP calls.
    ///
    /// Volume downloads use this to bound the wait for response headers and
    /// each wait for more data. Log follows use it only while opening the stream;
    /// an open follow waits for new entries without a limit. Uploads retain the
    /// total request timeout, including time spent producing and sending data.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Override the default `User-Agent` header value.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Provide a fully custom `reqwest::Client`. When set, `user_agent` is ignored
    /// and ordinary requests, including uploads, use the client's timeout.
    /// Log follows still use `request_timeout` while opening the stream, and
    /// downloads use it for response headers and read inactivity. A total timeout
    /// configured on the client also limits those streams. The context API key
    /// supplies Authorization.
    ///
    /// Service create, update, enable, disable and remove also use this client,
    /// so its retry and redirect policies decide whether a change request can be
    /// resent or redirected. Build it with `.retry(reqwest::retry::never())` and
    /// `.redirect(reqwest::redirect::Policy::none())` to keep each change to the
    /// requested endpoint at most once.
    pub fn client(mut self, client: reqwest::Client) -> Self {
        self.custom_client = Some(client);
        self
    }

    /// Omitted credentials and endpoint use `MSB_API_KEY` and `MSB_API_URL`.
    /// A missing or blank environment URL uses [`DEFAULT_CLOUD_API_URL`].
    pub fn build(self) -> MicrosandboxResult<RemoteContext> {
        let config = match self.config {
            Some(config) => config,
            None => Arc::new(BackendConfig::load()?),
        };

        config.require_backend(super::ContextKind::Remote, None)?;
        let url = self.url.unwrap_or_else(Self::environment_url);
        let url = url.trim();
        if url.is_empty() {
            return Err(MicrosandboxError::InvalidConfig(
                "RemoteContext URL must not be empty".into(),
            ));
        }
        let api_key = self
            .api_key
            .or_else(|| std::env::var("MSB_API_KEY").ok())
            .ok_or_else(|| {
                MicrosandboxError::InvalidConfig(
                    "RemoteContext requires an API key (set MSB_API_KEY or call .api_key(...))"
                        .into(),
                )
            })?;
        let api_key = api_key.trim();
        if api_key.is_empty() {
            return Err(MicrosandboxError::InvalidConfig(
                "RemoteContext API key must not be empty".into(),
            ));
        }
        // Normalise trailing slash so per-route construction can append cleanly.
        let url = url.trim_end_matches('/').to_string();
        let api_key = api_key.to_string();

        let mut authorization = HeaderValue::from_str(&format!("Bearer {api_key}"))
            .map_err(|_| MicrosandboxError::InvalidConfig("invalid API key header value".into()))?;
        authorization.set_sensitive(true);
        // Keep the existing transport when deriving, including its captured proxy/TLS
        // configuration. Timeout and User-Agent overrides are applied per request for SDK
        // clients; custom clients continue to own those two settings themselves.
        let user_agent_header = if self.custom_client.is_none() {
            let agent = self
                .user_agent
                .as_deref()
                .map(str::to_owned)
                .unwrap_or_else(default_user_agent);
            Some(HeaderValue::from_str(&agent).map_err(|e| {
                MicrosandboxError::InvalidConfig(format!("invalid user-agent value: {e}"))
            })?)
        } else {
            None
        };
        let http = match self.custom_client.clone().or(self.shared_client) {
            Some(client) => client,
            None => reqwest::Client::builder().build().map_err(|e| {
                MicrosandboxError::InvalidConfig(format!("failed to build HTTP client: {e}"))
            })?,
        };

        let service_http = match self.custom_client.as_ref() {
            Some(client) => client.clone(),
            None => service::service_change_client_builder()
                .build()
                .map_err(|error| {
                    MicrosandboxError::InvalidConfig(format!(
                        "failed to build Service client: {error}"
                    ))
                })?,
        };
        Ok(RemoteContext {
            inner: Arc::new(RemoteContextInner {
                url,
                api_key,
                http,
                service_http,
                authorization,
                user_agent_header,
                request_timeout: self.request_timeout,
                user_agent: self.user_agent,
                compute_type: self.compute_type,
                custom_client: self.custom_client,
                config,
                selection_source: ContextSelectionSource::Programmatic,
                profile: None,
            }),
            agent_identity: None,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for RemoteContextBuilder {
    fn default() -> Self {
        Self {
            url: None,
            api_key: None,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            user_agent: None,
            compute_type: None,
            custom_client: None,
            shared_client: None,
            config: None,
        }
    }
}

impl From<RemoteContext> for Arc<dyn Context> {
    fn from(backend: RemoteContext) -> Self {
        Arc::new(backend)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::process::Command;

    #[cfg(unix)]
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
    #[cfg(unix)]
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    #[cfg(unix)]
    use tempfile::TempDir;
    #[cfg(unix)]
    use tokio::net::TcpListener;
    #[cfg(unix)]
    use tokio_rustls::TlsAcceptor;

    #[cfg(unix)]
    use tokio_tungstenite::connect_async_tls_with_config;

    use super::*;
    use crate::context::ContextKind;

    #[test]
    fn cloud_construction_rejects_policy_before_credentials_or_client_setup() {
        for managed in [false, true] {
            let restriction =
                crate::config::GlobalConfigPatch::new().allowed_backends(vec![ContextKind::Local]);
            let config = if managed {
                BackendConfig::new(Default::default(), restriction)
            } else {
                BackendConfig::new(restriction, Default::default())
            };
            let error = RemoteContext::builder()
                .url("not a URL")
                .config_sources(config)
                .build()
                .err()
                .unwrap();
            assert!(
                error
                    .to_string()
                    .contains("remote backend selected by programmatic is disabled")
            );
        }
    }

    #[test]
    fn cloud_backend_keeps_captured_settings_until_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("config.json");
        let managed = dir.path().join("managed.json");
        std::fs::write(&user, r#"{"sandbox_defaults":{"cpus":4}}"#).unwrap();
        std::fs::write(&managed, r#"{"overrides":{"sandbox_defaults":{"cpus":2}}}"#).unwrap();
        let sources = BackendConfig::load_from(&user, Some(&managed)).unwrap();
        let cloud = RemoteContext::builder()
            .api_key("test-key")
            .config_sources(sources)
            .build()
            .unwrap();
        std::fs::write(&managed, "invalid").unwrap();
        assert_eq!(
            cloud
                .config_sources()
                .resolved_config()
                .sandbox_defaults
                .cpus,
            2
        );
        assert_eq!(
            cloud
                .clone()
                .config_sources()
                .resolved_config()
                .sandbox_defaults
                .cpus,
            2
        );
        assert!(BackendConfig::load_from(&user, Some(&managed)).is_err());
    }

    #[cfg(unix)]
    const TLS_TEST_CHILD_URL: &str = "MSB_TEST_CLOUD_AGENT_TLS_CHILD_URL";

    #[cfg(unix)]
    struct SystemCaWebSocket {
        url: String,
        ca_path: std::path::PathBuf,
        _temp_dir: TempDir,
        server: tokio::task::JoinHandle<()>,
    }

    #[cfg(unix)]
    impl SystemCaWebSocket {
        async fn start() -> Self {
            let mut ca_params = CertificateParams::default();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let ca_key = KeyPair::generate().expect("generate CA key");
            let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
            let issuer = Issuer::new(ca_params, ca_key);

            let leaf_key = KeyPair::generate().expect("generate server key");
            let leaf_params = CertificateParams::new(vec!["localhost".to_string()])
                .expect("server certificate params");
            let leaf_cert = leaf_params
                .signed_by(&leaf_key, &issuer)
                .expect("sign server certificate");
            let chain = vec![
                CertificateDer::from(leaf_cert.der().to_vec()),
                CertificateDer::from(ca_cert.der().to_vec()),
            ];
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let server_config = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("server TLS protocol configuration")
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .expect("server TLS config");

            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind test server");
            let port = listener.local_addr().expect("test server address").port();
            let acceptor = TlsAcceptor::from(Arc::new(server_config));
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.expect("accept test connection");
                let tls = acceptor.accept(tcp).await.expect("accept test TLS");
                tokio_tungstenite::accept_async(tls)
                    .await
                    .expect("accept test WebSocket");
            });

            let temp_dir = tempfile::tempdir().expect("create CA directory");
            let ca_path = temp_dir.path().join("ca.pem");
            std::fs::write(&ca_path, ca_cert.pem()).expect("write test CA");

            Self {
                url: format!("wss://localhost:{port}"),
                ca_path,
                _temp_dir: temp_dir,
                server,
            }
        }
    }

    #[test]
    fn agent_tls_connector_uses_explicit_rustls_config() {
        assert!(matches!(
            cloud_agent_tls_connector().unwrap(),
            Connector::Rustls(_)
        ));
    }

    #[cfg(unix)]
    #[cfg_attr(
        target_vendor = "apple",
        ignore = "macOS uses Keychain rather than SSL_CERT_FILE for platform trust"
    )]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn agent_tls_connector_trusts_ssl_cert_file() {
        if let Ok(url) = std::env::var(TLS_TEST_CHILD_URL) {
            connect_async_tls_with_config(
                url,
                None,
                false,
                Some(cloud_agent_tls_connector().expect("cloud TLS connector")),
            )
            .await
            .expect("connect with CA from SSL_CERT_FILE");
            return;
        }

        let fixture = SystemCaWebSocket::start().await;
        let url = fixture.url.clone();
        let ca_path = fixture.ca_path.clone();
        let child = tokio::task::spawn_blocking(move || {
            Command::new(std::env::current_exe().expect("current test executable"))
                .arg("agent_tls_connector_trusts_ssl_cert_file")
                .arg("--nocapture")
                .env(TLS_TEST_CHILD_URL, url)
                .env("SSL_CERT_FILE", ca_path)
                .output()
                .expect("run isolated TLS test")
        })
        .await
        .expect("join isolated TLS test");

        assert!(
            child.status.success(),
            "isolated TLS test failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr),
        );
        fixture.server.await.expect("join test server");
    }

    #[test]
    fn builder_succeeds_with_url_and_key() {
        let b =
            crate::test_support::cloud_backend("https://msb.example.com", "msb_test_abc").unwrap();
        assert_eq!(b.kind(), ContextKind::Remote);
        assert_eq!(b.url(), "https://msb.example.com");
        assert_eq!(
            b.info().unwrap().source,
            ContextSelectionSource::Programmatic
        );
    }

    #[test]
    fn backend_info_never_serializes_api_key() {
        let b =
            crate::test_support::cloud_backend("https://msb.example.com", "msb_test_super_secret")
                .unwrap();
        let json = serde_json::to_string(&b.info().unwrap()).unwrap();

        assert!(json.contains("https://msb.example.com"));
        assert!(!json.contains("msb_test_super_secret"));
        assert!(!json.contains("api_key"));
    }

    #[test]
    fn builder_strips_trailing_slash() {
        let b =
            crate::test_support::cloud_backend("https://msb.example.com/", "msb_test_abc").unwrap();
        assert_eq!(b.url(), "https://msb.example.com");
    }

    #[test]
    fn from_env_builder_uses_configured_or_default_url() {
        let _env_guard = crate::test_support::lock_env();
        let previous = ["MSB_API_KEY", "MSB_API_URL"].map(|name| (name, std::env::var_os(name)));
        // SAFETY: every environment-mutating SDK unit test holds the shared lock.
        unsafe { std::env::set_var("MSB_API_KEY", " msb_test_abc ") };
        let clouds = [
            (None, DEFAULT_CLOUD_API_URL),
            (Some("   "), DEFAULT_CLOUD_API_URL),
            (
                Some(" https://msb.example.com/ "),
                "https://msb.example.com",
            ),
        ]
        .map(|(url, expected)| {
            unsafe {
                match url {
                    Some(url) => std::env::set_var("MSB_API_URL", url),
                    None => std::env::remove_var("MSB_API_URL"),
                }
            }
            (
                RemoteContextBuilder::from_env().and_then(|builder| {
                    builder
                        .config_sources(BackendConfig::new(Default::default(), Default::default()))
                        .build()
                }),
                expected,
            )
        });
        for (name, value) in previous {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
        for (cloud, expected) in clouds {
            let cloud = cloud.unwrap();
            assert_eq!(cloud.url(), expected);
            assert_eq!(
                cloud.info().unwrap().source,
                ContextSelectionSource::Programmatic
            );
        }
    }

    #[test]
    fn from_env_rejects_missing_or_blank_key_with_url() {
        let _env_guard = crate::test_support::lock_env();
        let previous = ["MSB_API_KEY", "MSB_API_URL"].map(|name| (name, std::env::var_os(name)));
        // SAFETY: every environment-mutating SDK unit test holds the shared lock.
        unsafe {
            std::env::set_var("MSB_API_URL", "https://msb.example.com");
            std::env::remove_var("MSB_API_KEY");
        }
        let missing = RemoteContext::from_env();
        unsafe { std::env::set_var("MSB_API_KEY", "   ") };
        let blank = RemoteContext::from_env();
        for (name, value) in previous {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
        assert!(matches!(missing, Err(MicrosandboxError::InvalidConfig(_))));
        assert!(matches!(blank, Err(MicrosandboxError::InvalidConfig(_))));
    }

    #[test]
    fn builder_rejects_empty_url() {
        assert!(crate::test_support::cloud_backend("", "k").is_err());
    }

    #[test]
    fn builder_rejects_whitespace_url() {
        assert!(crate::test_support::cloud_backend("   ", "k").is_err());
    }

    #[test]
    fn builder_rejects_empty_key() {
        assert!(crate::test_support::cloud_backend("https://x", "").is_err());
    }

    #[test]
    fn builder_rejects_whitespace_key() {
        assert!(crate::test_support::cloud_backend("https://x", "   ").is_err());
    }

    #[test]
    fn agent_ws_url_maps_http_schemes() {
        let plain =
            crate::test_support::cloud_backend("http://127.0.0.1:8080", "msb_test_abc").unwrap();
        assert_eq!(
            plain.agent_ws_url("sandbox id").unwrap(),
            "ws://127.0.0.1:8080/v1/sandboxes/sandbox%20id/agent"
        );

        let tls = crate::test_support::cloud_backend("https://cloud.example.com", "msb_test_abc")
            .unwrap();
        assert_eq!(
            tls.agent_ws_url("abc").unwrap(),
            "wss://cloud.example.com/v1/sandboxes/abc/agent"
        );
    }

    #[test]
    fn agent_ws_url_rejects_non_http_url() {
        let backend =
            crate::test_support::cloud_backend("file:///tmp/api", "msb_test_abc").unwrap();
        let err = backend.agent_ws_url("abc").unwrap_err();

        assert!(matches!(err, MicrosandboxError::InvalidConfig(_)));
    }
}
