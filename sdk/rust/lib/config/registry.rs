//! Registry configuration, layered pull options, and credential resolution.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

#[cfg(feature = "local")]
use docker_credential::{CredentialRetrievalError, DockerCredential};
use microsandbox_types::ConfigPatch;
use microsandbox_types::RegistryAuth;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use super::layers::BackendConfig;
use super::{GlobalConfig, GlobalConfigPatch, layers::Overlay};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Service name for microsandbox-managed registry credentials in the OS keyring.
#[cfg(all(
    feature = "keyring",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
const REGISTRY_KEYRING_SERVICE: &str = "dev.microsandbox.registry";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Registry configuration.
///
/// Example:
/// ```json
/// {
///   "registries": {
///     "ca_certs": "/path/to/corporate-ca.pem",
///     "hosts": {
///       "localhost:5050": { "insecure": true },
///       "ghcr.io": {
///         "auth": { "username": "user", "store": "keyring" }
///       }
///     }
///   }
/// }
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
#[derive(ConfigPatch)]
#[config_patch(serde)]
pub struct RegistriesConfig {
    /// Path to a PEM file containing additional CA root certificates to trust.
    ///
    /// Applies globally to all registry connections.
    pub ca_certs: Option<PathBuf>,

    /// Per-registry settings keyed by hostname.
    #[serde(default)]
    #[config_patch(nested, merge)]
    pub hosts: HashMap<String, RegistryEntry>,
}

/// Configuration for a single OCI registry.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
#[derive(ConfigPatch)]
#[config_patch(serde)]
pub struct RegistryEntry {
    /// Authentication credentials.
    #[serde(default)]
    pub auth: Option<RegistryAuthEntry>,

    /// Access this registry over plain HTTP instead of HTTPS.
    #[serde(default)]
    pub insecure: bool,
}

/// Authentication credentials for a registry entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryAuthEntry {
    /// Registry username.
    pub username: String,

    /// Credential source metadata for interactive local auth.
    pub store: Option<RegistryCredentialStore>,

    /// Environment variable containing the password/token.
    pub password_env: Option<String>,

    /// Secret name — password is read from `{home}/secrets/registries/<secret_name>`.
    pub secret_name: Option<String>,
}

/// Credential source metadata for registry auth entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryCredentialStore {
    /// Credential is stored in the OS keyring.
    Keyring,
}

/// Per-pull registry options, applied above user configuration and below managed settings.
#[derive(Default)]
pub struct RegistryOptions {
    /// Explicit credentials for this pull.
    pub auth: Option<RegistryAuth>,
    /// Request plain HTTP access for this registry.
    pub insecure: bool,
    /// Additional PEM-encoded root certificates.
    pub ca_certs: Vec<Vec<u8>>,
    /// Additional PEM files. Only surviving certificate sources are read.
    pub ca_cert_files: Vec<PathBuf>,
}

/// Registry connection settings after all configuration layers have been applied.
pub struct RegistryConfig {
    /// Resolved credentials.
    pub auth: RegistryAuth,
    /// Resolved PEM-encoded root certificates.
    pub ca_certs: Vec<Vec<u8>>,
    /// Registry hosts that use plain HTTP.
    pub insecure_registries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyringRegistryCredential {
    username: String,
    password: String,
}

#[derive(Clone, Default, ConfigPatch)]
pub(crate) struct RegistrySettings {
    auth: AuthSource,
    insecure: bool,
    #[config_patch(merge)]
    ca_certs: Vec<Certificate>,
}

#[derive(Debug, Clone, Default)]
enum AuthSource {
    #[default]
    Automatic,
    Configured,
    Explicit(RegistryAuth),
}

#[derive(Debug, Clone)]
enum Certificate {
    File(PathBuf),
    Pem(Vec<u8>),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl GlobalConfig {
    /// Load additional CA root certificates from `registries.ca_certs`.
    ///
    /// Returns an empty vec if no path is configured.
    pub async fn resolve_ca_certs(&self) -> MicrosandboxResult<Vec<Vec<u8>>> {
        match &self.registries.ca_certs {
            Some(path) => Ok(vec![Certificate::read_file(path).await?]),
            None => Ok(Vec::new()),
        }
    }

    /// Return all registry hostnames configured as insecure (plain HTTP).
    pub fn insecure_registries(&self) -> Vec<String> {
        self.registries
            .hosts
            .iter()
            .filter(|(_, entry)| entry.insecure)
            .map(|(hostname, _)| hostname.clone())
            .collect()
    }

    /// Resolve registry authentication for a given hostname.
    ///
    /// Resolution order:
    /// 1. OS keyring (interactive CLI login, when the `keyring` feature is enabled)
    /// 2. `registries.<hostname>.auth` in this config
    /// 3. Docker credential store/config
    /// 4. Anonymous
    ///
    /// Returns `Anonymous` if no entry matches.
    pub fn resolve_registry_auth(&self, hostname: &str) -> MicrosandboxResult<RegistryAuth> {
        #[cfg(feature = "keyring")]
        {
            match KeyringRegistryCredential::load(hostname) {
                Ok(Some(auth)) => return Ok(auth.into()),
                Ok(None) => {}
                Err(error) => {
                    tracing::debug!(registry = hostname, error = %error, "failed to resolve registry auth from OS keyring");
                }
            }
        }

        if let Some(auth) = self.resolve_configured_registry_auth(hostname)? {
            return Ok(auth);
        }

        #[cfg(feature = "local")]
        if let Some(auth) =
            resolve_registry_auth_with_lookup(hostname, docker_credential::get_credential)
        {
            return Ok(auth);
        }

        Ok(RegistryAuth::Anonymous)
    }

    fn resolve_configured_registry_auth(
        &self,
        hostname: &str,
    ) -> MicrosandboxResult<Option<RegistryAuth>> {
        let entry = match self
            .registries
            .hosts
            .get(hostname)
            .and_then(|e| e.auth.as_ref())
        {
            Some(entry) => entry,
            None => return Ok(None),
        };

        entry.resolve(hostname, &self.secrets_dir()).map(Some)
    }
}

impl RegistryAuthEntry {
    fn resolve(&self, hostname: &str, secrets_dir: &Path) -> MicrosandboxResult<RegistryAuth> {
        let password = match (
            self.store,
            self.password_env.as_deref(),
            self.secret_name.as_deref(),
        ) {
            (Some(RegistryCredentialStore::Keyring), None, None) => {
                return match KeyringRegistryCredential::load(hostname) {
                    Ok(Some(auth)) => Ok(auth.into()),
                    Ok(None) => Err(MicrosandboxError::InvalidConfig(format!(
                        "registry auth for {hostname}: OS keyring entry is missing"
                    ))),
                    Err(error) => Err(MicrosandboxError::InvalidConfig(format!(
                        "registry auth for {hostname}: failed to read OS keyring entry: {error}"
                    ))),
                };
            }
            (None, Some(env_var), None) => std::env::var(env_var).map_err(|_| {
                MicrosandboxError::InvalidConfig(format!(
                    "registry auth for {hostname}: environment variable `{env_var}` is not set"
                ))
            })?,
            (None, None, Some(secret_name)) => {
                let secret_path = secrets_dir.join("registries").join(secret_name);
                std::fs::read_to_string(&secret_path)
                    .map_err(|e| {
                        MicrosandboxError::InvalidConfig(format!(
                            "registry auth for {hostname}: failed to read secret `{}`: {e}",
                            secret_path.display()
                        ))
                    })?
                    .trim()
                    .to_string()
            }
            (None, None, None) => {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "registry auth for {hostname}: entry has no credential source"
                )));
            }
            _ => {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "registry auth for {hostname}: entry defines multiple credential sources"
                )));
            }
        };

        Ok(RegistryAuth::Basic {
            username: self.username.clone(),
            password,
        })
    }
}

#[cfg(all(
    feature = "keyring",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
impl KeyringRegistryCredential {
    fn load(hostname: &str) -> Result<Option<Self>, String> {
        let entry = keyring::Entry::new(REGISTRY_KEYRING_SERVICE, hostname).map_err(|e| {
            format!("failed to open OS credential store entry for `{hostname}`: {e}")
        })?;

        let payload = match entry.get_secret() {
            Ok(payload) => payload,
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(error) => {
                return Err(format!(
                    "failed to read OS credential for `{hostname}`: {error}"
                ));
            }
        };

        serde_json::from_slice::<Self>(&payload)
            .map(Some)
            .map_err(|e| format!("failed to decode OS credential for `{hostname}`: {e}"))
    }

    fn save(&self, hostname: &str) -> Result<(), String> {
        let entry = keyring::Entry::new(REGISTRY_KEYRING_SERVICE, hostname).map_err(|e| {
            format!("failed to open OS credential store entry for `{hostname}`: {e}")
        })?;

        let payload = serde_json::to_vec(self)
            .map_err(|e| format!("failed to serialize keyring credential for `{hostname}`: {e}"))?;

        entry
            .set_secret(&payload)
            .map_err(|e| format!("failed to store OS credential for `{hostname}`: {e}"))
    }

    fn delete(hostname: &str) -> Result<(), String> {
        let entry = keyring::Entry::new(REGISTRY_KEYRING_SERVICE, hostname).map_err(|e| {
            format!("failed to open OS credential store entry for `{hostname}`: {e}")
        })?;

        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(format!(
                "failed to delete OS credential for `{hostname}`: {error}"
            )),
        }
    }
}

#[cfg(not(all(
    feature = "keyring",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
)))]
impl KeyringRegistryCredential {
    fn load(hostname: &str) -> Result<Option<Self>, String> {
        Err(Self::unavailable_message(hostname))
    }

    fn save(&self, hostname: &str) -> Result<(), String> {
        Err(Self::unavailable_message(hostname))
    }

    fn delete(hostname: &str) -> Result<(), String> {
        Err(Self::unavailable_message(hostname))
    }

    fn unavailable_message(hostname: &str) -> String {
        #[cfg(not(feature = "keyring"))]
        {
            format!(
                "secure OS credential storage is disabled; enable the `keyring` feature to use it for `{hostname}`"
            )
        }

        #[cfg(all(
            feature = "keyring",
            not(any(target_os = "linux", target_os = "macos", target_os = "windows"))
        ))]
        format!("secure OS credential storage is not supported on this platform for `{hostname}`")
    }
}

impl RegistrySettings {
    /// Resolve the selected sources after all registry patches have been composed.
    pub(crate) async fn resolve(
        self,
        hostname: &str,
        config: &GlobalConfig,
    ) -> MicrosandboxResult<RegistryConfig> {
        let auth = match self.auth {
            AuthSource::Automatic => config.resolve_registry_auth(hostname)?,
            AuthSource::Configured => config
                .resolve_configured_registry_auth(hostname)?
                .unwrap_or(RegistryAuth::Anonymous),
            AuthSource::Explicit(auth) => auth,
        };
        let mut ca_certs = Vec::with_capacity(self.ca_certs.len());
        for cert in self.ca_certs {
            ca_certs.push(cert.resolve().await?);
        }
        let mut insecure_registries = config.insecure_registries();
        insecure_registries.retain(|host| host != hostname);
        if self.insecure {
            insecure_registries.push(hostname.to_owned());
        }
        Ok(RegistryConfig {
            auth,
            ca_certs,
            insecure_registries,
        })
    }
}

impl Certificate {
    async fn resolve(self) -> MicrosandboxResult<Vec<u8>> {
        match self {
            Self::Pem(bytes) => Ok(bytes),
            Self::File(path) => Self::read_file(&path).await,
        }
    }

    async fn read_file(path: &Path) -> MicrosandboxResult<Vec<u8>> {
        tokio::fs::read(path).await.map_err(|error| {
            MicrosandboxError::InvalidConfig(format!(
                "failed to read CA certs from `{}`: {error}",
                path.display()
            ))
        })
    }
}

impl RegistrySettingsPatch {
    /// Convert saved TLS settings without changing normal credential lookup.
    pub(crate) fn from_defaults(global: &GlobalConfigPatch, hostname: &str) -> Self {
        let registries = &global.registries;
        let mut patch = Self::new();
        if let Some(configured) = &registries.ca_certs {
            // An explicit null replaces lower certificate sources with an empty list.
            patch.replace_ca_certs_mut(configured.iter().cloned().map(Certificate::File).collect());
        }
        if let Some(host) = registries.get_hosts().and_then(|hosts| hosts.get(hostname))
            && let Some(insecure) = host.insecure
        {
            patch.insecure_mut(insecure);
        }
        patch
    }

    /// Explicit managed auth, including null, suppresses ambient and per-call credentials.
    pub(crate) fn from_managed(global: &GlobalConfigPatch, hostname: &str) -> Self {
        let mut patch = Self::from_defaults(global, hostname);
        if let Some(host) = global
            .registries
            .get_hosts()
            .and_then(|hosts| hosts.get(hostname))
            && host.auth.is_some()
        {
            patch.auth_mut(AuthSource::Configured);
        }
        patch
    }

    /// Preserve per-pull credentials and append the caller's certificate sources.
    pub(crate) fn from_options(options: RegistryOptions) -> Self {
        let ca_certs = options
            .ca_certs
            .into_iter()
            .map(Certificate::Pem)
            .chain(options.ca_cert_files.into_iter().map(Certificate::File))
            .collect();
        let mut patch = Self::new().ca_certs(ca_certs);
        if let Some(auth) = options.auth {
            patch.auth_mut(AuthSource::Explicit(auth));
        }
        if options.insecure {
            patch.insecure_mut(true);
        }
        patch
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Overlay for RegistrySettingsPatch {
    fn overlay(self, higher: Self) -> Self {
        self.overlay(higher)
    }
}

impl From<KeyringRegistryCredential> for RegistryAuth {
    fn from(credential: KeyringRegistryCredential) -> Self {
        Self::Basic {
            username: credential.username,
            password: credential.password,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Store registry credentials in the OS keyring for interactive local use.
pub fn set_registry_keyring_auth(
    hostname: &str,
    username: &str,
    password: &str,
) -> MicrosandboxResult<()> {
    KeyringRegistryCredential {
        username: username.to_owned(),
        password: password.to_owned(),
    }
    .save(hostname)
    .map_err(MicrosandboxError::Custom)
}

/// Load registry credentials from the OS keyring, if present.
pub fn get_registry_keyring_auth(hostname: &str) -> MicrosandboxResult<Option<RegistryAuth>> {
    KeyringRegistryCredential::load(hostname)
        .map(|credential| credential.map(Into::into))
        .map_err(MicrosandboxError::Custom)
}

/// Delete registry credentials from the OS keyring if they exist.
pub fn delete_registry_keyring_auth(hostname: &str) -> MicrosandboxResult<()> {
    KeyringRegistryCredential::delete(hostname).map_err(MicrosandboxError::Custom)
}

#[cfg(feature = "local")]
fn resolve_registry_auth_with_lookup<F>(hostname: &str, mut lookup: F) -> Option<RegistryAuth>
where
    F: FnMut(&str) -> Result<DockerCredential, CredentialRetrievalError>,
{
    for server in docker_credential_servers(hostname) {
        match lookup(&server) {
            Ok(DockerCredential::UsernamePassword(username, password)) => {
                tracing::debug!(registry = hostname, server = %server, "resolved registry auth from Docker credentials");
                return Some(RegistryAuth::Basic { username, password });
            }
            Ok(DockerCredential::IdentityToken(_)) => {
                tracing::debug!(registry = hostname, server = %server, "ignoring Docker identity token for registry auth");
            }
            Err(CredentialRetrievalError::NoCredentialConfigured)
            | Err(CredentialRetrievalError::ConfigNotFound)
            | Err(CredentialRetrievalError::ConfigReadError) => {}
            Err(error) => {
                tracing::debug!(registry = hostname, server = %server, ?error, "failed to resolve Docker registry credentials");
            }
        }
    }

    None
}

#[cfg(feature = "local")]
fn docker_credential_servers(hostname: &str) -> Vec<String> {
    let mut servers = vec![hostname.to_string(), format!("https://{hostname}")];

    if matches!(
        hostname,
        "docker.io" | "index.docker.io" | "registry-1.docker.io"
    ) {
        servers.extend([
            "index.docker.io".to_string(),
            "https://index.docker.io".to_string(),
            "https://index.docker.io/v1/".to_string(),
            "registry-1.docker.io".to_string(),
            "https://registry-1.docker.io".to_string(),
        ]);
    }

    dedupe_strings(&mut servers);
    servers
}

#[cfg(feature = "local")]
fn dedupe_strings(values: &mut Vec<String>) {
    let mut deduped = Vec::new();
    for value in values.drain(..) {
        if !deduped.iter().any(|existing| existing == &value) {
            deduped.push(value);
        }
    }
    *values = deduped;
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "local"))]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::config::PathsConfig;

    fn basic(user: &str) -> RegistryAuth {
        RegistryAuth::Basic {
            username: user.into(),
            password: "token".into(),
        }
    }

    #[tokio::test]
    async fn managed_tls_only_preserves_credentials_and_other_host_fields() {
        let user = serde_json::from_str(
            r#"{"registries":{"hosts":{"registry.example":{
            "auth":{"username":"employee","password_env":"EMPLOYEE_TOKEN"},"insecure":true
        }}}}"#,
        )
        .unwrap();
        let managed = serde_json::from_str(
            r#"{"registries":{"hosts":{"registry.example":{"insecure":false}}}}"#,
        )
        .unwrap();
        let layers = BackendConfig::new(user, managed);
        let entry = &layers.resolved_config().registries.hosts["registry.example"];
        assert_eq!(entry.auth.as_ref().unwrap().username, "employee");
        assert!(!entry.insecure);
        let automatic = layers
            .registry_layers("registry.example")
            .options(RegistrySettingsPatch::from_options(
                RegistryOptions::default(),
            ))
            .build()
            .into_config();
        assert!(
            matches!(automatic.auth, AuthSource::Automatic),
            "keyring and Docker lookup must remain enabled"
        );
        let config = layers
            .registry_layers("registry.example")
            .options(RegistrySettingsPatch::from_options(RegistryOptions {
                auth: Some(basic("employee")),
                insecure: true,
                ..Default::default()
            }))
            .build()
            .into_config()
            .resolve("registry.example", layers.resolved_config())
            .await
            .unwrap();
        assert!(
            matches!(config.auth, RegistryAuth::Basic { username, .. } if username == "employee")
        );
        assert!(config.insecure_registries.is_empty());
    }

    #[tokio::test]
    async fn ordinary_options_append_certificates_and_override_auth() {
        let dir = tempfile::tempdir().unwrap();
        let user_ca = dir.path().join("user.pem");
        let cli_ca = dir.path().join("cli.pem");
        std::fs::write(&user_ca, b"user").unwrap();
        std::fs::write(&cli_ca, b"cli").unwrap();
        let global: GlobalConfigPatch = serde_json::from_value(serde_json::json!({
            "registries": {
                "ca_certs": user_ca,
                "hosts": {"registry.example": {"auth": {"username": "unused"}}}
            }
        }))
        .unwrap();
        let layers = BackendConfig::new(global, Default::default());
        let config = layers
            .registry_layers("registry.example")
            .options(RegistrySettingsPatch::from_options(RegistryOptions {
                auth: Some(basic("explicit")),
                insecure: true,
                ca_certs: vec![b"sdk".to_vec(), b"sdk".to_vec()],
                ca_cert_files: vec![cli_ca],
            }))
            .build()
            .into_config()
            .resolve("registry.example", layers.resolved_config())
            .await
            .unwrap();
        assert!(
            matches!(config.auth, RegistryAuth::Basic { username, .. } if username == "explicit")
        );
        assert_eq!(
            config.ca_certs,
            [
                b"user".to_vec(),
                b"sdk".to_vec(),
                b"sdk".to_vec(),
                b"cli".to_vec()
            ]
        );
        assert_eq!(config.insecure_registries, ["registry.example"]);
    }

    #[tokio::test]
    async fn managed_certificates_and_host_replace_all_per_call_options() {
        let dir = tempfile::tempdir().unwrap();
        let admin_ca = dir.path().join("admin.pem");
        std::fs::write(&admin_ca, b"admin").unwrap();
        for path in [Some(admin_ca), None] {
            let user: GlobalConfigPatch = serde_json::from_value(serde_json::json!({
                "registries": {
                    "ca_certs": dir.path().join("missing-user.pem"),
                    "hosts": {"other.example": {"insecure": true}}
                }
            }))
            .unwrap();
            let managed = serde_json::from_value(serde_json::json!({
                "registries": {"ca_certs": path, "hosts": {"registry.example": {"auth": null, "insecure": false}}}
            }))
            .unwrap();
            let layers = BackendConfig::new(user, managed);
            let config = layers
                .registry_layers("registry.example")
                .options(RegistrySettingsPatch::from_options(RegistryOptions {
                    auth: Some(basic("discarded")),
                    insecure: true,
                    ca_certs: vec![b"discarded".to_vec()],
                    ca_cert_files: vec![dir.path().join("missing-cli.pem")],
                }))
                .build()
                .into_config()
                .resolve("registry.example", layers.resolved_config())
                .await
                .unwrap();
            assert!(matches!(config.auth, RegistryAuth::Anonymous));
            assert_eq!(
                config.ca_certs,
                if path.is_some() {
                    vec![b"admin".to_vec()]
                } else {
                    Vec::new()
                }
            );
            assert_eq!(config.insecure_registries, ["other.example"]);
        }
    }

    #[tokio::test]
    async fn managed_credentials_are_resolved_after_layering() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("registries")).unwrap();
        let managed = serde_json::from_value(serde_json::json!({
            "paths": {"secrets": dir.path()},
            "registries": {"hosts": {"registry.example": {
                "auth": {"username": "admin", "secret_name": "admin"}
            }}}
        }))
        .unwrap();
        let layers = BackendConfig::new(Default::default(), managed);
        let settings = layers
            .registry_layers("registry.example")
            .options(RegistrySettingsPatch::from_options(RegistryOptions {
                auth: Some(basic("discarded")),
                ..Default::default()
            }))
            .build()
            .into_config();
        std::fs::write(dir.path().join("registries/admin"), b"admin-token").unwrap();
        let config = settings
            .resolve("registry.example", layers.resolved_config())
            .await
            .unwrap();
        assert!(
            matches!(config.auth, RegistryAuth::Basic { username, password }
            if username == "admin" && password == "admin-token")
        );
    }

    #[tokio::test]
    async fn invalid_managed_auth_does_not_fall_back_to_explicit_credentials() {
        let managed = serde_json::from_str(
            r#"{"registries":{"hosts":{"registry.example":{
            "auth":{"username":"invalid"}
        }}}}"#,
        )
        .unwrap();
        let layers = BackendConfig::new(Default::default(), managed);
        assert!(
            layers
                .registry_layers("registry.example")
                .options(RegistrySettingsPatch::from_options(RegistryOptions {
                    auth: Some(basic("explicit")),
                    ..Default::default()
                }))
                .build()
                .into_config()
                .resolve("registry.example", layers.resolved_config())
                .await
                .is_err()
        );
    }

    #[test]
    fn projection_preserves_whole_host_map_replacement_and_repeated_calls() {
        let mut user = GlobalConfigPatch::new();
        user.registries.hosts_mut(HashMap::from([(
            "registry.example".into(),
            RegistryEntry {
                insecure: true,
                ..Default::default()
            }
            .into(),
        )]));
        let mut options = GlobalConfigPatch::new();
        options.registries.replace_hosts_mut(HashMap::new());
        let layers = BackendConfig::new(user.overlay(options), Default::default());
        assert!(
            !layers
                .registry_layers("registry.example")
                .options(RegistrySettingsPatch::from_options(
                    RegistryOptions::default()
                ))
                .build()
                .into_config()
                .insecure
        );
        assert!(
            layers
                .registry_layers("registry.example")
                .options(RegistrySettingsPatch::from_options(RegistryOptions {
                    insecure: true,
                    ..Default::default()
                }))
                .build()
                .into_config()
                .insecure
        );
        assert!(
            !layers
                .registry_layers("registry.example")
                .options(RegistrySettingsPatch::from_options(
                    RegistryOptions::default()
                ))
                .build()
                .into_config()
                .insecure
        );
    }

    #[test]
    fn registry_source_field_matrix() {
        use serde_json::json;
        for managed in [false, true] {
            for auth in [
                json!({}),
                json!({"auth":null}),
                json!({"auth":{"username":"employee","password_env":"TOKEN"}}),
            ] {
                let global = serde_json::from_value(
                    json!({"registries":{"hosts":{"registry.example":auth}}}),
                )
                .unwrap();
                let layers = if managed {
                    BackendConfig::new(Default::default(), global)
                } else {
                    BackendConfig::new(global, Default::default())
                };
                let settings = layers
                    .registry_layers("registry.example")
                    .options(RegistrySettingsPatch::from_options(
                        RegistryOptions::default(),
                    ))
                    .build()
                    .into_config();
                assert_eq!(
                    matches!(settings.auth, AuthSource::Configured),
                    managed && auth.get("auth").is_some()
                );
            }
            for insecure in [None, Some(false), Some(true)] {
                let mut host = json!({});
                if let Some(value) = insecure {
                    host["insecure"] = json!(value);
                }
                let global = serde_json::from_value(
                    json!({"registries":{"hosts":{"registry.example":host}}}),
                )
                .unwrap();
                let layers = if managed {
                    BackendConfig::new(Default::default(), global)
                } else {
                    BackendConfig::new(global, Default::default())
                };
                let settings = layers
                    .registry_layers("registry.example")
                    .options(RegistrySettingsPatch::from_options(RegistryOptions {
                        insecure: true,
                        ..Default::default()
                    }))
                    .build()
                    .into_config();
                assert_eq!(
                    settings.insecure,
                    if managed {
                        insecure.unwrap_or(true)
                    } else {
                        true
                    }
                );
            }
            for ca in [
                json!({}),
                json!({"ca_certs":null}),
                json!({"ca_certs":"/host/ca.pem"}),
            ] {
                let global = serde_json::from_value(json!({"registries":ca})).unwrap();
                let layers = if managed {
                    BackendConfig::new(Default::default(), global)
                } else {
                    BackendConfig::new(global, Default::default())
                };
                let settings = layers
                    .registry_layers("registry.example")
                    .options(RegistrySettingsPatch::from_options(RegistryOptions {
                        ca_certs: vec![b"request".to_vec()],
                        ..Default::default()
                    }))
                    .build()
                    .into_config();
                let file = ca.get("ca_certs").is_some_and(|path| !path.is_null());
                let request = !managed || ca.get("ca_certs").is_none();
                assert_eq!(
                    settings.ca_certs.len(),
                    usize::from(file) + usize::from(request)
                );
                if file {
                    assert!(
                        matches!(&settings.ca_certs[0], Certificate::File(path) if path == Path::new("/host/ca.pem"))
                    );
                }
                if request {
                    assert!(
                        matches!(settings.ca_certs.last().unwrap(), Certificate::Pem(bytes) if bytes == b"request")
                    );
                }
            }
        }
    }

    /// Helper to build a `RegistriesConfig` from a list of `(hostname, RegistryEntry)` pairs.
    fn registries(entries: Vec<(&str, RegistryEntry)>) -> RegistriesConfig {
        RegistriesConfig {
            hosts: entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn test_deserialize_registry_keyring_store() {
        let json = r#"{
            "registries": {
                "hosts": {
                    "ghcr.io": {
                        "auth": {
                            "username": "octocat",
                            "store": "keyring"
                        }
                    }
                }
            }
        }"#;

        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        let entry = cfg
            .registries
            .hosts
            .get("ghcr.io")
            .unwrap()
            .auth
            .as_ref()
            .unwrap();
        assert_eq!(entry.username, "octocat");
        assert_eq!(entry.store, Some(RegistryCredentialStore::Keyring));
        assert!(entry.password_env.is_none());
        assert!(entry.secret_name.is_none());
    }

    #[test]
    fn test_save_and_read_persisted_config_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.json");

        let cfg = GlobalConfig {
            registries: registries(vec![(
                "ghcr.io",
                RegistryEntry {
                    auth: Some(RegistryAuthEntry {
                        username: "octocat".to_string(),
                        store: Some(RegistryCredentialStore::Keyring),
                        password_env: None,
                        secret_name: None,
                    }),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let content = serde_json::to_string_pretty(&cfg).unwrap();
        std::fs::write(&path, content).unwrap();

        let loaded = super::GlobalConfigPatch::load_from(&path).unwrap();
        let entry = loaded
            .registries
            .get_hosts()
            .unwrap()
            .get("ghcr.io")
            .unwrap()
            .auth
            .as_ref()
            .unwrap();
        let entry = entry.as_ref().unwrap();
        assert_eq!(entry.username, "octocat");
        assert_eq!(entry.store, Some(RegistryCredentialStore::Keyring));
    }

    #[test]
    fn test_resolve_configured_registry_auth_reads_secret_file() {
        let temp = tempfile::tempdir().unwrap();
        let secret_dir = temp.path().join("registries");
        std::fs::create_dir_all(&secret_dir).unwrap();
        std::fs::write(secret_dir.join("ghcr-token"), "secret-token\n").unwrap();

        let cfg = GlobalConfig {
            home: Some(temp.path().to_path_buf()),
            paths: PathsConfig {
                secrets: Some(temp.path().to_path_buf()),
                ..Default::default()
            },
            registries: registries(vec![(
                "ghcr.io",
                RegistryEntry {
                    auth: Some(RegistryAuthEntry {
                        username: "user".to_string(),
                        store: None,
                        password_env: None,
                        secret_name: Some("ghcr-token".to_string()),
                    }),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let auth = cfg.resolve_configured_registry_auth("ghcr.io").unwrap();
        match auth {
            Some(RegistryAuth::Basic { username, password }) => {
                assert_eq!(username, "user");
                assert_eq!(password, "secret-token");
            }
            other => panic!("expected basic auth, got {other:?}"),
        }
    }

    #[test]
    fn test_resolve_configured_registry_auth_rejects_multiple_sources() {
        let keyring = Some(RegistryCredentialStore::Keyring);
        for (store, password_env, secret_name) in [
            (keyring, Some("GHCR_TOKEN"), None),
            (keyring, None, Some("ghcr-token")),
            (None, Some("GHCR_TOKEN"), Some("ghcr-token")),
            (keyring, Some("GHCR_TOKEN"), Some("ghcr-token")),
        ] {
            let cfg = GlobalConfig {
                registries: registries(vec![(
                    "ghcr.io",
                    RegistryEntry {
                        auth: Some(RegistryAuthEntry {
                            username: "user".to_string(),
                            store,
                            password_env: password_env.map(str::to_owned),
                            secret_name: secret_name.map(str::to_owned),
                        }),
                        ..Default::default()
                    },
                )]),
                ..Default::default()
            };

            let error = cfg.resolve_configured_registry_auth("ghcr.io").unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("entry defines multiple credential sources")
            );
        }
    }

    #[cfg(not(all(
        feature = "keyring",
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    )))]
    #[test]
    fn test_resolve_configured_registry_auth_reports_disabled_keyring() {
        let cfg = GlobalConfig {
            registries: registries(vec![(
                "ghcr.io",
                RegistryEntry {
                    auth: Some(RegistryAuthEntry {
                        username: "user".to_string(),
                        store: Some(RegistryCredentialStore::Keyring),
                        password_env: None,
                        secret_name: None,
                    }),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let error = cfg.resolve_configured_registry_auth("ghcr.io").unwrap_err();
        assert!(matches!(error, MicrosandboxError::InvalidConfig(_)));
        assert!(
            error
                .to_string()
                .contains("secure OS credential storage is disabled")
                || error
                    .to_string()
                    .contains("secure OS credential storage is not supported")
        );
    }

    #[test]
    fn test_resolve_registry_auth_with_lookup_prefers_exact_hostname() {
        let auth = resolve_registry_auth_with_lookup("ghcr.io", |server| match server {
            "ghcr.io" => Ok(DockerCredential::UsernamePassword(
                "user".to_string(),
                "token".to_string(),
            )),
            other => panic!("unexpected server lookup: {other}"),
        });

        match auth {
            Some(RegistryAuth::Basic { username, password }) => {
                assert_eq!(username, "user");
                assert_eq!(password, "token");
            }
            other => panic!("expected basic auth, got {other:?}"),
        }
    }

    #[test]
    fn test_resolve_registry_auth_with_lookup_tries_docker_hub_aliases() {
        let auth = resolve_registry_auth_with_lookup("docker.io", |server| match server {
            "https://index.docker.io/v1/" => Ok(DockerCredential::UsernamePassword(
                "docker-user".to_string(),
                "docker-pass".to_string(),
            )),
            _ => Err(CredentialRetrievalError::NoCredentialConfigured),
        });

        match auth {
            Some(RegistryAuth::Basic { username, password }) => {
                assert_eq!(username, "docker-user");
                assert_eq!(password, "docker-pass");
            }
            other => panic!("expected basic auth, got {other:?}"),
        }
    }

    #[test]
    fn test_resolve_registry_auth_with_lookup_skips_identity_tokens() {
        let mut responses = VecDeque::from([
            Ok(DockerCredential::IdentityToken(
                "identity-token".to_string(),
            )),
            Ok(DockerCredential::UsernamePassword(
                "fallback-user".to_string(),
                "fallback-pass".to_string(),
            )),
        ]);

        let auth = resolve_registry_auth_with_lookup("ghcr.io", |_server| {
            responses
                .pop_front()
                .unwrap_or(Err(CredentialRetrievalError::NoCredentialConfigured))
        });

        match auth {
            Some(RegistryAuth::Basic { username, password }) => {
                assert_eq!(username, "fallback-user");
                assert_eq!(password, "fallback-pass");
            }
            other => panic!("expected basic auth, got {other:?}"),
        }
    }

    #[test]
    fn test_deserialize_registry_insecure() {
        let json = r#"{
            "registries": {
                "hosts": {
                    "localhost:5050": { "insecure": true }
                }
            }
        }"#;

        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        let entry = cfg.registries.hosts.get("localhost:5050").unwrap();
        assert!(entry.insecure);
        assert!(entry.auth.is_none());
    }

    #[test]
    fn test_deserialize_registry_ca_certs_global() {
        let json = r#"{
            "registries": {
                "ca_certs": "/path/to/ca.pem"
            }
        }"#;

        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            cfg.registries.ca_certs,
            Some(PathBuf::from("/path/to/ca.pem"))
        );
    }

    #[test]
    fn test_deserialize_registry_full_entry() {
        let json = r#"{
            "registries": {
                "ca_certs": "/path/to/ca.pem",
                "hosts": {
                    "localhost:5050": {
                        "insecure": true,
                        "auth": {
                            "username": "user",
                            "password_env": "TOKEN"
                        }
                    }
                }
            }
        }"#;

        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            cfg.registries.ca_certs,
            Some(PathBuf::from("/path/to/ca.pem"))
        );
        let entry = cfg.registries.hosts.get("localhost:5050").unwrap();
        assert!(entry.insecure);
        let auth = entry.auth.as_ref().unwrap();
        assert_eq!(auth.username, "user");
        assert_eq!(auth.password_env, Some("TOKEN".to_string()));
    }

    #[test]
    fn test_deserialize_empty_registries() {
        let json = r#"{"registries": {}}"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.registries.hosts.is_empty());
        assert!(cfg.registries.ca_certs.is_none());
    }

    #[tokio::test]
    async fn test_resolve_ca_certs_from_file() {
        let temp = tempfile::tempdir().unwrap();
        let pem_path = temp.path().join("ca.pem");
        let pem_data = b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n";
        std::fs::write(&pem_path, pem_data).unwrap();

        let cfg = GlobalConfig {
            registries: RegistriesConfig {
                ca_certs: Some(pem_path),
                ..Default::default()
            },
            ..Default::default()
        };

        let certs = cfg.resolve_ca_certs().await.unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0], pem_data);
    }

    #[tokio::test]
    async fn test_resolve_ca_certs_missing_file_errors() {
        let cfg = GlobalConfig {
            registries: RegistriesConfig {
                ca_certs: Some(PathBuf::from("/nonexistent/ca.pem")),
                ..Default::default()
            },
            ..Default::default()
        };

        let err = cfg.resolve_ca_certs().await.unwrap_err();
        assert!(err.to_string().contains("failed to read CA certs"));
    }

    #[tokio::test]
    async fn test_resolve_ca_certs_none_returns_empty() {
        let cfg = GlobalConfig::default();
        let certs = cfg.resolve_ca_certs().await.unwrap();
        assert!(certs.is_empty());
    }

    #[test]
    fn test_insecure_registries() {
        let cfg = GlobalConfig {
            registries: registries(vec![
                (
                    "localhost:5050",
                    RegistryEntry {
                        insecure: true,
                        ..Default::default()
                    },
                ),
                (
                    "ghcr.io",
                    RegistryEntry {
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };

        let insecure = cfg.insecure_registries();
        assert_eq!(insecure, vec!["localhost:5050"]);
    }
}
