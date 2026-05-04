//! Global configuration for the microsandbox library.
//!
//! Configuration is loaded from `~/.microsandbox/config.json` on first access.
//! All fields have sensible defaults — a missing config file is equivalent to `{}`.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use docker_credential::{CredentialRetrievalError, DockerCredential};
use microsandbox_image::RegistryAuth;
use microsandbox_runtime::logging::LogLevel;
use serde::{Deserialize, Serialize};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default number of vCPUs per sandbox.
const DEFAULT_CPUS: u8 = 1;

/// Default guest memory in MiB.
const DEFAULT_MEMORY_MIB: u32 = 512;

/// Default database max connections.
pub(crate) const DEFAULT_MAX_CONNECTIONS: u32 = 5;

/// Default database connection acquisition timeout in seconds.
pub(crate) const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 30;

/// Service name for microsandbox-managed registry credentials in the OS keyring.
#[cfg(all(
    feature = "keyring",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
const REGISTRY_KEYRING_SERVICE: &str = "dev.microsandbox.registry";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Global configuration for the microsandbox library.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct GlobalConfig {
    /// Root directory for all microsandbox data.
    pub home: Option<PathBuf>,

    /// Default runtime log level for SDK-spawned sandbox processes.
    ///
    /// `None` means sandbox runtime processes are silent unless overridden
    /// per-sandbox.
    pub log_level: Option<LogLevel>,

    /// Database configuration.
    pub database: DatabaseConfig,

    /// Path overrides.
    pub paths: PathsConfig,

    /// Default values for sandbox configuration.
    pub sandbox_defaults: SandboxDefaults,

    /// Registry authentication configuration.
    pub registries: RegistriesConfig,
}

/// Database configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// Database connection URL. `None` uses the default SQLite path.
    pub url: Option<String>,

    /// Maximum connection pool size.
    pub max_connections: u32,

    /// Timeout when acquiring a database connection from the pool.
    pub connect_timeout_secs: u64,

    /// SQLite `busy_timeout` PRAGMA: seconds SQLite waits on a contended
    /// lock before surfacing `SQLITE_BUSY` to the retry layer.
    pub busy_timeout_secs: u64,
}

/// Path overrides for runtime binaries and data directories.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PathsConfig {
    /// Path to `msb` binary.
    ///
    /// Resolution: `MSB_PATH` env → this → workspace-local (debug only)
    /// → `~/.microsandbox/bin/msb` → PATH lookup.
    pub msb: Option<PathBuf>,

    /// Path to `libkrunfw.{so,dylib}`.
    pub libkrunfw: Option<PathBuf>,

    /// Cache directory.
    pub cache: Option<PathBuf>,

    /// Per-sandbox state directory.
    pub sandboxes: Option<PathBuf>,

    /// Named volumes directory.
    pub volumes: Option<PathBuf>,

    /// Logs directory.
    pub logs: Option<PathBuf>,

    /// Secrets directory.
    pub secrets: Option<PathBuf>,
}

/// Default values applied to sandboxes when not overridden per-sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxDefaults {
    /// Default vCPU count.
    pub cpus: u8,

    /// Default guest memory in MiB.
    pub memory_mib: u32,

    /// Default shell for interactive sessions and scripts.
    pub shell: String,

    /// Default working directory inside the sandbox.
    pub workdir: Option<String>,
}

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
pub struct RegistriesConfig {
    /// Path to a PEM file containing additional CA root certificates to trust.
    ///
    /// Applies globally to all registry connections.
    pub ca_certs: Option<PathBuf>,

    /// Per-registry settings keyed by hostname.
    #[serde(default)]
    pub hosts: HashMap<String, RegistryEntry>,
}

/// Configuration for a single OCI registry.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RegistryEntry {
    /// Authentication credentials.
    #[serde(default)]
    pub auth: Option<RegistryAuthEntry>,

    /// Access this registry over plain HTTP instead of HTTPS.
    #[serde(default, skip_serializing_if = "is_false")]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyringRegistryCredential {
    username: String,
    password: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

static CONFIG: OnceLock<GlobalConfig> = OnceLock::new();

impl GlobalConfig {
    /// Get the resolved home directory.
    pub fn home(&self) -> PathBuf {
        self.home.clone().unwrap_or_else(resolve_default_home)
    }

    /// Resolve the `sandboxes` directory.
    pub fn sandboxes_dir(&self) -> PathBuf {
        self.paths
            .sandboxes
            .clone()
            .unwrap_or_else(|| self.home().join(microsandbox_utils::SANDBOXES_SUBDIR))
    }

    /// Resolve the `volumes` directory.
    pub fn volumes_dir(&self) -> PathBuf {
        self.paths
            .volumes
            .clone()
            .unwrap_or_else(|| self.home().join(microsandbox_utils::VOLUMES_SUBDIR))
    }

    /// Resolve the `logs` directory.
    pub fn logs_dir(&self) -> PathBuf {
        self.paths
            .logs
            .clone()
            .unwrap_or_else(|| self.home().join(microsandbox_utils::LOGS_SUBDIR))
    }

    /// Resolve the `cache` directory.
    pub fn cache_dir(&self) -> PathBuf {
        self.paths
            .cache
            .clone()
            .unwrap_or_else(|| self.home().join(microsandbox_utils::CACHE_SUBDIR))
    }

    /// Resolve the `secrets` directory.
    pub fn secrets_dir(&self) -> PathBuf {
        self.paths
            .secrets
            .clone()
            .unwrap_or_else(|| self.home().join(microsandbox_utils::SECRETS_SUBDIR))
    }

    /// Resolve registry transport for a given hostname from the global config.
    /// Load additional CA root certificates from the global `registries.ca_certs` path.
    ///
    /// Returns an empty vec if no path is configured.
    pub async fn resolve_ca_certs(&self) -> MicrosandboxResult<Vec<Vec<u8>>> {
        match &self.registries.ca_certs {
            Some(path) => {
                let data = tokio::fs::read(path).await.map_err(|e| {
                    MicrosandboxError::InvalidConfig(format!(
                        "failed to read CA certs from `{}`: {e}",
                        path.display()
                    ))
                })?;
                Ok(vec![data])
            }
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
    /// 2. `registries.<hostname>.auth` in global config
    /// 3. Docker credential store/config
    /// 4. Anonymous
    ///
    /// Returns `Anonymous` if no entry matches.
    pub fn resolve_registry_auth(&self, hostname: &str) -> MicrosandboxResult<RegistryAuth> {
        #[cfg(feature = "keyring")]
        {
            match lookup_registry_keyring_auth(hostname) {
                Ok(Some(auth)) => return Ok(auth),
                Ok(None) => {}
                Err(error) => {
                    tracing::debug!(registry = hostname, error = %error, "failed to resolve registry auth from OS keyring");
                }
            }
        }

        if let Some(auth) = self.resolve_configured_registry_auth(hostname)? {
            return Ok(auth);
        }

        if let Some(auth) = resolve_docker_registry_auth(hostname) {
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

        let source_count = usize::from(entry.store.is_some())
            + usize::from(entry.password_env.is_some())
            + usize::from(entry.secret_name.is_some());

        if source_count == 0 {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "registry auth for {hostname}: entry has no credential source"
            )));
        }

        if source_count > 1 {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "registry auth for {hostname}: entry defines multiple credential sources"
            )));
        }

        if entry.store == Some(RegistryCredentialStore::Keyring) {
            return match lookup_registry_keyring_auth(hostname) {
                Ok(Some(auth)) => Ok(Some(auth)),
                Ok(None) => Err(MicrosandboxError::InvalidConfig(format!(
                    "registry auth for {hostname}: OS keyring entry is missing"
                ))),
                Err(error) => Err(MicrosandboxError::InvalidConfig(format!(
                    "registry auth for {hostname}: failed to read OS keyring entry: {error}"
                ))),
            };
        }

        let password = if let Some(ref env_var) = entry.password_env {
            std::env::var(env_var).map_err(|_| {
                MicrosandboxError::InvalidConfig(format!(
                    "registry auth for {hostname}: environment variable `{env_var}` is not set"
                ))
            })?
        } else if let Some(ref secret_name) = entry.secret_name {
            let secret_path = self.secrets_dir().join("registries").join(secret_name);
            std::fs::read_to_string(&secret_path)
                .map_err(|e| {
                    MicrosandboxError::InvalidConfig(format!(
                        "registry auth for {hostname}: failed to read secret `{}`: {e}",
                        secret_path.display()
                    ))
                })?
                .trim()
                .to_string()
        } else {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "registry auth for {hostname}: entry has no usable credential source"
            )));
        };

        Ok(Some(RegistryAuth::Basic {
            username: entry.username.clone(),
            password,
        }))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: None,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
            busy_timeout_secs: microsandbox_db::pool::DEFAULT_BUSY_TIMEOUT_SECS,
        }
    }
}

impl Default for SandboxDefaults {
    fn default() -> Self {
        Self {
            cpus: DEFAULT_CPUS,
            memory_mib: DEFAULT_MEMORY_MIB,
            shell: "/bin/sh".into(),
            workdir: None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn is_false(v: &bool) -> bool {
    !v
}

fn resolve_docker_registry_auth(hostname: &str) -> Option<RegistryAuth> {
    resolve_registry_auth_with_lookup(hostname, docker_credential::get_credential)
}

fn lookup_registry_keyring_auth(hostname: &str) -> Result<Option<RegistryAuth>, String> {
    let payload = match load_keyring_registry_credential(hostname)? {
        Some(payload) => payload,
        None => return Ok(None),
    };

    Ok(Some(RegistryAuth::Basic {
        username: payload.username,
        password: payload.password,
    }))
}

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

/// Get the global configuration (lazy-loaded from disk on first call).
pub fn config() -> &'static GlobalConfig {
    CONFIG.get_or_init(|| load_config().unwrap_or_default())
}

/// Resolve the path to the persisted global config file.
pub fn config_path() -> PathBuf {
    resolve_default_home().join(microsandbox_utils::CONFIG_FILENAME)
}

/// Load the persisted config file or return the default config if it does not exist.
pub fn load_persisted_config_or_default() -> MicrosandboxResult<GlobalConfig> {
    let path = config_path();
    if !path.exists() {
        return Ok(GlobalConfig::default());
    }

    read_config_from(&path)
}

/// Persist the provided global config to disk as pretty JSON.
pub fn save_persisted_config(config: &GlobalConfig) -> MicrosandboxResult<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            MicrosandboxError::Custom(format!(
                "failed to create config directory `{}`: {e}",
                parent.display()
            ))
        })?;
    }

    let content = serde_json::to_string_pretty(config)
        .map_err(|e| MicrosandboxError::Custom(format!("failed to serialize config: {e}")))?;

    std::fs::write(&path, format!("{content}\n")).map_err(|e| {
        MicrosandboxError::Custom(format!("failed to write config `{}`: {e}", path.display()))
    })?;
    Ok(())
}

/// Store registry credentials in the OS keyring for interactive local use.
pub fn set_registry_keyring_auth(
    hostname: &str,
    username: &str,
    password: &str,
) -> MicrosandboxResult<()> {
    store_registry_keyring_auth(hostname, username, password).map_err(MicrosandboxError::Custom)
}

/// Load registry credentials from the OS keyring, if present.
pub fn get_registry_keyring_auth(hostname: &str) -> MicrosandboxResult<Option<RegistryAuth>> {
    lookup_registry_keyring_auth(hostname).map_err(MicrosandboxError::Custom)
}

/// Delete registry credentials from the OS keyring if they exist.
pub fn delete_registry_keyring_auth(hostname: &str) -> MicrosandboxResult<()> {
    remove_registry_keyring_auth(hostname).map_err(MicrosandboxError::Custom)
}

/// Override the global configuration programmatically.
///
/// Must be called before the first call to [`config()`]. Returns `Err` with the
/// provided config if the global has already been initialized.
#[allow(clippy::result_large_err)]
pub fn set_config(config: GlobalConfig) -> Result<(), GlobalConfig> {
    CONFIG.set(config)
}

/// Resolve the path to the `msb` binary.
///
/// Resolution order:
/// 1. `MSB_PATH` environment variable
/// 2. `config().paths.msb`
/// 3. workspace-local `build/msb` or `target/debug/msb` (debug builds only)
/// 4. `~/.microsandbox/bin/msb`
/// 5. `which::which("msb")`
pub fn resolve_msb_path() -> MicrosandboxResult<PathBuf> {
    if let Ok(path) = std::env::var("MSB_PATH") {
        tracing::debug!(path = %path, source = "MSB_PATH env", "resolved msb binary");
        return Ok(PathBuf::from(path));
    }

    if let Some(path) = &config().paths.msb {
        tracing::debug!(path = %path.display(), source = "config.paths.msb", "resolved msb binary");
        return Ok(path.clone());
    }

    // Only probe workspace-local dev builds in debug builds to prevent
    // binary hijacking from untrusted parent directories in production.
    #[cfg(debug_assertions)]
    {
        let mut local_candidates = Vec::new();
        if let Ok(current_dir) = std::env::current_dir() {
            local_candidates.extend(dev_msb_candidates_from(&current_dir));
        }
        if let Ok(current_exe) = std::env::current_exe()
            && let Some(exe_dir) = current_exe.parent()
        {
            local_candidates.extend(dev_msb_candidates_from(exe_dir));
        }
        dedupe_paths(&mut local_candidates);

        if let Some(path) = local_candidates.iter().find(|path| path.is_file()) {
            tracing::debug!(path = %path.display(), source = "workspace-local msb", "resolved msb binary");
            return Ok(path.clone());
        }
    }

    // Check ~/.microsandbox/bin/msb.
    let home_bin = config()
        .home()
        .join(microsandbox_utils::BIN_SUBDIR)
        .join(microsandbox_utils::MSB_BINARY);
    if home_bin.is_file() {
        tracing::debug!(path = %home_bin.display(), source = "~/.microsandbox/bin/msb", "resolved msb binary");
        return Ok(home_bin);
    }

    let path = which::which(microsandbox_utils::MSB_BINARY).map_err(|_| {
        MicrosandboxError::Custom(
            "msb binary not found. Run `cargo clean -p microsandbox && cargo build` to reinstall, \
             or set MSB_PATH to the binary location"
                .into(),
        )
    })?;
    tracing::debug!(path = %path.display(), source = "PATH lookup", "resolved msb binary");
    Ok(path)
}

/// Resolve the path to `libkrunfw`.
///
/// Resolution order:
/// 1. `config().paths.libkrunfw`
/// 2. A sibling of the resolved `msb` binary (for `build/msb`)
/// 3. `../lib/` next to the resolved `msb` binary (for installed layouts)
/// 4. `{home}/lib/libkrunfw.{so,dylib}`
pub fn resolve_libkrunfw_path() -> MicrosandboxResult<PathBuf> {
    if let Some(path) = &config().paths.libkrunfw {
        if path.is_file() {
            return Ok(path.clone());
        }
        return Err(MicrosandboxError::LibkrunfwNotFound(format!(
            "configured path does not exist: {}",
            path.display()
        )));
    }

    let os = if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    let filename = microsandbox_utils::libkrunfw_filename(os);
    let home_fallback = config()
        .home()
        .join(microsandbox_utils::LIB_SUBDIR)
        .join(&filename);

    let mut candidates = Vec::new();
    if let Ok(msb_path) = resolve_msb_path() {
        candidates.extend(libkrunfw_candidates_from_msb(&msb_path, &filename));
    }
    candidates.push(home_fallback);

    if let Some(path) = candidates.iter().find(|path| path.is_file()) {
        tracing::debug!(path = %path.display(), "resolved libkrunfw path");
        return Ok(path.clone());
    }

    let searched = candidates
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(MicrosandboxError::LibkrunfwNotFound(format!(
        "searched: {searched}"
    )))
}

fn libkrunfw_candidates_from_msb(msb_path: &Path, filename: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(msb_dir) = msb_path.parent() {
        candidates.push(msb_dir.join(filename));

        if let Some(parent) = msb_dir.parent() {
            candidates.push(parent.join(microsandbox_utils::LIB_SUBDIR).join(filename));
        }
    }

    let mut deduped = Vec::new();
    for path in candidates {
        if !deduped.iter().any(|existing| existing == &path) {
            deduped.push(path);
        }
    }

    deduped
}

#[cfg(debug_assertions)]
fn dev_msb_candidates_from(start: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    for ancestor in start.ancestors() {
        if !ancestor.join("Cargo.toml").is_file() {
            continue;
        }

        candidates.push(ancestor.join("build").join(microsandbox_utils::MSB_BINARY));
    }

    dedupe_paths(&mut candidates);
    candidates
}

#[cfg(debug_assertions)]
fn dedupe_paths(paths: &mut Vec<PathBuf>) {
    let mut deduped = Vec::new();
    for path in paths.drain(..) {
        if !deduped.iter().any(|existing| existing == &path) {
            deduped.push(path);
        }
    }
    *paths = deduped;
}

fn dedupe_strings(values: &mut Vec<String>) {
    let mut deduped = Vec::new();
    for value in values.drain(..) {
        if !deduped.iter().any(|existing| existing == &value) {
            deduped.push(value);
        }
    }
    *values = deduped;
}

fn read_config_from(path: &Path) -> MicrosandboxResult<GlobalConfig> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        MicrosandboxError::Custom(format!("failed to read config `{}`: {e}", path.display()))
    })?;

    serde_json::from_str(&content).map_err(|e| {
        MicrosandboxError::InvalidConfig(format!(
            "failed to parse config `{}`: {e}",
            path.display()
        ))
    })
}

/// Resolve the default home directory (`~/.microsandbox`).
fn resolve_default_home() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(microsandbox_utils::BASE_DIR_NAME)
}

/// Load config from the default config file path.
fn load_config() -> Option<GlobalConfig> {
    let path = config_path();
    load_config_from(&path)
}

/// Load config from a specific file path.
fn load_config_from(path: &Path) -> Option<GlobalConfig> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

#[cfg(all(
    feature = "keyring",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
fn store_registry_keyring_auth(
    hostname: &str,
    username: &str,
    password: &str,
) -> Result<(), String> {
    let entry = keyring::Entry::new(REGISTRY_KEYRING_SERVICE, hostname)
        .map_err(|e| format!("failed to open OS credential store entry for `{hostname}`: {e}"))?;

    let payload = serde_json::to_vec(&KeyringRegistryCredential {
        username: username.to_string(),
        password: password.to_string(),
    })
    .map_err(|e| format!("failed to serialize keyring credential for `{hostname}`: {e}"))?;

    entry
        .set_secret(&payload)
        .map_err(|e| format!("failed to store OS credential for `{hostname}`: {e}"))
}

#[cfg(not(all(
    feature = "keyring",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
)))]
fn store_registry_keyring_auth(
    hostname: &str,
    _username: &str,
    _password: &str,
) -> Result<(), String> {
    Err(keyring_unavailable_message(hostname))
}

#[cfg(all(
    feature = "keyring",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
fn load_keyring_registry_credential(
    hostname: &str,
) -> Result<Option<KeyringRegistryCredential>, String> {
    let entry = keyring::Entry::new(REGISTRY_KEYRING_SERVICE, hostname)
        .map_err(|e| format!("failed to open OS credential store entry for `{hostname}`: {e}"))?;

    let payload = match entry.get_secret() {
        Ok(payload) => payload,
        Err(keyring::Error::NoEntry) => return Ok(None),
        Err(error) => {
            return Err(format!(
                "failed to read OS credential for `{hostname}`: {error}"
            ));
        }
    };

    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|e| format!("failed to decode OS credential for `{hostname}`: {e}"))
}

#[cfg(not(all(
    feature = "keyring",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
)))]
fn load_keyring_registry_credential(
    hostname: &str,
) -> Result<Option<KeyringRegistryCredential>, String> {
    Err(keyring_unavailable_message(hostname))
}

#[cfg(all(
    feature = "keyring",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
fn remove_registry_keyring_auth(hostname: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(REGISTRY_KEYRING_SERVICE, hostname)
        .map_err(|e| format!("failed to open OS credential store entry for `{hostname}`: {e}"))?;

    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(format!(
            "failed to delete OS credential for `{hostname}`: {error}"
        )),
    }
}

#[cfg(not(all(
    feature = "keyring",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
)))]
fn remove_registry_keyring_auth(hostname: &str) -> Result<(), String> {
    Err(keyring_unavailable_message(hostname))
}

#[cfg(not(all(
    feature = "keyring",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
)))]
fn keyring_unavailable_message(hostname: &str) -> String {
    #[cfg(not(feature = "keyring"))]
    {
        return format!(
            "secure OS credential storage is disabled; enable the `keyring` feature to use it for `{hostname}`"
        );
    }

    #[cfg(all(
        feature = "keyring",
        not(any(target_os = "linux", target_os = "macos", target_os = "windows"))
    ))]
    format!("secure OS credential storage is not supported on this platform for `{hostname}`")
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;

    #[test]
    fn test_default_config() {
        let cfg = GlobalConfig::default();
        assert_eq!(cfg.sandbox_defaults.cpus, 1);
        assert_eq!(cfg.sandbox_defaults.memory_mib, 512);
        assert_eq!(cfg.sandbox_defaults.shell, "/bin/sh");
        assert_eq!(cfg.log_level, None);
        assert_eq!(cfg.database.max_connections, 5);
        assert_eq!(cfg.database.connect_timeout_secs, 30);
        assert_eq!(cfg.database.busy_timeout_secs, 5);
    }

    #[test]
    fn test_deserialize_empty_json() {
        let cfg: GlobalConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.sandbox_defaults.cpus, 1);
        assert!(cfg.home.is_none());
    }

    #[test]
    fn test_deserialize_partial_json() {
        let json = r#"{"sandbox_defaults": {"cpus": 4}}"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.sandbox_defaults.cpus, 4);
        assert_eq!(cfg.sandbox_defaults.memory_mib, 512);
    }

    #[test]
    fn test_deserialize_log_level() {
        let json = r#"{"log_level":"debug"}"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.log_level, Some(LogLevel::Debug));
    }

    #[test]
    fn test_deserialize_database_config() {
        let json = r#"{
            "database": {
                "max_connections": 9,
                "connect_timeout_secs": 7,
                "busy_timeout_secs": 12
            }
        }"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.database.max_connections, 9);
        assert_eq!(cfg.database.connect_timeout_secs, 7);
        assert_eq!(cfg.database.busy_timeout_secs, 12);
    }

    #[test]
    fn test_home_resolution() {
        let cfg = GlobalConfig {
            home: Some(PathBuf::from("/custom/home")),
            ..Default::default()
        };
        assert_eq!(cfg.home(), PathBuf::from("/custom/home"));
    }

    #[test]
    fn test_sandboxes_dir_override() {
        let cfg = GlobalConfig {
            paths: PathsConfig {
                sandboxes: Some(PathBuf::from("/custom/sandboxes")),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(cfg.sandboxes_dir(), PathBuf::from("/custom/sandboxes"));
    }

    #[test]
    fn test_load_config_from_missing_file() {
        let result = load_config_from(Path::new("/nonexistent/config.json"));
        assert!(result.is_none());
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

        let loaded = read_config_from(&path).unwrap();
        let entry = loaded
            .registries
            .hosts
            .get("ghcr.io")
            .unwrap()
            .auth
            .as_ref()
            .unwrap();
        assert_eq!(entry.username, "octocat");
        assert_eq!(entry.store, Some(RegistryCredentialStore::Keyring));
    }

    #[test]
    fn test_libkrunfw_candidates_for_build_msb() {
        let msb = PathBuf::from("/repo/build/msb");
        let paths = libkrunfw_candidates_from_msb(&msb, "libkrunfw.5.dylib");
        assert_eq!(paths[0], PathBuf::from("/repo/build/libkrunfw.5.dylib"));
        assert_eq!(paths[1], PathBuf::from("/repo/lib/libkrunfw.5.dylib"));
    }

    #[test]
    fn test_libkrunfw_candidates_for_target_msb() {
        let msb = PathBuf::from("/repo/target/debug/msb");
        let paths = libkrunfw_candidates_from_msb(&msb, "libkrunfw.5.dylib");
        assert_eq!(
            paths[0],
            PathBuf::from("/repo/target/debug/libkrunfw.5.dylib")
        );
        assert_eq!(
            paths[1],
            PathBuf::from("/repo/target/lib/libkrunfw.5.dylib")
        );
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn test_dev_msb_candidates_from_workspace_root() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("Cargo.toml"), "[workspace]\n").unwrap();

        let paths = dev_msb_candidates_from(temp.path());
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], temp.path().join("build").join("msb"));
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
        let cfg = GlobalConfig {
            registries: registries(vec![(
                "ghcr.io",
                RegistryEntry {
                    auth: Some(RegistryAuthEntry {
                        username: "user".to_string(),
                        store: Some(RegistryCredentialStore::Keyring),
                        password_env: Some("GHCR_TOKEN".to_string()),
                        secret_name: None,
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

    #[cfg(not(feature = "keyring"))]
    #[test]
    fn test_resolve_configured_registry_auth_reports_disabled_keyring() {
        let cfg = GlobalConfig {
            registries: RegistriesConfig {
                auth: HashMap::from([(
                    "ghcr.io".to_string(),
                    RegistryAuthEntry {
                        username: "user".to_string(),
                        store: Some(RegistryCredentialStore::Keyring),
                        password_env: None,
                        secret_name: None,
                    },
                )]),
            },
            ..Default::default()
        };

        let error = cfg.resolve_configured_registry_auth("ghcr.io").unwrap_err();
        assert!(error.to_string().contains("enable the `keyring` feature"));
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
