//! Global configuration for the microsandbox library.
//!
//! Configuration is loaded from `~/.microsandbox/config.json` on first access.
//! All fields have sensible defaults — a missing config file is equivalent to `{}`.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use microsandbox_image::RegistryAuth;
use microsandbox_runtime::logging::LogLevel;
use serde::{Deserialize, Serialize};

use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default number of vCPUs per sandbox.
const DEFAULT_CPUS: u8 = 1;

/// Default guest memory in MiB.
const DEFAULT_MEMORY_MIB: u32 = 512;

/// Default database max connections.
pub(crate) const DEFAULT_MAX_CONNECTIONS: u32 = 5;

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

/// Registry authentication configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RegistriesConfig {
    /// Per-registry authentication entries, keyed by registry hostname.
    ///
    /// Example:
    /// ```json
    /// {
    ///   "registries": {
    ///     "auth": {
    ///       "ghcr.io": { "username": "user", "password_env": "GHCR_TOKEN" },
    ///       "docker.io": { "username": "user", "secret_name": "dockerhub" }
    ///     }
    ///   }
    /// }
    /// ```
    pub auth: HashMap<String, RegistryAuthEntry>,
}

/// A single registry authentication entry from global config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryAuthEntry {
    /// Registry username.
    pub username: String,

    /// Environment variable containing the password/token.
    pub password_env: Option<String>,

    /// Secret name — password is read from `{home}/secrets/registries/<secret_name>`.
    pub secret_name: Option<String>,
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

    /// Resolve registry authentication for a given hostname.
    ///
    /// Looks up `registries.auth` in global config, resolving credentials from
    /// either `password_env` (environment variable) or `secret_name` (file-backed
    /// secret in `{home}/secrets/registries/<name>`).
    ///
    /// Returns `Anonymous` if no entry matches.
    pub fn resolve_registry_auth(&self, hostname: &str) -> MicrosandboxResult<RegistryAuth> {
        let entry = match self.registries.auth.get(hostname) {
            Some(entry) => entry,
            None => return Ok(RegistryAuth::Anonymous),
        };

        let password = if let Some(ref env_var) = entry.password_env {
            std::env::var(env_var).map_err(|_| {
                crate::MicrosandboxError::InvalidConfig(format!(
                    "registry auth for {hostname}: environment variable `{env_var}` is not set"
                ))
            })?
        } else if let Some(ref secret_name) = entry.secret_name {
            let secret_path = self.secrets_dir().join("registries").join(secret_name);
            std::fs::read_to_string(&secret_path)
                .map_err(|e| {
                    crate::MicrosandboxError::InvalidConfig(format!(
                        "registry auth for {hostname}: failed to read secret `{}`: {e}",
                        secret_path.display()
                    ))
                })?
                .trim()
                .to_string()
        } else {
            return Err(crate::MicrosandboxError::InvalidConfig(format!(
                "registry auth for {hostname}: entry has neither `password_env` nor `secret_name`"
            )));
        };

        Ok(RegistryAuth::Basic {
            username: entry.username.clone(),
            password,
        })
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

/// Get the global configuration (lazy-loaded from disk on first call).
pub fn config() -> &'static GlobalConfig {
    CONFIG.get_or_init(|| load_config().unwrap_or_default())
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

    let path = which::which(microsandbox_utils::MSB_BINARY).map_err(|e| {
        crate::MicrosandboxError::Custom(format!(
            "msb binary not found: set MSB_PATH env var or add msb to PATH ({e})"
        ))
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
        return Err(crate::MicrosandboxError::LibkrunfwNotFound(format!(
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
    Err(crate::MicrosandboxError::LibkrunfwNotFound(format!(
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

fn dev_msb_candidates_from(start: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    for ancestor in start.ancestors() {
        if !ancestor.join("Cargo.toml").is_file() {
            continue;
        }

        candidates.push(ancestor.join("build").join(microsandbox_utils::MSB_BINARY));
        candidates.push(
            ancestor
                .join("target")
                .join("debug")
                .join(microsandbox_utils::MSB_BINARY),
        );
    }

    dedupe_paths(&mut candidates);
    candidates
}

fn dedupe_paths(paths: &mut Vec<PathBuf>) {
    let mut deduped = Vec::new();
    for path in paths.drain(..) {
        if !deduped.iter().any(|existing| existing == &path) {
            deduped.push(path);
        }
    }
    *paths = deduped;
}

/// Resolve the default home directory (`~/.microsandbox`).
fn resolve_default_home() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(microsandbox_utils::BASE_DIR_NAME)
}

/// Load config from the default config file path.
fn load_config() -> Option<GlobalConfig> {
    let path = resolve_default_home().join(microsandbox_utils::CONFIG_FILENAME);
    load_config_from(&path)
}

/// Load config from a specific file path.
fn load_config_from(path: &Path) -> Option<GlobalConfig> {
    let content = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = GlobalConfig::default();
        assert_eq!(cfg.sandbox_defaults.cpus, 1);
        assert_eq!(cfg.sandbox_defaults.memory_mib, 512);
        assert_eq!(cfg.sandbox_defaults.shell, "/bin/sh");
        assert_eq!(cfg.log_level, None);
        assert_eq!(cfg.database.max_connections, 5);
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
        assert_eq!(paths[0], temp.path().join("build").join("msb"));
        assert_eq!(
            paths[1],
            temp.path().join("target").join("debug").join("msb")
        );
        assert_eq!(paths.len(), 2);
    }
}
