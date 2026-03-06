//! Global configuration for the microsandbox library.
//!
//! Configuration is loaded from `~/.microsandbox/config.json` on first access.
//! All fields have sensible defaults — a missing config file is equivalent to `{}`.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

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
pub struct GlobalConfig {
    /// Root directory for all microsandbox data.
    pub home: Option<PathBuf>,

    /// Log level.
    pub log_level: String,

    /// Database configuration.
    pub database: DatabaseConfig,

    /// Path overrides.
    pub paths: PathsConfig,

    /// Default values for sandbox configuration.
    pub sandbox_defaults: SandboxDefaults,
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
    /// Path to `msb` binary. Resolution: `MSB_PATH` env → this → PATH lookup.
    pub msb: Option<PathBuf>,

    /// Path to `libkrunfw.{so,dylib}`.
    pub libkrunfw: Option<PathBuf>,

    /// Path to `msbnet` binary.
    pub msbnet: Option<PathBuf>,

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

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

static CONFIG: OnceLock<GlobalConfig> = OnceLock::new();

impl GlobalConfig {
    /// Get the resolved home directory.
    pub fn home(&self) -> PathBuf {
        self.home
            .clone()
            .unwrap_or_else(|| resolve_default_home())
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
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            home: None,
            log_level: "info".into(),
            database: DatabaseConfig::default(),
            paths: PathsConfig::default(),
            sandbox_defaults: SandboxDefaults::default(),
        }
    }
}

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
pub fn set_config(config: GlobalConfig) -> Result<(), GlobalConfig> {
    CONFIG.set(config)
}

/// Resolve the path to the `msb` binary.
///
/// Resolution order:
/// 1. `MSB_PATH` environment variable
/// 2. `config().paths.msb`
/// 3. `which::which("msb")`
pub fn resolve_msb_path() -> MicrosandboxResult<PathBuf> {
    if let Ok(path) = std::env::var("MSB_PATH") {
        return Ok(PathBuf::from(path));
    }

    if let Some(path) = &config().paths.msb {
        return Ok(path.clone());
    }

    which::which(microsandbox_utils::MSB_BINARY).map_err(|e| {
        crate::MicrosandboxError::Custom(format!(
            "msb binary not found: set MSB_PATH env var or add msb to PATH ({e})"
        ))
    })
}

/// Resolve the path to `libkrunfw`.
///
/// Resolution order:
/// 1. `config().paths.libkrunfw`
/// 2. `{home}/lib/libkrunfw.{so,dylib}`
pub fn resolve_libkrunfw_path() -> PathBuf {
    if let Some(path) = &config().paths.libkrunfw {
        return path.clone();
    }

    let filename = if cfg!(target_os = "macos") {
        microsandbox_utils::libkrunfw_filename("macos")
    } else {
        microsandbox_utils::libkrunfw_filename("linux")
    };

    config()
        .home()
        .join(microsandbox_utils::LIB_SUBDIR)
        .join(filename)
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
        assert_eq!(cfg.log_level, "info");
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
}
