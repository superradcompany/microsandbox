//! Private persisted-config helpers for CLI commands.

use std::path::Path;

use anyhow::{Context, Result};
use microsandbox::{
    backend::LocalBackend,
    config::{LocalConfig, config_path},
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Load the CLI's persisted local config, defaulting only when the file is absent.
pub(crate) fn load_local_config() -> Result<LocalConfig> {
    let backend = LocalBackend::builder().try_build_lazy()?;
    Ok(backend.config().clone())
}

/// Persist the CLI's local config as pretty JSON.
pub(crate) fn save_local_config(config: &LocalConfig) -> Result<()> {
    save_local_config_to(config, &config_path())
}

fn save_local_config_to(config: &LocalConfig, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config directory `{}`", parent.display()))?;
    }

    let content = serde_json::to_string_pretty(config).context("failed to serialize config")?;
    std::fs::write(path, format!("{content}\n"))
        .with_context(|| format!("failed to write config `{}`", path.display()))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_config_is_pretty_json_with_a_trailing_newline() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nested/config.json");
        let config = LocalConfig::default();

        save_local_config_to(&config, &path).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let loaded: LocalConfig = serde_json::from_str(&content).unwrap();

        assert!(content.ends_with('\n'));
        assert_eq!(
            serde_json::to_value(loaded).unwrap(),
            serde_json::to_value(config).unwrap()
        );
    }
}
