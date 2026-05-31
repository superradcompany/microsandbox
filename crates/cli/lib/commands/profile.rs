//! `msb profile` command — manage SDK backend profiles.
//!
//! Profiles are stored in `~/.microsandbox/config.json` under the
//! `active_profile` + `profiles` keys. Each profile selects a backend (local
//! or cloud) and, for cloud, provides a URL + an `api_key_ref` (env / inline /
//! keyring — see `microsandbox::Profile`).
//!
//! The CLI inherits backend selection from the SDK; profile management is the
//! only CLI-side surface (`msb profile list / use / show`).

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use microsandbox::{Profile, ProfileBackend, SdkConfig, load_sdk_config};
use serde_json::Value;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Manage SDK backend profiles.
#[derive(Debug, Args)]
pub struct ProfileArgs {
    /// Profile subcommand to run.
    #[command(subcommand)]
    pub command: ProfileCommands,
}

/// Profile subcommands.
#[derive(Debug, Subcommand)]
pub enum ProfileCommands {
    /// List configured profiles, marking the active one.
    #[command(visible_alias = "ls")]
    List(ProfileListArgs),

    /// Show details of a profile (does not print secrets — only the `api_key_ref` is shown).
    Show(ProfileShowArgs),

    /// Set the active profile.
    Use(ProfileUseArgs),
}

/// Arguments for `msb profile list`.
#[derive(Debug, Args, Default)]
pub struct ProfileListArgs {}

/// Arguments for `msb profile show`.
#[derive(Debug, Args)]
pub struct ProfileShowArgs {
    /// Profile name. Defaults to the currently active profile.
    pub name: Option<String>,
}

/// Arguments for `msb profile use`.
#[derive(Debug, Args)]
pub struct ProfileUseArgs {
    /// Profile name to activate. Must exist in `~/.microsandbox/config.json`.
    pub name: String,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb profile` command.
pub async fn run(args: ProfileArgs) -> Result<()> {
    match args.command {
        ProfileCommands::List(args) => run_list(args),
        ProfileCommands::Show(args) => run_show(args),
        ProfileCommands::Use(args) => run_use(args),
    }
}

fn run_list(_args: ProfileListArgs) -> Result<()> {
    let cfg = load_sdk_config().context("load SDK config")?;
    if cfg.profiles.is_empty() {
        println!("no profiles configured");
        println!(
            "  add one to {} under \"profiles\":",
            microsandbox::config::config_path().display()
        );
        println!(
            r#"    {{ "active_profile": "prod", "profiles": {{ "prod": {{ "backend": "cloud", "url": "https://msb.example.com", "api_key_ref": "env:MSB_API_KEY" }} }} }}"#
        );
        return Ok(());
    }

    let active = cfg.active_profile.as_deref();
    let mut names: Vec<&String> = cfg.profiles.keys().collect();
    names.sort();
    for name in names {
        let profile = &cfg.profiles[name];
        let marker = if Some(name.as_str()) == active {
            "*"
        } else {
            " "
        };
        let kind = match profile.backend {
            ProfileBackend::Local => "local".to_string(),
            ProfileBackend::Cloud => match &profile.url {
                Some(url) => format!("cloud  {url}"),
                None => "cloud  (no url!)".to_string(),
            },
        };
        println!("{marker} {name:20}  {kind}");
    }
    Ok(())
}

fn run_show(args: ProfileShowArgs) -> Result<()> {
    let cfg = load_sdk_config().context("load SDK config")?;
    let name = args
        .name
        .or(cfg.active_profile.clone())
        .ok_or_else(|| anyhow::anyhow!("no profile name given and no active profile is set"))?;
    let profile = cfg
        .profiles
        .get(&name)
        .ok_or_else(|| anyhow::anyhow!("profile {name:?} not found"))?;
    print_profile(&name, profile, cfg.active_profile.as_deref() == Some(&name));
    Ok(())
}

fn run_use(args: ProfileUseArgs) -> Result<()> {
    // Verify the profile exists before activating.
    let cfg = load_sdk_config().context("load SDK config")?;
    if !cfg.profiles.contains_key(&args.name) {
        anyhow::bail!(
            "profile {:?} not found in {}",
            args.name,
            microsandbox::config::config_path().display()
        );
    }
    set_active_profile(&args.name)?;
    println!("Active profile set to {:?}.", args.name);
    Ok(())
}

/// Read `~/.microsandbox/config.json` as raw JSON, set `active_profile`,
/// write it back. Preserves all other keys (including `LocalConfig` fields,
/// which live in the same file).
fn set_active_profile(name: &str) -> Result<()> {
    let path = microsandbox::config::config_path();
    let mut value: Value = if path.exists() {
        let raw =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parse {} as JSON", path.display()))?
    } else {
        Value::Object(serde_json::Map::new())
    };

    // Promote to object if it isn't already.
    let obj = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("config file root must be a JSON object"))?;
    obj.insert("active_profile".into(), Value::String(name.to_string()));

    // Ensure parent dir exists (matches save_persisted_config behaviour).
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create config dir {}", parent.display()))?;
    }
    let serialised = serde_json::to_string_pretty(&value).context("re-serialise config JSON")?;
    std::fs::write(&path, serialised).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn print_profile(name: &str, profile: &Profile, is_active: bool) {
    println!("{}{}", if is_active { "* " } else { "  " }, name);
    match profile.backend {
        ProfileBackend::Local => println!("  backend      local"),
        ProfileBackend::Cloud => {
            println!("  backend      cloud");
            println!(
                "  url          {}",
                profile.url.as_deref().unwrap_or("(missing!)")
            );
            println!(
                "  api_key_ref  {}",
                profile
                    .api_key_ref
                    .as_deref()
                    .map(redact_api_key_ref)
                    .unwrap_or("(missing!)")
            );
        }
    }
}

fn redact_api_key_ref(api_key_ref: &str) -> &str {
    if api_key_ref.trim_start().starts_with("inline:") {
        return "inline:<redacted>";
    }
    api_key_ref
}

// Suppress unused warnings — `SdkConfig` is re-exported for completeness even
// when its fields aren't read directly here.
const _: fn() -> SdkConfig = SdkConfig::default;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_api_key_ref_hides_inline_secret() {
        assert_eq!(
            redact_api_key_ref("inline:msb_live_secret"),
            "inline:<redacted>"
        );
        assert_eq!(
            redact_api_key_ref("  inline:msb_live_secret"),
            "inline:<redacted>"
        );
        assert_eq!(redact_api_key_ref("env:MSB_API_KEY"), "env:MSB_API_KEY");
    }
}
