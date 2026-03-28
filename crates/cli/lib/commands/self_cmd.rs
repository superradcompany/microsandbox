//! `msb self` subcommands for managing the msb installation itself.

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

const MARKER_START: &str = "# >>> microsandbox >>>";
const MARKER_END: &str = "# <<< microsandbox <<<";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Update or uninstall msb.
#[derive(Debug, Args)]
pub struct SelfArgs {
    /// Subcommand to run.
    #[command(subcommand)]
    pub command: SelfCommand,
}

/// `msb self` subcommands.
#[derive(Debug, Subcommand)]
pub enum SelfCommand {
    /// Update msb and libkrunfw to the latest release.
    #[command(visible_alias = "upgrade")]
    Update(SelfUpdateArgs),

    /// Remove msb, libkrunfw, and shell configuration.
    Uninstall(SelfUninstallArgs),
}

/// Arguments for `msb self update`.
#[derive(Debug, Args)]
pub struct SelfUpdateArgs {
    /// Re-download even if already on the latest version.
    #[arg(long)]
    pub force: bool,
}

/// Arguments for `msb self uninstall`.
#[derive(Debug, Args)]
pub struct SelfUninstallArgs {
    /// Skip confirmation prompt.
    #[arg(long, short)]
    pub yes: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run a `msb self` subcommand.
pub async fn run(args: SelfArgs) -> anyhow::Result<()> {
    match args.command {
        SelfCommand::Update(args) => run_update(args).await,
        SelfCommand::Uninstall(args) => run_uninstall(args).await,
    }
}

async fn run_update(args: SelfUpdateArgs) -> anyhow::Result<()> {
    info(&format!("Current version: v{CURRENT_VERSION}"));

    let spinner = ui::Spinner::start("Checking", "latest release");
    let latest = fetch_latest_version().await?;
    spinner.finish_clear();

    info(&format!("Latest version: {latest}"));

    let latest_clean = latest.strip_prefix('v').unwrap_or(&latest);
    if !args.force && latest_clean == CURRENT_VERSION {
        success("Already up to date.");
        return Ok(());
    }

    let base_dir = resolve_base_dir()?;
    let bin_dir = base_dir.join(microsandbox_utils::BIN_SUBDIR);
    let lib_dir = base_dir.join(microsandbox_utils::LIB_SUBDIR);

    let spinner = ui::Spinner::start("Updating", &format!("to {latest}"));
    let result = microsandbox::setup::Setup::builder()
        .base_dir(base_dir)
        .force(true)
        .build()
        .install()
        .await;

    match result {
        Ok(()) => {
            spinner.finish_clear();
            success(&format!("Updated msb in {}", bin_dir.display()));
            success(&format!("Updated libkrunfw in {}/", lib_dir.display()));
        }
        Err(e) => {
            spinner.finish_error();
            anyhow::bail!("update failed: {e}");
        }
    }

    Ok(())
}

async fn run_uninstall(args: SelfUninstallArgs) -> anyhow::Result<()> {
    let base_dir = resolve_base_dir()?;

    if !base_dir.exists() {
        info("Nothing to uninstall.");
        return Ok(());
    }

    if !args.yes {
        eprintln!(
            "{} This will remove {} and clean shell configuration.",
            console::style("warn").yellow().bold(),
            base_dir.display(),
        );
        eprint!("Continue? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            info("Aborted.");
            return Ok(());
        }
    }

    // Remove shell configuration first.
    clean_shell_config()?;

    // Remove the installation directory.
    std::fs::remove_dir_all(&base_dir)?;
    success(&format!("Removed {}", base_dir.display()));

    success("Uninstall complete. Restart your shell to apply changes.");

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Fetch the latest release tag from GitHub.
async fn fetch_latest_version() -> anyhow::Result<String> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/releases/latest",
        microsandbox_utils::GITHUB_ORG,
        microsandbox_utils::MICROSANDBOX_REPO,
    );

    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .get(&url)
        .header("User-Agent", format!("msb/{CURRENT_VERSION}"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let tag = resp["tag_name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("could not parse latest release tag"))?;

    Ok(tag.to_string())
}

fn resolve_base_dir() -> anyhow::Result<PathBuf> {
    dirs::home_dir()
        .map(|h| h.join(microsandbox_utils::BASE_DIR_NAME))
        .ok_or_else(|| anyhow::anyhow!("could not determine home directory"))
}

fn info(msg: &str) {
    eprintln!("{} {msg}", console::style("info").cyan().bold());
}

fn success(msg: &str) {
    eprintln!("{} {msg}", console::style("done").green().bold());
}

/// Remove microsandbox marker blocks from shell config files.
fn clean_shell_config() -> anyhow::Result<()> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("no home dir"))?;

    for rc in [".profile", ".bash_profile", ".bashrc", ".zshrc"] {
        let path = home.join(rc);
        if path.exists() && remove_marker_block(&path)? {
            success(&format!("Cleaned ~/{rc}"));
        }
    }

    let fish_conf = home.join(".config/fish/conf.d/microsandbox.fish");
    if fish_conf.exists() {
        std::fs::remove_file(&fish_conf)?;
        success("Removed ~/.config/fish/conf.d/microsandbox.fish");
    }

    Ok(())
}

/// Remove the marker block from a shell config file. Returns true if modified.
fn remove_marker_block(path: &Path) -> anyhow::Result<bool> {
    let content = std::fs::read_to_string(path)?;
    if !content.contains(MARKER_START) {
        return Ok(false);
    }

    let mut result = String::new();
    let mut skip = false;
    for line in content.lines() {
        if line.contains(MARKER_START) {
            skip = true;
            continue;
        }
        if line.contains(MARKER_END) {
            skip = false;
            continue;
        }
        if !skip {
            result.push_str(line);
            result.push('\n');
        }
    }

    std::fs::write(path, result)?;
    Ok(true)
}
