//! `msb self` subcommands for managing the msb installation itself.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use console::{Key, Term, style};

use super::install::MARKER as INSTALL_MARKER;
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
    #[arg(short, long)]
    pub force: bool,
}

/// Arguments for `msb self uninstall`.
#[derive(Debug, Args)]
pub struct SelfUninstallArgs {
    /// Skip confirmation prompt and remove everything.
    #[arg(long, short)]
    pub yes: bool,
}

/// A category of data that can be removed during uninstall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UninstallCategory {
    All,
    Sandboxes,
    Volumes,
    Cache,
    Installs,
    Database,
    Logs,
    Secrets,
}

impl UninstallCategory {
    const ITEMS: &[Self] = &[
        Self::All,
        Self::Sandboxes,
        Self::Volumes,
        Self::Cache,
        Self::Installs,
        Self::Database,
        Self::Logs,
        Self::Secrets,
    ];

    fn label(&self) -> &'static str {
        match self {
            Self::All => "All — remove everything and clean shell config",
            Self::Sandboxes => "Sandboxes — sandbox state and rootfs",
            Self::Volumes => "Volumes — named volumes",
            Self::Cache => "Cache — OCI image layers",
            Self::Installs => "Installs — installed command aliases",
            Self::Database => "Database — metadata store",
            Self::Logs => "Logs — log files",
            Self::Secrets => "Secrets — secrets, TLS certs, and SSH keys",
        }
    }

    fn short_name(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Sandboxes => "sandboxes",
            Self::Volumes => "volumes",
            Self::Cache => "cache",
            Self::Installs => "installs",
            Self::Database => "database",
            Self::Logs => "logs",
            Self::Secrets => "secrets",
        }
    }
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
        done("Already up to date.");
        return Ok(());
    }

    let base_dir = resolve_base_dir()?;
    let bin_dir = base_dir.join(microsandbox_utils::BIN_SUBDIR);
    let lib_dir = base_dir.join(microsandbox_utils::LIB_SUBDIR);

    let spinner = ui::Spinner::start("Updating", &format!("to {latest}"));
    let result = microsandbox::setup::Setup::builder()
        .base_dir(base_dir)
        .version(latest_clean.to_string())
        .force(true)
        .build()
        .install()
        .await;

    match result {
        Ok(()) => {
            spinner.finish_clear();
            done(&format!("Updated msb in {}", bin_dir.display()));
            done(&format!("Updated libkrunfw in {}/", lib_dir.display()));
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

    // Non-interactive: remove everything.
    if args.yes {
        return uninstall_all(&base_dir);
    }

    let term = Term::stderr();
    if !term.is_term() {
        anyhow::bail!("non-interactive terminal; use --yes to remove everything");
    }

    ui::warn(&format!(
        "this will modify your {} installation",
        base_dir.display(),
    ));

    let labels: Vec<&str> = UninstallCategory::ITEMS.iter().map(|c| c.label()).collect();
    let selections = multi_select(&term, &labels)?;

    if selections.is_empty() {
        info("Nothing selected.");
        return Ok(());
    }

    let selected: Vec<UninstallCategory> = selections
        .iter()
        .map(|&i| UninstallCategory::ITEMS[i])
        .collect();

    let is_all = selected.contains(&UninstallCategory::All);

    // Confirmation.
    let prompt = if is_all {
        "Remove everything?".to_string()
    } else {
        let names: Vec<&str> = selected.iter().map(|c| c.short_name()).collect();
        format!("Remove {}?", names.join(", "))
    };
    eprint!("{prompt} [y/N] ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if !input.trim().eq_ignore_ascii_case("y") {
        info("Aborted.");
        return Ok(());
    }

    if is_all {
        uninstall_all(&base_dir)?;
    } else {
        for category in &selected {
            remove_category(&base_dir, *category)?;
        }
    }

    Ok(())
}

/// Remove everything: shell config + entire base directory.
fn uninstall_all(base_dir: &Path) -> anyhow::Result<()> {
    clean_shell_config()?;
    std::fs::remove_dir_all(base_dir)?;
    ui::success("Removed", &base_dir.display().to_string());
    done("Uninstall complete. Restart your shell to apply changes.");
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Multi-Select
//--------------------------------------------------------------------------------------------------

/// SIGINT handler that restores cursor visibility before exiting.
extern "C" fn sigint_show_cursor(_: libc::c_int) {
    let _ = std::io::stderr().write_all(b"\x1b[?25h");
    unsafe { libc::_exit(130) };
}

/// RAII guard that installs a SIGINT handler to restore cursor visibility
/// and restores the previous handler on drop.
struct SigintGuard {
    prev: libc::sighandler_t,
}

impl SigintGuard {
    fn install() -> Self {
        let prev = unsafe {
            libc::signal(
                libc::SIGINT,
                sigint_show_cursor as *const () as libc::sighandler_t,
            )
        };
        Self { prev }
    }
}

impl Drop for SigintGuard {
    fn drop(&mut self) {
        unsafe {
            libc::signal(libc::SIGINT, self.prev);
        }
    }
}

/// Interactive multi-select prompt. Returns indices of selected items.
///
/// Index 0 is treated as an "All" toggle: selecting it checks every item,
/// deselecting it unchecks every item. When all individual items are checked,
/// "All" is auto-checked; unchecking any individual item unchecks "All".
fn multi_select(term: &Term, items: &[&str]) -> anyhow::Result<Vec<usize>> {
    let mut selected = vec![false; items.len()];
    let mut cursor = 0usize;

    let _sigint = SigintGuard::install();
    term.hide_cursor()?;
    let mut lines = render_select(term, items, &selected, cursor)?;

    loop {
        match term.read_key()? {
            Key::ArrowUp | Key::Char('k') => {
                cursor = cursor.saturating_sub(1);
            }
            Key::ArrowDown | Key::Char('j') => {
                cursor = (cursor + 1).min(items.len() - 1);
            }
            Key::Char(' ') => {
                toggle_select(&mut selected, cursor);
            }
            Key::Enter => break,
            Key::Escape => {
                selected.fill(false);
                break;
            }
            _ => continue,
        }

        term.clear_last_lines(lines)?;
        lines = render_select(term, items, &selected, cursor)?;
    }

    term.clear_last_lines(lines)?;
    term.show_cursor()?;

    Ok(selected
        .iter()
        .enumerate()
        .filter(|&(_, &s)| s)
        .map(|(i, _)| i)
        .collect())
}

/// Render the multi-select list. Returns the number of lines written.
fn render_select(
    term: &Term,
    items: &[&str],
    selected: &[bool],
    cursor: usize,
) -> anyhow::Result<usize> {
    let mut lines = 0;

    for (i, item) in items.iter().enumerate() {
        let pointer = if i == cursor { ">" } else { " " };
        let check = if selected[i] {
            format!("{}", style("[x]").green())
        } else {
            format!("{}", style("[ ]").dim())
        };
        let label = if i == cursor {
            style(*item).bold().to_string()
        } else {
            item.to_string()
        };
        term.write_line(&format!("  {pointer} {check} {label}"))?;
        lines += 1;
    }

    term.write_line(&format!(
        "  {}",
        style("↑↓ navigate · space select · enter confirm · esc cancel").dim(),
    ))?;
    lines += 1;

    Ok(lines)
}

/// Toggle selection at the given cursor position, with "All" (index 0) linkage.
fn toggle_select(selected: &mut [bool], cursor: usize) {
    selected[cursor] = !selected[cursor];

    if cursor == 0 {
        // "All" toggled — propagate to every individual item.
        let state = selected[0];
        for s in selected.iter_mut().skip(1) {
            *s = state;
        }
    } else if !selected[cursor] {
        // Unchecked an individual → uncheck "All".
        selected[0] = false;
    } else if selected[1..].iter().all(|&s| s) {
        // All individuals now checked → auto-check "All".
        selected[0] = true;
    }
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
    eprintln!("{} {msg}", style("info").cyan().bold());
}

fn done(msg: &str) {
    eprintln!("{} {msg}", style("done").green().bold());
}

/// Remove a single uninstall category from the base directory.
fn remove_category(base_dir: &Path, category: UninstallCategory) -> anyhow::Result<()> {
    match category {
        UninstallCategory::All => unreachable!("handled before calling remove_category"),
        UninstallCategory::Sandboxes => {
            remove_subdir(base_dir, microsandbox_utils::SANDBOXES_SUBDIR, "sandboxes")
        }
        UninstallCategory::Volumes => {
            remove_subdir(base_dir, microsandbox_utils::VOLUMES_SUBDIR, "volumes")
        }
        UninstallCategory::Cache => {
            remove_subdir(base_dir, microsandbox_utils::CACHE_SUBDIR, "cache")
        }
        UninstallCategory::Installs => remove_installed_aliases(base_dir),
        UninstallCategory::Database => {
            remove_subdir(base_dir, microsandbox_utils::DB_SUBDIR, "database")
        }
        UninstallCategory::Logs => remove_subdir(base_dir, microsandbox_utils::LOGS_SUBDIR, "logs"),
        UninstallCategory::Secrets => {
            remove_subdir(base_dir, microsandbox_utils::SECRETS_SUBDIR, "secrets")?;
            remove_subdir(base_dir, microsandbox_utils::TLS_SUBDIR, "tls")?;
            remove_subdir(base_dir, microsandbox_utils::SSH_SUBDIR, "ssh")
        }
    }
}

/// Remove a subdirectory within the base directory.
fn remove_subdir(base_dir: &Path, subdir: &str, label: &str) -> anyhow::Result<()> {
    let path = base_dir.join(subdir);
    if path.exists() {
        std::fs::remove_dir_all(&path)?;
        ui::success("Removed", label);
    }
    Ok(())
}

/// Remove only msb-install-generated alias scripts from the bin directory,
/// leaving core binaries (msb, agentd) intact.
fn remove_installed_aliases(base_dir: &Path) -> anyhow::Result<()> {
    let bin_dir = base_dir.join(microsandbox_utils::BIN_SUBDIR);
    if !bin_dir.is_dir() {
        return Ok(());
    }

    for entry in std::fs::read_dir(&bin_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(&path)
            && content.lines().nth(1) == Some(INSTALL_MARKER)
        {
            std::fs::remove_file(&path)?;
            let name = entry.file_name().to_string_lossy().to_string();
            ui::success("Removed", &format!("alias {name}"));
        }
    }

    Ok(())
}

/// Remove microsandbox marker blocks from shell config files.
fn clean_shell_config() -> anyhow::Result<()> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("no home dir"))?;

    for rc in [".profile", ".bash_profile", ".bashrc", ".zshrc"] {
        let path = home.join(rc);
        if path.exists() && remove_marker_block(&path)? {
            ui::success("Cleaned", &format!("~/{rc}"));
        }
    }

    let fish_conf = home.join(".config/fish/conf.d/microsandbox.fish");
    if fish_conf.exists() {
        std::fs::remove_file(&fish_conf)?;
        ui::success("Removed", "~/.config/fish/conf.d/microsandbox.fish");
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
