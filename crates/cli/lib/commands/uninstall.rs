//! `msb uninstall` command — remove an installed sandbox alias.

use std::fs;

use clap::Args;
use microsandbox::config;

use super::install::MARKER;
use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Remove an installed sandbox command.
#[derive(Debug, Args)]
pub struct UninstallArgs {
    /// Command(s) to remove.
    #[arg(required = true)]
    pub names: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb uninstall` command.
pub async fn run(args: UninstallArgs) -> anyhow::Result<()> {
    let bin_dir = config::config().home().join("bin");

    let mut failed = false;

    for name in &args.names {
        if name.contains('/') || name.contains("..") {
            ui::error(&format!("invalid alias name '{name}'"));
            failed = true;
            continue;
        }

        let path = bin_dir.join(name);

        if !path.exists() {
            ui::error(&format!("alias '{name}' not found"));
            failed = true;
            continue;
        }

        // Validate it's an msb-generated script (marker must be on line 2).
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                ui::error(&format!("failed to read '{name}': {e}"));
                failed = true;
                continue;
            }
        };
        let is_msb_script = content.lines().nth(1) == Some(MARKER);
        if !is_msb_script {
            ui::error(&format!("'{name}' is not an msb-installed alias"));
            failed = true;
            continue;
        }

        match fs::remove_file(&path) {
            Ok(()) => ui::success("Uninstalled", name),
            Err(e) => {
                ui::error(&format!("failed to remove '{name}': {e}"));
                failed = true;
            }
        }
    }

    if failed {
        anyhow::bail!("some aliases failed to uninstall");
    }

    Ok(())
}
