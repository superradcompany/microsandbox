//! `msb ps` command — show running sandboxes (quick view).

use clap::Args;
use microsandbox::sandbox::{Sandbox, SandboxConfig, SandboxStatus};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Show running sandboxes.
#[derive(Debug, Args)]
pub struct PsArgs {
    /// Show all sandboxes (including stopped).
    #[arg(short, long)]
    pub all: bool,

    /// Show only sandbox names.
    #[arg(short, long)]
    pub quiet: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb ps` command.
pub async fn run(args: PsArgs) -> anyhow::Result<()> {
    let sandboxes = Sandbox::list().await?;

    let filtered: Vec<_> = if args.all {
        sandboxes
    } else {
        sandboxes
            .into_iter()
            .filter(|s| {
                s.status() == SandboxStatus::Running || s.status() == SandboxStatus::Draining
            })
            .collect()
    };

    if args.quiet {
        for s in &filtered {
            println!("{}", s.name());
        }
        return Ok(());
    }

    if filtered.is_empty() {
        if args.all {
            eprintln!("No sandboxes found.");
        } else {
            eprintln!("No running sandboxes.");
        }
        return Ok(());
    }

    let mut table = ui::Table::new(&["Name", "Image", "Status"]);

    for s in &filtered {
        let image = extract_image(s.config_json());
        let status = format!("{:?}", s.status());
        table.add_row(vec![
            s.name().to_string(),
            image,
            ui::format_status(&status),
        ]);
    }

    table.print();
    Ok(())
}

/// Extract image name from config JSON.
fn extract_image(config_json: &str) -> String {
    serde_json::from_str::<SandboxConfig>(config_json)
        .ok()
        .map(|c| match c.image {
            microsandbox::sandbox::RootfsSource::Oci(ref s) => s.clone(),
            microsandbox::sandbox::RootfsSource::Bind(ref p) => p.display().to_string(),
            microsandbox::sandbox::RootfsSource::DiskImage { ref path, .. } => {
                path.display().to_string()
            }
        })
        .unwrap_or_else(|| "-".to_string())
}
