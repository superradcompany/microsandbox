//! `msb list` command — list all sandboxes.

use clap::Args;
use microsandbox::sandbox::{Sandbox, SandboxConfig, SandboxHandle, SandboxStatus};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// List all stored sandboxes.
#[derive(Debug, Args)]
pub struct ListArgs {
    /// Show only running sandboxes.
    #[arg(long)]
    pub running: bool,

    /// Show only stopped sandboxes.
    #[arg(long)]
    pub stopped: bool,

    /// Output format.
    #[arg(long, value_name = "FORMAT")]
    pub format: Option<String>,

    /// Show only sandbox names.
    #[arg(short, long)]
    pub quiet: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb list` command.
pub async fn run(args: ListArgs) -> anyhow::Result<()> {
    let sandboxes = Sandbox::list().await?;

    let filtered: Vec<_> = sandboxes
        .into_iter()
        .filter(|s| {
            if args.running {
                s.status() == SandboxStatus::Running
            } else if args.stopped {
                s.status() == SandboxStatus::Stopped
            } else {
                true
            }
        })
        .collect();

    if args.format.as_deref() == Some("json") {
        print_json(&filtered)?;
        return Ok(());
    }

    if args.quiet {
        for s in &filtered {
            println!("{}", s.name());
        }
        return Ok(());
    }

    if filtered.is_empty() {
        eprintln!("No sandboxes found.");
        return Ok(());
    }

    let mut table = ui::Table::new(&["Name", "Image", "Status", "Created"]);

    for s in &filtered {
        let image = extract_image(s.config_json());
        let status = format!("{:?}", s.status());
        let created = s
            .created_at()
            .as_ref()
            .map(ui::format_datetime)
            .unwrap_or_else(|| "-".to_string());

        table.add_row(vec![
            s.name().to_string(),
            image,
            ui::format_status(&status),
            created,
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

fn print_json(sandboxes: &[SandboxHandle]) -> anyhow::Result<()> {
    let entries: Vec<serde_json::Value> = sandboxes
        .iter()
        .map(|s| {
            serde_json::json!({
                "name": s.name(),
                "status": format!("{:?}", s.status()),
                "created_at": s.created_at().map(|dt| ui::format_datetime(&dt)),
                "image": extract_image(s.config_json()),
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&entries)?);
    Ok(())
}
